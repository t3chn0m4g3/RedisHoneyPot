package honeypot

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultIdleTimeout    = 5 * time.Minute
	defaultMaxBulkBytes   = 1024 * 1024
	defaultMaxInlineBytes = 64 * 1024
	defaultMaxArrayElems  = 1024
	defaultMaxCommandSize = 4 * 1024 * 1024
	defaultMaxClients     = 1024

	maxAcceptBackoff = time.Second

	HealthcheckClientName = "__redishoneypot_healthcheck__"
)

type ServerOptions struct {
	Address        string
	Network        string
	Profile        RedisProfile
	IdleTimeout    time.Duration
	MaxBulkBytes   int
	MaxInlineBytes int
	MaxArrayElems  int
	// MaxCommandBytes caps the summed bulk payload of a single command.
	MaxCommandBytes int
	MaxClients      int
	// MaxLoggedPayloadBytes caps value_text, script_text and config_value.
	MaxLoggedPayloadBytes int
	Logger                *slog.Logger
	// TrustedPeer decides whether a peer may use the healthcheck client name to
	// suppress session logs. Defaults to loopback peers only.
	TrustedPeer func(net.Addr) bool
}

type RedisServer struct {
	listener net.Listener
	store    *Store
	profile  RedisProfile
	runtime  *runtimeFingerprint
	logger   *slog.Logger
	options  ServerOptions

	startedAt time.Time
	done      chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup

	connMu sync.Mutex
	conns  map[net.Conn]struct{}

	configMu sync.RWMutex
	config   map[string]string

	replMu sync.Mutex
	repl   replicationState

	stats   *serverStats
	scripts *scriptCache

	// clientsByIP counts open sessions per remote IP for connected_clients;
	// guarded by connMu.
	clientsByIP map[string]int

	totalConnections atomic.Uint64
	totalCommands    atomic.Uint64
	keyspaceHits     atomic.Uint64
	keyspaceMisses   atomic.Uint64
	protocolErrors   atomic.Uint64
	rejectedConns    atomic.Uint64
	syncFull         atomic.Uint64
	netIn            atomic.Uint64
	netOut           atomic.Uint64
	activeClients    atomic.Int64
	clientIDs        atomic.Uint64
}

type clientState struct {
	id            uint64
	sessionID     string
	db            int
	name          string
	libName       string
	libVersion    string
	connected     time.Time
	connectLogged bool
	suppressLogs  bool
	trustedLocal  bool

	proto      int
	remoteIP   string
	remoteAddr string
	localAddr  string
	fd         int
	netIn      int64
	netOut     int64
	commands   int64
	replica    bool

	// writeTargetSet is set once CONFIG SET dir/dbfilename succeeded.
	writeTargetSet bool
	hints          []string
}

func (s *clientState) addHint(hint string) {
	for _, existing := range s.hints {
		if existing == hint {
			return
		}
	}
	if len(s.hints) < 32 {
		s.hints = append(s.hints, hint)
	}
}

func DefaultServerOptions() ServerOptions {
	profile, _ := LookupRedisProfile(DefaultProfileName)
	return ServerOptions{
		Address:               "0.0.0.0:6379",
		Network:               "tcp",
		Profile:               profile,
		IdleTimeout:           defaultIdleTimeout,
		MaxBulkBytes:          defaultMaxBulkBytes,
		MaxInlineBytes:        defaultMaxInlineBytes,
		MaxArrayElems:         defaultMaxArrayElems,
		MaxCommandBytes:       defaultMaxCommandSize,
		MaxClients:            defaultMaxClients,
		MaxLoggedPayloadBytes: defaultMaxLoggedPayloadBytes,
		Logger:                NewJSONLogger(os.Stdout),
		TrustedPeer:           isLoopbackPeer,
	}
}

func NewRedisServer(address string, proto string, _ int) (*RedisServer, error) {
	options := DefaultServerOptions()
	options.Address = address
	options.Network = proto
	return NewRedisServerWithOptions(options)
}

func NewRedisServerWithOptions(options ServerOptions) (*RedisServer, error) {
	if options.Address == "" {
		options.Address = "0.0.0.0:6379"
	}
	if options.Network == "" {
		options.Network = "tcp"
	}
	if options.Profile.Name == "" {
		profile, _ := LookupRedisProfile(DefaultProfileName)
		options.Profile = profile
	}
	if options.IdleTimeout == 0 {
		options.IdleTimeout = defaultIdleTimeout
	}
	if options.MaxBulkBytes <= 0 {
		options.MaxBulkBytes = defaultMaxBulkBytes
	}
	if options.MaxInlineBytes <= 0 {
		options.MaxInlineBytes = defaultMaxInlineBytes
	}
	if options.MaxArrayElems <= 0 {
		options.MaxArrayElems = defaultMaxArrayElems
	}
	if options.MaxCommandBytes <= 0 {
		options.MaxCommandBytes = defaultMaxCommandSize
	}
	if options.MaxClients <= 0 {
		options.MaxClients = defaultMaxClients
	}
	if options.MaxLoggedPayloadBytes <= 0 {
		options.MaxLoggedPayloadBytes = defaultMaxLoggedPayloadBytes
	}
	if options.Logger == nil {
		options.Logger = NewJSONLogger(os.Stdout)
	}
	if options.TrustedPeer == nil {
		options.TrustedPeer = isLoopbackPeer
	}

	listener, err := net.Listen(options.Network, options.Address)
	if err != nil {
		return nil, err
	}

	s := &RedisServer{
		listener:    listener,
		store:       NewStore(),
		profile:     options.Profile,
		runtime:     newRuntimeFingerprint(options.Profile),
		logger:      options.Logger,
		options:     options,
		startedAt:   time.Now(),
		done:        make(chan struct{}),
		conns:       make(map[net.Conn]struct{}),
		config:      personaConfig(options.Profile),
		stats:       newServerStats(),
		scripts:     newScriptCache(),
		clientsByIP: make(map[string]int),
	}
	return s, nil
}

// Start serves connections until Stop is called. It returns only after all
// connection handlers have finished, so callers may close log sinks afterwards.
func (s *RedisServer) Start() error {
	var backoff time.Duration
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				s.wg.Wait()
				return nil
			default:
			}
			if isTemporaryAcceptError(err) {
				if backoff == 0 {
					backoff = 5 * time.Millisecond
				} else {
					backoff *= 2
				}
				if backoff > maxAcceptBackoff {
					backoff = maxAcceptBackoff
				}
				select {
				case <-time.After(backoff):
				case <-s.done:
				}
				continue
			}
			return err
		}
		backoff = 0

		accepted, full := s.trackConn(conn)
		if !accepted {
			if full {
				s.rejectedConns.Add(1)
				_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
				_, _ = conn.Write(ErrorReply("ERR max number of clients reached").Bytes())
			}
			_ = conn.Close()
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *RedisServer) Stop() {
	s.stopOnce.Do(func() {
		s.connMu.Lock()
		close(s.done)
		s.connMu.Unlock()
		_ = s.listener.Close()

		s.connMu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.connMu.Unlock()

		s.wg.Wait()
	})
}

func (s *RedisServer) Addr() net.Addr {
	return s.listener.Addr()
}

// trackConn registers conn and its handler goroutine. It refuses connections
// once Stop has begun and reports full when the client limit is reached.
func (s *RedisServer) trackConn(conn net.Conn) (accepted bool, full bool) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	select {
	case <-s.done:
		return false, false
	default:
	}
	if len(s.conns) >= s.options.MaxClients {
		return false, true
	}
	s.conns[conn] = struct{}{}
	s.clientsByIP[peerIP(conn.RemoteAddr())]++
	s.wg.Add(1)
	return true, false
}

func (s *RedisServer) removeConn(conn net.Conn) {
	s.connMu.Lock()
	delete(s.conns, conn)
	ip := peerIP(conn.RemoteAddr())
	if s.clientsByIP[ip]--; s.clientsByIP[ip] <= 0 {
		delete(s.clientsByIP, ip)
	}
	s.connMu.Unlock()
}

func peerIP(addr net.Addr) string {
	host, _ := splitAddr(addr)
	return host
}

func isTemporaryAcceptError(err error) bool {
	if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ENOMEM) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// isConnectionGone reports read errors that mean the peer went away or idled
// out; real Redis closes these connections without a protocol error reply.
func isConnectionGone(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE)
}

func isLoopbackPeer(addr net.Addr) bool {
	tcpAddr, ok := addr.(*net.TCPAddr)
	return ok && tcpAddr.IP.IsLoopback()
}

func (s *RedisServer) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer s.removeConn(conn)
	defer conn.Close()

	state := &clientState{
		id:           s.clientIDs.Add(1),
		sessionID:    randomHex(32),
		connected:    time.Now(),
		trustedLocal: s.options.TrustedPeer(conn.RemoteAddr()),
	}
	s.totalConnections.Add(1)
	s.activeClients.Add(1)
	defer s.activeClients.Add(-1)

	reader := bufio.NewReader(conn)
	parserConfig := ParserConfig{
		MaxBulkBytes:    s.options.MaxBulkBytes,
		MaxInlineBytes:  s.options.MaxInlineBytes,
		MaxArrayElems:   s.options.MaxArrayElems,
		MaxCommandBytes: s.options.MaxCommandBytes,
	}

	for {
		if s.options.IdleTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(s.options.IdleTimeout))
		}

		args, err := ReadCommand(reader, parserConfig)
		if err != nil {
			if isConnectionGone(err) {
				break
			}
			if errors.Is(err, errEmptyCommand) {
				continue
			}

			s.protocolErrors.Add(1)
			if !state.suppressLogs {
				s.ensureConnectLogged(state, conn)
				s.logProtocolError(state, conn, err)
			}
			reply := ErrorReply("ERR Protocol error: " + err.Error())
			s.stats.record("", 0, reply, false)
			_, _ = conn.Write(reply.Bytes())
			break
		}
		if len(args) == 0 {
			continue
		}

		started := time.Now()
		result := s.handleCommand(state, args)
		elapsed := time.Since(started).Microseconds()

		var reply []byte
		if !result.silent && !result.noReply {
			reply = result.reply.Encode(state.proto)
		}
		if result.silent {
			result.reply = RawReply("")
		}

		requestBytes := int64(len(encodeRequest(args)))
		state.netIn += requestBytes
		state.netOut += int64(len(reply))
		state.commands++
		s.netIn.Add(uint64(requestBytes))
		s.netOut.Add(uint64(len(reply)))
		if !state.suppressLogs {
			if !result.rejected && !result.silent {
				s.totalCommands.Add(1)
			}
			s.stats.record(result.statName, elapsed, result.reply, result.rejected)
		}

		if len(reply) > 0 {
			if s.options.IdleTimeout > 0 {
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			}
			if _, err := conn.Write(reply); err != nil {
				break
			}
		}

		if !state.suppressLogs {
			s.ensureConnectLogged(state, conn)
			s.logCommand(state, conn, args, result, len(reply))
		}

		if result.close {
			break
		}
	}

	if !state.suppressLogs {
		s.ensureConnectLogged(state, conn)
		s.logClose(state, conn, time.Now())
	}
}

func (s *RedisServer) ensureConnectLogged(state *clientState, conn net.Conn) {
	if state.connectLogged {
		return
	}
	s.logConnect(state, conn)
	state.connectLogged = true
}

// personaConfig starts from the CONFIG GET * defaults recorded from the real
// server and applies the persona's deployment overrides for known keys.
func personaConfig(profile RedisProfile) map[string]string {
	config := make(map[string]string, len(profile.data.config))
	for key, value := range profile.data.config {
		config[key] = value
	}
	for key, value := range profile.ConfigOverrides {
		if _, known := config[key]; known {
			config[key] = value
		}
	}
	return config
}

func (s *RedisServer) clientsFrom(ip string) int {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if n := s.clientsByIP[ip]; n > 0 {
		return n
	}
	return 1
}

func encodeRequest(args []string) []byte {
	values := make([]RESPValue, 0, len(args))
	for _, arg := range args {
		values = append(values, BulkString(arg))
	}
	return Array(values...).Bytes()
}

func (s *clientState) userAgent() string {
	if s.libName == "" {
		return ""
	}
	if s.libVersion == "" {
		return s.libName
	}
	return s.libName + "/" + s.libVersion
}
