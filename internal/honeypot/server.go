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
	"time"
)

const (
	defaultIdleTimeout    = 5 * time.Minute
	defaultMaxBulkBytes   = 1024 * 1024
	defaultMaxInlineBytes = 64 * 1024
	defaultMaxArrayElems  = 1024

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
	Logger         *slog.Logger
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

	totalConnections atomic.Uint64
	totalCommands    atomic.Uint64
	keyspaceHits     atomic.Uint64
	keyspaceMisses   atomic.Uint64
	protocolErrors   atomic.Uint64
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
}

func DefaultServerOptions() ServerOptions {
	profile, _ := LookupRedisProfile(DefaultProfileName)
	return ServerOptions{
		Address:        "0.0.0.0:6379",
		Network:        "tcp",
		Profile:        profile,
		IdleTimeout:    defaultIdleTimeout,
		MaxBulkBytes:   defaultMaxBulkBytes,
		MaxInlineBytes: defaultMaxInlineBytes,
		MaxArrayElems:  defaultMaxArrayElems,
		Logger:         NewJSONLogger(os.Stdout),
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
	if options.Logger == nil {
		options.Logger = NewJSONLogger(os.Stdout)
	}

	listener, err := net.Listen(options.Network, options.Address)
	if err != nil {
		return nil, err
	}

	s := &RedisServer{
		listener:  listener,
		store:     NewStore(),
		profile:   options.Profile,
		runtime:   newRuntimeFingerprint(options.Profile),
		logger:    options.Logger,
		options:   options,
		startedAt: time.Now(),
		done:      make(chan struct{}),
		conns:     make(map[net.Conn]struct{}),
		config:    cloneStringMap(options.Profile.Config),
	}
	return s, nil
}

func (s *RedisServer) Start() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
				return err
			}
		}

		s.addConn(conn)
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

func (s *RedisServer) Stop() {
	s.stopOnce.Do(func() {
		close(s.done)
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

func (s *RedisServer) addConn(conn net.Conn) {
	s.connMu.Lock()
	s.conns[conn] = struct{}{}
	s.connMu.Unlock()
}

func (s *RedisServer) removeConn(conn net.Conn) {
	s.connMu.Lock()
	delete(s.conns, conn)
	s.connMu.Unlock()
}

func (s *RedisServer) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer s.removeConn(conn)
	defer conn.Close()

	state := &clientState{
		id:        s.clientIDs.Add(1),
		sessionID: randomHex(32),
		connected: time.Now(),
	}
	s.totalConnections.Add(1)
	s.activeClients.Add(1)
	defer s.activeClients.Add(-1)

	reader := bufio.NewReader(conn)
	parserConfig := ParserConfig{
		MaxBulkBytes:   s.options.MaxBulkBytes,
		MaxInlineBytes: s.options.MaxInlineBytes,
		MaxArrayElems:  s.options.MaxArrayElems,
	}

	for {
		if s.options.IdleTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(s.options.IdleTimeout))
		}

		args, err := ReadCommand(reader, parserConfig)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
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
			_, _ = conn.Write(ErrorReply("ERR Protocol error: " + err.Error()).Bytes())
			break
		}
		if len(args) == 0 {
			continue
		}

		result := s.handleCommand(state, args)
		if !state.suppressLogs {
			s.totalCommands.Add(1)
		}

		reply := result.reply.Bytes()
		if s.options.IdleTimeout > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		}
		if _, err := conn.Write(reply); err != nil {
			break
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

func cloneStringMap(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
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
