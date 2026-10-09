package honeypot

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// startLoggedServer runs a server with a JSON log buffer. The returned stop
// function stops the server and returns the log; reading the buffer only after
// Stop is race-free because Start/Stop wait for all handlers.
func startLoggedServer(t *testing.T, mutate func(*ServerOptions)) (*RedisServer, func() string) {
	t.Helper()
	var logs bytes.Buffer
	options := DefaultServerOptions()
	options.Address = "127.0.0.1:0"
	options.Logger = NewJSONLogger(&logs)
	options.IdleTimeout = time.Second
	if mutate != nil {
		mutate(&options)
	}
	server, err := NewRedisServerWithOptions(options)
	if err != nil {
		t.Fatalf("NewRedisServerWithOptions returned error: %v", err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Start() }()

	stopped := false
	stop := func() string {
		if !stopped {
			stopped = true
			server.Stop()
			select {
			case err := <-errCh:
				if err != nil {
					t.Fatalf("server returned error: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("server did not stop")
			}
		}
		return logs.String()
	}
	t.Cleanup(func() { stop() })
	return server, stop
}

func TestHealthcheckNameFromUntrustedPeerIsLogged(t *testing.T) {
	server, stop := startLoggedServer(t, func(o *ServerOptions) {
		o.TrustedPeer = func(net.Addr) bool { return false }
	})
	conn, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	reader := bufio.NewReader(conn)
	writeCommand(t, conn, "CLIENT SETNAME "+HealthcheckClientName+"\r\n")
	if got := readRESP(t, reader); got != "+OK\r\n" {
		t.Fatalf("CLIENT SETNAME got %q", got)
	}
	writeCommand(t, conn, "CONFIG SET dir /var/spool/cron\r\n")
	readRESP(t, reader)
	writeCommand(t, conn, "QUIT\r\n")
	readRESP(t, reader)
	_ = conn.Close()

	events := decodeLogEvents(t, stop())
	var sawConfig, sawClose bool
	for _, event := range events {
		if event["event"] == "command" && event["command"] == "CONFIG" {
			sawConfig = true
		}
		if event["event"] == "close" {
			sawClose = true
		}
	}
	if !sawConfig || !sawClose {
		t.Fatalf("untrusted healthcheck-named session must be logged; config=%t close=%t", sawConfig, sawClose)
	}
}

func TestLoopbackPeerIsTrusted(t *testing.T) {
	if !isLoopbackPeer(&net.TCPAddr{IP: net.ParseIP("127.0.0.1")}) || !isLoopbackPeer(&net.TCPAddr{IP: net.ParseIP("::1")}) {
		t.Fatal("loopback peers must be trusted")
	}
	for _, ip := range []string{"172.22.0.1", "203.0.113.7", "::ffff:198.51.100.1"} {
		if isLoopbackPeer(&net.TCPAddr{IP: net.ParseIP(ip)}) {
			t.Fatalf("%s must not be trusted", ip)
		}
	}
}

func TestInlineCommandsAcceptBareLF(t *testing.T) {
	server, _ := startLoggedServer(t, nil)
	conn, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	writeCommand(t, conn, "PING\n")
	if got := readRESP(t, reader); got != "+PONG\r\n" {
		t.Fatalf("PING with bare LF got %q", got)
	}
	writeCommand(t, conn, "ECHO hello\n")
	if got := readRESP(t, reader); got != "$5\r\nhello\r\n" {
		t.Fatalf("ECHO with bare LF got %q", got)
	}
}

func TestErrorRepliesCannotInjectFrames(t *testing.T) {
	server := newTestServer(t, "redis74")
	got := string(server.unknownCommand([]string{"foo\r\n+OK", "a\nb"}).Bytes())
	if strings.Count(got, "\r\n") != 1 || !strings.HasSuffix(got, "\r\n") {
		t.Fatalf("error reply contains embedded line breaks: %q", got)
	}
}

func TestMaxClientsRejectsExtraConnections(t *testing.T) {
	server, _ := startLoggedServer(t, func(o *ServerOptions) { o.MaxClients = 1 })
	first, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	defer first.Close()
	writeCommand(t, first, "PING\r\n")
	if got := readRESP(t, bufio.NewReader(first)); got != "+PONG\r\n" {
		t.Fatalf("first PING got %q", got)
	}

	second, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	got, _ := io.ReadAll(second)
	if string(got) != "-ERR max number of clients reached\r\n" {
		t.Fatalf("second connection got %q", got)
	}
	if server.rejectedConns.Load() != 1 {
		t.Fatalf("rejected connections = %d, want 1", server.rejectedConns.Load())
	}
}

func TestIdleTimeoutAndTruncatedBulkAreNotProtocolErrors(t *testing.T) {
	server, stop := startLoggedServer(t, func(o *ServerOptions) { o.IdleTimeout = 100 * time.Millisecond })

	idle, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	writeCommand(t, idle, "PING\r\n")
	_ = idle.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, _ := io.ReadAll(idle)
	if string(got) != "+PONG\r\n" {
		t.Fatalf("idle connection got %q, want only PONG and a silent close", got)
	}

	partial, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	writeCommand(t, partial, "*1\r\n$10\r\nabc")
	_ = partial.Close()

	time.Sleep(200 * time.Millisecond)
	for _, event := range decodeLogEvents(t, stop()) {
		if event["event"] == "protocol_error" {
			t.Fatalf("unexpected protocol_error event: %v", event)
		}
	}
	if server.protocolErrors.Load() != 0 {
		t.Fatalf("protocol errors = %d, want 0", server.protocolErrors.Load())
	}
}

func TestCommandSizeBudget(t *testing.T) {
	config := ParserConfig{MaxBulkBytes: 8, MaxCommandBytes: 10}
	_, err := ReadCommand(bufio.NewReader(strings.NewReader("*2\r\n$6\r\nabcdef\r\n$6\r\nghijkl\r\n")), config)
	if err == nil || err.Error() != "invalid bulk length" {
		t.Fatalf("ReadCommand error = %v, want command size limit", err)
	}
}

func TestStopWaitsForCloseEvents(t *testing.T) {
	server, stop := startLoggedServer(t, nil)
	conn, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	defer conn.Close()
	writeCommand(t, conn, "PING\r\n")
	readRESP(t, bufio.NewReader(conn))

	var sawClose bool
	for _, event := range decodeLogEvents(t, stop()) {
		if event["event"] == "close" {
			sawClose = true
		}
	}
	if !sawClose {
		t.Fatal("Stop returned before the open session logged its close event")
	}
}

func TestAnalysisHintWithoutOtherAttrs(t *testing.T) {
	for _, args := range [][]string{{"PSYNC", "?", "-1"}, {"SYNC"}} {
		attrs := commandAnalysisAttrs(args)
		if len(attrs) == 0 || attrs[0].Key != "analysis_hint" || attrs[0].Value.String() != "redis_replication_attempt" {
			t.Fatalf("%v analysis attrs = %v, want redis_replication_attempt hint", args, attrs)
		}
	}
	if attrs := commandAnalysisAttrs([]string{"PING"}); len(attrs) != 0 {
		t.Fatalf("PING analysis attrs = %v, want none", attrs)
	}
}

func TestScriptCommandsLogCorrelatableFields(t *testing.T) {
	attrs := commandAnalysisAttrs([]string{"EVAL", "return 'x'", "0"})
	fields := map[string]string{}
	for _, attr := range attrs {
		fields[attr.Key] = attr.Value.String()
	}
	if fields["analysis_hint"] != "redis_lua_eval" || fields["script_sha1"] != "573cd020e2fc941d149285df8b681959190edd09" ||
		fields["script_text"] != "return 'x'" || fields["script_numkeys"] != "0" || fields["script_size"] != "10" {
		t.Fatalf("EVAL attrs = %v", fields)
	}

	attrs = commandAnalysisAttrs([]string{"EVALSHA", "573CD020E2FC941D149285DF8B681959190EDD09", "0"})
	if attrs[0].Value.String() != "redis_lua_eval" || attrs[1].Key != "script_sha1" || attrs[1].Value.String() != "573cd020e2fc941d149285df8b681959190edd09" {
		t.Fatalf("EVALSHA attrs = %v", attrs)
	}
}
