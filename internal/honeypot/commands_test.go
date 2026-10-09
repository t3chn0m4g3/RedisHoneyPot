package honeypot

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T, profileName string) *RedisServer {
	t.Helper()

	profile, ok := LookupRedisProfile(profileName)
	if !ok {
		t.Fatalf("unknown profile %q", profileName)
	}

	options := DefaultServerOptions()
	options.Address = "127.0.0.1:0"
	options.Profile = profile
	options.IdleTimeout = time.Second
	options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	server, err := NewRedisServerWithOptions(options)
	if err != nil {
		t.Fatalf("NewRedisServerWithOptions returned error: %v", err)
	}
	t.Cleanup(server.Stop)
	return server
}

func call(server *RedisServer, state *clientState, args ...string) string {
	if state.proto == 0 {
		state.proto = 2
	}
	return string(server.handleCommand(state, args).reply.Encode(state.proto))
}

func infoText(server *RedisServer, sections ...string) string {
	return server.handleInfo(&clientState{connected: time.Now(), proto: 2}, sections).str
}

func TestCommandStringStoreAndRESPRegression(t *testing.T) {
	server := newTestServer(t, "legacy6")
	state := &clientState{connected: time.Now()}

	if got := call(server, state, "PING"); got != "+PONG\r\n" {
		t.Fatalf("PING got %q", got)
	}
	if got := call(server, state, "GET", "missing"); got != "$-1\r\n" {
		t.Fatalf("missing GET got %q, want nil bulk", got)
	}
	if got := call(server, state, "SET", "alpha", "one"); got != "+OK\r\n" {
		t.Fatalf("SET got %q", got)
	}
	if got := call(server, state, "GET", "alpha"); got != "$3\r\none\r\n" {
		t.Fatalf("GET got %q", got)
	}
	if got := call(server, state, "EXISTS", "alpha", "missing"); got != ":1\r\n" {
		t.Fatalf("EXISTS got %q, want integer reply", got)
	}
	if got := call(server, state, "DBSIZE"); got != ":1\r\n" {
		t.Fatalf("DBSIZE got %q, want integer reply", got)
	}
	if got := call(server, state, "DEL", "alpha", "missing"); got != ":1\r\n" {
		t.Fatalf("DEL got %q, want integer reply", got)
	}
	if got := call(server, state, "KEYS", "*"); got != "*0\r\n" {
		t.Fatalf("empty KEYS got %q, want empty array", got)
	}
}

func TestCommandSelectUsesConnectionLocalDB(t *testing.T) {
	server := newTestServer(t, "legacy6")
	state := &clientState{connected: time.Now()}

	if got := call(server, state, "SET", "same", "db0"); got != "+OK\r\n" {
		t.Fatalf("SET db0 got %q", got)
	}
	if got := call(server, state, "SELECT", "1"); got != "+OK\r\n" {
		t.Fatalf("SELECT got %q", got)
	}
	if got := call(server, state, "GET", "same"); got != "$-1\r\n" {
		t.Fatalf("GET db1 got %q, want nil bulk", got)
	}
	if got := call(server, state, "SET", "same", "db1"); got != "+OK\r\n" {
		t.Fatalf("SET db1 got %q", got)
	}
	if got := call(server, state, "GET", "same"); got != "$3\r\ndb1\r\n" {
		t.Fatalf("GET db1 got %q", got)
	}
}

func TestConfigRegressionAndMutation(t *testing.T) {
	server := newTestServer(t, "legacy6")
	state := &clientState{connected: time.Now()}

	if got := call(server, state, "CONFIG"); !strings.HasPrefix(got, "-ERR") {
		t.Fatalf("CONFIG without args got %q, want error without panic", got)
	}
	if got := call(server, state, "CONFIG", "GET", "does-not-exist"); got != "*0\r\n" {
		t.Fatalf("CONFIG GET missing got %q, want empty array", got)
	}
	if got := call(server, state, "CONFIG", "GET", "dir"); got != "*2\r\n$3\r\ndir\r\n$19\r\n/var/lib/redis/6379\r\n" {
		t.Fatalf("CONFIG GET dir got %q", got)
	}
	if got := call(server, state, "CONFIG", "SET", "dir", "/nonexistent-xyz"); got != "-ERR Changing directory: No such file or directory\r\n" {
		t.Fatalf("CONFIG SET missing dir got %q", got)
	}
	if got := call(server, state, "CONFIG", "SET", "dir", "/tmp/"); got != "+OK\r\n" {
		t.Fatalf("CONFIG SET dir got %q", got)
	}
	if got := call(server, state, "CONFIG", "GET", "dir"); got != "*2\r\n$3\r\ndir\r\n$4\r\n/tmp\r\n" {
		t.Fatalf("CONFIG GET updated dir got %q", got)
	}
}

func TestProfilesChangeInfoFingerprint(t *testing.T) {
	legacy := newTestServer(t, "legacy6")
	current := newTestServer(t, "current8")
	state := &clientState{connected: time.Now()}

	if got := call(legacy, state, "INFO", "server"); !strings.Contains(got, "redis_version:6.2.18") {
		t.Fatalf("legacy INFO did not include legacy version: %q", got)
	}
	if got := call(current, state, "INFO", "server"); !strings.Contains(got, "redis_version:8.8.0") {
		t.Fatalf("current INFO did not include current version: %q", got)
	}
}

func TestHoneypotRealismCommandsDoNotExecuteButLookWritable(t *testing.T) {
	server := newTestServer(t, "redis74")
	state := &clientState{connected: time.Now()}

	for _, args := range [][]string{
		{"CONFIG", "SET", "dir", "/root/.ssh"},
		{"CONFIG", "SET", "dbfilename", "authorized_keys"},
		{"SET", "payload", "ssh-rsa AAAA..."},
		{"SAVE"},
		{"REPLCONF", "listening-port", "6379"},
	} {
		if got := call(server, state, args...); got != "+OK\r\n" {
			t.Fatalf("%v got %q, want OK", args, got)
		}
	}

	if got := call(server, state, "MODULE", "LOAD", "/tmp/exp.so"); got != "-ERR Error loading the extension. Please check the server logs.\r\n" {
		t.Fatalf("MODULE LOAD got %q", got)
	}
	if got := call(server, state, "PSYNC", "?", "-1"); !strings.HasPrefix(got, "+FULLRESYNC ") || !strings.Contains(got, "REDIS0012") {
		t.Fatalf("PSYNC got %q, want full resync with RDB v12", got)
	}

	if got := call(server, state, "SLAVEOF", "198.51.100.10", "6379"); got != "+OK\r\n" {
		t.Fatalf("SLAVEOF got %q", got)
	}
	if got := call(server, state, "ROLE"); !strings.HasPrefix(got, "*5\r\n$5\r\nslave\r\n$13\r\n198.51.100.10\r\n:6379\r\n$7\r\nconnect\r\n") {
		t.Fatalf("ROLE as replica got %q", got)
	}
	if got := call(server, state, "SET", "x", "y"); got != "-READONLY You can't write against a read only replica.\r\n" {
		t.Fatalf("SET on replica got %q", got)
	}
	if got := infoText(server, "replication"); !strings.Contains(got, "master_host:198.51.100.10") || !strings.Contains(got, "master_link_status:down") {
		t.Fatalf("INFO replication as replica got %q", got)
	}
	if got := call(server, state, "REPLICAOF", "NO", "ONE"); got != "+OK\r\n" {
		t.Fatalf("REPLICAOF NO ONE got %q", got)
	}

	current := newTestServer(t, "current8")
	if got := call(current, state, "MODULE", "LIST"); !strings.Contains(got, "search") {
		t.Fatalf("MODULE LIST current profile got %q, want built-in module names", got)
	}
	if got := call(current, state, "CONFIG", "SET", "dir", "/tmp"); !strings.Contains(got, "can't set protected config") {
		t.Fatalf("current8 CONFIG SET dir got %q, want protected config error", got)
	}
}

func TestWrongArityAndUnknownCommand(t *testing.T) {
	server := newTestServer(t, "legacy6")
	state := &clientState{connected: time.Now()}

	if got := call(server, state, "GET"); !strings.HasPrefix(got, "-ERR wrong number of arguments") {
		t.Fatalf("GET wrong arity got %q", got)
	}
	if got := call(server, state, "NOPE", "x"); !strings.HasPrefix(got, "-ERR unknown command") {
		t.Fatalf("unknown command got %q", got)
	}
}
