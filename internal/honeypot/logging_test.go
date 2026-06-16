package honeypot

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServerLogsFlatJSONForLogstash(t *testing.T) {
	var logs bytes.Buffer

	options := DefaultServerOptions()
	options.Address = "127.0.0.1:0"
	options.Logger = NewJSONLogger(&logs)
	options.IdleTimeout = time.Second

	server, err := NewRedisServerWithOptions(options)
	if err != nil {
		t.Fatalf("NewRedisServerWithOptions returned error: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	conn, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	reader := bufio.NewReader(conn)

	writeCommand(t, conn, "CLIENT SETINFO LIB-NAME testlib\r\n")
	if got := readRESP(t, reader); got != "+OK\r\n" {
		t.Fatalf("CLIENT SETINFO LIB-NAME got %q", got)
	}
	writeCommand(t, conn, "CLIENT SETINFO LIB-VER 1.2.3\r\n")
	if got := readRESP(t, reader); got != "+OK\r\n" {
		t.Fatalf("CLIENT SETINFO LIB-VER got %q", got)
	}
	writeCommand(t, conn, "AUTH default super-secret\r\n")
	if got := readRESP(t, reader); got != "+OK\r\n" {
		t.Fatalf("AUTH got %q", got)
	}
	writeCommand(t, conn, "PING\r\n")
	if got := readRESP(t, reader); got != "+PONG\r\n" {
		t.Fatalf("PING got %q", got)
	}
	writeCommand(t, conn, "QUIT\r\n")
	if got := readRESP(t, reader); got != "+OK\r\n" {
		t.Fatalf("QUIT got %q", got)
	}
	_ = conn.Close()

	server.Stop()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}

	events := decodeLogEvents(t, logs.String())
	var sawPing bool
	var sawAuth bool
	var sawClose bool

	for _, event := range events {
		assertFlatLogEvent(t, event)
		if _, err := time.Parse(time.RFC3339Nano, stringField(t, event, "timestamp")); err != nil {
			t.Fatalf("timestamp is not RFC3339Nano/ISO-8601 compatible: %v", err)
		}
		requireCommonNetworkAndSessionFields(t, event)

		switch event["event"] {
		case "command":
			switch event["command"] {
			case "PING":
				sawPing = true
				if got := stringField(t, event, "user_agent"); got != "testlib/1.2.3" {
					t.Fatalf("PING user_agent got %q, want testlib/1.2.3", got)
				}
				for _, key := range []string{"args_text", "args_truncated", "args_sha256"} {
					if _, ok := event[key]; ok {
						t.Fatalf("PING log unexpectedly contains empty argument field %q", key)
					}
				}
				if _, ok := event["args"]; ok {
					t.Fatal("flat log event unexpectedly contains args array field")
				}
			case "AUTH":
				sawAuth = true
				if got := stringField(t, event, "args_text"); strings.Contains(got, "super-secret") {
					t.Fatalf("AUTH args_text leaked password: %q", got)
				}
				if got := stringField(t, event, "auth_password_sha256"); got == "" {
					t.Fatal("AUTH log missing auth_password_sha256")
				}
			}
		case "close":
			sawClose = true
			if _, err := time.Parse(time.RFC3339Nano, stringField(t, event, "session_end")); err != nil {
				t.Fatalf("session_end is not RFC3339Nano/ISO-8601 compatible: %v", err)
			}
		}
	}

	if !sawPing {
		t.Fatal("did not see PING command log")
	}
	if !sawAuth {
		t.Fatal("did not see AUTH command log")
	}
	if !sawClose {
		t.Fatal("did not see close log")
	}
}

func TestHealthcheckSessionDoesNotWriteLogs(t *testing.T) {
	var logs bytes.Buffer

	options := DefaultServerOptions()
	options.Address = "127.0.0.1:0"
	options.Logger = NewJSONLogger(&logs)
	options.IdleTimeout = time.Second

	server, err := NewRedisServerWithOptions(options)
	if err != nil {
		t.Fatalf("NewRedisServerWithOptions returned error: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	conn, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	reader := bufio.NewReader(conn)

	writeCommand(t, conn, "CLIENT SETNAME "+HealthcheckClientName+"\r\n")
	if got := readRESP(t, reader); got != "+OK\r\n" {
		t.Fatalf("healthcheck CLIENT SETNAME got %q", got)
	}
	writeCommand(t, conn, "PING\r\n")
	if got := readRESP(t, reader); got != "+PONG\r\n" {
		t.Fatalf("healthcheck PING got %q", got)
	}
	writeCommand(t, conn, "QUIT\r\n")
	if got := readRESP(t, reader); got != "+OK\r\n" {
		t.Fatalf("healthcheck QUIT got %q", got)
	}
	_ = conn.Close()

	server.Stop()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}

	if got := strings.TrimSpace(logs.String()); got != "" {
		t.Fatalf("healthcheck session wrote logs:\n%s", got)
	}
}

func decodeLogEvents(t *testing.T, raw string) []map[string]any {
	t.Helper()

	lines := strings.Split(strings.TrimSpace(raw), "\n")
	events := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("log line is not JSON: %v\nline: %s", err, line)
		}
		events = append(events, event)
	}
	if len(events) == 0 {
		t.Fatal("no log events captured")
	}
	return events
}

func assertFlatLogEvent(t *testing.T, event map[string]any) {
	t.Helper()

	for key, value := range event {
		if value == nil {
			t.Fatalf("log field %q is JSON null, want field omitted", key)
		}
		switch value.(type) {
		case map[string]any, []any:
			t.Fatalf("log field %q is nested (%T), want flat primitive JSON value", key, value)
		}
		if text, ok := value.(string); ok && text == "" {
			switch key {
			case "session_end", "client_name", "client_library_name", "client_library_version", "user_agent":
				t.Fatalf("optional log field %q is empty, want field omitted", key)
			}
		}
	}
}

func requireCommonNetworkAndSessionFields(t *testing.T, event map[string]any) {
	t.Helper()

	for _, key := range []string{"src_ip", "dest_ip", "session_start", "session_id"} {
		if _, ok := event[key]; !ok {
			t.Fatalf("missing log field %q in %#v", key, event)
		}
	}
	for _, key := range []string{"src_port", "dest_port", "session_duration", "session_duration_ms"} {
		if _, ok := event[key].(float64); !ok {
			t.Fatalf("log field %q has type %T, want JSON number", key, event[key])
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, stringField(t, event, "session_start")); err != nil {
		t.Fatalf("session_start is not RFC3339Nano/ISO-8601 compatible: %v", err)
	}
	if value, ok := event["session_end"]; ok {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("log field session_end has type %T, want string", value)
		}
		if _, err := time.Parse(time.RFC3339Nano, text); err != nil {
			t.Fatalf("session_end is not RFC3339Nano/ISO-8601 compatible: %v", err)
		}
		if event["event"] != "close" {
			t.Fatalf("session_end is present on %q event, want only on close", event["event"])
		}
	}
}

func stringField(t *testing.T, event map[string]any, key string) string {
	t.Helper()

	value, ok := event[key]
	if !ok {
		t.Fatalf("missing log field %q", key)
	}
	text, ok := value.(string)
	if !ok {
		t.Fatalf("log field %q has type %T, want string", key, value)
	}
	return text
}
