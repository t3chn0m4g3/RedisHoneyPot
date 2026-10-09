package honeypot

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"RedisHoneyPot/internal/fixtures"
)

// skippedProbes are not emulated yet; each later phase removes its entries.
var skippedProbes = map[string]bool{
	"eval_return_int": true, "eval_return_str": true, "eval_arity": true, "eval_numkeys_bad": true,
	"script_load": true, "evalsha_ok": true, "evalsha_missing": true, "script_exists": true,
	"function_list": true, "psync": true,
}

// dataCaptureRequests mirrors cmd/fixture-recorder's first connection, so
// INFO statistics see the same command history as the real server did.
var dataCaptureRequests = [][]string{
	{"COMMAND"}, {"COMMAND", "DOCS"}, {"CONFIG", "GET", "*"}, {"MODULE", "LIST"},
	{"INFO"}, {"INFO", "all"}, {"INFO", "everything"}, {"CLIENT", "LIST"},
}

// TestFidelityAgainstRecordedServers replays the recorder's probe sequence and
// compares replies with those captured from real Redis/Valkey containers
// (scripts/record-fixtures.sh).
func TestFidelityAgainstRecordedServers(t *testing.T) {
	for _, persona := range ProfileNames() {
		t.Run(persona, func(t *testing.T) {
			recorded := loadFixtures(t, persona)
			server, _ := startLoggedServer(t, func(o *ServerOptions) {
				profile, _ := LookupRedisProfile(persona)
				o.Profile = profile
				o.IdleTimeout = 5 * time.Second
			})
			replies := replayProbes(t, server.Addr().String())

			for _, probe := range fixtures.Probes {
				if skippedProbes[probe.Name] {
					continue
				}
				want, ok := recorded[probe.Name]
				if !ok {
					t.Errorf("%s: no recorded fixture; re-run scripts/record-fixtures.sh", probe.Name)
					continue
				}
				got := replies[probe.Name]
				if err := compareReply(probe.Mode, want, got); err != nil {
					t.Errorf("%s (%s): %v\n  want %q\n  got  %q", probe.Name, probe.Mode, err, clip(want.Bytes()), clip(got.Bytes()))
				}
			}
		})
	}
}

func clip(b []byte) string {
	if len(b) > 300 {
		return string(b[:300]) + "..."
	}
	return string(b)
}

func loadFixtures(t *testing.T, persona string) map[string]fixtures.Recorded {
	t.Helper()
	data, err := os.ReadFile("testdata/fixtures/" + persona + ".json")
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var list []fixtures.Recorded
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatalf("decode fixtures: %v", err)
	}
	out := make(map[string]fixtures.Recorded, len(list))
	for _, r := range list {
		out[r.Name] = r
	}
	return out
}

type probeSession struct {
	conn   net.Conn
	reader *bufio.Reader
}

func dialProbe(t *testing.T, addr string) *probeSession {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &probeSession{conn: conn, reader: bufio.NewReaderSize(conn, 1<<20)}
}

func replayProbes(t *testing.T, addr string) map[string]fixtures.Recorded {
	t.Helper()
	capture := dialProbe(t, addr)
	for _, request := range dataCaptureRequests {
		_ = capture.conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := capture.conn.Write(fixtures.Command(request...)); err != nil {
			t.Fatalf("data capture write: %v", err)
		}
		if _, err := fixtures.ReadReply(capture.reader); err != nil {
			t.Fatalf("data capture %v: %v", request, err)
		}
	}
	_ = capture.conn.Close()

	replies := make(map[string]fixtures.Recorded)
	var current *probeSession
	for _, probe := range fixtures.Probes {
		if probe.NewConn || current == nil {
			if current != nil {
				_ = current.conn.Close()
			}
			current = dialProbe(t, addr)
		}
		_ = current.conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := current.conn.Write(probe.Send); err != nil {
			replies[probe.Name] = fixtures.Recorded{Name: probe.Name, Closed: true}
			continue
		}

		var reply []byte
		var closed bool
		switch probe.Mode {
		case fixtures.Closed:
			_ = current.conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
			reply, closed = readToClose(current)
		case fixtures.Sync:
			reply = readSyncReply(current)
		default:
			r, err := fixtures.ReadReply(current.reader)
			reply = r
			if err != nil {
				closed = true
			} else if strings.HasPrefix(probe.Name, "proto_") {
				_ = current.conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
				_, closed = readToClose(current)
			}
		}
		replies[probe.Name] = fixtures.NewRecorded(probe.Name, reply, closed)
	}
	return replies
}

func readToClose(s *probeSession) ([]byte, bool) {
	data, err := io.ReadAll(s.reader)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return data, false
	}
	return data, true
}

func readSyncReply(s *probeSession) []byte {
	head, err := s.reader.ReadString('\n')
	if err != nil {
		return []byte(head)
	}
	sizeLine, err := s.reader.ReadString('\n')
	if err != nil {
		return []byte(head + sizeLine)
	}
	size, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(sizeLine, "$"), "\r\n"))
	if err != nil {
		return []byte(head + sizeLine)
	}
	body := make([]byte, size)
	n, _ := io.ReadFull(s.reader, body)
	return append([]byte(head+sizeLine), body[:n]...)
}

func compareReply(mode fixtures.Mode, want, got fixtures.Recorded) error {
	w, g := want.Bytes(), got.Bytes()
	switch mode {
	case fixtures.Exact:
		if !bytes.Equal(w, g) {
			return errors.New("reply differs")
		}
	case fixtures.Type:
		if len(w) == 0 || len(g) == 0 || w[0] != g[0] {
			return errors.New("RESP type differs")
		}
	case fixtures.Shape:
		wn, _, err1 := parseRESP(w)
		gn, _, err2 := parseRESP(g)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("parse: want %v, got %v", err1, err2)
		}
		return compareShape(wn, gn, "")
	case fixtures.Info:
		return compareInfo(w, g)
	case fixtures.ClientInfo:
		if wk, gk := clientInfoKeys(w), clientInfoKeys(g); wk != gk {
			return fmt.Errorf("fields differ:\n  want %s\n  got  %s", wk, gk)
		}
	case fixtures.Closed:
		if len(g) != 0 || !got.Closed {
			return errors.New("expected silent close")
		}
	case fixtures.Sync:
		return compareSync(w, g)
	}
	if want.Closed != got.Closed {
		return fmt.Errorf("closed: want %t, got %t", want.Closed, got.Closed)
	}
	return nil
}

func compareShape(want, got respNode, path string) error {
	if want.kind != got.kind {
		return fmt.Errorf("%s: type %q, want %q", path, got.kind, want.kind)
	}
	if len(want.children) != len(got.children) {
		return fmt.Errorf("%s: %d elements, want %d", path, len(got.children), len(want.children))
	}
	if want.kind == '-' && want.str != got.str {
		return fmt.Errorf("%s: error %q, want %q", path, got.str, want.str)
	}
	for i := range want.children {
		if err := compareShape(want.children[i], got.children[i], fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

func bulkPayload(raw []byte) (string, bool) {
	node, _, err := parseRESP(raw)
	if err != nil || node.kind != '$' {
		return "", false
	}
	return node.str, true
}

// dynamicInfoSections list their entries in an order that depends on hash
// iteration in Redis, so only the set of field names is compared.
var dynamicInfoSections = map[string]bool{"commandstats": true, "errorstats": true, "latencystats": true}

func compareInfo(want, got []byte) error {
	w, ok1 := bulkPayload(want)
	g, ok2 := bulkPayload(got)
	if !ok1 || !ok2 {
		if bytes.Equal(want, got) {
			return nil
		}
		return errors.New("not a bulk reply")
	}
	ws, gs := parseInfoTemplate(w), parseInfoTemplate(g)
	if names(ws) != names(gs) {
		return fmt.Errorf("sections differ:\n  want %s\n  got  %s", names(ws), names(gs))
	}
	for i := range ws {
		wk, gk := infoKeys(ws[i]), infoKeys(gs[i])
		if dynamicInfoSections[strings.ToLower(ws[i].name)] {
			sort.Strings(wk)
			sort.Strings(gk)
		}
		if strings.Join(wk, ",") != strings.Join(gk, ",") {
			return fmt.Errorf("section %s keys differ:\n  want %v\n  got  %v", ws[i].name, wk, gk)
		}
	}
	if strings.HasSuffix(w, "\r\n\r\n") != strings.HasSuffix(g, "\r\n\r\n") {
		return errors.New("trailing blank line differs")
	}
	return nil
}

func names(sections []infoSection) string {
	out := make([]string, 0, len(sections))
	for _, s := range sections {
		out = append(out, s.name)
	}
	return strings.Join(out, ",")
}

func infoKeys(section infoSection) []string {
	out := make([]string, 0, len(section.lines))
	for _, line := range section.lines {
		out = append(out, line.key)
	}
	return out
}

func clientInfoKeys(raw []byte) string {
	body, ok := bulkPayload(raw)
	if !ok {
		return string(raw)
	}
	line, _, _ := strings.Cut(body, "\n")
	var keys []string
	for _, field := range strings.Fields(line) {
		key, _, _ := strings.Cut(field, "=")
		keys = append(keys, key)
	}
	return strings.Join(keys, " ") + fmt.Sprintf(" (newline=%t)", strings.HasSuffix(body, "\n"))
}

type rdbSummary struct {
	header    string
	auxBefore []string
	dbKeys    []string
	auxAfter  []string
	crcOK     bool
}

func compareSync(want, got []byte) error {
	ws, err := summarizeSync(want)
	if err != nil {
		return fmt.Errorf("recorded: %w", err)
	}
	gs, err := summarizeSync(got)
	if err != nil {
		return err
	}
	if !gs.crcOK {
		return errors.New("honeypot RDB has a bad CRC64")
	}
	sort.Strings(ws.dbKeys)
	sort.Strings(gs.dbKeys)
	if fmt.Sprint(ws.header, ws.auxBefore, ws.dbKeys, ws.auxAfter) != fmt.Sprint(gs.header, gs.auxBefore, gs.dbKeys, gs.auxAfter) {
		return fmt.Errorf("RDB differs:\n  want %+v\n  got  %+v", ws, gs)
	}
	return nil
}

func summarizeSync(raw []byte) (rdbSummary, error) {
	parts := bytes.SplitN(raw, []byte("\r\n"), 3)
	if len(parts) != 3 || !bytes.HasPrefix(parts[0], []byte("+FULLRESYNC ")) || len(bytes.Fields(parts[0])) != 3 {
		return rdbSummary{}, fmt.Errorf("bad handshake %q", clip(raw))
	}
	body := parts[2]
	if len(body) < 18 {
		return rdbSummary{}, errors.New("RDB too short")
	}
	summary := rdbSummary{header: string(body[:9])}
	summary.crcOK = crc64Jones(body[:len(body)-8]) == binary.LittleEndian.Uint64(body[len(body)-8:])

	pos := 9
	readLen := func() (uint64, bool) {
		b := body[pos]
		switch b >> 6 {
		case 0:
			pos++
			return uint64(b & 0x3f), false
		case 1:
			pos += 2
			return uint64(b&0x3f)<<8 | uint64(body[pos-1]), false
		case 2:
			if b == 0x80 {
				pos += 5
				return uint64(binary.BigEndian.Uint32(body[pos-4:])), false
			}
			pos += 9
			return binary.BigEndian.Uint64(body[pos-8:]), false
		default:
			pos++
			return uint64(b & 0x3f), true
		}
	}
	readString := func() string {
		n, encoded := readLen()
		if encoded {
			size := map[uint64]int{0: 1, 1: 2, 2: 4}[n]
			pos += size
			return "<int>"
		}
		value := string(body[pos : pos+int(n)])
		pos += int(n)
		return value
	}

	seenDB := false
	for pos < len(body)-8 {
		switch op := body[pos]; op {
		case 0xFA:
			pos++
			key := readString()
			_ = readString()
			if seenDB {
				summary.auxAfter = append(summary.auxAfter, key)
			} else {
				summary.auxBefore = append(summary.auxBefore, key)
			}
		case 0xFE:
			pos++
			seenDB = true
			readLen()
		case 0xFB:
			pos++
			readLen()
			readLen()
		case 0xFC:
			pos += 9
		case 0x00:
			pos++
			summary.dbKeys = append(summary.dbKeys, readString())
			_ = readString()
		case 0xFF:
			return summary, nil
		default:
			return summary, fmt.Errorf("unexpected RDB opcode 0x%02x at %d", op, pos)
		}
	}
	return summary, nil
}
