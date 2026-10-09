// Command fixture-recorder captures replies from a real Redis/Valkey server.
// It writes probe fixtures for the fidelity tests and the persona data files
// (COMMAND tables, INFO templates, CONFIG defaults, MODULE LIST) that the
// honeypot embeds. Run it via scripts/record-fixtures.sh, never against
// production servers.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"RedisHoneyPot/internal/fixtures"
)

func main() {
	var addr, fixtureFile, dataDir string
	flag.StringVar(&addr, "addr", "127.0.0.1:6379", "real server address")
	flag.StringVar(&fixtureFile, "fixtures", "", "output JSON file for probe replies")
	flag.StringVar(&dataDir, "data", "", "output directory for persona data files")
	flag.Parse()
	if fixtureFile == "" || dataDir == "" {
		fmt.Fprintln(os.Stderr, "-fixtures and -data are required")
		os.Exit(2)
	}
	if err := run(addr, fixtureFile, dataDir); err != nil {
		fmt.Fprintf(os.Stderr, "fixture-recorder: %v\n", err)
		os.Exit(1)
	}
}

func run(addr, fixtureFile, dataDir string) error {
	if err := recordData(addr, dataDir); err != nil {
		return fmt.Errorf("record data: %w", err)
	}
	recorded, err := recordProbes(addr)
	if err != nil {
		return fmt.Errorf("record probes: %w", err)
	}
	out, err := json.MarshalIndent(recorded, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(fixtureFile), 0o755); err != nil {
		return err
	}
	return os.WriteFile(fixtureFile, append(out, '\n'), 0o644)
}

type session struct {
	conn   net.Conn
	reader *bufio.Reader
}

func dial(addr string) (*session, error) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	return &session{conn: conn, reader: bufio.NewReaderSize(conn, 1<<20)}, nil
}

func (s *session) roundTrip(request []byte) ([]byte, error) {
	_ = s.conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := s.conn.Write(request); err != nil {
		return nil, err
	}
	return fixtures.ReadReply(s.reader)
}

func recordData(addr, dataDir string) error {
	s, err := dial(addr)
	if err != nil {
		return err
	}
	defer s.conn.Close()
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}

	files := []struct {
		name    string
		args    []string
		bulkTxt bool
	}{
		{"command.resp", []string{"COMMAND"}, false},
		{"command_docs.resp", []string{"COMMAND", "DOCS"}, false},
		{"config.resp", []string{"CONFIG", "GET", "*"}, false},
		{"module_list.resp", []string{"MODULE", "LIST"}, false},
		{"info_default.txt", []string{"INFO"}, true},
		{"info_all.txt", []string{"INFO", "all"}, true},
		{"info_everything.txt", []string{"INFO", "everything"}, true},
		{"client_list.txt", []string{"CLIENT", "LIST"}, true},
	}
	for _, file := range files {
		reply, err := s.roundTrip(fixtures.Command(file.args...))
		if err != nil {
			return fmt.Errorf("%s: %w", strings.Join(file.args, " "), err)
		}
		if bytes.HasPrefix(reply, []byte("-")) {
			// Command not available in this version; keep no file.
			_ = os.Remove(filepath.Join(dataDir, file.name))
			continue
		}
		if file.bulkTxt {
			reply = bulkBody(reply)
		}
		if err := os.WriteFile(filepath.Join(dataDir, file.name), reply, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func bulkBody(reply []byte) []byte {
	idx := bytes.Index(reply, []byte("\r\n"))
	if idx < 0 || len(reply) < idx+4 {
		return reply
	}
	return reply[idx+2 : len(reply)-2]
}

func recordProbes(addr string) ([]fixtures.Recorded, error) {
	var current *session
	defer func() {
		if current != nil {
			_ = current.conn.Close()
		}
	}()

	var recorded []fixtures.Recorded
	for _, probe := range fixtures.Probes {
		if probe.NewConn || current == nil {
			if current != nil {
				_ = current.conn.Close()
			}
			s, err := dial(addr)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", probe.Name, err)
			}
			current = s
		}

		var reply []byte
		var closed bool
		var err error
		switch probe.Mode {
		case fixtures.Closed:
			reply, closed, err = readUntilClose(current, probe.Send)
		case fixtures.Sync:
			reply, err = readSync(current, probe.Send)
		default:
			reply, err = current.roundTrip(probe.Send)
			if err == nil && strings.HasPrefix(probe.Name, "proto_") {
				_, closed, _ = readUntilClose(current, nil)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", probe.Name, err)
		}
		recorded = append(recorded, fixtures.NewRecorded(probe.Name, reply, closed))
	}
	return recorded, nil
}

func readUntilClose(s *session, request []byte) ([]byte, bool, error) {
	_ = s.conn.SetDeadline(time.Now().Add(2 * time.Second))
	if request != nil {
		if _, err := s.conn.Write(request); err != nil {
			return nil, false, err
		}
	}
	data, err := io.ReadAll(s.reader)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return data, false, nil
	}
	return data, true, nil
}

// readSync reads "+FULLRESYNC ..." followed by the RDB transfer, which is
// either "$<len>\r\n<rdb>" or the diskless "$EOF:<mark>\r\n<rdb><mark>" form.
func readSync(s *session, request []byte) ([]byte, error) {
	_ = s.conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := s.conn.Write(request); err != nil {
		return nil, err
	}
	head, err := s.reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	out := []byte(head)
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return out, err
		}
		if line == "\n" {
			continue // keepalive newline while the master forks
		}
		out = append(out, line...)
		size := strings.TrimSuffix(strings.TrimPrefix(line, "$"), "\r\n")
		if mark, ok := strings.CutPrefix(size, "EOF:"); ok {
			var body []byte
			for !bytes.HasSuffix(body, []byte(mark)) {
				b, err := s.reader.ReadByte()
				if err != nil {
					return append(out, body...), err
				}
				body = append(body, b)
			}
			return append(out, body...), nil
		}
		n, err := strconv.Atoi(size)
		if err != nil {
			return out, fmt.Errorf("unexpected sync line %q", line)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(s.reader, body); err != nil {
			return out, err
		}
		return append(out, body...), nil
	}
}
