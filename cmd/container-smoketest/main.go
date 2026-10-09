package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	var address string
	var logFile string
	var logOffset int64
	var timeout time.Duration

	flag.StringVar(&address, "addr", "127.0.0.1:6379", "RedisHoneyPot address")
	flag.StringVar(&logFile, "log-file", "logs/redishoneypot.log", "host-side JSONL event log path")
	flag.Int64Var(&logOffset, "log-offset", 0, "byte offset in the log file where this smoke run starts")
	flag.DurationVar(&timeout, "timeout", 15*time.Second, "overall smoke test timeout")
	flag.Parse()

	if err := run(address, logFile, logOffset, timeout); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "container smoke test failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("container smoke test passed")
}

func run(address string, logFile string, logOffset int64, timeout time.Duration) error {
	conn, err := dialUntil(address, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	// The smoke test may run against a live sensor, so it restores the state it
	// touches and leaves no smoke-key or changed dir behind for attackers to see.
	originalDir, err := configGet(conn, reader, "dir")
	if err != nil {
		return err
	}

	checks := []struct {
		command string
		want    string
	}{
		{"CLIENT SETINFO LIB-NAME container-smoketest\r\n", "+OK\r\n"},
		{"PING\r\n", "+PONG\r\n"},
		{"SET smoke-key smoke-value\r\n", "+OK\r\n"},
		{"GET smoke-key\r\n", "$11\r\nsmoke-value\r\n"},
		{"CONFIG SET dir /tmp\r\n", "+OK\r\n"},
		{"SAVE\r\n", "+OK\r\n"},
		{"DEL smoke-key\r\n", ":1\r\n"},
		{respCommand("CONFIG", "SET", "dir", originalDir), "+OK\r\n"},
		{"QUIT\r\n", "+OK\r\n"},
	}

	for _, check := range checks {
		if _, err := io.WriteString(conn, check.command); err != nil {
			return fmt.Errorf("write %q: %w", strings.TrimSpace(check.command), err)
		}
		got, err := readRESP(reader)
		if err != nil {
			return fmt.Errorf("read response for %q: %w", strings.TrimSpace(check.command), err)
		}
		if got != check.want {
			return fmt.Errorf("%q got %q, want %q", strings.TrimSpace(check.command), got, check.want)
		}
	}

	return waitForLogEvidence(logFile, logOffset, timeout)
}

func respCommand(args ...string) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&builder, "$%d\r\n%s\r\n", len(arg), arg)
	}
	return builder.String()
}

func configGet(conn net.Conn, reader *bufio.Reader, key string) (string, error) {
	if _, err := io.WriteString(conn, respCommand("CONFIG", "GET", key)); err != nil {
		return "", fmt.Errorf("write CONFIG GET %s: %w", key, err)
	}
	got, err := readRESP(reader)
	if err != nil {
		return "", fmt.Errorf("read CONFIG GET %s: %w", key, err)
	}
	parts := strings.Split(got, "\r\n")
	// *2, $len, key, $len, value, ""
	if len(parts) != 6 || parts[0] != "*2" || parts[2] != key {
		return "", fmt.Errorf("CONFIG GET %s got %q", key, got)
	}
	return parts[4], nil
}

func dialUntil(address string, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
	return nil, fmt.Errorf("dial %s: %w", address, lastErr)
}

func readRESP(reader *bufio.Reader) (string, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	head := string(append([]byte{first}, []byte(line)...))

	switch first {
	case '+', '-', ':':
		return head, nil
	case '$':
		length, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			return "", err
		}
		if length < 0 {
			return head, nil
		}
		body := make([]byte, length+2)
		if _, err := io.ReadFull(reader, body); err != nil {
			return "", err
		}
		return head + string(body), nil
	case '*':
		count, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			return "", err
		}
		if count < 0 {
			return head, nil
		}
		var builder strings.Builder
		builder.WriteString(head)
		for i := 0; i < count; i++ {
			value, err := readRESP(reader)
			if err != nil {
				return "", err
			}
			builder.WriteString(value)
		}
		return builder.String(), nil
	default:
		return "", fmt.Errorf("unknown RESP prefix %q", first)
	}
}

func waitForLogEvidence(logFile string, logOffset int64, timeout time.Duration) error {
	if logFile == "" {
		return nil
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		result, err := inspectLogFile(logFile, logOffset)
		if err == nil && result.hasPing && result.hasSet && result.hasSave && result.hasClose {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}

	result, err := inspectLogFile(logFile, logOffset)
	if err != nil {
		return err
	}
	return fmt.Errorf("log file missing expected events: ping=%t set=%t save=%t close=%t", result.hasPing, result.hasSet, result.hasSave, result.hasClose)
}

type logEvidence struct {
	hasPing  bool
	hasSet   bool
	hasSave  bool
	hasClose bool
}

func inspectLogFile(logFile string, logOffset int64) (logEvidence, error) {
	data, err := os.ReadFile(logFile)
	if err != nil {
		return logEvidence{}, err
	}
	if logOffset > int64(len(data)) {
		return logEvidence{}, fmt.Errorf("log offset %d beyond log size %d; was the log rotated?", logOffset, len(data))
	}
	data = data[logOffset:]

	var evidence logEvidence
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return evidence, fmt.Errorf("invalid JSON log line %q: %w", line, err)
		}
		for key, value := range event {
			if value == nil {
				return evidence, fmt.Errorf("log field %q is JSON null in line %q", key, line)
			}
		}

		eventName, _ := event["event"].(string)
		switch eventName {
		case "start", "shutdown_requested", "startup_failed", "server_failed", "deprecated_flag_ignored", "log_file_setup_failed", "log_file_open_failed":
			return evidence, fmt.Errorf("lifecycle event %q leaked into event log", eventName)
		case "close":
			evidence.hasClose = true
		case "command":
			command, _ := event["command"].(string)
			switch command {
			case "PING":
				evidence.hasPing = true
			case "SET":
				evidence.hasSet = true
			case "SAVE":
				evidence.hasSave = true
			}
		}
	}

	if !evidence.hasPing && !evidence.hasSet && !evidence.hasSave && !evidence.hasClose {
		return evidence, errors.New("no smoke-test log evidence found")
	}
	return evidence, nil
}
