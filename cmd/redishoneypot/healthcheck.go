package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"RedisHoneyPot/internal/honeypot"
)

func runHealthcheck(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var address string
	var network string
	var timeout time.Duration
	fs.StringVar(&address, "addr", "127.0.0.1:6379", "RedisHoneyPot address")
	fs.StringVar(&network, "proto", "tcp", "network protocol")
	fs.DurationVar(&timeout, "timeout", 2*time.Second, "healthcheck timeout")

	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 2
	}

	conn, err := net.DialTimeout(network, address, timeout)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "healthcheck dial failed: %v\n", err)
		return 1
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	reader := bufio.NewReader(conn)
	commands := []struct {
		write string
		want  string
	}{
		{"CLIENT SETNAME " + honeypot.HealthcheckClientName + "\r\n", "+OK"},
		{"PING\r\n", "+PONG"},
		{"QUIT\r\n", "+OK"},
	}

	for _, command := range commands {
		if _, err := io.WriteString(conn, command.write); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "healthcheck write failed: %v\n", err)
			return 1
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "healthcheck read failed: %v\n", err)
			return 1
		}
		line = strings.TrimRight(line, "\r\n")
		if line != command.want {
			_, _ = fmt.Fprintf(os.Stderr, "healthcheck unexpected response: got %q want %q\n", line, command.want)
			return 1
		}
	}

	return 0
}
