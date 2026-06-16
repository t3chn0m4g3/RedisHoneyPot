package honeypot

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

func TestRESPEncoder(t *testing.T) {
	tests := []struct {
		name string
		in   RESPValue
		want string
	}{
		{name: "simple", in: SimpleString("OK"), want: "+OK\r\n"},
		{name: "error", in: ErrorReply("ERR no"), want: "-ERR no\r\n"},
		{name: "integer", in: IntegerReply(42), want: ":42\r\n"},
		{name: "bulk", in: BulkString("value"), want: "$5\r\nvalue\r\n"},
		{name: "nil bulk", in: NilBulkString(), want: "$-1\r\n"},
		{name: "nil array", in: NilArray(), want: "*-1\r\n"},
		{name: "array", in: Array(BulkString("key"), IntegerReply(1)), want: "*2\r\n$3\r\nkey\r\n:1\r\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.in.Bytes()); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadInlineCommand(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("SET \"user name\" 'marco'\\ value\r\n"))
	got, err := ReadCommand(reader, ParserConfig{})
	if err != nil {
		t.Fatalf("ReadCommand returned error: %v", err)
	}

	want := []string{"SET", "user name", "marco value"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestReadArrayCommand(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n"))
	got, err := ReadCommand(reader, ParserConfig{})
	if err != nil {
		t.Fatalf("ReadCommand returned error: %v", err)
	}

	want := []string{"SET", "key", "value"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestReadCommandRejectsMalformedArray(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("*2\r\n$3\r\nGET\r\n+bad\r\n"))
	_, err := ReadCommand(reader, ParserConfig{})
	if err == nil {
		t.Fatal("expected malformed array to fail")
	}
}

func TestReadCommandRejectsOversizedBulkString(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("*2\r\n$3\r\nGET\r\n$5\r\nvalue\r\n"))
	_, err := ReadCommand(reader, ParserConfig{MaxBulkBytes: 4})
	if err == nil || !strings.Contains(err.Error(), "bulk string exceeds limit") {
		t.Fatalf("got error %v, want bulk string limit error", err)
	}
}

func TestReadCommandTreatsEmptyInlineAsEmptyCommand(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("\r\n"))
	_, err := ReadCommand(reader, ParserConfig{})
	if !errors.Is(err, errEmptyCommand) {
		t.Fatalf("got %v, want errEmptyCommand", err)
	}
}
