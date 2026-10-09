package honeypot

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

var errEmptyCommand = errors.New("empty command")

type ParserConfig struct {
	MaxBulkBytes    int
	MaxInlineBytes  int
	MaxArrayElems   int
	MaxCommandBytes int
}

type respKind int

const (
	respSimple respKind = iota
	respError
	respInteger
	respBulk
	respNilBulk
	respNilArray
	respArray
	respRaw
)

type RESPValue struct {
	kind  respKind
	str   string
	num   int64
	array []RESPValue
}

// lineSafe mirrors Redis, which replaces CR and LF in status and error replies
// with spaces so client-controlled text cannot break the reply framing.
var lineSafe = strings.NewReplacer("\r", " ", "\n", " ")

func SimpleString(value string) RESPValue {
	return RESPValue{kind: respSimple, str: lineSafe.Replace(value)}
}

func ErrorReply(value string) RESPValue {
	return RESPValue{kind: respError, str: lineSafe.Replace(value)}
}

func IntegerReply(value int64) RESPValue {
	return RESPValue{kind: respInteger, num: value}
}

func BulkString(value string) RESPValue {
	return RESPValue{kind: respBulk, str: value}
}

func NilBulkString() RESPValue {
	return RESPValue{kind: respNilBulk}
}

func NilArray() RESPValue {
	return RESPValue{kind: respNilArray}
}

func Array(values ...RESPValue) RESPValue {
	return RESPValue{kind: respArray, array: values}
}

func BulkArray(values []string) RESPValue {
	items := make([]RESPValue, 0, len(values))
	for _, value := range values {
		items = append(items, BulkString(value))
	}
	return Array(items...)
}

func RawReply(value string) RESPValue {
	return RESPValue{kind: respRaw, str: value}
}

func (v RESPValue) Bytes() []byte {
	var buf bytes.Buffer
	v.writeTo(&buf)
	return buf.Bytes()
}

func (v RESPValue) Class() string {
	switch v.kind {
	case respSimple:
		return "simple_string"
	case respError:
		return "error"
	case respInteger:
		return "integer"
	case respBulk:
		return "bulk_string"
	case respNilBulk:
		return "nil_bulk_string"
	case respNilArray:
		return "nil_array"
	case respArray:
		return "array"
	case respRaw:
		return "raw"
	default:
		return "unknown"
	}
}

func (v RESPValue) writeTo(buf *bytes.Buffer) {
	switch v.kind {
	case respSimple:
		buf.WriteByte('+')
		buf.WriteString(v.str)
		buf.WriteString("\r\n")
	case respError:
		buf.WriteByte('-')
		buf.WriteString(v.str)
		buf.WriteString("\r\n")
	case respInteger:
		buf.WriteByte(':')
		buf.WriteString(strconv.FormatInt(v.num, 10))
		buf.WriteString("\r\n")
	case respBulk:
		buf.WriteByte('$')
		buf.WriteString(strconv.Itoa(len(v.str)))
		buf.WriteString("\r\n")
		buf.WriteString(v.str)
		buf.WriteString("\r\n")
	case respNilBulk:
		buf.WriteString("$-1\r\n")
	case respNilArray:
		buf.WriteString("*-1\r\n")
	case respArray:
		buf.WriteByte('*')
		buf.WriteString(strconv.Itoa(len(v.array)))
		buf.WriteString("\r\n")
		for _, item := range v.array {
			item.writeTo(buf)
		}
	case respRaw:
		buf.WriteString(v.str)
	}
}

func ReadCommand(reader *bufio.Reader, config ParserConfig) ([]string, error) {
	applyParserDefaults(&config)

	first, err := reader.Peek(1)
	if err != nil {
		return nil, err
	}
	if first[0] == '*' {
		return readArrayCommand(reader, config)
	}
	return readInlineCommand(reader, config)
}

func applyParserDefaults(config *ParserConfig) {
	if config.MaxBulkBytes <= 0 {
		config.MaxBulkBytes = defaultMaxBulkBytes
	}
	if config.MaxInlineBytes <= 0 {
		config.MaxInlineBytes = defaultMaxInlineBytes
	}
	if config.MaxArrayElems <= 0 {
		config.MaxArrayElems = defaultMaxArrayElems
	}
	if config.MaxCommandBytes <= 0 {
		config.MaxCommandBytes = defaultMaxCommandSize
	}
}

func readArrayCommand(reader *bufio.Reader, config ParserConfig) ([]string, error) {
	line, err := readLine(reader, 64, false)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("expected array header")
	}

	count, err := strconv.Atoi(line[1:])
	if err != nil || count < 0 {
		return nil, fmt.Errorf("invalid array length")
	}
	if count == 0 {
		return nil, errEmptyCommand
	}
	if count > config.MaxArrayElems {
		return nil, fmt.Errorf("array length exceeds limit")
	}

	args := make([]string, 0, count)
	total := 0
	for i := 0; i < count; i++ {
		header, err := readLine(reader, 64, false)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(header, "$") {
			return nil, fmt.Errorf("expected bulk string")
		}

		size, err := strconv.Atoi(header[1:])
		if err != nil || size < 0 {
			return nil, fmt.Errorf("invalid bulk string length")
		}
		if size > config.MaxBulkBytes {
			return nil, fmt.Errorf("bulk string exceeds limit")
		}
		total += size
		if total > config.MaxCommandBytes {
			return nil, fmt.Errorf("command exceeds limit")
		}

		data := make([]byte, size+2)
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, err
		}
		if data[size] != '\r' || data[size+1] != '\n' {
			return nil, fmt.Errorf("bulk string missing CRLF")
		}
		args = append(args, string(data[:size]))
	}

	return args, nil
}

func readInlineCommand(reader *bufio.Reader, config ParserConfig) ([]string, error) {
	line, err := readLine(reader, config.MaxInlineBytes, true)
	if err != nil {
		return nil, err
	}
	fields, err := splitInlineCommand(line)
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, errEmptyCommand
	}
	return fields, nil
}

// readLine reads one protocol line. Multibulk headers require CRLF; inline
// commands, like in Redis, accept a bare LF and drop an optional trailing CR.
func readLine(reader *bufio.Reader, limit int, allowBareLF bool) (string, error) {
	var buf []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > limit {
			return "", fmt.Errorf("line exceeds limit")
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return "", err
		}
		break
	}
	if allowBareLF {
		line := buf[:len(buf)-1]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		return string(line), nil
	}
	if len(buf) < 2 || buf[len(buf)-2] != '\r' || buf[len(buf)-1] != '\n' {
		return "", fmt.Errorf("line missing CRLF")
	}
	return string(buf[:len(buf)-2]), nil
}

func splitInlineCommand(line string) ([]string, error) {
	var fields []string
	var current strings.Builder
	var quote rune
	escaped := false
	tokenStarted := false

	for _, r := range line {
		if escaped {
			switch r {
			case 'n':
				current.WriteByte('\n')
			case 'r':
				current.WriteByte('\r')
			case 't':
				current.WriteByte('\t')
			default:
				current.WriteRune(r)
			}
			escaped = false
			tokenStarted = true
			continue
		}

		if quote != 0 {
			if r == '\\' {
				escaped = true
				continue
			}
			if r == quote {
				quote = 0
				continue
			}
			current.WriteRune(r)
			continue
		}

		switch {
		case r == '\'' || r == '"':
			quote = r
			tokenStarted = true
		case r == '\\':
			escaped = true
		case r == ' ' || r == '\t':
			if tokenStarted {
				fields = append(fields, current.String())
				current.Reset()
				tokenStarted = false
			}
		default:
			current.WriteRune(r)
			tokenStarted = true
		}
	}

	if escaped {
		return nil, fmt.Errorf("unfinished escape sequence")
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quoted string")
	}
	if tokenStarted {
		fields = append(fields, current.String())
	}
	return fields, nil
}
