// Package fixtures holds the probe catalogue shared by the fixture recorder and
// the fidelity tests, plus a raw RESP2/RESP3 reply reader.
package fixtures

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
)

// ReadReply reads exactly one complete RESP2 or RESP3 reply and returns its raw
// bytes, including any RESP3 attribute prefix.
func ReadReply(reader *bufio.Reader) ([]byte, error) {
	var out []byte
	if err := readValue(reader, &out); err != nil {
		return out, err
	}
	return out, nil
}

func readValue(reader *bufio.Reader, out *[]byte) error {
	line, err := reader.ReadBytes('\n')
	*out = append(*out, line...)
	if err != nil {
		return err
	}
	if len(line) < 3 || line[len(line)-2] != '\r' {
		return fmt.Errorf("malformed RESP line %q", line)
	}
	body := string(line[1 : len(line)-2])

	switch line[0] {
	case '+', '-', ':', '_', ',', '#', '(':
		return nil
	case '$', '=', '!':
		size, err := strconv.Atoi(body)
		if err != nil {
			return fmt.Errorf("bad bulk length %q", body)
		}
		if size < 0 {
			return nil
		}
		data := make([]byte, size+2)
		n, err := io.ReadFull(reader, data)
		*out = append(*out, data[:n]...)
		return err
	case '*', '~', '>':
		return readChildren(reader, out, body, 1)
	case '%', '|':
		if err := readChildren(reader, out, body, 2); err != nil {
			return err
		}
		if line[0] == '|' {
			// An attribute map precedes the actual reply.
			return readValue(reader, out)
		}
		return nil
	default:
		return fmt.Errorf("unknown RESP type %q", line[0])
	}
}

func readChildren(reader *bufio.Reader, out *[]byte, body string, factor int) error {
	count, err := strconv.Atoi(body)
	if err != nil {
		return fmt.Errorf("bad aggregate length %q", body)
	}
	for i := 0; i < count*factor; i++ {
		if err := readValue(reader, out); err != nil {
			return err
		}
	}
	return nil
}

// Command encodes args as a RESP2 multibulk request.
func Command(args ...string) []byte {
	out := []byte("*" + strconv.Itoa(len(args)) + "\r\n")
	for _, arg := range args {
		out = append(out, '$')
		out = append(out, strconv.Itoa(len(arg))...)
		out = append(out, "\r\n"...)
		out = append(out, arg...)
		out = append(out, "\r\n"...)
	}
	return out
}
