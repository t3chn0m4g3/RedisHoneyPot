package honeypot

import (
	"bytes"
	"fmt"
	"strconv"
)

// respNode is a parsed RESP2/RESP3 value that keeps its raw encoding, so
// recorded persona data can be replayed byte-for-byte or partially re-encoded.
type respNode struct {
	kind     byte
	str      string
	num      int64
	children []respNode
	raw      []byte
}

func parseRESP(data []byte) (respNode, int, error) {
	end := bytes.Index(data, []byte("\r\n"))
	if end < 1 {
		return respNode{}, 0, fmt.Errorf("truncated RESP line")
	}
	node := respNode{kind: data[0]}
	body := string(data[1:end])
	pos := end + 2

	switch node.kind {
	case '+', '-', ',', '#', '(', '_':
		node.str = body
	case ':':
		n, err := strconv.ParseInt(body, 10, 64)
		if err != nil {
			return respNode{}, 0, err
		}
		node.num = n
	case '$', '=', '!':
		size, err := strconv.Atoi(body)
		if err != nil {
			return respNode{}, 0, err
		}
		if size >= 0 {
			if len(data) < pos+size+2 {
				return respNode{}, 0, fmt.Errorf("truncated bulk")
			}
			node.str = string(data[pos : pos+size])
			pos += size + 2
		} else {
			node.num = -1
		}
	case '*', '~', '>', '%', '|':
		count, err := strconv.Atoi(body)
		if err != nil {
			return respNode{}, 0, err
		}
		if count < 0 {
			node.num = -1
			break
		}
		if node.kind == '%' || node.kind == '|' {
			count *= 2
		}
		for i := 0; i < count; i++ {
			child, n, err := parseRESP(data[pos:])
			if err != nil {
				return respNode{}, 0, err
			}
			node.children = append(node.children, child)
			pos += n
		}
	default:
		return respNode{}, 0, fmt.Errorf("unknown RESP type %q", node.kind)
	}
	node.raw = data[:pos]
	return node, pos, nil
}

// toValue converts a parsed node back into an encodable value. Arrays of
// alternating key/value pairs can be turned into maps with asMap.
func (n respNode) toValue() RESPValue {
	switch n.kind {
	case '+':
		return SimpleString(n.str)
	case '-':
		return ErrorReply(n.str)
	case ':':
		return IntegerReply(n.num)
	case '$':
		if n.num == -1 {
			return NilBulkString()
		}
		return BulkString(n.str)
	case '*':
		if n.num == -1 {
			return NilArray()
		}
		items := make([]RESPValue, 0, len(n.children))
		for _, child := range n.children {
			items = append(items, child.toValue())
		}
		return Array(items...)
	default:
		return RawReply(string(n.raw))
	}
}
