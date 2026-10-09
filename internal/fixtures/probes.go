package fixtures

import (
	"encoding/base64"
	"unicode/utf8"
)

// Mode tells the fidelity test how strictly a recorded reply must match.
type Mode string

const (
	// Exact compares reply bytes.
	Exact Mode = "exact"
	// Shape compares RESP types and aggregate sizes, not scalar contents.
	Shape Mode = "shape"
	// Type compares only the RESP type of the reply.
	Type Mode = "type"
	// Info compares INFO section headers and field names in order.
	Info Mode = "info"
	// ClientInfo compares CLIENT INFO/LIST field names in order.
	ClientInfo Mode = "clientinfo"
	// Closed expects the server to close the connection without replying.
	Closed Mode = "closed"
	// Sync compares a PSYNC/SYNC handshake structure and the RDB header.
	Sync Mode = "sync"
)

// Probe is one request sent to a real server by the recorder and replayed
// against the honeypot by the fidelity tests.
type Probe struct {
	Name    string
	Send    []byte
	Mode    Mode
	NewConn bool
}

func inline(line string) []byte { return []byte(line + "\r\n") }

// Probes run in order on one connection unless NewConn is set. The sequence
// never makes a real server connect outwards (no SLAVEOF <host>) and never
// executes anything beyond trivial Lua.
var Probes = []Probe{
	{Name: "ping", Send: inline("PING"), Mode: Exact},
	{Name: "ping_arg", Send: Command("PING", "hello"), Mode: Exact},
	{Name: "echo_arity", Send: Command("ECHO"), Mode: Exact},
	{Name: "get_arity", Send: Command("GET"), Mode: Exact},
	{Name: "unknown_noargs", Send: Command("FOOBAR"), Mode: Exact},
	{Name: "unknown_args", Send: Command("FOOBAR", "a", "b c"), Mode: Exact},
	{Name: "unknown_inline", Send: inline("FOOBAR a b"), Mode: Exact},
	{Name: "config_unknown_sub", Send: Command("CONFIG", "FOO"), Mode: Exact},
	{Name: "client_unknown_sub", Send: Command("CLIENT", "FOO"), Mode: Exact},
	{Name: "command_unknown_sub", Send: Command("COMMAND", "FOO"), Mode: Exact},
	{Name: "module_unknown_sub", Send: Command("MODULE", "FOO"), Mode: Exact},
	{Name: "auth_nopass", Send: Command("AUTH", "secret"), Mode: Exact},
	{Name: "auth_user", Send: Command("AUTH", "default", "secret"), Mode: Exact},
	{Name: "hello_noargs", Send: Command("HELLO"), Mode: Shape},
	{Name: "hello_3", Send: Command("HELLO", "3"), Mode: Shape},
	{Name: "hello_back_2", Send: Command("HELLO", "2"), Mode: Shape},
	{Name: "hello_bad", Send: Command("HELLO", "4"), Mode: Exact},
	{Name: "client_setname", Send: Command("CLIENT", "SETNAME", "probe"), Mode: Exact},
	{Name: "client_getname", Send: Command("CLIENT", "GETNAME"), Mode: Exact},
	{Name: "client_setinfo", Send: Command("CLIENT", "SETINFO", "LIB-NAME", "probe"), Mode: Exact},
	{Name: "client_id", Send: Command("CLIENT", "ID"), Mode: Type},
	{Name: "client_info", Send: Command("CLIENT", "INFO"), Mode: ClientInfo},
	{Name: "client_list", Send: Command("CLIENT", "LIST"), Mode: ClientInfo},
	{Name: "command_count", Send: Command("COMMAND", "COUNT"), Mode: Exact},
	{Name: "command_info_get", Send: Command("COMMAND", "INFO", "get"), Mode: Exact},
	{Name: "command_info_unknown", Send: Command("COMMAND", "INFO", "nosuchcmd"), Mode: Exact},
	{Name: "command_docs_get", Send: Command("COMMAND", "DOCS", "get"), Mode: Exact},
	{Name: "info_default", Send: Command("INFO"), Mode: Info},
	{Name: "info_server", Send: Command("INFO", "server"), Mode: Info},
	{Name: "info_all", Send: Command("INFO", "all"), Mode: Info},
	{Name: "info_everything", Send: Command("INFO", "everything"), Mode: Info},
	{Name: "info_multi", Send: Command("INFO", "server", "clients"), Mode: Info},
	{Name: "info_keyspace_empty", Send: Command("INFO", "keyspace"), Mode: Exact},
	{Name: "info_unknown_section", Send: Command("INFO", "nosuchsection"), Mode: Exact},
	{Name: "config_get_dir", Send: Command("CONFIG", "GET", "dir"), Mode: Shape},
	{Name: "config_get_protected", Send: Command("CONFIG", "GET", "enable-protected-configs"), Mode: Exact},
	{Name: "config_get_module_cmd", Send: Command("CONFIG", "GET", "enable-module-command"), Mode: Exact},
	{Name: "config_get_multi", Send: Command("CONFIG", "GET", "port", "databases"), Mode: Exact},
	{Name: "config_set_unknown", Send: Command("CONFIG", "SET", "nosuchparam", "1"), Mode: Exact},
	{Name: "config_set_arity", Send: Command("CONFIG", "SET", "dir"), Mode: Exact},
	{Name: "config_set_dir_missing", Send: Command("CONFIG", "SET", "dir", "/nonexistent/probe"), Mode: Exact},
	{Name: "config_set_dir", Send: Command("CONFIG", "SET", "dir", "/tmp"), Mode: Exact},
	{Name: "config_set_dbfilename", Send: Command("CONFIG", "SET", "dbfilename", "probe.rdb"), Mode: Exact},
	{Name: "config_set_dbfilename_path", Send: Command("CONFIG", "SET", "dbfilename", "../probe.rdb"), Mode: Exact},
	{Name: "set_basic", Send: Command("SET", "k", "v"), Mode: Exact},
	{Name: "set_nx_existing", Send: Command("SET", "k", "v2", "NX"), Mode: Exact},
	{Name: "set_xx_missing", Send: Command("SET", "k2", "v", "XX"), Mode: Exact},
	{Name: "set_get", Send: Command("SET", "k", "v3", "GET"), Mode: Exact},
	{Name: "set_ex", Send: Command("SET", "k4", "v", "EX", "100"), Mode: Exact},
	{Name: "set_bad_expire", Send: Command("SET", "k5", "v", "EX", "0"), Mode: Exact},
	{Name: "set_syntax", Send: Command("SET", "k", "v", "BOGUS"), Mode: Exact},
	{Name: "ttl_ex", Send: Command("TTL", "k4"), Mode: Type},
	{Name: "ttl_persistent", Send: Command("TTL", "k"), Mode: Exact},
	{Name: "type_string", Send: Command("TYPE", "k"), Mode: Exact},
	{Name: "type_none", Send: Command("TYPE", "missing"), Mode: Exact},
	{Name: "expire", Send: Command("EXPIRE", "k", "1000"), Mode: Exact},
	{Name: "scan", Send: Command("SCAN", "0"), Mode: Shape},
	{Name: "dbsize", Send: Command("DBSIZE"), Mode: Exact},
	{Name: "info_keyspace", Send: Command("INFO", "keyspace"), Mode: Exact},
	{Name: "info_keysizes", Send: Command("INFO", "keysizes"), Mode: Exact},
	{Name: "info_errorstats", Send: Command("INFO", "errorstats"), Mode: Info},
	{Name: "info_replication", Send: Command("INFO", "replication"), Mode: Info},
	{Name: "select_bad", Send: Command("SELECT", "99"), Mode: Exact},
	{Name: "save", Send: Command("SAVE"), Mode: Exact},
	{Name: "module_list", Send: Command("MODULE", "LIST"), Mode: Shape},
	{Name: "module_load_missing", Send: Command("MODULE", "LOAD", "/tmp/nonexistent.so"), Mode: Exact},
	{Name: "eval_return_int", Send: Command("EVAL", "return 1", "0"), Mode: Exact},
	{Name: "eval_return_str", Send: Command("EVAL", "return 'x'", "0"), Mode: Exact},
	{Name: "eval_arity", Send: Command("EVAL", "return 1"), Mode: Exact},
	{Name: "eval_numkeys_bad", Send: Command("EVAL", "return 1", "5"), Mode: Exact},
	{Name: "script_load", Send: Command("SCRIPT", "LOAD", "return 'x'"), Mode: Exact},
	{Name: "evalsha_ok", Send: Command("EVALSHA", "573cd020e2fc941d149285df8b681959190edd09", "0"), Mode: Exact},
	{Name: "evalsha_missing", Send: Command("EVALSHA", "0000000000000000000000000000000000000000", "0"), Mode: Exact},
	{Name: "script_exists", Send: Command("SCRIPT", "EXISTS", "573cd020e2fc941d149285df8b681959190edd09", "0000000000000000000000000000000000000000"), Mode: Exact},
	{Name: "function_list", Send: Command("FUNCTION", "LIST"), Mode: Exact},
	{Name: "role", Send: Command("ROLE"), Mode: Shape},
	{Name: "replicaof_no_one", Send: Command("REPLICAOF", "NO", "ONE"), Mode: Exact},
	{Name: "time", Send: Command("TIME"), Mode: Shape},
	{Name: "quit", Send: Command("QUIT"), Mode: Exact},

	{Name: "proto_bad_multibulk", Send: []byte("*abc\r\n"), Mode: Exact, NewConn: true},
	{Name: "proto_expected_dollar", Send: []byte("*1\r\nfoo\r\n"), Mode: Exact, NewConn: true},
	{Name: "proto_bad_bulk_len", Send: []byte("*1\r\n$abc\r\n"), Mode: Exact, NewConn: true},
	{Name: "proto_unbalanced_quotes", Send: inline(`SET "a`), Mode: Exact, NewConn: true},
	{Name: "http_post", Send: []byte("POST / HTTP/1.1\r\nHost: probe\r\n\r\n"), Mode: Closed, NewConn: true},
	{Name: "http_host_line", Send: []byte("Host: probe\r\n"), Mode: Closed, NewConn: true},
	{Name: "psync", Send: Command("PSYNC", "?", "-1"), Mode: Sync, NewConn: true},
}

// Recorded is one probe result as stored in testdata. Replies that are not
// valid UTF-8 (RDB payloads) are stored base64-encoded, because JSON would
// otherwise replace invalid bytes.
type Recorded struct {
	Name        string `json:"name"`
	Reply       string `json:"reply,omitempty"`
	ReplyBase64 string `json:"reply_base64,omitempty"`
	Closed      bool   `json:"closed,omitempty"`
}

// NewRecorded stores reply losslessly.
func NewRecorded(name string, reply []byte, closed bool) Recorded {
	if utf8.Valid(reply) {
		return Recorded{Name: name, Reply: string(reply), Closed: closed}
	}
	return Recorded{Name: name, ReplyBase64: base64.StdEncoding.EncodeToString(reply), Closed: closed}
}

// Bytes returns the recorded reply bytes.
func (r Recorded) Bytes() []byte {
	if r.ReplyBase64 != "" {
		data, err := base64.StdEncoding.DecodeString(r.ReplyBase64)
		if err == nil {
			return data
		}
	}
	return []byte(r.Reply)
}
