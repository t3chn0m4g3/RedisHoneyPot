package honeypot

import "strings"

// commandCategories groups commands for the command_category log field.
// Command metadata itself (arity, flags, COMMAND output) comes from the
// persona's recorded COMMAND table.
var commandCategories = map[string]string{
	"auth": "auth", "hello": "auth",
	"bgsave": "persistence", "save": "persistence", "lastsave": "persistence",
	"client": "recon", "command": "recon", "config": "recon", "info": "recon",
	"role": "recon", "time": "recon", "debug": "recon",
	"dbsize": "read", "exists": "read", "get": "read", "keys": "read", "mget": "read",
	"scan": "read", "ttl": "read", "pttl": "read", "type": "read",
	"del": "write", "flushall": "write", "flushdb": "write", "set": "write",
	"expire": "write", "pexpire": "write", "persist": "write",
	"echo": "session", "ping": "session", "quit": "session", "select": "session",
	"module": "module",
	"psync":  "replication", "replconf": "replication", "replicaof": "replication",
	"slaveof": "replication", "sync": "replication",
	"eval": "scripting", "eval_ro": "scripting", "evalsha": "scripting",
	"evalsha_ro": "scripting", "script": "scripting", "function": "scripting",
	"fcall": "scripting", "fcall_ro": "scripting",
}

func commandCategory(command string) string {
	if category, ok := commandCategories[strings.ToLower(command)]; ok {
		return category
	}
	return "unknown"
}
