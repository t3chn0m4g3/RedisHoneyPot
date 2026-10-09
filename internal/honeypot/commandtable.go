package honeypot

import (
	"sort"
	"strings"
)

// commandSpec describes a supported command once; COMMAND replies and log
// categories are derived from it.
type commandSpec struct {
	arity    int64
	flags    []string
	firstKey int64
	lastKey  int64
	step     int64
	category string
}

var commandTable = map[string]commandSpec{
	"auth":      {2, []string{"noscript", "loading", "stale", "fast"}, 0, 0, 0, "auth"},
	"bgsave":    {-1, []string{"admin", "noscript"}, 0, 0, 0, "persistence"},
	"client":    {-2, []string{"admin", "noscript", "random", "loading", "stale"}, 0, 0, 0, "recon"},
	"command":   {-1, []string{"loading", "stale"}, 0, 0, 0, "recon"},
	"config":    {-2, []string{"admin", "noscript", "loading", "stale"}, 0, 0, 0, "recon"},
	"dbsize":    {1, []string{"readonly", "fast"}, 0, 0, 0, "read"},
	"del":       {-2, []string{"write"}, 1, -1, 1, "write"},
	"echo":      {2, []string{"fast"}, 0, 0, 0, "session"},
	"exists":    {-2, []string{"readonly", "fast"}, 1, -1, 1, "read"},
	"flushall":  {-1, []string{"write"}, 0, 0, 0, "write"},
	"flushdb":   {-1, []string{"write"}, 0, 0, 0, "write"},
	"get":       {2, []string{"readonly", "fast"}, 1, 1, 1, "read"},
	"info":      {-1, []string{"loading", "stale"}, 0, 0, 0, "recon"},
	"keys":      {2, []string{"readonly", "sort_for_script"}, 1, 1, 1, "read"},
	"mget":      {-2, []string{"readonly", "fast"}, 1, -1, 1, "read"},
	"module":    {-2, []string{"admin", "noscript"}, 0, 0, 0, "module"},
	"ping":      {-1, []string{"stale", "fast"}, 0, 0, 0, "session"},
	"psync":     {3, []string{"admin", "noscript"}, 0, 0, 0, "replication"},
	"quit":      {1, []string{"fast"}, 0, 0, 0, "session"},
	"replconf":  {-1, []string{"admin", "noscript", "loading", "stale"}, 0, 0, 0, "replication"},
	"replicaof": {3, []string{"admin", "noscript", "stale"}, 0, 0, 0, "replication"},
	"role":      {1, []string{"noscript", "loading", "stale", "fast"}, 0, 0, 0, "recon"},
	"save":      {1, []string{"admin", "noscript"}, 0, 0, 0, "persistence"},
	"select":    {2, []string{"loading", "stale", "fast"}, 0, 0, 0, "session"},
	"set":       {-3, []string{"write", "denyoom"}, 1, 1, 1, "write"},
	"slaveof":   {3, []string{"admin", "noscript", "stale"}, 0, 0, 0, "replication"},
	"sync":      {1, []string{"admin", "noscript"}, 0, 0, 0, "replication"},
	"time":      {1, []string{"random", "fast"}, 0, 0, 0, "recon"},
	"ttl":       {2, []string{"readonly", "fast"}, 1, 1, 1, "read"},
	"type":      {2, []string{"readonly", "fast"}, 1, 1, 1, "read"},
}

var supportedCommands = func() []string {
	names := make([]string, 0, len(commandTable))
	for name := range commandTable {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}()

func commandMetadata(name string) RESPValue {
	spec, ok := commandTable[name]
	if !ok {
		return NilArray()
	}
	return Array(
		BulkString(name),
		IntegerReply(spec.arity),
		BulkArray(spec.flags),
		IntegerReply(spec.firstKey),
		IntegerReply(spec.lastKey),
		IntegerReply(spec.step),
	)
}

func commandCategory(command string) string {
	if spec, ok := commandTable[strings.ToLower(command)]; ok {
		return spec.category
	}
	return "unknown"
}
