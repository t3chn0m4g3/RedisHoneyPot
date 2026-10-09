package honeypot

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type commandResult struct {
	reply RESPValue
	close bool
}

func (s *RedisServer) handleCommand(state *clientState, args []string) commandResult {
	name := strings.ToLower(args[0])

	switch name {
	case "ping":
		if len(args) == 1 {
			return ok(SimpleString("PONG"))
		}
		if len(args) == 2 {
			return ok(BulkString(args[1]))
		}
		return ok(wrongArity(name))
	case "echo":
		if len(args) != 2 {
			return ok(wrongArity(name))
		}
		return ok(BulkString(args[1]))
	case "auth":
		if len(args) != 2 && len(args) != 3 {
			return ok(wrongArity(name))
		}
		return ok(SimpleString("OK"))
	case "quit":
		if len(args) != 1 {
			return ok(wrongArity(name))
		}
		return commandResult{reply: SimpleString("OK"), close: true}
	case "info":
		if len(args) > 2 {
			return ok(wrongArity(name))
		}
		section := ""
		if len(args) == 2 {
			section = args[1]
		}
		return ok(BulkString(s.info(section)))
	case "set":
		if len(args) < 3 {
			return ok(wrongArity(name))
		}
		s.store.Set(state.db, args[1], args[2])
		s.runtime.markDirty(1)
		return ok(SimpleString("OK"))
	case "get":
		if len(args) != 2 {
			return ok(wrongArity(name))
		}
		value, exists := s.store.Get(state.db, args[1])
		if exists {
			s.keyspaceHits.Add(1)
			return ok(BulkString(value))
		}
		s.keyspaceMisses.Add(1)
		return ok(NilBulkString())
	case "mget":
		if len(args) < 2 {
			return ok(wrongArity(name))
		}
		items := make([]RESPValue, 0, len(args)-1)
		for _, key := range args[1:] {
			value, exists := s.store.Get(state.db, key)
			if exists {
				s.keyspaceHits.Add(1)
				items = append(items, BulkString(value))
			} else {
				s.keyspaceMisses.Add(1)
				items = append(items, NilBulkString())
			}
		}
		return ok(Array(items...))
	case "del":
		if len(args) < 2 {
			return ok(wrongArity(name))
		}
		deleted := s.store.Del(state.db, args[1:])
		s.runtime.markDirty(int64(deleted))
		return ok(IntegerReply(int64(deleted)))
	case "exists":
		if len(args) < 2 {
			return ok(wrongArity(name))
		}
		return ok(IntegerReply(int64(s.store.Exists(state.db, args[1:]))))
	case "keys":
		if len(args) != 2 {
			return ok(wrongArity(name))
		}
		return ok(BulkArray(s.store.Keys(state.db, args[1])))
	case "type":
		if len(args) != 2 {
			return ok(wrongArity(name))
		}
		if _, exists := s.store.Get(state.db, args[1]); exists {
			return ok(SimpleString("string"))
		}
		return ok(SimpleString("none"))
	case "ttl":
		if len(args) != 2 {
			return ok(wrongArity(name))
		}
		if _, exists := s.store.Get(state.db, args[1]); exists {
			return ok(IntegerReply(-1))
		}
		return ok(IntegerReply(-2))
	case "flushall":
		if len(args) > 2 {
			return ok(wrongArity(name))
		}
		s.runtime.markDirty(int64(s.store.FlushAll()))
		return ok(SimpleString("OK"))
	case "flushdb":
		if len(args) > 2 {
			return ok(wrongArity(name))
		}
		s.runtime.markDirty(int64(s.store.FlushDB(state.db)))
		return ok(SimpleString("OK"))
	case "save":
		if len(args) != 1 {
			return ok(wrongArity(name))
		}
		s.runtime.markSaved()
		return ok(SimpleString("OK"))
	case "bgsave":
		if len(args) > 2 {
			return ok(wrongArity(name))
		}
		s.runtime.markSaved()
		return ok(SimpleString("Background saving started"))
	case "select":
		if len(args) != 2 {
			return ok(wrongArity(name))
		}
		db, err := strconv.Atoi(args[1])
		if err != nil || db < 0 || db > 15 {
			return ok(ErrorReply("ERR DB index is out of range"))
		}
		state.db = db
		return ok(SimpleString("OK"))
	case "dbsize":
		if len(args) != 1 {
			return ok(wrongArity(name))
		}
		return ok(IntegerReply(int64(s.store.Size(state.db))))
	case "config":
		return ok(s.handleConfig(args))
	case "client":
		return ok(s.handleClient(state, args))
	case "command":
		return ok(s.handleCommandCommand(args))
	case "role":
		if len(args) != 1 {
			return ok(wrongArity(name))
		}
		return ok(Array(BulkString("master"), IntegerReply(0), Array()))
	case "time":
		if len(args) != 1 {
			return ok(wrongArity(name))
		}
		now := time.Now()
		return ok(Array(
			BulkString(strconv.FormatInt(now.Unix(), 10)),
			BulkString(strconv.FormatInt(int64(now.Nanosecond()/1000), 10)),
		))
	case "slaveof", "replicaof":
		if len(args) != 3 {
			return ok(wrongArity(name))
		}
		return ok(SimpleString("OK"))
	case "replconf":
		if len(args) < 2 {
			return ok(wrongArity(name))
		}
		return ok(SimpleString("OK"))
	case "psync":
		if len(args) != 3 {
			return ok(wrongArity(name))
		}
		return ok(RawReply("+FULLRESYNC " + s.runtime.masterReplID + " 0\r\n$0\r\n\r\n"))
	case "sync":
		if len(args) != 1 {
			return ok(wrongArity(name))
		}
		return ok(RawReply("+FULLRESYNC " + s.runtime.masterReplID + " 0\r\n$0\r\n\r\n"))
	case "module":
		return ok(s.handleModule(args))
	default:
		return ok(unknownCommand(args))
	}
}

func ok(reply RESPValue) commandResult {
	return commandResult{reply: reply}
}

func wrongArity(command string) RESPValue {
	return ErrorReply("ERR wrong number of arguments for '" + strings.ToLower(command) + "' command")
}

func unknownCommand(args []string) RESPValue {
	if len(args) == 1 {
		return ErrorReply("ERR unknown command '" + args[0] + "', with args beginning with:")
	}
	preview, _ := joinArgsForLog(args[1:], 128)
	return ErrorReply("ERR unknown command '" + args[0] + "', with args beginning with: " + preview)
}

func (s *RedisServer) handleConfig(args []string) RESPValue {
	if len(args) < 2 {
		return wrongArity("config")
	}

	switch strings.ToLower(args[1]) {
	case "get":
		if len(args) != 3 {
			return ErrorReply("ERR Unknown subcommand or wrong number of arguments for 'get'. Try CONFIG HELP.")
		}
		return s.configGet(args[2])
	case "set":
		if len(args) != 4 {
			return ErrorReply("ERR Unknown subcommand or wrong number of arguments for 'set'. Try CONFIG HELP.")
		}
		key := strings.ToLower(args[2])
		s.configMu.Lock()
		s.config[key] = args[3]
		s.configMu.Unlock()
		return SimpleString("OK")
	case "rewrite":
		if len(args) != 2 {
			return ErrorReply("ERR Unknown subcommand or wrong number of arguments for 'rewrite'. Try CONFIG HELP.")
		}
		return SimpleString("OK")
	case "resetstat":
		if len(args) != 2 {
			return ErrorReply("ERR Unknown subcommand or wrong number of arguments for 'resetstat'. Try CONFIG HELP.")
		}
		s.keyspaceHits.Store(0)
		s.keyspaceMisses.Store(0)
		s.protocolErrors.Store(0)
		return SimpleString("OK")
	case "help":
		return BulkArray([]string{
			"CONFIG GET <pattern>",
			"CONFIG SET <directive> <value>",
			"CONFIG RESETSTAT",
			"CONFIG REWRITE",
			"CONFIG HELP",
		})
	default:
		return ErrorReply("ERR Unknown subcommand or wrong number of arguments for '" + args[1] + "'. Try CONFIG HELP.")
	}
}

func (s *RedisServer) configGet(pattern string) RESPValue {
	s.configMu.RLock()
	defer s.configMu.RUnlock()

	keys := make([]string, 0, len(s.config))
	for key := range s.config {
		if stringMatch(pattern, key, true) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	items := make([]RESPValue, 0, len(keys)*2)
	for _, key := range keys {
		items = append(items, BulkString(key), BulkString(s.config[key]))
	}
	return Array(items...)
}

func (s *RedisServer) handleClient(state *clientState, args []string) RESPValue {
	if len(args) < 2 {
		return wrongArity("client")
	}

	switch strings.ToLower(args[1]) {
	case "setname":
		if len(args) != 3 {
			return wrongArity("client|setname")
		}
		state.name = args[2]
		if args[2] == HealthcheckClientName && state.trustedLocal {
			state.suppressLogs = true
		}
		return SimpleString("OK")
	case "setinfo":
		if len(args) != 4 {
			return wrongArity("client|setinfo")
		}
		switch strings.ToLower(args[2]) {
		case "lib-name":
			state.libName = args[3]
		case "lib-ver":
			state.libVersion = args[3]
		}
		return SimpleString("OK")
	case "getname":
		if len(args) != 2 {
			return wrongArity("client|getname")
		}
		if state.name == "" {
			return NilBulkString()
		}
		return BulkString(state.name)
	case "id":
		if len(args) != 2 {
			return wrongArity("client|id")
		}
		return IntegerReply(int64(state.id))
	case "info":
		if len(args) != 2 {
			return wrongArity("client|info")
		}
		return BulkString(s.clientInfo(state))
	case "list":
		if len(args) != 2 {
			return wrongArity("client|list")
		}
		return BulkString(s.clientInfo(state))
	case "help":
		return BulkArray([]string{
			"CLIENT ID",
			"CLIENT INFO",
			"CLIENT LIST",
			"CLIENT GETNAME",
			"CLIENT SETNAME <connection-name>",
			"CLIENT SETINFO <attribute> <value>",
			"CLIENT HELP",
		})
	default:
		return ErrorReply("ERR unknown subcommand '" + args[1] + "'. Try CLIENT HELP.")
	}
}

func (s *RedisServer) clientInfo(state *clientState) string {
	age := int(time.Since(state.connected).Seconds())
	return fmt.Sprintf("id=%d addr=0.0.0.0:0 laddr=%s fd=8 name=%s age=%d idle=0 flags=N db=%d sub=0 psub=0 multi=-1 qbuf=0 qbuf-free=20474 argv-mem=0 obl=0 oll=0 omem=0 tot-mem=37632 events=r cmd=client user=default redir=-1 resp=2 lib-name=%s lib-ver=%s\r\n",
		state.id,
		s.listener.Addr().String(),
		clientInfoValue(state.name),
		age,
		state.db,
		clientInfoValue(state.libName),
		clientInfoValue(state.libVersion),
	)
}

func clientInfoValue(value string) string {
	if value == "" {
		return ""
	}
	return strings.NewReplacer(" ", "_", "\r", "", "\n", "").Replace(value)
}

func (s *RedisServer) handleCommandCommand(args []string) RESPValue {
	if len(args) == 1 {
		items := make([]RESPValue, 0, len(supportedCommands))
		for _, name := range supportedCommands {
			items = append(items, commandMetadata(name))
		}
		return Array(items...)
	}

	switch strings.ToLower(args[1]) {
	case "count":
		if len(args) != 2 {
			return wrongArity("command|count")
		}
		return IntegerReply(int64(len(supportedCommands)))
	case "info":
		if len(args) < 3 {
			return wrongArity("command|info")
		}
		items := make([]RESPValue, 0, len(args)-2)
		for _, name := range args[2:] {
			meta := commandMetadata(strings.ToLower(name))
			if meta.kind == respNilArray {
				items = append(items, NilArray())
			} else {
				items = append(items, meta)
			}
		}
		return Array(items...)
	case "docs":
		return Array()
	case "help":
		return BulkArray([]string{
			"COMMAND",
			"COMMAND COUNT",
			"COMMAND INFO <command-name> [command-name ...]",
			"COMMAND DOCS [command-name ...]",
			"COMMAND HELP",
		})
	default:
		return ErrorReply("ERR unknown subcommand '" + args[1] + "'. Try COMMAND HELP.")
	}
}

func (s *RedisServer) handleModule(args []string) RESPValue {
	if len(args) < 2 {
		return wrongArity("module")
	}

	switch strings.ToLower(args[1]) {
	case "list":
		if len(args) != 2 {
			return wrongArity("module|list")
		}
		items := make([]RESPValue, 0, len(s.profile.SupportedModules))
		for _, module := range s.profile.SupportedModules {
			items = append(items, Array(
				BulkString("name"), BulkString(module),
				BulkString("ver"), IntegerReply(profileModuleVersion(s.profile.Version)),
				BulkString("path"), BulkString("/usr/lib/redis/modules/"+module+".so"),
			))
		}
		return Array(items...)
	case "load", "unload":
		if len(args) < 3 {
			return wrongArity("module|" + strings.ToLower(args[1]))
		}
		return SimpleString("OK")
	case "help":
		return BulkArray([]string{
			"MODULE LIST",
			"MODULE LOAD <path> [arg ...]",
			"MODULE UNLOAD <name>",
			"MODULE HELP",
		})
	default:
		return ErrorReply("ERR unknown subcommand '" + args[1] + "'. Try MODULE HELP.")
	}
}

func profileModuleVersion(version string) int64 {
	parts := strings.Split(version, ".")
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	patch, _ := strconv.Atoi(parts[2])
	return int64(major*10000 + minor*100 + patch)
}
