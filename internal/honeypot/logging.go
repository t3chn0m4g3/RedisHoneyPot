package honeypot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	maxLoggedArgsBytes    = 512
	maxLoggedPayloadBytes = 8192
)

func NewJSONLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Value.Kind() == slog.KindAny && attr.Value.Any() == nil {
				return slog.Attr{}
			}
			switch attr.Key {
			case slog.TimeKey:
				attr.Key = "timestamp"
				attr.Value = slog.StringValue(formatLogTime(attr.Value.Time()))
			case slog.MessageKey:
				attr.Key = "message"
			case slog.LevelKey:
				attr.Value = slog.StringValue(attr.Value.String())
			}
			return attr
		},
	}))
}

func (s *RedisServer) logConnect(state *clientState, conn net.Conn) {
	attrs := s.baseLogAttrs("connect", state, conn, time.Time{})
	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "connect", attrs...)
}

func (s *RedisServer) logProtocolError(state *clientState, conn net.Conn, err error) {
	attrs := s.baseLogAttrs("protocol_error", state, conn, time.Time{})
	attrs = append(attrs,
		slog.String("error", err.Error()),
		slog.Int("max_bulk_bytes", s.options.MaxBulkBytes),
		slog.Int("max_inline_bytes", s.options.MaxInlineBytes),
		slog.Int("max_array_elems", s.options.MaxArrayElems),
	)
	s.logger.LogAttrs(context.Background(), slog.LevelWarn, "protocol_error", attrs...)
}

func (s *RedisServer) logCommand(state *clientState, conn net.Conn, args []string, result commandResult, responseBytes int) {
	attrs := s.baseLogAttrs("command", state, conn, time.Time{})
	command := strings.ToUpper(args[0])
	logArgs := redactedArgsForLog(args)

	attrs = append(attrs,
		slog.Int("redis_db", state.db),
		slog.String("command", command),
		slog.String("command_category", commandCategory(command)),
		slog.Int("arg_count", len(args)-1),
		slog.String("response_class", result.reply.Class()),
		slog.Int("response_bytes", responseBytes),
		slog.String("outcome", commandOutcome(result)),
		slog.Bool("close_after_command", result.close),
	)
	if len(logArgs) > 1 {
		argsText, argsTruncated := joinArgsForLog(logArgs[1:], maxLoggedArgsBytes)
		attrs = append(attrs,
			slog.String("args_text", argsText),
			slog.Bool("args_truncated", argsTruncated),
			slog.String("args_sha256", hashArgs(args[1:])),
		)
	}
	attrs = append(attrs, commandAnalysisAttrs(args)...)

	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "command", attrs...)
}

func (s *RedisServer) logClose(state *clientState, conn net.Conn, endedAt time.Time) {
	attrs := s.baseLogAttrs("close", state, conn, endedAt)
	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "close", attrs...)
}

func (s *RedisServer) baseLogAttrs(event string, state *clientState, conn net.Conn, sessionEnd time.Time) []slog.Attr {
	srcIP, srcPort := splitAddr(conn.RemoteAddr())
	destIP, destPort := splitAddr(conn.LocalAddr())

	now := time.Now()
	elapsedUntil := now
	if !sessionEnd.IsZero() {
		elapsedUntil = sessionEnd
	}
	elapsed := elapsedUntil.Sub(state.connected)
	if elapsed < 0 {
		elapsed = 0
	}

	attrs := []slog.Attr{
		slog.String("event", event),
		slog.String("protocol", "redis"),
		slog.String("network", s.options.Network),
		slog.String("profile", s.profile.Name),
		slog.String("session_id", state.sessionID),
		slog.Uint64("client_id", state.id),
		slog.String("src_ip", srcIP),
		slog.Int("src_port", srcPort),
		slog.String("dest_ip", destIP),
		slog.Int("dest_port", destPort),
		slog.String("session_start", formatLogTime(state.connected)),
		slog.Float64("session_duration", elapsed.Seconds()),
		slog.Int64("session_duration_ms", elapsed.Milliseconds()),
	}
	if !sessionEnd.IsZero() {
		attrs = append(attrs, slog.String("session_end", formatLogTime(sessionEnd)))
	}
	attrs = appendNonEmptyStringAttr(attrs, "client_name", state.name)
	attrs = appendNonEmptyStringAttr(attrs, "client_library_name", state.libName)
	attrs = appendNonEmptyStringAttr(attrs, "client_library_version", state.libVersion)
	attrs = appendNonEmptyStringAttr(attrs, "user_agent", state.userAgent())

	return attrs
}

func appendNonEmptyStringAttr(attrs []slog.Attr, key string, value string) []slog.Attr {
	if value == "" {
		return attrs
	}
	return append(attrs, slog.String(key, value))
}

func formatLogTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func splitAddr(addr net.Addr) (string, int) {
	if addr == nil {
		return "", 0
	}
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), 0
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return host, 0
	}
	return host, port
}

func joinArgsForLog(args []string, limit int) (string, bool) {
	if len(args) == 0 {
		return "", false
	}

	var builder strings.Builder
	truncated := false
	for i, arg := range args {
		if i > 0 {
			builder.WriteByte(' ')
		}
		remaining := limit - builder.Len()
		if remaining <= 0 {
			truncated = true
			break
		}
		if len(arg) > remaining {
			builder.WriteString(arg[:remaining])
			truncated = true
			break
		}
		builder.WriteString(arg)
	}
	return builder.String(), truncated
}

func redactedArgsForLog(args []string) []string {
	out := append([]string(nil), args...)
	if len(out) == 0 {
		return out
	}

	switch strings.ToLower(out[0]) {
	case "auth":
		if len(out) == 2 {
			out[1] = "[password redacted]"
		}
		if len(out) == 3 {
			out[2] = "[password redacted]"
		}
	case "config":
		if len(out) == 4 && strings.EqualFold(out[1], "set") && strings.EqualFold(out[2], "requirepass") {
			out[3] = "[password redacted]"
		}
	}
	return out
}

func hashArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	sum := sha256.New()
	for _, arg := range args {
		_, _ = sum.Write([]byte(arg))
		_, _ = sum.Write([]byte{0})
	}
	return hex.EncodeToString(sum.Sum(nil))
}

func hashString(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func commandOutcome(result commandResult) string {
	switch {
	case result.silent:
		return "connection_closed"
	case result.reply.kind == respError:
		return "error"
	default:
		return "success"
	}
}

func commandAnalysisAttrs(args []string) []slog.Attr {
	if len(args) == 0 {
		return nil
	}

	command := strings.ToLower(args[0])
	attrs := []slog.Attr{}

	switch command {
	case "get", "set", "type", "ttl":
		if len(args) > 1 {
			attrs = append(attrs, slog.String("key", args[1]), slog.Int("key_count", 1))
		}
		if command == "set" && len(args) > 2 {
			attrs = append(attrs,
				slog.Int("value_size", len(args[2])),
				slog.String("value_sha256", hashString(args[2])),
			)
		}
	case "mget", "del", "exists":
		if len(args) > 1 {
			attrs = append(attrs, slog.String("key", args[1]), slog.Int("key_count", len(args)-1))
		}
	case "keys":
		if len(args) > 1 {
			attrs = append(attrs, slog.String("key_pattern", args[1]))
		}
	case "config":
		if len(args) > 1 {
			attrs = append(attrs, slog.String("config_subcommand", strings.ToLower(args[1])))
		}
		if len(args) > 2 {
			attrs = append(attrs, slog.String("config_key", strings.ToLower(args[2])))
		}
		if len(args) > 3 {
			value := args[3]
			if strings.EqualFold(args[2], "requirepass") {
				value = "[password redacted]"
			}
			valueText, truncated := joinArgsForLog([]string{value}, 128)
			attrs = append(attrs,
				slog.String("config_value", valueText),
				slog.Bool("config_value_truncated", truncated),
				slog.String("config_value_sha256", hashString(args[3])),
			)
		}
	case "auth":
		passwordIndex := 1
		if len(args) == 3 {
			attrs = append(attrs, slog.String("auth_username", args[1]))
			passwordIndex = 2
		}
		if len(args) > passwordIndex {
			attrs = append(attrs,
				slog.Int("auth_password_length", len(args[passwordIndex])),
				slog.String("auth_password_sha256", hashString(args[passwordIndex])),
			)
		}
	case "slaveof", "replicaof":
		if len(args) > 1 {
			attrs = append(attrs, slog.String("replica_host", args[1]))
		}
		if len(args) > 2 {
			attrs = append(attrs, slog.String("replica_port", args[2]))
		}
	case "replconf":
		if len(args) > 1 {
			attrs = append(attrs, slog.String("replconf_key", strings.ToLower(args[1])))
		}
		if len(args) > 2 {
			attrs = append(attrs, slog.String("replconf_value", args[2]))
		}
	case "module":
		if len(args) > 1 {
			attrs = append(attrs, slog.String("module_subcommand", strings.ToLower(args[1])))
		}
		if len(args) > 2 {
			attrs = append(attrs, slog.String("module_path", args[2]))
		}
	case "client":
		if len(args) > 1 {
			attrs = append(attrs, slog.String("client_subcommand", strings.ToLower(args[1])))
		}
	case "eval", "eval_ro":
		if len(args) > 1 {
			attrs = append(attrs, scriptAttrs(args[1])...)
		}
		if len(args) > 2 {
			if numKeys, err := strconv.Atoi(args[2]); err == nil {
				attrs = append(attrs, slog.Int("script_numkeys", numKeys))
			}
		}
	case "evalsha", "evalsha_ro":
		if len(args) > 1 {
			attrs = append(attrs, slog.String("script_sha1", strings.ToLower(args[1])))
		}
	case "script":
		if len(args) > 2 && strings.EqualFold(args[1], "load") {
			attrs = append(attrs, scriptAttrs(args[2])...)
		}
	case "function":
		if len(args) > 2 && strings.EqualFold(args[1], "load") {
			attrs = append(attrs, scriptAttrs(args[len(args)-1])...)
		}
	}

	hint := analysisHint(args)
	if len(attrs) == 0 && hint == genericAnalysisHint(command) {
		return nil
	}
	return append([]slog.Attr{slog.String("analysis_hint", hint)}, attrs...)
}

func analysisHint(args []string) string {
	if len(args) == 0 {
		return ""
	}

	switch strings.ToLower(args[0]) {
	case "config":
		if len(args) >= 4 && strings.EqualFold(args[1], "set") {
			switch strings.ToLower(args[2]) {
			case "dir", "dbfilename":
				return "redis_write_file_attempt"
			case "requirepass":
				return "redis_auth_config_attempt"
			}
		}
	case "set":
		if len(args) >= 3 && strings.Contains(strings.ToLower(args[2]), "ssh-rsa") {
			return "ssh_key_payload"
		}
	case "slaveof", "replicaof", "psync", "sync", "replconf":
		return "redis_replication_attempt"
	case "module":
		if len(args) >= 2 && strings.EqualFold(args[1], "load") {
			return "redis_module_load_attempt"
		}
	case "auth":
		return "redis_auth_attempt"
	case "eval", "eval_ro", "evalsha", "evalsha_ro":
		return "redis_lua_eval"
	case "script":
		if len(args) >= 2 && strings.EqualFold(args[1], "load") {
			return "redis_lua_script_load"
		}
	case "function":
		if len(args) >= 2 && strings.EqualFold(args[1], "load") {
			return "redis_function_load"
		}
	}
	return genericAnalysisHint(args[0])
}

// scriptAttrs describes a Lua script body; the SHA1 matches what EVALSHA
// callers use, so script loads and later calls can be correlated.
func scriptAttrs(body string) []slog.Attr {
	text, truncated := joinArgsForLog([]string{body}, maxLoggedPayloadBytes)
	return []slog.Attr{
		slog.String("script_sha1", scriptSHA1(body)),
		slog.String("script_sha256", hashString(body)),
		slog.Int("script_size", len(body)),
		slog.String("script_text", text),
		slog.Bool("script_truncated", truncated),
	}
}

func genericAnalysisHint(command string) string {
	return fmt.Sprintf("redis_%s", strings.ToLower(command))
}
