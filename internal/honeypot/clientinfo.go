package honeypot

import (
	"strconv"
	"strings"
	"time"
)

// clientInfoLine renders a CLIENT INFO/LIST line from the persona's recorded
// field layout. Only the caller's own connection is listed so the honeypot
// never discloses other visitors' addresses.
func (s *RedisServer) clientInfoLine(state *clientState, subcommand string) string {
	now := time.Now()
	cmd := "client"
	if s.profile.atLeast(7, 0) {
		cmd = "client|" + subcommand
	}
	values := map[string]string{
		"id":          strconv.FormatUint(state.id, 10),
		"addr":        state.remoteAddr,
		"laddr":       state.localAddr,
		"fd":          strconv.Itoa(state.fd),
		"name":        clientInfoValue(state.name),
		"age":         strconv.FormatInt(int64(now.Sub(state.connected).Seconds()), 10),
		"idle":        "0",
		"db":          strconv.Itoa(state.db),
		"cmd":         cmd,
		"resp":        strconv.Itoa(state.proto),
		"lib-name":    clientInfoValue(state.libName),
		"lib-ver":     clientInfoValue(state.libVersion),
		"tot-net-in":  strconv.FormatInt(state.netIn, 10),
		"tot-net-out": strconv.FormatInt(state.netOut, 10),
		"tot-cmds":    strconv.FormatInt(state.commands, 10),
	}

	var line strings.Builder
	for i, field := range s.profile.data.clientFields {
		if i > 0 {
			line.WriteByte(' ')
		}
		value, dynamic := values[field.key]
		if !dynamic {
			value = field.value
		}
		line.WriteString(field.key)
		line.WriteByte('=')
		line.WriteString(value)
	}
	line.WriteByte('\n')
	return line.String()
}

func clientInfoValue(value string) string {
	return strings.NewReplacer(" ", "_", "\r", "", "\n", "").Replace(value)
}
