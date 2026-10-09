package honeypot

import (
	"sort"
	"strings"
	"sync"
)

const maxErrorStatsEntries = 128

type commandStat struct {
	calls    uint64
	usec     uint64
	rejected uint64
	failed   uint64
}

// serverStats feeds INFO commandstats/errorstats/latencystats with the
// sessions' real activity, using Redis' naming (subcommands as "config|get").
type serverStats struct {
	mu          sync.Mutex
	commands    map[string]*commandStat
	errors      map[string]uint64
	totalErrors uint64
}

func newServerStats() *serverStats {
	return &serverStats{commands: make(map[string]*commandStat), errors: make(map[string]uint64)}
}

func (st *serverStats) record(statName string, usec int64, reply RESPValue, rejected bool) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if reply.kind == respError {
		prefix, _, _ := strings.Cut(reply.str, " ")
		if _, ok := st.errors[prefix]; ok || len(st.errors) < maxErrorStatsEntries {
			st.errors[prefix]++
		}
		st.totalErrors++
	}
	if statName == "" {
		return
	}
	stat := st.commands[statName]
	if stat == nil {
		stat = &commandStat{}
		st.commands[statName] = stat
	}
	if rejected {
		stat.rejected++
		return
	}
	stat.calls++
	if usec < 1 {
		usec = 1
	}
	stat.usec += uint64(usec)
	if reply.kind == respError {
		stat.failed++
	}
}

func (st *serverStats) reset() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.commands = make(map[string]*commandStat)
	st.errors = make(map[string]uint64)
	st.totalErrors = 0
}

type namedCommandStat struct {
	name string
	commandStat
}

func (st *serverStats) snapshot() (commands []namedCommandStat, errors map[string]uint64, totalErrors uint64) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for name, stat := range st.commands {
		commands = append(commands, namedCommandStat{name: name, commandStat: *stat})
	}
	sort.Slice(commands, func(i, j int) bool { return commands[i].name < commands[j].name })
	errors = make(map[string]uint64, len(st.errors))
	for prefix, count := range st.errors {
		errors[prefix] = count
	}
	return commands, errors, st.totalErrors
}
