package honeypot

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

const DefaultProfileName = "legacy6"

type RedisProfile struct {
	Name             string
	Version          string
	GitSHA           string
	BuildID          string
	Mode             string
	OS               string
	ArchBits         string
	MultiplexingAPI  string
	AtomicvarAPI     string
	GCCVersion       string
	Executable       string
	ConfigFile       string
	Allocator        string
	MemoryHuman      string
	UsedMemory       string
	TotalMemory      string
	MaxMemoryPolicy  string
	ModuleLine       string
	Config           map[string]string
	SupportedModules []string
}

func LookupRedisProfile(name string) (RedisProfile, bool) {
	switch strings.ToLower(name) {
	case "", "legacy6", "redis6":
		return legacy6Profile(), true
	case "current8", "redis8":
		return current8Profile(), true
	default:
		return RedisProfile{}, false
	}
}

func legacy6Profile() RedisProfile {
	return RedisProfile{
		Name:            "legacy6",
		Version:         "6.2.18",
		GitSHA:          "00000000",
		BuildID:         "b6f0c8e9dbe4a2b1",
		Mode:            "standalone",
		OS:              "Linux 5.4.0-196-generic x86_64",
		ArchBits:        "64",
		MultiplexingAPI: "epoll",
		AtomicvarAPI:    "atomic-builtin",
		GCCVersion:      "9.4.0",
		Executable:      "/usr/bin/redis-server",
		ConfigFile:      "/etc/redis/redis.conf",
		Allocator:       "jemalloc-5.1.0",
		MemoryHuman:     "1.16M",
		UsedMemory:      "1218840",
		TotalMemory:     "16763367424",
		MaxMemoryPolicy: "noeviction",
		Config: map[string]string{
			"appendonly":       "no",
			"bind":             "0.0.0.0",
			"daemonize":        "yes",
			"databases":        "16",
			"dbfilename":       "dump.rdb",
			"dir":              "/var/lib/redis",
			"logfile":          "/var/log/redis/redis-server.log",
			"maxmemory":        "0",
			"maxmemory-policy": "noeviction",
			"pidfile":          "/var/run/redis/redis-server.pid",
			"port":             "6379",
			"protected-mode":   "no",
			"requirepass":      "",
			"save":             "900 1 300 10 60 10000",
			"supervised":       "systemd",
		},
	}
}

func current8Profile() RedisProfile {
	return RedisProfile{
		Name:             "current8",
		Version:          "8.8.0",
		GitSHA:           "00000000",
		BuildID:          "9ad2a50f7c8a0ce1",
		Mode:             "standalone",
		OS:               "Linux 6.8.0-60-generic x86_64",
		ArchBits:         "64",
		MultiplexingAPI:  "epoll",
		AtomicvarAPI:     "atomic-builtin",
		GCCVersion:       "13.3.0",
		Executable:       "/opt/redis-stack/bin/redis-server",
		ConfigFile:       "/etc/redis/redis.conf",
		Allocator:        "jemalloc-5.3.0",
		MemoryHuman:      "2.43M",
		UsedMemory:       "2548736",
		TotalMemory:      "33554423808",
		MaxMemoryPolicy:  "noeviction",
		ModuleLine:       "module:name=search,ver=80800,api=1,filters=0,usedby=[],using=[],options=[]",
		SupportedModules: []string{"search", "timeseries", "json", "bf"},
		Config: map[string]string{
			"appendonly":       "no",
			"bind":             "0.0.0.0",
			"daemonize":        "yes",
			"databases":        "16",
			"dbfilename":       "dump.rdb",
			"dir":              "/var/lib/redis",
			"io-threads":       "1",
			"logfile":          "/var/log/redis/redis-server.log",
			"maxmemory":        "0",
			"maxmemory-policy": "noeviction",
			"pidfile":          "/var/run/redis/redis-server.pid",
			"port":             "6379",
			"protected-mode":   "no",
			"requirepass":      "",
			"save":             "900 1 300 10 60 10000",
			"supervised":       "systemd",
		},
	}
}

func (s *RedisServer) info(section string) string {
	section = strings.ToLower(section)
	if section == "" || section == "default" {
		section = "all"
	}

	uptime := int64(time.Since(s.startedAt).Seconds())
	if uptime < 0 {
		uptime = 0
	}

	port := "6379"
	if tcpAddr, ok := s.listener.Addr().(*net.TCPAddr); ok {
		port = strconv.Itoa(tcpAddr.Port)
	}

	fp := s.runtime
	usedMemory := fp.usedMemory.Load()
	usedMemoryRSS := fp.usedMemoryRSS.Load()
	usedMemoryPeak := fp.usedMemoryPeak.Load()
	if usedMemoryPeak < usedMemory {
		usedMemoryPeak = usedMemory
	}
	peakPercent := 100.0
	if usedMemoryPeak > 0 {
		peakPercent = float64(usedMemory) / float64(usedMemoryPeak) * 100
	}
	fragmentationRatio := 1.0
	if usedMemory > 0 {
		fragmentationRatio = float64(usedMemoryRSS) / float64(usedMemory)
	}

	sections := map[string][]string{
		"server": {
			"redis_version:" + s.profile.Version,
			"redis_git_sha1:" + s.profile.GitSHA,
			"redis_git_dirty:0",
			"redis_build_id:" + fp.redisBuildID,
			"redis_mode:" + s.profile.Mode,
			"os:" + s.profile.OS,
			"arch_bits:" + s.profile.ArchBits,
			"multiplexing_api:" + s.profile.MultiplexingAPI,
			"atomicvar_api:" + s.profile.AtomicvarAPI,
			"gcc_version:" + s.profile.GCCVersion,
			"process_id:" + strconv.Itoa(fp.processID),
			"run_id:" + fp.runID,
			"tcp_port:" + port,
			"uptime_in_seconds:" + strconv.FormatInt(uptime, 10),
			"uptime_in_days:" + strconv.FormatInt(uptime/86400, 10),
			"hz:10",
			"configured_hz:10",
			"lru_clock:" + strconv.FormatInt(fp.lruClock(uptime), 10),
			"executable:" + s.profile.Executable,
			"config_file:" + s.profile.ConfigFile,
		},
		"clients": {
			"connected_clients:" + strconv.FormatInt(s.activeClients.Load(), 10),
			"client_recent_max_input_buffer:" + strconv.FormatInt(fp.clientRecentMaxInputBuffer, 10),
			"client_recent_max_output_buffer:" + strconv.FormatInt(fp.clientRecentMaxOutputBuffer, 10),
			"blocked_clients:0",
			"tracking_clients:0",
			"clients_in_timeout_table:0",
		},
		"memory": {
			"used_memory:" + strconv.FormatInt(usedMemory, 10),
			"used_memory_human:" + formatRedisBytes(usedMemory),
			"used_memory_rss:" + strconv.FormatInt(usedMemoryRSS, 10),
			"used_memory_rss_human:" + formatRedisBytes(usedMemoryRSS),
			"used_memory_peak:" + strconv.FormatInt(usedMemoryPeak, 10),
			"used_memory_peak_human:" + formatRedisBytes(usedMemoryPeak),
			"used_memory_peak_perc:" + fmt.Sprintf("%.2f%%", peakPercent),
			"used_memory_lua:" + strconv.FormatInt(fp.usedMemoryLua, 10),
			"used_memory_lua_human:" + formatRedisBytes(fp.usedMemoryLua),
			"maxmemory:0",
			"maxmemory_human:0B",
			"maxmemory_policy:" + s.profile.MaxMemoryPolicy,
			"mem_fragmentation_ratio:" + fmt.Sprintf("%.2f", fragmentationRatio),
			"mem_allocator:" + s.profile.Allocator,
			"total_system_memory:" + s.profile.TotalMemory,
		},
		"persistence": {
			"loading:0",
			"rdb_changes_since_last_save:" + strconv.FormatInt(fp.rdbChangesSinceSave.Load(), 10),
			"rdb_bgsave_in_progress:0",
			"rdb_last_save_time:" + strconv.FormatInt(fp.rdbLastSaveTime.Load(), 10),
			"rdb_last_bgsave_status:ok",
			"rdb_last_bgsave_time_sec:" + strconv.FormatInt(fp.rdbLastBgsaveTimeSec.Load(), 10),
			"aof_enabled:0",
			"aof_rewrite_in_progress:0",
			"aof_last_bgrewrite_status:ok",
			"aof_last_write_status:ok",
		},
		"stats": {
			"total_connections_received:" + strconv.FormatUint(s.totalConnections.Load(), 10),
			"total_commands_processed:" + strconv.FormatUint(s.totalCommands.Load(), 10),
			"instantaneous_ops_per_sec:0",
			"rejected_connections:0",
			"expired_keys:0",
			"evicted_keys:0",
			"keyspace_hits:" + strconv.FormatUint(s.keyspaceHits.Load(), 10),
			"keyspace_misses:" + strconv.FormatUint(s.keyspaceMisses.Load(), 10),
			"pubsub_channels:0",
			"pubsub_patterns:0",
			"latest_fork_usec:" + strconv.FormatInt(fp.latestForkUsec, 10),
			"unexpected_error_replies:" + strconv.FormatUint(s.protocolErrors.Load(), 10),
		},
		"replication": {
			"role:master",
			"connected_slaves:0",
			"master_replid:" + fp.masterReplID,
			"master_replid2:0000000000000000000000000000000000000000",
			"master_repl_offset:0",
			"second_repl_offset:-1",
			"repl_backlog_active:0",
			"repl_backlog_size:1048576",
			"repl_backlog_first_byte_offset:0",
			"repl_backlog_histlen:0",
		},
		"cpu": {
			"used_cpu_sys:" + fmt.Sprintf("%.6f", fp.cpuSys(uptime)),
			"used_cpu_user:" + fmt.Sprintf("%.6f", fp.cpuUser(uptime)),
			"used_cpu_sys_children:" + fmt.Sprintf("%.6f", fp.cpuSysChildrenBase),
			"used_cpu_user_children:" + fmt.Sprintf("%.6f", fp.cpuUserChildrenBase),
		},
		"cluster": {
			"cluster_enabled:0",
		},
	}

	if s.profile.ModuleLine != "" {
		sections["modules"] = []string{s.profile.ModuleLine}
	}

	keyspace := s.store.Keyspace()
	if len(keyspace) > 0 {
		lines := make([]string, 0, len(keyspace))
		dbs := make([]int, 0, len(keyspace))
		for db := range keyspace {
			dbs = append(dbs, db)
		}
		sort.Ints(dbs)
		for _, db := range dbs {
			lines = append(lines, fmt.Sprintf("db%d:keys=%d,expires=0,avg_ttl=0", db, keyspace[db]))
		}
		sections["keyspace"] = lines
	}

	order := []string{"server", "clients", "memory", "persistence", "stats", "replication", "cpu", "cluster", "modules", "keyspace"}
	var out strings.Builder
	for _, name := range order {
		lines, ok := sections[name]
		if !ok {
			continue
		}
		if section != "all" && section != name {
			continue
		}
		out.WriteString("# ")
		out.WriteString(strings.ToUpper(name[:1]))
		out.WriteString(name[1:])
		out.WriteString("\r\n")
		for _, line := range lines {
			out.WriteString(line)
			out.WriteString("\r\n")
		}
		out.WriteString("\r\n")
	}
	return out.String()
}
