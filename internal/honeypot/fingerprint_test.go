package honeypot

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRuntimeFingerprintVariesPerServer(t *testing.T) {
	first := newTestServer(t, "legacy6")
	second := newTestServer(t, "legacy6")

	if first.runtime.runID == second.runtime.runID {
		t.Fatal("run_id should differ between server starts")
	}
	if first.runtime.masterReplID == second.runtime.masterReplID {
		t.Fatal("master_replid should differ between server starts")
	}
	if first.runtime.redisBuildID == second.runtime.redisBuildID {
		t.Fatal("redis_build_id should differ between server starts")
	}
}

func TestRuntimeFingerprintKeepsPersonaAnchors(t *testing.T) {
	server := newTestServer(t, "legacy6")
	info := parseInfo(t, infoText(server, "all"))

	assertInfoValue(t, info, "redis_version", "6.2.18")
	assertInfoValue(t, info, "arch_bits", "64")
	assertInfoValue(t, info, "config_file", "/etc/redis/6379.conf")
	assertInfoValue(t, info, "executable", "/usr/local/bin/redis-server")
	assertInfoValue(t, info, "gcc_version", "9.4.0")
	if !containsString(focalKernels, info["os"]) {
		t.Fatalf("os %q is not one of the persona kernels", info["os"])
	}

	if got := call(server, &clientState{connected: time.Now()}, "CONFIG", "GET", "dir"); got != "*2\r\n$3\r\ndir\r\n$19\r\n/var/lib/redis/6379\r\n" {
		t.Fatalf("CONFIG GET dir got %q", got)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestContainerPersonaRunsAsPIDOne(t *testing.T) {
	info := parseInfo(t, infoText(newTestServer(t, "redis74"), "server"))
	assertInfoValue(t, info, "process_id", "1")
	assertInfoValue(t, info, "executable", "/data/redis-server")
	if strings.Contains(info["os"], "linuxkit") {
		t.Fatalf("os %q leaks the recording host", info["os"])
	}
}

func TestRuntimeFingerprintInfoFormatAndMemoryConsistency(t *testing.T) {
	server := newTestServer(t, "legacy6")
	info := parseInfo(t, infoText(server, "all"))

	assertHexLength(t, info["run_id"], 40)
	assertHexLength(t, info["master_replid"], 40)
	assertHexLength(t, info["redis_build_id"], 16)

	usedMemory := parseInfoInt(t, info, "used_memory")
	usedMemoryRSS := parseInfoInt(t, info, "used_memory_rss")
	usedMemoryPeak := parseInfoInt(t, info, "used_memory_peak")
	processID := parseInfoInt(t, info, "process_id")
	lruClock := parseInfoInt(t, info, "lru_clock")
	latestForkUsec := parseInfoInt(t, info, "latest_fork_usec")

	if usedMemory <= 0 {
		t.Fatalf("used_memory should be positive, got %d", usedMemory)
	}
	if usedMemoryPeak < usedMemory {
		t.Fatalf("used_memory_peak %d is below used_memory %d", usedMemoryPeak, usedMemory)
	}
	if usedMemoryRSS <= usedMemory {
		t.Fatalf("used_memory_rss %d should be above used_memory %d", usedMemoryRSS, usedMemory)
	}
	if info["used_memory_human"] != formatRedisBytes(usedMemory) {
		t.Fatalf("used_memory_human got %q, want %q", info["used_memory_human"], formatRedisBytes(usedMemory))
	}
	if info["used_memory_rss_human"] != formatRedisBytes(usedMemoryRSS) {
		t.Fatalf("used_memory_rss_human got %q, want %q", info["used_memory_rss_human"], formatRedisBytes(usedMemoryRSS))
	}
	if info["used_memory_peak_human"] != formatRedisBytes(usedMemoryPeak) {
		t.Fatalf("used_memory_peak_human got %q, want %q", info["used_memory_peak_human"], formatRedisBytes(usedMemoryPeak))
	}
	if processID < 300 || processID > 65000 {
		t.Fatalf("process_id got %d, want plausible Redis process id", processID)
	}
	if lruClock < 0 || lruClock >= 1<<24 {
		t.Fatalf("lru_clock got %d, want 24-bit clock range", lruClock)
	}
	if latestForkUsec < 120 || latestForkUsec > 2600 {
		t.Fatalf("latest_fork_usec got %d, want plausible range", latestForkUsec)
	}
}

func TestRDBChangesEvolveWithMutationsAndSave(t *testing.T) {
	server := newTestServer(t, "legacy6")
	state := &clientState{connected: time.Now()}

	initial := parseInfo(t, infoText(server, "persistence"))
	initialSaveTime := parseInfoInt(t, initial, "rdb_last_save_time")
	if got := parseInfoInt(t, initial, "rdb_changes_since_last_save"); got != 0 {
		t.Fatalf("initial rdb changes got %d, want 0", got)
	}

	if got := call(server, state, "SET", "dirty", "1"); got != "+OK\r\n" {
		t.Fatalf("SET got %q", got)
	}

	afterSet := parseInfo(t, infoText(server, "persistence"))
	if got := parseInfoInt(t, afterSet, "rdb_changes_since_last_save"); got < 1 {
		t.Fatalf("after SET rdb changes got %d, want >= 1", got)
	}

	if got := call(server, state, "SAVE"); got != "+OK\r\n" {
		t.Fatalf("SAVE got %q", got)
	}

	afterSave := parseInfo(t, infoText(server, "persistence"))
	if got := parseInfoInt(t, afterSave, "rdb_changes_since_last_save"); got != 0 {
		t.Fatalf("after SAVE rdb changes got %d, want 0", got)
	}
	if got := parseInfoInt(t, afterSave, "rdb_last_save_time"); got < initialSaveTime {
		t.Fatalf("after SAVE rdb_last_save_time got %d, want >= initial %d", got, initialSaveTime)
	}
}

func parseInfo(t *testing.T, raw string) map[string]string {
	t.Helper()

	out := make(map[string]string)
	for _, line := range strings.Split(raw, "\r\n") {
		if line == "" || strings.HasPrefix(line, "# ") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("invalid INFO line %q", line)
		}
		out[key] = value
	}
	return out
}

func parseInfoInt(t *testing.T, info map[string]string, key string) int64 {
	t.Helper()

	value, ok := info[key]
	if !ok {
		t.Fatalf("missing INFO key %q", key)
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		t.Fatalf("INFO key %q value %q is not an int: %v", key, value, err)
	}
	return parsed
}

func assertInfoValue(t *testing.T, info map[string]string, key string, want string) {
	t.Helper()

	if got := info[key]; got != want {
		t.Fatalf("INFO %s got %q, want %q", key, got, want)
	}
}

func assertHexLength(t *testing.T, value string, length int) {
	t.Helper()

	if len(value) != length {
		t.Fatalf("hex value %q length got %d, want %d", value, len(value), length)
	}
	if !regexp.MustCompile(`^[0-9a-f]+$`).MatchString(value) {
		t.Fatalf("value %q is not lowercase hex", value)
	}
}
