package honeypot

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const DefaultProfileName = "redis74"

// personaFS holds data recorded from real servers by cmd/fixture-recorder:
// COMMAND/COMMAND DOCS replies, CONFIG GET * defaults, MODULE LIST, INFO
// templates and a CLIENT LIST line.
//
//go:embed personas
var personaFS embed.FS

// RedisProfile describes one server persona. Static values that would let
// sensors be clustered (OS kernel, memory size, monotonic clock) are chosen
// per start from candidate lists.
type RedisProfile struct {
	Name    string
	Flavor  string // "redis" or "valkey"
	Version string
	// CompatVersion is the Redis feature level, e.g. Valkey 8 behaves like 7.2.
	CompatVersion string
	RDBVersion    int

	OSCandidates          []string
	MonotonicCandidates   []string
	TotalMemoryCandidates []int64
	GCCVersion            string
	Executable            string
	ConfigFile            string
	ProcessSupervised     string
	// Containerized personas run as PID 1 with Docker's /data layout.
	Containerized bool

	// ConfigOverrides replace recorded CONFIG defaults that describe the
	// recording container rather than the persona's deployment.
	ConfigOverrides map[string]string

	major, minor int
	data         *personaData
}

var (
	profilesOnce sync.Once
	profiles     map[string]RedisProfile
	profileNames []string
)

var cloudKernels = []string{
	"Linux 5.15.0-1084-aws x86_64",
	"Linux 6.8.0-1031-aws x86_64",
	"Linux 6.1.0-37-cloud-amd64 x86_64",
	"Linux 5.15.0-151-generic x86_64",
	"Linux 6.8.0-79-generic x86_64",
	"Linux 6.8.0-1033-azure x86_64",
	"Linux 5.14.0-570.25.1.el9_6.x86_64 x86_64",
	"Linux 6.1.141-155.222.amzn2023.x86_64 x86_64",
	"Linux 6.8.0-71-generic x86_64",
}

var focalKernels = []string{
	"Linux 5.4.0-216-generic x86_64",
	"Linux 5.4.0-212-generic x86_64",
	"Linux 5.4.0-205-generic x86_64",
	"Linux 5.4.0-1145-aws x86_64",
	"Linux 5.15.0-139-generic x86_64",
	"Linux 5.4.0-1150-azure x86_64",
}

var vmMemorySizes = []int64{
	2_062_913_536, 4_105_273_344, 8_218_525_696, 16_766_849_024, 33_546_739_712, 67_111_890_944,
}

func personaDefinitions() []RedisProfile {
	dockerOverrides := func(extra map[string]string) map[string]string {
		base := map[string]string{
			"dir":            "/data",
			"dbfilename":     "dump.rdb",
			"save":           "3600 1 300 100 60 10000",
			"protected-mode": "no",
			"appendonly":     "no",
		}
		for key, value := range extra {
			base[key] = value
		}
		return base
	}

	return []RedisProfile{
		{
			Name: "redis74", Flavor: "redis", Version: "7.4.5", RDBVersion: 12,
			OSCandidates: cloudKernels, TotalMemoryCandidates: vmMemorySizes,
			Executable: "/data/redis-server", ProcessSupervised: "no", Containerized: true,
			// A misconfigured but plausible exposure: protected configs and
			// MODULE are enabled, so the common file-write TTPs proceed.
			ConfigOverrides: dockerOverrides(map[string]string{
				"enable-protected-configs": "yes",
				"enable-module-command":    "yes",
			}),
		},
		{
			Name: "legacy6", Flavor: "redis", Version: "6.2.18", RDBVersion: 9,
			OSCandidates: focalKernels, TotalMemoryCandidates: vmMemorySizes,
			GCCVersion: "9.4.0", Executable: "/usr/local/bin/redis-server",
			ConfigFile: "/etc/redis/6379.conf", ProcessSupervised: "no",
			ConfigOverrides: map[string]string{
				"bind":           "0.0.0.0",
				"daemonize":      "yes",
				"dir":            "/var/lib/redis/6379",
				"dbfilename":     "dump.rdb",
				"logfile":        "/var/log/redis_6379.log",
				"pidfile":        "/var/run/redis_6379.pid",
				"protected-mode": "no",
				"save":           "900 1 300 10 60 10000",
				"appendonly":     "no",
			},
		},
		{
			Name: "current8", Flavor: "redis", Version: "8.8.0", RDBVersion: 14,
			OSCandidates: cloudKernels, TotalMemoryCandidates: vmMemorySizes,
			MonotonicCandidates: []string{
				"X86 TSC @ 2100 ticks/us", "X86 TSC @ 2200 ticks/us", "X86 TSC @ 2400 ticks/us",
				"X86 TSC @ 2500 ticks/us", "X86 TSC @ 2900 ticks/us", "X86 TSC @ 3000 ticks/us",
			},
			Executable: "/data/redis-server", ProcessSupervised: "no", Containerized: true,
			ConfigOverrides: dockerOverrides(nil),
		},
		{
			Name: "redis50", Flavor: "redis", Version: "5.0.7", RDBVersion: 9,
			OSCandidates: focalKernels, TotalMemoryCandidates: vmMemorySizes,
			GCCVersion: "9.3.0", Executable: "/usr/bin/redis-server",
			ConfigFile: "/etc/redis/redis.conf", ProcessSupervised: "no",
			ConfigOverrides: map[string]string{
				"bind":           "0.0.0.0",
				"daemonize":      "yes",
				"supervised":     "systemd",
				"dir":            "/var/lib/redis",
				"dbfilename":     "dump.rdb",
				"logfile":        "/var/log/redis/redis-server.log",
				"pidfile":        "/var/run/redis/redis-server.pid",
				"protected-mode": "no",
				"save":           "900 1 300 10 60 10000",
				"appendonly":     "no",
			},
		},
		{
			Name: "valkey8", Flavor: "valkey", Version: "8.1.3", CompatVersion: "7.2.4", RDBVersion: 11,
			OSCandidates: cloudKernels, TotalMemoryCandidates: vmMemorySizes,
			Executable: "/data/valkey-server", ProcessSupervised: "no", Containerized: true,
			ConfigOverrides: dockerOverrides(map[string]string{
				"enable-protected-configs": "yes",
				"enable-module-command":    "yes",
			}),
		},
	}
}

var profileAliases = map[string]string{
	"":       DefaultProfileName,
	"redis7": "redis74",
	"redis6": "legacy6",
	"redis8": "current8",
	"redis5": "redis50",
	"valkey": "valkey8",
}

func loadProfiles() {
	profiles = make(map[string]RedisProfile)
	for _, profile := range personaDefinitions() {
		data, err := loadPersonaData(profile.Name)
		if err != nil {
			panic(fmt.Sprintf("persona %s: %v", profile.Name, err))
		}
		profile.data = data
		compat := profile.CompatVersion
		if compat == "" {
			compat = profile.Version
		}
		profile.major, profile.minor = parseMajorMinor(compat)
		profiles[profile.Name] = profile
		profileNames = append(profileNames, profile.Name)
	}
	sort.Strings(profileNames)
}

func LookupRedisProfile(name string) (RedisProfile, bool) {
	profilesOnce.Do(loadProfiles)
	name = strings.ToLower(name)
	if alias, ok := profileAliases[name]; ok {
		name = alias
	}
	profile, ok := profiles[name]
	return profile, ok
}

// ProfileNames lists the available persona names.
func ProfileNames() []string {
	profilesOnce.Do(loadProfiles)
	return append([]string(nil), profileNames...)
}

func parseMajorMinor(version string) (int, int) {
	parts := strings.Split(version, ".")
	major, _ := strconv.Atoi(parts[0])
	minor := 0
	if len(parts) > 1 {
		minor, _ = strconv.Atoi(parts[1])
	}
	return major, minor
}

// atLeast reports whether the persona's Redis feature level is >= major.minor.
func (p RedisProfile) atLeast(major, minor int) bool {
	return p.major > major || (p.major == major && p.minor >= minor)
}

func (p RedisProfile) isValkey() bool { return p.Flavor == "valkey" }

// modernErrors: Redis 7 changed many error texts ('quoted' args, "unknown
// subcommand", "CONFIG SET failed (possibly related to argument ...)").
func (p RedisProfile) modernErrors() bool { return p.atLeast(7, 0) }

type personaData struct {
	commandsRaw  []byte
	commands     map[string]commandEntry
	docsRaw      []byte
	docs         map[string][]byte
	config       map[string]string
	modules      []respNode
	info         []infoSection
	infoGroups   map[string]map[string]bool
	clientFields []clientField
}

type commandEntry struct {
	raw         []byte
	arity       int64
	flags       map[string]bool
	firstKey    int64
	subcommands map[string]commandEntry
}

type infoSection struct {
	name  string
	lines []infoLine
}

type infoLine struct {
	key   string
	value string
}

type clientField struct {
	key   string
	value string
}

func loadPersonaData(name string) (*personaData, error) {
	read := func(file string) ([]byte, error) {
		data, err := fs.ReadFile(personaFS, "personas/"+name+"/"+file)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	optional := func(file string) []byte {
		data, _ := read(file)
		return data
	}

	data := &personaData{infoGroups: make(map[string]map[string]bool)}

	raw, err := read("command.resp")
	if err != nil {
		return nil, err
	}
	data.commandsRaw = raw
	if data.commands, err = parseCommandTable(raw); err != nil {
		return nil, fmt.Errorf("command.resp: %w", err)
	}

	if docs := optional("command_docs.resp"); len(docs) > 0 {
		data.docsRaw = docs
		if data.docs, err = parseCommandDocs(docs); err != nil {
			return nil, fmt.Errorf("command_docs.resp: %w", err)
		}
	}

	raw, err = read("config.resp")
	if err != nil {
		return nil, err
	}
	node, _, err := parseRESP(raw)
	if err != nil {
		return nil, fmt.Errorf("config.resp: %w", err)
	}
	data.config = make(map[string]string, len(node.children)/2)
	for i := 0; i+1 < len(node.children); i += 2 {
		data.config[node.children[i].str] = node.children[i+1].str
	}

	if raw := optional("module_list.resp"); len(raw) > 0 {
		node, _, err := parseRESP(raw)
		if err != nil {
			return nil, fmt.Errorf("module_list.resp: %w", err)
		}
		data.modules = node.children
	}

	template := optional("info_everything.txt")
	if len(template) == 0 {
		template = optional("info_all.txt")
	}
	data.info = parseInfoTemplate(string(template))
	for group, file := range map[string]string{"default": "info_default.txt", "all": "info_all.txt", "everything": "info_everything.txt"} {
		names := make(map[string]bool)
		for _, section := range parseInfoTemplate(string(optional(file))) {
			names[strings.ToLower(section.name)] = true
		}
		data.infoGroups[group] = names
	}

	line := strings.TrimSpace(string(optional("client_list.txt")))
	for _, field := range strings.Fields(line) {
		key, value, _ := strings.Cut(field, "=")
		data.clientFields = append(data.clientFields, clientField{key: key, value: value})
	}
	return data, nil
}

func parseCommandTable(raw []byte) (map[string]commandEntry, error) {
	node, _, err := parseRESP(raw)
	if err != nil {
		return nil, err
	}
	commands := make(map[string]commandEntry, len(node.children))
	for _, child := range node.children {
		entry, name := commandEntryFromNode(child)
		commands[name] = entry
	}
	return commands, nil
}

func commandEntryFromNode(node respNode) (commandEntry, string) {
	entry := commandEntry{raw: node.raw, flags: make(map[string]bool)}
	if len(node.children) < 6 {
		return entry, ""
	}
	name := strings.ToLower(node.children[0].str)
	entry.arity = node.children[1].num
	for _, flag := range node.children[2].children {
		entry.flags[flag.str] = true
	}
	entry.firstKey = node.children[3].num
	if len(node.children) >= 10 {
		entry.subcommands = make(map[string]commandEntry)
		for _, sub := range node.children[9].children {
			subEntry, subName := commandEntryFromNode(sub)
			entry.subcommands[subName] = subEntry
		}
	}
	return entry, name
}

// parseCommandDocs indexes COMMAND DOCS (name, doc-map pairs) by name so
// filtered requests can return the recorded raw encoding.
func parseCommandDocs(raw []byte) (map[string][]byte, error) {
	node, _, err := parseRESP(raw)
	if err != nil {
		return nil, err
	}
	docs := make(map[string][]byte, len(node.children)/2)
	for i := 0; i+1 < len(node.children); i += 2 {
		name := strings.ToLower(node.children[i].str)
		pair := append(append([]byte(nil), node.children[i].raw...), node.children[i+1].raw...)
		docs[name] = pair
	}
	return docs, nil
}

func parseInfoTemplate(text string) []infoSection {
	var sections []infoSection
	for _, line := range strings.Split(text, "\r\n") {
		if line == "" {
			continue
		}
		if name, ok := strings.CutPrefix(line, "# "); ok {
			sections = append(sections, infoSection{name: name})
			continue
		}
		if len(sections) == 0 {
			continue
		}
		key, value, _ := strings.Cut(line, ":")
		last := &sections[len(sections)-1]
		last.lines = append(last.lines, infoLine{key: key, value: value})
	}
	return sections
}
