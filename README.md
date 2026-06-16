# RedisHoneyPot

RedisHoneyPot is a high-interaction Redis protocol honeypot written in Go. It is designed to look useful to opportunistic Redis scanners and common post-exploitation playbooks while keeping all behavior local and non-executing.

This service is intentionally deceptive. Run it only in an isolated monitoring environment, keep host permissions minimal, and block outbound traffic so attacker-triggered replication or module-loading attempts cannot leave the sensor.

## Features

- RESP2 server implemented with the Go standard library.
- JSON command logs via `log/slog`.
- Switchable Redis personas:
  - `legacy6`: default Redis 6.x-style fingerprint for exposed legacy targets.
  - `current8`: Redis Open Source 8.x-style fingerprint with built-in module hints.
- Per-start fingerprint variation for volatile INFO fields such as build id, process id, memory, CPU, persistence, and replication identifiers.
- Connection-local logical DB selection with a concurrency-safe in-memory string store.
- Bounded inline and bulk command parsing to reduce memory abuse.
- Plausible but harmless responses for common reconnaissance and exploitation commands.

## Build

```sh
GOTOOLCHAIN=go1.26.4 go build -o RedisHoneyPot ./cmd/redishoneypot
```

## Run

```sh
./RedisHoneyPot -addr 0.0.0.0:6379 -proto tcp -profile legacy6
```

Useful flags:

```text
-addr            Listen address. Default: 0.0.0.0:6379
-proto           Listen protocol. Default: tcp
-profile         Redis persona: legacy6 or current8. Default: legacy6
-idle-timeout    Connection idle timeout. Default: 5m
-max-bulk-bytes  Maximum RESP bulk string size. Default: 1048576
-num             Deprecated compatibility flag; accepted but ignored
```

## Docker

Build the image:

```sh
docker build -t redishoneypot:local .
```

Run it directly:

```sh
docker run --rm \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -p 6379:6379/tcp \
  redishoneypot:local
```

Run with Docker Compose:

```sh
docker compose up --build
```

Docker Compose bind-mounts `./logs` on the host to `/var/log/redishoneypot` in the container. The image writes honeypot event logs to `/var/log/redishoneypot/redishoneypot.log`, so the host-side file is `logs/redishoneypot.log`.

The container still writes stdout JSON logs, but the mounted event log intentionally contains only honeypot interaction events. Typical process lifecycle events such as `start`, `shutdown_requested`, `startup_failed`, and `server_failed` are kept out of `redishoneypot.log`.

If your host user is not UID/GID `1000`, pass the desired runtime IDs when starting Compose so the non-root container can write to the bind mount:

```sh
REDISHONEYPOT_UID="$(id -u)" REDISHONEYPOT_GID="$(id -g)" docker compose up --build
```

Keep egress filtering at the host, firewall, or orchestration layer if this sensor is exposed to untrusted traffic.

The image includes a built-in Docker healthcheck. It runs:

```sh
/redishoneypot healthcheck -addr 127.0.0.1:6379 -timeout 2s
```

The probe identifies itself with `CLIENT SETNAME __redishoneypot_healthcheck__`; the server suppresses logs for that internal session so periodic healthchecks do not fill the event stream.

Smoke-test a running Compose container:

```sh
docker compose up -d --build
./scripts/smoke-running-container.sh
```

The smoke test sends Redis protocol commands through the published port and verifies that `logs/redishoneypot.log` contains command/session events without lifecycle events or JSON `null` fields.

## Supported Commands

Core Redis-like commands:

```text
PING ECHO AUTH QUIT INFO SET GET MGET DEL EXISTS KEYS TYPE TTL
SELECT DBSIZE FLUSHDB FLUSHALL SAVE BGSAVE CONFIG CLIENT COMMAND
ROLE TIME
```

Honeypot-focused commands:

```text
SLAVEOF REPLICAOF REPLCONF PSYNC SYNC MODULE
```

`CONFIG SET`, `SAVE`, `SLAVEOF`, `REPLICAOF`, `REPLCONF`, `PSYNC`, `SYNC`, and `MODULE LOAD` never write files, load code, or initiate outbound connections. They only update in-memory state or return plausible protocol replies.

## Fingerprint Variation

Each process start generates a fresh runtime fingerprint while keeping the selected persona coherent. Stable persona anchors include Redis version, OS string, architecture, allocator, executable path, config path, and default `CONFIG GET` values. Volatile values such as `redis_build_id`, `process_id`, `run_id`, `master_replid`, memory figures, fork timing, CPU counters, and persistence timestamps vary automatically.

Runtime mutations also affect the fake server state: `SET`, `DEL`, and `FLUSH*` increase `rdb_changes_since_last_save`; `SAVE` and `BGSAVE` update save metadata and reset the pending change count. All changes remain in memory and disappear on restart.

## Logs

Logs are flat JSON lines on stdout. Field names use snake case and values are primitive JSON types only, so Logstash can ingest them without nested object or array mappings. Timestamps use UTC RFC3339Nano, which is ISO-8601 compatible. Fields with unknown or unavailable values are omitted instead of being emitted as JSON `null` or empty placeholders.

Event names include:

```text
start connect command protocol_error close shutdown_requested
```

Connection and command events include:

```text
timestamp event message level protocol network profile session_id client_id
src_ip src_port dest_ip dest_port session_start session_duration session_duration_ms
```

`close` events also include `session_end`. Client metadata fields such as `client_name`, `client_library_name`, `client_library_version`, and `user_agent` are emitted only after the client has supplied them.

Command events also include:

```text
redis_db command command_category arg_count response_class response_bytes outcome close_after_command
```

Argument fields such as `args_text`, `args_truncated`, and `args_sha256` are emitted only when the command has arguments. Additional analysis fields are emitted when relevant, for example `analysis_hint`, `key`, `key_count`, `value_size`, `value_sha256`, `config_key`, `config_value`, `config_value_sha256`, `replica_host`, `replica_port`, `module_path`, `auth_username`, `auth_password_length`, and `auth_password_sha256`.

Redis does not have an HTTP-style User-Agent header. The `user_agent` field is populated when a client sends Redis client metadata with `CLIENT SETINFO LIB-NAME ...` and optionally `CLIENT SETINFO LIB-VER ...`; otherwise the field is omitted. `AUTH` passwords and `CONFIG SET requirepass` values are redacted from `args_text` while their SHA-256 hashes and lengths are still logged for correlation.

Example:

```json
{"timestamp":"2026-06-16T12:00:00Z","level":"INFO","message":"command","event":"command","protocol":"redis","network":"tcp","profile":"legacy6","session_id":"6f8b1f7a0d9c44b2a78f8ef650d01d2c","client_id":1,"src_ip":"203.0.113.10","src_port":51432,"dest_ip":"198.51.100.20","dest_port":6379,"session_start":"2026-06-16T12:00:00Z","session_duration":1.234,"session_duration_ms":1234,"client_library_name":"go-redis","client_library_version":"9.7.0","user_agent":"go-redis/9.7.0","redis_db":0,"command":"CONFIG","command_category":"recon","arg_count":3,"args_text":"SET dir /tmp","args_truncated":false,"args_sha256":"...","response_class":"simple_string","response_bytes":5,"outcome":"success","close_after_command":false,"analysis_hint":"redis_write_file_attempt","config_subcommand":"set","config_key":"dir","config_value":"/tmp","config_value_truncated":false,"config_value_sha256":"..."}
```

## Tests

```sh
GOTOOLCHAIN=go1.26.4 go test ./...
GOTOOLCHAIN=go1.26.4 go test -race ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

The test suite covers RESP parsing/encoding, command behavior, regression cases from the original implementation, and TCP smoke tests for redis-cli-like flows.

## Repository Layout

```text
cmd/redishoneypot/      CLI entrypoint and process signal handling
internal/honeypot/      Redis protocol server, personas, parser, store, logging, and tests
README.md              Operator documentation
```

## Deployment Notes

- Prefer a dedicated VM, container, or network namespace.
- Do not run with privileged filesystem permissions.
- Apply egress filtering; the honeypot should not be able to connect back to attacker-controlled replication hosts.
- Send stdout logs to your collector and keep raw payload retention aligned with your local policy.
- Put the sensor on infrastructure where receiving unsolicited traffic is expected and authorized.
