#!/usr/bin/env bash
set -euo pipefail

service="${REDISHONEYPOT_SERVICE:-redishoneypot}"
addr="${REDISHONEYPOT_SMOKE_ADDR:-127.0.0.1:6379}"
log_file="${REDISHONEYPOT_LOG_FILE:-logs/redishoneypot.log}"

mkdir -p "$(dirname "$log_file")"
# Never truncate: the log may hold live attacker events. Only inspect what this
# run appends after the current end of file.
log_offset=0
if [[ -f "$log_file" ]]; then
  log_offset="$(wc -c < "$log_file" | tr -d ' ')"
fi

container_id="$(docker compose ps -q "$service")"
if [[ -z "$container_id" ]]; then
  echo "service '$service' is not running; start it with: docker compose up -d --build" >&2
  exit 1
fi

for _ in $(seq 1 30); do
  status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container_id")"
  if [[ "$status" == "healthy" || "$status" == "none" ]]; then
    break
  fi
  sleep 1
done

status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container_id")"
if [[ "$status" != "healthy" && "$status" != "none" ]]; then
  echo "service '$service' health status is '$status'" >&2
  exit 1
fi

GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.4}" go run ./cmd/container-smoketest -addr "$addr" -log-file "$log_file" -log-offset "$log_offset"
