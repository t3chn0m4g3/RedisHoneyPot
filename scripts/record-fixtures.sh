#!/usr/bin/env bash
# Records persona data and fidelity fixtures from real Redis/Valkey containers.
# Containers bind to 127.0.0.1 only and are removed afterwards.
set -euo pipefail

cd "$(dirname "$0")/.."

# persona | image | extra server args
personas=(
  "redis74|redis:7.4.5|--enable-protected-configs yes --enable-module-command yes"
  "legacy6|redis:6.2.18|"
  "current8|redis:8.8.0|"
  "redis50|redis:5.0.7|"
  "valkey8|valkey/valkey:8.1.3|--enable-protected-configs yes --enable-module-command yes"
)
only="${1:-}"
port=16390

for entry in "${personas[@]}"; do
  IFS='|' read -r persona image extra <<<"$entry"
  if [[ -n "$only" && "$only" != "$persona" ]]; then
    continue
  fi
  name="redishoneypot-fixture-$persona"
  server="redis-server"
  [[ "$image" == valkey/* ]] && server="valkey-server"
  echo "==> $persona ($image)"
  docker rm -f "$name" >/dev/null 2>&1 || true
  # shellcheck disable=SC2086
  docker run -d --rm --name "$name" -p "127.0.0.1:$port:6379" "$image" \
    "$server" --protected-mode no --save "" $extra >/dev/null
  for _ in $(seq 1 30); do
    if docker exec "$name" sh -c "${server%-server}-cli ping" 2>/dev/null | grep -q PONG; then
      break
    fi
    sleep 0.5
  done
  go run ./cmd/fixture-recorder -addr "127.0.0.1:$port" \
    -fixtures "internal/honeypot/testdata/fixtures/$persona.json" \
    -data "internal/honeypot/personas/$persona"
  docker rm -f "$name" >/dev/null
  port=$((port + 1))
done
