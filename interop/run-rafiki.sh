#!/usr/bin/env bash
# .NET client (Gnap.Client) -> Rafiki auth server. Starts Rafiki's auth service with
# docker compose (unless RAFIKI_EXTERNAL=1, e.g. when running Rafiki from source,
# see docs/interop.md), waits for it, and runs Gnap.Interop.Tests.Rafiki.
set -euo pipefail
cd "$(dirname "$0")/.."

compose=(docker compose -f interop/rafiki/docker-compose.yml)
if [[ "${RAFIKI_EXTERNAL:-0}" != "1" ]]; then
  "${compose[@]}" up -d
  trap '"${compose[@]}" logs auth > interop-rafiki-auth.log 2>&1 || true; "${compose[@]}" down -v' EXIT
  # The wallet address server runs on the host; Rafiki reaches it via host.docker.internal.
  export INTEROP_WALLET_BASE="${INTEROP_WALLET_BASE:-http://host.docker.internal:5199/}"
fi

echo "Waiting for Rafiki auth on :3006 ..."
for _ in $(seq 1 90); do
  if curl -fsS http://localhost:3006/healthz > /dev/null 2>&1; then break; fi
  sleep 2
done
curl -fsS http://localhost:3006/discovery && echo

GNAP_INTEROP_RAFIKI=1 dotnet test tests/Gnap.Interop.Tests --configuration "${CONFIGURATION:-Release}" \
  --filter "FullyQualifiedName~Rafiki" --logger "trx;LogFileName=rafiki.trx" --results-directory TestResults/interop \
  --logger "console;verbosity=normal"
