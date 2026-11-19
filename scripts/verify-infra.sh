#!/usr/bin/env bash
# Verify local infrastructure: RETURN 1 on Memgraph, SELECT 1 on PostgreSQL.
# Run from the repo root after `docker compose up -d`.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -f .env ]; then
  set -a; . ./.env; set +a
fi

fail=0

echo -n "Memgraph  (RETURN 1): "
if out=$(echo 'RETURN 1;' | docker compose exec -T memgraph mgconsole --output-format=csv 2>&1) && echo "$out" | grep -qx '"1"'; then
  echo OK
else
  echo FAIL; echo "$out"; fail=1
fi

echo -n "PostgreSQL (SELECT 1): "
if out=$(docker compose exec -T postgres psql -U "${POSTGRES_USER:?POSTGRES_USER not set}" -d "${POSTGRES_DB:?POSTGRES_DB not set}" -tAc 'SELECT 1;' 2>&1) && [ "$(echo "$out" | tr -d '[:space:]')" = "1" ]; then
  echo OK
else
  echo FAIL; echo "$out"; fail=1
fi

if [ "$fail" -eq 0 ]; then echo "All infrastructure checks passed."; else echo "Infrastructure check FAILED."; fi
exit "$fail"
