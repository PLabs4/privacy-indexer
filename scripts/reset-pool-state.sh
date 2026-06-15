#!/usr/bin/env bash
set -euo pipefail

POOL="${POOL:-0x8eb5DE242852F519b40416061dE54dBf3d345A4B}"
START_BLOCK="${START_BLOCK:?Set START_BLOCK to a block before this pool was deployed}"
RPC_URL="${RPC_URL:-https://rpc.monad.xyz}"
POSTGRES_USER="${POSTGRES_USER:-privacybtc}"
POSTGRES_DB="${POSTGRES_DB:-privacybtc}"

if ! [[ "$POOL" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
  echo "POOL must be a 20-byte 0x-prefixed address" >&2
  exit 2
fi
if ! [[ "$START_BLOCK" =~ ^[0-9]+$ ]]; then
  echo "START_BLOCK must be a decimal block number" >&2
  exit 2
fi

POOL_LC="$(printf '%s' "$POOL" | tr '[:upper:]' '[:lower:]')"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "[reset] stopping indexer"
docker compose stop indexer

echo "[reset] clearing PostgreSQL state for $POOL_LC"
docker compose exec -T postgres psql \
  -U "$POSTGRES_USER" \
  -d "$POSTGRES_DB" \
  -v ON_ERROR_STOP=1 \
  -v pool="$POOL_LC" <<'SQL'
BEGIN;
DELETE FROM pending_tx   WHERE lower(pool_address) = :'pool';
DELETE FROM notes        WHERE lower(pool_address) = :'pool';
DELETE FROM frozen_cmx   WHERE lower(pool_address) = :'pool';
DELETE FROM cmx_leaves   WHERE lower(pool_address) = :'pool';
DELETE FROM indexer_meta WHERE lower(pool_address) = :'pool';
COMMIT;
SQL

if docker compose cp indexer:/data/pools.json "$tmpdir/pools.json" >/dev/null 2>&1; then
  echo "[reset] updating /data/pools.json start_block for $POOL_LC"
  python3 - "$tmpdir/pools.json" "$POOL_LC" "$START_BLOCK" <<'PY'
import json
import sys

path, pool, start_block = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    data = {}

pools = data.setdefault("pools", [])
for entry in pools:
    if str(entry.get("address", "")).lower() == pool:
        entry["address"] = pool
        entry["start_block"] = start_block
        break
else:
    pools.append({"address": pool, "start_block": start_block})

with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
  docker compose cp "$tmpdir/pools.json" indexer:/data/pools.json
  docker compose run --rm --no-deps --user root --entrypoint chown indexer \
    10001:10001 /data/pools.json
else
  echo "[reset] no existing /data/pools.json found; the pool will need CLI config, discovery, or POST /pools"
fi

echo "[reset] ensure .env contains:"
echo "  PRIVACYBTC_ETH_RPC_URL=$RPC_URL"
echo "  PRIVACYBTC_START_BLOCK=$START_BLOCK"
echo "[reset] start with: docker compose up -d --build indexer"
