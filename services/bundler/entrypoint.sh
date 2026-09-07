#!/bin/sh
set -eu

: "${ALTO_RPC_URL:?ALTO_RPC_URL is required}"
ALTO_ENTRYPOINTS="${ALTO_ENTRYPOINTS:-0x0000000071727De22E5E9d8BAf0edAc6f37da032}"
ALTO_SAFE_MODE="${ALTO_SAFE_MODE:-true}"
ALTO_PORT="${ALTO_PORT:-4337}"

# The well-known Anvil account 0 key — never legitimate outside a devnet.
ANVIL_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

if [ -z "${ALTO_EXECUTOR_PRIVATE_KEYS:-}" ]; then
  echo "FATAL: ALTO_EXECUTOR_PRIVATE_KEYS is required (executor keys sign bundle transactions)" >&2
  exit 1
fi

case "${ALTO_EXECUTOR_PRIVATE_KEYS}${ALTO_UTILITY_PRIVATE_KEY:-}" in
  *"$ANVIL_KEY"*)
    if [ "${GIANO_DEV_MODE:-false}" != "true" ]; then
      echo "FATAL: refusing to start with the well-known Anvil key outside dev mode (set GIANO_DEV_MODE=true for local devnets only)" >&2
      exit 1
    fi
    echo "WARNING: running with the well-known Anvil key (GIANO_DEV_MODE=true) — never do this against a real chain" >&2
    ;;
esac

exec alto run \
  --rpc-url "$ALTO_RPC_URL" \
  --entrypoints "$ALTO_ENTRYPOINTS" \
  --executor-private-keys "$ALTO_EXECUTOR_PRIVATE_KEYS" \
  ${ALTO_UTILITY_PRIVATE_KEY:+--utility-private-key "$ALTO_UTILITY_PRIVATE_KEY"} \
  --safe-mode "$ALTO_SAFE_MODE" \
  --port "$ALTO_PORT"
