#!/usr/bin/env bash
# Bootstrap checks run before loading any TypeScript or requesting credentials.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
command -v node >/dev/null || { echo 'Install Node.js 24+ and enable Corepack, then rerun.' >&2; exit 1; }
node -e 'if (Number(process.versions.node.split(".")[0]) < 24) process.exit(1)' || { echo 'Select Node.js 24+ (for example: nvm use 24), then rerun.' >&2; exit 1; }
command -v pnpm >/dev/null || { echo 'Enable pnpm with corepack enable; this repo pins its version in package.json.' >&2; exit 1; }
[ -x packages/contracts/node_modules/.bin/tsx ] || { echo 'Install dependencies first: corepack pnpm install --frozen-lockfile' >&2; exit 1; }
COMMAND="${1:-deploy}"
if [ "$#" -gt 0 ]; then shift; fi
case "$COMMAND" in
  deploy) exec pnpm --filter @appliedblockchain/giano-contracts deploy:guided "$@" ;;
  funding|provision|sponsorship|doctor|timelock|handoff) exec pnpm --filter @appliedblockchain/giano-contracts deploy:operate "$COMMAND" "$@" ;;
  *) echo 'Choose deploy, funding, provision, sponsorship, doctor, timelock or handoff.' >&2; exit 1 ;;
esac
