#!/usr/bin/env bash
# Provenance check for the vendored Euler replay transactions: re-fetch
# each raw transaction from a public mainnet RPC and compare against the
# vendored bytes in transactions/.
#
# Read-only against public RPCs. Requires foundry (cast).
set -euo pipefail
export PATH="$PATH:$HOME/.foundry/bin"

RPC="${RAWTX_RPC:-https://ethereum-rpc.publicnode.com}" # 1rpc.io/eth also works
DIR="$(cd "$(dirname "$0")" && pwd)/transactions"

fail=0
for f in "$DIR"/*.raw; do
    name="$(basename "$f")"
    hash="0x$(echo "$name" | cut -d_ -f2)"
    vendored="$(tr -d '[:space:]' < "$f")"
    fetched="$(cast rpc eth_getRawTransactionByHash "$hash" --rpc-url "$RPC" | tr -d '"' | tr -d '[:space:]')"
    if [ "$vendored" = "$fetched" ]; then
        echo "OK   $name"
    else
        echo "MISMATCH $name"
        fail=1
    fi
    sleep 0.4 # stay under public RPC rate limits
done
exit $fail
