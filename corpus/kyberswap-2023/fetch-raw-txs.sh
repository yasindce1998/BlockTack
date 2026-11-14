#!/usr/bin/env bash
# Provenance check for the vendored KyberSwap replay transactions:
# re-fetch each raw transaction from a public mainnet RPC and compare
# against the vendored bytes in transactions/. Read-only. Requires cast.
set -euo pipefail
export PATH="$PATH:$HOME/.foundry/bin"

RPC="${RAWTX_RPC:-https://ethereum-rpc.publicnode.com}"
DIR="$(cd "$(dirname "$0")" && pwd)/transactions"

fail=0
for f in "$DIR"/*.raw; do
    name="$(basename "$f")"
    h="${name#*_}"        # strip "NN_" order prefix
    hash="${h%.raw}"      # strip ".raw" suffix -> "0x..."
    vendored="$(tr -d '[:space:]' < "$f")"
    fetched="$(cast rpc eth_getRawTransactionByHash "$hash" --rpc-url "$RPC" | tr -d '"' | tr -d '[:space:]')"
    # Guard against RPCs that serve non-canonical serializations: a
    # fetched raw is only accepted if keccak256(raw) == tx hash.
    if [ -n "$fetched" ] && [ "$(cast keccak "$fetched")" != "$hash" ]; then
        echo "NONCANONICAL $name (fetched bytes do not hash to $hash)"
        fail=1
        continue
    fi
    if [ "$vendored" = "$fetched" ]; then
        echo "OK   $name"
    else
        echo "MISMATCH $name"
        fail=1
    fi
    sleep 0.4
done
exit $fail
