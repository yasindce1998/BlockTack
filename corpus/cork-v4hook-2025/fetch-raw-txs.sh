#!/usr/bin/env bash
# Provenance check for the vendored Cork 2025 replay transactions:
# re-derive each raw transaction from Ethereum mainnet RPCs and compare
# against the vendored bytes in transactions/. Read-only. Requires cast.
#
# Paths (both keccak-gated by keccak256(raw) == tx hash):
#   1. eth_getRawTransactionByHash (publicnode serves historical raws;
#      drpc's free plan does not)
#   2. RLP reconstruction from the on-chain tx object (drpc,
#      reconstruct_raw.py, types 0/1/2/4)
# The ordered replay list (blocks, pinned timestamps, roles) lives in
# manifest.json; this script checks byte provenance only.
set -uo pipefail
export PATH="$PATH:$HOME/.foundry/bin"

DIR="$(cd "$(dirname "$0")" && pwd)"
RAWTX_RPC="${RAWTX_RPC:-https://ethereum-rpc.publicnode.com}"
export OBJ_RPC="${OBJ_RPC:-https://eth.drpc.org}"

ok=0; fail=0; n_raw=0; n_recon=0
hashes=$(python3 -c "
import json
for e in json.load(open('$DIR/manifest.json')):
    print(e['hash'])
")

for hash in $hashes; do
    f="$DIR/transactions/"*"_${hash#0x}.raw"
    vendored="$(cat $f 2>/dev/null | tr -d '[:space:]')"
    fetched=""
    method=""
    resp="$(cast rpc eth_getRawTransactionByHash "$hash" --rpc-url "$RAWTX_RPC" 2>/dev/null | tr -d '"' | tr -d '[:space:]')" || resp=""
    case "$resp" in
        0x[0-9a-fA-F][0-9a-fA-F]*)
            if [ "$(cast keccak "$resp")" = "$hash" ]; then
                fetched="$resp"; method="raw"; n_raw=$((n_raw+1))
            fi
            ;;
    esac
    if [ -z "$fetched" ]; then
        tmp="$(mktemp -d)"
        printf '%s\n' "$hash" > "$tmp/hash.txt"
        if python3 "$DIR/reconstruct_raw.py" "$tmp/hash.txt" "$tmp/out" >/dev/null 2>&1; then
            cand="$(cat "$tmp/out"/*_"$hash" 2>/dev/null | tr -d '[:space:]')"
            if [ -n "$cand" ] && [ "$(cast keccak "$cand")" = "$hash" ]; then
                fetched="$cand"; method="rlp-reconstructed"; n_recon=$((n_recon+1))
            fi
        fi
        rm -rf "$tmp"
    fi
    if [ -z "$fetched" ]; then
        echo "ERROR $hash: no keccak-verified derivation available"
        fail=$((fail+1))
    elif [ "$vendored" = "$fetched" ]; then
        echo "OK   ${hash:0:20}… ($method)"
        ok=$((ok+1))
    else
        echo "MISMATCH $hash ($method bytes are canonical but differ from vendored)"
        fail=$((fail+1))
    fi
    sleep 0.2
done
echo "verified $ok/$((ok+fail)) txs byte-exact ($n_raw via raw RPC, $n_recon via RLP reconstruction)"
[ "$fail" -eq 0 ]
