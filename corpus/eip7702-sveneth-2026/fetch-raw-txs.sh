#!/usr/bin/env bash
# Provenance check for the vendored EIP-7702 sven.eth drainer replay
# transaction: re-derive the raw transaction from Ethereum mainnet RPCs
# and compare against the vendored bytes. Read-only. Requires cast for
# keccak verification.
#
# Two independent paths, each gated by keccak256(raw) == tx hash:
#   1. eth_getRawTransactionByHash (publicnode serves the raw for this
#      tx without an archive token; drpc's free plan does not serve
#      raws at all)
#   2. RLP reconstruction from the on-chain tx object served by drpc
#      (reconstruct_raw.py, type-4 incl. authorization list) — a signed
#      tx is fully determined by its fields, so reconstruction is
#      byte-exact
set -uo pipefail
export PATH="$PATH:$HOME/.foundry/bin"

DIR="$(cd "$(dirname "$0")" && pwd)"
TXDIR="$DIR/transactions"
RAWTX_RPC="${RAWTX_RPC:-https://ethereum-rpc.publicnode.com}"
export OBJ_RPC="${OBJ_RPC:-https://eth.drpc.org}"

ok=0; fail=0; n_raw=0; n_recon=0

for f in "$TXDIR"/*.raw; do
    name="$(basename "$f")"
    h="${name#*_}"
    hash="${h%.raw}"
    vendored="$(tr -d '[:space:]' < "$f")"

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
        recon_ok=0
        if python3 "$DIR/reconstruct_raw.py" "$tmp/hash.txt" "$tmp/out" >/dev/null 2>&1; then
            cand="$(cat "$tmp/out"/*_"$hash" 2>/dev/null | tr -d '[:space:]')"
            if [ -n "$cand" ] && [ "$(cast keccak "$cand")" = "$hash" ]; then
                fetched="$cand"; method="rlp-reconstructed"
                recon_ok=1; n_recon=$((n_recon+1))
            fi
        fi
        rm -rf "$tmp"
        if [ "$recon_ok" -eq 0 ]; then
            echo "ERROR $name: no keccak-verified derivation available"
            fail=$((fail+1))
            continue
        fi
    fi

    if [ "$vendored" = "$fetched" ]; then
        echo "OK   $name ($method)"
        ok=$((ok+1))
    else
        echo "MISMATCH $name ($method bytes are canonical but differ from vendored)"
        fail=$((fail+1))
    fi
done

echo "verified $ok/$((ok+fail)) txs byte-exact ($n_raw via raw RPC, $n_recon via RLP reconstruction)"
[ "$fail" -eq 0 ]
