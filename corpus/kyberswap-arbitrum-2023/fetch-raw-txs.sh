#!/usr/bin/env bash
# Provenance check for the vendored KyberSwap Arbitrum replay
# transactions: re-derive each raw transaction from Arbitrum RPCs and
# compare against the vendored bytes in transactions/. Read-only.
# Requires foundry (cast) for keccak verification.
#
# Two independent paths, each gated by keccak256(raw) == tx hash:
#   1. eth_getRawTransactionByHash (meowrpc). WARNING: meowrpc
#      load-balances across backend nodes that disagree on raw-tx
#      serialization (non-canonical v/yParity re-encoding on some
#      nodes); the same hash returns different bytes on different
#      requests. A fetched raw is therefore only accepted if it hashes
#      to the tx hash.
#   2. RLP reconstruction from the on-chain tx object served by
#      arb1.arbitrum.io/rpc (reconstruct_raw.py) — a signed tx is fully
#      determined by its fields, so reconstruction is byte-exact.
set -uo pipefail
export PATH="$PATH:$HOME/.foundry/bin"

DIR="$(cd "$(dirname "$0")" && pwd)"
TXDIR="$DIR/transactions"
RAWTX_RPC="${RAWTX_RPC:-https://arbitrum.meowrpc.com}"
OBJ_RPC="${OBJ_RPC:-https://arb1.arbitrum.io/rpc}"

ok=0; fail=0; n_raw=0; n_recon=0

for f in "$TXDIR"/*.raw; do
    name="$(basename "$f")"
    h="${name#*_}"        # strip "NN_" order prefix
    hash="${h%.raw}"      # strip ".raw" suffix -> "0x..."
    vendored="$(tr -d '[:space:]' < "$f")"

    fetched=""
    method=""
    # Path 1: raw from a raw-serving RPC, accepted only if canonical.
    resp="$(cast rpc eth_getRawTransactionByHash "$hash" --rpc-url "$RAWTX_RPC" 2>/dev/null | tr -d '"' | tr -d '[:space:]')" || resp=""
    case "$resp" in
        0x[0-9a-fA-F][0-9a-fA-F]*)
            if [ "$(cast keccak "$resp")" = "$hash" ]; then
                fetched="$resp"; method="raw"; n_raw=$((n_raw+1))
            fi
            ;;
    esac

    # Path 2: RLP-reconstruct from the arb1 tx object, keccak-gated too.
    if [ -z "$fetched" ]; then
        tmp="$(mktemp -d)"
        printf '%s\n' "$hash" > "$tmp/hash.txt"
        recon_ok=0
        if python3 "$DIR/reconstruct_raw.py" "$tmp/hash.txt" "$tmp/out" >/dev/null 2>&1; then
            cand="$(cat "$tmp/out"/*_"$hash".raw 2>/dev/null | tr -d '[:space:]')"
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
    sleep 0.3
done

echo "verified $ok/${ok+$((ok+fail))} txs byte-exact ($n_raw via raw RPC, $n_recon via RLP reconstruction)"
[ "$fail" -eq 0 ]
