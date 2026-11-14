#!/usr/bin/env bash
# Replay the KyberSwap Arbitrum attacker transactions on the local anvil
# fork (127.0.0.1:8558 by default). Pure curl/python3 (no cast
# dependency). Resumable: skips already-mined txs. Exits non-zero if any
# transaction reverts or never mines.
#
# The attacker EOA (nonce 0 at fork block 153081940, 2 ETH balance
# already in the fork state) re-broadcasts the 12 vendored signed
# transactions in order: 2 contract deployments + 10 attack batches.
set -u
cd "$(dirname "$0")"
RPC="${ANVIL_RPC:-http://127.0.0.1:8558}"
LOG="${REPLAY_LOG:-replay_run.log}"

rpc() { # rpc <method> <json-params> -> result on stdout
    curl -s -m 7200 -X POST -H 'Content-Type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$RPC"
}

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

receipt_status() { # -> "0x1" / "0x0" / "" (not mined)
    rpc eth_getTransactionReceipt "[\"$1\"]" | python3 -c '
import json,sys
try:
    d = json.load(sys.stdin)
    r = d.get("result")
    print(r["status"] if r else "")
except Exception:
    print("")
'
}

rc=0
for f in transactions/*.raw; do
    name="$(basename "$f")"
    h="${name#*_}"
    hash="${h%.raw}"
    st="$(receipt_status "$hash")"
    if [ -n "$st" ]; then
        log "SKIP  $name (already mined, status=$st)"
        [ "$st" = "0x1" ] || rc=1
        continue
    fi
    raw="$(tr -d '[:space:]' < "$f")"
    log "PUBLISH $name ..."
    t0=$SECONDS
    resp=$(rpc eth_sendRawTransaction "[\"$raw\"]")
    log "SENT   $name -> $(echo "$resp" | head -c 200) (send took $((SECONDS-t0))s)"
    st=""
    for i in $(seq 1 3600); do
        st="$(receipt_status "$hash")"
        if [ -n "$st" ]; then
            log "MINED  $name status=$st (waited $((SECONDS-t0))s)"
            break
        fi
        sleep 3
    done
    if [ -z "$st" ]; then
        log "TIMEOUT waiting for receipt of $name"
        rc=1
    elif [ "$st" != "0x1" ]; then
        log "REVERTED $name"
        rc=1
    fi
done
log "REPLAY SEQUENCE COMPLETE"
exit $rc
