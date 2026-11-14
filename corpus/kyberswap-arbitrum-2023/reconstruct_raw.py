#!/usr/bin/env python3
"""Reconstruct raw signed EVM transactions from eth_getTransactionByHash fields.

Supports type 0 (legacy, incl. EIP-155), type 1 (EIP-2930), type 2 (EIP-1559).
A signed tx is fully determined by its fields, so reconstruction from
(nonce, gas, to, value, data, chainId, v/yParity, r, s, accessList) is byte-exact.
Source: arb1.arbitrum.io/rpc serves full historical tx objects incl. signatures.
"""
import json, sys, urllib.request

RPC = "https://arb1.arbitrum.io/rpc"

def encode_len(l, off):
    if l < 56:
        return bytes([off + l])
    lb = l.to_bytes((l.bit_length() + 7) // 8, "big")
    return bytes([off + 55 + len(lb)]) + lb

def enc_int(n):
    if n == 0:
        return b"\x80"
    if n <= 0x7f:
        return bytes([n])
    out = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return encode_len(len(out), 0x80) + out

def enc_bytes(b):
    if len(b) == 1 and b[0] <= 0x7f:
        return b
    return encode_len(len(b), 0x80) + b

def rlp_list(items):
    payload = b"".join(items)
    return encode_len(len(payload), 0xc0) + payload

def strip_leading_zeros(b):
    i = 0
    while i < len(b) and b[i] == 0:
        i += 1
    return b[i:] if i < len(b) else b"\x00"

def to_int(x):
    if x is None:
        return 0
    return int(x, 16) if isinstance(x, str) else int(x)

def to_bytes(x):
    if x is None or x == "0x":
        return b""
    if isinstance(x, str):
        h = x[2:]
        if len(h) % 2:
            h = "0" + h
        return bytes.fromhex(h)
    return x

def access_list_rlp(al):
    items = []
    for entry in al or []:
        items.append(rlp_list([
            enc_bytes(to_bytes(entry["address"])),
            rlp_list([enc_bytes(to_bytes(k)) for k in entry.get("storageKeys", [])]),
        ]))
    return rlp_list(items)

def reconstruct(tx):
    t = to_int(tx.get("type", "0x0"))
    chain_id = to_int(tx.get("chainId"))
    nonce = to_int(tx["nonce"])
    gas = to_int(tx["gas"])
    to = to_bytes(tx.get("to"))
    value = to_int(tx["value"])
    data = to_bytes(tx.get("input") or tx.get("data"))
    r = strip_leading_zeros(to_bytes(tx["r"]))
    s = strip_leading_zeros(to_bytes(tx["s"]))
    v = to_int(tx["v"])
    if t == 0:
        if v >= 35:  # EIP-155 legacy
            items = [enc_int(nonce), enc_int(to_int(tx["gasPrice"])), enc_int(gas),
                     enc_bytes(to), enc_int(value), enc_bytes(data),
                     enc_int(chain_id), enc_bytes(b""), enc_bytes(b""), enc_bytes(r), enc_bytes(s)]
        else:
            items = [enc_int(nonce), enc_int(to_int(tx["gasPrice"])), enc_int(gas),
                     enc_bytes(to), enc_int(value), enc_bytes(data), enc_int(v), enc_bytes(r), enc_bytes(s)]
        return rlp_list(items)
    elif t == 1:
        ypar = v if v in (0, 1) else v - 27
        return bytes([0x01]) + rlp_list([
            enc_int(chain_id), enc_int(nonce), enc_int(to_int(tx["gasPrice"])),
            enc_int(gas), enc_bytes(to), enc_int(value), enc_bytes(data),
            access_list_rlp(tx.get("accessList")), enc_int(ypar), enc_bytes(r), enc_bytes(s)])
    elif t == 2:
        ypar = v if v in (0, 1) else v - 27
        return bytes([0x02]) + rlp_list([
            enc_int(chain_id), enc_int(nonce),
            enc_int(to_int(tx["maxPriorityFeePerGas"])), enc_int(to_int(tx["maxFeePerGas"])),
            enc_int(gas), enc_bytes(to), enc_int(value), enc_bytes(data),
            access_list_rlp(tx.get("accessList")), enc_int(ypar), enc_bytes(r), enc_bytes(s)])
    else:
        raise ValueError(f"unsupported tx type {t}")

def get_tx(h, rpc=RPC):
    req = urllib.request.Request(
        rpc, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionByHash",
                              "params": [h]}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "blocktack-fetch/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        res = json.loads(resp.read())
    if not res.get("result"):
        raise RuntimeError(f"no tx {h}: {res}")
    return res["result"]

def raw_hex(tx):
    return "0x" + reconstruct(tx).hex()

if __name__ == "__main__":
    import os
    hashes = [l.strip() for l in open(sys.argv[1]) if l.strip() and not l.strip().startswith("#")]
    outdir = sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    for i, h in enumerate(hashes):
        tx = get_tx(h)
        raw = raw_hex(tx)
        open(f"{outdir}/{i:02d}_{h}.raw", "w").write(raw)
        print(f"{i:02d} {h} nonce={to_int(tx['nonce'])} len={len(raw)//2-1}B to={tx.get('to') or 'CREATE'}")
