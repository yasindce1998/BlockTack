#!/usr/bin/env python3
"""Logging/caching/retrying HTTP proxy for JSON-RPC: anvil -> proxy -> upstream archive RPC.

- logs every upstream request (method + timing) for visibility
- disk-caches deterministic state requests so warmed state survives restarts
- 60s timeout + 3 retries to break upstream stalls (blastapi-style tarpits)
"""
import json, os, sys, threading, time, hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8559
UPSTREAM = sys.argv[2] if len(sys.argv) > 2 else "https://arbitrum-one-public.nodies.app"
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rpc_cache")
TIMEOUT = 60
CACHEABLE = {"eth_getStorageAt", "eth_getCode", "eth_getBalance", "eth_getTransactionCount",
             "eth_getBlockByNumber", "eth_getBlockByHash", "eth_getTransactionByHash",
             "eth_getTransactionReceipt"}
os.makedirs(CACHE_DIR, exist_ok=True)
print_lock = threading.Lock()

def log(msg):
    with print_lock:
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def cache_key(body):
    return hashlib.sha256(body).hexdigest()

def cache_get(body):
    p = os.path.join(CACHE_DIR, cache_key(body))
    if os.path.exists(p):
        with open(p, "rb") as f:
            return f.read()
    return None

def cache_put(body, resp):
    p = os.path.join(CACHE_DIR, cache_key(body))
    if not os.path.exists(p):
        with open(p, "wb") as f:
            f.write(resp)

def upstream_call(body, depth=0):
    req = urllib.request.Request(UPSTREAM, data=body,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "blocktack-fork-proxy/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read()
    except Exception as e:
        if depth < 3:
            time.sleep(2)
            return upstream_call(body, depth + 1)
        raise

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        cacheable = False
        try:
            payload = json.loads(body)
            if isinstance(payload, list):
                methods = [p.get("method") for p in payload]
                cacheable = all(m in CACHEABLE for m in methods)
            else:
                methods = [payload.get("method")]
                cacheable = payload.get("method") in CACHEABLE
        except Exception:
            methods = ["?"]
        tag = ",".join(str(m) for m in methods)
        if cacheable:
            c = cache_get(body)
            if c is not None:
                log(f"-> {tag} ({length}B) CACHE HIT")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(c)))
                self.end_headers()
                self.wfile.write(c)
                return
        log(f"-> {tag} ({length}B)")
        t0 = time.time()
        try:
            resp = upstream_call(body)
        except Exception as e:
            log(f"!! upstream error after {time.time()-t0:.1f}s: {e}")
            resp = json.dumps({"jsonrpc": "2.0", "id": None,
                               "error": {"code": -32000, "message": f"proxy: {e}"}}).encode()
        log(f"<- {len(resp)}B in {time.time()-t0:.1f}s")
        if cacheable:
            try:
                cache_put(body, resp)
            except Exception:
                pass
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

if __name__ == "__main__":
    print(f"proxy on :{PORT} -> {UPSTREAM} cache={CACHE_DIR}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
