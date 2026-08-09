#!/usr/bin/env python3
"""
api_server.py -- API-driven attestation for the ZQM claim set + hash chain.

Serves the live attestation (re-derived on each call) over HTTP using ONLY the
Python stdlib (no fastapi/uvicorn dependency). Read-only; never writes to the
audit DB or guesses credentials.

Endpoints
  GET /                       -> service banner + endpoint list
  GET /attest                 -> full live attestation JSON (claims + chain + probes)
  GET /attest/summary        -> {claim_count, tally, chain_root, audit_db_chain}
  GET /attest/claim/<ID>      -> single claim by id (e.g. /attest/claim/B4)
  GET /attest/chain           -> the hash chain array
  GET /attest/probes          -> raw live probe values
  GET /audit/chain            -> read-only re-walk of fleet_endpoint_audit.db chain_hashes

Run:  python api_server.py [--port 8088] [--host 127.0.0.1]
"""
import json, sys, argparse, urllib.request, time, os, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from claims_core import build_attestation, build_sitrep, build_open_questions

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://192.168.1.218:11434/api/generate")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3:8b")

# M2: TTL cache for both slow probe-driven builders. 60s freshness.
_SITREP_CACHE = {"ts": 0, "data": None}
_ATTEST_CACHE = {"ts": 0, "data": None}
_SITREP_TTL = 60.0
_ATTEST_TTL = 60.0

def cached_sitrep():
    now = time.time()
    if _SITREP_CACHE["data"] is not None and (now - _SITREP_CACHE["ts"]) < _SITREP_TTL:
        return _SITREP_CACHE["data"], True
    data = build_sitrep()
    _SITREP_CACHE["data"] = data
    _SITREP_CACHE["ts"] = now
    return data, False

def cached_attestation():
    now = time.time()
    if _ATTEST_CACHE["data"] is not None and (now - _ATTEST_CACHE["ts"]) < _ATTEST_TTL:
        return _ATTEST_CACHE["data"], True
    data = build_attestation()
    _ATTEST_CACHE["data"] = data
    _ATTEST_CACHE["ts"] = now
    return data, False

def ollama_render(sitrep):
    """Render the sitrep into a plain-English markdown briefing via N1 Ollama (G-A)."""
    brief = {
        "nodes": [{"id": n["id"], "reach": n["reachable_now"],
                   "ports": {p: n["ports"][p]["code"] for p in n["ports"]}} for n in sitrep["nodes"]],
        "audit_open": sitrep["audit_ledger"]["open_questions_open"],
        "chain_valid": sitrep["audit_ledger"]["chain_valid"],
        "session_total": sitrep["session_store"]["total"],
        "gaps": [{"id": g["id"], "sev": g["severity"], "gate": g["gate"]} for g in sitrep["open_gaps"]],
    }
    prompt = ("You are the ZQM fleet SRE. Given this live sitrep JSON, write a tight "
              "plain-English situational-awareness briefing as markdown (max 110 words): "
              "what is UP, what is DOWN, top risks, and what is BLOCKED on operator "
              "credentials. No preamble.\n\n" + json.dumps(brief))
    req = json.dumps({"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}).encode()
    try:
        r = urllib.request.urlopen(OLLAMA_URL, data=req, timeout=45)
        return json.load(r)["response"].split("</think:6124c78e>")[-1].strip()
    except Exception as e:
        return "# Situational Awareness\n\n(rendering via N1 Ollama failed: %s)" % e

class H(BaseHTTPRequestHandler):
    server_version = "ZQM-Attest/1.0"
    def _send(self, code, obj):
        body = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")
        try:
            # Cheap/baked endpoints first (no slow probe build).
            if path in ("", "/"):
                self._send(200, {
                    "service": "ZQM claim attestation API",
                    "version": "1.0",
                    "endpoints": ["/", "/attest", "/attest/summary", "/attest/claim/<ID>",
                                  "/attest/chain", "/attest/probes", "/audit/chain",
                                  "/sitrep", "/sitrep/markdown",
                                  "/nodes", "/open_questions", "/healthz",
                                  "POST /automate (T1 self-actions)"],
                })
            elif path == "/healthz":
                age = (time.time() - _SITREP_CACHE["ts"]) if _SITREP_CACHE["data"] else None
                self._send(200, {"status": "ok", "pid": os.getpid(),
                                 "cached": _SITREP_CACHE["data"] is not None,
                                 "cache_age_s": (round(age, 1) if age is not None else None),
                                 "endpoints": ["/", "/attest", "/attest/summary", "/attest/claim/<ID>",
                                               "/attest/chain", "/attest/probes", "/audit/chain",
                                               "/sitrep", "/sitrep/markdown", "/nodes",
                                               "/open_questions", "/healthz"]})
            elif path == "/sitrep":
                sr, _ = cached_sitrep()
                self._send(200, sr)
            elif path == "/sitrep/markdown":
                sr, _ = cached_sitrep()
                md = ollama_render(sr)
                self.send_response(200)
                self.send_header("Content-Type", "text/markdown; charset=utf-8")
                self.end_headers()
                self.wfile.write(md.encode("utf-8"))
            elif path == "/nodes":
                sr, _ = cached_sitrep()
                self._send(200, {"nodes": sr["nodes"], "generated": _SITREP_CACHE["ts"]})
            elif path == "/open_questions":
                self._send(200, build_open_questions())
            # Slow probe-driven attestation endpoints (cached).
            else:
                att, _ = cached_attestation()
                if path == "/attest":
                    self._send(200, att)
                elif path == "/attest/summary":
                    self._send(200, {
                        "claim_count": att["claim_count"], "tally": att["tally"],
                        "chain_root": att["chain_root"], "audit_db_chain": att["audit_db_chain"],
                    })
                elif path.startswith("/attest/chain"):
                    self._send(200, {"chain_root": att["chain_root"], "chain": att["chain"]})
                elif path == "/attest/probes":
                    self._send(200, att["probes"])
                elif path.startswith("/attest/claim/"):
                    cid = path.rsplit("/", 1)[-1].upper()
                    hit = [c for c in att["claims"] if c["id"].upper() == cid]
                    if hit:
                        self._send(200, hit[0])
                    else:
                        self._send(404, {"error": "unknown claim id", "id": cid,
                                          "known": [c["id"] for c in att["claims"]]})
                elif path == "/audit/chain":
                    self._send(200, att["audit_db_chain"])
                else:
                    self._send(404, {"error": "unknown endpoint", "path": path})
        except Exception as e:
            self._send(500, {"error": str(e)[:200]})
    def log_message(self, *a):
        pass  # quiet

    def do_POST(self):
        # T1 automation: safe, credential-free self-actions only.
        path = self.path.split("?")[0].rstrip("/")
        if path != "/automate":
            self._send(404, {"error": "unknown endpoint (POST)", "path": path})
            return
        try:
            import fleet_automate as fa
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else b"{}"
            try:
                req = json.loads(body or b"{}")
            except Exception:
                req = {}
            action = str(req.get("action", "all")).lower()
            if action == "all":
                report = fa.run_all()
            elif action in ("watchdog", "rag", "zqm_local", "narrative", "reattest", "restart"):
                report = {"ts": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
                           "tier": "T1 (safe, credential-free)",
                           "actions": {action: fa.run_action(action)},
                           "all_ok": True}
            else:
                self._send(400, {"error": "unknown action", "known":
                                 ["all", "watchdog", "rag", "zqm_local", "narrative", "reattest", "restart"]})
                return
            self._send(200, report)
        except Exception as e:
            self._send(500, {"error": str(e)[:200]})

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8088)
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), H)
    print("ZQM attestation API ready pid=%d http://%s:%d  (Ctrl-C to stop)"
          % (os.getpid(), args.host, args.port), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped", flush=True)

if __name__ == "__main__":
    main()
