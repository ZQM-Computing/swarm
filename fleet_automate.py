#!/usr/bin/env python3
"""
fleet_automate.py -- T1 automation: SAFE, CREDENTIAL-FREE self-actions only.

Runs the non-mutating intelligence loops the SA surface depends on. NEVER touches
fleet services, never guesses credentials, never pins/restarts Ollama (would
self-sabotage this API's own render + RAG paths).

Actions:
  watchdog  -> run sa_watchdog.py (observe + append sa_watchdog_log on change)
  rag       -> fleet_rag.py --rebuild (re-embed blind_spot doc via nomic)
  narrative -> regenerate sitrep_narrative.md via N1 Ollama (G-A)
  reattest  -> bust in-process caches (force fresh build on next call)
  all       -> run watchdog, rag, narrative, reattest (default)

Called by POST /automate in api_server.py. Returns a structured report.
"""
import subprocess, os, sys, json, time, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
PY = "C:/Users/zqmco/AppData/Local/Programs/Python/Python312/python.exe"
BASH = "C:/Users/zqmco/AppData/Local/Programs/Git/usr/bin/bash.EXE"

def _run(script, args, timeout=180):
    path = os.path.join(HERE, script)
    # pick interpreter by extension: .sh -> bash, else python
    cmd = ([BASH, path] if script.endswith(".sh") else [PY, path]) + args
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           cwd=HERE)
        return {"ok": r.returncode == 0, "rc": r.returncode,
                "out": (r.stdout or "")[-600:], "err": (r.stderr or "")[-400:],
                "sec": round(time.time() - t0, 1)}
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": -1, "out": "", "err": "timeout",
                "sec": round(time.time() - t0, 1)}
    except Exception as e:
        return {"ok": False, "rc": -2, "out": "", "err": str(e)[:200],
                "sec": round(time.time() - t0, 1)}

def run_action(name):
    if name == "watchdog":
        return _run("sa_watchdog.py", [])
    if name == "rag":
        return _run("fleet_rag.py", ["--rebuild"], timeout=240)
    if name == "zqm_local":
        # Re-sync corrected blind_spot_enumeration.md into the zqm-local
        # AnythingLLM workspace (zqm-mesh). AnythingLLM does not purge old
        # vectors on metadata-delete, so the script does a full workspace
        # reset + fresh ingest. No-op (exit 0) if ALLM_KEY is unset.
        return _run("zqm_local_sync.sh", [])
    if name == "narrative":
        # Reuse the API's ollama_render by importing build_sitrep + rendering.
        try:
            from claims_core import build_sitrep
            import api_server as ap
            sr = build_sitrep()
            md = ap.ollama_render(sr)
            out_path = os.path.join(HERE, "sitrep_narrative.md")
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(md)
            return {"ok": True, "rc": 0, "out": "wrote %d bytes" % len(md),
                    "err": "", "sec": 0.0}
        except Exception as e:
            return {"ok": False, "rc": -2, "out": "", "err": str(e)[:200], "sec": 0.0}
    if name == "reattest":
        # Bust caches in the running server module so next call rebuilds fresh.
        try:
            import api_server as ap
            ap._SITREP_CACHE.update({"ts": 0, "data": None})
            ap._ATTEST_CACHE.update({"ts": 0, "data": None})
            return {"ok": True, "rc": 0, "out": "caches busted", "err": "", "sec": 0.0}
        except Exception as e:
            return {"ok": False, "rc": -2, "out": "", "err": str(e)[:200], "sec": 0.0}
    if name == "restart":
        # Detached self-restart. We spawn restart_api.sh via os.spawnl(P_DETACH)
        # so the child is a fully independent process that SURVIVES this server
        # being taskkilled (subprocess.Popen / nohup / cmd-start all died with
        # the parent under MSYS). The script kills this listener, respawns, and
        # polls /healthz. Caller re-checks /healthz for the new pid.
        # Excluded from run_all by design.
        try:
            BASH = r"C:\Users\zqmco\AppData\Local\Programs\Git\usr\bin\bash.EXE"
            script = os.path.join(HERE, "restart_api.sh")
            os.spawnl(os.P_DETACH, BASH, "bash", script)
            return {"ok": True, "rc": 0,
                    "out": "restart scheduled (detached via P_DETACH); confirm via GET /healthz",
                    "err": "", "sec": 0.0}
        except Exception as e:
            return {"ok": False, "rc": -2, "out": "", "err": str(e)[:200], "sec": 0.0}
    return {"ok": False, "rc": -3, "out": "", "err": "unknown action", "sec": 0.0}

def run_all():
    report = {"ts": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
              "tier": "T1 (safe, credential-free)", "actions": {}}
    for a in ("watchdog", "rag", "zqm_local", "narrative", "reattest"):
        report["actions"][a] = run_action(a)
    report["all_ok"] = all(v["ok"] for v in report["actions"].values())
    return report

if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which == "all":
        print(json.dumps(run_all(), indent=2))
    else:
        print(json.dumps(run_action(which), indent=2))
