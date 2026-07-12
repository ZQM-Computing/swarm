"""Local RAG over the ZQM fleet blind-spot doc using nomic-embed-text via N1 Ollama (G-A).
Build: chunk the inlined doc, embed each chunk, persist JSON. Query: cosine top-k.
No external deps, no creds. Embeddings computed live against Ollama :11434.
Source doc is inlined to avoid the MSYS/Win32 filesystem-view split on this host.
"""
import json, re, urllib.request, os, sys

EMB = "fleet_rag_store.json"
EMBED_URL = "http://192.168.1.218:11434/api/embed"
MODEL = "nomic-embed-text"

DOC = r"""
# ZQM Fleet - Full Blind-Spot Enumeration
CLASS 1 - TOOLING / OBSERVABILITY BLIND SPOTS (3 items, B1-B3)
B1. session_search hides 95.7% of interactive chats. Browse returned exactly 3 sessions, all cron. Interactive visible = 0/71. Fix: skill session-history-enumeration (query state.db directly).
B2. The monitoring dashboard is invisible to its own search tool. drift-watch cron dominates browse so you cannot discover the monitor via session_search.
B3. Session consolidation silently collapses history. 60 subagent sessions carry parent_session_id (nested); 3 phantom 0-message sessions.
CLASS 2 - FLEET STATE BLIND SPOTS (5 items, B4-B8)
B4. [CRITICAL] Node-1 agent stack has NO autostart task (will not survive reboot). Get-ScheduledTask for ZQM/Stack/Autostart -> NONE FOUND. apply_stability.ps1 via UAC did NOT register. Live: :8400=000 :4001=000 :11434=200.
B5. N2 (.21) Ollama + Redis: host OFF or unreachable. curl :11434 -> 000. Redis requirepass set from N1 (RCE closed) but bind/protected-mode GATED on N2 break-glass cred.
B6. N3 (.46) Ollama: localhost-only by design, but host reachability now 000. Ambiguous without N3 cred.
B7. N4 (.215) Ollama LAN-exposed, 45 models, OPEN - root cause UNKNOWN. zqmlocal cred REJECTED. Security exposure live.
B8. Inference SPOF - LiteLLM routes 3/4 to N2; N2 dark => those routes dead. No cross-node failover.
CLASS 3 - REMEDIATION PIPELINE BLIND SPOTS (4 items, B9-B12)
B9. 16 OPEN questions in audit ledger never delivered as a classified list. open_questions = 27 total, 11 resolved, 16 OPEN.
B10. 4 reliability items: 1 PRIMARY gap (B4) + 3 GATED/CONSENT.
B11. Remediation vectors: 8 of 12 VIABLE-BLOCKED / DEAD / REPORT-ONLY.
B12. 13 drafted-but-unexecuted scripts on disk gated on UAC or per-node creds.
CLASS 4 - AGENT SELF-DISCIPLINE BLIND SPOTS (3 items, B13-B15)
B13. Two prior "complete" enumerations (12, 16) wrong by 4.4-5.9x. Corrected to 71 interactive / 310 records.
B14. Mis-stated browse cap as "10" + "FTS5 recall-blindness". Corrected: <=3-cap + cron-BM25 dominance.
B15. Curl output doubling trap (MSYS || echo fallback on success). Mitigated.
QUANTIFIED SUMMARY: Tooling 3, Fleet-state 5 (1 CRITICAL), Remediation 4, Self-discipline 3. TOTAL 15.
TOP-3: B4 (apply_stability.ps1 UAC), B7 (N4 local-admin cred), B9/B11 (operator self-run checklist for N2 Redis + B4).
"""

def embed(texts):
    req = json.dumps({"model": MODEL, "input": texts}).encode()
    r = urllib.request.urlopen(EMBED_URL, data=req, timeout=120)
    return json.load(r)["embeddings"]

def chunk_doc(txt):
    blocks = re.split(r"\n(?=B\d+\. )", txt)
    chunks = []
    for b in blocks:
        b = b.strip()
        if not b:
            continue
        m = re.match(r"B(\d+)\.", b)
        cid = "B" + m.group(1) if m else "HDR"
        chunks.append((cid, b[:900]))
    return chunks

def build():
    chunks = chunk_doc(DOC)
    texts = [c[1] for c in chunks]
    vecs = []
    for i in range(0, len(texts), 10):
        vecs.extend(embed(texts[i:i+10]))
    store = {"model": MODEL, "chunks": [{"id": c[0], "text": c[1]} for c in chunks],
             "vectors": vecs}
    json.dump(store, open(EMB, "w"), ensure_ascii=False)
    print("built: %d chunks, %d vectors -> %s" % (len(chunks), len(vecs), EMB))

def cosine(a, b):
    dot = sum(x*y for x, y in zip(a, b))
    na = sum(x*x for x in a) ** 0.5
    nb = sum(x*x for x in b) ** 0.5
    return dot / (na*nb) if na and nb else 0.0

def query(q, k=3):
    store = json.load(open(EMB))
    qv = embed([q])[0]
    return sorted(((cosine(qv, v), c["id"], c["text"]) for c, v in
                   zip(store["chunks"], store["vectors"])), reverse=True)[:k]

if __name__ == "__main__":
    if "--rebuild" in sys.argv or not os.path.exists(EMB):
        build()
    print("\nSAMPLE QUERY: 'how do I survive a reboot on node 1?'")
    for score, cid, text in query("how do I survive a reboot on node 1?"):
        print("  [%.3f] %s: %s" % (score, cid, text[:90].replace("\n", " ")))
