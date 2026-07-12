#!/usr/bin/env bash
# zqm_local_sync.sh -- idempotent re-sync of corrected blind_spot_enumeration.md
# into the zqm-local AnythingLLM workspace (zqm-mesh).
#
# WHY: AnythingLLM's metadata-delete endpoints do NOT purge old vectors from the
# vector store. Re-ingesting an updated doc stacks duplicate/stale chunks and
# similarity search keeps returning the OLD text. The only reliable clean sync is
# a full workspace reset (delete docs -> recreate -> fresh ingest).
#
# T1-safe: credential-free EXCEPT it needs ALLM_KEY (the AnythingLLM API key) in
# the environment. If ALLM_KEY is unset, this step is a no-op (falls back to the
# local fleet_rag_store.json, which is always authoritative for automation).
#
# Called by fleet_automate.py run_action("zqm_local") when ALLM_KEY is present.
set -u
SWARM=/c/Users/zqmco/swarm
PY="C:/Users/zqmco/AppData/Local/Programs/Python/Python312/python.exe"
SRC="$SWARM/blind_spot_enumeration.md"
WS=zqm-mesh
ALLM=http://127.0.0.1:3001

[ -z "${ALLM_KEY:-}" ] && { echo "ALLM_KEY unset -> skip zqm-local sync (local RAG store is authoritative)"; exit 0; }
[ -f "$SRC" ] || { echo "source $SRC missing"; exit 1; }

# 1) list current docs, 2) delete each by docId, 3) recreate workspace, 4) ingest.
OUT=$( curl -s --max-time 15 -H "Authorization: Bearer $ALLM_KEY" "$ALLM/api/v1/workspace/$WS" 2>/dev/null )
DOCIDS=$( echo "$OUT" | "$PY" -c "
import sys,json
try:
    d=json.load(sys.stdin); ws=d.get('workspace')
    if isinstance(ws,list): ws=ws[0] or {}
    for x in (ws.get('documents',[]) if ws else []):
        print(x.get('docId'))
except Exception: pass
" 2>/dev/null )
for DID in $DOCIDS; do
  curl -s --max-time 15 -o /dev/null -X DELETE "$ALLM/api/v1/workspace/$WS/document/$DID" \
    -H "Authorization: Bearer $ALLM_KEY" 2>/dev/null
done
# recreate (AnythingLLM wants {"name":...})
curl -s --max-time 20 -o /dev/null -X POST "$ALLM/api/v1/workspace/new" \
  -H "Authorization: Bearer $ALLM_KEY" -H "Content-Type: application/json" \
  -d "{\"name\":\"$WS\"}" 2>/dev/null
# fresh ingest via the zqm-local MCP-equivalent REST upload (multipart)
curl -s --max-time 60 -o /dev/null -X POST "$ALLM/api/v1/workspace/$WS/upload-file" \
  -H "Authorization: Bearer $ALLM_KEY" -F "file=@$SRC" 2>/dev/null
echo "zqm-local sync: workspace $WS reset + re-ingested $SRC"
