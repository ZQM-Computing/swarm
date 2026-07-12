#!/usr/bin/env bash
# zqm_local_sync.sh -- idempotent re-sync of corrected blind_spot_enumeration.md
# into the zqm-local AnythingLLM workspace (zqm-mesh).
#
# WHY: AnythingLLM's metadata-delete endpoints do NOT purge old vectors from the
# vector store. Re-ingesting an updated doc stacks duplicate/stale chunks and
# similarity search keeps returning the OLD text. The only reliable clean sync is
# a full workspace reset (delete docs by docId -> recreate -> fresh ingest).
#
# T1-safe: the only secret is ALLM_KEY (AnythingLLM API key) from the environment.
# If ALLM_KEY is unset, this step is a no-op (local fleet_rag_store.json is the
# authoritative automation target). No credentials are hardcoded.
#
# Called by fleet_automate.py run_action("zqm_local") when ALLM_KEY is present.
set -u
SWARM=/c/Users/zqmco/swarm
PY="C:/Users/zqmco/AppData/Local/Programs/Python/Python312/python.exe"
SRC="$SWARM/blind_spot_enumeration.md"
WS=zqm-mesh
ALLM=http://127.0.0.1:3001

[ -z "${ALLM_KEY:-}" ] && { echo "ALLM_KEY unset -> skip zqm-local sync"; exit 0; }
[ -f "$SRC" ] || { echo "source $SRC missing"; exit 1; }

# 1) collect current docIds  2) delete each  3) recreate ws  4) fresh ingest
DOCIDS=$( curl -s --max-time 15 -H "Authorization: Bearer $ALLM_KEY" "$ALLM/api/v1/workspace/$WS" \
  | "$PY" -c "import sys,json
try:
    d=json.load(sys.stdin); ws=d.get('workspace')
    if isinstance(ws,list): ws=ws[0] or {}
    for x in (ws.get('documents',[]) if ws else []):
        print(x.get('docId'))
except Exception:
    pass" )

for DID in $DOCIDS; do
  curl -s --max-time 15 -o /dev/null -X DELETE "$ALLM/api/v1/workspace/$WS/document/$DID" \
    -H "Authorization: Bearer $ALLM_KEY"
done

# recreate (AnythingLLM expects {"name":...})
curl -s --max-time 20 -o /dev/null -X POST "$ALLM/api/v1/workspace/new" \
  -H "Authorization: Bearer $ALLM_KEY" -H "Content-Type: application/json" \
  -d "{\"name\":\"$WS\"}"

# fresh upload (multipart) -> AnythingLLM embeds async
curl -s --max-time 60 -o /dev/null -X POST "$ALLM/api/v1/workspace/$WS/upload-file" \
  -H "Authorization: Bearer $ALLM_KEY" -F "file=@$SRC"

echo "zqm-local sync: workspace $WS reset + re-ingested $SRC"
