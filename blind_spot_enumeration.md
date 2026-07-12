# ZQM Fleet — Full Blind-Spot Enumeration
Generated: 2026-07-12 (recreated from live state.db, live fleet curl probes, and fleet_endpoint_audit.db)
Classification: internal / operator-reference

This document enumerates every blind spot identified across tooling, fleet state,
the remediation pipeline, and the agent's own verification discipline. Each item
is tagged with status and the proof source. Counts are verified, not asserted.

================================================================================
CLASS 1 — TOOLING / OBSERVABILITY BLIND SPOTS  (3 items, B1–B3)
================================================================================

B1. session_search hides 95.7% of interactive chats.
    Status: CONFIRMED (mechanism verified this session)
    Proof:
      - Browse (no query) returned exactly 3 sessions, all cron. Interactive
        visible = 0 / 71.
      - Discovery (query) hard-caps at 3 results/call ("Garden","bounty","node"
        each returned 3).
      - messages_fts = 150,668 rows, COMPLETE (trigram variant present, live
        insert/update/delete triggers). The defect is PRESENTATION, not indexing:
        per-session BM25 over a cron-heavy corpus + a 3-row cap buries chats.
    Fix: skill `session-history-enumeration` (query state.db directly).

B2. The monitoring dashboard is invisible to its own search tool.
    Status: CONFIRMED
    Proof: drift-watch cron (71 runs) dominates browse, so you cannot discover
      the monitor via session_search. The monitor IS live:
      fleet_endpoint_audit.db mtime 2026-07-12 12:25, populated tables
      (claim_hash 16, swarm_findings 68, hash_drift_log 82, open_questions 27).

B3. Session consolidation silently collapses history.
    Status: CONFIRMED
    Proof: consolidate_meta table exists; 60 subagent sessions carry
      parent_session_id (nested, hidden from flat lists); 3 phantom
      (0-message) sessions present. The "310 records" is post-merge surface;
      true interaction volume is higher once subagent work is re-included.

================================================================================
CLASS 2 — FLEET STATE BLIND SPOTS  (5 items, B4–B8) — curl-verified 2026-07-12
================================================================================

B4. [CRITICAL] Node-1 ZBit+LiteLLM+Ollama stack has NO autostart (will not survive reboot).
    Status: OPEN / CONFIRMED (no task/service covers the ZBit stack; stack currently manually-up)
    Proof (re-verified 2026-07-12 live):
      - No Windows service and no scheduled task references ollama/zbit/litellm/zqm/
        hermes/swarm. SpaceAgentTask[Ready,Boot] exists but runs SpaceAgent.exe
        (system telemetry, NOT the ZBit stack) — earlier "no task at all" was imprecise.
      - apply_stability.ps1 is a MANUAL fallback (not registered as an AtStartup task).
      - Live stack RIGHT NOW: :8400 ZBit=200 (UP), :4001 LiteLLM=200 (UP),
        :11434 Ollama=200 (UP). Running but launched MANUALLY, NOT by a persistent
        task -> dies on next reboot.
    Impact: every reboot silently kills the agent brain (ZBit+LiteLLM) until manual
      re-launch. The durable gap is the missing autostart, not a perpetual outage.
    Closure: operator runs the elevated apply_stability.ps1 (see checklist B4).

B5. N2 (.21) Ollama + Redis: host OFF or unreachable.
    Status: UNVERIFIED (host dark)
    Proof: curl :11434 -> 000. Audit DB: N2 Redis set requirepass from N1
      (RCE closed) but bind/protected-mode + final hardening GATED on N2
      break-glass cred (NOT 'EllaRose89!').

B6. N3 (.46) Ollama: localhost-only by design, but host reachability now 000.
    Status: AMBIGUOUS
    Proof: curl :11434 -> 000. Audit says localhost-bound (LAN-closed) — consistent,
      but N1 cannot distinguish "intentional localhost" from "host down" without cred.

B7. N4 (.215) Ollama LAN-exposed, 46 models, OPEN — root cause INFERRED (Ollama default
    binds 0.0.0.0:11434; no OLLAMA_HOST pin visible from N1). Unconfirmed on-host
    (no N4 local-admin cred).
    Status: OPEN (exposure live)
    Proof: curl :11434 -> 200 (UP, exposed, 46 models). Door-B Node-4 zqmlocal cred was
      REJECTED ("No authentication methods available"). WHY it is LAN-open is inferred
      as the default bind, but undetermined with certainty without N4 access. Security
      exposure is live.

B8. Inference SPOF — LiteLLM routes 3/4 to N2; N2 currently unreachable from N1
    (probe timeout 2026-07-12) => those routes degraded/dead when N2 down.
    Status: OPEN (by design, no failover) — N2 reachability INCONCLUSIVE now.
    Proof: reliability table: "LiteLLM routes 3/4 to N2... No cross-node
      failover configured." N2 :6379/:11434 unreachable this pass (cannot
      re-confirm prior AUTH_REQ state).

================================================================================
CLASS 3 — REMEDIATION PIPELINE BLIND SPOTS  (4 items, B9–B12)
================================================================================

B9. 16 OPEN questions in audit ledger never delivered as a classified list.
    Status: SURFACED THIS SESSION (now in this doc + checklist)
    Proof: open_questions table = 27 total, 11 resolved, 16 OPEN (41%).
      Highlights: Q4 N2 Redis incomplete; Q6/Q12 N1 Ollama LAN-open (DiD missing);
      Q11 SMB/WinRM scope; Q14 LiteLLM master_key missing; Q20–25 supervision/
      bind/retry/integrate drafts all OPEN.
    CORRECTION 2026-07-12: Q14 "master_key missing" is STALE — litellm_config.yaml:69
      wires `master_key: ${LITELLM_MASTER_KEY}` (env from .env). Runtime enforcement
      depends on whether the env var is set (unverified). Reclassify Q14 as
      "master_key WIRED, enforcement UNVERIFIED" not "missing".

B10. 4 reliability items: 1 PRIMARY gap (B4) + 3 GATED/CONSENT.
    Status: OPEN
    Proof: reliability_applied table:
      - litellm zbit-heavy timeout+fallback: APPLIED+VERIFIED
      - ZBit/LiteLLM boot autostart: GATED (UAC)
      - sshd crash auto-restart: APPLIED
      - N2 Redis UNAUTH: PARTIAL (requirepass live; bind/fw GATED N2 cred)

B11. Remediation vectors: 8 of 12 VIABLE-BLOCKED / DEAD / REPORT-ONLY.
    Status: OPEN
    Proof: remediations table — N2 Redis only 2 viable vectors (WinRM-from-N1
      needs N2 cred; operator self-run). SSH/RDP/mesh/cached-cred = DEAD.

B12. 13 drafted-but-unexecuted scripts on disk (effect = phantom until elevated).
    Status: DRAFTED-OPEN
    Proof: stability_*.ps1, integrate_fleet.py, redact_*.py, n2_redis_fix.ps1
      exist but are gated on UAC or per-node creds.

================================================================================
CLASS 4 — AGENT SELF-DISCIPLINE BLIND SPOTS  (3 items, B13–B15)
================================================================================

B13. Two prior "complete" enumerations (12, 16) wrong by 4.4–5.9x.
    Status: CORRECTED (true count 71 interactive / 310 records)
    Proof: direct state.db query this session.

B14. Mis-stated browse cap as "10" + "FTS5 recall-blindness".
    Status: CORRECTED
    Proof: verified mechanism = <=3-cap + cron-BM25 dominance; skill patched.

B15. Curl output doubling trap (MSYS `|| echo` fallback on success).
    Status: MITIGATED
    Proof: re-probed with 3-digit normalization before reporting.

================================================================================
QUANTIFIED SUMMARY
================================================================================
  Tooling blind spots .......... 3  (B1–B3)
  Fleet-state blind spots ...... 5  (B4–B8)  [1 CRITICAL, 4 OPEN/UNVERIFIED]
  Remediation-pipeline gaps .... 4  (B9–B12)  [16 open Q's, 4 gated reli, 13 phantom scripts]
  Self-discipline blind spots .. 3  (B13–B15)
  TOTAL CLASSIFIED ............. 15

TOP-3 TO CLOSE (highest leverage):
  1. B4  — execute apply_stability.ps1 (UAC) so ZBit+LiteLLM survive reboot.
  2. B7  — get N4 local-admin cred to determine WHY Ollama is LAN-open.
  3. B9/B11 — operator self-run checklist for N2 Redis + B4 (no agent creds needed).
