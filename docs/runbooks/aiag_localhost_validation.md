# AIAG Localhost Validation Runbook

**Scope:** AG-177 (shared infra) + AG-178 (Tier 1A attack paths) + AG-179 (Tier 1B trust score) + AG-180 (Tier 2A data reachability) + AG-181 (Tier 2C lifecycle drift) + AG-182 (Tier 3A behavior baseline).

**Audience:** Founder + dev. Validates every AIAG capability end-to-end on localhost against a seeded demo tenant. Cloud-dev deployment is the next step after this passes.

---

## Pre-flight (one-time)

### 1. Confirm running services
```bash
# Backend should be on :5001
lsof -i :5001 | grep LISTEN          # expect Python wsgi.py
# Frontend should be on :3000
lsof -i :3000 | grep LISTEN          # expect node vite/CRA
# Postgres should be on :5432
PGPASSWORD=changeme psql -h localhost -p 5432 -U auditgraph_admin -d auditgraph -c "SELECT 1"
```

### 2. ⚠️ Restart the backend after every commit that adds/edits routes

The currently running backend process is whatever you started before this session. New routes added by commit `212d934` (Tier 1) and `53fe7e8` (Tier 2/3) **are not loaded until you restart**.

```bash
# Find the existing process
lsof -i :5001 | grep LISTEN
# Kill it (or Ctrl-C in its terminal)
kill <PID>
# Restart from backend/
cd backend && ./venv/bin/python wsgi.py
```

If you don't restart you'll see `Scorecard API error: 404`, `Failed to load anomalies (HTTP 404)`, `Unable to load AI lifecycle snapshot`, etc. **This is the cause of every error in the current screenshots.**

### 3. Apply migrations 120 → 124 if you haven't already
```bash
cd backend
for n in 120 121 122 123 124; do
  PGPASSWORD=changeme psql -h localhost -p 5432 -U auditgraph_admin -d auditgraph \
    -f migrations/${n}_*.sql 2>&1 | tail -2
done
```

### 4. Seed the demo tenant (localhost-only synthetic data)
```bash
cd backend
./venv/bin/python scripts/seed_aiag_demo.py --org-id 10
```

This populates org=10 with: 8 AI agents, 3 cognitive services accounts with managed identities, 2 key vaults (one with KV-Admin grants), 4 storage accounts (1 tagged PHI, 1 tagged PCI), 2 SQL DBs (1 tagged Source), 2 Cosmos accounts, and 2 historical discovery runs so lifecycle drift can fire. **All deterministic UUIDs — no real Azure data, no PHI content.**

Login: `demoadmin` / `changeme` on `http://localhost:3000`.

---

## Per-feature validation matrix

For every check: ✅ = pass, ❌ = fail (write what you saw + screenshot).

### AG-178 — AI Identity Attack Paths
| # | Action | Expected | Got |
|---|---|---|---|
| 1 | Nav `Sidebar → AI Security → AI Attack Paths` | Page renders; 3 stats at top show counts (non-zero) | |
| 2 | Click the first path in the list | `AttackPathView` renders cinematic chain with 6-7 nodes | |
| 3 | Look at the chain node icons | ai_agent 🤖, managed_identity 🛡, kv_secret 🔑, storage_account 🗄, data_classification 📋, network_egress 🌐 | |
| 4 | Look above the chain | MITRE chip strip with T1078.004, T1552.001, T1530, T1041 — chips clickable to attack.mitre.org | |
| 5 | Look below the chain | Blast-radius rollup: `1 vault · 12 secrets · 4 storage accts · ~120K PHI rows · open egress` | |
| 6 | Empty case: `curl /api/attack-paths?source_entity_type=ai_agent` with a fresh tenant | Returns `{paths: []}` and UI shows empty state | |

**Curl:** `curl -H "Authorization: Bearer $TOKEN" http://localhost:5001/api/attack-paths?source_entity_type=ai_agent`

---

### AG-179 — Trust Score + Board Scorecard
| # | Action | Expected | Got |
|---|---|---|---|
| 1 | Nav `AI Inventory → Agents` → click an AI agent | `AIInvestigateDrawer` opens; **first** thing visible is the Trust Score card | |
| 2 | Watch the score on first open | Needle sweeps 0 → score over ~800ms (cubic-out) | |
| 3 | Below the score | 5 dimension rows: Ownership · Secrets · Egress · Telemetry · Oversight — each with a grade chip + 1-line evidence | |
| 4 | Hover the Telemetry grade | Tooltip: "Heuristic: last_sign_in OR last_activity within 30d. PARTIAL/FULL split requires diagnostic settings (v1.1)" | |
| 5 | Nav `Sidebar → AI Security → Board Scorecard` | 5 hero KPI cards count up from 0 over ~600ms | |
| 6 | Below the KPI cards | Distribution histogram (4 bars: Strong / Good / Elevated / Critical) | |
| 7 | Below that | Trend sparkline (inline SVG, no chart library) showing the last 180 days | |
| 8 | Worst-10 table | Click a row → navigates to `/identities/<id>` | |
| 9 | "Download Board Pack" button | Stub: `alert('Board pack PDF — coming in next sprint')` | |

**Curl:** `curl -H "Authorization: Bearer $TOKEN" http://localhost:5001/api/ai-security/board-scorecard`

---

### AG-180 — Sensitive Data Reachability
| # | Action | Expected | Got |
|---|---|---|---|
| 1 | Nav `Sidebar → AI Security → Data Reachability` | Page renders; 7 classification hero cards (PHI / PCI / PII / Source / HR / Financial / Confidential) | |
| 2 | Header copy | Says "**We never read data-plane content.** Classification is based on Azure tags you set and resource-name patterns." | |
| 3 | Each card shows | Resource count + Est. records (or "—" — never fabricated) + `X tagged · Y suspected (name)` | |
| 4 | Hover the "X tagged · Y suspected" line | Tooltip explains tagged=HIGH confidence, name-pattern=MEDIUM confidence, never inspects content | |
| 5 | Open `AIInvestigateDrawer` for an AI agent with KV-Admin | Should show data-reachability breakdown per classification — agent's est. records exposure | |
| 6 | Empty case: drop all `data_classification` columns | Page shows "No classified data detected yet" + auto-classify CTA | |

**Curl:** `curl -H "Authorization: Bearer $TOKEN" http://localhost:5001/api/data-security`

---

### AG-181 — AI Lifecycle + Drift
| # | Action | Expected | Got |
|---|---|---|---|
| 1 | Nav `Sidebar → AI Security → AI Lifecycle` | Page renders with 3 bucket cards: Joiners (blue), Movers (amber), Leavers (gray) | |
| 2 | Watch bucket cards on mount | J→M→L cascade animation over ~400ms | |
| 3 | Each bucket | Big count + up to 5 truncated identity names — click row → /identities/<id> | |
| 4 | Recent events table below | event_type | identity | severity chip | timestamp | description | |
| 5 | The seeded `ai_permissions_escalated` event | Severity chip should be CRITICAL (red) | |
| 6 | The seeded `model_changed` event | Should show with MITRE chip if tagged | |
| 7 | Toggle window 7 / 30 / 90 days | Refetches with new `window_days` param | |
| 8 | Empty case: clean tenant with 1 run | "No AI lifecycle events in the last 7 days. The lifecycle log populates after at least 2 discovery runs." | |

**Curl:** `curl -H "Authorization: Bearer $TOKEN" http://localhost:5001/api/dashboard/ai-jml-snapshot?window_days=7`

---

### AG-182 — Activity Timeline + Behavior Baseline
| # | Action | Expected | Got |
|---|---|---|---|
| 1 | Nav `Sidebar → AI Security → Activity Timeline` | Two panels: Recent Anomalies (top) + Per-Agent Forensic Timeline (bottom) | |
| 2 | Anomalies panel | Up to 5 recent. Each row: agent ID + anomaly_type badge (volume_spike red / new_peer orange / new_resource orange / off_hours_break amber) + delta | |
| 3 | Per-Agent dropdown | Agent picker (sourced from `/api/ai-agents/enriched`) | |
| 4 | Pick `ai_startup_alexander_CoS_project` | Baseline strip shows 4 metric mini-cards (avg/p95 model calls, records read, distinct peers) | |
| 5 | Cold-start case | Yellow "Still learning (5/14 days)" badge if samples_count < 14 | |
| 6 | Timeline below | Events fade in cascading (~30ms each, capped at 30) | |
| 7 | Click a timeline event | Expands to show resource_id, resource_type, source, raw_payload | |

**Curl:** `curl -H "Authorization: Bearer $TOKEN" http://localhost:5001/api/ai-agents/activity/anomalies?limit=20`

---

## Acceptance checklist

Before declaring "ready for cloud-dev":
- [ ] All ✅ in the matrix above on the seeded tenant.
- [ ] Empty-state UX verified by hitting a clean tenant (org=99 unused) — every page shows honest copy, no errors, no fake data.
- [ ] `tsc --noEmit` clean.
- [ ] Backend logs show no exceptions during a full discovery run.
- [ ] PHI copy verified: header says "We never read data-plane content."
- [ ] Trust Score thresholds (90/70/50) reviewed and signed off by founder (see `docs/runbooks/trust_score_thresholds_proposal.md`).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| "Scorecard API error: 404" | Backend not restarted since code change | Kill PID + `./venv/bin/python wsgi.py` |
| "Unable to load AI lifecycle snapshot" | Same | Same |
| Empty pages everywhere with `200 OK` | No demo seed loaded | Run `seed_aiag_demo.py` |
| Trust score shows 100/100 for everyone | Org has no detect_signals data | Re-run discovery against the seeded tenant |
| `agent_classifications` table missing | Migration 076 wasn't applied | `psql -f migrations/076_agent_classifications.sql` |
