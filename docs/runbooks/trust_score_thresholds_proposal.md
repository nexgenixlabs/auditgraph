# AI Agent Trust Score — Threshold Proposal for Founder Sign-Off

**Status:** ⚠️ Awaiting founder approval. Do **not** show this to any external customer until thresholds are signed off — post-launch recalibration would churn scores and embarrass early users.

**Ticket:** AG-179 acceptance criterion: *"Grade thresholds … stored in `settings` table — NOT hardcoded. Founder approval required before customer exposure."*

---

## What needs sign-off

Two things:
1. **Per-dimension penalty weights** (subtracted from 100 to produce the 0-100 trust_score)
2. **Display band thresholds** (which score is `STRONG` vs `GOOD` vs `ELEVATED` vs `CRITICAL`)

Both live in code today as fallback defaults. The recommended path: founder signs off on the values below → ops writes them to the `settings` table key `agent_trust_weights` → engine reads from settings with these as fallback only.

---

## Recommended penalty weights

For each dimension, the agent earns a grade and the trust_score is decremented by a penalty. Default weights below — adjust as needed.

| Dimension | Grade | Penalty | Rationale |
|---|---|---|---|
| **Ownership** | PASS | 0 | Owner is required for accountability |
| | FAIL | **15** | Ownerless agent → blast radius unaccountable |
| **Secrets** | NONE | 0 | No secrets-vault access |
| | LOW | 5 | Single secret read |
| | MEDIUM | 12 | Vault-level read |
| | HIGH | 22 | Vault-level write or KV Secrets Officer |
| | CRITICAL | **30** | Key Vault Administrator — full vault takeover |
| **Egress** | PASS | 0 | Private endpoint or NSG-restricted |
| | FAIL | **18** | Open to internet — exfil path is one HTTP call away |
| **Telemetry** | NONE | **5** | (soft penalty; "still learning" UX clarifies heuristic) |
| | PARTIAL | 2 | Some logs, not diagnostic-settings level |
| | FULL | 0 | Diagnostic settings on (v1.1+) |
| **Oversight** | PASS | 0 | Recent attestation or human-in-loop control |
| | FAIL | **10** | No attestation in >180d AND no governance exception |

### Worst case: all-FAIL agent

`100 - 15 (Ownership) - 30 (Secrets) - 18 (Egress) - 5 (Telemetry) - 10 (Oversight) = 22 / 100` ← **CRITICAL band**.

This anchors the "42/100" demo number from the AG-179 spec — a critical agent with one passing dimension.

### Best case: all-PASS agent

`100 / 100` ← **STRONG band**.

---

## Recommended band thresholds

| Band | Score range | Color | Meaning |
|---|---|---|---|
| **STRONG** | 90 – 100 | green | Production-ready posture |
| **GOOD** | 70 – 89 | blue | Acceptable; minor gaps |
| **ELEVATED** | 50 – 69 | amber | Investigate; not blocking |
| **CRITICAL** | < 50 | red | Stop-the-line for new privileged work |

These bands live in code (`AgentTrustScoreCard.tsx`) and are intentionally **not** in settings — see the comment in that file explaining why: UI consistency across drawer / table / scorecard / PDF demands a single source. Per-dimension *weights* are the only thing in settings.

---

## What founder is signing off on

- [ ] The 5 dimensions are the right grading axes
- [ ] The 14 penalty values above
- [ ] The 4 band thresholds (90/70/50)
- [ ] The worst-case "22/100" → CRITICAL is the demo number we're comfortable defending
- [ ] Once signed, these values get written to the `settings` table key `agent_trust_weights` and become the live config

## Process after sign-off

```bash
# Localhost
PGPASSWORD=changeme psql -h localhost -p 5432 -U auditgraph_admin -d auditgraph -c "
INSERT INTO settings (key, value, updated_at)
VALUES ('agent_trust_weights', $$
{
  \"ownership\": {\"PASS\": 0, \"FAIL\": 15},
  \"secrets\":   {\"NONE\": 0, \"LOW\": 5, \"MEDIUM\": 12, \"HIGH\": 22, \"CRITICAL\": 30},
  \"egress\":    {\"PASS\": 0, \"FAIL\": 18},
  \"telemetry\": {\"NONE\": 5, \"PARTIAL\": 2, \"FULL\": 0},
  \"oversight\": {\"PASS\": 0, \"FAIL\": 10}
}
$$::jsonb, NOW())
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW();
"

# Cloud dev — apply same INSERT via apply_cloud_migration.py with a settings.sql one-off
```

## Open questions for founder

1. **Telemetry NONE penalty (5)** — soft on purpose because customers without diagnostic settings will hover here. Acceptable, or punish harder?
2. **Oversight FAIL penalty (10)** — small because Service Account Governance attestation flow is new (Phase 63). Will increase as customers adopt the attestation cadence. Defer hardening or set now?
3. **Worst-case 22/100** — should we cap the floor at 30 (so even "all-FAIL" looks fixable) or let it go to 0 (theoretical max-bad agent shows as 0)? Currently theoretical max-bad = 0 in the math; demo case is 22 because the agent has *some* passing dimensions.

---

## Customer messaging when thresholds change

If we ever recalibrate post-launch, the FAQ entry must say:
> "AI Trust Scores were recalibrated on [date]. Your agents' absolute scores may have shifted by ±N points; relative ranking and band membership are preserved. We expose the calibration version in the API (`/api/ai-security/trust-score/<id>` → `calibration_version`) so audit trails are clear."

This is why founder sign-off **before** customer exposure matters — recalibration after public visibility is a trust hit.
