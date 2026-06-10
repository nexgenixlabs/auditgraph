# AuditGraph Demo Data Inventory

**Tenant:** `AuditGraph Demo` (org_id = 9, localhost only)
**Seeder:** `backend/scripts/seed_feature_exerciser.py`
**Last run:** 2026-06-10
**Safety:** script refuses to operate on any org name that doesn't contain "demo"; INSERT + UPDATE only, never DELETE.

This doc lists every demo identity and which feature surface it exercises. When something looks broken in the UI ("page renders empty"), check whether the data here is present first.

---

## Field distributions applied to existing demo identities

The seeder runs UPDATE statements against the existing 283-identity demo population to give every field a realistic spread. Without this step the new feature pages render "no data in scope" because the original seeder left MFA, credential, and ownership fields NULL.

| Field family | Population | Distribution |
|---|---|---|
| `mfa_status` (humans + guests) | 163 | ~55% enabled · ~20% disabled · ~15% unknown · ~10% NULL (Entra P2 missing) |
| `activity_status='stale'` + `last_seen_auth` 120d ago | humans | ~15% (every id % 7) |
| `credential_status='expired'` + `credential_expiration` 30d ago | SPNs | ~8% (every id % 12 = 0) |
| `credential_risk='expiring_soon'` + `credential_expiration` 15d from now | SPNs | ~8% (every id % 12 = 1) |
| `has_federated_credentials=true` + `federated_issuer_types=[github_actions,terraform_cloud,azure_devops]` | SPNs | ~6% (every id % 17 = 0) |
| `owner_display_name` ∈ {Sarah Chen, David Kim, Jessica Lee} | NHIs | ~60% (id % 5 ≤ 2) |
| `blast_radius_score` | NHIs | bucketed 95 / 80 / 65 / 50 / 35 / 15 across id % 9 |
| `can_escalate=true` | NHIs | ~9% (every id % 11 = 0) |
| `pim_eligible_count` + `pim_active_count` | privileged humans | ~20% of risk≥70 humans (id % 5 = 0) |

After the seeder runs, the headline counters reflect real risk distributions: 36 humans with MFA disabled, 7 NHIs with expired secrets, 5 federated-only SPNs, 60 stale humans — every number that previously read 0 has a non-zero value.

---

## Hero demo identities (15)

These are explicitly-named identities that each exercise one feature surface. They use the `demo-*` prefix so they're unmistakable in the UI and the `AuditGraph Demo` owner so nobody mistakes them for real customer data. (See [[feedback_demo_naming]] for the rule.)

### NHI Secrets surface — credential time-bombs

| Identity | Risk | Feature exercised | What you see in UI |
|---|---|---|---|
| `demo-spn-expired-secret-01` | critical · 78 | NHI Secrets · Expired bucket | Appears in `/nhi/secrets` "Expired" card with expiration date 30 days ago |
| `demo-spn-expiring-3days-01` | high · 65 | NHI Secrets · Expiring < 30d | Appears in `/nhi/secrets` "Expiring < 30 days" card |
| `demo-spn-github-actions-fic-01` | high · 72 | NHI Secrets · Federated-only + CI/CD Attack Paths | Federated-only card + `/attack-paths?source_type=cicd` |
| `demo-spn-terraform-cloud-fic-01` | high · 70 | NHI Secrets · Federated-only + CI/CD Attack Paths | Same — second federation issuer for variety |

### NHI Governance surface — policy violations

| Identity | Risk | Feature exercised | What you see in UI |
|---|---|---|---|
| `demo-spn-orphan-critical-01` | critical · 85 | NHI Governance · Human owner policy | Counts as violator on "Every NHI must have an accountable human owner" (orphan + critical) |
| `demo-spn-sub-owner-violation-01` | critical · 88 | NHI Governance · Subscription Owner | Counts as violator on "NHIs must not hold Owner/Contributor/UAA at subscription scope" |
| `demo-spn-blast-radius-high-01` | high · 74 | NHI Governance · Blast radius cap | Counts as violator on "NHIs must not exceed high/critical blast radius" |

### Human Access surface — hygiene cards

| Identity | Risk | Feature exercised | What you see in UI |
|---|---|---|---|
| `demo-human-no-mfa-priv-01` | critical · 82 | Human Access · No MFA + Privileged | "Highly Privileged" + "MFA Disabled" cards both light up; this identity appears in the Top Privileged Humans table |
| `demo-human-stale-180d-01` | medium · 42 | Human Access · Stale > 90d | "Stale > 90 days" card; `last_seen_auth` is 180 days ago |
| `demo-human-unknown-mfa-01` | high · 68 | Human Access · Unknown MFA | "Unknown MFA" card; demonstrates the "Entra P2 not licensed" state |

### Human Governance surface — policy violations

| Identity | Risk | Feature exercised | What you see in UI |
|---|---|---|---|
| `demo-guest-permanent-01` | high · 58 | Human Governance · Guest lifecycle | Counts as violator on "Guest accounts must be time-bound" |
| `demo-human-standing-admin-01` | critical · 92 | Human Governance · No standing admin | Counts as violator on "No human should hold standing Owner/Contributor/UAA" — risk_score 92 + no PIM eligibility |

### AI Identity surface — were previously absent

The original demo org had **0 AI agents**. These three new identities populate the AI bucket so AI Inventory / AI Access / AI Trust / Unified Identity Graph have something to render.

| Identity | Risk | Feature exercised | What you see in UI |
|---|---|---|---|
| `demo-ai-agent-copilot-overpriv-01` | critical · 89 | AI Inventory + AI Access | Overprivileged AI agent in the AI Permissions findings panel |
| `demo-ai-agent-rag-indexer-01` | high · 74 | AI Inventory · RAG → Storage | Useful node when data reachability graph extends to Storage tier |
| `demo-ai-agent-claude-connector-01` | high · 76 | AI Inventory · Anthropic connector | Surfaces in Unified Identity Graph's "AI Agents" tier |

---

## Re-running the seeder

The script is **idempotent**. To refresh distributions or re-plant heroes after a base re-seed:

```bash
cd backend
python3 scripts/seed_feature_exerciser.py
```

Existing `demo-*` identities are detected by `identity_id` and UPDATED in place — no duplicates.

If you re-run `seed_demo_org.py` (which is destructive within the demo org), re-run this exerciser after.

---

## Adding new heroes

When a new feature surface is added that needs demo data:

1. Add an entry to the `HERO_IDENTITIES` list in `seed_feature_exerciser.py`.
2. Include `feature="..."` describing what surface it lights up.
3. Re-run the script.
4. Add a row to this doc.

Keep the `demo-*` prefix; keep the owner as `AuditGraph Demo` unless the feature being demonstrated specifically requires an orphan (in which case set `no_owner=True`).

---

## Related

- [[feedback_demo_naming]] — `demo-*` prefix + "AuditGraph Demo" owner rule
- [[feedback_no_org_data_deletion]] — never delete; UPDATE+INSERT only
- `seed_demo_org.py` — base 280-identity seeder (run this first)
- `seed_feature_exerciser.py` — this layer (run after base)
