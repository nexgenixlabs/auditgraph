# Screen Walkthrough — PIM Overprivilege Detection

**Route**: `/identity-security/pim` · **Section**: Identity Security · **Audience**: CISOs, identity governance leads, GRC, IAM ops

## What this screen answers

> *"Which identities carry privileged PIM eligibility that they never (or rarely) actually use?"*

PIM Overprivilege Detection is the patent-track Azure feature that surfaces unused privileged-role eligibility. Standing PIM eligibility that's never exercised is a top-three audit finding in regulated industries — but Microsoft Entra PIM doesn't surface it natively. AuditGraph computes the eligible-vs-active delta and emits three named findings ranked by severity.

## What you see on screen

### Top — Headline card

One sentence framing the entire screen:

> *"4 PIM overprivilege findings across 5 eligible assignments — 2 critical · 2 high."*

The headline number is the total finding count. Color shifts from green (no findings) → amber (medium severity) → red (any critical) based on the worst finding present.

### Summary cards (4)

| Card | Counts |
|---|---|
| Eligible assignments | Total PIM-eligible role assignments in the tenant |
| Critical | Findings at severity `critical` |
| High | Findings at severity `high` |
| Medium | Findings at severity `medium` |

### Severity filter chips

`all · critical · high · medium · low` — click any to filter the table below.

### Findings table

Per-row drilldown — each row is one finding:

| Column | Source |
|---|---|
| Severity | Critical / high / medium / low — color-coded with dot |
| Finding | One of 3 types (see below) |
| Title | Human-readable headline ("Global Administrator eligible 420d, never activated") |
| Identity | Display name + identity_id |
| Open → | Click to open detail modal |

Sorted by severity descending, then by identity_id. Critical findings always appear first.

### Per-finding detail modal

When you click a row:

- **Severity tag** + finding type
- **Title** + identity context
- **Recommendation** — paragraph explaining what to do (e.g., "Remove the eligibility assignment. The identity has never exercised this role and has not requested it in 420 days.")
- **Evidence** — full JSON snapshot of the architectural signals that triggered the detection

### Full eligibility table (collapsed by default)

Expand to see every PIM-eligible (identity, role, scope) combination including those with no findings:

| Column | Use |
|---|---|
| Identity | Display name |
| Role | Directory role name |
| Eligible (d) | Days the identity has held this eligibility |
| Act 90d | Activation count in the last 90 days |
| Since last | Days since last activation |
| MFA | ✓ green = MFA required · ✗ red = activation policy bypasses MFA |
| Classification | `healthy_active` · `unused_eligibility` · `low_frequency_activation` · `weak_mfa` (or combined) |

The healthy rows here are the proof-point — they show the engine doesn't false-positive on legitimate active use.

## The 3 finding types

### 1. `pim_unused_eligibility`

> Identity has been eligible for a privileged role for ≥180 days but has never activated it.

**Severity:** `critical` for top privileged roles (Global Administrator, Privileged Role Administrator, etc.) eligible 365+ days · `high` for shorter dormancy or non-top roles · `medium` for non-privileged roles.

**Action:** remove the eligibility assignment. The identity isn't using it; standing assignment is overprivilege.

### 2. `pim_low_frequency_activation`

> Identity has been eligible AND activated, but rarely (less than 2 activations in the trailing 90 days).

**Severity:** `high` for privileged roles with 0 activations in 90d · `medium` otherwise.

**Action:** convert the standing eligibility to a time-bound assignment for known activity windows, or revoke if the need has passed.

### 3. `pim_weak_activation_control`

> Identity has PIM eligibility but the role's activation policy doesn't require MFA.

**Severity:** `critical` for top privileged roles · `high` otherwise.

**Action:** tighten the activation policy in Entra (require MFA on activation) — this is a Entra config change, not an identity revocation.

## How the engine works (read-only, agentless, architecture-derived)

The engine queries two purpose-built tables populated by the discovery pipeline:

| Source | What |
|---|---|
| `pim_eligibility_state` | Per-(identity, role, scope) eligibility records + activation policy (MFA required? Approval? Max duration?) |
| `pim_activation_observations` | Rolling timeseries of when activations actually occurred |

Both tables are populated from Microsoft Graph API calls using **read-only permissions only**:

- `RoleManagement.Read.Directory`
- `Policy.Read.All` (for activation policy fields)
- `AuditLog.Read.All` (optional, P2-licensed tenants only — enriches activation history)

No agent deployed in customer environment. No write permissions requested. The eligible-vs-active delta — the primary signal — is computable from architecture alone; activation history enriches when available but doesn't gate.

## P2 license behavior

| Available data | What works |
|---|---|
| Full Entra P2 (typical for any org with >50 employees) | All 3 finding types fire correctly |
| Eligibility data only (no audit logs) | `pim_unused_eligibility` + `pim_weak_activation_control` fire correctly. `pim_low_frequency_activation` shows "unknown frequency" rather than fabricating a value |
| No PIM at all (P1-only tenant) | Page shows "No PIM data — Entra P2 license required for PIM features" honestly |

This graceful degradation is the moat point: AuditGraph produces useful output even on tenants where competitors return empty.

## Common questions

**Q: How is this different from Entra PIM's built-in dashboard?**
Entra PIM shows eligibility AND shows activation history, but it doesn't compute the delta. It also doesn't surface "this eligibility was never exercised" as a discoverable finding — you have to know to look. AuditGraph emits the finding proactively.

**Q: What's the data freshness?**
Computed on every discovery snapshot (daily by default; configurable). When PIM Phase 2 Stream C ships, there will also be a 30-60 minute delta sync between snapshots for activation events.

**Q: How does this interact with the rest of the platform?**
PIM Overprivilege findings:
- Roll into the Oversight dimension of the 9-dim Identity Trust score
- Surface in the unified AI Findings catalog (as 3 distinct types)
- Trigger SOAR playbooks when severity = critical (if a matching playbook is configured)
- Drive the Peer Benchmarking "PIM hygiene" metric

**Q: Can a customer dispute a finding?**
Yes — each finding has a status workflow: `open` → `acknowledged` → `in_progress` → (`resolved` | `accepted_risk` | `false_positive`). Accept-risk requires an expiration date so the finding re-opens for re-evaluation.

## What to do next

1. **Sort by severity DESC** — focus on critical findings first
2. **For each critical**: click into the detail modal, read the recommendation, decide between (a) remove the eligibility, (b) tighten the activation policy in Entra, or (c) document accepted risk with business justification + expiration date
3. **For each high/medium**: triage during the next quarterly access review
4. **Schedule** PIM Overprivilege findings to be part of your quarterly recertification process — they're a natural input
5. **After remediation**: trigger a fresh discovery (next scan will re-evaluate)

## Related screens

- [Identity Trust](#screen-identity-trust) — Oversight dimension is driven by PIM hygiene
- [Entra Role Activity](#screen-entra-role-activity) — sibling feature for non-PIM directory role assignments
- [AI Findings](#screen-ai-findings) — PIM findings appear in the unified catalog
- [Multi-Hop XGRAPH](#screen-multi-hop-xgraph) — overprivileged PIM eligibility extends blast radius across agent chains
