# Screen Walkthrough — AI Findings

**Route**: `/ai-findings` · **Section**: AI Security · **Audience**: Security analysts, IR teams, compliance

## What this screen answers

> *"What specific AI security issues need triage in my tenant right now?"*

AI Findings is the unified detector surface for AI-specific security issues. Where Identity Trust shows aggregate scoring, this screen shows individual *findings* — each one a specific, actionable issue with a clear remediation path. Think of it as the issue tracker for AI security posture.

## What you see on screen

### Top — summary strip (4 cards)

| Card | Counts |
|---|---|
| Total | All open findings |
| Critical | Severity = critical |
| High | Severity = high |
| Net New (24h) | Findings created in last 24h |

### Filter chips

- Severity: all · critical · high · medium · low
- Status: open · acknowledged · in_progress · accepted_risk · resolved · false_positive
- Type: all 12 finding types (e.g., `ai_excessive_privilege`, `ai_no_owner`, `ai_unapproved_model_in_use`)

### Body — findings table

Each row is one finding:

| Column | Source |
|---|---|
| Severity | enum dot + label |
| Type | finding_type (e.g., `ai_excessive_privilege`) |
| Title | human-readable headline (e.g., "demo-ai-copilot-prod has Owner scope at subscription") |
| Affected identity | display_name of the agent/identity |
| First seen | timestamp |
| Status | enum |
| Inspect → | click to open detail |

Sorted by severity DESC, then by first_seen ASC (oldest critical at top).

### Detail modal

Per-finding drilldown:

- **Description** — what the issue is
- **Evidence** — the architecture signals that triggered the detection (e.g., "Role Owner assigned at /subscriptions/sub-prod-001 on 2026-03-12")
- **Affected resource** — the cloud resource involved (when applicable)
- **Remediation** — recommended fix
- **Status workflow buttons** — Acknowledge / In Progress / Accept Risk / Resolve / Mark False Positive

Status changes are logged with user + timestamp + reason for the audit trail.

## The 12 finding types

| Type | Severity | What triggers it |
|---|---|---|
| `ai_no_owner` | medium | AI agent has no assigned human owner |
| `ai_excessive_privilege` | critical/high | Owner or Contributor at subscription/management group scope |
| `ai_credential_exposure` | high | Multiple secrets / certificates / federated credentials |
| `ai_credential_expiry` | medium | Credential expires within 30 days |
| `ai_no_telemetry` | medium | No diagnostic settings, no sign-in audit signal |
| `ai_reaches_phi_write` | critical | Agent can write to a PHI-classified store |
| `ai_reaches_pci_write` | critical | Agent can write to a PCI-classified store |
| `ai_public_endpoint` | high | Linked AI resource (Cognitive Services account, vector DB) has public network access enabled |
| `ai_unapproved_model_in_use` | high | Deployment uses a model not in Approved status in the Model Registry |
| `ai_finetune_unverified` | high | Fine-tuned model without training-data provenance documented |
| `ai_supply_chain_critical_flag` | critical | Supply chain component has cve or unbounded_scope or multiple high-impact flags |
| `ai_dormant_agent` | low | Agent has no sign-in / activity in 90+ days |

Each type is implemented as a pure detector function (`backend/app/engines/ai/findings.py`). Each detector accepts the same input batch (agents, role_assignments, classifications, reachability, governance state) and emits 0+ findings per agent.

## How findings are composed

A scheduled job (or manual `POST /findings/recompose`) runs all 12 detectors against the current snapshot. Each detector emits zero or more findings. Each finding has a stable `fingerprint` (hash of finding_type + affected_identity_id + evidence_summary) that survives multiple recompose cycles — if the same issue is re-detected, it's UPSERTed (no duplicate row).

This means:

- Manual status changes (acknowledged, in_progress, etc.) are preserved across recomposes.
- Resolved-then-re-emerged findings are tracked through their lifecycle.
- The First Seen timestamp is the original detection date.

## Status workflow

```
                ┌─────────────┐
                │    open     │  <- newly detected
                └─────┬───────┘
                      │
        ┌─────────────┼─────────────┬─────────────┐
        │             │             │             │
        ▼             ▼             ▼             ▼
 ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐
 │acknowledged│ │in_progress│ │ accepted │  │false_positive│
 └────┬─────┘  └─────┬────┘  └────┬─────┘  └─────────────┘
      │              │            │
      └──────────────┴─────────────┘
                     │
                     ▼
              ┌──────────┐
              │ resolved │
              └──────────┘
```

Each transition requires a comment (for audit). `accepted_risk` requires an expiration date — after which the finding re-opens for re-evaluation.

## The triage workflow

Recommended cadence:

1. **Daily** (15 min) — open the page, sort by severity DESC, look at any new critical findings from the last 24h. Acknowledge each one (someone is tracking it).
2. **Weekly** (1 hour) — look at the open + acknowledged backlog. Assign to engineers. Move each to in_progress with an estimate.
3. **Monthly** — review accepted_risk findings nearing expiration. Decide: extend acceptance with new business justification, or remediate.
4. **Quarterly** — review the entire backlog with the AI governance committee. Adjust severity thresholds and add new finding types as new threat patterns emerge.

## Common questions

**Q: How is this different from the general Findings screen in Command Center?**
The Command Center Findings is the org-wide security findings catalog (covers everything: identity, configuration, network, etc.). This screen is the *AI-specific* subset, with detectors tuned for AI agent issues. There's overlap by design — an AI agent with overprivileged scope shows up in both — but the AI Findings catalog has the AI-specific evidence and remediation language.

**Q: Can I add a custom finding type?**
Yes — write a detector function that takes the standard input batch and returns a list of findings. Add it to the detector registry. The UI auto-renders new types.

**Q: How do findings interact with SOAR / playbooks?**
The SOAR engine subscribes to finding events. When a finding is created with severity ≥ high, matching playbooks (e.g., `playbook_revoke_owner_role_at_subscription`) trigger automatically. Playbooks can: (a) propose a remediation action, (b) execute the action after approval, (c) auto-resolve the finding when the underlying signal clears.

## What to do next

1. Filter to critical + open. That's the top of the backlog.
2. For each one, click Inspect, read evidence + remediation.
3. Decide: Acknowledge (track but don't act yet), In Progress (assigning to someone), Accept Risk (with justification + expiration), Resolve (after fix).
4. Re-run recompose after any architectural change to surface new findings (or auto-resolve fixed ones).

## Related screens

- [Identity Trust](#screen-identity-trust) — same evidence, aggregated as scores
- [AI Inventory](#screen-ai-inventory) — per-agent context for findings
- Compliance Evidence (Governance & Assurance) — findings auto-flow to compliance evidence packages
