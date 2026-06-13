# Screen Walkthrough — Executive Posture

**Route**: `/` · **Section**: Command Center · **Audience**: CISOs, CIOs, board members

## What this screen answers

> *"What is my identity security posture right now, in business-impact terms a board would understand?"*

This is the landing page. The audience is executive, not architect. Every number is paired with a sentence explaining what it means in business terms — and a one-click drill-down so the analyst can audit it.

## Hero row — four cards across the top

| Card | What it shows |
|---|---|
| **Identity Security Score** | 0-100 posture score with verdict (Secure / Elevated / Critical) and a "Why?" drawer. |
| **Potential Exposure Impact** | The dollar headline — derived from classified data the org has on its tenant. Click to open the [methodology drawer](breach-cost-methodology). |
| **Attack Paths** | Total multi-hop paths identified with critical/high/medium split. |
| **Compliance Posture** | Overall posture % across the wired frameworks. |

### Potential Exposure Impact — the card every CISO clicks first

This card was renamed from "Estimated Exposure" in 2026. The new name is honest about what we compute: a benchmark estimate, not an actuarial loss model.

Under the dollar value the card carries a **decorator row** answering "who can reach this?":

```
👤 682 reachable identities · ⚔ 115 attack paths · 🕳 951 orphan NHIs · 🤖 N AI models can reach data
Top: SVC_Forensit can reach $113.8M (143 PHI)
↓ $56.9M reduction opportunity
```

The decorators are the moat. Asset count anyone can compute; **who can reach what** is what AuditGraph's identity graph adds.

Click the dollar value to open the drawer. The drawer renders:

1. **PHI / PCI / PII subtotal**
2. **Total Exposure Formula** — `count × per_asset = subtotal` for each class summing to the total. A CFO re-derives the headline from this table in 30 seconds.
3. **AI Workloads — Attribution (non-additive)** — `Discovered N · Reach Classified M · Attributable $X`. AI is attribution, not contribution. When *Reach Classified = 0* a green callout says *"AI workloads are correctly segregated — none have RBAC reach to classified data."*
4. **What This Is — And Isn't** — two-column honest-claim block.
5. **Active Data Trust Zones** — the rules in force on this tenant.
6. **By Classification Source** — tier breakdown (zone / tag / name pattern / Purview).
7. **Confidence Bands** — High / Medium / Low resource counts.
8. **Exposure Chain** — reachable identities, attack paths terminating here, internet-reachable resources.

See [Potential Exposure Impact methodology](breach-cost-methodology) for the full formula.

## Top Improvement Opportunities

Three actionable rows ranked by points gained. Each row maps to one of the 6 score factors with the lift visible:

- `+20 pts` Close critical multi-hop attack paths
- `+10 pts` Enable telemetry / activity monitoring on AI agents
- `+1.5 pts` Assign accountable owners to unowned non-human identities

The headroom box on the right shows the projected score if all three were closed.

## Unified Identity Graph (Row 2)

Five tier circles — **Human → Non-Human → AI Agents → Models → Data Sources** — with dots animating to convey flow. Clicks open the tier-specific inventory:

- **Human** → All Identities (humans filter)
- **Non-Human** → Non-Human Identity Inventory
- **AI Agents** → AI Identities
- **Models** → AI Model Registry
- **Data Sources** → [Classified Resources](screen-classified-resources)

The three small badges below the row — *Active Attack Paths*, *Orphaned Identities*, *Critical Data Assets* — surface the cross-cutting signals.

## Tier Risk Cards (Row 3)

Human / Non-Human / AI side-by-side, each with its own risk gauge and 3 sub-counts. Quick scan of where the heat is concentrated.

## Top Reach panels (Row 3.5) — NEW

Two side-by-side panels added in Sprint B (2026-06-13):

- **Top Reach by Identity** — top 5 identities by `reachable_classified_exposure`. Click any row to open the identity drawer.
- **Top Reach by AI Model** — top 5 AI deployments by reach. Each row carries a provenance chip showing the linkage method (`name-matched MI` / `RBAC upper bound` / `unresolved`).

On a healthy tenant, the AI panel shows an empty state: *"No AI deployments with resolvable reach."* That's the architecture-derived answer that AI is properly segregated.

When this panel surfaces the same dollar number against 5+ identities, that's the audit finding: an over-privileged role (typically subscription-level Reader / Contributor) is concentrating exposure. Revoke it from 4 of 5 and the top reach drops sharply.

## Workshop row (Row 4)

Three columns:

| Top Attack Paths | Immediate Risks | Top Remediation Actions |
|---|---|---|
| Top 5 paths by severity | Counts by severity grouped by finding type | Top 3 remediation playbooks ranked by affected count |

## What Changed (sidebar)

Last 24h: recomputed-tables events, discovery scans, schedule completions. Live-updating.

## How this differs from Risk Monitoring

Executive Posture is *what posture is* (high-level, board-ready, business-impact framing).

Risk Monitoring is *what happened* (operational, SOC/IAM-ops audience, change-event framing).

Same data, different summarisation and audience.

## Common questions

**Q: The headline went down. Why?**
The math changed. In Sprint B (2026-06-13) we removed the flat per-AI-deployment multiplier because it double-counted: a GPT's value was being added on top of the PHI bucket it could reach. The headline now reflects only PHI / PCI / PII data. AI inherits attribution; it doesn't add dollars.

**Q: Same identity shows up 5 times at $113.8M in Top Reach. Why?**
That's the over-privileged-role pattern: a subscription-level Reader / Contributor gives 5+ principals the same access. The reach is real; the finding is *one role assignment* (not five). Removing it from 4 of them collapses the duplication.

**Q: Why can a junior contractor reach $113.8M of PHI?**
Because their group inherits a sub-level role that spans the PHI resource group. The drawer's *Exposure Chain* section shows the path; the [Role Optimization](#screen-role-optimisation) screen recommends a tighter scope.

**Q: My AI deployments show "unresolved" attribution method. Fix?**
Discovery hasn't captured the parent Azure OpenAI account's managed-identity principal_id. As a fallback we use name-match (account_name = MI display_name) and, failing that, an RBAC upper bound (max reach of any identity with a role on the account). Adding the account's MI principal_id at discovery — tracked for the next iteration — promotes the linkage to `mi_principal_id`.

## What to do next

1. Read the verdict and the top-3 improvement bar.
2. Click the **Potential Exposure Impact** card to audit how the headline is derived.
3. Scan **Top Reach by Identity** for over-priv concentrations.
4. Open **Settings → Data Trust Zones** to tighten broad RG zones into narrow name-pattern zones.

## Related screens

- [Potential Exposure Impact Methodology](breach-cost-methodology)
- [Data Trust Zones](screen-data-trust-zones)
- [Classified Resources](screen-classified-resources)
