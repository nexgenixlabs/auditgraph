# Screen Walkthrough — Identity Trust

**Route**: `/identity-trust` · **Section**: Identity Security · **Audience**: CISOs, security architects, GRC teams

## What this screen answers

> *"Across every non-human identity in my tenant, how many are below an acceptable trust threshold — and what dimensions are failing?"*

Identity Trust is the org-wide rollup of the 9-dimensional Trust Score across all NHIs (service principals, managed identities, AI agents). It produces a single board-ready headline number, surfaces the top failing dimensions, and lists the 25 worst identities so you know exactly which to fix first.

## What you see on screen

### Top — Headline card

Single sentence framing the entire screen:

> *"27 of 133 non-human identities have Trust below 50 (20%) — review the worst to remediate first."*

This sentence is generated dynamically. The headline number is `below_threshold_count` and the threshold defaults to 50. You can change the threshold via the chip selector below.

### Threshold chips

Four buttons: **≤40 · ≤50 · ≤65 · ≤80**. Click any to recompute the headline at that threshold. Useful for understanding the distribution — e.g., is your tail at 30 (catastrophic) or at 65 (workable)?

### Band distribution — 4 cards

Each card is one trust band with its count and percentage:

| Band | Range | Color | Interpretation |
|---|---|---|---|
| Strong | 80-100 | Emerald | Solid posture. Documented owner, full telemetry, least privilege. |
| Good | 65-79 | Blue | One or two dimensions partial. Acceptable. |
| Elevated | 40-64 | Amber | Multiple failing dimensions. Triage this quarter. |
| Critical | 0-39 | Red | Imminent risk. Triage now. |

The percentages on these cards sum to 100% of NHIs evaluated.

### Top failing dimensions bar chart

A list of the 9 trust dimensions sorted by *how many identities are failing this dimension*. Reading this:

- A dimension at the top with a high count means *every NHI is failing it* — that's a systemic problem (e.g., no telemetry on any agent → you haven't enabled diagnostic settings).
- A dimension lower in the list means failure is sporadic — that's a per-identity problem.

The top 3 systemic failures typically are:

1. **Telemetry** — diagnostic settings not configured. Every agent shows 0 audit signal. Fix at the cloud-config layer.
2. **Data Access** — agents reach classified data they don't need. Fix per-identity with role scope reduction.
3. **Ownership** — no human owner assigned. Fix in the [Ownership Center](#screen-ownership-center).

### Worst 25 identities table

Per-row drill-down for triage:

| Column | Source | Use |
|---|---|---|
| Identity | display name + identity_id | Who |
| Trust | 0-100 score with band color | How bad |
| Failing dimensions | chips | What needs fixing |
| Inspect → | link to the agent's drawer | Drill in |

Sorted by trust ASC (worst first), tied by failing-dimension count DESC.

## The 9 Trust dimensions

The score is computed from these 9 graded dimensions. Each can be PASS, FAIL, NONE, PARTIAL, or one of the {LOW, MEDIUM, HIGH, CRITICAL} severity grades depending on the dimension. The aggregate Trust Score is `100 − Σ dimension_penalty` with penalty weights configurable in the `settings` table.

| # | Dimension | What it grades | Failing means |
|---|---|---|---|
| 1 | **Ownership** | Is a human owner assigned? | No owner = FAIL |
| 2 | **Secrets** | Key Vault privilege tier | Admin scope = CRITICAL |
| 3 | **Egress** | Outbound network posture | Public internet reach = FAIL |
| 4 | **Telemetry** | Diagnostic / sign-in evidence | No logs = NONE |
| 5 | **Oversight** | Governance exception, owner-attested, etc. | No oversight = FAIL |
| 6 | **Data Access** | Classified-data reachability | Reaches PHI/PCI = HIGH or CRITICAL |
| 7 | **Network** | Public network exposure on linked AI resources | Public endpoint = FAIL |
| 8 | **Model Exposure** | Number of distinct model deployments | Multi-model = MULTI |
| 9 | **Supply Chain** | Model provenance and approval | Unverified vendor = FAIL |

For non-AI NHIs (regular SPNs, MIs), dimensions 8 and 9 will return NONE — those are AI-specific. They don't count against the score for non-AI agents.

## How is this score calibrated?

Each dimension has a maximum penalty pulled from the `settings` table. Defaults (sum to 100):

- Ownership: 25 max
- Secrets: 30 max (critical at full penalty)
- Egress: 10 max
- Telemetry: 15 max
- Oversight: 5 max
- Data Access: 20 max
- Network: 10 max
- Model Exposure: 15 max
- Supply Chain: 15 max

Operators can adjust these weights to reflect their organization's risk appetite — e.g., a highly regulated tenant may bump Data Access to 30 max.

## Common questions

**Q: Why is this called Trust, not Risk?**
Two reasons. First, *Trust* is the executive-friendly framing — boards understand "Trust below 50" intuitively. *Risk score 7.4* requires explanation. Second, Trust is *higher is better* — it inverts naturally for charts and rollups.

**Q: Does this apply to humans?**
Not yet. The current Trust engine is calibrated for non-human identities. A 5-dimension human Trust Score (MFA, password age, last login, role drift, PIM hygiene) is on the roadmap. For now, humans show "Identity Trust not available for human users yet" if you query their endpoint.

**Q: How fresh is the data?**
Computed on every discovery snapshot (typically daily). The badge in the corner of each identity drawer shows snapshot age.

**Q: Can I configure the threshold globally?**
Yes — the default of 50 is a tenant setting (`identity_trust_threshold`). Updating it changes the headline calculation on this page and the alerting threshold for any scheduled report.

## What to do next

1. Read the headline — that's your board-ready statement.
2. Look at the top failing dimension. If telemetry is #1, your fix is one configuration change at the diagnostic-settings layer, not 100 per-agent fixes.
3. Click the worst-25 entries one by one. For each: assign owner, scope reduction if overprivileged, document acceptance if intentional.
4. Re-check next week and watch the *strong* band grow.

## Related screens

- [Ownership Center](#screen-ownership-center) — close the ownership dimension
- [AI Inventory](#screen-ai-inventory) — drill into individual agents
- [Multi-Hop XGRAPH](#screen-multi-hop-xgraph) — see how a low Trust agent's reach extends through other agents
