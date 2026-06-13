# Potential Exposure Impact — Methodology

**The question every CISO asks**: *"How did you arrive at that dollar amount?"*

This page is the answer. AuditGraph's dollar number is a **benchmark estimate**, not an actuarial loss model. Every figure is re-derivable from a single table the user can audit in 30 seconds.

> What changed in 2026: AuditGraph moved from "records × per-record cost" to "classified resources × per-asset cost" and reorganised so that **dollars attach to data, not to entities**. AI workloads and identities don't add dollars to the headline; they inherit *attribution* from the data they can reach. See [Architectural change](#architectural-change-2026) below.

## What it is — and what it isn't

| What it is | What it isn't |
|---|---|
| A benchmark estimate using public breach-cost data | An actuarial loss model |
| A way to compare assets and prioritise remediation | A probability-weighted breach prediction |
| Re-derivable from the table on screen | Insurance-grade quantification |

The Potential Exposure Impact figure exists to drive a board conversation, not to back an insurance claim. AuditGraph never claims to forecast breach likelihood.

## The formula

```
total_potential_exposure
    = (count_PHI × per_asset_PHI)
    + (count_PCI × per_asset_PCI)
    + (count_PII × per_asset_PII)
```

That's the whole equation. There are no hidden multipliers. The "Total Exposure Formula" panel in the [Potential Exposure Impact drawer](#the-drawer) renders exactly these four lines summing to the headline.

### Why this beats the old per-record model

The 2025 model used `records × $/record`. It required AuditGraph to count rows inside a Cosmos collection or SQL table, which crossed the read-only line (we never inspect data plane). Per-asset cost keeps the moat intact: we count **resources** (storage accounts, key vaults, SQL DBs, generic ARM resources) carrying a data classification — every signal architecture-derived.

### Per-asset defaults (IBM Cost of a Data Breach 2024)

| Class | Default per-asset (USD) | Source |
|---|---:|---|
| **PHI** | **$720,000** | IBM CoDB 2024 — Healthcare median |
| **PCI** | **$1,200,000** | IBM CoDB 2024 — Financial median |
| **PII** | **$540,000** | IBM CoDB 2024 — global average |
| AI Models | **$0** *(reach-derived; see below)* | — |

Every tenant can override these in **Settings → Exposure Defaults**. Leaving a field blank reverts to the IBM default. Overrides are stored in the `settings` table under keys `exposure_phi_per_asset` / `exposure_pci_per_asset` / `exposure_pii_per_asset` / `exposure_ai_per_asset`.

## How a resource gets classified

A resource becomes PHI / PCI / PII through one of six tiers; the first that matches wins. Confidence band travels with the answer so a reviewer can see the provenance.

| # | Tier | Confidence | What it looks at |
|---|---|---:|---|
| 1 | **Manual override** | 100 | A per-resource override an admin typed |
| 2 | **Regex override** | 95 | A tenant regex pattern matching the resource name |
| 3a | **Data Trust Zone — resource-name pattern** | 100 | Glob on resource name (e.g. `*phi*`, `*claims*`, `*patient*`) |
| 3b | **Data Trust Zone — broad scope + name corroborates** | 100 | RG / subscription scope **and** the resource name carries a class keyword |
| 3c | **Data Trust Zone — broad scope only** | 60 *(Medium)* | RG / subscription scope; resource name is silent on the class |
| 4 | **Microsoft Purview** | 95 | Purview classification label (read via Graph API, never data) |
| 5 | **Azure tag** | 80 *(60 if key not in allow-list)* | Tag value like `classification=PHI` or `phi=true` |
| 6 | **Name pattern** | 45 *(Low)* | Built-in heuristic over the resource name |

A broad Data Trust Zone (e.g. *PHI = whole resource group `carehub-centus-prd-rg`*) used to rubber-stamp every resource at confidence 100. As of 2026-06-13 it only earns 100 confidence when the resource name corroborates the class; otherwise it lands at 60 (Medium). The UI labels these rows **"zone-asserted, name-unverified"** in amber so a SOC analyst sees the provenance honestly.

See [Data Trust Zones](screen-data-trust-zones) for the customer-facing screen and [Classified Resources](screen-classified-resources) for the row-level view.

## AI attribution (non-additive)

AI workloads are surfaced separately from the additive formula because **they don't add a dollar line — they inherit attribution from the classified data they can reach**.

For every AI agent identity (managed identity classified by `agent_classifications.agent_identity_type IN ('ai_agent','possible_ai_agent')`) we walk its `role_assignments`. We take the union (deduplicated) of classified resources reachable across all AI workloads and value it at the per-asset rates above.

```
attributable_AI_exposure
    = Σ classified_resource.exposure
      for resource in distinct_set(
        every classified resource any AI workload has RBAC reach to
      )
```

The drawer's **AI Workloads — Attribution (non-additive)** panel reports:

- **Discovered** — count of AI identities in the tenant
- **Reach Classified** — how many of them can reach any classified data
- **Attributable $$** — the dollar figure above

When *Reach Classified = 0* the drawer says explicitly *"AI workloads are correctly segregated — none have RBAC reach to classified data."* That's the architecture-derived answer, not a configuration gap.

For AI deployments tracked in `azure_ai_model_deployments` (e.g. Azure OpenAI), we attribute reach via a two-pass linkage to the parent account's managed identity. The recorded `reach_attribution_method` is one of:

| Method | When | Confidence |
|---|---|---|
| `mi_principal_id` | Discovery captured the parent account's identity.principalId | Highest |
| `name_match` | Account name matches a `managed_identity_system` display_name | High |
| `rbac_upper_bound` | Falls back to max reach across any identity with a role on the account | Soft upper bound — over-estimates when humans hold roles |
| `unresolved` | No linkage found | Reach left null; drawer flags it |

## The drawer

Click the **Potential Exposure Impact** card on the Executive Posture page. The drawer renders the full chain in one scroll:

1. **PHI / PCI / PII subtotal** — the headline matching the card.
2. **Total Exposure Formula** — the additive table summing to total.
3. **AI Workloads — Attribution (non-additive)** — the AI panel above.
4. **What This Is — And Isn't** — the two-column caveat.
5. **Active Data Trust Zones** — the rules in force.
6. **By Classification Source** — count of resources by tier.
7. **Confidence Bands** — High / Medium / Low resource counts.
8. **Exposure Chain** — reachable identities, attack paths terminating here, internet-reachable resources.

A CFO can re-derive the number from screen #2 in 30 seconds. That's the whole point.

## Architectural change (2026)

We moved off the per-record model after peer review highlighted three issues:

1. **It crossed the read-only line.** Counting Cosmos rows or SQL records required data-plane access that conflicts with AuditGraph's "we never read your data" guarantee.
2. **It double-counted AI.** A GPT deployment was independently valued at $1.4M *on top of* the PHI bucket it could reach. The same business value showed up twice in the headline.
3. **It couldn't survive a CFO question.** "Why is my dev GPT worth $1.4M?" had no answer when the model could reach nothing.

The per-asset / data-as-source model resolves all three. The headline is the union of classified data dollars; entities inherit attribution. The reach engine writes a single cached `reachable_classified_exposure` column per identity and per AI deployment, computed in the tier-2 post-discovery hook.

## Sources

- IBM Security · *Cost of a Data Breach Report 2024* — per-asset medians by industry. The default values shipped with AuditGraph.
- Ponemon Institute · *Healthcare Data Breach 2024* — used to validate PHI default.
- Verizon DBIR 2024 — cross-check on PCI median.

Update annually as new reports publish. Defaults are versioned in the codebase (`backend/app/api/handlers.py:get_dashboard_business_impact:DEFAULTS`).
