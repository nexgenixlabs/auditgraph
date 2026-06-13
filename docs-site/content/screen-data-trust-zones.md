# Screen Walkthrough — Data Trust Zones

**Route**: `/settings/data-trust-zones` · **Section**: Platform · **Audience**: CISOs, Data Governance, IAM admins

## What this screen answers

> *"How does AuditGraph know which resources hold PHI / PCI / PII — without reading the data?"*

You tell it. A **Data Trust Zone** is a CISO-asserted scope rule: *"Treat everything under this scope as the named class."* AuditGraph propagates that label across discovery and the dashboard, deterministically.

This is the customer-facing name. Internally the table is `data_trust_zones` (engineering may also see "classification scope rules" in code comments).

## Why this exists

70% of orgs don't systematically tag classification on Azure resources. Without tags, AuditGraph used to show *Data Sources = 0* — a fatal credibility gap on the dashboard. Reading data content to fix it would have broken the "we never read your data" guarantee.

Data Trust Zones bridge that gap **without crossing the read-only line**. You assert classification at the scope level (subscription / resource group / glob pattern); AuditGraph propagates down the ARM tree at discovery time. No data plane access. Every assertion is auditable and revocable.

## The 6-tier classification engine

A resource picks up a class through the first matching tier (highest wins):

| # | Tier | Confidence |
|---|---|---:|
| 1 | Manual override (admin click) | 100 |
| 2 | Regex override (tenant settings) | 95 |
| 3 | **Data Trust Zone** | 60-100 *(see below)* |
| 4 | Microsoft Purview label | 95 |
| 5 | Azure tag (`classification`, `sensitivity`, `phi`, …) | 80 |
| 6 | Built-in name pattern heuristic | 45 |

Within tier 3, narrow patterns beat broad scopes:

| Scope type | Confidence | Note |
|---|---:|---|
| `resource_name_pattern` (e.g. `*phi*`, `*claims*`) | **100** | Per-resource glob — most precise |
| `subscription` literal | 100 if name corroborates, 60 if silent | Broad scope; name must back it up for High |
| `resource_group` literal | 100 if name corroborates, 60 if silent | Same |
| `subscription_pattern` glob | 100 if name corroborates, 60 if silent | Same |
| `resource_group_pattern` glob | 100 if name corroborates, 60 if silent | Same |

**Why broad zones drop to 60 (Medium):** an RG named `carehub-centus-prd-rg` likely holds PHI **but not every resource inside is PHI** — a monitoring storage account or a CI/CD key vault sitting in the same RG probably isn't. The new rule: a broad zone earns full confidence only when the resource name also carries a class keyword (e.g. `claims`, `patient`, `phi`). Otherwise the row is marked *"zone-asserted, name-unverified"* in amber on the Classified Resources page.

## What you see on screen

### Class palette

Seven coloured chips: PHI / PCI / PII / SOURCE / HR / FINANCIAL / CONFIDENTIAL. Pick one when creating a zone.

### Active zones table

For each zone:

- **Scope** — value + scope type chip
- **Asserted by / asserted at** — who and when (audit trail)
- **Coverage** — count of resources currently classified by this zone, with a per-table breakdown
- **Revoke** — soft delete (sets `revoked_at`; never hard-deleted)

### Add a zone (recommended scope types first)

The scope-type dropdown leads with **Resource Name (glob) — recommended** because it's the most precise:

- `PHI = *claims*` → every resource named with "claims" anywhere is PHI at confidence 100
- `PHI = *patient*` or `PII = *member*` → same pattern
- `PHI = process-*-outbound` → tighter pattern

Broad scopes are below and labelled accordingly so it's clear they trade precision for coverage.

### Argus suggestion card (Sprint 2)

Argus proposes zones based on RG name keyword matches in the current discovery. *"Suggested: PHI = `carehub-*-prd-rg` — 286 resources would gain a label."* One click to accept; the zone is created and a recompute fires.

### Audit Log tab

Every create / edit / revoke event with the actor + timestamp. Soft-delete means the history is preserved indefinitely.

### Microsoft Purview banner (Sprint 3)

When the `FEATURE_PURVIEW_INTEGRATION` flag is on, a banner shows the Purview cache hit rate and feature status. Purview labels arrive as tier 4 and **never include the underlying data** — only the label metadata flows through the Graph API.

## When to use which zone type

| You want… | Use |
|---|---|
| To label a single specific bucket | Manual override on that resource |
| To label every resource whose name carries a known keyword | `resource_name_pattern` zone (e.g. `PHI = *claims*`) |
| To label everything in a CI/CD-managed PHI environment | `resource_group` literal **plus** a narrow `resource_name_pattern` zone for the items that don't carry the keyword |
| To label an entire production subscription as PCI | `subscription` literal (resources whose name doesn't include `card`/`pan`/etc land at Medium) |

A common pairing: use a broad `resource_group` zone as a *catch-all default* and overlay specific `resource_name_pattern` zones for the items you want at High confidence.

## How it propagates

At discovery time the scheduler runs the post-step `_run_data_trust_zones_classification` which calls `apply_scope_classification`. The engine walks every classifiable resource in the current run and applies the highest-precedence tier. It never overwrites manual / regex_override / Purview classifications.

After classification, the next step (`_run_reach_attribution`) computes per-identity and per-AI-model reach against the freshly classified resources. So labels and reach are always in sync after a scan.

## Standing rules

- **Read-only.** Zones describe scope; AuditGraph never reads data content to confirm them.
- **Soft-delete.** Revoking sets `revoked_at`; the row stays for audit.
- **Customer-facing copy says "Data Trust Zones."** Engineering terms (`classification_scope_rules`) never appear in the UI.
- **Architecture-derived only.** A zone is metadata about *where* the data sits, not *what* the data says.

## Related screens

- [Classified Resources](screen-classified-resources)
- [Potential Exposure Impact Methodology](breach-cost-methodology)
- [Executive Posture](screen-executive-posture)
