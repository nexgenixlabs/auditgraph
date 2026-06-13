# Screen Walkthrough — Classified Resources

**Route**: `/data-classification` · **Section**: Graph Intelligence · Data Sources · **Audience**: SOC analysts, IAM admins, auditors

## What this screen answers

> *"Show me every resource that carries a data classification, why it got that label, and how confident we are."*

This is the row-level view behind the dashboard's *Data Sources* tier and *Potential Exposure Impact* headline. Every PHI / PCI / PII bucket the org has on Azure surfaces here with the rule and confidence that landed the label.

## What you see on screen

### Filter chips

Across the top: `All · N` followed by per-class chips (`PHI · 286 · PII · 40 · …`). Clicking a chip restricts the table to that class. The active chip mirrors the URL query (`?classification=PHI`) so the page is shareable.

### Resource table

| Column | What it shows |
|---|---|
| **Resource** | Friendly name with the full ARM resource_id on hover |
| **Kind** | Resource kind chip (Storage / Key Vault / SQL / Cosmos / Resource) |
| **Class** | Coloured chip — PHI red, PCI orange, PII amber, etc. |
| **Source** | Friendly tier name — Data Trust Zone / Azure Tag / Name Pattern / Manual / Purview |
| **Confidence** | Numeric (0-100) + band chip — High (≥85) / Medium (≥60) / Low |
| **Resource Group** | RG name, monospaced |

When a row's source is `Data Trust Zone` with confidence < 85 a small amber caption appears: **"zone-asserted, name unverified."** That's the honest signal that the zone matched the resource at a broad scope (RG / sub) but the resource name doesn't corroborate the class. A SOC analyst can decide whether to:

- Tighten the zone to a `resource_name_pattern` so the matching rows get High confidence, or
- Accept the broad zone and live with the Medium signal.

### Empty state

When no resources match the current filter: a panel pointing the user to **Settings → Data Trust Zones** with an *"Add a Zone →"* CTA. The classification engine returns no results until either a tag, a zone, or a name pattern fires.

## How a resource lands on this page

Every row carries provenance you can audit:

1. Discovery enumerates every classifiable Azure resource and writes it to one of the canonical tables (`azure_storage_accounts`, `azure_key_vaults`, `azure_sql_databases`, `azure_cosmos_databases`, generic `discovered_resources`).
2. The post-discovery scheduler step `_run_data_trust_zones_classification` applies the [6-tier classification engine](breach-cost-methodology#how-a-resource-gets-classified).
3. Each row gets four provenance columns: `data_classification`, `classification_source`, `classification_confidence`, `classification_rule_id`.
4. The next step `_run_reach_attribution` walks RBAC and stores `reachable_classified_exposure` per identity + per AI deployment.

This page reads the union of those tables filtered to `data_classification IS NOT NULL`.

## Why we never read your data

A resource's class comes from one of:

- A CISO assertion (Data Trust Zone)
- A regex / manual override
- An Azure tag (control-plane metadata)
- A Microsoft Purview label (metadata via Graph API, never data content)
- A name pattern (heuristic over the resource name)

No path involves opening a blob, querying a row, or reading a secret. The "Source" column tells you exactly which signal fired.

## When to drill in

| Pattern | What it means | Where to go next |
|---|---|---|
| All PHI rows show `Source = Data Trust Zone` at confidence 100 | A `resource_name_pattern` zone matched the names directly. Strongest provenance. | Audit the zone in [Settings → Data Trust Zones](screen-data-trust-zones) |
| Many rows show `Data Trust Zone` at confidence 60 with "zone-asserted, name unverified" | A broad RG / sub zone is doing the work; resource names don't corroborate | Consider adding a narrow `resource_name_pattern` zone alongside the broad one |
| Source = `Azure Tag` | Your team has wired classification tags via Azure Policy — strongest hands-off path | Keep going. Tag confidence is 80 (High) |
| Source = `Name Pattern` | Confidence 45 (Low). Heuristic only — there's no zone or tag, just a built-in regex caught the name | Add a Data Trust Zone or a tag to promote this row's confidence |
| Source = `Purview` | Microsoft Purview classified this resource. We pulled the label via Graph API | The label is owned by Purview; manage it there |

## Common questions

**Q: Why does my dev storage account show PHI?**
Look at the **Source** column. If it's *Data Trust Zone* with the *carehub-centus-prd-rg* RG name, the broad RG zone is propagating. If the resource name doesn't actually carry PHI keywords, expect the confidence band to be Medium. Tighten the zone to a `resource_name_pattern` to fix it, or move the dev resource to a different RG.

**Q: My PCI storage account isn't here.**
No classification signal fired for it. Add a tag (`classification=PCI`), a manual override, a regex, or a Data Trust Zone. Verify in [Settings → Data Trust Zones](screen-data-trust-zones).

**Q: Can I export this list?**
Not from this page yet. The closest path today is filtering by class + copying the URL — the auditor can replay the exact list. Export-as-CSV is on the roadmap.

## What to do next

1. Sort by confidence. Anything in the High band (≥ 85) is strongly asserted; Medium / Low rows are improvement candidates.
2. Click through to a representative row's drawer to confirm the source.
3. If too many rows are Medium because of a broad RG zone, add narrow name-pattern zones in [Settings → Data Trust Zones](screen-data-trust-zones).
4. Re-trigger discovery (or wait for the scheduled scan) to recompute.

## Related screens

- [Data Trust Zones](screen-data-trust-zones) — where the rules are managed
- [Potential Exposure Impact Methodology](breach-cost-methodology) — how classification turns into a dollar figure
- [Executive Posture](screen-executive-posture) — where the headline lands
