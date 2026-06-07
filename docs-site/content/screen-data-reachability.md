# Screen Walkthrough — Data Reachability

**Route**: `/ai-access/data-reachability` · **Section**: Attack Surface · **Audience**: CISOs, data governance, security architects

## What this screen answers

> *"What classified data — PHI, PCI, PII, financial — can my identities (and specifically AI agents) reach?"*

Data Reachability is the strongest single differentiator on the platform per peer review v3. Very few vendors map identities to data classifications with dollar exposure. This screen does. It answers the compliance question (HIPAA, PCI, SOC2, ISO27001 budgets all live here) and the AI safety question (what AI can touch).

## What you see on screen

### Top — 4 summary cards

| Card | Counts |
|---|---|
| Total reachable records | Sum across all classifications, MAX-deduplicated per class |
| Total identities with reach | NHIs that can read or write any classified data |
| **Est. exposure** | The dollar value (low / mid / high) |
| AI-reachable subset | The dollar value reachable specifically by AI agents |

The Est. exposure card carries the **ⓘ Methodology** button — one click to see the cost factor derivation.

### Per-classification cards

One card per data class (PHI / PCI / PII / FINANCIAL / HR / SOURCE / CONFIDENTIAL):

- Class label + color
- Records reachable across the tenant (MAX of all identities reaching that class)
- Identities with reach (count)
- Dollar band for this class
- Worst-5 identities (sorted by records reached)

### Per-identity drill (when you click into a class)

Per-row breakdown:

- Identity display name
- Identity category (Human / SPN / MI / AI agent badge)
- Records reachable
- Write resource count (writeable shadow risk)
- Resource count (total reachable resources)

Click any row to open the per-identity reachability detail (which specific resources).

## How records are estimated

The discovery pipeline scans cloud resources and estimates record counts via:

- **Database table row counts** (sampled via `COUNT(*)` or query-store statistics where SELECT is permitted)
- **Cosmos collection sizes** (from collection metadata)
- **Blob container object counts × estimated records-per-object** (for structured blob data)
- **Customer declarations** (override for cases where automated estimation isn't possible)

Estimates are bracketed (we know "approximately 120,000 PHI records" not "exactly 119,547"). The bracketing is intentional — overprecision creates false confidence.

## How classifications are assigned

Resources are classified by:

1. **Schema inspection** — column names like `ssn`, `dob`, `mrn`, `card_number`, `iban` → PII / PHI / PCI
2. **Resource tags** — `data-classification=PHI` is honored
3. **Container/namespace patterns** — `patient-records`, `customer-pii`, etc.
4. **Customer rules** — explicit YAML/JSON classification rules

Confidence is per-resource. Low-confidence classifications can be reviewed and confirmed via the Compliance Evidence screen.

## The dedup-by-MAX rationale

When five agents all reach the same 120,000 PHI records via different paths, the headline number is **120,000**, not **600,000**. The rationale:

- A single attacker who reaches that data once has reached all 120,000 records.
- Five paths to the same data ≠ five separate breaches.
- Summing would produce misleadingly inflated numbers boards would discount.

This MAX-deduplication is applied at the classification level. Same data class, multiple paths → take the max record count of any path.

## Common questions

**Q: Are these estimates audit-grade?**
The classifications and counts are surfaced with confidence indicators. The dollar bands carry source citations. For SOC 2 or HIPAA evidence, you can export the underlying data with full provenance.

**Q: What if my data isn't in Azure?**
The data reachability pipeline supports Azure, AWS, GCP, and customer-declared sources. Connect them via the Connectors page.

**Q: How fresh is this?**
Computed on every discovery snapshot. The freshness indicator on the page tells you when the underlying scan ran.

**Q: Why do I see only 4 of 7 classifications?**
Cards are hidden when zero records of that class are reachable in your tenant — keeps the page clean. To show all, toggle the *Show empty classes* filter.

## What to do next

1. Look at the largest dollar exposure class (typically PHI in healthcare, PCI in finance, PII elsewhere).
2. Click into the class to see the worst-N identities reaching that data.
3. For each, decide: scope reduction (revoke unnecessary access) vs documented acceptance (justify the access).
4. Re-discover and watch the exposure drop.

## Related screens

- [Multi-Hop XGRAPH](#screen-multi-hop-xgraph) — same data, presented as transitive chains
- [AI Abuse Scenarios](#screen-ai-abuse-scenarios) — what these reachabilities mean under attack
- [Breach Cost Methodology](#breach-cost-methodology) — where the $ comes from
