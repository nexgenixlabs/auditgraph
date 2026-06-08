# Breach Cost Methodology

**The question every CISO asks**: *"How did you arrive at that dollar amount?"*

This page is the answer. Every dollar figure AuditGraph displays — on the Executive Posture, in AI Abuse Scenarios, on Multi-Hop XGRAPH chains, anywhere — is computed deterministically from the same publicly cited industry cost factors. No model, no fabrication, no opaque heuristic.

## The formula

```
exposure_low  = records × factor.low_usd
exposure_mid  = records × factor.mid_usd      ← shown as the headline
exposure_high = records × factor.high_usd
```

Two inputs:

1. **records** — the count of classified records each identity can reach via RBAC + Entra directory roles. Computed from cloud resource inspection (Cosmos collections, SQL tables, Blob containers, Key Vault secrets, etc.) cross-joined with the identity's effective permissions.

2. **factor** — industry cost-per-record from the citations below. Stored as a row in the `breach_cost_factors` database table. Each row carries its source, source year, and effective date.

Multiply them and you get a low/mid/high band expressing realistic uncertainty.

## Cost factor table

| Class | Low (USD/rec) | **Mid (USD/rec)** | High (USD/rec) | Source |
|---|---:|---:|---:|---|
| **PHI** | $408 | **$471** | $535 | IBM Cost of a Data Breach 2023 — Healthcare · Ponemon Healthcare 2023 |
| **PCI** | $180 | **$303** | $429 | IBM Cost of a Data Breach 2023 — Financial Services · Verizon DBIR 2023 |
| **PII** | $148 | **$165** | $183 | IBM Cost of a Data Breach 2023 — global average |
| **FINANCIAL** | $180 | **$303** | $429 | IBM CoDB 2023 Financial Services |
| **HR** | $148 | **$165** | $183 | IBM CoDB 2023 — PII baseline |
| **SOURCE** | $120 | **$200** | $350 | Verizon DBIR 2023 IP-theft incidents (estimated) |
| **CONFIDENTIAL** | $80 | **$150** | $250 | IBM CoDB 2023 corporate-data average |

Mid is the headline figure shown on dashboards. Low and high define the credible range.

Factors are versioned by year (`source_year`) and refreshed annually as new editions of the source reports are published. Regional adjustments (US / EU / APAC) are supported by adding region-specific rows.

## Worked example

The single most-shown example in the demo:

> `demo-ai-copilot-prod` can write to a Cosmos collection containing **120,000 PHI records**.

```
exposure_low  = 120,000 × $408 = $48.96M
exposure_mid  = 120,000 × $471 = $56.52M   ← displayed
exposure_high = 120,000 × $535 = $64.20M
```

Source: IBM Cost of a Data Breach 2023 — Healthcare vertical, U.S. region, all-cause average across confirmed breaches.

When the same agent shows up on the Executive Posture as `$56.52M`, on Multi-Hop XGRAPH as a $56.52M chain, and on AI Abuse Scenarios under `prompt_injection` as $56.52M — they're all referencing this same calculation. Numbers are reproducible and the citation is one click away from every screen via the **ⓘ Methodology** button.

## What AuditGraph deliberately does NOT do

These omissions are intentional, not gaps:

- **No probability of breach.** AuditGraph quantifies *consequence given compromise*. Likelihood is a separate discipline (threat intelligence, vendor exposure analysis) that requires its own data and methodology. Mixing the two produces numbers that are hard to defend in a regulator's office.
- **No ML-derived multipliers.** Numbers are deterministic. The same inputs always produce the same outputs. An auditor can replay any calculation from raw source.
- **No summing across overlapping chains.** When the same data class is reached by multiple chains (e.g., five agents all reaching the same 120,000 PHI records), we use the MAX record count, not the sum. Five paths to the same data is still 120,000 records.
- **No hidden factors.** Every dollar on every screen traces back to a row in `breach_cost_factors` with a citation. No "proprietary cost model."

## Primary references

- **IBM Security** — *Cost of a Data Breach Report 2023* (annual, public).
  Authoritative source for per-record costs across industry verticals.
- **Ponemon Institute** — *Cost of Healthcare Data Breach Report 2023*.
  Healthcare-specific factors, used for PHI calibration.
- **Verizon** — *Data Breach Investigations Report (DBIR) 2023*.
  Cross-industry incident data, used for source code and IP factors.
- **GDPR Enforcement Tracker** (gdprhub.eu).
  Used for EU regulatory-fine reference points and high-band calibration.
- **HHS Office for Civil Rights** — HIPAA breach reporting database.
  Used for PHI breach incident frequency and severity calibration.

## Where the table lives

The cost factor table is defined by the SQL migration `backend/migrations/204_breach_cost_factors.sql`. Each row carries:

- `classification` (PHI, PCI, PII, etc.)
- `region` (US, EU, APAC, GLOBAL)
- `factor_low_usd`, `factor_mid_usd`, `factor_high_usd`
- `source` (citation string)
- `source_year` (integer — for trend analysis)
- `notes` (free text — caveats)
- `effective_date` (when this row becomes the active factor)

Operators can override factors on a per-tenant basis to reflect specific contractual terms (e.g., a SaaS vendor with a per-record contractual penalty might use the contractual figure as the low band).

## How this number lands at a board meeting

```
"Our worst-case breach exposure across AI-reachable data
 is $81.6 million mid-band ($48.96M to $100.4M low-to-high).
 This is computed from 187,432 classified records reachable
 by our AI agents at current role assignments, multiplied by
 IBM 2023 industry cost factors for PHI, PCI, and PII.
 The single agent contributing the most exposure is
 demo-ai-copilot-prod ($56.52M)."
```

That sentence — defensible, sourced, reproducible — is what AuditGraph generates. The same number renders on the Multi-Hop XGRAPH chain to demo-ai-copilot-prod, on the AI Abuse Scenarios card under `prompt_injection`, and on the Business Impact section of the Executive Posture page. All consistent, all traceable.

## Audit trail

Every breach exposure calculation is logged with:

- Timestamp
- User who triggered (if interactive) or system (if scheduled)
- Inputs (record count, classification)
- Factor row used (with source_year)
- Output values

This produces an audit trail suitable for SOC 2, HIPAA, and PCI evidence requirements where a regulator might ask "where did you get $56 million?".
