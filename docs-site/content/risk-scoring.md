# Section 4 -- Risk Scoring Model

## Overview

AuditGraph uses a proprietary composite scoring model called **AGIRS** (AuditGraph Identity Risk Score) to quantify organizational identity risk. The model evaluates three independent axes and produces a single 0-100 score.

```
                    ┌─────────────────────────────┐
                    │         AGIRS Score          │
                    │          (0-100)             │
                    │                              │
                    │  0.40 × HIRI                 │
                    │  0.40 × NHIRI                │
                    │  0.20 × GEI                  │
                    └──────────────┬──────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
       ┌──────▼──────┐     ┌──────▼──────┐     ┌──────▼──────┐
       │    HIRI     │     │   NHIRI     │     │    GEI      │
       │ Human Risk  │     │ Non-Human   │     │ Governance  │
       │  (40%)      │     │ Risk (40%)  │     │ (20%)       │
       └─────────────┘     └─────────────┘     └─────────────┘
```

| Score | Component | Weight | Measures |
|-------|-----------|--------|----------|
| **AGIRS** | Composite | 100% | Overall organizational identity risk posture |
| **HIRI** | Human Identity Risk Index | 40% | Risk from human user accounts |
| **NHIRI** | Non-Human Identity Risk Index | 40% | Risk from service principals, managed identities, API keys |
| **GEI** | Governance Effectiveness Index | 20% | Quality of identity governance practices |

---

## AGIRS -- AuditGraph Identity Risk Score

### What It Represents

AGIRS is a single number (0-100) that represents how well an organization manages identity risk across all cloud environments. A higher score means lower risk.

### Calculation

```
AGIRS = 0.40 × HIRI + 0.40 × NHIRI + 0.20 × GEI
```

### Grade Mapping

| Score Range | Grade | Status | Interpretation |
|-------------|-------|--------|----------------|
| 92-100 | A | Resilient | Identity risk is well-managed. Governance practices are mature. |
| 80-91 | B | Controlled | Minor gaps exist. Remediation is needed for specific findings. |
| 65-79 | C | Elevated | Significant risk factors present. Priority remediation recommended. |
| 45-64 | D | Critical | Major identity risk gaps. Immediate action required. |
| 0-44 | F | Critical | Severe risk posture. Foundational governance is missing. |

### Example

```
Organization: Acme Corp
  HIRI:  74.2 (Human Risk)
  NHIRI: 68.5 (Non-Human Risk)
  GEI:   75.0 (Governance)

  AGIRS = 0.40 × 74.2 + 0.40 × 68.5 + 0.20 × 75.0
        = 29.68 + 27.40 + 15.00
        = 72.08

  Grade: C (Elevated)
```

---

## HIRI -- Human Identity Risk Index

### What It Represents

HIRI measures risk from human user accounts: employees, contractors, and guests. It starts at 100 and deducts points based on the severity and prevalence of risk factors.

### Risk Factors

| Code | Factor | Weight | Description |
|------|--------|--------|-------------|
| **H1** | Ghost Humans | 3 | Disabled or deleted accounts that still have active RBAC or Entra role assignments |
| **H2** | Dormant Privileged | 5 | Stale users (90+ days inactive) that hold T0, T1, or T2 roles |
| **H3** | Over-Privileged | 4 | Users with risk score >= 70 or T0 tier |
| **H4** | External Guests with Privilege | 6 | Guest accounts holding T0, T1, or T2 roles, or RBAC Owner/Contributor/UAA |
| **H5** | Zombie Humans | 7 | Disabled users paired with enabled duplicates that have valid credentials |

### Calculation

```
raw_deductions = (H1_count × 3) + (H2_count × 5) + (H3_count × 4)
               + (H4_count × 6) + (H5_count × 7)

normalized = min(raw_deductions / max(human_count, 1) × 100, 500)

HIRI = max(100 - normalized, 0)
```

The normalization step scales deductions relative to the total number of human identities. The cap at 500 prevents the score from going below 0 in extreme cases.

### Example: Low Risk

```
Organization: SecureCo (200 human identities)
  H1 Ghost:        2 accounts  × 3 = 6
  H2 Dormant Priv: 1 account   × 5 = 5
  H3 Over-Priv:    3 accounts  × 4 = 12
  H4 Ext Guests:   0 accounts  × 6 = 0
  H5 Zombies:      0 accounts  × 7 = 0

  raw = 23
  normalized = min(23 / 200 × 100, 500) = 11.5
  HIRI = max(100 - 11.5, 0) = 88.5

  Interpretation: Good posture. Minor cleanup needed for ghost and dormant accounts.
```

### Example: High Risk

```
Organization: RiskyCo (150 human identities)
  H1 Ghost:        44 accounts × 3 = 132
  H2 Dormant Priv:  5 accounts × 5 = 25
  H3 Over-Priv:    73 accounts × 4 = 292
  H4 Ext Guests:    8 accounts × 6 = 48
  H5 Zombies:       3 accounts × 7 = 21

  raw = 518
  normalized = min(518 / 150 × 100, 500) = 345.3
  HIRI = max(100 - 345.3, 0) = 0.0

  Interpretation: Critical. Nearly half of humans are over-privileged.
                  44 ghost accounts represent immediate remediation targets.
```

---

## NHIRI -- Non-Human Identity Risk Index

### What It Represents

NHIRI measures risk from service principals, managed identities, and API keys. Non-human identities typically outnumber humans and often have persistent credentials with broad permissions.

### Risk Factors

| Code | Factor | Weight | Description |
|------|--------|--------|-------------|
| **N1** | Orphaned NHI | 4 | Service principals or managed identities with no owners |
| **N2** | Dormant NHI | 3 | Inactive NHIs (60+ days) that still have active role assignments |
| **N3** | Zombie NHI | 6 | Stale NHIs with risk score >= 70 AND valid credentials |
| **N4** | Expired/Expiring Credentials | 2 | Credentials expired or expiring within 30 days |
| **N5** | Ownerless Apps | 5 | App registrations with zero owners AND high-risk permissions |

### Calculation

NHIRI uses a scope multiplier (default 1.3) to account for the typically broader access scope of non-human identities:

```
raw_deductions = ((N1_count × 4) + (N2_count × 3) + (N3_count × 6)
               +  (N4_count × 2) + (N5_count × 5)) × scope_multiplier

normalized = min(raw_deductions / max(nhi_count, 1) × 100, 500)

NHIRI = max(100 - normalized, 0)
```

### Phantom Breakdown

NHIRI provides a detailed breakdown called the "phantom breakdown" showing the exact count for each risk factor:

```json
{
  "phantom_breakdown": {
    "orphaned": 34,
    "dormant": 56,
    "zombie_nhi": 12,
    "expired_creds": 89,
    "ownerless_apps": 5
  }
}
```

### Example: Medium Risk

```
Organization: MidCo (120 non-human identities)
  N1 Orphaned:     16 × 4 = 64
  N2 Dormant:       8 × 3 = 24
  N3 Zombie:        2 × 6 = 12
  N4 Expired Creds: 5 × 2 = 10
  N5 Ownerless:     3 × 5 = 15

  raw = (64 + 24 + 12 + 10 + 15) × 1.3 = 162.5
  normalized = min(162.5 / 120 × 100, 500) = 135.4
  NHIRI = max(100 - 135.4, 0) = 0.0

  Interpretation: Critical. 16 orphaned SPNs and 8 dormant NHIs need
                  immediate ownership assignment and access review.
```

---

## GEI -- Governance Effectiveness Index

### What It Represents

GEI measures how well an organization's governance processes are working. Unlike HIRI and NHIRI which measure risk factors, GEI measures protective controls.

### Components

GEI is the average of four independent governance components, each scored 0-100:

| Component | Weight | Measures |
|-----------|--------|----------|
| **Ownership Coverage** | 25% | Percentage of custom SPNs with at least one owner assigned |
| **PIM Adoption** | 25% | Percentage of T0/T1 identities with PIM eligible assignments |
| **Access Review Completion** | 25% | Percentage of service account attestations with status "attested" |
| **Monitoring Coverage (P2)** | 25% | Percentage of NHIs with P2 telemetry sign-in data |

### Calculation

```
GEI = (ownership_pct + pim_pct + review_pct + monitoring_pct) / 4
```

### Component Details

**Ownership Coverage:**
```sql
owned_spns / total_custom_spns × 100

Example: 78 of 120 SPNs have owners → 65%
```

**PIM Adoption:**
```sql
pim_covered_t0_t1 / total_t0_t1_identities × 100

Example: 12 of 18 T0/T1 identities have PIM → 66.7%
```

**Access Review Completion:**
```sql
attested_count / total_attestations × 100

Example: 45 of 60 attestations completed → 75%
```

**Monitoring Coverage:**
```sql
nhi_with_signin_data / total_nhi × 100

Example: 80 of 120 NHIs have sign-in telemetry → 66.7%
```

### Example

```
Organization: GovCo
  Ownership Coverage:   65.0%
  PIM Adoption:         66.7%
  Access Reviews:       75.0%
  Monitoring Coverage:  66.7%

  GEI = (65.0 + 66.7 + 75.0 + 66.7) / 4 = 68.35

  Interpretation: Moderate governance. PIM adoption and ownership
                  coverage should be improved first.
```

---

## Blast Radius Score

### What It Represents

The blast radius score is a per-identity metric that estimates the impact if that specific identity is compromised. Higher scores mean an attacker can reach more resources and critical assets.

### Calculation

```
Blast Radius = Tier Weight × Scope Multiplier × Dormancy Multiplier × Exposure Multiplier
```

**Tier Weights:**

| Tier | Weight | Description |
|------|--------|-------------|
| T0 | 10 | Tenant-wide control (Global Admin, Privileged Role Admin) |
| T1 | 7 | Subscription-wide control (Owner, UAA) |
| T2 | 4 | Resource group control (Contributor at RG level) |
| T3 | 1 | Single resource access |

**Scope Multipliers:**

| Scope | Multiplier |
|-------|-----------|
| Tenant-wide (Entra roles) | 3.0 |
| Subscription-level | 2.0 |
| Resource group | 1.5 |
| Single resource | 1.0 |

**Dormancy Multipliers:**

| Activity Status | Multiplier | Rationale |
|----------------|-----------|-----------|
| Never used | 2.5 | Highest risk: no one monitoring this identity |
| Stale (90+ days) | 2.0 | Likely unmonitored, credentials may be exposed |
| Inactive (30-90 days) | 1.5 | Reduced monitoring attention |
| Active | 1.0 | Baseline |
| Unknown | 1.0 | Baseline (conservative) |

**Exposure Multipliers:**

| Condition | Multiplier |
|-----------|-----------|
| Cross-subscription access | ×1.5 |
| Multi-tenant application | ×1.3 |

### Example

```
Identity: prod-automation-sp (Service Principal)
  Tier:     T0 (Global Administrator)      → Weight: 10
  Scope:    Tenant-wide                    → Multiplier: 3.0
  Activity: Stale (120 days no sign-in)    → Multiplier: 2.0
  Exposure: Cross-subscription             → Multiplier: 1.5

  Blast Radius = 10 × 3.0 × 2.0 × 1.5 = 90.0

  Interpretation: Critical blast radius. If compromised, an attacker
                  gains Global Admin access across all subscriptions.
                  The identity is stale, increasing the likelihood of
                  undetected compromise.
```

### High Blast Radius Threshold

Identities with a blast radius score >= 70 are flagged as "high blast radius" and counted in the organization's risk summary. These identities are priority remediation targets.

---

## Using Scores for Remediation Prioritization

### Triage Framework

| Priority | Criteria | Action |
|----------|----------|--------|
| **P0 -- Immediate** | Blast radius >= 70 AND activity = stale/never_used | Disable or remove access within 24 hours |
| **P1 -- Urgent** | HIRI factor H5 (zombie) or NHIRI factor N3 (zombie NHI) | Investigate and remediate within 72 hours |
| **P2 -- High** | H2 (dormant privileged) or N1 (orphaned NHI with roles) | Assign owners, review access within 1 week |
| **P3 -- Medium** | H3 (over-privileged) or N4 (expired credentials) | Schedule access review, rotate credentials |
| **P4 -- Low** | N2 (dormant NHI) or low blast radius findings | Address in next quarterly review |

### Score Improvement Estimates

Each remediation action has an estimated impact on the AGIRS score:

| Remediation | Estimated AGIRS Impact |
|-------------|----------------------|
| Remove 1 over-privileged identity | +0.37 points |
| Remove 1 ghost account | +0.41 points |
| Assign owner to 1 orphaned SPN | +0.56 points |
| Remove 1 dormant privileged account | +1.8 points |
| Enable PIM for 1 T0 identity | +0.8 points |

### Dashboard Interpretation

```
┌──────────────────────────────────────────────────────────┐
│  AGIRS: 72 (Grade C -- Elevated)                         │
│                                                          │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐                 │
│  │ HIRI    │  │ NHIRI   │  │ GEI     │                 │
│  │  74.2   │  │  68.5   │  │  75.0   │                 │
│  │ ▲ +2.3  │  │ ▼ -1.1  │  │ ▲ +5.0  │                 │
│  └─────────┘  └─────────┘  └─────────┘                 │
│                                                          │
│  Top Risks:                                              │
│  1. 73 over-privileged identities (score impact: +27)    │
│  2. 44 ghost accounts (score impact: +18)                │
│  3.  5 dormant privileged (score impact: +9)             │
│  4. 16 orphaned SPNs (score impact: +9)                  │
│                                                          │
│  Recommended Actions:                                     │
│  → Right-size 73 over-privileged identities              │
│  → Remove 44 ghost account role assignments              │
│  → Review 5 dormant privileged accounts                  │
│  → Assign owners to 16 orphaned SPNs                     │
└──────────────────────────────────────────────────────────┘
```

---

## Data Persistence

All scores are computed after each discovery run and persisted to the `risk_summary` table:

| Column | Type | Description |
|--------|------|-------------|
| `agirs_score` | NUMERIC(6,2) | Composite AGIRS score |
| `agirs_tier` | VARCHAR(2) | Letter grade (A/B/C/D/F) |
| `hiri_score` | NUMERIC(5,2) | Human Identity Risk Index |
| `nhiri_score` | NUMERIC(5,2) | Non-Human Identity Risk Index |
| `gei_score` | NUMERIC(5,2) | Governance Effectiveness Index |
| `hiri_breakdown` | JSONB | Detailed H1-H5 counts |
| `nhiri_breakdown` | JSONB | Detailed N1-N5 counts (phantom breakdown) |
| `gei_breakdown` | JSONB | Component scores and configured flags |
| `dangerous_identities` | JSONB | Top identities by blast radius |

The table includes `UNIQUE(organization_id, discovery_run_id)` to ensure one risk summary per scan.

---

## References

- [Introduction](introduction.md) -- Identity concepts and privilege tiers
- [Architecture](architecture.md) -- Risk computation pipeline
- [Best Practices](best-practices.md) -- Remediation guidance
- [API Reference](api-reference.md) -- Risk summary API endpoints
