# AuditGraph Scoring Reference

> Merged from `backend/docs/SCORING.md` + `backend/SCORING_CALIBRATION.md`.
> Originals archived at `docs/archive/merged/`.

---

## Part 1: Identity Risk Scoring System

### Overview

AuditGraph uses a two-level scoring system:
1. **Identity Risk Score** (0.0-10.0) — per-identity, CVSS v3.1 aligned
2. **Posture Score** (0-100) — org-level, aggregated from identity scores

Both are computed from the same SSOT data in `identity_list`.

---

### Identity Risk Score (CVSSIdentityScorer)

**File:** `backend/app/engines/scoring/cvss_identity_scorer.py`

#### Five Dimensions

| Dimension | Range | Source | NIST/CIS Ref |
|-----------|-------|--------|-------------|
| Blast Radius | 0-10 | Widest scope x privilege impact | NIST 800-207 S2.1 |
| Privilege Exposure | 0-10 | Most dangerous role held | NIST 800-207 S3.3 |
| Dormancy Risk | 0-10 | Days since last activity | NIST 800-63B S4.1.3 |
| Governance Gaps | 0-10 | Owner/review status | CIS v8 S5.3 |
| Credential Risk | 0-10 | Rotation status (NHI only) | CIS v8 S5.2 |

#### Composition Formula

```
threat  = max(blast_radius, privilege)
hygiene = max(dormancy, governance, credential)

if threat >= 7.0:      base = max(threat, hygiene)          # no cap
elif threat >= 4.0:    base = max(threat, min(hygiene, 7.5))  # cap HIGH
else:                  base = max(threat, min(hygiene, 5.5))  # cap upper-MEDIUM

severity_score = clamp(base * env_multiplier, 0.0, 10.0)
```

**Privilege-modulated composition (April 2026):** Hygiene dimensions (dormancy,
governance, credential) represent poor practice but not direct danger.
A dormant Reader is concerning (MEDIUM) but not CRITICAL — only privileged
dormant identities represent critical risk. The `threat` score gates how
high hygiene alone can push the final score.

#### Environment Multipliers

| Environment | Multiplier |
|-------------|-----------|
| production | 1.30 |
| corporate | 1.20 |
| ci_cd | 1.15 |
| platform | 1.10 |
| dev | 1.00 |
| unknown | 1.05 |

#### CVSS Severity Bands

| Band | Score Range |
|------|-----------|
| CRITICAL | >= 9.0 |
| HIGH | 7.0-8.99 |
| MEDIUM | 4.0-6.99 |
| LOW | 0.01-3.99 |
| INFO | 0.0 |

#### Key Design Decisions

- **Privilege-modulated composition**: Hygiene dimensions are capped based on privilege level. Standard-privilege identities (< 4.0) cap at 5.5 (upper-MEDIUM). Medium-privilege (4.0-6.99) cap at 7.5 (HIGH). Only highly-privileged (>= 7.0) can reach CRITICAL from hygiene gaps alone.

- **Blast radius impact factor**: Scope score is modulated by role privilege. A Reader at subscription scope (0.3 x 8.5 = 2.55) scores much lower than an Owner at subscription scope (1.0 x 8.5 = 8.5).

- **Governance calibration**: Unowned standard-privilege identities score 2.0 (LOW), not 9.5.

- **Context-aware env_multiplier**: Managed identities (system/user MSI) with standard privilege (< 4.0) use multiplier 1.0 regardless of environment tier.

---

### Posture Score (PostureScorer)

**File:** `backend/app/engines/scoring/posture_scorer.py`

#### Formula

```
penalty = SUM(severity_score * band_weight * env_weight) for each scored identity
posture_score = max(0, 100 - penalty / identity_count)
```

#### Band Weights

| CVSS Band | Weight | Rationale |
|-----------|--------|-----------|
| CRITICAL | 265 | A single CRITICAL identity dominates |
| HIGH | 20 | Significant but manageable |
| MEDIUM | 11 | Moderate concern |
| LOW | 0.42 | Minimal impact on aggregate score |
| INFO | 0 | No penalty |

#### Environment Weights

| Environment | Weight |
|-------------|--------|
| production | 1.5 |
| corporate | 1.2 |
| platform | 1.0 |
| ci_cd | 0.8 |
| dev | 0.5 |
| unknown | 1.0 |

#### Posture Labels

| Score Range | Label |
|------------|-------|
| >= 85 | Strong |
| 70-84 | Moderate |
| 50-69 | Elevated Risk |
| < 50 | Critical Exposure |

#### Calibration (AzureCredits tenant, org_id=2)

Known distribution: 2 CRITICAL, 2 MEDIUM, 316 LOW (320 total).
Target: Dashboard value ~82 ("Moderate").

---

### Fix Prioritization

**Files:**
- `backend/app/engines/remediation/fix_catalogue.py`
- `backend/app/engines/remediation/fix_simulator.py`
- `backend/app/engines/remediation/fix_prioritizer.py`

#### Priority Formula

```
priority_score = risk_reduction_pct * 0.6
               + (1 / effort_minutes) * 100 * 0.3
               + len(framework_badges) * 5 * 0.1
```

#### Five Fix Types

| Fix Type | Safety | Effort | Affected Dimensions |
|----------|--------|--------|-------------------|
| ESTABLISH_OWNERSHIP | Safe | 15 min | governance |
| REVOKE_EXCESSIVE_ROLE | Caution | 30 min | blast_radius, privilege |
| REDUCE_SCOPE | Caution | 30 min | blast_radius |
| ROTATE_CREDENTIALS | Caution | 20 min | credential |
| ENABLE_PIM | Safe | 60 min | governance |

#### Safety Escalation Rules

- Production environment + REVOKE/REDUCE -> "Requires Manual Review"
- CRITICAL identity + REVOKE -> "Requires Manual Review"
- All others -> catalogue default (Safe or Caution)

---

## Part 2: AGIRS Composite Model (Phase 4B Calibration)

### Three-Axis Composite

| Axis | Weight | Range | Purpose |
|------|--------|-------|---------|
| HIRI | 40% | 0-100 | Human Identity Risk Index — ghost, dormant, over-priv, guest, zombie |
| NHIRI | 40% | 0-100 | Non-Human Identity Risk Index — orphan, dormant, zombie, expired, ownerless, federated, PAT, DevOps |
| GEI | 20% | 25-100 | Governance Effectiveness Index — ownership, PIM, reviews, monitoring |

**Formula**: `AGIRS = 0.40 * HIRI + 0.40 * NHIRI + 0.20 * GEI`

### Blast Radius Scoring (0-100)

#### Base Score Components (max 150, capped at 100)

| Component | Max Weight | Source |
|-----------|-----------|--------|
| Entra role privilege | 50 | Global Admin = 50, Priv Role Admin = 45 |
| RBAC role privilege | 40 | Owner = 40, Contributor = 30 |
| Scope weight | 15 | Management Group = 15, Subscription = 10 |
| Resource count | 10 | log2-based scale |
| Sensitive data | 15 | Any sensitive resource access |
| Guest identity | 10 | External guest bonus |
| Escalation paths | 10 | 3 per path, max 10 |

#### Additive Bonuses (stacking)

| Bonus | Points | Trigger |
|-------|--------|---------|
| SAMI AKS resource context | 12 | System MI on AKS cluster |
| SAMI App Service context | 8 | System MI on App Service |
| SAMI VM context | 6 | System MI on VM |
| SAMI default context | 3 | System MI on other resource |
| Compute danger (env secrets) | 5-15 | High-severity env secrets on accessed compute |
| Federated misconfigured | 12 | Overly-broad federated credential |
| DB admin (mixed+open) | 15 | AAD admin of mixed-auth + open-firewall DB |
| DB admin (mixed only) | 8 | AAD admin of mixed-auth DB |
| Analytics PATs (no-expiry) | 5-15 | 5 per no-expiry PAT, max 15 |
| Analytics broad KV access | 12 | Workspace linked service with broad KV |
| DevOps sub-scope SC | 15 | SPN in subscription-scope ADO service connection |
| DevOps RG-scope SC | 8 | SPN in RG-scope ADO service connection |
| APIM unscoped subs | 8 | APIM MSI with unscoped subscription keys |
| Root SAS key | 10 | Event Hub/Service Bus root Manage key |
| Batch SharedKey | 5 | Batch MSI with SharedKey auth enabled |
| Pipeline escalation | 20 | GitHub OIDC + high-priv role (attack path) |

#### Score Interpretation

| Range | Level | Meaning |
|-------|-------|---------|
| 0-39 | LOW | Minimal blast radius, standard lifecycle |
| 40-59 | MEDIUM | Moderate exposure, review recommended |
| 60-79 | HIGH | Significant exposure, remediation needed |
| 80-100 | CRITICAL | Maximum exposure, urgent remediation |

### Recalibration Guards (Phase 4B)

1. **Critical Inflation Cap (30%)**: If > 30% of non-system identities are CRITICAL, warning logged. Does NOT auto-adjust.
2. **HEALTHY/AGIRS Contradiction**: If AGIRS > 80 but CRITICAL identities exist, flagged for review.
3. **GEI Floor at 25**: GEI cannot drop below 25 — partial governance always has some value.
4. **Confidence Score** (0-100): No humans -20, No NHIs -20, Unconfigured GEI -15 each, No P2 -10, Single run -5.

### Six-Plane Coverage

| Plane | Scoring Inputs | Phase |
|-------|---------------|-------|
| 1. Compute | env secret danger, App Service/VM SAMI context | 2A |
| 2. Container | AKS SAMI context, federated misconfigured, pipeline escalation | 2B |
| 3. Data | DB admin mixed-auth, open-firewall bonus | 3A |
| 4. Analytics | PAT no-expiry, broad KV access, admin sprawl GEI penalty | 3B |
| 5. DevOps | ADO sub/RG scope, APIM unscoped, root SAS key, NHIRI N8 | 4A |
| 6. Long-tail | Batch SharedKey | 4B |

### Verification Queries

```sql
-- Critical distribution check
SELECT risk_level, COUNT(*) as cnt,
       ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 1) as pct
FROM identities
WHERE discovery_run_id IN (SELECT id FROM discovery_runs WHERE status = 'completed' ORDER BY id DESC LIMIT 1)
  AND NOT COALESCE(is_microsoft_system, false)
  AND deleted_at IS NULL
GROUP BY risk_level ORDER BY cnt DESC;

-- AGIRS score + confidence
SELECT * FROM risk_summary
WHERE organization_id = 1
ORDER BY id DESC LIMIT 1;

-- Blast radius distribution
SELECT
  CASE WHEN blast_radius_score >= 80 THEN 'CRITICAL'
       WHEN blast_radius_score >= 60 THEN 'HIGH'
       WHEN blast_radius_score >= 40 THEN 'MEDIUM'
       ELSE 'LOW' END as tier,
  COUNT(*) as cnt
FROM identities
WHERE discovery_run_id IN (SELECT id FROM discovery_runs WHERE status = 'completed' ORDER BY id DESC LIMIT 1)
  AND NOT COALESCE(is_microsoft_system, false)
  AND deleted_at IS NULL
GROUP BY 1 ORDER BY 1;
```
