# AGIRS Scoring Calibration — Post Phase 4B (2026-03-29)

## Three-Axis Composite Model

| Axis | Weight | Range | Purpose |
|------|--------|-------|---------|
| HIRI | 40% | 0-100 | Human Identity Risk Index — ghost, dormant, over-priv, guest, zombie |
| NHIRI | 40% | 0-100 | Non-Human Identity Risk Index — orphan, dormant, zombie, expired, ownerless, federated, PAT, DevOps |
| GEI | 20% | 25-100 | Governance Effectiveness Index — ownership, PIM, reviews, monitoring |

**Formula**: `AGIRS = 0.40 * HIRI + 0.40 * NHIRI + 0.20 * GEI`

## Blast Radius Scoring (0-100)

### Base Score Components (max 150, capped at 100)
| Component | Max Weight | Source |
|-----------|-----------|--------|
| Entra role privilege | 50 | Global Admin = 50, Priv Role Admin = 45 |
| RBAC role privilege | 40 | Owner = 40, Contributor = 30 |
| Scope weight | 15 | Management Group = 15, Subscription = 10 |
| Resource count | 10 | log2-based scale |
| Sensitive data | 15 | Any sensitive resource access |
| Guest identity | 10 | External guest bonus |
| Escalation paths | 10 | 3 per path, max 10 |

### Additive Bonuses (stacking)
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

### Score Interpretation
| Range | Level | Meaning |
|-------|-------|---------|
| 0-39 | LOW | Minimal blast radius, standard lifecycle |
| 40-59 | MEDIUM | Moderate exposure, review recommended |
| 60-79 | HIGH | Significant exposure, remediation needed |
| 80-100 | CRITICAL | Maximum exposure, urgent remediation |

## Recalibration Guards (Phase 4B)

### Check 1: Critical Inflation Cap (30%)
If > 30% of non-system identities are CRITICAL, a warning is logged. This indicates blast radius weights may be too aggressive. The cap does NOT auto-adjust scores — it surfaces the issue for manual review.

### Check 2: HEALTHY/AGIRS Contradiction
If AGIRS > 80 (indicating good posture) but CRITICAL identities exist, this contradiction is flagged. Typical cause: a few high-privilege identities in an otherwise well-governed tenant.

### Check 3: GEI Floor at 25
GEI cannot drop below 25 even with mixed-auth and admin-sprawl penalties. Rationale: having any governance framework partially deployed provides some value — penalizing to 0 is misleading.

### Check 4: Confidence Score
Confidence (0-100) reflects data completeness. Deductions:
- No humans: -20
- No NHIs: -20
- Unconfigured GEI component: -15 each
- No P2 telemetry: -10
- Single discovery run: -5

## Six-Plane Coverage

| Plane | Scoring Inputs | Phase |
|-------|---------------|-------|
| 1. Compute | env secret danger, App Service/VM SAMI context | 2A |
| 2. Container | AKS SAMI context, federated misconfigured, pipeline escalation | 2B |
| 3. Data | DB admin mixed-auth, open-firewall bonus | 3A |
| 4. Analytics | PAT no-expiry, broad KV access, admin sprawl GEI penalty | 3B |
| 5. DevOps | ADO sub/RG scope, APIM unscoped, root SAS key, NHIRI N8 | 4A |
| 6. Long-tail | Batch SharedKey | 4B |

## Verification Queries

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
