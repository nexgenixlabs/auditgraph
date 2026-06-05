# AuditGraph Scoring System

## Overview

AuditGraph uses a two-level scoring system:
1. **Identity Risk Score** (0.0–10.0) — per-identity, CVSS v3.1 aligned
2. **Posture Score** (0–100) — org-level, aggregated from identity scores

Both are computed from the same SSOT data in `identity_list`.

---

## Identity Risk Score (CVSSIdentityScorer)

**File:** `backend/app/engines/scoring/cvss_identity_scorer.py`

### Five Dimensions

| Dimension | Range | Source | NIST/CIS Ref |
|-----------|-------|--------|-------------|
| Blast Radius | 0–10 | Widest scope × privilege impact | NIST 800-207 §2.1 |
| Privilege Exposure | 0–10 | Most dangerous role held | NIST 800-207 §3.3 |
| Dormancy Risk | 0–10 | Days since last activity | NIST 800-63B §4.1.3 |
| Governance Gaps | 0–10 | Owner/review status | CIS v8 §5.3 |
| Credential Risk | 0–10 | Rotation status (NHI only) | CIS v8 §5.2 |

### Composition Formula

```
threat  = max(blast_radius, privilege)
hygiene = max(dormancy, governance, credential)

if threat ≥ 7.0:      base = max(threat, hygiene)        # no cap
elif threat ≥ 4.0:    base = max(threat, min(hygiene, 7.5))  # cap HIGH
else:                 base = max(threat, min(hygiene, 5.5))  # cap upper-MEDIUM

severity_score = clamp(base × env_multiplier, 0.0, 10.0)
```

**Privilege-modulated composition (April 2026):** Hygiene dimensions (dormancy,
governance, credential) represent poor practice but not direct danger.
A dormant Reader is concerning (MEDIUM) but not CRITICAL — only privileged
dormant identities represent critical risk. The `threat` score gates how
high hygiene alone can push the final score.

### Environment Multipliers

| Environment | Multiplier |
|-------------|-----------|
| production | 1.30 |
| corporate | 1.20 |
| ci_cd | 1.15 |
| platform | 1.10 |
| dev | 1.00 |
| unknown | 1.05 |

### CVSS Severity Bands

| Band | Score Range |
|------|-----------|
| CRITICAL | ≥ 9.0 |
| HIGH | 7.0–8.99 |
| MEDIUM | 4.0–6.99 |
| LOW | 0.01–3.99 |
| INFO | 0.0 |

### Key Design Decisions

- **Privilege-modulated composition**: Hygiene dimensions (dormancy, governance,
  credential) are capped based on the identity's privilege level. Standard-privilege
  identities (privilege < 4.0) cap at 5.5 (upper-MEDIUM). Medium-privilege identities
  (4.0–6.99) cap at 7.5 (HIGH). Only highly-privileged identities (≥ 7.0) can reach
  CRITICAL from hygiene gaps alone. This prevents dormancy/governance from pushing
  thousands of routine managed identities into CRITICAL.

- **Blast radius impact factor**: Scope score is modulated by role privilege.
  A Reader at subscription scope (0.3 × 8.5 = 2.55) scores much lower than
  an Owner at subscription scope (1.0 × 8.5 = 8.5). This prevents workload
  SPNs with Reader-only roles from being flagged as HIGH risk.

- **Governance calibration**: Unowned standard-privilege identities score 2.0
  (LOW), not 9.5. The governance gap is only CRITICAL when there is no
  accountability for a privileged identity.

- **Context-aware env_multiplier**: Managed identities (system/user MSI) with
  standard privilege (< 4.0) use multiplier 1.0 regardless of environment tier.
  These are routine automation and should not be penalised for being in production.

---

## Posture Score (PostureScorer)

**File:** `backend/app/engines/scoring/posture_scorer.py`

### Formula

```
penalty = Σ (severity_score × band_weight × env_weight)
          for each scored identity

posture_score = max(0, 100 - penalty / identity_count)
```

### Band Weights

| CVSS Band | Weight | Rationale |
|-----------|--------|-----------|
| CRITICAL | 265 | A single CRITICAL identity dominates |
| HIGH | 20 | Significant but manageable |
| MEDIUM | 11 | Moderate concern |
| LOW | 0.42 | Minimal impact on aggregate score |
| INFO | 0 | No penalty |

### Environment Weights

| Environment | Weight |
|-------------|--------|
| production | 1.5 |
| corporate | 1.2 |
| platform | 1.0 |
| ci_cd | 0.8 |
| dev | 0.5 |
| unknown | 1.0 |

### Posture Labels

| Score Range | Label |
|------------|-------|
| ≥ 85 | Strong |
| 70–84 | Moderate |
| 50–69 | Elevated Risk |
| < 50 | Critical Exposure |

### Calibration Methodology

Calibrated against AzureCredits tenant (org_id=2) with known distribution:
- 2 CRITICAL (severity=10.0, env=ci_cd/production)
- 2 MEDIUM (severity≈5.5, env=corporate/dev)
- 316 LOW (severity≈2.68, env=platform)
- Total: 320 identities

**Target:** Dashboard value ~82 ("Moderate")

**Working backwards:**
```
penalty target = (100 - 82) × 320 = 5760

CRITICAL: 2 × 10.0 × 265 × 0.8 = 4240  (ci_cd env)
MEDIUM:   2 × 5.5  × 11  × 1.0 = 121   (unknown env)
LOW:      316 × 2.68 × 0.42 × 1.0 = 356 (platform env)

Total penalty ≈ 4717 / 320 = 14.7 → posture ≈ 85.3
```

Actual result depends on exact per-identity env_tier values.

### Standards References

- **NIST SP 800-55r2** (Information Security Performance Measurement):
  Posture score is an aggregated security metric per §5.2 guidelines.

- **CIS Controls v8 IG2/IG3** (Implementation Groups):
  Band weights reflect maturity-based risk tolerance — CRITICAL identities
  in IG3 environments warrant disproportionate penalty.

---

## Fix Prioritization

**Files:**
- `backend/app/engines/remediation/fix_catalogue.py` — Fix type definitions
- `backend/app/engines/remediation/fix_simulator.py` — Delta simulation
- `backend/app/engines/remediation/fix_prioritizer.py` — Ranking logic

### Priority Formula

```
priority_score = risk_reduction_pct × 0.6
               + (1 / effort_minutes) × 100 × 0.3
               + len(framework_badges) × 5 × 0.1
```

### Five Fix Types

| Fix Type | Safety | Effort | Affected Dimensions |
|----------|--------|--------|-------------------|
| ESTABLISH_OWNERSHIP | Safe | 15 min | governance |
| REVOKE_EXCESSIVE_ROLE | Caution | 30 min | blast_radius, privilege |
| REDUCE_SCOPE | Caution | 30 min | blast_radius |
| ROTATE_CREDENTIALS | Caution | 20 min | credential |
| ENABLE_PIM | Safe | 60 min | governance |

### Safety Escalation Rules

- Production environment + REVOKE/REDUCE → "Requires Manual Review"
- CRITICAL identity + REVOKE → "Requires Manual Review"
- All others → catalogue default (Safe or Caution)

### Simulation Design

Each fix simulation:
1. Calls CVSSIdentityScorer methods to recompute affected dimension(s)
2. Keeps all unaffected dimensions at their stored values
3. Recomposes using privilege-modulated formula (see Composition Formula)
4. Returns simulated severity_score

**Note:** Privilege-modulated composition means a fix only reduces the final
score when it targets the dominant dimension within its tier. Fixing dormancy
on a standard-privilege identity has no effect if privilege (threat) is already
the limiting factor. The engine only recommends fixes that produce actual
improvement.
