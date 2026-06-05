# AuditGraph — SOC 2 Type II Control Map

**Status**: Skeleton for auditor pre-engagement. NOT a final report.
**Trust Service Criteria**: Security (CC), Confidentiality (C), Availability (A)
**Scope**: AuditGraph SaaS platform — backend API + frontend portal + database
**Date**: 2026-06-05
**Reviewing controls catalog**: AICPA TSC 2017 with 2022 points-of-focus revisions

---

## How to read this document

Each row maps an AICPA Trust Service Criterion control to a concrete AuditGraph implementation (code path, table, or process). For SOC 2 Type II we need 6-12 months of evidence; this document is the prep for the **TYPE I** readiness pass first.

The `[STATUS]` column:
- ✅ — implemented, evidence exists
- ⏳ — implemented, evidence collection pending
- ❌ — gap, needs work before audit

---

## CC1 — Control Environment

| Control ID | Description | AuditGraph implementation | Status |
|---|---|---|---|
| CC1.1 | Demonstrates commitment to integrity and ethical values | Code of conduct in employee handbook (to be created) | ❌ |
| CC1.2 | Board of directors demonstrates independence | N/A (founder-stage) | ❌ |
| CC1.3 | Establishes structures, reporting lines, authority | Org chart + role definitions | ❌ |
| CC1.4 | Demonstrates commitment to competence | Annual training records (DevSecOps onboarding) | ❌ |
| CC1.5 | Enforces accountability | RACI matrix for incident response | ❌ |

## CC2 — Communication and Information

| CC2.1 | Communicates relevant security information internally | All-hands meetings + Slack #security channel | ❌ |
| CC2.2 | Communicates relevant security information externally | Trust center page + security.txt | ❌ |
| CC2.3 | Communicates with external parties for security | Vulnerability disclosure email + public PGP key | ❌ |

## CC3 — Risk Assessment

| CC3.1 | Specifies suitable objectives | This SOC 2 readiness doc | ⏳ |
| CC3.2 | Identifies risks to achieving objectives | `docs/AG_PROD_READINESS_PENTEST_2026_06_04.md` | ✅ |
| CC3.3 | Considers fraud risks | Internal pentest report + threat-model session | ⏳ |
| CC3.4 | Identifies and assesses change | Change Control Center page (`/remediation-queue`) | ✅ |

## CC4 — Monitoring Activities

| CC4.1 | Selects, develops, performs ongoing evaluations | Activity Timeline + Anomaly Detection (Phase 40) | ✅ |
| CC4.2 | Evaluates and communicates control deficiencies | Quarterly readiness review (process to be defined) | ❌ |

## CC5 — Control Activities

| CC5.1 | Selects and develops control activities | This doc + IaC in `infra/` | ⏳ |
| CC5.2 | Selects and develops technology controls | Migrations 017 (RLS), 211 (RLS Tier 1-4) | ✅ |
| CC5.3 | Deploys controls via policies and procedures | `.github/workflows/pr-gate.yml` + `deploy-dev.yml` | ✅ |

## CC6 — Logical and Physical Access

### CC6.1 — Logical access (the big one for us)

| Sub-control | Implementation | Status |
|---|---|---|
| User registration + provisioning | `app/api/auth.py` user CRUD (admin-only) | ✅ |
| Authentication — MFA where appropriate | SSO/SAML in Phase 54 (`saml.py`); MFA inherited from IdP | ✅ |
| Authentication — password complexity | bcrypt cost=12, minimum length, complexity check | ✅ |
| Authorization — RBAC | Phase 31 — admin/auditor/viewer + role hierarchy | ✅ |
| Authorization — tenant isolation | Strict Postgres RLS on all 50 multi-tenant tables (migrations 017, 091, 211) | ✅ |
| Authorization — superadmin scope | X-Tenant-Id header gated to `is_superadmin` only | ✅ |
| Periodic access review | Access Reviews page (`/access-reviews`) + Ownership Center (`/ownership`) | ✅ |
| Session management | JWT 15 min access + refresh rotation; CSRF token; `purgeStaleCsrfCookies` recovery | ✅ |
| Account lockout | Login rate-limit via `check_sso_rate_limit` (5 attempts/5min) | ✅ |
| Termination/deprovisioning | User CRUD + `DELETE /api/users/<id>` triggers session invalidation | ✅ |

### CC6.6 — Network access

| Sub-control | Implementation | Status |
|---|---|---|
| Firewall + perimeter | Azure Container Apps with managed ingress + VNet | ✅ |
| TLS in transit | Managed certs (mc-dev-cae-*-9258/9066/9758); HSTS header | ✅ |
| Internal traffic encryption | All inter-service via TLS within VNet | ✅ |

### CC6.7 — Confidentiality

| Sub-control | Implementation | Status |
|---|---|---|
| Encryption at rest — DB | Azure PostgreSQL Flexible Server — encryption at rest enabled by default | ✅ |
| Encryption at rest — file storage | Azure Blob with customer-managed keys (CMK to be configured) | ⏳ |
| Secret management | Webhook secrets in dedicated `threat_connectors.webhook_secret` column (Pentest F-002 fix) | ✅ |
| Key rotation | Manual quarterly process; tracked in IaC | ⏳ |

## CC7 — System Operations

| CC7.1 | Detects and responds to security events | `activity_log`, `anomalies`, `soar_actions` tables | ✅ |
| CC7.2 | Develops response activities | SOAR playbooks in `soar_playbooks` (Phase 43) | ✅ |
| CC7.3 | Evaluates security events | Argus Analyst page (`/argus`) | ✅ |
| CC7.4 | Implements business continuity / DR | Azure backups + read replicas (to be configured for prod) | ⏳ |
| CC7.5 | Identifies and develops actions for breach response | Incident response runbook (to be created) | ❌ |

## CC8 — Change Management

| CC8.1 | Authorizes, designs, develops, deploys | PR Gate + Deploy DEV workflow + migrations via `apply_cloud_migration.py` | ✅ |

## CC9 — Risk Mitigation

| CC9.1 | Identifies, selects, develops risk mitigation | This document + prod-readiness report | ⏳ |
| CC9.2 | Assesses vendor / business partner | Vendor security review template (to be created) | ❌ |

---

## A1 — Availability

| Control | Implementation | Status |
|---|---|---|
| A1.1 — capacity demand mgmt | Azure Container Apps autoscale (min=1, max=10) | ✅ |
| A1.2 — env protection (DDoS, redundancy) | Azure Front Door + WAF (to be added before customer prod) | ❌ |
| A1.3 — backup + recovery | Postgres PITR + nightly logical dumps to Azure Blob | ⏳ |

## C1 — Confidentiality

| Control | Implementation | Status |
|---|---|---|
| C1.1 — protects confidential info | Strict tenant RLS + bcrypt password hashing + JWT signing | ✅ |
| C1.2 — disposes of confidential info | `DELETE` cascades + `deleted_at` soft-delete pattern | ✅ |

## Threat-model artifacts

| Artifact | Path / status |
|---|---|
| Internal pentest report | `docs/AG_INTERNAL_PENTEST_FULL_2026_06_04.md` |
| Production readiness audit | `docs/AG_PROD_READINESS_FULL_2026_06_04.md` |
| Patent draft | `docs/AG_PATENT_DRAFT_MULTIHOP_XGRAPH_2026_06_05.md` |
| Architecture + IA | `docs/AG_FINAL_IA_AND_BRAND_2026_06_05.md` |

## Gaps to close before SOC 2 Type I

1. **Policy documents** (handbook, code of conduct, incident response plan, vendor management) — 1 week with a template provider (Drata / Vanta / Secureframe)
2. **Trust Center + security.txt** — 1 day
3. **CMK for Blob storage** — 2 days (Azure Key Vault integration)
4. **DR runbook + tested failover** — 1 week (engage Azure DR consultant)
5. **Annual security training** — 1 day (Workramp / KnowBe4 subscription)
6. **Vendor risk assessment template** — 1 day
7. **Continuous monitoring tool** (Drata recommended) — 2 days to onboard
8. **External pentest by Trail of Bits or NCC Group** — 4-6 weeks engagement, $25-40k

**Estimated time to SOC 2 Type I readiness**: ~10 weeks elapsed (mostly external waiting).
**Estimated time from Type I to Type II report**: 6 months observation window.

---

**Next action**: pick a continuous monitoring vendor (recommend Drata for SaaS pricing + Azure native integrations) and start the policy template intake.
