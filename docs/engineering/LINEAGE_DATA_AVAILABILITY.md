# AuditGraph Lineage — Data Availability by Azure AD License Tier

AuditGraph delivers full Tier 1 analysis on free-tier tenants. Tier 2 signals activate automatically when P1/P2 is present. No configuration changes needed — the engine detects available APIs at runtime and gracefully degrades.

## Signal Availability Matrix

| Signal | Free Tier | P1 | P2 |
|---|---|---|---|
| App registration metadata | Full | Full | Full |
| Role topology inference | Full | Full | Full |
| OAuth2 grant patterns (M1) | Full | Full | Full |
| Required resource access audit (M2) | Full | Full | Full |
| ARM resource binding scan | Full | Full | Full |
| Federated credential detection | Full | Full | Full |
| Owned/created objects scan (M5) | Full | Full | Full |
| Audit log provenance (M3) | 7 days | 30 days | 90 days |
| Service principal sign-in logs (M4) | None | None | Full |
| Interactive sign-in split | None | None | Full |
| P2 behavioral telemetry | None | None | Full |

## Enrichment Tiers

| Tier | Meaning | Typical License |
|---|---|---|
| `STATIC` | Base signals only (app reg, roles, name heuristics) | Free |
| `ENRICHED` | Static intelligence modules populated (M1-M3, M5) | Free + AuditLog.Read.All |
| `FULL` | Sign-in activity data available | P2 (or M4 data present) |
| `P2_AUDIT` | Full P2 telemetry pipeline active | P2 |

## Verdict Actions

| Action | Meaning | Demo Impact |
|---|---|---|
| `ORPHANED` | Has RBAC roles, no owner, no sign-in — real finding | CISO acts on this |
| `UNUSED` | No roles, no sign-in — safe to remove | Cleanup candidate |
| `STALE` | Last sign-in >365 days but still has roles | Review candidate |
| `AT_RISK` | Shared identity/credential detected | Security alert |
| `NEEDS_REVIEW` | Has roles but no lineage signals | Manual review |
| `HEALTHY` | Well-understood with confirmed lineage evidence | No action needed |

## What This Means for Sales

**Differentiator**: Most CSPM tools require Azure AD P2 to do anything useful with workload identities. AuditGraph delivers actionable ORPHANED/UNUSED verdicts on day one with a free-tier tenant. The product gracefully upgrades as the customer invests in P1/P2 licensing — more signals, higher confidence, richer narratives.

**Demo flow**: Even with one ORPHANED SPN showing an active Contributor role on a subscription with no owner and no recorded authentication — that's a real finding a CISO acts on.
