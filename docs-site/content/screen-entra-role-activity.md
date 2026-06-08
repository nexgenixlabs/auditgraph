# Screen Walkthrough — Entra Directory Role Last-Used

**Route**: `/identity-security/entra-role-activity` · **Section**: Identity Security · **Audience**: CISOs, IAM ops, GRC, audit teams

## What this screen answers

> *"For every Entra directory role assignment in my tenant, when was it last actually exercised?"*

Microsoft Entra tells you who *has* a directory role. It doesn't tell you who has *used* it. This screen answers the second question — surfacing dormant standing role grants that should be either revoked, converted to PIM eligibility, or documented as accepted risk.

This is **Feature E Phase 2** — the patent-track capability where AuditGraph attributes audit-log events to specific role assignments via a cross-product mapping of `(role → audit categories)`. No competitor surfaces per-directory-role last-used inference at the assignment level today.

## What you see on screen

### Top — Headline card

> *"1 privileged directory role assignment with no observed activity in 90+ days — review for least-privilege cleanup."*

Or, if everything's healthy:

> *"All 23 directory role assignments show recent activity."*

### Summary cards (4)

| Card | Counts |
|---|---|
| Role assignments | Total directory role assignments analyzed |
| High dormancy (90+ days) | No observed activity in last 90 days |
| Medium (30-90 days) | Activity but stale |
| Active (<30 days) | Recent activity |

### Dormancy filter chips

`all · high · medium · low · unknown` — click to filter the table below.

### Assignments table

Sorted by dormancy DESC (worst first):

| Column | Source |
|---|---|
| Dormancy | `high` / `medium` / `low` / `unknown` band — color-coded |
| Identity | Display name + identity_id |
| Directory Role | Role name (Global Administrator, User Administrator, etc.) |
| Days since last | Days since the latest audit-log event attributable to this assignment |
| 90d acts | Count of activities in last 90 days |
| Bucket | `daily` / `weekly` / `monthly` / `rare` / `dormant` / `unknown` |
| Source | `auditLogs` (green, real data) or `unknown` (amber, tenant lacks P2) |

### Findings panel (when dormant assignments detected)

For each high-dormancy assignment of a privileged role:

- **Severity tag** + finding type (`dormant_directory_role_assignment`)
- **Title** ("Global Administrator assignment with no observed activity in 120d")
- **Identity context**
- **Recommendation** paragraph

## The patent-track moat — CATEGORIES_REQUIRING

For each Entra directory role, we maintain a mapping to the audit-log categories the role's permissions gate:

| Role | Audit categories required |
|---|---|
| Global Administrator | All categories (broadest reach) |
| Privileged Role Administrator | RoleManagement, DirectoryManagement, Policy |
| User Administrator | UserManagement, GroupManagement, Authentication |
| Application Administrator | ApplicationManagement, Authorization, AuthorizationPolicy |
| Cloud Application Administrator | ApplicationManagement, Authorization |
| Conditional Access Administrator | Policy, ConditionalAccess, AuthorizationPolicy |
| Security Administrator | Policy, IdentityProtection, ConditionalAccess, RoleManagement |
| Billing Administrator | Other, ResourceManagement |

When an audit event arrives for user U with category C, we look up which of U's role assignments have C in their `CATEGORIES_REQUIRING` set and attribute the event to those — and only those — assignments.

**Why this matters:** the naive approach attributes ALL events for a user to ALL of the user's roles (false positives — a User Admin who once was a Global Admin would still look "active" as a GA because of group management events). The cross-product narrows attribution to which role's permissions actually gate this event's category. This is the patent-track invention — see `docs/AG_PATENT_AND_NEXT_PLATE_2026_06_07.md` § P2.

## Activity buckets

Computed deterministically from activity counts:

| Bucket | Rule |
|---|---|
| `daily` | ≥20 activities in 30 days |
| `weekly` | 5-19 activities in 30 days |
| `monthly` | 3+ activities in 90 days (but not weekly cadence) |
| `rare` | 1-2 activities in 90 days |
| `dormant` | 0 activities observed |
| `unknown` | No audit log access (P2 unavailable) |

## Dormancy bands

| Band | Rule |
|---|---|
| `low` | <30 days since last activity (healthy) |
| `medium` | 30-90 days (stale, review) |
| `high` | 90+ days (dormant, action required) |
| `unknown` | No activity data inferable |

## Findings emitted

### `dormant_directory_role_assignment`

> Identity holds a directory role that has not been exercised in 90+ days.

**Severity:** `critical` for top privileged roles (Global Administrator, Privileged Role Administrator, Security Administrator) · `high` for other roles in the CATEGORIES_REQUIRING mapping.

**Recommendation:** review with the assignment owner — either remove the standing grant, replace with PIM-eligibility (time-bound activation), or document why standing grant is required.

**Important:** the finding only fires when `inference_confidence='observed'` — meaning we have real audit log data. On tenants without P2 audit logs, the row shows `dormancy_band='unknown'` and NO finding fires (we don't fabricate findings on absent data — moat compliance).

## Graceful degradation on P2-less tenants

| Available data | What shows |
|---|---|
| Full P2 with audit logs | All buckets/bands populated from real activity |
| No P2 / no audit log read | Assignments show with `bucket='unknown'`, `band='unknown'`, `source='unknown'` |
| Partial P2 | Mix of observed + unknown — surfaced honestly per row |

This is the moat point: features stay useful even when the tenant doesn't have logs (70% don't). See `memory/spec_checklist_agentless_readonly.md`.

## Common questions

**Q: How does this differ from PIM Overprivilege Detection?**
PIM Overprivilege covers PIM-*eligible* assignments (where the user can activate but isn't permanently elevated). Entra Role Activity covers *standing* directory role grants (already permanently elevated). Different surfaces, complementary analysis.

**Q: A user has Global Administrator but I see "unknown" — why?**
The tenant lacks audit log access (Entra P2 required). Get the customer's IAM admin to verify `AuditLog.Read.All` is in the consent grant, and that the tenant has Entra P2 licensing.

**Q: Can custom Entra roles be analyzed?**
Today, only the 8 most common built-in roles are in `CATEGORIES_REQUIRING`. Custom roles fall back to `unknown`. Expanding the mapping to custom roles is on the roadmap — needs role-permission introspection via Graph API.

**Q: Why doesn't `dormant_directory_role_assignment` fire on a custom role with 120d no activity?**
The finding only fires for roles we have confidence-attributed (i.e., in CATEGORIES_REQUIRING). For custom roles, we surface the row with `band='high'` but emit no finding because we can't be confident about cross-product attribution.

## What to do next

1. **Sort by dormancy DESC** — focus on `high` band first
2. **For each critical finding** (Global Admin / Priv Role Admin / Security Admin dormant 90+ days): walk through with the assignment owner. These are the most-asked-about identities in audits.
3. **For each non-finding high-band row** (custom roles with no activity): manual review — we can't be sure they're truly dormant, but worth a conversation
4. **Convert appropriate standing grants to PIM eligibility** — moves them from this page to PIM Overprivilege Detection where they're tracked under JIT activation
5. **Schedule** this view as input to quarterly access reviews

## Related screens

- [PIM Overprivilege](#screen-pim-overprivilege) — sibling: analyzes PIM-eligible assignments (this screen covers standing grants)
- [Identity Trust](#screen-identity-trust) — Telemetry + Oversight dimensions reflect role activity hygiene
- [AI Findings](#screen-ai-findings) — `dormant_directory_role_assignment` shows up here too
- [Multi-Hop XGRAPH](#screen-multi-hop-xgraph) — dormant privileged role = unmonitored blast radius
