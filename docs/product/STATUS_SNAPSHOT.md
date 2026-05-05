# AuditGraph — Status Snapshot

> Last updated: 2026-05-02

---

## Current Sprint Focus

- Documentation consolidation and repo hygiene
- Pipeline health monitoring engine
- Resource inventory collector
- Privilege drift event tracking
- Identity reachability mapping

---

## Known Open Issues

| Issue | Description | Impact |
|-------|-------------|--------|
| Disabled identity misclassification | Some disabled identities may show incorrect status in certain edge cases | Low — cosmetic |
| False "Last Used Today" | Activity timestamp can show current date for identities without real P2 sign-in data (heuristic fallback) | Medium — misleading for auditors |
| P2 telemetry DDL | Savepoint-based DDL required to avoid startup deadlocks with multiple workers | Mitigated — fix deployed |

---

## Project Management

- **Jira**: Project `AG` at `nexgenixlabs.atlassian.net`
- **Confluence**: Space "Auditgraph" (spaceId: `21856259`)
- **GitHub**: Private repo, CI/CD on `dev` branch push

---

## Deployment Status

| Environment | URL | Status |
|-------------|-----|--------|
| Production API | `https://api.auditgraph.ai` | Active |
| Production App | `https://app.auditgraph.ai` | Active |
| Production Admin | `https://admin.auditgraph.ai` | Active |
| Dev API | `https://dev.api.auditgraph.ai` | Active |
| Dev App | `https://dev.app.auditgraph.ai` | Active |
| Demo | `https://demo.auditgraph.ai` | Active |

---

## Recent Completions (last 5 commits)

1. CISO board — privilege exposure, anomalies, blast radius wired to real data
2. Core ARM activity + signInActivity — real IPs, sign-in datetimes, role last-used
3. P2 sign-in events pipeline, workload_signin_events populated
4. NHI lineage section, role usage honest labels
5. Identity Explorer consolidated tabs (4 nav items -> 1 wrapper)

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Database tables | 54+ |
| API endpoints | ~198 routes |
| Frontend pages | 38+ |
| Completed phases | 86+ |
| Identity categories | 6 (service_principal, managed_identity_system, managed_identity_user, human_user, guest, microsoft_internal) |
