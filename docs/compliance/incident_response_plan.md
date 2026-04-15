# Incident Response Plan — AuditGraph

**Version:** 1.0
**Effective Date:** 2026-03-03
**Owner:** Security Engineering
**SOC 2 Controls:** CC7.3, CC7.4 | **HIPAA:** 164.308(a)(6)
**Review Cadence:** Annual + after every P1/P2 incident

---

## 1. Purpose

This plan defines how AuditGraph detects, classifies, responds to, and recovers from security incidents. It maps the platform's automated security telemetry (`SecurityEventLogger`) to human response workflows, ensuring incidents are handled within defined timelines.

## 2. Scope

This plan covers:
- Security events detected by `SecurityEventLogger` (10 event types)
- Anomalies detected by `AnomalyDetector` (6 anomaly types)
- Infrastructure incidents (pool exhaustion, DB failures, deployment issues)
- Customer-reported security concerns
- Data breach scenarios (tenant isolation failure, unauthorized data access)

---

## 3. Incident Classification

### 3.1 Severity Matrix

| Priority | Severity | Description | Response Time | Resolution Target |
|----------|----------|-------------|---------------|-------------------|
| **P1** | Critical | Tenant isolation breach, data exposure, RLS bypass | 15 minutes | 4 hours |
| **P2** | High | Admin guard bypass, auth system failure, pool exhaustion | 30 minutes | 8 hours |
| **P3** | Medium | Slow queries degrading service, tenant skew, auth failures | 2 hours | 24 hours |
| **P4** | Low/Info | Successful operations, rotations, migrations | Next business day | 5 business days |

### 3.2 SecurityEventLogger → Severity Mapping

| Security Event | Priority | Auto-Alert | Escalation |
|---------------|----------|------------|------------|
| `TENANT_CONTEXT_VIOLATION` | **P1** | Slack/Teams + PagerDuty | Immediate to Security Lead |
| `RLS_DRIFT_DETECTED` | **P1** | Slack/Teams + PagerDuty | Immediate to Security Lead + CTO |
| `ADMIN_GUARD_BLOCKED` | **P2** | Slack/Teams | Security Lead within 30 min |
| `POOL_EXHAUSTION` | **P2** | Slack/Teams | On-call SRE within 30 min |
| `AUTH_FAILURE` (burst >10/min) | **P2** | Slack/Teams | Security Lead within 30 min |
| `SLOW_QUERY` | **P3** | Log Analytics alert | Engineering review next sprint |
| `TENANT_SKEW` | **P3** | Slack/Teams | Platform team within 2 hours |
| `AUTH_FAILURE` (individual) | **P3** | Log only | Review in daily triage |
| `SECRET_ROTATION` (failure) | **P2** | Slack/Teams + PagerDuty | Security Lead within 30 min |
| `SECRET_ROTATION` (success) | **P4** | Log only | No action required |
| `MIGRATION_APPLIED` | **P4** | Log only | Verify in deploy pipeline |
| `STARTUP_VALIDATION` (failure) | **P2** | Deploy fails, Slack alert | On-call SRE within 30 min |

### 3.3 AnomalyDetector → Severity Mapping

| Anomaly Type | Priority | Response |
|-------------|----------|----------|
| `permission_escalation` | **P2** | Investigate identity, check for compromise |
| `risk_score_spike` | **P3** | Review identity changes in last 24 hours |
| `dormant_reactivation` | **P3** | Verify reactivation was authorized |
| `credential_surge` | **P2** | Check for credential stuffing or compromise |
| `off_hours_pim` | **P2** | Verify PIM activation was authorized |
| `excessive_pim_usage` | **P3** | Review standing access vs JIT need |

---

## 4. Response Procedures

### 4.1 P1 — Tenant Isolation Breach

**Trigger:** `TENANT_CONTEXT_VIOLATION` or `RLS_DRIFT_DETECTED`

**Immediate (0-15 min):**
1. Security Lead acknowledges alert
2. Check `security_events` log: identify affected tenant(s), request correlation ID
3. Determine scope: single request vs systemic failure
4. If RLS drift: verify `FORCE ROW LEVEL SECURITY` on all 44 tables
   ```sql
   SELECT relname, relforcerowsecurity
   FROM pg_class
   WHERE relname IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public')
   AND relrowsecurity = true AND relforcerowsecurity = false;
   ```

**Containment (15-60 min):**
5. If tenant context lost: identify and patch code path (verify_tenant_context audit)
6. If RLS drift: re-apply FORCE RLS immediately via emergency migration
7. If data exposure confirmed: note affected tenant IDs and time window

**Eradication (1-4 hours):**
8. Deploy hotfix or rollback to last known-good version
9. Run full isolation stress test (`test_isolation_stress.py`)
10. Verify all 44 tables have correct RLS policies

**Recovery (4-24 hours):**
11. Audit `activity_log` for any cross-tenant data access during incident window
12. Notify affected tenants per communication protocol (Section 7)
13. Update incident timeline and root cause document

**Post-Incident:**
14. Conduct blameless postmortem within 48 hours
15. Add regression test for the specific failure mode
16. Update this plan if new detection or response gaps found

### 4.2 P2 — Admin Guard Bypass / Auth System Failure

**Trigger:** `ADMIN_GUARD_BLOCKED`, `POOL_EXHAUSTION`, `AUTH_FAILURE` burst, `SECRET_ROTATION` failure

**Immediate (0-30 min):**
1. On-call engineer acknowledges alert
2. Check security event details: correlation_id, affected endpoint
3. Verify system health: `GET /api/health`, `GET /api/system/health`

**Investigation (30-120 min):**
4. For admin guard: identify unauthorized `Database()` creation — code path audit
5. For pool exhaustion: check `GET /api/system/health` → connection_pool stats, identify leak
6. For auth burst: check for brute force (rate limiting should block), verify IP patterns
7. For secret rotation failure: check credential expiry, Azure service health

**Resolution (2-8 hours):**
8. Deploy fix or apply configuration change
9. Verify with targeted test
10. Monitor for recurrence over 24 hours

### 4.3 P3 — Degradation / Individual Incidents

**Trigger:** `SLOW_QUERY`, `TENANT_SKEW`, individual `AUTH_FAILURE`

**Triage (next daily standup or within 2 hours if during business):**
1. Review in daily security triage
2. For slow queries: identify query, check execution plan, add index if needed
3. For tenant skew: review tenant growth, consider data archival or partition
4. For auth failures: check if user error or potential credential testing

**Resolution (within 24 hours):**
5. Apply fix if systemic
6. Log in sprint backlog if optimization needed
7. No customer notification unless service degradation visible

---

## 5. Detection Infrastructure

### 5.1 Automated Detection

```
SecurityEventLogger  →  JSON structured logs  →  Azure Log Analytics
       ↓                                              ↓
  Slack/Teams webhook                          Alert rules (KQL queries)
  (NotificationDispatcher)                          ↓
       ↓                                     PagerDuty (P1/P2)
  #auditgraph-security channel
```

### 5.2 Key Log Analytics Queries (KQL)

**P1 — Tenant isolation violations (last hour):**
```kql
ContainerAppConsoleLogs_CL
| where Log_s contains "TENANT_CONTEXT_VIOLATION"
| project TimeGenerated, Log_s
| order by TimeGenerated desc
```

**P2 — Auth failure burst detection (>10 per minute):**
```kql
ContainerAppConsoleLogs_CL
| where Log_s contains "AUTH_FAILURE"
| summarize count() by bin(TimeGenerated, 1m)
| where count_ > 10
```

**P2 — Pool exhaustion trend:**
```kql
ContainerAppConsoleLogs_CL
| where Log_s contains "POOL_EXHAUSTION"
| project TimeGenerated, Log_s
| order by TimeGenerated desc
```

### 5.3 Notification Channels

| Channel | Used For | Configuration |
|---------|----------|--------------|
| Slack (`#auditgraph-security`) | All P1-P3 events | `NotificationDispatcher` webhook |
| Microsoft Teams | Alternative to Slack | `NotificationDispatcher` webhook |
| PagerDuty | P1 and P2 on-call paging | Integration via Slack or direct |
| Email | Customer breach notification | `EmailService` |
| Activity log | All events (permanent record) | `database.py:log_activity()` |

---

## 6. Roles & Responsibilities

| Role | Responsibility | Contact Method |
|------|---------------|----------------|
| **Security Lead** | P1/P2 incident commander, breach assessment, customer communication | PagerDuty + Slack |
| **On-Call SRE** | Infrastructure incidents (pool, deploy, health), first responder | PagerDuty rotation |
| **CTO** | P1 escalation, breach notification decision, external communication | Direct contact |
| **Engineering Lead** | Code-level investigation, hotfix deployment | Slack + PagerDuty |
| **Compliance Officer** | Regulatory notification assessment (HIPAA breach rule) | Email |

### Escalation Path

```
Alert → On-Call SRE (15 min) → Security Lead (30 min) → CTO (1 hour)
                                      ↓
                              Compliance Officer (if data breach)
```

---

## 7. Communication Protocol

### 7.1 Internal Communication

| Timeline | Action |
|----------|--------|
| 0-15 min | Alert acknowledged in `#auditgraph-security` |
| 15-30 min | Incident channel created (`#inc-YYYY-MM-DD-brief`) |
| Every 30 min | Status update in incident channel (during active response) |
| Resolution | Summary posted, channel archived |

### 7.2 Customer Notification (Data Breach)

| Timeline | Action |
|----------|--------|
| 0-4 hours | Internal assessment of breach scope |
| 4-24 hours | Draft notification reviewed by Security Lead + CTO |
| 24-48 hours | Affected tenants notified via email with: scope, timeline, remediation |
| 72 hours | HIPAA breach notification filed if PHI involved (per 164.408) |
| 30 days | Full incident report provided to affected tenants |

### 7.3 Notification Template

```
Subject: Security Incident Notification — AuditGraph [INC-YYYY-MM-DD]

Dear [Tenant Admin],

We are writing to inform you of a security incident that may have affected your
AuditGraph environment.

What Happened: [Brief description]
When: [Date/time range in UTC]
What Data Was Involved: [Specific data types]
What We Have Done: [Remediation steps taken]
What You Should Do: [Recommended customer actions]

We take the security of your data seriously and have implemented additional
safeguards to prevent recurrence. A detailed incident report will follow within
30 days.

Contact: security@auditgraph.ai
```

---

## 8. Post-Incident Activities

### 8.1 Postmortem (within 48 hours of P1/P2)

Template:
1. **Timeline**: Minute-by-minute reconstruction
2. **Root Cause**: Technical root cause (5 Whys analysis)
3. **Impact**: Affected tenants, data scope, duration
4. **Detection**: How was the incident detected? Was it automated?
5. **Response**: What went well? What could improve?
6. **Action Items**: Each with owner + deadline + tracking ticket

### 8.2 Evidence Preservation

For every P1/P2 incident, preserve:
- [ ] `activity_log` entries for incident window (export via `/api/audit/export`)
- [ ] Security event logs from Log Analytics (export query results)
- [ ] Database query logs (if slow query or RLS issue)
- [ ] Container Apps deployment logs
- [ ] Screenshots of dashboard state at time of detection
- [ ] Git diff of any emergency hotfix deployed

### 8.3 Metrics & Reporting

Track quarterly:
- Mean Time to Detect (MTTD) per severity
- Mean Time to Respond (MTTR) per severity
- Incident count by category
- False positive rate for automated alerts
- Customer notification count

---

## 9. Plan Testing

| Activity | Frequency | Owner |
|----------|-----------|-------|
| Tabletop exercise (P1 scenario) | Quarterly | Security Lead |
| Notification channel test | Monthly | On-Call SRE |
| DR drill (see `dr_test_procedure.md`) | Quarterly | Engineering Lead |
| Plan review and update | Annually + post-incident | Security Lead |
| Escalation contact verification | Monthly | On-Call SRE |
