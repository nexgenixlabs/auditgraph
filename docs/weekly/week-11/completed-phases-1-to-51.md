# AuditGraph — Completed Phases (1–51)

## Week 11 Summary & Reference

This document provides a detailed explanation of every phase implemented in AuditGraph, covering what each phase does, why it's needed, how it helps, usage instructions, configuration, and **business test cases for QA validation**.

---

## Table of Contents

1. [Phase 1–6: Core Discovery & Multi-Cloud Foundation](#phase-1-6)
2. [Phase 7: Access Graph Visualization](#phase-7)
3. [Phase 8: PIM Tracking](#phase-8)
4. [Phase 9: Conditional Access Discovery](#phase-9)
5. [Phase 10: Hierarchical Access Graph](#phase-10)
6. [Phase 11: Dashboard Cloud Context](#phase-11)
7. [Phase 12: Remediation Engine](#phase-12)
8. [Phase 13: Report Generation](#phase-13)
9. [Phase 14: Drift Detection](#phase-14)
10. [Phase 15: Settings & Configuration](#phase-15)
11. [Phase 16: Drift History](#phase-16)
12. [Phase 17: Activity Log](#phase-17)
13. [Phase 18: Scheduled Reports & Email Verification](#phase-18)
14. [Phase 19–20: Identity Comparison & Bulk Operations](#phase-19-20)
15. [Phase 21–22: Dark Mode & Webhooks](#phase-21-22)
16. [Phase 23–25: Custom Risk Rules & Notifications](#phase-23-25)
17. [Phase 26–29: In-App Notification Center](#phase-26-29)
18. [Phase 30: Notification Center](#phase-30)
19. [Phase 31: RBAC & Authentication](#phase-31)
20. [Phase 32–33: Compliance Frameworks & Export Pipeline](#phase-32-33)
21. [Phase 34–35: Saved Views & Identity Lifecycle](#phase-34-35)
22. [Phase 36–37: Access Reviews & Role Mining](#phase-36-37)
23. [Phase 38: Identity Groups](#phase-38)
24. [Phase 39: Advanced Query Builder](#phase-39)
25. [Phase 40: Anomaly Detection](#phase-40)
26. [Phase 41: Risk Trend Analytics](#phase-41)
27. [Phase 42: API Key Management](#phase-42)
28. [Phase 43: SOAR Integration](#phase-43)
29. [Phase 44: Dashboard Customization](#phase-44)
30. [Phase 45: Multi-Tenant Foundation](#phase-45)
31. [Phase 46: Tenant User Management](#phase-46)
32. [Phase 47: Identity Lifecycle Tracking](#phase-47)
33. [Phase 48: Access Review Campaigns](#phase-48)
34. [Phase 49: Identity Risk Simulation](#phase-49)
35. [Phase 50: Compliance Gap Analysis](#phase-50)
36. [Phase 51: Compliance Trend Tracking](#phase-51)

---

<a id="phase-1-6"></a>
## Phase 1–6: Core Discovery & Multi-Cloud Foundation

### What It Does
The foundation of AuditGraph. Discovers all identities (service principals, managed identities, human users, guests) across Azure tenants by querying Microsoft Graph API and Azure Resource Manager. Computes risk scores based on role assignments, credentials, permissions, and activity status. Also establishes multi-cloud stubs for AWS IAM and GCP IAM discovery.

### Why It's Needed
Organizations have hundreds or thousands of identities in Azure AD/Entra ID with varying privilege levels. Without automated discovery, security teams have no visibility into over-privileged service principals, stale credentials, or dormant accounts — the #1 attack vector in cloud breaches.

### How It Helps
- Automatically discovers ALL identity types across subscriptions
- Calculates risk scores (0–100+) based on privilege accumulation
- Categorizes identities: `service_principal`, `managed_identity_system`, `managed_identity_user`, `human_user`, `guest`, `microsoft_internal`
- Tracks credential health (expired, expiring, valid)
- Monitors activity status (active, inactive, stale, never_used)
- Multi-cloud ready with AWS/GCP engine stubs

### Usage

**API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | Latest run summary with trend comparison |
| GET | `/api/identity-summary` | Category risk breakdown + monitored resource counts |
| GET | `/api/identities` | All identities (supports `limit`, `offset`, `cloud`, `risk_level`, `identity_category`, `search`) |
| GET | `/api/identities/<id>` | Full identity detail with roles, permissions, app_roles, owners, trend, evidence |
| GET | `/api/risks` | Critical/high risk identities list |
| GET | `/api/runs` | Discovery runs history |
| POST | `/api/runs/trigger` | Manually trigger a discovery run |
| GET | `/api/scheduler` | Scheduler status + next run time |

**UI Location:** Overview page (root `/`), Dashboard (`/dashboard`), Identities table (`/identities`)

### Configuration

| Setting | Environment Variable | Default |
|---------|---------------------|---------|
| Azure Tenant ID | `AZURE_TENANT_ID` | Required |
| Azure Client ID | `AZURE_CLIENT_ID` | Required |
| Azure Client Secret | `AZURE_CLIENT_SECRET` | Required |
| Subscription ID | `AZURE_SUBSCRIPTION_ID` | Auto-discovered |
| Discovery Interval | `DISCOVERY_INTERVAL_HOURS` | 12 hours |

**Required Graph API Permissions:** `Application.Read.All`, `Directory.Read.All`, `RoleManagement.Read.Directory`, `Policy.Read.All`, `AuditLog.Read.All`

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-1.1 | Manual discovery trigger | Login as admin → POST `/api/runs/trigger` | New discovery run created, identities populated, run appears in `/api/runs` |
| TC-1.2 | Identity list pagination | GET `/api/identities?limit=10&offset=0` then `offset=10` | First 10 identities, then next 10, no duplicates |
| TC-1.3 | Identity search | GET `/api/identities?search=admin` | Only identities with "admin" in display name or app_id |
| TC-1.4 | Risk level filter | GET `/api/identities?risk_level=critical` | Only critical-risk identities returned |
| TC-1.5 | Category filter | GET `/api/identities?identity_category=human_user` | Only human users returned |
| TC-1.6 | Identity detail | GET `/api/identities/<id>` | Full detail with roles, permissions, credentials, owners |
| TC-1.7 | Stats endpoint | GET `/api/stats` | Returns total counts, risk distribution, previous_run for trends |
| TC-1.8 | Scheduler status | GET `/api/scheduler` | Shows scheduler running status and next_run_time |
| TC-1.9 | Unauthenticated access blocked | GET `/api/identities` without token | Returns 401 error |
| TC-1.10 | Overview page renders | Navigate to `/` | GlobalRiskCards, CloudComparison, CategoryRiskGrid, InsightsPanel all visible |

---

<a id="phase-7"></a>
## Phase 7: Access Graph Visualization

### What It Does
Interactive network graph showing identity-to-resource access paths using ReactFlow. Dual-mode visualization: **Executive mode** (blast radius summary) and **Technical mode** (detailed relationship map with 13 custom node types).

### Why It's Needed
Understanding the blast radius of a compromised identity requires visual mapping. A single service principal might have access to 50+ resources through nested role assignments — a table can't convey that complexity. Auditors and CISOs need different views (technical detail vs. executive summary).

### How It Helps
- Visualizes identity → role → scope → resource chains
- Shows blast radius at a glance (how many resources are reachable)
- Exposes federated trust relationships and cross-tenant access
- Helps auditors trace exactly what an identity can do

### Usage

**API Endpoint:** `GET /api/identities/<id>/graph-data`

Returns pre-computed nodes and edges with:
- Trust score, scope count, exposure metrics
- Hierarchical ARM tree (Subscription → Resource Group → Resource)
- Entra directory role branch
- Permission and credential nodes

**UI Location:** Identity Detail page → "Access Graph" tab

### Configuration
No additional configuration needed. Graph data is computed server-side from existing role and permission data.

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-7.1 | Graph renders for identity | Navigate to `/identities/<id>` → Access Graph tab | ReactFlow canvas loads with nodes and edges |
| TC-7.2 | Executive mode | Toggle to Executive mode | Shows blast radius summary node with aggregate counts |
| TC-7.3 | Technical mode | Toggle to Technical mode | Shows hierarchical ARM tree with individual resources |
| TC-7.4 | Node hover tooltips | Hover over any node | Tooltip shows node details (role name, scope, risk level) |
| TC-7.5 | 13 node types render | Check for identity, role, permission, credential, scope, subscription, resource_group, resource, entra_directory, risk_summary, blast_radius, owner, federated_trust | Each node type renders with distinct styling |
| TC-7.6 | Graph for identity with no roles | View graph for low-privilege identity | Shows identity node with minimal connections |

---

<a id="phase-8"></a>
## Phase 8: PIM Tracking

### What It Does
Discovers and tracks Privileged Identity Management (PIM) eligible assignments and activation history from Entra ID. Identifies overuse patterns (identities that keep PIM roles activated permanently).

### Why It's Needed
PIM is Azure's just-in-time access mechanism. If identities leave PIM roles activated 24/7, it defeats the purpose of least-privilege. Tracking PIM usage patterns reveals who is circumventing security controls.

### How It Helps
- Shows which identities have PIM-eligible roles
- Tracks activation frequency and duration
- Calculates overuse metrics (ratio of activated time vs. eligible time)
- Flags identities that abuse PIM for persistent access
- PIM badge appears in identity table for quick identification

### Usage

**API Endpoint:** `GET /api/identities/<id>/pim`

Returns:
- `eligible_assignments`: List of PIM-eligible roles with status
- `activations`: Recent activation records with timestamps and justification
- `overuse_metrics`: Activation frequency and duration analysis

**UI Location:** Identity Detail page → "PIM" tab, plus PIM badge in Identities table

### Configuration
**Required Graph API Permission:** `RoleManagement.Read.Directory`

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-8.1 | PIM tab loads | Navigate to identity with PIM data → PIM tab | Shows eligible assignments list |
| TC-8.2 | PIM activations shown | Check activations section | Lists activation history with timestamps, justification, status |
| TC-8.3 | Overuse metrics | Check overuse section | Shows activation frequency, average duration, overuse flag |
| TC-8.4 | PIM badge in table | Navigate to `/identities` | Identities with PIM show badge icon |
| TC-8.5 | Identity without PIM | View PIM tab for non-PIM identity | Shows "No PIM eligible assignments" message |

---

<a id="phase-9"></a>
## Phase 9: Conditional Access Discovery

### What It Does
Discovers Conditional Access (CA) policies from Entra ID, computes per-identity coverage, and identifies gaps (identities not protected by MFA or other CA controls).

### Why It's Needed
Conditional Access policies are the first line of defense for identity security. If an identity is not covered by any CA policy requiring MFA, it's vulnerable to credential theft. Coverage gaps are a top audit finding.

### How It Helps
- Maps which CA policies protect which identities
- Computes MFA enforcement percentage
- Flags identities excluded from policies
- Shows weak policy configurations
- Shield icon in identity table for quick coverage status

### Usage

**API Endpoint:** `GET /api/dashboard/conditional-access`

Returns:
- Total policies, enabled count
- MFA enforcement percentage
- Identities covered vs. uncovered
- Weak policy flags

**UI Location:** Dashboard → ConditionalAccessCard, Identity table → shield icon, IdentityDetail → Compliance tab

### Configuration
**Required Graph API Permission:** `Policy.Read.All`

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-9.1 | CA card on dashboard | Navigate to `/dashboard` | ConditionalAccessCard shows policy count and MFA % |
| TC-9.2 | Shield icon in table | Navigate to `/identities` | Identities with CA coverage show shield icon |
| TC-9.3 | CA coverage details | View identity detail → Compliance tab | Shows which CA policies apply to this identity |
| TC-9.4 | Uncovered identities flagged | Check identities without CA coverage | No shield icon, identified as gap in compliance |

---

<a id="phase-10"></a>
## Phase 10: Hierarchical Access Graph

### What It Does
Enhanced access graph with ARM resource hierarchy (Subscription → Resource Group → Resource). Four new node types added. Entra directory roles displayed in a separate branch. Role badges show at each scope level.

### Why It's Needed
Azure RBAC scopes are hierarchical — a role at subscription level cascades to all resource groups and resources within it. The flat graph from Phase 7 didn't show this inheritance. Auditors need to understand scope inheritance to assess real blast radius.

### How It Helps
- Shows role inheritance through ARM hierarchy
- Visualizes scope of access (subscription-wide vs. resource-specific)
- Separates Entra directory roles from Azure RBAC roles
- Role badges at each level show exactly what permissions exist where

### Usage
Same API endpoint as Phase 7: `GET /api/identities/<id>/graph-data`

The `scope_hierarchy` field drives the ARM tree layout.

**UI Location:** Identity Detail → Access Graph tab (Technical mode)

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-10.1 | ARM hierarchy visible | Open Access Graph for identity with subscription roles | Shows Subscription → Resource Group → Resource tree |
| TC-10.2 | Role badges at scope | Check each node in ARM tree | Role badges appear at the scope where they're assigned |
| TC-10.3 | Entra branch separate | Check graph layout | Entra directory roles appear in separate upper-right branch |

---

<a id="phase-11"></a>
## Phase 11: Dashboard Cloud Context

### What It Does
CloudContextBanner component showing connected cloud providers (Azure, AWS, GCP) and monitored resource counts (subscriptions, accounts, projects).

### Why It's Needed
When managing multi-cloud environments, security teams need to quickly see which cloud providers are connected and how many resources are being monitored. This provides confidence that discovery is comprehensive.

### How It Helps
- Shows Azure/AWS/GCP connection status at a glance
- Displays monitored subscription/account/project counts
- Indicates gaps in cloud coverage

### Usage
**UI Location:** Dashboard page → top banner

**Data Source:** `/api/identity-summary` (includes `monitored_resources` object)

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-11.1 | Banner shows connected providers | Navigate to `/dashboard` | CloudContextBanner displays Azure as connected with subscription count |
| TC-11.2 | Resource counts accurate | Compare banner counts with Azure portal | Subscription count matches Azure portal |

---

<a id="phase-12"></a>
## Phase 12: Remediation Engine

### What It Does
Pattern-matching remediation system with 20 pre-built playbooks. Each playbook defines a risk pattern (e.g., "expired credentials", "over-privileged service principal") and provides step-by-step remediation instructions with severity levels, estimated effort, and Azure CLI/PowerShell commands.

### Why It's Needed
Identifying risks is only half the battle — security teams need actionable guidance on how to fix issues. Without remediation playbooks, auditors generate findings reports that engineering teams can't act on. This bridges the gap between "what's wrong" and "how to fix it."

### How It Helps
- Automatically matches playbooks to identity risk patterns
- Provides step-by-step remediation instructions
- Includes Azure CLI commands for automated fixes
- Categorizes by effort (quick-fix, moderate, significant)
- Tracks remediation progress per identity
- Links to compliance framework references (SOC2, HIPAA, etc.)

### Usage

**API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/identities/<id>/remediations` | Matched playbooks for an identity |
| GET | `/api/identities/<id>/remediation-status` | Remediation progress tracking |
| POST | `/api/identities/<id>/remediation-action` | Execute a remediation action |
| GET | `/api/remediation-summary` | Overall remediation statistics |
| POST | `/api/bulk/remediation` | Bulk remediation across identities |

**UI Location:** Identity Detail page → "Remediation" tab

### Configuration
Playbooks are pre-loaded in the `remediation_playbooks` table. Admins can modify priority, enable/disable, or add custom playbooks.

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-12.1 | Remediation tab shows playbooks | Navigate to identity with expired credentials → Remediation tab | At least one playbook matched (e.g., "Rotate Expired Credentials") |
| TC-12.2 | Playbook has steps | Expand a matched playbook | Shows numbered remediation steps with CLI commands |
| TC-12.3 | Severity and effort shown | Check playbook metadata | Severity (critical/high/medium/low) and effort (quick-fix/moderate/significant) visible |
| TC-12.4 | Compliance references | Check playbook details | Links to SOC2, HIPAA, or other framework controls |
| TC-12.5 | No match for clean identity | View remediation tab for low-risk identity | "No remediation needed" or empty playbook list |
| TC-12.6 | Bulk remediation | POST `/api/bulk/remediation` with multiple identity IDs | Actions created for all specified identities |
| TC-12.7 | Remediation summary | GET `/api/remediation-summary` | Returns counts of open, acknowledged, completed actions |

---

<a id="phase-13"></a>
## Phase 13: Report Generation

### What It Does
Professional PDF report generation using jsPDF. Creates multi-page executive reports with cover page, executive summary (posture score, risk distribution), top risk identities table, remediation playbook, and evidence methodology section.

### Why It's Needed
Auditors and CISOs need polished reports for board presentations, compliance audits, and regulatory submissions. Manual report creation is time-consuming and error-prone. Automated reports ensure consistency and include all critical data points.

### How It Helps
- One-click PDF generation with professional formatting
- Executive summary with posture score gauge and risk breakdown
- Top risk identities with recommended actions
- Compliance status across all frameworks
- Evidence methodology section for audit defensibility

### Usage

**API Endpoint:** `GET /api/reports/data` — Returns comprehensive JSON payload for PDF generation

**UI Location:** Reports page (`/reports`) → "Generate Report" button

**Frontend:** `utils/pdfGenerator.ts` — `generateReport()` function builds multi-page PDF

### Configuration
No additional configuration. Report content is derived from existing discovery data.

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-13.1 | Report page loads | Navigate to `/reports` | Report generation page displays with options |
| TC-13.2 | PDF download | Click "Generate Report" | PDF file downloads to browser |
| TC-13.3 | Cover page | Open downloaded PDF | Page 1 shows organization name, date, discovery metadata |
| TC-13.4 | Executive summary | Check page 2 | Posture score gauge, risk distribution chart, credential health |
| TC-13.5 | Top risks table | Check subsequent pages | Table of critical/high risk identities with remediation notes |
| TC-13.6 | Evidence methodology | Check final page | Data sources list and 5-step discovery process |
| TC-13.7 | Report data API | GET `/api/reports/data` | Returns JSON with all sections populated |

---

<a id="phase-14"></a>
## Phase 14: Drift Detection

### What It Does
Compares consecutive discovery runs to detect security-relevant changes. Persists drift reports to the `drift_reports` table. Sends email notifications with all 5 change types. Powers the RecentChanges dashboard widget.

### Why It's Needed
Cloud identity configurations change constantly — new service principals, role assignments, credential rotations. Without drift detection, security teams only see point-in-time snapshots. Drift detection reveals *what changed* between runs, enabling proactive security response.

### How It Helps
- Detects 5 change types: new identities, removed identities, permission changes, risk escalations, credential status changes
- Persists change reports for historical review
- Triggers email alerts for critical changes
- Powers RecentChanges widget on dashboard
- Enables compliance evidence for change management controls

### Usage

**API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/drift/latest` | Most recent drift report summary |
| GET | `/api/drift/history` | Historical drift reports list |
| GET | `/api/runs/<id>/drift` | Full drift report for a specific run |

**UI Location:** Dashboard → RecentChanges widget, Drift History page (`/drift`)

### Configuration

| Setting | Location | Options |
|---------|----------|---------|
| Email notifications | Settings page | Toggle on/off |
| Per-type notifications | Settings page | Toggle each: new identities, removed, permissions, risk, credentials |
| Email recipient | Settings page / env `EMAIL_TO` | Email address |

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-14.1 | Drift detected after run | Trigger two discovery runs | Second run produces drift report comparing to first |
| TC-14.2 | Latest drift endpoint | GET `/api/drift/latest` | Returns most recent drift with change counts |
| TC-14.3 | Drift history | GET `/api/drift/history` | Returns list of drift reports ordered by date |
| TC-14.4 | Run-specific drift | GET `/api/runs/<id>/drift` | Returns detailed drift for that run |
| TC-14.5 | RecentChanges widget | Navigate to `/dashboard` | Widget shows summary of latest changes |
| TC-14.6 | Email sent on changes | Enable email notifications → trigger discovery | Email received with change summary |
| TC-14.7 | No email if no changes | Run discovery with no changes | No email sent |

---

<a id="phase-15"></a>
## Phase 15: Settings & Configuration

### What It Does
Key-value settings system stored in the `settings` table. Provides a Settings page with sections for organization name, discovery scheduler interval, email toggle, and per-type notification flags.

### Why It's Needed
Enterprise deployments need configurable behavior without code changes. Admins must control discovery frequency, notification preferences, and organizational branding from the UI.

### How It Helps
- Centralized configuration management
- No restart required for setting changes
- Per-notification-type toggle granularity
- Scheduler interval adjustment (6/12/24 hours)

### Usage

**API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/settings` | Get all settings + system status |
| POST | `/api/settings` | Update settings (key-value pairs) |

**UI Location:** Settings page (`/settings`) — admin only

### Configuration
Settings are stored as key-value pairs in the database:

| Key | Description | Default |
|-----|-------------|---------|
| `org_name` | Organization name for reports | "My Organization" |
| `discovery_interval` | Hours between scheduled runs | 12 |
| `email_enabled` | Enable email notifications | true |
| `notify_new_identities` | Email on new identities | true |
| `notify_removed_identities` | Email on removed identities | true |
| `notify_permission_changes` | Email on permission changes | true |
| `notify_risk_changes` | Email on risk level changes | true |
| `notify_credential_changes` | Email on credential changes | true |

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-15.1 | Settings page loads | Navigate to `/settings` as admin | All setting sections visible |
| TC-15.2 | Update org name | Change org name → save | New name reflected in reports and UI |
| TC-15.3 | Change discovery interval | Set interval to 6 hours → save | Scheduler adjusts next run time |
| TC-15.4 | Toggle email | Disable email → trigger discovery | No email sent after run |
| TC-15.5 | Per-type toggle | Disable "new identities" notification, keep others | Email sent but omits new identities section |
| TC-15.6 | Non-admin blocked | Login as viewer → navigate to `/settings` | Access denied or redirect |
| TC-15.7 | Settings persist | Change setting → refresh page | Setting retains updated value |

---

<a id="phase-16"></a>
## Phase 16: Drift History

### What It Does
Dedicated Drift History page with timeline table showing all drift reports. Each row is expandable to reveal 5 collapsible change sections (new identities, removed, permission changes, risk changes, credential changes).

### Why It's Needed
While the dashboard shows the latest drift, auditors need to review historical changes for compliance evidence. The drift history page provides a full timeline of all security-relevant changes across all discovery runs.

### How It Helps
- Full timeline of identity changes
- Expandable detail views per change type
- Supports compliance audit evidence collection
- Links from RecentChanges dashboard widget

### Usage
**UI Location:** Drift History page (`/drift`), linked from RecentChanges widget "View History"

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-16.1 | Drift History page loads | Navigate to `/drift` | Timeline table with drift reports listed |
| TC-16.2 | Expand drift report | Click on a drift report row | 5 change sections appear (new, removed, permissions, risk, credentials) |
| TC-16.3 | Change sections collapsible | Click each section header | Section expands/collapses with change details |
| TC-16.4 | Empty sections hidden | Expand drift with no credential changes | Credential changes section not shown or shows "0 changes" |
| TC-16.5 | Link from dashboard | Click "View History" in RecentChanges widget | Navigates to `/drift` page |

---

<a id="phase-17"></a>
## Phase 17: Activity Log

### What It Does
Append-only audit trail stored in `activity_log` table. Records all significant system and user actions (discovery runs, settings changes, report generation, user management). ActivityLog page with filter buttons and metadata display.

### Why It's Needed
Every enterprise security tool needs an audit trail. Compliance frameworks (SOC2 CC7.2, HIPAA) require logging of administrative actions. The activity log provides non-repudiable evidence of who did what and when.

### How It Helps
- Complete audit trail of all system actions
- User attribution (who performed each action)
- Tenant attribution (which tenant context)
- Filterable by action type
- Metadata display for additional context
- Supports compliance evidence for audit controls

### Usage

**API Endpoint:** `GET /api/activity` (supports `limit`, `offset`, `type` filter)

**UI Location:** Activity Log page (`/activity`)

**Logged Actions:** discovery_started, discovery_completed, settings_updated, report_generated, drift_detected, user_created, user_updated, login, logout, remediation_action, anomaly_resolved, soar_executed, and more

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-17.1 | Activity log page loads | Navigate to `/activity` | Timeline of recent actions displayed |
| TC-17.2 | Action type filter | Click filter button (e.g., "Discovery") | Only discovery-related entries shown |
| TC-17.3 | User attribution | Check any activity entry | Shows username of who performed the action |
| TC-17.4 | Settings change logged | Change a setting → check activity log | "settings_updated" entry appears |
| TC-17.5 | Login logged | Login → check activity log | "login" entry with username |
| TC-17.6 | Pagination | Scroll or paginate through entries | More entries load as expected |
| TC-17.7 | Metadata shown | Expand an activity entry | Additional metadata (details, affected items) visible |

---

<a id="phase-18"></a>
## Phase 18: Scheduled Reports & Email Verification

### What It Does
Adds scheduled report delivery (weekly or monthly) via email. Includes a "Test Email" button in Settings to verify email configuration before relying on scheduled delivery.

### Why It's Needed
Executives and compliance officers want regular reports without logging in. Weekly/monthly automated reports ensure stakeholders stay informed about identity security posture without manual effort.

### How It Helps
- Automated weekly or monthly executive reports via email
- Test email button verifies configuration before deployment
- Reduces manual report generation effort
- Ensures stakeholders receive updates on schedule

### Usage

**API Endpoint:** `POST /api/settings/test-email` — sends test email to configured recipient

**UI Location:** Settings page → Section 4 "Scheduled Reports" (weekly/monthly toggle), "Test Email" button

### Configuration

| Setting | Options |
|---------|---------|
| Report frequency | Weekly (Monday 08:00 UTC) or Monthly (1st of month 08:00 UTC) |
| Email recipient | Configured in email settings |

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-18.1 | Test email button | Click "Test Email" in Settings | Test email received at configured address |
| TC-18.2 | Weekly report toggle | Enable weekly reports → wait for Monday | Report email received on Monday morning |
| TC-18.3 | Monthly report toggle | Enable monthly reports | Scheduler job configured for 1st of month |
| TC-18.4 | Report content | Open received email | Contains executive summary with posture score, risk breakdown |

---

<a id="phase-19-20"></a>
## Phase 19–20: Identity Comparison & Bulk Operations

### What It Does
**Identity Comparison:** Side-by-side comparison of two identities showing risk deltas, permission differences, and trend data.
**Bulk Operations:** Select multiple identities and apply remediation actions in bulk.

### Why It's Needed
Auditors frequently need to compare two similar identities to understand why one is higher risk. Bulk operations save time when the same fix applies to multiple identities (e.g., rotating credentials for all stale service principals).

### How It Helps
- Compare any two identities side-by-side
- See which permissions differ between them
- Apply fixes to multiple identities at once
- Reduces repetitive manual work

### Usage

**UI Location:** Identity Comparison (`/identities/compare`), Bulk actions in Identities table

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-19.1 | Compare two identities | Select two identities → compare | Side-by-side view with highlighted differences |
| TC-19.2 | Risk delta shown | Compare high-risk vs. low-risk | Clear visualization of risk score difference |
| TC-19.3 | Permission diff | Compare identities with different roles | Unique permissions highlighted for each |
| TC-20.1 | Bulk select identities | Check multiple identities in table | Bulk action toolbar appears |
| TC-20.2 | Bulk remediation | Select 5 identities → apply bulk action | Remediation actions created for all 5 |

---

<a id="phase-21-22"></a>
## Phase 21–22: Dark Mode & Webhooks

### What It Does
**Dark Mode:** Theme toggle (light/dark) with localStorage persistence and system preference detection.
**Webhooks:** Configure HTTP webhook endpoints to receive real-time notifications when identity changes are detected. Supports HMAC-SHA256 signing, retry logic, and delivery tracking.

### Why It's Needed
Dark mode reduces eye strain for SOC analysts working night shifts. Webhooks enable integration with existing security toolchains (Splunk, Slack, ServiceNow, PagerDuty) for real-time incident response.

### How It Helps
- **Dark Mode:** Comfortable viewing in low-light environments, personal preference
- **Webhooks:** Real-time alerts to SIEM, ticketing, chat systems; automated incident response triggers; delivery tracking for reliability

### Usage

**Webhook API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/webhooks` | List configured webhooks |
| POST | `/api/webhooks` | Create new webhook |
| PUT | `/api/webhooks/<id>` | Update webhook |
| DELETE | `/api/webhooks/<id>` | Delete webhook |
| POST | `/api/webhooks/<id>/test` | Test webhook delivery |
| GET | `/api/webhooks/<id>/deliveries` | View delivery history |

**Webhook Event Types:** `discovery_completed`, `risk_escalation`, `new_identities`, `removed_identities`, `permission_changes`, `credential_changes`, `drift_detected`

**UI Location:** Settings page → Webhooks section, Theme toggle in nav bar

### Configuration

| Setting | Description |
|---------|-------------|
| Webhook URL | HTTPS endpoint to receive payloads |
| Secret | HMAC-SHA256 signing key (sent in `X-Webhook-Signature` header) |
| Events | Which event types to subscribe to |
| Custom Headers | Additional HTTP headers to send |

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-21.1 | Dark mode toggle | Click theme toggle | UI switches to dark theme, persists on refresh |
| TC-21.2 | System preference | Set OS to dark mode → open app | App defaults to dark mode |
| TC-22.1 | Create webhook | Settings → Webhooks → Add → enter URL and events | Webhook created and listed |
| TC-22.2 | Test webhook | Click "Test" on a webhook | Test payload delivered, 200 status in delivery history |
| TC-22.3 | Webhook signature | Receive test payload on endpoint | `X-Webhook-Signature` header contains valid HMAC-SHA256 |
| TC-22.4 | Delivery tracking | View webhook delivery history | Shows timestamp, HTTP status, response for each delivery |
| TC-22.5 | Webhook on discovery | Trigger discovery with webhook subscribed to `discovery_completed` | Webhook receives payload after run completes |
| TC-22.6 | Failed delivery logged | Set webhook URL to invalid endpoint → trigger event | Delivery logged with failed status |

---

<a id="phase-23-25"></a>
## Phase 23–25: Custom Risk Rules & Notifications

### What It Does
**Custom Risk Rules:** User-defined rules that adjust risk scores or override risk levels based on identity attributes. Supports 13+ fields, 8 operators, points-based or level-override modes.
**Notifications:** Per-notification-type email controls (granular toggle for each change type).

### Why It's Needed
Default risk scoring can't account for organization-specific context. A "Contributor" role might be low-risk generally but critical in a production subscription. Custom rules let security teams encode their institutional knowledge into the scoring model.

### How It Helps
- Encode organization-specific risk knowledge
- Override default scores for known exceptions
- Preview rule impact before applying
- Layer custom rules on top of default scoring

### Usage

**API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/risk-rules` | List custom risk rules |
| POST | `/api/risk-rules` | Create rule |
| PUT | `/api/risk-rules/<id>` | Update rule |
| DELETE | `/api/risk-rules/<id>` | Delete rule |
| POST | `/api/risk-rules/preview` | Preview rule impact on identities |

**UI Location:** Settings page → Risk Rules section

### Configuration

| Field | Description | Examples |
|-------|-------------|---------|
| `name` | Rule name | "Flag production contributors" |
| `conditions` | Matching criteria | `[{field: "scope", operator: "contains", value: "/subscriptions/prod-"}]` |
| `action` | What to do on match | `{type: "adjust_points", value: 30}` or `{type: "set_level", value: "critical"}` |
| `enabled` | Active/inactive | true/false |

**Supported Operators:** eq, neq, gt, lt, gte, lte, in, contains, not_contains, regex

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-23.1 | Create risk rule | Settings → Risk Rules → Add rule | Rule created with conditions and action |
| TC-23.2 | Preview rule impact | Click "Preview" | Shows which identities would be affected and score changes |
| TC-23.3 | Rule adjusts score | Create +50 point rule matching an identity → run discovery | Identity's risk score increases by 50 |
| TC-23.4 | Level override | Create "set critical" rule → run discovery | Matching identity becomes critical regardless of score |
| TC-23.5 | Disable rule | Toggle rule off | Rule no longer applied on next run |
| TC-23.6 | Delete rule | Delete a rule → run discovery | Identity score returns to default calculation |

---

<a id="phase-26-29"></a>
## Phase 26–29: In-App Notification System

### What It Does
In-app notification system that generates notifications for discovery events (new identities, risk escalations, permission changes, credential issues). Aggregates high-volume alerts to prevent notification spam.

### Why It's Needed
Not all users have access to email alerts. In-app notifications provide real-time awareness within the application itself, with severity levels and smart aggregation to prevent alert fatigue.

### How It Helps
- Real-time in-app alerts for security events
- Severity levels (info, low, medium, high) for prioritization
- Smart aggregation (>5 items grouped into summary notification)
- Auto-cleanup of old notifications (90+ days)

### Usage

**API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/notifications` | List notifications (filterable) |
| GET | `/api/notifications/stats` | Notification counts by severity |
| PATCH | `/api/notifications/<id>` | Mark as read |
| POST | `/api/notifications/mark-all-read` | Mark all as read |
| DELETE | `/api/notifications/<id>` | Delete notification |

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-26.1 | Notifications generated | Trigger discovery | In-app notifications created for changes |
| TC-26.2 | Severity levels | Check notification list | Appropriate severity assigned (high for risk escalation, info for discovery complete) |
| TC-26.3 | Aggregation | Trigger discovery with 10+ new identities | Aggregated into single summary notification |
| TC-26.4 | Mark as read | Click "Mark read" on notification | Notification marked, unread count decreases |
| TC-26.5 | Mark all read | Click "Mark all read" | All notifications marked as read |

---

<a id="phase-30"></a>
## Phase 30: Notification Center

### What It Does
Dedicated Notification Center page with bell badge in navigation, filterable by severity and category. Shows unread count badge on the bell icon.

### Why It's Needed
Users need a centralized inbox for all security notifications rather than scattered alerts. The bell badge provides persistent visibility of unread notifications.

### How It Helps
- Bell icon with unread count in navigation bar
- Dedicated page for notification management
- Filter by severity (info/low/medium/high) and category
- Quick actions (mark read, delete)

### Usage
**UI Location:** Bell icon in navigation → `/notifications`

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-30.1 | Bell badge shows count | Login with unread notifications | Bell icon shows unread count |
| TC-30.2 | Notification center page | Click bell icon | `/notifications` page with full list |
| TC-30.3 | Filter by severity | Select "High" filter | Only high-severity notifications shown |
| TC-30.4 | Badge updates | Mark all read | Bell badge count goes to 0 |

---

<a id="phase-31"></a>
## Phase 31: RBAC & Authentication

### What It Does
JWT-based authentication system with 3 roles (admin, auditor, viewer). Login page, protected routes, AuthContext with global fetch interceptor that auto-attaches Bearer tokens. User management in Settings.

### Why It's Needed
Multi-user access control is essential for enterprise deployment. Different team members need different access levels — admins configure the system, auditors investigate, viewers monitor.

### How It Helps
- Secure login with bcrypt password hashing
- JWT access + refresh token flow
- Role-based page and API access control
- Global fetch interceptor handles token lifecycle automatically
- User management for admins

### Usage

**API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Authenticate user |
| POST | `/api/auth/refresh` | Refresh access token |
| POST | `/api/auth/logout` | Invalidate session |
| GET | `/api/auth/me` | Current user info |
| GET/POST | `/api/users` | List/create users (admin only) |
| PUT/DELETE | `/api/users/<id>` | Update/delete user (admin only) |

**UI Location:** Login page (`/login`), User Management in Settings

### Configuration

| Setting | Environment Variable | Default |
|---------|---------------------|---------|
| Admin username | `ADMIN_USERNAME` | admin |
| Admin password | `ADMIN_PASSWORD` | changeme |
| JWT secret | `JWT_SECRET_KEY` | Auto-generated |

**Roles:**
| Role | Capabilities |
|------|-------------|
| admin | Full access: configuration, user management, all operations |
| auditor | Read access + remediation actions, no configuration |
| viewer | Read-only access to all data pages |

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-31.1 | Login with valid credentials | Enter admin/changeme → submit | Redirected to Overview, user info in nav |
| TC-31.2 | Login with invalid credentials | Enter wrong password | Error message, no redirect |
| TC-31.3 | Token refresh | Wait for access token expiry | Automatic refresh, no user disruption |
| TC-31.4 | Logout | Click logout | Redirected to login, token invalidated |
| TC-31.5 | Admin access to Settings | Login as admin → navigate to `/settings` | Full settings page accessible |
| TC-31.6 | Viewer blocked from Settings | Login as viewer → navigate to `/settings` | Access denied or redirect |
| TC-31.7 | Create user | Settings → Users → Add → fill form | New user created with assigned role |
| TC-31.8 | Delete user | Settings → Users → Delete | User removed, can no longer login |
| TC-31.9 | Role enforcement on API | Call admin-only API with viewer token | Returns 403 Forbidden |
| TC-31.10 | Password change | PUT `/api/auth/password` | Password updated, old password no longer works |

---

<a id="phase-32-33"></a>
## Phase 32–33: Compliance Frameworks & Export Pipeline

### What It Does
**Compliance Frameworks:** 6 compliance frameworks (SOC2, HIPAA, PCI-DSS, NIST 800-53, CIS Azure Foundations, ISO 27001) with 29 total controls evaluated against computed metrics.
**Export Pipeline:** Multi-format data export (CSV, JSON, PDF) with 20-column identity exports, compliance exports, and drift exports.

### Why It's Needed
Organizations must demonstrate compliance with regulatory frameworks. Automated compliance evaluation against real identity data eliminates manual control testing. Export capability supports evidence collection for external auditors.

### How It Helps
- Automated compliance scoring against 6 frameworks
- Pass/warn/fail status per control with configurable thresholds
- Enable/disable individual frameworks
- Export identity data in CSV, JSON, or PDF format
- Pre-defined column sets for common export needs

### Usage

**Compliance API:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/compliance/frameworks` | List available frameworks |
| PATCH | `/api/compliance/frameworks/<id>` | Enable/disable framework |
| GET | `/api/dashboard/compliance` | Compliance scorecard summary |

**Export API:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/export/<type>` | Export data (CSV, PDF, JSON) |

**UI Location:** Compliance page (`/compliance`), Exports page (`/exports`), CSV/JSON export buttons in Identities table

### Configuration
Frameworks can be individually enabled/disabled via the API or Settings page.

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-32.1 | Compliance page loads | Navigate to `/compliance` | All enabled frameworks shown with scores |
| TC-32.2 | Framework scores | Check each framework | Score rings show pass percentage (0-100%) |
| TC-32.3 | Control status | Expand a framework | Individual controls show pass/warn/fail with reason |
| TC-32.4 | Enable/disable framework | Disable a framework → refresh | Framework no longer shown in compliance view |
| TC-33.1 | CSV export from Identities | Click CSV export button | CSV file downloads with 20 columns |
| TC-33.2 | JSON export | Click JSON export button | JSON file downloads with full identity data |
| TC-33.3 | Export from Exports page | Navigate to `/exports` → select format | Export file downloads |

---

<a id="phase-34-35"></a>
## Phase 34–35: Saved Views & Identity Lifecycle

### What It Does
**Saved Views:** Save and recall custom identity table filters, column selections, and sort orders. Set a default view.
**Identity Lifecycle:** Track identity state transitions (new → active → dormant → deprovisioned) with lifecycle dashboard widget.

### Why It's Needed
Analysts repeatedly apply the same filter combinations (e.g., "critical risk service principals in production"). Saved views eliminate repetitive filter setup. Lifecycle tracking reveals the full journey of an identity from creation to deprovisioning.

### How It Helps
- Save complex filter combinations for one-click reuse
- Share views across team members
- Set default view for consistent starting point
- Track identity state transitions over time
- Identify identities stuck in risky lifecycle states

### Usage

**Saved Views API:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/saved-views` | List saved views |
| POST | `/api/saved-views` | Create view |
| PUT | `/api/saved-views/<id>` | Update view |
| DELETE | `/api/saved-views/<id>` | Delete view |
| POST | `/api/saved-views/<id>/default` | Set as default |

**Lifecycle API:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/identities/<id>/lifecycle` | Identity lifecycle status and transitions |

**UI Location:** Identities page → saved views dropdown, Identity Detail → lifecycle indicators

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-34.1 | Save a view | Apply filters → click "Save View" → name it | View saved and appears in dropdown |
| TC-34.2 | Load saved view | Select saved view from dropdown | Filters, columns, sort applied automatically |
| TC-34.3 | Set default view | Mark a view as default | View auto-loads when visiting Identities page |
| TC-34.4 | Delete view | Delete a saved view | View removed from dropdown |
| TC-35.1 | Lifecycle status shown | Check identity detail | Shows current lifecycle state |
| TC-35.2 | Lifecycle transitions | Check identity with state changes | Shows transition history (new → active → dormant) |

---

<a id="phase-36-37"></a>
## Phase 36–37: Access Reviews & Role Mining

### What It Does
**Access Reviews:** Certification campaigns for reviewing identity access. Reviewers can approve, revoke, or flag each access item. Campaigns have deadlines and progress tracking.
**Role Mining:** Analyzes role usage patterns to identify unused roles, redundant assignments, over-privileged identities, and suggests role consolidation.

### Why It's Needed
Periodic access reviews are mandated by SOC2 (CC6.1), HIPAA, and other frameworks. Role mining reduces privilege sprawl by identifying optimization opportunities. Both are critical for maintaining least-privilege posture.

### How It Helps
- **Access Reviews:** Structured certification workflow, deadline management, audit evidence
- **Role Mining:** Identifies unused/redundant roles, suggests consolidation, reduces attack surface

### Usage

**Access Review API:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/api/access-reviews` | List/create campaigns |
| GET | `/api/access-reviews/<id>` | Campaign detail |
| PATCH | `/api/access-reviews/<id>/reviews/<rid>` | Update review decision |
| POST | `/api/access-reviews/<id>/reviews/bulk` | Bulk review decisions |

**Role Mining API:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/role-mining` | Role optimization analysis |
| GET | `/api/dashboard/role-usage` | Role usage analytics |

**UI Location:** Access Reviews page (`/access-reviews`), Role Mining page (`/role-mining`)

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-36.1 | Create access review | Access Reviews → Create Campaign | Campaign created with review items for selected identities |
| TC-36.2 | Review access item | Open campaign → approve/revoke/flag items | Decision recorded with timestamp |
| TC-36.3 | Bulk review | Select multiple items → bulk approve | All selected items approved at once |
| TC-36.4 | Campaign progress | Check campaign overview | Progress bar shows % reviewed |
| TC-37.1 | Role mining page | Navigate to `/role-mining` | Shows unused, redundant, orphaned, over-privileged roles |
| TC-37.2 | Role usage chart | Check dashboard role usage widget | Active vs. inactive role distribution |
| TC-37.3 | Role consolidation suggestions | Check role mining results | Suggests which roles can be merged or removed |

---

<a id="phase-38"></a>
## Phase 38: Identity Groups

### What It Does
Custom grouping of identities for organized management. Create groups, add/remove members, compare groups, and view group-level analytics.

### Why It's Needed
Identities often need to be managed in logical groups (by team, application, environment). Groups enable batch analysis, comparison, and coordinated remediation.

### How It Helps
- Organize identities by team, application, or purpose
- Batch operations on group members
- Compare groups for permission drift
- Group-level risk aggregation

### Usage

**API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/api/groups` | List/create groups |
| GET/PUT/DELETE | `/api/groups/<id>` | CRUD operations |
| POST | `/api/groups/<id>/members` | Add members |
| DELETE | `/api/groups/<id>/members` | Remove members |
| GET | `/api/groups/compare` | Compare two groups |
| GET | `/api/identities/<id>/groups` | Groups for an identity |

**UI Location:** Identity Groups page (`/groups`)

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-38.1 | Create group | Groups → Create → name + description | Group created |
| TC-38.2 | Add members | Select identities → add to group | Members listed in group detail |
| TC-38.3 | Remove member | Click remove on a member | Member removed from group |
| TC-38.4 | Compare groups | Select two groups → compare | Side-by-side comparison with differences highlighted |
| TC-38.5 | Identity shows groups | View identity detail | Shows which groups this identity belongs to |

---

<a id="phase-39"></a>
## Phase 39: Advanced Query Builder

### What It Does
Visual query builder for complex identity filtering. Supports 28 queryable fields, 10 operators, AND/OR condition groups. Integrates with saved views. Toggle between simple filter mode and advanced query mode.

### Why It's Needed
Simple text search and dropdown filters can't handle complex queries like "Show all service principals in production with risk score > 50 AND more than 2 credentials AND no owner." Advanced query builder enables complex, precise identity searches.

### How It Helps
- Build complex multi-condition queries visually
- AND/OR group logic for flexible filtering
- 28 queryable fields covering all identity attributes
- Preview results before saving
- Integrates with saved views for reuse

### Usage

**API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/identities/query` | Execute advanced query |
| GET | `/api/identities/query/fields` | Available fields, operators, value suggestions |

**UI Location:** Identities page → "Advanced" toggle → QueryBuilder component

### Configuration
**Query Field Allowlist (`QUERY_FIELD_MAP`):** 25 direct columns + 3 computed subquery fields — all use `i.` alias to prevent SQL injection.

**Supported Operators:** `eq`, `neq`, `gt`, `lt`, `gte`, `lte`, `in`, `contains`, `not_contains`, `is_null`

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-39.1 | Simple to advanced toggle | Click "Advanced" in Identities page | QueryBuilder UI appears |
| TC-39.2 | Single condition query | Add condition: risk_score > 50 → execute | Only identities with risk_score > 50 returned |
| TC-39.3 | AND conditions | Add: risk_score > 50 AND identity_category = service_principal | Only matching service principals returned |
| TC-39.4 | OR groups | Add two groups with OR logic | Identities matching either group returned |
| TC-39.5 | Field suggestions | Click field dropdown | All 28 queryable fields listed with types |
| TC-39.6 | Operator validation | Select a numeric field | Only numeric operators shown (gt, lt, eq, etc.) |
| TC-39.7 | Save query as view | Execute query → save as view | Saved view stores query conditions |
| TC-39.8 | SQL injection prevented | Try field value: `'; DROP TABLE identities; --` | Query executes safely with parameterized values |

---

<a id="phase-40"></a>
## Phase 40: Anomaly Detection

### What It Does
Behavioral anomaly detection engine that identifies 6 types of suspicious identity behavior: permission escalation, risk score spikes, dormant reactivation, credential surges, off-hours PIM activation, and excessive PIM usage. Runs automatically after each discovery. Dashboard widget shows top unresolved anomalies.

### Why It's Needed
Traditional security tools detect known threats, but anomaly detection catches unusual patterns that might indicate compromise. A dormant service principal suddenly gaining Global Admin is suspicious even if the individual actions are authorized.

### How It Helps
- Detects 6 anomaly types automatically after each discovery
- Severity classification (critical, high, medium, low)
- Dashboard widget for immediate awareness
- Identity-specific anomaly view
- Resolution workflow (acknowledge + resolve)

### Usage

**API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/anomalies` | List anomalies (filters: type, severity, identity_id, resolved, run_id) |
| GET | `/api/anomalies/stats` | Summary (total, unresolved, by_type, by_severity) |
| GET | `/api/anomalies/<id>` | Single anomaly detail |
| PATCH | `/api/anomalies/<id>` | Resolve anomaly (admin/auditor) |
| GET | `/api/identities/<id>/anomalies` | Identity-specific anomalies |
| GET | `/api/dashboard/anomalies` | Top unresolved for dashboard widget |

**UI Location:** Dashboard → AnomalyAlerts widget, Identity Detail → Anomalies tab

### Configuration
Anomaly detection thresholds are set in the `AnomalyDetector` engine:
- PIM business hours: configurable start/end hour
- Risk spike threshold: minimum score delta to trigger
- PIM frequency threshold: activations per period

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-40.1 | Anomalies generated after discovery | Trigger discovery run | Anomalies detected and stored |
| TC-40.2 | Anomaly list | GET `/api/anomalies` | Returns list with type, severity, identity info |
| TC-40.3 | Filter by type | GET `/api/anomalies?type=permission_escalation` | Only permission escalation anomalies returned |
| TC-40.4 | Filter by severity | GET `/api/anomalies?severity=critical` | Only critical anomalies returned |
| TC-40.5 | Anomaly stats | GET `/api/anomalies/stats` | Total, unresolved counts, breakdowns by type and severity |
| TC-40.6 | Resolve anomaly | PATCH `/api/anomalies/<id>` with resolution | Anomaly marked as resolved |
| TC-40.7 | Dashboard widget | Navigate to `/dashboard` | AnomalyAlerts widget shows top unresolved anomalies |
| TC-40.8 | Identity anomalies | Navigate to identity → Anomalies tab | Shows anomalies specific to that identity |
| TC-40.9 | Viewer cannot resolve | Login as viewer → try PATCH | Returns 403 Forbidden |

---

<a id="phase-41"></a>
## Phase 41: Risk Trend Analytics

### What It Does
Historical risk trend tracking with enhanced `/api/trends` endpoint (posture_score, avg_risk_score), risk velocity API (inflow/outflow/retention of risk categories), per-identity risk score history, batch sparkline data, RiskVelocityChart dashboard widget, sparkline column in Identities table, and Risk Score Trajectory chart in IdentityDetail.

### Why It's Needed
Point-in-time risk scores don't tell the full story. Trending reveals whether your security posture is improving or degrading. Risk velocity shows the rate of change — critical for resource allocation decisions.

### How It Helps
- Track posture score over time (improving or declining?)
- Risk velocity shows rate of identities entering/leaving risk categories
- Per-identity sparklines in table for quick visual trend assessment
- Detailed risk score trajectory chart in identity detail
- Data-driven decisions on where to focus remediation effort

### Usage

**API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/trends` | Posture score + avg risk trend data |
| GET | `/api/trends/velocity` | Risk category inflow/outflow/retention |
| GET | `/api/identities/<id>/risk-history` | Per-identity risk score over time |
| POST | `/api/identities/risk-history/batch` | Batch sparkline data for table |

**UI Location:** Dashboard → RiskVelocityChart widget, Identities table → Trend sparkline column, Identity Detail → Overview → Risk Score Trajectory chart

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-41.1 | Trend data available | GET `/api/trends` | Returns array of posture scores over time |
| TC-41.2 | Risk velocity | GET `/api/trends/velocity` | Shows inflow/outflow counts per risk category |
| TC-41.3 | Sparkline in table | Navigate to `/identities` | Trend sparkline column shows mini chart per identity |
| TC-41.4 | Risk trajectory chart | Navigate to identity detail → Overview | Risk Score Trajectory chart shows score over time |
| TC-41.5 | Velocity widget on dashboard | Navigate to `/dashboard` | RiskVelocityChart shows risk flow visualization |
| TC-41.6 | Batch sparkline API | POST `/api/identities/risk-history/batch` with identity IDs | Returns sparkline data for all requested identities |

---

<a id="phase-42"></a>
## Phase 42: API Key Management

### What It Does
API key authentication for programmatic access. Keys have `ag_` prefix, are SHA-256 hashed in storage, support role-scoping, and track usage (last used timestamp, use count). Dual authentication: `X-API-Key` header or `Bearer ag_...` token.

### Why It's Needed
CI/CD pipelines, scripts, and third-party integrations need programmatic access without user credentials. API keys provide long-lived, role-scoped authentication suitable for automation.

### How It Helps
- Programmatic access for scripts and integrations
- Role-scoped keys (admin, auditor, viewer) limit blast radius
- Usage tracking reveals which keys are active
- Keys can be enabled/disabled without deletion
- One-time key display ensures security (can't retrieve key after creation)

### Usage

**API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/api-keys` | List API keys (admin only) |
| POST | `/api/api-keys` | Create key (returns raw key once) |
| PUT | `/api/api-keys/<id>` | Update key (name, role, enabled) |
| DELETE | `/api/api-keys/<id>` | Delete key |

**Authentication:** Include key in requests as:
- Header: `X-API-Key: ag_abc123...`
- Bearer: `Authorization: Bearer ag_abc123...`

**UI Location:** Settings page → API Keys section

### Configuration

| Field | Description |
|-------|-------------|
| Name | Descriptive name for the key |
| Role | Permission scope (admin/auditor/viewer) |
| Enabled | Active/inactive toggle |

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-42.1 | Create API key | Settings → API Keys → Create | Key created, raw key displayed once in modal |
| TC-42.2 | Key displayed only once | Close modal, return to API Keys | Key shows masked (last 8 chars only) |
| TC-42.3 | Authenticate with key | GET `/api/identities` with `X-API-Key: ag_xxx` | Request succeeds, returns identity data |
| TC-42.4 | Bearer token auth | GET `/api/identities` with `Authorization: Bearer ag_xxx` | Request succeeds |
| TC-42.5 | Role scoping | Create viewer key → POST `/api/users` | Returns 403 (viewer can't create users) |
| TC-42.6 | Disable key | Toggle key off → make request with key | Returns 401 |
| TC-42.7 | Usage tracking | Make requests with key → check key list | `last_used` and `use_count` updated |
| TC-42.8 | Delete key | Delete key → make request | Returns 401 |
| TC-42.9 | Non-admin cannot manage | Login as viewer → GET `/api/api-keys` | Returns 403 |

---

<a id="phase-43"></a>
## Phase 43: SOAR Integration

### What It Does
Security Orchestration, Automation, and Response (SOAR) engine. Define playbooks with trigger conditions and automated actions. Supports 4 trigger types (anomaly, risk_escalation, drift, new_identity), 4 action types (webhook, create_ticket, send_notification, tag_for_review), and 7 integration targets (ServiceNow, Jira, Slack, PagerDuty, Teams, custom webhook, internal).

### Why It's Needed
Manual response to every security alert doesn't scale. SOAR automation enables predefined responses to common scenarios — automatically creating Jira tickets for risk escalations, sending Slack alerts for anomalies, or tagging identities for review when drift is detected.

### How It Helps
- Automated incident response workflows
- Reduce mean time to respond (MTTR)
- Consistent handling of common scenarios
- Integration with existing security toolchain
- Cooldown management prevents alert fatigue
- Dry-run testing before enabling

### Usage

**API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/api/soar/playbooks` | List/create playbooks |
| PUT/DELETE | `/api/soar/playbooks/<id>` | Update/delete playbook |
| POST | `/api/soar/playbooks/<id>/test` | Dry-run test with mock event |
| GET | `/api/soar/actions` | Action execution history |
| GET | `/api/soar/actions/stats` | Action statistics |
| POST | `/api/soar/execute` | Manual trigger (playbook_id + optional event) |

**UI Location:** Settings page → Section 10 (SOAR Playbooks), Dashboard → SOARActivity widget

### Configuration

| Field | Description | Options |
|-------|-------------|---------|
| `trigger_type` | What triggers the playbook | anomaly, risk_escalation, drift, new_identity |
| `conditions` | Matching criteria | JSON conditions (e.g., `{severity: "critical"}`) |
| `action_type` | What action to take | webhook, create_ticket, send_notification, tag_for_review |
| `integration` | Target system | servicenow, jira, slack, pagerduty, teams, webhook, internal |
| `cooldown_minutes` | Minimum time between triggers | Integer (prevents spam) |
| `enabled` | Active/inactive | true/false |

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-43.1 | Create SOAR playbook | Settings → SOAR → Create → configure trigger + action | Playbook created and listed |
| TC-43.2 | Test playbook (dry-run) | Click "Test" on playbook | Mock event generated, action simulated, result shown |
| TC-43.3 | Automatic trigger | Create anomaly trigger → run discovery → anomaly detected | Action auto-executed, logged in actions history |
| TC-43.4 | Webhook action | Configure webhook action → trigger | HTTP POST sent to webhook URL with event data |
| TC-43.5 | Cooldown enforcement | Trigger same playbook twice within cooldown | Second trigger skipped, cooldown logged |
| TC-43.6 | Action history | GET `/api/soar/actions` | Shows all executed actions with status |
| TC-43.7 | Action stats | GET `/api/soar/actions/stats` | Total, success/failed counts, by_integration breakdown |
| TC-43.8 | Manual execute | POST `/api/soar/execute` with playbook_id | Action executed manually |
| TC-43.9 | Dashboard widget | Navigate to `/dashboard` | SOARActivity widget shows recent actions |
| TC-43.10 | Disable playbook | Toggle playbook off → trigger condition | No action executed |

---

<a id="phase-44"></a>
## Phase 44: Dashboard Customization

### What It Does
User-level dashboard widget customization. Widget registry with 16 widgets in 4 groups (stats, charts, monitoring, compliance). Drag-and-drop reordering via CustomizePanel. Preferences persisted per user.

### Why It's Needed
Different roles need different dashboard views. A CISO wants compliance and posture score. A SOC analyst wants anomalies and SOAR activity. Dashboard customization lets each user configure their optimal view.

### How It Helps
- Show/hide individual widgets
- Drag-and-drop reordering
- Per-user preferences persist across sessions
- Reset to defaults option
- Widget grouping for organized management

### Usage

**API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard/preferences` | Get user's widget preferences |
| PUT | `/api/dashboard/preferences` | Save widget order and visibility |
| DELETE | `/api/dashboard/preferences` | Reset to defaults |

**UI Location:** Dashboard page → "Customize" button → CustomizePanel sidebar

### Configuration
**Widget Registry (16 widgets):**

| Group | Widgets |
|-------|---------|
| Stats | PostureScore, QuickActions, RecentChanges, CloudContextBanner |
| Charts | RiskHeatMap, RiskDonutChart, RiskTrendChart, RiskVelocityChart, RoleUsageChart |
| Monitoring | CredentialHealth, AnomalyAlerts, SOARActivity, RemediationProgress |
| Compliance | ComplianceScorecard, ConditionalAccessCard |

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-44.1 | Customize panel opens | Click "Customize" on dashboard | Side panel shows all widgets with toggles |
| TC-44.2 | Hide widget | Toggle off RiskHeatMap → save | Heat map no longer visible on dashboard |
| TC-44.3 | Reorder widgets | Drag PostureScore to top → save | PostureScore appears first on dashboard |
| TC-44.4 | Preferences persist | Customize → refresh page | Same customization retained |
| TC-44.5 | Reset to defaults | Click "Reset to Defaults" | All widgets shown in original order |
| TC-44.6 | Per-user preferences | Login as different user | Different dashboard layout |

---

<a id="phase-45"></a>
## Phase 45: Multi-Tenant Foundation

### What It Does
Multi-tenant architecture with `tenants` table, tenant_id on users/discovery_runs/settings, JWT tenant context, superadmin role, and tenant CRUD API. Data isolation between tenants.

### Why It's Needed
MSPs (Managed Security Providers) and large enterprises need to manage multiple client tenants from a single AuditGraph instance. Multi-tenancy ensures data isolation while enabling centralized administration.

### How It Helps
- Manage multiple client tenants from one instance
- Data isolation between tenants
- Superadmin can administer all tenants
- Per-tenant settings and configuration
- Cross-tenant analytics for MSPs

### Usage

**API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/tenants` | List tenants (superadmin only) |
| POST | `/api/tenants` | Create tenant |
| PUT | `/api/tenants/<id>` | Update tenant |
| DELETE | `/api/tenants/<id>` | Delete tenant |
| GET | `/api/tenant` | Get current tenant context |
| GET | `/api/analytics/tenants` | Cross-tenant analytics |

**UI Location:** Settings page → Tenant Management section (superadmin only)

### Configuration
- JWT includes `tenant_id`, `tenant_name`, `is_superadmin`
- `_tenant_id()` helper auto-extracts tenant from JWT
- Default tenant created on first startup ("Default Organization")

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-45.1 | Tenant list (superadmin) | Login as superadmin → GET `/api/tenants` | Returns list of all tenants |
| TC-45.2 | Create tenant | POST `/api/tenants` with name | New tenant created |
| TC-45.3 | Tenant isolation | Create data in tenant A → login to tenant B | Tenant B cannot see tenant A's data |
| TC-45.4 | Non-superadmin blocked | Login as regular admin → GET `/api/tenants` | Returns 403 |
| TC-45.5 | Default tenant exists | Check tenants list | "Default Organization" exists |

---

<a id="phase-46"></a>
## Phase 46: Tenant User Management

### What It Does
Superadmin tenant switching via `X-Tenant-Id` header, TenantSwitcher dropdown in navigation, tenant-scoped activity logging with user_id/tenant_id columns, tenant-scoped user lists, and cross-tenant guards.

### Why It's Needed
Superadmins managing multiple tenants need seamless switching without re-authentication. Activity logs must track which tenant context each action occurred in for audit purposes.

### How It Helps
- Switch between tenants via dropdown without logging out
- All actions logged with tenant context
- Users scoped to their assigned tenant
- Cross-tenant operations guarded for safety

### Usage

**Header:** `X-Tenant-Id: <tenant_id>` — superadmin can override tenant context

**UI Location:** TenantSwitcher dropdown in navigation bar (visible to superadmins only)

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-46.1 | Tenant switcher visible | Login as superadmin | TenantSwitcher dropdown appears in nav |
| TC-46.2 | Switch tenant | Select different tenant from dropdown | Dashboard shows data for selected tenant |
| TC-46.3 | Activity log includes tenant | Perform action → check activity log | Entry shows tenant_id and tenant_name |
| TC-46.4 | Non-superadmin no switcher | Login as regular admin | No TenantSwitcher visible |
| TC-46.5 | X-Tenant-Id header works | Superadmin sends API request with header | Response scoped to specified tenant |
| TC-46.6 | Cross-tenant guard | Non-superadmin sends X-Tenant-Id header | Header ignored, own tenant used |

---

<a id="phase-47"></a>
## Phase 47: Identity Lifecycle Tracking

### What It Does
Tracks identity lifecycle states (new, active, dormant, deprovisioned) and state transitions over time. Provides lifecycle dashboard widget and lifecycle tab in IdentityDetail showing state history.

### Why It's Needed
Understanding an identity's journey from creation through active use to dormancy helps identify abandoned or orphaned identities that should be deprovisioned. Lifecycle tracking is required by most compliance frameworks.

### How It Helps
- Visualize identity state transitions over time
- Identify identities stuck in risky states (e.g., dormant but privileged)
- Support compliance evidence for identity lifecycle management controls
- Dashboard widget for lifecycle state distribution

### Usage

**API Endpoint:** `GET /api/identities/<id>/lifecycle`

**UI Location:** Identity Detail → Lifecycle tab, Dashboard → Lifecycle widget

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-47.1 | Lifecycle tab loads | Navigate to identity → Lifecycle tab | Shows current state and transition history |
| TC-47.2 | State transitions shown | Check identity with multiple runs | Timeline of state changes (new → active → dormant) |
| TC-47.3 | Lifecycle widget | Navigate to `/dashboard` | Widget shows distribution of lifecycle states |
| TC-47.4 | Dormant identity flagged | Check dormant identity | Lifecycle shows transition to dormant with timestamp |

---

<a id="phase-48"></a>
## Phase 48: Access Review Campaigns

### What It Does
Full access review certification workflow with `access_review_campaigns` and `campaign_reviews` tables. Create campaigns targeting specific identities or groups, assign reviewers, set deadlines, and track approve/revoke/flag decisions.

### Why It's Needed
SOC2 CC6.1 and HIPAA require periodic access reviews. Access review campaigns formalize this process with deadlines, reviewer assignment, and decision tracking — providing auditable evidence of compliance.

### How It Helps
- Structured certification workflow
- Reviewer assignment and deadline tracking
- Approve/revoke/flag decision options per access item
- Bulk review capability for efficiency
- Campaign progress tracking
- Audit trail for compliance evidence

### Usage

**API Endpoints:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/api/access-reviews` | List/create campaigns |
| GET | `/api/access-reviews/<id>` | Campaign detail with review items |
| PUT | `/api/access-reviews/<id>` | Update campaign |
| DELETE | `/api/access-reviews/<id>` | Delete campaign |
| PATCH | `/api/access-reviews/<id>/reviews/<rid>` | Update review decision |
| POST | `/api/access-reviews/<id>/reviews/bulk` | Bulk review decisions |

**UI Location:** Access Reviews page (`/access-reviews`)

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-48.1 | Create campaign | Access Reviews → Create → select scope + reviewers + deadline | Campaign created with review items |
| TC-48.2 | Review items listed | Open campaign detail | All access items for targeted identities listed |
| TC-48.3 | Approve access | Click "Approve" on a review item | Decision recorded with reviewer name and timestamp |
| TC-48.4 | Revoke access | Click "Revoke" on a review item | Item marked for revocation |
| TC-48.5 | Flag for review | Click "Flag" on suspicious item | Item flagged for further investigation |
| TC-48.6 | Bulk approve | Select 10 items → bulk approve | All 10 items approved at once |
| TC-48.7 | Campaign progress | Check campaign overview | Progress bar shows reviewed/total percentage |
| TC-48.8 | Past-deadline warning | Create campaign with past deadline | Campaign shows overdue indicator |

---

<a id="phase-49"></a>
## Phase 49: Identity Risk Simulation

### What It Does
"What If" analysis tab in IdentityDetail. Simulate the impact of adding or removing roles and permissions on an identity's risk score. Shows instant risk score delta, factor-by-factor comparison, and risk level change.

### Why It's Needed
Before making access changes, security teams need to understand the impact. "What if we remove Global Admin?" or "What if we add Contributor to production?" — simulation answers these questions without making real changes.

### How It Helps
- Preview risk score impact before making changes
- Toggle existing roles/permissions on/off to see delta
- Add hypothetical new roles to see impact
- Side-by-side comparison (current vs. simulated)
- Factor-by-factor breakdown (which scoring components change)

### Usage

**API Endpoint:** `POST /api/identities/<id>/simulate`

**Request Body:**
```json
{
  "removed_roles": ["Global Administrator"],
  "added_roles": ["Directory Readers"],
  "removed_permissions": ["RoleManagement.ReadWrite.Directory"],
  "added_permissions": []
}
```

**Response:**
```json
{
  "current_score": 85,
  "simulated_score": 35,
  "delta": -50,
  "current_level": "critical",
  "simulated_level": "medium",
  "current_reasons": [...],
  "simulated_reasons": [...]
}
```

**UI Location:** Identity Detail → "What If" tab

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-49.1 | What If tab loads | Navigate to identity → What If tab | Shows current roles/permissions with checkboxes |
| TC-49.2 | Remove role simulation | Uncheck "Global Administrator" → click Simulate | Score drops, delta shown in green |
| TC-49.3 | Add role simulation | Add "Owner" role → click Simulate | Score increases, delta shown in red |
| TC-49.4 | Empty simulation | Click Simulate with no changes | Delta is 0, scores match |
| TC-49.5 | Reset simulation | Click "Reset" | All checkboxes restored to original state |
| TC-49.6 | Score comparison | Run simulation | Side-by-side current vs. simulated with color coding |
| TC-49.7 | Reason comparison | Run simulation | Shows which risk factors change |
| TC-49.8 | API direct test | POST to `/api/identities/<id>/simulate` with removed_roles | Returns current_score, simulated_score, delta |
| TC-49.9 | Unauthenticated blocked | POST without token | Returns 401 |

---

<a id="phase-50"></a>
## Phase 50: Compliance Gap Analysis

### What It Does
Enhanced compliance page that shows evidence identities per failing control and matched remediation playbooks. Each non-passing control is expandable to reveal the specific identities causing the failure and recommended remediation steps. Supports CSV export.

### Why It's Needed
Knowing a compliance control fails isn't enough — auditors need to know *which identities* cause the failure and *what to do about it*. Gap analysis bridges compliance status to actionable remediation.

### How It Helps
- Shows which specific identities cause each control to fail
- Matches remediation playbooks to each failing control
- Evidence table per control with identity name, type, risk level, and reason
- CSV export for external reporting
- Eliminates manual investigation of compliance failures

### Usage

**API Endpoint:** `GET /api/compliance/gap-analysis`

Query params: `framework` (optional, filter to one framework), `format` (json or csv)

**Response includes per control:**
- `evidence_identities`: List of identities causing the failure (name, type, risk_level, reason)
- `playbooks`: Matched remediation playbooks (name, severity, steps)

**UI Location:** Compliance page (`/compliance`) — expandable control rows

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-50.1 | Gap analysis loads | Navigate to `/compliance` | Framework cards with score rings and control status |
| TC-50.2 | Expand failing control | Click on a non-passing control | Evidence identities table + remediation playbooks appear |
| TC-50.3 | Evidence identities listed | Check expanded control | Lists specific identities with name, type, risk level, reason |
| TC-50.4 | Playbooks matched | Check expanded control | Remediation playbooks shown with steps |
| TC-50.5 | Passing control not expandable | Click on a passing (green) control | No expansion or shows "No issues" |
| TC-50.6 | CSV export | GET `/api/compliance/gap-analysis?format=csv` | CSV file with all controls and evidence |
| TC-50.7 | Framework filter | GET `/api/compliance/gap-analysis?framework=soc2` | Only SOC2 controls returned |
| TC-50.8 | No evidence for passing | Check passing control evidence | Empty evidence list |

---

<a id="phase-51"></a>
## Phase 51: Compliance Trend Tracking

### What It Does
Persists compliance scores after each discovery run in `compliance_snapshots` table. Provides trend API with automatic backfill. Displays Recharts LineChart on Compliance page showing score evolution per framework over time. Adds trend direction indicators (up/down/unchanged arrows) on framework cards.

### Why It's Needed
Compliance posture changes over time as identities are added, roles change, and credentials expire. Without trend tracking, there's no way to demonstrate continuous improvement or detect regression — both critical for audit readiness.

### How It Helps
- Visualize compliance score trends over time
- One line per framework + overall score
- Compare framework performance
- Direction indicators show improvement/regression at a glance
- Automatic backfill populates history from existing runs
- Compliance trend evidence for auditors

### Usage

**API Endpoint:** `GET /api/compliance/trends`

Query params: `framework` (optional, filter to one), `limit` (default 20)

**Response:**
```json
{
  "count": 20,
  "runs": [
    {
      "run_id": 42,
      "date": "2026-02-09T...",
      "overall_score": 72,
      "frameworks": {
        "soc2": {"score": 80, "pass_count": 4, "warn_count": 0, "fail_count": 1, "total_controls": 5, "name": "SOC 2 (Type II)"},
        "hipaa": {"score": 60, ...}
      }
    }
  ]
}
```

**UI Location:** Compliance page — LineChart between summary cards and framework cards, trend arrows on framework card score rings

### Configuration
Snapshots are automatically saved after each discovery run via scheduler hook. No additional configuration needed.

### Business Test Cases

| # | Test Case | Steps | Expected Result |
|---|-----------|-------|-----------------|
| TC-51.1 | Trend chart renders | Navigate to `/compliance` | LineChart showing score trends over time |
| TC-51.2 | Multiple framework lines | Check chart | One line per enabled framework + dashed overall line |
| TC-51.3 | Trend direction indicators | Check framework cards | Green up arrow (improved), red down arrow (regressed), or gray dash (unchanged) |
| TC-51.4 | Tooltip on chart | Hover over chart data point | Shows all framework scores for that run date |
| TC-51.5 | Trends API | GET `/api/compliance/trends` | Returns array of runs with per-framework scores |
| TC-51.6 | Single framework filter | GET `/api/compliance/trends?framework=soc2` | Returns SOC2-only score history |
| TC-51.7 | Backfill on first call | Clear compliance_snapshots → GET `/api/compliance/trends` | Auto-computes and saves snapshots for existing runs |
| TC-51.8 | Snapshot after discovery | Trigger discovery run → check compliance_snapshots table | New snapshot row for each framework |
| TC-51.9 | Chart hidden if < 2 runs | Have only 1 discovery run | Trend chart not shown (need at least 2 data points) |
| TC-51.10 | Unauthenticated blocked | GET `/api/compliance/trends` without token | Returns 401 |

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| Total Phases | 51 |
| API Routes | 96+ |
| Database Tables | 37 |
| Engine Classes | 13 |
| Scheduler Jobs | 2 |
| Frontend Pages | 20 |
| Dashboard Widgets | 16 |
| Compliance Frameworks | 6 |
| Remediation Playbooks | 20 |
| Anomaly Types | 6 |
| SOAR Integrations | 7 |
| Identity Categories | 6 |
| Business Test Cases | 150+ |

---

*Document generated: February 10, 2026*
*AuditGraph v1.0 — Identity Security Posture Management Platform*
