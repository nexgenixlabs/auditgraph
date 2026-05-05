# AuditGraph: Completed Phases 12-51 Documentation

> Comprehensive technical and functional reference for all completed phases of the AuditGraph identity security audit platform. This document covers backend architecture, API endpoints, database schema, frontend UI components, and configuration for each phase.

---

## Table of Contents

- [Phase 12: Remediation Engine](#phase-12-remediation-engine)
- [Phase 13: Report Generation](#phase-13-report-generation)
- [Phase 14: Drift Detection](#phase-14-drift-detection)
- [Phase 15: Settings & Configuration](#phase-15-settings--configuration)
- [Phase 16: Drift History](#phase-16-drift-history)
- [Phase 17: Activity Log](#phase-17-activity-log)
- [Phase 18: Scheduled Reports & Email Verification](#phase-18-scheduled-reports--email-verification)
- [Phase 19: Identity Comparison](#phase-19-identity-comparison)
- [Phase 20: Historical Trends](#phase-20-historical-trends)
- [Phase 21: Remediation Action Tracking](#phase-21-remediation-action-tracking)
- [Phase 22-24: Dark Mode & UI Enhancements](#phases-22-24-dark-mode--ui-enhancements)
- [Phase 25: Bulk Operations](#phase-25-bulk-operations)
- [Phase 26: Dashboard Charts & Role Usage](#phase-26-dashboard-charts--role-usage)
- [Phase 27: Global Search](#phase-27-global-search)
- [Phase 28: Webhooks Integration](#phase-28-webhooks-integration)
- [Phase 29: Custom Risk Rules](#phase-29-custom-risk-rules)
- [Phase 30: Notification Center](#phase-30-notification-center)
- [Phase 31: RBAC & Authentication](#phase-31-rbac--authentication)
- [Phase 32: Compliance Frameworks](#phase-32-compliance-frameworks)
- [Phase 33: Export Pipeline](#phase-33-export-pipeline)
- [Phase 34: Saved Views](#phase-34-saved-views)
- [Phase 35: Identity Lifecycle](#phase-35-identity-lifecycle)
- [Phase 36: Access Review Campaigns](#phase-36-access-review-campaigns)
- [Phase 37: Role Mining & Optimization](#phase-37-role-mining--optimization)
- [Phase 38: Identity Groups](#phase-38-identity-groups)
- [Phase 39: Advanced Query Builder](#phase-39-advanced-query-builder)
- [Phase 40: Anomaly Detection](#phase-40-anomaly-detection)
- [Phase 41: Risk Trend Analytics](#phase-41-risk-trend-analytics)
- [Phase 42: API Key Management](#phase-42-api-key-management)
- [Phase 43: SOAR Integration](#phase-43-soar-integration)
- [Phase 44: Dashboard Customization](#phase-44-dashboard-customization)
- [Phase 45: Multi-Tenant Foundation](#phase-45-multi-tenant-foundation)
- [Phase 46: Tenant User Management](#phase-46-tenant-user-management)
- [Phase 47: Cross-Tenant Analytics](#phase-47-cross-tenant-analytics)
- [Phase 48: Onboarding Wizard](#phase-48-onboarding-wizard)
- [Phase 49: Identity Risk Simulation](#phase-49-identity-risk-simulation)
- [Phase 50: Compliance Gap Analysis](#phase-50-compliance-gap-analysis)
- [Phase 51: Compliance Trend Tracking](#phase-51-compliance-trend-tracking)

---

## Phase 12: Remediation Engine

### What It Does

The Remediation Engine provides a library of 20 pre-built remediation playbooks that are automatically matched to identities based on their risk patterns. When viewing an identity's detail page, the system uses pattern-matching logic to surface relevant remediation steps -- for example, if an identity has an expired credential, the "Rotate Expired Credentials" playbook is matched and displayed.

Each playbook contains:
- A risk pattern string and pattern type (contains, exact, regex)
- A human-readable title and description
- Step-by-step remediation instructions (stored as JSONB)
- Impact level (high/medium/low), effort estimate, and priority score
- Compliance references linking the remediation to specific standards (e.g., NIST, SOC 2)
- A category tag for grouping (credential, access, configuration, etc.)

### Why It Is Needed

Security teams discovering hundreds of identity risks need actionable guidance, not just alerts. Without remediation playbooks, analysts must manually research every issue, leading to inconsistent responses and slower mean-time-to-remediate. The Remediation Engine transforms risk findings into prescriptive, repeatable actions that align with compliance frameworks.

### How It Helps

- Reduces analyst investigation time by providing immediate, relevant remediation steps for each risk finding
- Ensures consistent remediation across the organization regardless of analyst experience level
- Maps remediation actions to compliance controls, simplifying audit evidence collection
- Prioritizes remediations by impact and effort so teams can focus on high-value fixes first

### Usage

**API Endpoint:**

```
GET /api/identities/<identity_id>/remediations
```

**Response example:**
```json
{
  "identity_id": "abc-123",
  "playbooks": [
    {
      "id": 3,
      "title": "Rotate Expired Credentials",
      "description": "Identity has credentials that have expired...",
      "steps": [
        {"step": 1, "action": "Navigate to App Registrations", "detail": "..."},
        {"step": 2, "action": "Delete expired secret", "detail": "..."},
        {"step": 3, "action": "Generate new secret with 90-day expiry", "detail": "..."}
      ],
      "impact": "high",
      "effort": "low",
      "priority_score": 85,
      "compliance_refs": ["NIST AC-2", "SOC2 CC6.1"],
      "category": "credential"
    }
  ]
}
```

**UI Location:** Identity Detail page > Remediation tab (the 9th tab)

### Configuration

No additional configuration required. The 20 playbooks are seeded into the `remediation_playbooks` table on first startup. Custom playbooks can be added directly to the database.

**Database Table:**

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Auto-incrementing identifier |
| `risk_pattern` | VARCHAR(255) | Pattern to match against risk reasons |
| `pattern_type` | VARCHAR(20) | Match mode: `contains`, `exact`, or `regex` |
| `title` | VARCHAR(255) | Human-readable playbook title |
| `description` | TEXT | Detailed explanation of the risk |
| `steps` | JSONB | Array of step objects with action/detail fields |
| `impact` | VARCHAR(10) | `high`, `medium`, or `low` |
| `effort` | VARCHAR(10) | `high`, `medium`, or `low` |
| `priority_score` | INTEGER | 0-100 score for prioritization |
| `compliance_refs` | JSONB | Array of compliance control references |
| `category` | VARCHAR(50) | Grouping category |

---

## Phase 13: Report Generation

### What It Does

The Report Generation system provides a comprehensive data endpoint that feeds a client-side PDF generator built with jsPDF and jspdf-autotable. The `/api/reports/data` endpoint aggregates data from across the platform into a single JSON payload suitable for generating executive-level audit reports. The frontend `pdfGenerator.ts` utility transforms this data into a professionally formatted PDF with:

- Cover page with organization name, date, and branding
- Executive summary with risk distribution and posture score
- Compliance scorecard section
- Top critical/high risk identities table
- Remediation playbook recommendations
- Evidence and data source metadata

### Why It Is Needed

Auditors and compliance teams require formal documentation for regulatory reviews, board presentations, and stakeholder communications. Manually compiling identity security data into reports is time-consuming and error-prone. Automated report generation ensures consistent, comprehensive, and timely delivery of security posture information.

### How It Helps

- Generates audit-ready PDF reports with one click
- Consolidates data from multiple sources (risk scores, compliance, remediation) into a single document
- Provides executive summaries suitable for non-technical stakeholders
- Creates a permanent record of security posture at a point in time

### Usage

**API Endpoint:**

```
GET /api/reports/data
```

**Response:** A comprehensive JSON object containing risk summary, compliance data, top identities, remediation recommendations, and metadata.

**UI Location:** Reports page (`/reports` route) -- click "Generate Report" to produce and download the PDF.

**Frontend Utility:** `frontend/src/utils/pdfGenerator.ts`

### Configuration

No special configuration required. The report pulls data from the latest completed discovery run. Organization name is sourced from the Settings page (`org_name` setting).

---

## Phase 14: Drift Detection

### What It Does

Drift Detection compares consecutive discovery runs to identify changes in the identity landscape. After each scheduled discovery, the system automatically computes and persists a drift report covering five categories of change:

1. **New Identities** -- identities appearing for the first time
2. **Removed Identities** -- identities no longer present
3. **Permission Changes** -- role assignments gained or lost
4. **Risk Changes** -- risk level or score changes
5. **Credential Changes** -- new, expired, or modified credentials

Results are persisted in the `drift_reports` table (JSONB) for historical reference. Email notifications are sent when changes are detected (subject to Settings configuration).

### Why It Is Needed

Identity environments are dynamic. New service principals are created, permissions change, and credentials rotate. Without drift detection, security teams operate on point-in-time snapshots without visibility into what changed. Drift detection provides the critical "what changed since last time" view that enables proactive security management.

### How It Helps

- Alerts security teams immediately when identities gain or lose critical permissions
- Detects unauthorized changes between scheduled audits
- Provides historical change evidence for compliance investigations
- Enables trend analysis of identity environment stability

### Usage

**API Endpoints:**

```
GET /api/drift/latest         -- Most recent drift report summary (dashboard widget)
GET /api/drift/history        -- List of all drift reports
GET /api/runs/<run_id>/drift  -- Full drift report for a specific run
```

**Dashboard Widget:** The RecentChanges widget on the Dashboard page shows a summary of the latest drift findings.

**Email Notifications:** Configurable per change type via Settings (Phase 15).

### Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `email_enabled` | `true` | Master toggle for email notifications |
| `notify_new_identities` | `true` | Email on new identity detection |
| `notify_removed_identities` | `true` | Email on identity removal |
| `notify_permission_changes` | `true` | Email on permission drift |
| `notify_risk_changes` | `true` | Email on risk level changes |
| `notify_credential_changes` | `true` | Email on credential changes |

**Database Table: `drift_reports`**

Stores the full drift comparison result as JSONB, linked to both the current and previous discovery run IDs.

---

## Phase 15: Settings & Configuration

### What It Does

Provides a centralized key-value settings store backed by a `settings` table in PostgreSQL, with a REST API and a full Settings page in the frontend. Settings are organized into sections:

- **Section 1: Organization** -- org name, branding
- **Section 2: Discovery Schedule** -- scheduler interval (6/12/24 hours)
- **Section 3: Email Notifications** -- master toggle + per-type notification flags
- **Section 4: Scheduled Reports** -- weekly/monthly report scheduling
- Other sections added by later phases (webhooks, SOAR, API keys, tenants, etc.)

Settings are consumed by the scheduler, email service, and various API handlers at runtime.

### Why It Is Needed

A production identity security platform must be configurable without code changes. Administrators need to control discovery frequency, notification behavior, and organizational branding through a user interface rather than environment variables alone.

### How It Helps

- Allows non-technical administrators to configure platform behavior
- Eliminates the need for code deployments to change operational parameters
- Centralizes configuration for audit and troubleshooting
- Settings changes are logged in the activity log for accountability

### Usage

**API Endpoints:**

```
GET  /api/settings      -- Retrieve all settings + system status
POST /api/settings      -- Update one or more settings (admin only)
```

**Request body example:**
```json
{
  "org_name": "Contoso Inc.",
  "discovery_interval": "12",
  "email_enabled": "true",
  "notify_risk_changes": "false"
}
```

**UI Location:** Settings page (`/settings` route, admin-only)

### Configuration

Settings are self-contained in the `settings` table (key VARCHAR, value TEXT). Initial defaults are applied on first access. The scheduler reads settings on startup and applies them. Environment variables (e.g., `DISCOVERY_INTERVAL_HOURS`) serve as fallback defaults.

---

## Phase 16: Drift History

### What It Does

Extends Phase 14 with a dedicated Drift History page (`DriftHistory.tsx`) that displays a timeline table of all past drift reports. Each row shows the comparison run pair, total change count, and a breakdown badge. Clicking a row expands an inline detail view with five collapsible sections (one per change type), showing the specific identities and changes involved.

### Why It Is Needed

While Phase 14 provides the latest drift summary, security teams need historical context. Compliance auditors ask questions like "What changed in the last 30 days?" or "When did identity X gain that role?" The Drift History page provides the complete audit trail of identity environment changes over time.

### How It Helps

- Provides a searchable timeline of all identity changes
- Enables retrospective investigation of security incidents
- Supports compliance evidence requirements (e.g., SOC 2 change management)
- Links back to specific discovery runs for full context

### Usage

**UI Location:** Drift page (`/drift` route) -- accessible via the main navigation "Drift" link.

The RecentChanges dashboard widget includes a "View History" link that navigates to this page.

**API:** Uses the same `GET /api/drift/history` and `GET /api/runs/<id>/drift` endpoints from Phase 14.

### Configuration

No additional configuration. Drift reports are automatically persisted after each discovery run.

---

## Phase 17: Activity Log

### What It Does

Implements an append-only audit trail stored in the `activity_log` table. Every significant action in the system is logged: discovery runs, settings changes, report generation, drift detection, user login, remediation actions, SOAR executions, and more.

The frontend `ActivityLog.tsx` page displays a timeline of activities with:
- Action type badges (color-coded by category)
- Filter buttons to narrow by action type
- Expandable metadata for each entry
- Pagination (limit/offset)

### Why It Is Needed

Audit trails are a fundamental security control. Regulators and auditors require evidence of who did what and when. The Activity Log provides non-repudiation, supports incident investigation, and satisfies compliance requirements (SOC 2 CC7.2, HIPAA audit controls).

### How It Helps

- Creates a tamper-evident record of all platform actions
- Supports incident forensics by tracking user and system activities
- Satisfies compliance audit trail requirements
- Helps administrators understand system behavior and troubleshoot issues

### Usage

**API Endpoint:**

```
GET /api/activity?limit=50&offset=0&type=discovery_completed
```

Query parameters:
- `limit` (default 50): Number of records to return
- `offset` (default 0): Pagination offset
- `type` (optional): Filter by action type

**UI Location:** Activity page (`/activity` route) -- accessible via the "Activity" navigation link.

### Configuration

No additional configuration. Activity logging is automatic and integrated into all handler functions via the `_log()` helper and `db.log_activity()`.

**Database Table: `activity_log`**

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Auto-incrementing ID |
| `action_type` | VARCHAR(50) | Category of action |
| `description` | TEXT | Human-readable description |
| `metadata` | JSONB | Additional context data |
| `user_id` | INTEGER | User who performed the action (Phase 46) |
| `tenant_id` | INTEGER | Tenant context (Phase 46) |
| `created_at` | TIMESTAMPTZ | Timestamp of the action |

---

## Phase 18: Scheduled Reports & Email Verification

### What It Does

Adds two capabilities to the email notification system:

1. **Test Email:** A "Send Test Email" button in Settings that invokes `send_test_email()` to verify SMTP/email configuration is working before relying on automated notifications.

2. **Scheduled Reports:** A second APScheduler job (`scheduled_report`) that delivers executive summary reports on a configurable cadence (weekly on Mondays at 08:00 UTC, or monthly on the 1st at 08:00 UTC). The `send_scheduled_report()` function in `EmailService` generates and sends the report email.

Settings Section 4 in the frontend provides toggles for enabling/disabling scheduled reports and selecting the frequency.

### Why It Is Needed

Email is a critical communication channel for security alerts and reports. Without the ability to test email configuration, teams discover broken notifications only when a real alert fails to arrive. Scheduled reports ensure that stakeholders receive regular security posture updates without needing to log into the platform.

### How It Helps

- Validates email configuration before it is needed for real alerts
- Delivers regular executive summaries to stakeholders automatically
- Reduces "alert fatigue" from ad-hoc notifications by consolidating into scheduled digests
- Ensures continuous visibility even for stakeholders who do not use the platform daily

### Usage

**API Endpoints:**

```
POST /api/settings/test-email   -- Send a test email (admin only)
```

**Settings Section 4 Configuration:**

| Setting | Default | Description |
|---------|---------|-------------|
| `report_schedule_enabled` | `false` | Enable/disable scheduled reports |
| `report_schedule_frequency` | `weekly` | `weekly` or `monthly` |

**Scheduler Jobs:**
- `scheduled_discovery` -- identity discovery (existing)
- `scheduled_report` -- report email delivery (new)

### Configuration

Requires email credentials configured via environment variables or settings:
- `SENDGRID_API_KEY` or SMTP configuration
- `ALERT_EMAIL_TO` -- recipient address
- `ALERT_EMAIL_FROM` -- sender address

---

## Phase 19: Identity Comparison

### What It Does

Provides a side-by-side comparison view for two identities, allowing analysts to compare risk profiles, role assignments, permissions, credentials, and compliance posture simultaneously. The `IdentityComparison.tsx` page loads full detail data for both identities and renders them in a split-screen layout.

### Why It Is Needed

Analysts frequently need to compare identities -- for example, comparing a compromised service principal against a known-good baseline, or evaluating two similar identities to understand why one has a higher risk score. Without a comparison feature, this requires switching between tabs and manually tracking differences.

### How It Helps

- Enables rapid identification of permission differences between similar identities
- Supports incident investigation by comparing before/after states
- Helps standardize permissions by identifying inconsistencies across similar identities
- Reduces investigation time from minutes to seconds

### Usage

**UI Location:** Identities page > Compare (`/identities/compare` route)

Users can select two identities from the Identities table and compare them side by side.

### Configuration

No additional configuration required.

---

## Phase 20: Historical Trends

### What It Does

Provides historical trend data across discovery runs, including total identities, risk distribution, posture score, and average risk score over time. The `/api/trends` endpoint returns an array of run snapshots that power sparklines on the Overview page and trend charts on the Dashboard.

### Why It Is Needed

Point-in-time security metrics are insufficient for understanding trajectory. Stakeholders need to know whether the security posture is improving or degrading. Historical trends provide the longitudinal view necessary for strategic decision-making and demonstrating security program effectiveness.

### How It Helps

- Shows whether security investments are reducing risk over time
- Identifies concerning trends (e.g., steadily increasing critical identities) before they become crises
- Provides board-level metrics for security program reporting
- Supports compliance evidence for continuous monitoring requirements

### Usage

**API Endpoint:**

```
GET /api/trends
```

**Response example:**
```json
{
  "runs": [
    {
      "run_id": 45,
      "completed_at": "2025-01-15T10:00:00Z",
      "total": 250,
      "critical": 5,
      "high": 20,
      "medium": 80,
      "low": 145,
      "posture_score": 72,
      "avg_risk_score": 35
    }
  ]
}
```

**UI Location:** Overview page (sparklines on risk cards), Dashboard (trend arrows on stat cards).

### Configuration

No additional configuration. Trends are computed from historical discovery run data.

---

## Phase 21: Remediation Action Tracking

### What It Does

Extends the Remediation Engine (Phase 12) with persistent action tracking. Analysts can mark remediation playbooks as "open", "in_progress", "completed", or "dismissed" for each identity, creating an auditable record of remediation activities. A `remediation_actions` table stores the status with timestamps and notes.

Additionally, a remediation dashboard summary endpoint provides aggregated progress metrics.

### Why It Is Needed

Identifying risks is only half the battle -- tracking remediation to completion is equally important. Without action tracking, teams cannot demonstrate to auditors that identified risks were actually addressed. This phase bridges the gap between detection and resolution.

### How It Helps

- Tracks remediation progress from identification to completion
- Provides accountability for who addressed which risk and when
- Generates compliance evidence showing timely remediation
- Enables dashboard-level visibility into overall remediation velocity

### Usage

**API Endpoints:**

```
GET  /api/identities/<id>/remediation-status   -- Get action statuses for an identity
POST /api/identities/<id>/remediation-action    -- Create/update a remediation action
GET  /api/remediation-summary                   -- Dashboard summary of all remediation progress
```

**Request body example (action):**
```json
{
  "playbook_id": 3,
  "status": "in_progress",
  "notes": "Credential rotation scheduled for Friday maintenance window"
}
```

**Roles:** auditor and admin can create/update remediation actions.

### Configuration

No additional configuration. The `remediation_actions` table is created automatically.

**Database Table: `remediation_actions`**

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Auto-incrementing ID |
| `identity_id` | TEXT | Identity being remediated |
| `playbook_id` | INTEGER | Associated remediation playbook |
| `status` | VARCHAR(20) | `open`, `in_progress`, `completed`, `dismissed` |
| `notes` | TEXT | Analyst notes |
| `created_at` | TIMESTAMPTZ | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | Last update timestamp |

---

## Phases 22-24: Dark Mode & UI Enhancements

### What They Do

These phases add visual and usability improvements:

- **Dark Mode:** A `useTheme` hook and toggle button in the navigation bar. Persists preference to localStorage. All UI components respect the `dark` CSS class for Tailwind dark mode variants.
- **Error Boundary:** `ErrorBoundary` component wraps all route pages, catching React rendering errors and displaying a user-friendly fallback instead of a white screen.
- **Stale Data Banner:** `StaleDataBanner` component checks when the last discovery run completed and warns users if data is older than a configurable threshold.
- **Toast Notifications:** `ToastProvider` wrapping the app provides ephemeral success/error notifications for user actions.

### Why They Are Needed

Professional enterprise applications must support accessibility preferences (dark mode reduces eye strain), handle errors gracefully, and provide clear feedback for user actions. These foundational UI improvements are essential for production readiness and user adoption.

### How They Help

- Dark mode improves usability in low-light environments and respects user preferences
- Error boundaries prevent cascading failures from crashing the entire application
- Stale data warnings prevent users from making decisions on outdated information
- Toast notifications provide immediate feedback for actions like saving settings

### Usage

**UI Location:** Dark mode toggle is in the navigation bar (sun/moon icon). Error boundaries and toast notifications are automatic.

### Configuration

No backend configuration required. Dark mode preference is stored in the browser's localStorage.

---

## Phase 25: Bulk Operations

### What It Does

Enables batch remediation actions across multiple identities simultaneously. Instead of creating remediation actions one identity at a time, administrators can select multiple identities and apply a status update (e.g., "mark all as in_progress") in a single operation.

### Why It Is Needed

In environments with hundreds of identities sharing the same risk pattern, applying remediation actions individually is impractical. Bulk operations enable teams to process large volumes efficiently during remediation campaigns.

### How It Helps

- Reduces remediation processing time from hours to minutes for large-scale campaigns
- Ensures consistent remediation tracking across groups of similar identities
- Supports "remediation sprints" where teams address specific risk categories in bulk

### Usage

**API Endpoint:**

```
POST /api/bulk/remediation
```

**Request body:**
```json
{
  "identity_ids": ["abc-123", "def-456", "ghi-789"],
  "status": "in_progress",
  "notes": "Bulk assigned during weekly remediation sprint"
}
```

**Roles:** auditor and admin only.

### Configuration

No additional configuration required.

---

## Phase 26: Dashboard Charts & Role Usage

### What It Does

Adds a role usage statistics endpoint that provides distribution data for role usage statuses (active, inactive, unknown) and risk levels across all role assignments. This data feeds the Dashboard's role usage chart visualizations.

### Why It Is Needed

Understanding how roles are actually being used (vs. merely assigned) is critical for right-sizing permissions. The role usage chart gives immediate visual feedback on the proportion of roles that are actively used, helping identify over-provisioning at a glance.

### How It Helps

- Visualizes the gap between assigned and actively used roles
- Highlights the scope of over-provisioning in the environment
- Provides data for justifying role cleanup campaigns
- Supports least-privilege initiatives with empirical evidence

### Usage

**API Endpoint:**

```
GET /api/dashboard/role-usage
```

**UI Location:** Dashboard page -- role usage chart widget.

### Configuration

No additional configuration required.

---

## Phase 27: Global Search

### What It Does

Implements a keyboard-shortcut-activated global search modal (`SearchModal` component). Users press `Cmd+K` (Mac) or `Ctrl+K` (Windows/Linux) to open an overlay search dialog that searches across identities, pages, and actions. Results are displayed in real-time as the user types.

### Why It Is Needed

In a platform with thousands of identities and dozens of pages, navigation becomes a bottleneck. Global search provides instant access to any identity or feature without navigating through menus, significantly improving analyst workflow speed.

### How It Helps

- Provides sub-second access to any identity by name or ID
- Reduces navigation clicks for experienced users
- Follows the familiar command-palette pattern used by modern developer tools
- Improves discoverability of platform features

### Usage

**UI Location:** Press `Cmd+K` / `Ctrl+K` anywhere in the application, or click the search icon in the navigation bar.

### Configuration

No additional configuration required. Search operates against the existing identity API with the `search` query parameter.

---

## Phase 28: Webhooks Integration

### What It Does

Provides a full webhook management system for pushing event notifications to external services (Slack, Microsoft Teams, Splunk, custom endpoints). The system includes:

- Webhook CRUD (create, read, update, delete)
- 7 event types: `discovery_completed`, `risk_escalation`, `new_identities`, `removed_identities`, `permission_changes`, `credential_changes`, `drift_detected`
- HMAC-SHA256 signature verification for payload integrity
- Delivery tracking with retry logic
- Test endpoint for verifying webhook configuration

### Why It Is Needed

Security teams operate within broader toolchains (SIEM, SOAR, chat platforms). Webhooks enable real-time integration with these systems, ensuring that identity security events flow into existing operational workflows without manual intervention.

### How It Helps

- Pushes real-time alerts to Slack/Teams channels for immediate team awareness
- Feeds identity security events into SIEM platforms for correlation
- Enables custom automation triggered by identity changes
- Provides delivery audit trail for troubleshooting integration issues

### Usage

**API Endpoints:**

```
GET    /api/webhooks                        -- List all webhooks
POST   /api/webhooks                        -- Create a webhook
PUT    /api/webhooks/<id>                   -- Update a webhook
DELETE /api/webhooks/<id>                   -- Delete a webhook
POST   /api/webhooks/<id>/test              -- Send a test payload
GET    /api/webhooks/<id>/deliveries        -- View delivery history
```

**Request body (create):**
```json
{
  "name": "Slack Security Channel",
  "url": "https://hooks.slack.com/services/T.../B.../xxx",
  "secret": "my-webhook-secret",
  "event_types": ["risk_escalation", "new_identities"],
  "enabled": true
}
```

**Roles:** admin only for write operations.

**UI Location:** Settings page, Webhooks section.

### Configuration

Webhook events are fired automatically by the scheduler after each discovery run. The `WebhookService` class in `backend/app/services/webhook_service.py` handles delivery.

**Database Tables: `webhooks` + `webhook_deliveries`**

| Table | Key Columns |
|-------|-------------|
| `webhooks` | id, name, url, secret, event_types[], headers (JSONB), enabled |
| `webhook_deliveries` | id, webhook_id, event_type, payload (JSONB), status, http_status, attempts, next_retry_at |

---

## Phase 29: Custom Risk Rules

### What It Does

Enables administrators to define custom risk scoring rules that augment the built-in risk calculation engine. Rules are evaluated after default scoring and can either adjust points (add/subtract) or force a specific risk level. The `RiskRuleEngine` class supports:

- 14 supported identity fields for conditions (identity_category, display_name, activity_status, role_count, has_write_permissions, etc.)
- 8 comparison operators (eq, neq, gt, lt, gte, lte, in, contains)
- "All conditions must match" logic (AND within a rule)
- Two action types: `adjust_points` and `force_level`
- Preview mode to test a rule before saving

### Why It Is Needed

Every organization has unique risk criteria. A healthcare company may want to flag any identity with access to patient data systems regardless of other factors. A financial institution may consider certain legacy applications as higher risk. Custom rules allow organizations to encode their domain-specific risk knowledge into the scoring engine.

### How It Helps

- Tailors risk scoring to organization-specific policies and threat models
- Eliminates false positives by allowing fine-grained rule adjustments
- Supports "what-if" preview before activating a rule
- Provides an auditable record of custom risk logic (rules are versioned with timestamps)

### Usage

**API Endpoints:**

```
GET    /api/risk-rules              -- List all rules
POST   /api/risk-rules              -- Create a rule (admin only)
PUT    /api/risk-rules/<id>         -- Update a rule (admin only)
DELETE /api/risk-rules/<id>         -- Delete a rule (admin only)
POST   /api/risk-rules/preview      -- Preview rule impact (admin only)
```

**Request body (create):**
```json
{
  "name": "Flag disabled global admins",
  "description": "Disabled identities with Global Administrator should be critical",
  "conditions": {
    "all": [
      {"field": "enabled", "op": "eq", "value": false},
      {"field": "has_entra_role", "op": "eq", "value": "Global Administrator"}
    ]
  },
  "action_type": "force_level",
  "force_level": "critical",
  "reason_text": "Disabled Global Administrator account"
}
```

**UI Location:** Settings page, Custom Risk Rules section.

### Configuration

Rules are stored in the `custom_risk_rules` table and evaluated during risk scoring.

**Database Table: `custom_risk_rules`**

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Rule ID |
| `name` | VARCHAR(255) | Rule name |
| `conditions` | JSONB | Condition groups |
| `action_type` | VARCHAR(20) | `adjust_points` or `force_level` |
| `points_adjustment` | INTEGER | Points to add/subtract |
| `force_level` | VARCHAR(20) | Forced risk level |
| `reason_text` | TEXT | Text added to risk_reasons |
| `enabled` | BOOLEAN | Active/inactive toggle |
| `priority` | INTEGER | Evaluation order |

---

## Phase 30: Notification Center

### What It Does

Implements a full in-app notification inbox with a bell icon badge in the navigation bar. Notifications are generated automatically by the system for discovery events, drift changes, risk escalations, anomalies, and SOAR actions. The `NotificationCenter.tsx` page provides:

- Filterable list of notifications by severity (critical/high/medium/info) and category
- Read/unread status tracking with mark-as-read functionality
- Bulk "Mark All as Read" action
- Individual notification deletion
- Real-time unread count badge (polled every 60 seconds)

### Why It Is Needed

Email notifications may be delayed, filtered, or missed. In-app notifications provide an always-available, real-time awareness channel within the platform itself. This is especially important for critical security events that require immediate attention.

### How It Helps

- Provides immediate visibility into security events without leaving the platform
- Reduces reliance on email for time-sensitive alerts
- Supports multiple severity levels for appropriate prioritization
- Maintains notification history for review and accountability

### Usage

**API Endpoints:**

```
GET    /api/notifications                    -- List notifications (supports severity, category filters)
GET    /api/notifications/stats              -- Get unread count and category breakdown
PATCH  /api/notifications/<id>               -- Mark notification as read
POST   /api/notifications/mark-all-read      -- Mark all notifications as read
DELETE /api/notifications/<id>               -- Delete a notification
```

**UI Location:** Bell icon in navigation bar (shows unread count badge), Notifications page (`/notifications` route).

### Configuration

Notifications are generated automatically by the scheduler pipeline. Old notifications are cleaned up after 90 days.

**Database Table: `notifications`**

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Notification ID |
| `event_type` | VARCHAR(50) | Type of event |
| `category` | VARCHAR(30) | Category for filtering |
| `severity` | VARCHAR(20) | `critical`, `high`, `medium`, `info` |
| `title` | VARCHAR(255) | Notification title |
| `description` | TEXT | Detailed description |
| `payload` | JSONB | Additional event data |
| `related_identity_id` | TEXT | Associated identity |
| `related_run_id` | INTEGER | Associated discovery run |
| `read` | BOOLEAN | Read/unread status |
| `read_at` | TIMESTAMPTZ | When marked as read |

---

## Phase 31: RBAC & Authentication

### What It Does

Implements a complete authentication and authorization system:

**Authentication:**
- JWT-based login (`POST /api/auth/login`) with access tokens (short-lived) and refresh tokens
- Password hashing with bcrypt
- Token refresh flow (`POST /api/auth/refresh`)
- Logout with token revocation (`POST /api/auth/logout`)
- Current user endpoint (`GET /api/auth/me`)
- Password change endpoint (`PUT /api/auth/password`)

**Authorization:**
- Three roles: `admin` (full access), `auditor` (read + remediation), `viewer` (read-only)
- `require_role()` decorator on Flask routes
- Role-based UI visibility (e.g., Settings only visible to admins)

**Frontend:**
- `AuthContext` with global `window.fetch` interceptor that auto-attaches Bearer tokens
- `Login` page component
- `ProtectedRoute` wrapper redirecting unauthenticated users
- User management UI in Settings (admin only)

**User Management:**
- CRUD operations for users (admin only)
- Default admin user seeded on first startup (`admin`/`changeme`)

### Why It Is Needed

An identity security platform without its own access controls would be an ironic security risk. RBAC ensures that only authorized personnel can view sensitive identity data, make configuration changes, or perform remediation actions. This is a fundamental security control required by every compliance framework.

### How It Helps

- Prevents unauthorized access to sensitive identity security data
- Enforces least-privilege within the platform itself
- Provides accountability through user-specific audit trails
- Satisfies compliance requirements for access control (SOC 2, HIPAA, NIST)

### Usage

**API Endpoints:**

```
POST   /api/auth/login          -- Authenticate and receive tokens
POST   /api/auth/refresh        -- Refresh access token
POST   /api/auth/logout         -- Revoke refresh token
GET    /api/auth/me             -- Get current user info
PUT    /api/auth/password       -- Change password

GET    /api/users               -- List users (admin only)
POST   /api/users               -- Create user (admin only)
PUT    /api/users/<id>          -- Update user (admin only)
DELETE /api/users/<id>          -- Delete user (admin only)
```

**Login request:**
```json
{
  "username": "admin",
  "password": "changeme"
}
```

**Login response:**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "abc123...",
  "user": {
    "id": 1,
    "username": "admin",
    "display_name": "Administrator",
    "role": "admin"
  }
}
```

**Public paths (no auth required):** `/api/auth/login`, `/api/auth/refresh`, `/api/health`, `/health`

### Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `ADMIN_USERNAME` | `admin` | Default admin username |
| `ADMIN_PASSWORD` | `changeme` | Default admin password |
| `JWT_SECRET` | (required) | Secret key for JWT signing |

**Database Tables: `users` + `refresh_tokens`**

---

## Phase 32: Compliance Frameworks

### What It Does

Introduces a data-driven compliance framework engine. Frameworks (e.g., SOC 2, NIST 800-53, HIPAA, CIS Azure) are stored in the `compliance_frameworks` and `compliance_controls` tables, each with quantitative pass/warn/fail thresholds tied to identity security metrics. The system evaluates controls against real-time data to compute compliance scores.

Frameworks can be enabled/disabled by administrators, and the evaluation engine supports multiple metric types:
- Counts (e.g., number of identities with expired credentials)
- Percentages (e.g., percentage of identities with MFA)
- Threshold comparisons (less than, greater than, etc.)

### Why It Is Needed

Organizations must demonstrate compliance with industry regulations and standards. Manual compliance assessment is slow and subjective. Automated, data-driven compliance evaluation provides continuous, objective measurement of adherence to security controls.

### How It Helps

- Provides real-time compliance posture scores across multiple frameworks simultaneously
- Identifies specific failing controls with drill-down capability
- Enables proactive compliance management rather than reactive audit preparation
- Supports multi-framework mapping to identify overlapping controls

### Usage

**API Endpoints:**

```
GET   /api/compliance/frameworks                     -- List all frameworks
PATCH /api/compliance/frameworks/<id>                -- Toggle enabled state (admin only)
GET   /api/dashboard/compliance                      -- Dashboard compliance scorecard
```

**UI Location:** Compliance page (`/compliance` route), Dashboard compliance scorecard widget.

### Configuration

Frameworks are seeded automatically on startup via `db.seed_compliance_frameworks()`. Custom frameworks can be added to the database.

**Database Tables:**

| Table | Key Columns |
|-------|-------------|
| `compliance_frameworks` | id, key, name, description, version, enabled, display_order |
| `compliance_controls` | id, framework_id, control_id, name, metric, pass_operator, pass_value, warn_operator, warn_value, drilldown_url |

---

## Phase 33: Export Pipeline

### What It Does

Provides a structured data export system that returns JSON payloads designed for client-side file generation (CSV, JSON). Four export types are supported:

1. **identities** -- All identities with risk, role, and credential data
2. **compliance** -- Framework compliance scores and control statuses
3. **drift** -- Latest drift report with all change categories
4. **risk-summary** -- Aggregated risk distribution statistics

The frontend `Exports.tsx` page provides a dedicated UI for selecting export type and format, with optional filters.

### Why It Is Needed

Auditors, managers, and external compliance reviewers often need data in portable formats (CSV for spreadsheets, JSON for integrations). Export capability enables data sharing outside the platform without granting direct access.

### How It Helps

- Enables auditors to work with identity data in their preferred tools (Excel, Python, etc.)
- Supports regulatory data requests and compliance evidence packages
- Facilitates integration with external analytics and reporting systems
- Provides data portability without API integration complexity

### Usage

**API Endpoint:**

```
GET /api/export/<type>?risk_level=critical&identity_category=service_principal
```

Types: `identities`, `compliance`, `drift`, `risk-summary`

**UI Location:** Exports page (`/exports` route).

### Configuration

No additional configuration required. Exports are based on the latest completed discovery run.

---

## Phase 34: Saved Views

### What It Does

Allows users to save and recall filter/sort configurations for the Identities table. A saved view stores:
- Filter criteria (risk level, category, cloud, search text, etc.)
- Sort field and direction
- Whether the view is shared with other users
- Whether it is the user's default view

Views are user-scoped with optional sharing, and each user can designate one view as their default (auto-applied when visiting the Identities page).

### Why It Is Needed

Power users create complex filter combinations repeatedly (e.g., "Critical service principals in Azure with expired credentials"). Without saved views, they must reconstruct these filters every session. Saved views also enable teams to share standardized views for common workflows.

### How It Helps

- Eliminates repetitive filter setup for recurring analysis tasks
- Enables team-wide standardized views for consistent monitoring
- Supports workflow automation by bookmarking commonly needed data slices
- Reduces cognitive load by preserving analyst context between sessions

### Usage

**API Endpoints:**

```
GET    /api/saved-views                     -- List user's views + shared views
POST   /api/saved-views                     -- Create a view
PUT    /api/saved-views/<id>                -- Update a view
DELETE /api/saved-views/<id>                -- Delete a view
POST   /api/saved-views/<id>/default        -- Set as default view
```

**Request body (create):**
```json
{
  "name": "Critical Service Principals",
  "description": "All critical-risk service principals for weekly review",
  "filters": {
    "risk_level": "critical",
    "identity_category": "service_principal"
  },
  "sort_field": "risk_score",
  "sort_direction": "desc",
  "is_shared": true
}
```

**UI Location:** Identities page -- saved view dropdown/selector integrated with the Query Builder.

### Configuration

No additional configuration required.

**Database Table: `saved_views`**

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | View ID |
| `name` | VARCHAR(255) | View name |
| `filters` | JSONB | Filter criteria |
| `sort_field` | VARCHAR(50) | Sort column |
| `sort_direction` | VARCHAR(10) | `asc` or `desc` |
| `is_default` | BOOLEAN | Default view flag |
| `is_shared` | BOOLEAN | Shared with all users |
| `user_id` | INTEGER FK | Owner user |

---

## Phase 35: Identity Lifecycle

### What It Does

Tracks the full lifecycle of each identity across discovery runs, constructing a timeline of events from creation through current state. The `GET /api/identities/<id>/lifecycle` endpoint compares consecutive snapshots of an identity to detect:

- Identity creation (first discovery)
- Risk level changes
- Credential events (added, expired, rotated)
- Permission changes (roles gained/lost)
- Activity status changes (active/dormant/stale)
- Compliance posture changes (CA coverage, MFA status)

The response includes a summary with counts of each event type and a chronological (newest-first) list of events.

### Why It Is Needed

Understanding an identity's history is essential for incident investigation and compliance. "When did this identity gain Global Administrator?" or "How long has this credential been expired?" are common audit questions that require lifecycle visibility.

### How It Helps

- Provides a complete audit trail for any identity across its entire lifetime
- Supports incident investigation by revealing the sequence of changes
- Enables proactive monitoring by highlighting identities with frequent changes
- Satisfies compliance requirements for identity lifecycle management (ISO 27001, NIST)

### Usage

**API Endpoint:**

```
GET /api/identities/<identity_id>/lifecycle
```

**Response example:**
```json
{
  "identity_id": "abc-123",
  "display_name": "my-service-principal",
  "total_events": 8,
  "events": [
    {
      "timestamp": "2025-01-15T10:00:00Z",
      "run_id": 45,
      "event_type": "risk_level_changed",
      "category": "risk",
      "description": "Risk level changed from medium to high",
      "previous_value": "medium",
      "current_value": "high",
      "severity": "high"
    }
  ],
  "summary": {
    "total_runs_observed": 12,
    "first_seen": "2024-11-01T08:00:00Z",
    "last_seen": "2025-01-15T10:00:00Z",
    "risk_changes": 3,
    "credential_events": 2,
    "access_changes": 1,
    "status_changes": 2
  }
}
```

**UI Location:** Identity Detail page -- Lifecycle events are integrated into the identity timeline view.

### Configuration

No additional configuration. Lifecycle data is computed from historical identity snapshots across discovery runs.

---

## Phase 36: Access Review Campaigns

### What It Does

Implements a full access review campaign system for periodic certification of identity access. The system includes:

- **Campaign Management:** Create campaigns with name, description, scope filters, and deadline
- **Automatic Review Population:** On campaign creation, the system queries identities matching the scope filters and creates review items for each
- **Reviewer Assignment:** Each review item can be assigned to a reviewer (auditor/admin)
- **Decision Workflow:** Reviewers can approve, revoke, or flag each identity's access
- **Bulk Decisions:** Process multiple reviews at once
- **Campaign Lifecycle:** active -> completed (with completion timestamp)

### Why It Is Needed

Access reviews (also called access certifications) are a core identity governance requirement. Regulations like SOX, HIPAA, and SOC 2 require periodic review of who has access to what. Automated campaign management ensures reviews happen on schedule, no identity is missed, and decisions are documented.

### How It Helps

- Automates the access review process from scoping through decision recording
- Ensures complete coverage -- every in-scope identity is reviewed
- Provides an auditable record of review decisions for compliance evidence
- Tracks campaign progress with completion percentage metrics

### Usage

**API Endpoints:**

```
GET    /api/access-reviews                                      -- List campaigns
POST   /api/access-reviews                                      -- Create campaign (admin only)
GET    /api/access-reviews/<campaign_id>                        -- Campaign detail with review items
PUT    /api/access-reviews/<campaign_id>                        -- Update campaign (admin only)
DELETE /api/access-reviews/<campaign_id>                        -- Delete campaign (admin only)
PATCH  /api/access-reviews/<campaign_id>/reviews/<review_id>    -- Record decision
POST   /api/access-reviews/<campaign_id>/reviews/bulk           -- Bulk decisions
```

**Create campaign request:**
```json
{
  "name": "Q1 2025 Service Principal Review",
  "description": "Quarterly review of all high-risk service principals",
  "scope_filters": {
    "risk_level": "high",
    "identity_category": "service_principal"
  },
  "deadline": "2025-03-31T23:59:59Z"
}
```

**Decision request:**
```json
{
  "decision": "approve",
  "notes": "Access verified with application owner"
}
```

**UI Location:** Access Reviews page (`/access-reviews` route).

**Roles:** admin creates campaigns; auditor and admin record decisions.

### Configuration

No additional configuration required.

**Database Tables: `access_review_campaigns` + `campaign_reviews`**

| Table | Key Columns |
|-------|-------------|
| `access_review_campaigns` | id, name, status, scope_filters (JSONB), deadline, created_by |
| `campaign_reviews` | id, campaign_id, identity_id, reviewer_id, decision, notes, decided_at |

---

## Phase 37: Role Mining & Optimization

### What It Does

Analyzes role assignment patterns across identities to identify optimization opportunities:

- **Over-provisioned roles:** Roles assigned but never used (based on usage_status)
- **Redundant assignments:** Identities with overlapping role permissions
- **Common role patterns:** Groups of roles frequently assigned together (candidates for custom role creation)
- **Risk distribution by role:** Which roles contribute most to critical/high risk scores

### Why It Is Needed

Over-provisioning is one of the most common identity security risks. Role mining provides data-driven recommendations for right-sizing permissions, helping organizations move toward least-privilege access without breaking legitimate workflows.

### How It Helps

- Identifies roles that can be safely removed (never used)
- Suggests custom role definitions based on actual usage patterns
- Quantifies the risk reduction achievable through role optimization
- Supports continuous improvement of the permission model

### Usage

**API Endpoint:**

```
GET /api/role-mining
```

**UI Location:** Role Mining page (`/role-mining` route).

### Configuration

No additional configuration required. Role mining operates on data from the latest discovery run.

---

## Phase 38: Identity Groups

### What It Does

Enables organizing identities into logical groups for collective management and comparison. Two group types are supported:

1. **Custom Groups:** Manually curated collections of identities
2. **Auto Groups:** Dynamically populated based on criteria (risk level, category, activity status, etc.)

Features include:
- Group CRUD with color-coding and descriptions
- Add/remove members (for custom groups)
- Cross-group comparison (compare risk profiles of two groups)
- Per-identity group membership lookup
- Auto groups are pre-seeded on startup (e.g., "Critical Risk Identities", "Dormant Identities")

### Why It Is Needed

Managing identities individually does not scale. Groups provide logical organization for teams, departments, applications, or risk categories. They enable batch analysis, comparison, and reporting at the group level.

### How It Helps

- Organizes identities into meaningful collections for team-based management
- Enables group-level risk comparison for prioritization decisions
- Supports automated grouping based on dynamic criteria
- Facilitates delegation of identity management to group owners

### Usage

**API Endpoints:**

```
GET    /api/groups                            -- List all groups
POST   /api/groups                            -- Create a group
GET    /api/groups/<id>                       -- Group detail with members
PUT    /api/groups/<id>                       -- Update group
DELETE /api/groups/<id>                       -- Delete group (admin only)
POST   /api/groups/<id>/members               -- Add members
DELETE /api/groups/<id>/members               -- Remove members
GET    /api/groups/compare?ids=1,2            -- Compare two groups
GET    /api/identities/<id>/groups            -- Identity's group memberships
```

**UI Location:** Groups page (`/groups` route).

### Configuration

Auto groups are seeded on startup via `db.seed_auto_groups()`.

**Database Tables: `identity_groups` + `identity_group_members`**

| Table | Key Columns |
|-------|-------------|
| `identity_groups` | id, name, description, color, group_type (`custom`/`auto`), auto_criteria (JSONB), created_by |
| `identity_group_members` | id, group_id, identity_id, added_at |

---

## Phase 39: Advanced Query Builder

### What It Does

Provides a powerful, SQL-injection-safe query engine for filtering identities using complex, multi-condition queries. Key components:

**Backend:**
- `POST /api/identities/query` -- accepts structured query groups (AND conditions within groups, OR between groups)
- Field allowlist (`QUERY_FIELD_MAP`) with 25 direct database columns and 3 computed subquery fields (28 total)
- 10 comparison operators: `eq`, `neq`, `gt`, `lt`, `gte`, `lte`, `in`, `not_in`, `contains`, `is_null`
- All field references use the `i.` table alias to prevent SQL injection
- Compatible with saved views (Phase 34) for persistence

**Frontend:**
- `QueryBuilder.tsx` component with simple mode (quick filters) and advanced mode (full condition builder)
- Dynamic field selection with type-aware value inputs
- Add/remove conditions and groups
- Toggle between simple and advanced mode

### Why It Is Needed

Standard filter dropdowns are insufficient for complex analysis tasks. Security analysts need to construct queries like "Show me all service principals that are inactive AND have write permissions AND were created more than 365 days ago." The query builder makes this possible without SQL knowledge.

### How It Helps

- Enables complex multi-criteria identity searches without SQL expertise
- Prevents SQL injection through a strict field allowlist and parameterized queries
- Supports both casual users (simple mode) and power users (advanced mode)
- Integrates with saved views for repeatable complex queries

### Usage

**API Endpoints:**

```
POST /api/identities/query
GET  /api/identities/query/fields
```

**Query request example:**
```json
{
  "groups": [
    {
      "conditions": [
        {"field": "risk_level", "operator": "eq", "value": "critical"},
        {"field": "identity_category", "operator": "eq", "value": "service_principal"}
      ]
    },
    {
      "conditions": [
        {"field": "risk_score", "operator": "gte", "value": 90}
      ]
    }
  ],
  "limit": 50,
  "offset": 0,
  "sort_field": "risk_score",
  "sort_direction": "desc"
}
```

This query returns: (critical service principals) OR (identities with risk score >= 90).

**Fields endpoint response:** Returns available fields with their types, operators, and suggested values for building dynamic UI dropdowns.

**UI Location:** Identities page -- toggle between simple and advanced mode at the top of the filter panel.

### Configuration

No additional configuration required. The field allowlist is defined in `QUERY_FIELD_MAP` and `QUERY_COMPUTED_FIELDS` in `handlers.py`.

---

## Phase 40: Anomaly Detection

### What It Does

Implements a behavioral anomaly detection engine (`AnomalyDetector` class) that runs automatically after drift detection in the scheduler pipeline. It analyzes identity data across consecutive discovery runs to detect six types of anomalies:

| Anomaly Type | Severity | Description |
|-------------|----------|-------------|
| `permission_escalation` | Critical/High | Identity gains critical or high-risk roles (Global Administrator, Owner, etc.) between runs |
| `risk_score_spike` | Critical/High/Medium | Risk score increases by 100+ points or jumps 2+ risk levels |
| `dormant_reactivation` | High | Previously dormant/never-used identity becomes active (potential compromise indicator) |
| `credential_surge` | High/Medium | Credential count increases by 2+ between runs (potential key rotation issues) |
| `off_hours_pim` | High/Medium | PIM role activations outside configurable business hours (default 06:00-20:00 UTC) |
| `excessive_pim_usage` | High/Medium | PIM activation frequency exceeds threshold in 30-day window (default threshold: 10) |

Anomalies are persisted in the `anomalies` table and generate in-app notifications. Each anomaly includes identity reference, detailed evidence, and severity classification.

### Why It Is Needed

Drift detection identifies what changed, but anomaly detection identifies what is suspicious. A dormant service principal becoming active, an identity gaining Global Administrator overnight, or PIM activations at 3 AM are all behavioral signals that may indicate compromise or policy violations. Automated detection ensures these signals are not missed.

### How It Helps

- Provides early warning for potential identity compromise
- Detects privilege escalation attempts across discovery runs
- Identifies unusual PIM usage patterns that may warrant investigation
- Reduces mean-time-to-detect for identity-based security incidents

### Usage

**API Endpoints:**

```
GET   /api/anomalies                              -- List anomalies (filters: type, severity, identity_id, resolved, run_id)
GET   /api/anomalies/stats                        -- Summary (total, unresolved, by_type, by_severity)
GET   /api/anomalies/<id>                         -- Single anomaly detail
PATCH /api/anomalies/<id>                         -- Resolve anomaly (admin/auditor)
GET   /api/identities/<id>/anomalies              -- Identity-specific anomalies
GET   /api/dashboard/anomalies                    -- Top unresolved for dashboard widget
```

**Resolve request:**
```json
{
  "resolved": true,
  "resolved_by": "analyst@company.com"
}
```

**UI Location:**
- Dashboard: AnomalyAlerts widget showing top unresolved anomalies
- Identity Detail: Anomalies tab showing identity-specific findings
- Anomaly list accessible via dashboard widget links

### Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `anomaly_pim_hours_start` | `6` | Business hours start (UTC hour) |
| `anomaly_pim_hours_end` | `20` | Business hours end (UTC hour) |
| `anomaly_pim_frequency_threshold` | `10` | Max PIM activations per 30 days |
| `anomaly_risk_spike_threshold` | `100` | Score increase to trigger spike anomaly |

Old resolved anomalies are cleaned up after 180 days automatically.

**Database Table: `anomalies`**

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Anomaly ID |
| `discovery_run_id` | INTEGER FK | Associated run |
| `anomaly_type` | VARCHAR(50) | One of the 6 types |
| `severity` | VARCHAR(20) | `critical`, `high`, `medium` |
| `identity_id` | TEXT | Affected identity |
| `identity_name` | VARCHAR(255) | Display name |
| `title` | VARCHAR(255) | Human-readable title |
| `description` | TEXT | Detailed description with evidence |
| `details` | JSONB | Structured evidence data |
| `resolved` | BOOLEAN | Resolution status |
| `resolved_at` | TIMESTAMPTZ | Resolution timestamp |
| `resolved_by` | VARCHAR(100) | Who resolved it |

---

## Phase 41: Risk Trend Analytics

### What It Does

Enhances the trend analytics system with three new capabilities:

1. **Enhanced `/api/trends`:** Adds `posture_score` and `avg_risk_score` to each run snapshot, providing overall security health metrics over time.

2. **Velocity API (`/api/trends/velocity`):** Computes risk flow metrics -- inflow (new critical/high identities), outflow (identities whose risk decreased), and retention (identities that remained critical/high). This reveals whether the organization is winning or losing the risk reduction battle.

3. **Per-Identity Risk History:** `GET /api/identities/<id>/risk-history` returns the risk score trajectory for a single identity across all discovery runs it appeared in. `POST /api/identities/risk-history/batch` returns sparkline-ready data for multiple identities at once.

**Frontend Components:**
- `RiskVelocityChart` dashboard widget visualizing inflow/outflow/retention
- Sparkline column in the Identities table showing each identity's risk trajectory
- Risk Score Trajectory chart in the Identity Detail Overview tab

### Why It Is Needed

Static risk scores are snapshots; risk trends reveal trajectories. Knowing whether an identity's risk is climbing, stable, or declining provides critical context for prioritization. Velocity metrics answer the strategic question: "Are we reducing risk faster than it accumulates?"

### How It Helps

- Provides per-identity risk trajectories for contextual decision-making
- Quantifies organizational risk velocity (inflow vs. outflow)
- Enables visual identification of trending risks in the Identities table
- Supports executive-level reporting on security program effectiveness

### Usage

**API Endpoints:**

```
GET  /api/trends                                          -- Enhanced run history
GET  /api/trends/velocity                                 -- Risk inflow/outflow/retention
GET  /api/identities/<identity_id>/risk-history           -- Single identity risk trajectory
POST /api/identities/risk-history/batch                   -- Batch sparkline data
```

**Batch request:**
```json
{
  "identity_ids": ["abc-123", "def-456"],
  "limit": 10
}
```

**UI Location:**
- Dashboard: RiskVelocityChart widget
- Identities table: Trend sparkline column
- Identity Detail: Risk Score Trajectory chart in Overview tab

### Configuration

No additional configuration required.

---

## Phase 42: API Key Management

### What It Does

Implements programmatic API access via API keys, enabling external systems to integrate with AuditGraph without user credentials. Key features:

- **Key Format:** `ag_` prefix followed by 32 hex characters (e.g., `ag_a1b2c3d4...`)
- **Security:** Keys are SHA-256 hashed before storage; the raw key is shown exactly once on creation
- **Dual Authentication:** Keys can be used via `X-API-Key` header or `Bearer ag_...` authorization header
- **Role Scoping:** Each key is assigned a role (admin/auditor/viewer) limiting its permissions
- **Usage Tracking:** Last-used timestamp and usage count are updated on each API call
- **Expiration:** Optional expiration date for time-limited access

### Why It Is Needed

Organizations need to integrate AuditGraph with CI/CD pipelines, SIEM systems, custom dashboards, and automation scripts. API keys provide a secure, manageable way to grant programmatic access without sharing user credentials or maintaining interactive sessions.

### How It Helps

- Enables secure API integration with external tools and automation
- Provides fine-grained access control through role-scoped keys
- Supports key rotation and expiration for security best practices
- Tracks usage for auditing and detecting potential key compromise

### Usage

**API Endpoints:**

```
GET    /api/api-keys                -- List all API keys (admin only)
POST   /api/api-keys               -- Create a key (admin only, returns raw key once)
PUT    /api/api-keys/<id>          -- Update key metadata/enable/disable (admin only)
DELETE /api/api-keys/<id>          -- Delete a key (admin only)
```

**Create request:**
```json
{
  "name": "CI/CD Pipeline Key",
  "description": "Used by GitHub Actions for automated risk checks",
  "role": "viewer",
  "expires_at": "2025-12-31T23:59:59Z"
}
```

**Create response (one-time):**
```json
{
  "id": 5,
  "name": "CI/CD Pipeline Key",
  "role": "viewer",
  "key_prefix": "ag_a1b2c3d4",
  "raw_key": "ag_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "message": "Save this key now. It will not be shown again."
}
```

**Using an API key:**
```bash
# Via header
curl -H "X-API-Key: ag_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" /api/identities

# Via Bearer token
curl -H "Authorization: Bearer ag_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" /api/identities
```

**UI Location:** Settings page, API Keys section -- with create modal, enable/disable toggles, and one-time key display with clipboard copy.

### Configuration

No additional environment variables required. API keys are managed entirely through the UI and API.

**Database Table: `api_keys`**

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Key ID |
| `key_prefix` | VARCHAR(12) | Visible prefix (e.g., `ag_a1b2c3d4`) |
| `key_hash` | VARCHAR(64) | SHA-256 hash of full key |
| `name` | VARCHAR(255) | Descriptive name |
| `role` | VARCHAR(20) | Assigned role |
| `enabled` | BOOLEAN | Active/disabled |
| `created_by` | INTEGER FK | Admin who created it |
| `last_used_at` | TIMESTAMPTZ | Last API call timestamp |
| `expires_at` | TIMESTAMPTZ | Optional expiration |
| `usage_count` | INTEGER | Total API calls made |

---

## Phase 43: SOAR Integration

### What It Does

Implements a Security Orchestration, Automation, and Response (SOAR) engine that automates security responses to detected events. The `SoarEngine` class evaluates playbooks when security events occur and dispatches actions to external systems.

**Trigger Types:**
- `anomaly` -- fires when anomaly detection finds issues
- `risk_escalation` -- fires when identity risk level increases
- `drift` -- fires when identity drift is detected
- `new_identity` -- fires when new identities are discovered

**Action Types:**
- `webhook` -- send HTTP payload to external endpoint (Slack, Teams, PagerDuty, custom)
- `create_ticket` -- create incident in ServiceNow or Jira
- `send_notification` -- create in-app notification
- `tag_for_review` -- flag identity for remediation review

**Integrations:** Slack, Microsoft Teams, PagerDuty, ServiceNow, Jira, custom webhook, internal

Additional features:
- Cooldown management (prevent action flooding)
- Condition matching (trigger only when event matches criteria)
- Dry-run test mode (validate playbook without execution)
- Action history tracking with success/failure status

### Why It Is Needed

Security teams are overwhelmed with alerts. SOAR integration automates routine responses -- creating tickets for critical findings, alerting on-call engineers for anomalies, and flagging identities for review -- freeing analysts to focus on complex investigations.

### How It Helps

- Automates routine security responses to reduce mean-time-to-respond
- Integrates with existing ITSM and communication tools
- Ensures consistent response to security events regardless of time of day
- Provides complete audit trail of automated actions and their outcomes

### Usage

**API Endpoints:**

```
GET    /api/soar/playbooks                          -- List all playbooks
POST   /api/soar/playbooks                          -- Create playbook (admin only)
PUT    /api/soar/playbooks/<id>                     -- Update playbook (admin only)
DELETE /api/soar/playbooks/<id>                     -- Delete playbook (admin only)
POST   /api/soar/playbooks/<id>/test                -- Dry-run test (admin only)
GET    /api/soar/actions                            -- Action history
GET    /api/soar/actions/stats                      -- Action statistics
POST   /api/soar/execute                            -- Manual trigger (admin only)
```

**Create playbook request:**
```json
{
  "name": "Alert on Critical Anomalies",
  "description": "Send Slack alert when critical anomalies are detected",
  "trigger_type": "anomaly",
  "trigger_conditions": {
    "severity": "critical"
  },
  "action_type": "webhook",
  "action_config": {
    "url": "https://hooks.slack.com/services/T.../B.../xxx"
  },
  "integration": "slack",
  "cooldown_minutes": 30,
  "enabled": true
}
```

**UI Location:**
- Dashboard: SOARActivity widget showing recent automated actions
- Settings: Section 10 -- SOAR Playbook management with create/edit/toggle/delete/test
- Activity Log: 7 new action types (soar_playbook_created, soar_action_executed, etc.)

### Configuration

Playbook configuration is managed via the Settings UI. Integration-specific settings (URLs, API tokens, routing keys) are stored in the `action_config` JSONB field of each playbook.

**Database Tables: `soar_playbooks` + `soar_actions`**

| Table | Key Columns |
|-------|-------------|
| `soar_playbooks` | id, name, trigger_type, trigger_conditions (JSONB), action_type, action_config (JSONB), integration, cooldown_minutes, last_triggered_at, trigger_count |
| `soar_actions` | id, playbook_id, identity_id, anomaly_id, trigger_event (JSONB), action_type, integration, status, result (JSONB), executed_at |

---

## Phase 44: Dashboard Customization

### What It Does

Enables users to personalize their dashboard layout by selecting which widgets are visible, reordering them, and resizing them. Preferences are persisted per-user in the `dashboard_preferences` table.

**Components:**
- Widget registry defining all available dashboard widgets with default visibility and order
- `CustomizePanel` component with drag-and-drop reordering
- Preferences stored as JSONB (widget order, visibility, size preferences)
- Reset to default functionality

### Why It Is Needed

Different roles need different dashboard views. An executive wants high-level posture scores and compliance scorecards. A security analyst wants anomaly alerts and drift changes. Dashboard customization ensures each user sees what matters most to them.

### How It Helps

- Enables role-appropriate dashboard views without code changes
- Reduces information overload by hiding irrelevant widgets
- Improves user satisfaction and adoption through personalization
- Supports multiple workflow patterns with a single dashboard infrastructure

### Usage

**API Endpoints:**

```
GET    /api/dashboard/preferences          -- Get current user's preferences
PUT    /api/dashboard/preferences          -- Save preferences
DELETE /api/dashboard/preferences          -- Reset to defaults
```

**Save request:**
```json
{
  "widgets": [
    {"id": "posture_score", "visible": true, "order": 0, "size": "large"},
    {"id": "anomaly_alerts", "visible": true, "order": 1, "size": "medium"},
    {"id": "compliance_scorecard", "visible": true, "order": 2, "size": "medium"},
    {"id": "recent_changes", "visible": false, "order": 3, "size": "medium"}
  ]
}
```

**UI Location:** Dashboard page -- "Customize" button opens the CustomizePanel overlay.

**Frontend Hook:** `useDashboardPreferences` manages loading and saving preferences.

### Configuration

No additional configuration required.

**Database Table: `dashboard_preferences`**

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Preference ID |
| `user_id` | INTEGER UNIQUE FK | User (one preference set per user) |
| `preferences` | JSONB | Widget configuration |

---

## Phase 45: Multi-Tenant Foundation

### What It Does

Introduces multi-tenancy support, enabling a single AuditGraph deployment to serve multiple organizations. Key components:

- **Tenants Table:** Central registry of tenants with name, slug, plan, settings, and enabled status
- **Tenant Scoping:** `tenant_id` foreign key added to `users`, `discovery_runs`, and `settings` tables
- **JWT Tenant Context:** Tokens include `tenant_id`, `tenant_name`, and `is_superadmin` claims
- **Superadmin Role:** A special role that can manage tenants and access cross-tenant data
- **Tenant CRUD API:** Full lifecycle management for tenants
- **Default Tenant:** Auto-created on first startup, existing users/runs assigned to it

### Why It Is Needed

MSPs (Managed Security Providers) and large enterprises with multiple business units need to manage identity security across organizational boundaries. Multi-tenancy enables a single deployment to serve multiple customers or divisions with data isolation.

### How It Helps

- Enables SaaS and MSP deployment models
- Provides data isolation between organizations/business units
- Supports centralized management with per-tenant configuration
- Reduces operational overhead compared to separate deployments per tenant

### Usage

**API Endpoints:**

```
GET    /api/tenants                  -- List all tenants (superadmin only)
POST   /api/tenants                  -- Create tenant (superadmin only)
PUT    /api/tenants/<id>             -- Update tenant (superadmin only)
DELETE /api/tenants/<id>             -- Delete tenant (superadmin only)
GET    /api/tenant                   -- Get current tenant info
```

**Create tenant request:**
```json
{
  "name": "Contoso Healthcare",
  "slug": "contoso-hc",
  "plan": "enterprise",
  "settings": {
    "max_identities": 10000
  }
}
```

**UI Location:** Settings page -- Tenant Management section (superadmin only).

### Configuration

The default tenant is created automatically on first startup. The `_tenants_ensured` guard flag prevents redundant migration checks.

**Database Table: `tenants`**

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Tenant ID |
| `name` | VARCHAR(255) | Tenant display name |
| `slug` | VARCHAR(100) UNIQUE | URL-safe identifier |
| `plan` | VARCHAR(20) | `free`, `pro`, `enterprise` |
| `settings` | JSONB | Tenant-specific settings |
| `enabled` | BOOLEAN | Active/disabled |

---

## Phase 46: Tenant User Management

### What It Does

Extends multi-tenancy with user-level tenant management:

- **X-Tenant-Id Header Override:** Superadmins can impersonate tenant context by sending `X-Tenant-Id` in request headers, enabling cross-tenant data access
- **TenantSwitcher Dropdown:** Navigation bar component (superadmin only) showing all tenants with click-to-switch functionality
- **Tenant-Scoped Activity Log:** Activity log entries include `user_id` and `tenant_id` columns; the `_log()` helper auto-injects context from the authenticated user
- **Cross-Tenant Guards:** Non-superadmin users cannot access data outside their assigned tenant

### Why It Is Needed

Superadmins managing multiple tenants need to switch context efficiently. The tenant switcher provides a seamless UX for navigating between organizations. Activity log scoping ensures audit trails reflect the correct tenant context.

### How It Helps

- Enables superadmins to manage multiple tenants without logging out/in
- Provides tenant-scoped audit trails for compliance evidence
- Prevents unauthorized cross-tenant data access
- Supports delegation of tenant administration to local admins

### Usage

**UI Location:** Navigation bar -- purple TenantSwitcher dropdown (visible only to superadmins).

**Header Override:**
```bash
# Switch to tenant 3 as superadmin
curl -H "Authorization: Bearer <token>" \
     -H "X-Tenant-Id: 3" \
     /api/identities
```

### Configuration

No additional configuration required. Tenant assignment is managed through the user CRUD API.

---

## Phase 47: Cross-Tenant Analytics

### What It Does

Provides superadmin-only analytics that aggregate data across all tenants for a holistic view of the entire platform. Two endpoints:

- `GET /api/analytics/tenants` -- Per-tenant summary (identity counts, risk distribution, last run time)
- `GET /api/analytics/tenants/trends` -- Cross-tenant trend data over time

The frontend `CrossTenantAnalytics.tsx` page presents this data in a comparative dashboard format.

### Why It Is Needed

MSPs and enterprise security teams need to compare security posture across their portfolio of managed organizations. Cross-tenant analytics provide the "big picture" view necessary for resource allocation and identifying the highest-risk tenants.

### How It Helps

- Enables portfolio-level security posture assessment
- Identifies the highest-risk tenants for priority attention
- Supports resource allocation decisions across managed organizations
- Provides executive-level reporting for MSP/enterprise leadership

### Usage

**API Endpoints:**

```
GET /api/analytics/tenants              -- Per-tenant summaries (superadmin only)
GET /api/analytics/tenants/trends       -- Cross-tenant trends (superadmin only)
```

**UI Location:** Analytics page (`/analytics` route, purple nav link visible only to superadmins).

### Configuration

No additional configuration required. Requires superadmin role.

---

## Phase 48: Onboarding Wizard

### What It Does

Provides a guided setup experience for new AuditGraph deployments. The `OnboardingWizard.tsx` page walks administrators through:

1. Azure credential configuration (Tenant ID, Client ID, Client Secret)
2. Connection testing via `POST /api/onboarding/test-connection`
3. Initial discovery trigger
4. First-run configuration

The wizard automatically redirects new admin users on login if Azure is not yet configured. Credentials can be stored in the database settings (alternative to environment variables).

### Why It Is Needed

First-time setup of an identity security platform requires Azure AD app registration, credential configuration, and initial discovery. The onboarding wizard guides administrators through this process, reducing time-to-value and preventing common configuration errors.

### How It Helps

- Reduces initial setup time from hours to minutes
- Prevents common configuration mistakes through guided validation
- Tests connectivity before committing configuration
- Provides a clear path from installation to first discovery results

### Usage

**API Endpoints:**

```
GET  /api/onboarding/status                  -- Check onboarding completion status
POST /api/onboarding/test-connection         -- Test Azure AD connectivity (admin only)
```

**UI Location:** Onboarding page (`/onboarding` route, auto-redirect for unconfigured deployments).

### Configuration

The wizard stores Azure credentials in the settings table as fallback (environment variables take precedence):
- `azure_tenant_id`
- `azure_client_id`
- `azure_client_secret`

---

## Phase 49: Identity Risk Simulation

### What It Does

Implements a "What If" analysis engine that allows users to simulate the impact of adding or removing roles and permissions on an identity's risk score. The simulation:

1. Loads the identity's current risk data (roles, permissions, credentials)
2. Applies the hypothetical modifications (remove roles, add roles, remove permissions, add permissions)
3. Recomputes the risk score using the same scoring algorithm as the production risk calculator
4. Returns the delta (score difference) and any changes to risk level and risk reasons

### Why It Is Needed

Before making access changes, security teams need to understand the risk impact. "If we remove the Global Administrator role from this service principal, how much does its risk score drop?" Without simulation, teams must make changes in production and wait for the next discovery run to see the impact.

### How It Helps

- Enables risk impact assessment before making changes
- Supports "least privilege" initiatives by quantifying the benefit of removing specific permissions
- Helps prioritize which access changes will have the most risk reduction
- Provides evidence for change approval processes

### Usage

**API Endpoint:**

```
POST /api/identities/<identity_id>/simulate
```

**Request body:**
```json
{
  "remove_roles": ["Global Administrator", "Owner"],
  "add_roles": [
    {"role_name": "Reader", "role_type": "azure", "scope_type": "subscription"}
  ],
  "remove_permissions": ["Mail.ReadWrite"],
  "add_permissions": [
    {"permission_name": "Mail.Read", "risk_level": "medium"}
  ]
}
```

**Response:**
```json
{
  "current": {
    "risk_score": 420,
    "risk_level": "critical",
    "risk_reasons": ["Global Administrator role", "Mail.ReadWrite permission", "..."]
  },
  "simulated": {
    "risk_score": 180,
    "risk_level": "medium",
    "risk_reasons": ["Mail.Read permission", "..."]
  },
  "delta": -240,
  "level_change": "critical -> medium",
  "removed_reasons": ["Global Administrator role", "Mail.ReadWrite permission"],
  "added_reasons": ["Mail.Read permission"]
}
```

**Roles:** auditor and admin only.

**UI Location:** Identity Detail page -- "What If" tab.

### Configuration

No additional configuration required. Uses the same `_compute_risk_score()` function as the production risk engine.

---

## Phase 50: Compliance Gap Analysis

### What It Does

Extends the compliance framework system with detailed gap analysis capabilities:

1. **Evidence Identities:** For each failing or warning control, the system identifies the specific identities contributing to the failure (e.g., which identities have expired credentials, which lack MFA)
2. **Playbook Matching:** Failing controls are matched to relevant remediation playbooks from Phase 12, providing a direct path from gap to remediation
3. **CSV Export:** Gap analysis data can be exported in CSV format for offline review and evidence packages
4. **Expandable Evidence UI:** The Compliance page displays frameworks with expandable cards showing per-control status, evidence identities, and matched remediation actions

### Why It Is Needed

Knowing that a compliance control is failing is not enough -- auditors need to know which identities are causing the failure and what actions can fix it. Gap analysis bridges the gap between compliance scoring and actionable remediation.

### How It Helps

- Identifies the exact identities responsible for compliance failures
- Links failing controls to specific remediation playbooks
- Enables CSV export for audit evidence packages
- Provides drill-down from compliance score to individual identity issues

### Usage

**API Endpoint:**

```
GET /api/compliance/gap-analysis?framework=soc2&format=json
```

Query parameters:
- `framework` (optional): Filter to specific framework key
- `format`: `json` (default) or `csv`

**Response (JSON, partial):**
```json
{
  "frameworks": {
    "soc2": {
      "name": "SOC 2 Type II",
      "score": 78,
      "controls": [
        {
          "control_id": "CC6.1",
          "name": "Logical and Physical Access",
          "status": "fail",
          "value": 15,
          "detail": "15 identities with expired credentials...",
          "evidence_identities": [
            {"identity_id": "abc-123", "display_name": "my-sp", "risk_level": "high"}
          ],
          "matched_playbooks": [
            {"id": 3, "title": "Rotate Expired Credentials"}
          ]
        }
      ]
    }
  }
}
```

**UI Location:** Compliance page (`/compliance` route) -- framework cards with expandable control details and evidence lists.

### Configuration

No additional configuration required. Gap analysis uses existing compliance frameworks, identity data, and remediation playbooks.

---

## Phase 51: Compliance Trend Tracking

### What It Does

Adds historical compliance score tracking by persisting compliance snapshots after each discovery run. This enables visualization of compliance posture over time.

**Components:**
- **`compliance_snapshots` Table:** Stores per-framework compliance scores, pass/warn/fail counts, and raw metrics for each discovery run
- **Auto-Persist:** After each discovery run completes, the scheduler calls `_save_compliance_snapshot()` to compute and store scores for all enabled frameworks
- **Trend API:** `GET /api/compliance/trends` returns historical scores with automatic backfill (if the table is empty, it retrospectively computes snapshots from historical runs)
- **Frontend Visualization:** Recharts `LineChart` on the Compliance page showing score trends per framework over time
- **Direction Indicators:** Framework cards display up/down arrows indicating whether compliance scores are improving or declining compared to previous runs

### Why It Is Needed

Compliance is not a binary state -- it is a continuous process. Stakeholders need to see whether compliance scores are trending upward (demonstrating security program effectiveness) or degrading (indicating emerging risks). Trend data is essential for compliance program reporting and strategic planning.

### How It Helps

- Demonstrates compliance program trajectory to auditors and leadership
- Identifies frameworks where compliance is degrading for proactive intervention
- Provides historical evidence of continuous compliance monitoring
- Supports comparison of compliance posture before and after remediation campaigns

### Usage

**API Endpoint:**

```
GET /api/compliance/trends?framework=soc2&limit=20
```

Query parameters:
- `framework` (optional): Filter to a single framework key for flattened response
- `limit` (default 20, max 50): Number of historical runs to include

**Response:**
```json
{
  "runs": [
    {
      "run_id": 45,
      "date": "2025-01-15T10:00:00Z",
      "frameworks": {
        "soc2": {
          "score": 82,
          "pass_count": 9,
          "warn_count": 1,
          "fail_count": 1,
          "total_controls": 11
        },
        "nist_800_53": {
          "score": 75,
          "pass_count": 6,
          "warn_count": 1,
          "fail_count": 1,
          "total_controls": 8
        }
      }
    }
  ],
  "count": 15
}
```

**UI Location:** Compliance page -- Recharts line chart at the top, direction indicators (arrow icons) on each framework card.

### Configuration

No additional configuration required. Snapshots are computed and stored automatically after each discovery run. The backfill mechanism ensures trends are available even for runs that completed before this phase was deployed.

**Database Table: `compliance_snapshots`**

| Column | Type | Description |
|--------|------|-------------|
| `id` | SERIAL PK | Snapshot ID |
| `run_id` | INTEGER FK | Discovery run (unique with framework_key) |
| `framework_key` | VARCHAR(50) | Framework identifier |
| `framework_name` | VARCHAR(100) | Framework display name |
| `score` | INTEGER | Compliance score (0-100) |
| `pass_count` | INTEGER | Number of passing controls |
| `warn_count` | INTEGER | Number of warning controls |
| `fail_count` | INTEGER | Number of failing controls |
| `total_controls` | INTEGER | Total controls evaluated |
| `metrics` | JSONB | Raw metrics used for computation |

---

## Summary Table

| Phase | Name | Backend | Frontend | Database Tables |
|-------|------|---------|----------|-----------------|
| 12 | Remediation Engine | Pattern-matching API | Remediation tab | `remediation_playbooks` |
| 13 | Report Generation | `/api/reports/data` | Reports page, pdfGenerator | -- |
| 14 | Drift Detection | Drift persister, email | RecentChanges widget | `drift_reports` |
| 15 | Settings & Config | GET/POST `/api/settings` | Settings page | `settings` |
| 16 | Drift History | `/api/drift/history` | DriftHistory.tsx | -- |
| 17 | Activity Log | `/api/activity` | ActivityLog.tsx | `activity_log` |
| 18 | Scheduled Reports | APScheduler report job | Settings Section 4 | -- |
| 19 | Identity Comparison | Existing APIs | IdentityComparison.tsx | -- |
| 20 | Historical Trends | `/api/trends` | Sparklines, trend arrows | -- |
| 21 | Remediation Tracking | CRUD endpoints | Remediation status UI | `remediation_actions` |
| 22-24 | Dark Mode & UI | -- | useTheme, ErrorBoundary, ToastProvider | -- |
| 25 | Bulk Operations | `/api/bulk/remediation` | Bulk action UI | -- |
| 26 | Dashboard Charts | `/api/dashboard/role-usage` | Role usage chart | -- |
| 27 | Global Search | -- | SearchModal (Cmd+K) | -- |
| 28 | Webhooks | CRUD + delivery | Settings UI | `webhooks`, `webhook_deliveries` |
| 29 | Custom Risk Rules | CRUD + preview | Settings UI | `custom_risk_rules` |
| 30 | Notification Center | 5 endpoints | NotificationCenter.tsx, bell badge | `notifications` |
| 31 | RBAC & Auth | JWT, user CRUD | Login, AuthContext, ProtectedRoute | `users`, `refresh_tokens` |
| 32 | Compliance Frameworks | Framework engine | Compliance page | `compliance_frameworks`, `compliance_controls` |
| 33 | Export Pipeline | `/api/export/<type>` | Exports.tsx | -- |
| 34 | Saved Views | CRUD endpoints | View selector | `saved_views` |
| 35 | Identity Lifecycle | `/api/identities/<id>/lifecycle` | Lifecycle timeline | -- |
| 36 | Access Reviews | Campaign CRUD | AccessReviews.tsx | `access_review_campaigns`, `campaign_reviews` |
| 37 | Role Mining | `/api/role-mining` | RoleMining.tsx | -- |
| 38 | Identity Groups | Group CRUD | IdentityGroups.tsx | `identity_groups`, `identity_group_members` |
| 39 | Query Builder | `/api/identities/query` | QueryBuilder.tsx | -- |
| 40 | Anomaly Detection | 6 detectors, 6 endpoints | AnomalyAlerts widget, Anomalies tab | `anomalies` |
| 41 | Risk Trends | Velocity API, batch sparklines | RiskVelocityChart, sparkline column | -- |
| 42 | API Key Mgmt | CRUD + dual auth | Settings UI | `api_keys` |
| 43 | SOAR Integration | SoarEngine, 8 endpoints | SOARActivity widget, Settings | `soar_playbooks`, `soar_actions` |
| 44 | Dashboard Custom | Prefs CRUD | CustomizePanel | `dashboard_preferences` |
| 45 | Multi-Tenant | Tenant CRUD, JWT scoping | Settings UI | `tenants` |
| 46 | Tenant Users | X-Tenant-Id, _log() | TenantSwitcher | -- |
| 47 | Cross-Tenant Analytics | Analytics API | CrossTenantAnalytics.tsx | -- |
| 48 | Onboarding Wizard | Status + test endpoints | OnboardingWizard.tsx | -- |
| 49 | Risk Simulation | `/api/identities/<id>/simulate` | What If tab | -- |
| 50 | Compliance Gap | `/api/compliance/gap-analysis` | Expandable evidence UI | -- |
| 51 | Compliance Trends | `/api/compliance/trends` | LineChart, direction arrows | `compliance_snapshots` |
