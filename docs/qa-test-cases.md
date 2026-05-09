# AuditGraph — QA Test Case Document

**Product:** AuditGraph by NexGenix Labs
**Version:** Phase 85+
**Date:** 2026-05-09
**Scope:** Full product validation — 74 pages, 610 API endpoints, 66 engines
**Priority Levels:** P0 (blocker), P1 (critical), P2 (high), P3 (medium), P4 (low)

---

## Table of Contents

1. [Authentication & Account Management](#1-authentication--account-management)
2. [Onboarding & Setup](#2-onboarding--setup)
3. [CISO Dashboard](#3-ciso-dashboard)
4. [Security Command Center](#4-security-command-center)
5. [Identity Explorer](#5-identity-explorer)
6. [Identity Detail](#6-identity-detail)
7. [Attack Paths & Blast Radius](#7-attack-paths--blast-radius)
8. [Risk & Compliance](#8-risk--compliance)
9. [Security Findings](#9-security-findings)
10. [Remediation Center](#10-remediation-center)
11. [Drift Detection & Anomalies](#11-drift-detection--anomalies)
12. [Governance & Access Reviews](#12-governance--access-reviews)
13. [Reports & Exports](#13-reports--exports)
14. [AI Security Copilot](#14-ai-security-copilot)
15. [Settings — General](#15-settings--general)
16. [Settings — Users](#16-settings--users)
17. [Settings — Connections](#17-settings--connections)
18. [Settings — Notifications](#18-settings--notifications)
19. [Settings — Security (API Keys & SSO)](#19-settings--security)
20. [Settings — Scoring (Custom Risk Rules)](#20-settings--scoring)
21. [Settings — Integrations](#21-settings--integrations)
22. [Client Billing](#22-client-billing)
23. [Admin Console — Tenants](#23-admin-console--tenants)
24. [Admin Console — Users](#24-admin-console--users)
25. [Admin Console — Onboarding](#25-admin-console--onboarding)
26. [Admin Console — Monitoring](#26-admin-console--monitoring)
27. [Admin Console — Billing](#27-admin-console--billing)
28. [Admin Console — Action Log](#28-admin-console--action-log)
29. [Multi-Tenant Isolation](#29-multi-tenant-isolation)
30. [API Security & Rate Limiting](#30-api-security--rate-limiting)
31. [Performance & Load](#31-performance--load)
32. [Browser & Responsive](#32-browser--responsive)

---

## 1. Authentication & Account Management

### 1.1 Login Page (`/login`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| AUTH-001 | Valid login with username/password | 1. Navigate to `/login` 2. Enter valid username 3. Enter valid password 4. Click "Sign In" | User redirected to `/` (CISO Dashboard). JWT cookie set. User info loaded. | - 200 response from `POST /api/auth/login` - httpOnly cookie `ag_access` set - httpOnly cookie `ag_refresh` set - CSRF cookie `ag_csrf` set - User role displayed in header | P0 |
| AUTH-002 | Invalid password | 1. Enter valid username 2. Enter wrong password 3. Click "Sign In" | Error: "Invalid credentials". No token issued. Failed attempt logged. | - 401 response - Same error message for wrong user AND wrong password (no enumeration) - `failed_login_attempts` incremented in DB | P0 |
| AUTH-003 | Invalid username | 1. Enter nonexistent username 2. Enter any password 3. Click "Sign In" | Error: "Invalid credentials". Same message as wrong password. | - 401 response - Error message identical to AUTH-002 (prevents user enumeration) | P0 |
| AUTH-004 | Empty fields | 1. Leave username blank 2. Leave password blank 3. Click "Sign In" | Form validation error. Submit button disabled or inline error shown. | - No API call made - Inline validation messages appear | P1 |
| AUTH-005 | Account lockout after N failures | 1. Enter valid username 2. Enter wrong password 5+ times rapidly | Account locked. Error: "Account temporarily locked. Try again later." | - locked_until timestamp set in DB - Subsequent valid password attempts also fail until lockout expires - Lockout duration >= 15 minutes | P0 |
| AUTH-006 | Login from wrong portal | 1. Admin user attempts login on client portal `/login` | Error: "This account does not have access to this portal." | - 403 response - No token issued | P1 |
| AUTH-007 | Login to wrong subdomain | 1. User from org-A logs in on org-B's subdomain | Error: "Invalid credentials" or "Organization mismatch" | - Domain-based tenant validation blocks access - No cross-org token issued | P0 |
| AUTH-008 | Forced password change | 1. Login with user flagged `force_password_change=true` | Password change form appears before dashboard access. | - Current password required - New password must meet policy (min 12 chars, complexity) - After change, `force_password_change` set to false - Redirects to dashboard | P1 |
| AUTH-009 | Session persistence on refresh | 1. Login successfully 2. Refresh browser page | User remains logged in. Dashboard loads. | - JWT cookie survives page refresh - No redirect to login page | P1 |
| AUTH-010 | Token refresh | 1. Login 2. Wait for access token to expire (30 min admin / 60 min client) | Auto-refresh triggers. User stays logged in. | - `POST /api/auth/refresh` called automatically - New access token issued - No visible interruption to user | P1 |
| AUTH-011 | Logout | 1. Click logout button/link | Redirected to `/login`. All cookies cleared. | - `POST /api/auth/logout` called - `ag_access`, `ag_refresh`, `ag_csrf` cookies cleared - Subsequent API calls return 401 - Refresh token revoked in DB | P0 |
| AUTH-012 | SSO/SAML login | 1. Click "Sign in with SSO" 2. Authenticate with IdP 3. Return to AuditGraph | User logged in via SAML. JWT issued. | - SAML assertion validated - User auto-provisioned if JIT enabled - Role mapped from SAML attributes - Activity logged | P1 |
| AUTH-013 | OIDC login | 1. Click OIDC provider button 2. Authenticate with IdP 3. Return via callback | User logged in via OIDC. JWT issued. | - Authorization code exchanged for tokens - User matched/created by email - Role assigned per OIDC config | P1 |
| AUTH-014 | Concurrent sessions | 1. Login from browser A 2. Login from browser B with same user | Both sessions active. Both can make API calls. | - Both sessions valid - No forced logout of first session | P2 |
| AUTH-015 | Refresh token reuse detection | 1. Login 2. Copy refresh token 3. Use refresh token from two different clients | Second usage triggers revocation of ALL user tokens. | - All sessions for this user terminated - Warning logged: "Refresh token reuse detected" - User must re-authenticate | P0 |

### 1.2 Signup (`/signup`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| AUTH-020 | Valid signup | 1. Navigate to `/signup` 2. Fill org name, email, password 3. Select plan (Free/Trial) 4. Submit | Account created. Redirected to onboarding wizard. | - 201 from `POST /api/auth/signup` - Organization created in DB - User created with role=admin - Redirect to `/onboarding` | P0 |
| AUTH-021 | Duplicate email | 1. Signup with email that already exists | Error: "Email already registered" | - 409 response - No duplicate user created | P1 |
| AUTH-022 | Weak password | 1. Enter password "123456" | Validation error: password requirements not met. | - Min 12 chars, 1 upper, 1 lower, 1 number, 1 special - Common password blocklist checked (175 patterns) | P1 |
| AUTH-023 | Plan selection limits | 1. Select Free plan 2. Complete signup | Account created with Free plan limits. | - max_subscriptions = 1 - max_identities = 50 - Blocked features: SOAR, API keys, advanced query, custom risk rules, AI copilot, scheduled reports, compliance export, SSO | P1 |

### 1.3 Password Reset (`/forgot-password`, `/reset-password`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| AUTH-030 | Request password reset | 1. Click "Forgot Password?" 2. Enter registered email 3. Submit | Success message shown. Reset email sent. | - 200 response regardless of email existence (no enumeration) - Email sent only if account exists - Reset token valid for limited time | P1 |
| AUTH-031 | Reset with valid token | 1. Click reset link from email 2. Enter new password 3. Submit | Password changed. Redirect to login. | - Token validated via `GET /api/auth/validate-reset-token` - Password updated in DB (bcrypt hashed) - Token single-use (cannot reuse) | P1 |
| AUTH-032 | Reset with expired token | 1. Use reset link after expiry period | Error: "Reset token expired" | - 400 or 401 response - User prompted to request new reset | P2 |
| AUTH-033 | Rate limit on reset | 1. Request reset 5+ times in quick succession | Rate limited after threshold. | - Max 3 resets per hour per email - Max 5 requests per 5 min per IP | P2 |

### 1.4 Accept Invitation (`/accept-invite`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| AUTH-040 | Accept valid invitation | 1. Click invitation link 2. Set password 3. Submit | Account activated. Redirect to dashboard. | - Token validated via `GET /api/auth/validate-invitation` - User created with invited role - Organization membership established | P1 |
| AUTH-041 | Expired invitation | 1. Click expired invitation link | Error: "Invitation has expired" | - 400 response - Prompt to contact admin for new invite | P2 |

---

## 2. Onboarding & Setup

### 2.1 Onboarding Wizard (`/onboarding`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| ONB-001 | Complete Azure onboarding | 1. Enter org name 2. Select Azure 3. Enter Tenant ID, Client ID, Client Secret 4. Test connection 5. Configure discovery interval 6. Launch | Connection created. First discovery starts. Redirect to dashboard. | - `POST /api/client/connections` succeeds - Connection status: "connected" - Discovery run triggered - Subscriptions discovered and listed | P0 |
| ONB-002 | Invalid Azure credentials | 1. Enter wrong Client Secret 2. Click "Test Connection" | Error: "Connection failed. Please verify credentials." | - Test endpoint returns failure - User can correct and retry - No connection saved with invalid creds | P0 |
| ONB-003 | Step persistence on refresh | 1. Complete steps 1-3 2. Refresh browser | Steps 1-3 data retained. Wizard resumes at step 4. | - sessionStorage preserves wizard state - No data loss on page refresh | P2 |
| ONB-004 | Skip optional steps | 1. Complete required steps 2. Skip email notification config | Onboarding completes without notifications configured. | - Default discovery interval applied - Email notifications disabled by default | P3 |
| ONB-005 | Locked dashboard before onboarding | 1. Login to new org (no connections) 2. Navigate to `/` | Locked dashboard shown. Redirect to `/settings` or onboarding prompt. | - No data panels load - Clear CTA to connect cloud provider | P1 |

---

## 3. CISO Dashboard

### 3.1 CISO Dashboard (`/`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| CISO-001 | Dashboard loads with data | 1. Login as user with completed discovery 2. Navigate to `/` | Dashboard loads with all sections populated. | - Posture score displayed (0-100) - Risk distribution chart renders - Identity counts shown (total, critical, high, medium, low) - Blast radius section populated - Anomalies section shows count - No "loading" spinners stuck | P0 |
| CISO-002 | Posture score accuracy | 1. Load dashboard 2. Verify posture score matches API | Score matches `GET /api/v1/posture/score` response. | - overall_score matches displayed score - 5 dimension scores shown: attack_surface, privilege, credentials, activity, governance - Score color: green (>=85), yellow (70-84), orange (50-69), red (<50) | P0 |
| CISO-003 | Risk distribution chart | 1. Load dashboard 2. Verify risk breakdown | Chart shows critical/high/medium/low identity counts. | - Counts match `GET /api/identities` with risk_label filter - Clicking a segment navigates to filtered identity list - Chart renders correctly (no overlapping labels) | P1 |
| CISO-004 | Blast radius section | 1. Load dashboard 2. Check blast radius data | Top risky identities with blast radius shown. | - Subscriptions reachable count displayed - Resource groups count displayed - Key vaults count displayed - Data sourced from live discovery (not mock) | P1 |
| CISO-005 | Anomaly count | 1. Load dashboard 2. Check anomalies | Anomaly count and severity breakdown shown. | - Matches `GET /api/anomalies/stats` response - Critical anomalies highlighted - Click navigates to anomalies page | P1 |
| CISO-006 | Privilege exposure section | 1. Load dashboard 2. Check privilege data | T0/T1/T2/T3 identity counts shown. | - Tier counts based on privilege_level from identities - T0 count highlighted if > 0 - Data from current discovery run | P1 |
| CISO-007 | Dashboard refresh | 1. Click refresh/reload button on dashboard | Data refreshes without full page reload. | - API calls made to refresh data - Loading indicators shown during refresh - Data updates reflected immediately | P2 |
| CISO-008 | Empty state (no discovery) | 1. Login to org with 0 discovery runs | Dashboard shows empty state with guidance. | - No errors/500s - Message: "No discovery data available" or similar - CTA to run first discovery | P1 |
| CISO-009 | Fallback strings (no data) | 1. Load dashboard when specific data unavailable | Graceful fallback messages shown. | - No "undefined", "null", "NaN" displayed - "No additional insights for this period" for missing insights - "Service principal data pending next discovery scan" for missing SPN data | P1 |

---

## 4. Security Command Center

### 4.1 Security Command Center (`/command-center`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| SCC-001 | Command center loads | 1. Navigate to `/command-center` | Page loads with security overview, risky identities, recommendations. | - Security overview metrics populated - Top risky identities listed (sorted by risk_score desc) - Fix recommendations shown | P1 |
| SCC-002 | Severity badges | 1. View command center 2. Check severity badges on identities | Badges show correct colors and labels. | - CRITICAL = red - HIGH = orange - MEDIUM = yellow - LOW = green | P2 |
| SCC-003 | Activity timeline | 1. View command center 2. Check activity timeline | Recent security events displayed chronologically. | - Events from activity_log - Newest first - Event type, timestamp, identity/user shown | P2 |

---

## 5. Identity Explorer

### 5.1 Identity Explorer (`/identity-explorer`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| IDE-001 | Identity list loads | 1. Navigate to `/identity-explorer` | Identity table populated with all identities. | - Table shows: display_name, identity_type, risk_score, risk_label, privilege_level, activity_status - Pagination controls shown - Total count matches header | P0 |
| IDE-002 | Pagination | 1. Load identity list 2. Click page 2 3. Click "Next" 4. Click "Previous" | Pages navigate correctly. Data changes per page. | - Default limit=50 - Offset updates correctly - Page number reflects current position - Total count remains stable | P0 |
| IDE-003 | Filter by identity type | 1. Select filter: "Service Principal" | Only service principals shown. Count updates. | - API called with `identity_type=service_principal` - Table shows only matching identities - Filter chip displayed and removable | P0 |
| IDE-004 | Filter by risk level | 1. Select filter: "Critical" | Only critical-risk identities shown. | - API called with `risk_label=critical` - All shown identities have risk_label=critical | P0 |
| IDE-005 | Filter by cloud provider | 1. Select filter: "Azure" | Only Azure identities shown. | - API called with `cloud_provider=azure` | P1 |
| IDE-006 | Filter by dormancy | 1. Toggle "Dormant Only" filter | Only dormant identities shown. | - API called with `is_dormant=true` - All shown identities have is_dormant=true | P1 |
| IDE-007 | Search by name | 1. Type "admin" in search box | Identities matching "admin" in display_name shown. | - Client-side or server-side filter applies - Results update as user types (debounced) - Case-insensitive matching | P1 |
| IDE-008 | Combined filters | 1. Filter: type=service_principal AND risk=critical | Only critical SPNs shown. | - Both filters applied simultaneously - Count reflects intersection - Removing one filter expands results | P1 |
| IDE-009 | Sort by risk score | 1. Click "Risk Score" column header | Table sorts by risk_score descending. Click again for ascending. | - Sort indicator arrow shown - Data re-ordered correctly - Sort persists across pagination | P1 |
| IDE-010 | Click identity row | 1. Click on an identity row | Navigate to identity detail page `/identities/:id`. | - Correct identity_id in URL - Detail page loads with that identity's data | P0 |
| IDE-011 | Tab: All Identities | 1. Click "All Identities" tab | Shows all identity types combined. | - Tab is default active - Count includes users + SPNs + MIs + guests | P1 |
| IDE-012 | Tab: AI/Non-Human Agents | 1. Click "AI/Non-Human" tab | Shows only non-human identities (SPNs, MIs, app regs). | - Filtered to non-human identity types only | P1 |
| IDE-013 | Tab: Privileged Access | 1. Click "Privileged Access" tab | Shows only T0/T1 privileged identities. | - Only identities with privilege_level in (T0, T1) shown | P1 |
| IDE-014 | Tab: Identity Graph | 1. Click "Identity Graph" tab | Graph visualization renders. | - @xyflow/react graph component loads - Nodes represent identities - Edges represent relationships (ownership, permissions) - Interactive: drag, zoom, pan | P2 |
| IDE-015 | Empty state | 1. View identity list for org with 0 identities | Empty state message shown. | - "No identities discovered yet" message - CTA to run discovery | P2 |
| IDE-016 | Large dataset (1000+ identities) | 1. Load identity list for org with 1000+ identities | Table loads within 3 seconds. Pagination works. | - No browser hang - Pagination handles large total - Scroll performance acceptable | P2 |

---

## 6. Identity Detail

### 6.1 Identity Detail Page (`/identities/:id`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| IDT-001 | Detail page loads | 1. Navigate to `/identities/:id` | Identity detail page loads with all sections. | - Display name shown in header - Identity type badge (User/SPN/MI/Guest) - Risk score with CVSS severity color - Privilege tier (T0/T1/T2/T3) badge - Last seen timestamp - Activity status | P0 |
| IDT-002 | Permissions tab | 1. Click "Permissions" tab | Role assignments and API permissions listed. | - Azure RBAC roles listed with scope - Entra directory roles listed - Graph API permissions listed - App role assignments listed - Role tier classification shown | P0 |
| IDT-003 | Ownership tab | 1. Click "Ownership" tab | Ownership chain displayed. | - Owner(s) listed with names - Owned resources/apps listed - "No owner" flag if applicable | P1 |
| IDT-004 | Lifecycle tab | 1. Click "Lifecycle" tab | Identity lifecycle information shown. | - Created date - Last sign-in date - Last activity date - Credential status (healthy/expiring/expired) - Credential expiry dates - Account enabled/disabled status | P1 |
| IDT-005 | Lineage tab | 1. Click "Lineage" tab | Lineage verdict and contributing factors shown. | - Verdict displayed (e.g., "review_federated_dependencies") - Confidence score (0-1.0) - Contributing factors listed with weights - Previous verdict (if changed) - Verdict source | P1 |
| IDT-006 | Activity tab | 1. Click "Activity" tab | Sign-in and activity history shown. | - Recent sign-in events with timestamps - IP addresses - Geographic location (if available) - Authentication method | P2 |
| IDT-007 | Attack paths for identity | 1. View attack paths section on detail page | Attack paths involving this identity listed. | - Paths where this identity is source or target - Path severity shown - Click navigates to attack path detail | P1 |
| IDT-008 | Remediation actions | 1. View remediation section on detail page | Recommended remediation actions listed. | - Each action has: type, description, priority - "Execute" button for auto-fixable actions - "Create Approval" button for manual actions | P1 |
| IDT-009 | Non-existent identity | 1. Navigate to `/identities/99999999` (invalid ID) | 404 error page or redirect. | - No 500 error - Graceful error message - Back/home navigation available | P2 |
| IDT-010 | Cross-org identity access | 1. Navigate to identity belonging to different org | 403 or 404 (no data leak). | - Returns 403 (not 404, to prevent existence leak) - No identity data exposed | P0 |

---

## 7. Attack Paths & Blast Radius

### 7.1 Attack Paths (`/attack-paths`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| ATK-001 | Attack paths list | 1. Navigate to `/attack-paths` | List of attack paths shown. | - Path type (privilege_escalation, lateral_movement, data_exposure) - Severity (critical/high/medium/low) - Source and target identities - Occurrence count - MITRE ATT&CK technique ID | P0 |
| ATK-002 | Filter by severity | 1. Filter attack paths by "Critical" | Only critical paths shown. | - Count updates - All shown paths are critical severity | P1 |
| ATK-003 | Filter by path type | 1. Filter by "Privilege Escalation" | Only escalation paths shown. | - Path type filter applied correctly | P1 |
| ATK-004 | Attack path detail | 1. Click on an attack path | Detail view shows full path narrative. | - Step-by-step escalation chain - Affected resources listed - Remediation recommendations - Blast radius at each step | P1 |
| ATK-005 | Attack path visualization | 1. View path detail with graph | Interactive graph of attack chain renders. | - Nodes: identities and resources - Edges: permission relationships - Direction arrows show escalation flow - Severity color coding | P2 |

### 7.2 Attack Simulator (`/attack-simulator`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| ATK-010 | Simulate compromise | 1. Navigate to `/attack-simulator` 2. Select an identity 3. Click "Simulate Compromise" | What-if analysis shown. | - Blast radius calculated - Reachable subscriptions listed - Reachable resource groups listed - Reachable key vaults listed - Impact score calculated | P1 |
| ATK-011 | Simulate with remediation | 1. Simulate compromise 2. Apply suggested remediation 3. Re-simulate | Reduced blast radius shown after remediation. | - Before/after comparison - Impact reduction quantified | P2 |

---

## 8. Risk & Compliance

### 8.1 Compliance Dashboard (`/compliance-posture`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| CMP-001 | Compliance dashboard loads | 1. Navigate to `/compliance-posture` | Compliance posture with framework scores shown. | - Overall governance score displayed - Framework-level scores (SOC 2, NIST, HIPAA, PCI-DSS, CIS, MITRE) - Gap analysis summary - Trend chart | P1 |
| CMP-002 | Framework drill-down | 1. Click on a compliance framework (e.g., SOC 2) | Control-level compliance details shown. | - Individual controls listed (e.g., CC6.1, CC6.3) - Pass/fail status per control - Evidence references - Gap count | P1 |
| CMP-003 | Compliance trend | 1. View compliance trend chart | Compliance score over time shown. | - Line chart with daily/weekly data points - Trend direction (improving/declining) visible - Date range selector works | P2 |

### 8.2 Role Mining (`/role-mining`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| CMP-010 | Toxic role combinations | 1. Navigate to `/role-mining` | Toxic role combinations listed. | - Combinations flagged with severity - Identity count per combination - Description of why combination is risky | P2 |
| CMP-011 | Unused roles | 1. View unused roles section | Roles with 0 assignments or 0 usage shown. | - Role name, type, assignment count - Last used date - "Remove" action available | P2 |

### 8.3 Effective Access (`/effective-access`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| CMP-020 | Effective access resolution | 1. Navigate to `/effective-access` 2. Select an identity | Full resolved permissions shown. | - Direct role assignments - Inherited permissions (via group membership) - API permissions - App roles - Effective access = union of all sources | P1 |

---

## 9. Security Findings

### 9.1 Security Findings (`/security-findings`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| FND-001 | Findings list loads | 1. Navigate to `/security-findings` | Security findings listed with severity. | - Finding title and description - Severity badge (critical/high/medium/low) - Affected identity count - Status (open/acknowledged/resolved) - Fingerprint-based deduplication (no duplicates across runs) | P0 |
| FND-002 | Filter by severity | 1. Filter by "Critical" | Only critical findings shown. | - Count updates - All visible findings are critical | P1 |
| FND-003 | Filter by status | 1. Filter by "Open" | Only unresolved findings shown. | - Acknowledged and resolved findings hidden | P1 |
| FND-004 | Acknowledge finding | 1. Click "Acknowledge" on a finding | Finding status changes to "acknowledged". | - `POST /api/findings/:id/status` with status=acknowledged - Finding remains visible but marked - Audit trail recorded | P1 |
| FND-005 | Resolve finding | 1. Click "Resolve" on a finding | Finding status changes to "resolved". | - Finding moves to resolved list - Can be re-opened if issue recurs | P1 |
| FND-006 | Create Jira ticket | 1. Click "Create Jira Ticket" on a finding | Jira issue created with finding details. | - `POST /api/findings/:id/jira` - Ticket key returned and displayed - Link to Jira ticket shown | P2 |
| FND-007 | Finding detail | 1. Click on a finding row | Finding detail view shown. | - Full description - Affected identities listed - MITRE ATT&CK technique mapping - NIST/CIS control reference - Recommended remediation steps | P1 |
| FND-008 | NHI-specific findings | 1. View findings related to non-human identities | NHI findings categorized separately. | - Finding types: orphaned SPN, expired secret, ownerless app, dormant MI - Each has specific remediation guidance | P1 |

---

## 10. Remediation Center

### 10.1 Remediation Center (`/remediation`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| REM-001 | Remediation queue loads | 1. Navigate to `/remediation` | Remediation actions listed with priority. | - Action type, description, identity affected - Priority (P1-P4) - Status (pending/approved/executing/executed/failed) - Blast radius impact | P0 |
| REM-002 | Execute auto-fixable action | 1. Find auto-fixable action 2. Click "Execute" 3. Confirm | Action executed against Azure. Status updates. | - Confirmation dialog shown with impact warning - `POST /api/v1/identities/:id/remediation/:action_id/execute` - Status transitions: pending -> executing -> executed - Execution result logged | P0 |
| REM-003 | Create approval request | 1. Find action requiring approval 2. Click "Request Approval" | Approval request created. Routed to approver. | - `POST /api/approvals` with action details - Status: "pending" - Approver notified (if notifications configured) | P1 |
| REM-004 | Approval workflow — approve | 1. Login as approver 2. View pending approval 3. Click "Approve" with note | Approval granted. Action queued for execution. | - `POST /api/approvals/:ref/approve` - Status: approved -> queued -> executing -> executed - Approval note saved - Audit trail recorded | P1 |
| REM-005 | Approval workflow — reject | 1. Login as approver 2. Click "Reject" with reason | Approval rejected. No action taken. | - `POST /api/approvals/:ref/reject` - Status: "rejected" - Rejection reason saved | P1 |
| REM-006 | Two-level approval | 1. First approver approves 2. Second approver approves | Both levels completed. Action proceeds. | - Status: pending -> approved -> fully_approved -> queued - Both approver IDs recorded | P2 |
| REM-007 | Rollback executed action | 1. Find executed action 2. Click "Rollback" | Rollback initiated. | - `POST /api/approvals/:ref/rollback` - Status: "rolled_back" - Rollback reason recorded | P2 |
| REM-008 | Execution script preview | 1. Click "View Script" on an action | Preview of Azure CLI/API command shown. | - `GET /api/approvals/:ref/script` - Script shown in read-only code block - Includes exact Azure command to be executed | P2 |
| REM-009 | Execution history | 1. Click "History" on an action | Full execution history shown. | - `GET /api/approvals/:ref/execution-history` - Each step with timestamp, status, output | P2 |
| REM-010 | Demo org write guard | 1. Login to demo org 2. Attempt to execute remediation | Action blocked: "Write operations disabled for demo tenant." | - 403 response - No Azure API call made - Clear message explaining demo restriction | P1 |

### 10.2 Supported Remediation Actions

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| REM-020 | Remove role assignment | 1. Execute "remove_role" action | Azure RBAC role removed from identity. | - Role assignment deleted in Azure - Identity's role list updated on next discovery - Audit logged | P1 |
| REM-021 | Assign owner | 1. Execute "assign_owner" action | Owner assigned to service principal/app. | - Owner added in Azure AD - Ownership visible on next discovery | P1 |
| REM-022 | Disable identity | 1. Execute "disable_identity" action | Identity disabled in Azure AD. | - accountEnabled set to false - Identity shows as disabled on next discovery | P1 |
| REM-023 | Revoke credential | 1. Execute "revoke_credential" action | Credential removed/rotated. | - Secret/certificate removed or rotated - Credential status updates on next discovery | P1 |
| REM-024 | Enable PIM | 1. Execute "enable_pim" action | PIM eligibility configured. | - Privileged Identity Management assignment created - Time-limited access enforced | P2 |

---

## 11. Drift Detection & Anomalies

### 11.1 Drift Analysis (`/drift-analysis`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| DFT-001 | Drift report loads | 1. Navigate to `/drift-analysis` | Drift events between discovery runs shown. | - New privileged access events listed - Removed permissions listed - New identities discovered - Identities removed - Severity classification per drift event | P1 |
| DFT-002 | Drift comparison | 1. Select two discovery runs to compare | Side-by-side diff shown. | - Identity count changes (added/removed) - Permission changes highlighted - Risk score changes shown - New findings from drift | P1 |
| DFT-003 | Drift severity | 1. View drift events | Severity correctly classified. | - Privilege escalation drift = Critical/High - New admin role = Critical - Permission removal = Info - Credential rotation = Low | P2 |

### 11.2 Anomalies

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| ANM-001 | Anomaly list | 1. Navigate to anomalies section | Anomalies listed with type and severity. | - Anomaly type (ghost_identity, risk_score_spike, unusual_activity) - Severity (critical/high/medium/low) - Affected identity - Detection timestamp | P1 |
| ANM-002 | Anomaly stats | 1. View anomaly statistics | Stats match API response. | - `GET /api/anomalies/stats` matches displayed data - Count by severity - Count by type | P1 |
| ANM-003 | Anomaly detail | 1. Click on anomaly | Detail view with context shown. | - Description of anomaly - Contributing factors - Historical pattern - Recommended action | P2 |

---

## 12. Governance & Access Reviews

### 12.1 Access Reviews (`/access-reviews`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| GOV-001 | Access review campaigns | 1. Navigate to `/access-reviews` | Active review campaigns listed. | - Campaign name, status, deadline - Identities included in review - Completion percentage - Reviewer assignments | P1 |
| GOV-002 | Certify access | 1. Open review campaign 2. Approve/deny access for identities | Attestation recorded. | - Each identity can be approved, denied, or flagged - Decision recorded with reviewer ID and timestamp - Completion % updates | P2 |

---

## 13. Reports & Exports

### 13.1 Reports (`/reports`)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| RPT-001 | Generate PDF report | 1. Navigate to `/reports` 2. Select report type 3. Click "Generate" | PDF report generated and downloadable. | - `POST /api/reports` creates report - `GET /api/reports/:id/download?format=pdf` returns PDF - PDF contains: posture score, findings, identity summary, compliance status | P1 |
| RPT-002 | Generate CSV export | 1. Select identities 2. Click "Export CSV" | CSV file downloaded with identity data. | - CSV contains all visible columns - Respects current filters - UTF-8 encoding - No sensitive data (secrets, passwords) leaked | P1 |
| RPT-003 | Scheduled reports | 1. Configure weekly report schedule | Reports auto-generated and emailed. | - Schedule saved in settings - Report generated at configured time (Monday 8:00 UTC / 1st of month) - Email delivered to configured recipients - Requires Pro/Trial plan | P2 |
| RPT-004 | Report with filters | 1. Apply filters (risk=critical) 2. Generate report | Report reflects applied filters. | - Report title indicates filter applied - Only filtered data included | P2 |

---

## 14. AI Security Copilot

### 14.1 Copilot (`/copilot` or copilot panel)

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| COP-001 | Ask risk question | 1. Open copilot 2. Type "What are the riskiest identities?" | AI returns ranked list of risky identities. | - Response includes identity names, risk scores, risk factors - Data sourced from live DB (not hallucinated) - Response within 15 seconds | P1 |
| COP-002 | Ask blast radius question | 1. Type "What's the blast radius of admin@company.com?" | AI returns blast radius analysis. | - Subscriptions, resource groups, key vaults reachable - Attack paths listed - Remediation suggestions | P1 |
| COP-003 | Ask compliance question | 1. Type "Map our findings to NIST 800-53" | AI maps findings to NIST controls. | - Control IDs referenced (AC-2, AC-6, IA-5) - Gap analysis provided | P2 |
| COP-004 | Rate limiting (Free plan) | 1. Login as Free plan user 2. Make 11 queries | 11th query rate limited. | - First 10 queries succeed - 11th returns rate limit message - Message explains daily limit | P1 |
| COP-005 | Rate limiting (Pro plan) | 1. Login as Pro plan user 2. Make queries | Up to 1000 queries per day allowed. | - Counter tracks per-org daily usage - Resets at UTC midnight | P2 |
| COP-006 | Copilot tenant isolation | 1. Ask about identities 2. Verify response only includes current org's data | No cross-org data in response. | - AI can only access current org's identities - No leakage of other orgs' data | P0 |
| COP-007 | Conversation history | 1. Ask multiple questions 2. Click "History" | Previous conversations listed. | - `GET /api/copilot/conversations` returns history - Click loads previous conversation context | P3 |

---

## 15. Settings — General

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| SET-001 | Update org name | 1. Settings > General 2. Change org name 3. Save | Organization name updated. | - Name appears in header/branding - Name appears on PDF reports | P2 |
| SET-002 | Upload org logo | 1. Settings > General 2. Upload PNG/JPG logo (< 2MB) 3. Save | Logo displayed in header and reports. | - File validated (PNG/SVG/JPG only, max 2MB) - Logo renders correctly in header - Logo appears on PDF exports | P2 |
| SET-003 | Change timezone | 1. Select different timezone 2. Save | Timestamps display in selected timezone. | - Dashboard timestamps reflect timezone - Report timestamps reflect timezone | P3 |
| SET-004 | Change theme | 1. Toggle Dark/Light/System theme | UI theme changes immediately. | - Dark mode: dark backgrounds, light text - Light mode: white backgrounds, dark text - System: follows OS preference | P3 |
| SET-005 | Change password | 1. Enter current password 2. Enter new password (meets policy) 3. Confirm new password 4. Save | Password updated. | - Current password validated - New password meets policy (min 12 chars, complexity) - Confirmation matches - All sessions remain valid | P1 |
| SET-006 | Plan info display (read-only) | 1. View General tab | Current plan, term, activation/expiry dates shown. | - Matches organization's actual plan - Expiry date accurate for Trial plans - No editable fields for plan info | P2 |

---

## 16. Settings — Users

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| USR-001 | List organization users | 1. Settings > Users tab | All org users listed with role and status. | - Username, role, auth provider, status, last login shown - Only users from current org (RLS enforced) | P0 |
| USR-002 | Invite user | 1. Click "Invite User" 2. Enter email and role 3. Submit | Invitation sent. User appears in pending list. | - `POST /api/users` creates pending user - Email sent with invitation link - Role assigned per selection | P0 |
| USR-003 | Change user role | 1. Click role dropdown for a user 2. Select new role | Role updated. | - Admin-only action - Available roles: Admin, Security Admin, Security Analyst, Compliance, Reader - Role change takes effect immediately | P1 |
| USR-004 | Disable user | 1. Toggle user status to disabled | User cannot login. | - `PUT /api/users/:id` with enabled=false - Disabled user's login attempts fail - Existing sessions remain valid until token expiry | P1 |
| USR-005 | Delete user | 1. Click "Delete" on a user 2. Confirm | User removed from organization. | - Confirmation dialog shown - User deleted (or soft-deleted) - Cannot delete self - Cannot delete last admin | P1 |
| USR-006 | Resend invitation | 1. Find pending invitation 2. Click "Resend" | New invitation email sent. | - Previous token invalidated - New token generated and emailed | P2 |
| USR-007 | Revoke invitation | 1. Find pending invitation 2. Click "Revoke" | Invitation cancelled. Token invalidated. | - Token no longer valid for accepting - User removed from pending list | P2 |
| USR-008 | Non-admin cannot manage users | 1. Login as viewer/analyst 2. Navigate to Users tab | Users tab hidden or read-only. | - Role check: only admin can invite/edit/delete users - Non-admin sees read-only list or tab hidden | P0 |
| USR-009 | Filter users | 1. Filter by: Active / Pending / Disabled | Filtered list shown correctly. | - Each tab shows correct subset - Counts per tab accurate | P2 |

---

## 17. Settings — Connections

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| CON-001 | Add Azure connection | 1. Settings > Connections 2. Click "Add Connection" 3. Enter Tenant ID, Client ID, Client Secret 4. Test connection 5. Save | Azure connection created. Subscriptions listed. | - `POST /api/client/connections` succeeds - Connection status: "connected" - Active subscriptions discovered and shown | P0 |
| CON-002 | Test connection failure | 1. Enter invalid Azure credentials 2. Click "Test Connection" | Error message with failure reason. | - "Authentication failed" or "Invalid credentials" - No connection saved - User can correct and retry | P0 |
| CON-003 | Edit connection | 1. Click edit on existing connection 2. Update Client Secret 3. Save | Connection updated. Re-tested. | - Secret encrypted before storage (Fernet) - Connection re-validated - Previous secret zeroed | P1 |
| CON-004 | Delete connection | 1. Click delete on a connection 2. Confirm | Connection removed. Associated data purged. | - Confirmation dialog: "This will delete all discovered data" - `DELETE /api/client/connections/:id` - Discovery data purged for this connection | P1 |
| CON-005 | Trigger manual discovery | 1. Click "Run Discovery" on a connection | Discovery run starts. Progress shown. | - `POST /api/client/connections/:id/discover` - Status updates: running -> completed - Identity count updates after completion | P0 |
| CON-006 | Discovery settings | 1. View/edit discovery settings for connection | Discovery interval configurable. | - Toggle continuous discovery on/off - Set interval (hours) - Settings saved per connection | P2 |
| CON-007 | Connection list display | 1. View connections table | All connections shown with status. | - Cloud provider icon + name - Directory/Tenant ID - Active subs count - Last discovery timestamp - Status (connected/disconnected/error) | P1 |
| CON-008 | Plan limit enforcement | 1. Free plan user: try to add 2nd connection | Blocked: "Free plan allows 1 cloud subscription." | - Limit enforced per plan (Free=1, Trial=5, Pro=unlimited) - Upgrade prompt shown | P1 |

---

## 18. Settings — Notifications

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| NTF-001 | Enable email notifications | 1. Settings > Notifications 2. Toggle email notifications on 3. Enter recipient email 4. Save | Notifications enabled. | - Settings saved - Test email available - Email service status shown | P1 |
| NTF-002 | Test email delivery | 1. Click "Send Test Email" | Test email received by recipient. | - Email sent via SendGrid - Delivery confirmation shown | P2 |
| NTF-003 | Configure notification types | 1. Toggle individual notification types | Only selected notifications sent. | - 6 toggles: secret expiry, drift, critical risk, snapshot failure, completion summary, weekly digest - Each toggleable independently | P2 |
| NTF-004 | Webhook configuration | 1. Add webhook URL 2. Select event types 3. Save | Webhook registered. | - URL validated (HTTPS preferred) - Event types selectable - Webhook appears in list | P1 |
| NTF-005 | Test webhook | 1. Click "Test" on a webhook | Test payload delivered. | - HTTP POST to webhook URL - Response status shown (200=success) - Delivery logged | P2 |
| NTF-006 | Report scheduling (Pro only) | 1. Enable scheduled reports 2. Select frequency (weekly/monthly) 3. Enter recipient | Schedule configured. | - Feature locked for Free plan (greyed out with upgrade CTA) - Trial/Pro plans can configure | P2 |

---

## 19. Settings — Security

### 19.1 API Keys

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| SEC-001 | Create API key | 1. Settings > Security 2. Click "Create API Key" 3. Enter name, select role, set expiry 4. Save | API key generated. Secret shown once. | - Full key shown ONCE (copy-to-clipboard button) - Key prefix stored (ag_xxxx) - Hash stored in DB (not plaintext) - Key usable for API authentication | P0 |
| SEC-002 | API key authentication | 1. Use generated API key in `X-API-Key` header 2. Call `/api/identities` | API returns data for key's org. | - Response scoped to org_id from key - Usage count incremented - Last used timestamp updated | P0 |
| SEC-003 | API key expiry | 1. Create key with 1-day expiry 2. Wait for expiry 3. Use expired key | 401 Unauthorized. | - Key no longer valid - Error: "API key expired" | P1 |
| SEC-004 | Disable API key | 1. Toggle key to disabled | Key no longer authenticates. | - Subsequent API calls with key return 401 - Key can be re-enabled | P1 |
| SEC-005 | Delete API key | 1. Click "Delete" on a key 2. Confirm | Key permanently removed. | - Key no longer authenticates - Removed from list - Cannot be recovered | P1 |
| SEC-006 | API key on admin portal | 1. Use API key to access admin portal endpoint | Blocked. | - API keys only work on client portal - 403 for admin portal endpoints | P1 |

### 19.2 SSO/SAML Configuration

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| SEC-010 | Configure SAML SSO | 1. Settings > Security > SSO 2. Enter IdP metadata URL 3. Click "Fetch & Parse" 4. Save | SAML SSO configured. | - IdP metadata parsed - Entity ID, SSO URL, certificate auto-populated - SP metadata URL displayed for IdP configuration | P1 |
| SEC-011 | SAML login flow | 1. Enable SSO 2. Logout 3. Click "Sign in with SSO" | SAML authentication completes. | - Redirect to IdP login - Assertion consumed and validated - JWT issued - User provisioned (JIT) or matched by email | P1 |
| SEC-012 | Force SSO | 1. Enable "Force SSO" toggle | Password login disabled for org users. | - Login page shows SSO only - No username/password form - Admin bypass still works | P2 |
| SEC-013 | SAML assertion replay | 1. Capture SAML assertion 2. Replay it | Replay detected and rejected. | - 401 response - "SAML authentication failed" error - Warning logged | P1 |
| SEC-014 | Role mapping | 1. Configure SAML group to role mapping | Users assigned roles based on SAML attributes. | - Group "SecurityAdmins" -> role "security_admin" - Mapping applies on each SSO login - Unmapped users get default role | P2 |

---

## 20. Settings — Scoring

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| SCR-001 | Create custom risk rule | 1. Settings > Scoring 2. Click "Add Rule" 3. Configure conditions 4. Set action (force level / adjust points) 5. Save | Rule created and active. | - Rule appears in list - Conditions validated - Max 50 rules per org enforced | P1 |
| SCR-002 | Rule conditions builder | 1. Add condition: Identity Category = service_principal AND Activity Status = inactive | Condition builder works with AND logic. | - Field selector shows all available fields - Operator appropriate for field type - Value input matches field type | P1 |
| SCR-003 | Preview rule impact | 1. Configure rule conditions 2. Click "Preview" | Count of matching identities shown. | - "This rule will affect X identities" - Preview runs against live data - No side effects from preview | P1 |
| SCR-004 | Force level action | 1. Create rule with action "Force Critical" | Matching identities forced to critical risk. | - On next discovery/scoring, matching identities become critical - Overrides calculated score - Rule reason shown on identity detail | P1 |
| SCR-005 | Adjust points action | 1. Create rule with action "+50 points" | Matching identities' scores adjusted. | - Points added to calculated risk score - May change risk level if crossing threshold | P1 |
| SCR-006 | Edit rule | 1. Click edit on existing rule 2. Change conditions 3. Save | Rule updated. | - Previous config replaced - Effective on next scoring cycle | P2 |
| SCR-007 | Delete rule | 1. Click delete on a rule 2. Confirm | Rule removed. | - Rule no longer applied to scoring - Affected identities revert to calculated scores on next run | P2 |
| SCR-008 | Rule priority | 1. Create two conflicting rules with different priorities | Higher priority rule wins. | - Priority 0 = highest - Conflicting rules resolved by priority - Visible priority number in list | P2 |

---

## 21. Settings — Integrations

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| INT-001 | Connect Jira | 1. Settings > Integrations 2. Select Jira 3. Enter URL, API token, Project Key 4. Test & Save | Jira integration connected. | - Test connection validates credentials - Project key validated - Connected badge shown - Findings can create Jira issues | P1 |
| INT-002 | Connect ServiceNow | 1. Select ServiceNow 2. Enter instance URL, Client ID/Secret 3. Test & Save | ServiceNow integration connected. | - OAuth credentials validated - Assignment group validated | P2 |
| INT-003 | Test integration connection | 1. Click "Test Connection" on configured integration | Connection test result shown. | - Success: green badge "Connected" - Failure: red badge with error message - Credentials NOT logged | P1 |
| INT-004 | Disconnect integration | 1. Click "Disconnect" on active integration | Integration removed. | - Credentials deleted - New findings don't create tickets - Existing tickets unaffected | P2 |

---

## 22. Client Billing

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| BIL-001 | Billing page loads | 1. Navigate to `/billing` | Billing information displayed. | - Current plan shown - Active subscriptions count - Projected monthly cost - Invoice history (if any) | P1 |
| BIL-002 | Projected charges accuracy | 1. View projected charges | Charges match calculation. | - Platform fee: $500 (Pro) / $0 (Free) / waived (Trial) - Subscription charges: count x $69/sub - Commitment discount applied if applicable - Tax calculated if configured | P1 |
| BIL-003 | Invoice download | 1. Click download on an invoice | PDF invoice downloaded. | - PDF contains: company info, line items, totals, tax - Professional formatting - Immutable (cannot be modified after generation) | P2 |
| BIL-004 | Trial plan display | 1. Login as Trial plan user 2. View billing | Trial-specific messaging shown. | - "No charges during trial" message - Trial expiry countdown - Upgrade prompt to Pro | P2 |
| BIL-005 | Free plan upgrade prompt | 1. Login as Free plan user 2. View billing | Upgrade options shown. | - Comparison table (Free vs Pro features) - "Upgrade to Pro" CTA | P2 |

---

## 23. Admin Console — Tenants

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| ADM-001 | Tenant list loads | 1. Login as superadmin 2. Navigate to admin console > Clients | All tenants listed. | - Org name, plan, status, user count, license status shown - Only accessible to superadmin/poweradmin | P0 |
| ADM-002 | Create new tenant | 1. Admin > Onboarding 2. Fill org name, plan, credentials 3. Submit | New tenant created. | - Organization record created - Root admin user provisioned - Slug auto-generated - Confirmation with credentials shown | P0 |
| ADM-003 | Edit tenant | 1. Click edit on a tenant 2. Change org name/logo 3. Save | Tenant updated. | - Name change reflected across platform - Logo upload works (max 500KB) | P1 |
| ADM-004 | Suspend tenant | 1. Click suspend on a tenant | Tenant users cannot login. Data preserved. | - All tenant users blocked from login - Discovery jobs paused - Data NOT deleted - Can be reactivated | P1 |
| ADM-005 | Delete tenant | 1. Click delete on a tenant 2. Type org name to confirm | Tenant and all data deleted. | - Confirmation requires typing org name - Organization + all related data cascade deleted - Action logged in admin audit | P0 |
| ADM-006 | Change tenant plan | 1. Admin > Billing 2. Change plan for a tenant (Free -> Pro) | Plan updated. Limits adjusted. | - Feature gates updated immediately - Subscription limits changed - Platform fee applies from next billing cycle | P1 |
| ADM-007 | Reset root password | 1. Click "Reset Root Password" on tenant | Root user password reset. | - New password generated or set - Previous sessions invalidated - Email notification sent to root user | P1 |

---

## 24. Admin Console — Users

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| ADM-010 | Create portal user | 1. Admin > Users 2. Click "Create User" 3. Fill username, role, password | Portal user created. | - User can login to admin console - Role determines admin capabilities | P0 |
| ADM-011 | Portal roles enforcement | 1. Login as each portal role | Access matches role definition. | - superadmin: full access - poweradmin: create/edit clients, no delete, no user mgmt - billing: billing page only (read-only) - reader: overview + monitoring only (read-only) | P0 |
| ADM-012 | Edit portal user | 1. Click edit on portal user 2. Change role 3. Save | Role updated. | - Cannot demote self - Cannot remove last superadmin | P1 |
| ADM-013 | Disable portal user | 1. Disable a portal user | User cannot login to admin. | - Login attempts fail for disabled user - Can be re-enabled | P1 |

---

## 25. Admin Console — Onboarding

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| ADM-020 | Full onboarding flow | 1. Admin > Onboarding 2. Enter org name (auto-slug) 3. Select plan 4. Select industry + compliance framework 5. Select cloud provider 6. Enter root credentials 7. Submit | New client fully provisioned. | - Organization created with plan - Root user created with credentials - Slug unique and valid (no reserved names) - Industry/compliance recorded - Success page with credentials | P0 |
| ADM-021 | Slug validation | 1. Enter org name with special chars | Slug auto-sanitized to lowercase alphanumeric + hyphens. | - Reserved slugs rejected (admin, api, www, etc.) - Duplicate slugs rejected - Preview shows final slug | P1 |
| ADM-022 | Generate password | 1. Click "Generate Password" | Strong random password generated. | - Meets 12+ char policy - Includes uppercase, lowercase, number, special - Copy button works | P2 |
| ADM-023 | Subscription term selection | 1. Select Pro plan 2. Choose 3-year commitment | 25% discount applied. | - Discount percentage shown - Effective rate calculated - Commitment term saved to org | P2 |

---

## 26. Admin Console — Monitoring

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| ADM-030 | Monitoring dashboard loads | 1. Admin > Monitoring | Platform health metrics shown. | - Snapshots today count - Failed snapshots count - Critical/warning health tenants - Job queue depth - API uptime/latency/error rate | P1 |
| ADM-031 | Recent snapshot runs | 1. View snapshot runs table | Recent runs listed with status. | - Org name, status, duration, identity count shown - Failed runs highlighted in red - Running status shown with spinner | P1 |
| ADM-032 | Login sessions | 1. View login sessions table | Active/ended sessions listed. | - Username, org, login time, IP, status shown - Filter by portal (admin/client) - Filter by tenant | P2 |
| ADM-033 | Alerts management | 1. View alerts 2. Acknowledge an alert | Alert marked as acknowledged. | - Severity badge (critical/warning/info) - Alert message and timestamp - Acknowledge action recorded | P2 |

---

## 27. Admin Console — Billing

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| ADM-040 | Billing summary | 1. Admin > Billing | Billing summary with MRR/ARR shown. | - Total MRR calculated from all active orgs - ARR = MRR * 12 - Plan distribution chart - Revenue by cloud provider | P1 |
| ADM-041 | Generate invoice | 1. Select tenant 2. Set period 3. Click "Generate" | Invoice generated with line items. | - Platform fee line item - Per-subscription line items - Discount applied - Tax calculated - Total correct | P1 |
| ADM-042 | Send invoice | 1. Click "Send" on generated invoice | Invoice emailed to org billing contact. | - Email delivered with PDF attachment - Invoice status: "sent" - Delivery logged in action log | P2 |
| ADM-043 | Mark invoice paid | 1. Click "Mark as Paid" on sent invoice | Invoice status updated. | - Status changes to "paid" - Payment date recorded - Action logged | P2 |
| ADM-044 | Override platform fee | 1. Edit tenant platform fee | Custom platform fee applied. | - Override saved per org - Reflected in next invoice - Action logged in admin audit | P2 |

---

## 28. Admin Console — Action Log

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| ADM-050 | Action log displays | 1. Admin > Action Log | All admin actions logged and displayed. | - Timestamp, admin user, action type, target tenant, details, IP - Sorted newest first - Filter by: All / Admin / Billing | P1 |
| ADM-051 | Actions are immutable | 1. Attempt to delete or edit action log entries | Cannot modify audit trail. | - No edit/delete actions available on log entries - Log entries append-only | P1 |
| ADM-052 | Critical actions logged | 1. Perform: delete tenant, plan change, password reset | Each action appears in log. | - Delete tenant: logged with org name and confirming user - Plan change: logged with old/new plan - Password reset: logged with target user ID | P0 |

---

## 29. Multi-Tenant Isolation

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| ISO-001 | RLS isolation — identities | 1. Login as org-A user 2. Query identities API | Only org-A identities returned. | - Zero identities from other orgs - `SET app.current_organization_id` enforced - COUNT matches org-A only | P0 |
| ISO-002 | RLS isolation — discovery runs | 1. Login as org-A user 2. Query discovery runs | Only org-A discovery runs returned. | - No cross-org data leakage | P0 |
| ISO-003 | RLS isolation — anomalies | 1. Login as org-A user 2. Query anomalies | Only org-A anomalies returned. | - No cross-org anomaly data | P0 |
| ISO-004 | RLS isolation — findings | 1. Login as org-A user 2. Query findings | Only org-A findings returned. | - No cross-org finding data | P0 |
| ISO-005 | RLS isolation — remediation | 1. Login as org-A user 2. Query approvals | Only org-A approval requests returned. | - Cannot view/approve other org's remediations | P0 |
| ISO-006 | Direct ID access cross-org | 1. Login as org-A user 2. Try to access org-B identity by ID: `GET /api/v1/identities/:orgB_identity_id` | 403 Forbidden returned (not 404). | - 403 prevents existence leakage - No data from org-B exposed | P0 |
| ISO-007 | JWT token org mismatch | 1. Get JWT for org-A 2. Use on org-B subdomain | 403: "Token organization mismatch" | - Issuer claim validated against host slug - Token rejected for wrong org | P0 |
| ISO-008 | Cross-org copilot isolation | 1. Login as org-A 2. Ask copilot about org-B data | No org-B data in response. | - AI context limited to org-A only - No cross-org data retrieved | P0 |
| ISO-009 | Superadmin impersonation isolation | 1. Superadmin impersonates org-A user | Only org-A data visible during impersonation. | - Impersonation scoped to org-A - 15-minute max duration - Activity logged with impersonator ID | P0 |
| ISO-010 | Connection pool isolation | 1. Rapid concurrent requests from org-A and org-B | Each request sees only its org's data. | - Connection RESET before each checkout - No org_id bleed between requests - Verify with concurrent test tool | P0 |

---

## 30. API Security & Rate Limiting

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| SEC-030 | Unauthenticated access | 1. Call any API endpoint without JWT/API key | 401 Unauthorized. | - No data returned - Error: "Authentication required" - Only health endpoints exempt | P0 |
| SEC-031 | Login rate limiting | 1. Attempt 6+ logins in 1 minute from same IP | 429 Too Many Requests on 6th attempt. | - Rate limit: 5 attempts/min per IP - Retry-After header present - Limit resets after window | P0 |
| SEC-032 | Signup rate limiting | 1. Attempt 4+ signups in 1 minute from same IP | 429 Too Many Requests on 4th attempt. | - Rate limit: 3 attempts/min per IP | P1 |
| SEC-033 | CSRF protection | 1. Send mutating request (POST/PUT/DELETE) without CSRF token | 403 Forbidden. | - CSRF cookie `ag_csrf` validated - Only mutating methods require CSRF - GET requests exempt | P0 |
| SEC-034 | XSS in input fields | 1. Enter `<script>alert(1)</script>` in search/name fields | Script not executed. Input sanitized. | - Input sanitizer strips/blocks XSS patterns - Content-Security-Policy prevents inline scripts - DOMPurify sanitizes output | P0 |
| SEC-035 | SQL injection in search | 1. Enter `' OR '1'='1` in search fields | No SQL injection. Query parameterized. | - Input sanitizer blocks SQL patterns - parameterized queries used (%s placeholders) - No data leak or error | P0 |
| SEC-036 | Security headers present | 1. Check response headers on any page | All security headers set. | - X-Content-Type-Options: nosniff - X-Frame-Options: DENY - X-XSS-Protection: 1; mode=block - Strict-Transport-Security: max-age=31536000; includeSubDomains; preload - Content-Security-Policy: script-src 'self' - Referrer-Policy: strict-origin | P0 |
| SEC-037 | Cookie security flags | 1. Inspect cookies in browser dev tools | Cookies have security flags. | - ag_access: httpOnly=true, Secure=true (prod), SameSite=Lax - ag_refresh: httpOnly=true, Secure=true (prod), SameSite=Lax - ag_csrf: httpOnly=false (readable by JS), SameSite=Lax | P0 |
| SEC-038 | Password not in response | 1. Check all API responses for password fields | No passwords in any response. | - User objects never include password hash - API key secrets shown only once at creation | P0 |
| SEC-039 | Client secret not in response | 1. Check connection/integration API responses | Encrypted secrets never returned in plaintext. | - client_secret fields masked or omitted - Fernet-encrypted values not exposed | P0 |

---

## 31. Performance & Load

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| PRF-001 | Dashboard load time | 1. Login 2. Measure time to full dashboard render | Dashboard loads within 3 seconds. | - First contentful paint < 1.5s - All API calls complete < 3s - No blocking requests | P1 |
| PRF-002 | Identity list (1000+ rows) | 1. Load identity list for org with 1000+ identities | List loads within 3 seconds. Scroll is smooth. | - Pagination works (server-side) - No browser memory issues - Table renders without lag | P1 |
| PRF-003 | Discovery run performance | 1. Trigger discovery for org with 500 identities | Discovery completes within 10 minutes. | - All 13 phases complete - No timeout errors - Summary stats accurate | P2 |
| PRF-004 | Concurrent users | 1. 10 users from same org query simultaneously | All requests succeed. No data corruption. | - No race conditions on connection pool - Org isolation maintained - Response times < 5s | P2 |
| PRF-005 | API response time P95 | 1. Measure P95 response time for common endpoints | P95 < 2 seconds for read endpoints. | - Identity list: < 1s - Identity detail: < 1.5s - Posture score: < 500ms - Dashboard: < 2s | P2 |

---

## 32. Browser & Responsive

| ID | Test Case | Steps | Expected Result | Acceptance Criteria | Priority |
|----|-----------|-------|-----------------|-------------------|----------|
| BRW-001 | Chrome latest | 1. Run full app in Chrome latest | All pages render correctly. | - No layout issues - All interactions work - No console errors | P0 |
| BRW-002 | Firefox latest | 1. Run full app in Firefox latest | All pages render correctly. | - Same as Chrome baseline | P1 |
| BRW-003 | Safari latest | 1. Run full app in Safari latest | All pages render correctly. | - Same as Chrome baseline - SameSite cookie handling verified | P1 |
| BRW-004 | Edge latest | 1. Run full app in Edge latest | All pages render correctly. | - Same as Chrome baseline | P2 |
| BRW-005 | 1920x1080 resolution | 1. View app at full HD | Layout fills screen appropriately. | - No horizontal scroll - Sidebar and content area properly sized | P1 |
| BRW-006 | 1366x768 resolution | 1. View app at common laptop resolution | Layout adapts. No overlap. | - All elements visible - No text truncation in critical areas - Scroll works for content overflow | P2 |
| BRW-007 | Dark mode consistency | 1. Enable dark mode 2. Navigate all pages | Consistent dark theme throughout. | - No white backgrounds on dark mode - Text readable on all pages - Charts/graphs have dark backgrounds | P3 |

---

## Appendix A: Test Data Requirements

| Data | Minimum for Testing |
|------|-------------------|
| Organizations | 2+ (for isolation testing) |
| Users per org | 3+ (admin, analyst, viewer) |
| Identities per org | 50+ (mix of users, SPNs, MIs, guests) |
| Discovery runs | 2+ per org (for drift testing) |
| Risk levels | At least 1 identity per level (critical, high, medium, low) |
| Attack paths | 5+ (various types) |
| Security findings | 10+ (various severities) |
| Anomalies | 5+ (various types) |
| Remediation actions | 5+ (various statuses) |
| Credentials | Mix of healthy, expiring, expired |
| API keys | 2+ per org |
| Webhooks | 1+ configured |

## Appendix B: User Roles for Testing

| Role | Access Level | Test Account Needed |
|------|-------------|-------------------|
| Superadmin (platform) | Full admin console | Yes |
| Poweradmin (platform) | Admin without delete | Yes |
| Billing (platform) | Billing read-only | Yes |
| Reader (platform) | Read-only overview | Yes |
| Admin (org) | Full org settings | Yes |
| Security Admin (org) | Security settings | Yes |
| Security Analyst (org) | View + investigate | Yes |
| Compliance (org) | Compliance reports | Yes |
| Viewer (org) | Read-only dashboard | Yes |

## Appendix C: Test Case Count Summary

| Section | Test Cases |
|---------|-----------|
| Authentication & Account | 41 |
| Onboarding & Setup | 5 |
| CISO Dashboard | 9 |
| Security Command Center | 3 |
| Identity Explorer | 16 |
| Identity Detail | 10 |
| Attack Paths & Blast Radius | 7 |
| Risk & Compliance | 5 |
| Security Findings | 8 |
| Remediation Center | 15 |
| Drift & Anomalies | 6 |
| Governance & Access Reviews | 2 |
| Reports & Exports | 4 |
| AI Copilot | 7 |
| Settings — General | 6 |
| Settings — Users | 9 |
| Settings — Connections | 8 |
| Settings — Notifications | 6 |
| Settings — Security | 14 |
| Settings — Scoring | 8 |
| Settings — Integrations | 4 |
| Client Billing | 5 |
| Admin — Tenants | 7 |
| Admin — Users | 4 |
| Admin — Onboarding | 4 |
| Admin — Monitoring | 4 |
| Admin — Billing | 5 |
| Admin — Action Log | 3 |
| Multi-Tenant Isolation | 10 |
| API Security | 10 |
| Performance | 5 |
| Browser & Responsive | 7 |
| **TOTAL** | **~260 test cases** |

---

*QA Test Case Document — AuditGraph by NexGenix Labs*
*Generated: 2026-05-09*
*Coverage: 74 pages, 610 API endpoints, 32 test sections, ~260 test cases*
