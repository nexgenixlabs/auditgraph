# Phase 11 — Final Information Architecture Consolidation

## Target Route Tree (5 Sections)

### COMMAND CENTER (`#2563eb`)
- Executive Posture → `/`
- Risk Monitoring → `/dashboard`
- Drift History → `/drift`
- Remediation Plan → `/remediation`

### IDENTITY TRUTH (`#8b5cf6`)
- Identity Inventory → `/identities`
- Non-Human Identities → `/workload-identities`
- Privileged Access → `/service-accounts`

### ACCESS EXPLAINABILITY (`#0891b2`)
- Access Graph → `/access-graph`
- Effective Access Explorer → `/effective-access`
- Sensitive Data Access → `/sensitive-access`
- Role Optimization → `/role-mining`
- Secrets & Keys → `/key-vaults`
- Storage Exposure → `/storage-accounts`

### EVIDENCE (`#ca8a04`)
- Compliance Evidence → `/compliance`
- Access Reviews → `/access-reviews`
- Snapshots → `/reports`
- Export Center → `/exports`

### PLATFORM (`#64748b`)
- Connectors → `/settings/connections` (admin only)
- Audit Log → `/activity`
- Tenant Settings → `/settings/general` (admin only)

---

## Old → New Mapping

| Old Section | Old Label | New Section | New Label | Route |
|-------------|-----------|-------------|-----------|-------|
| Command Center | Risk Dashboard | Command Center | Executive Posture | `/` |
| Command Center | Risk Monitoring | Command Center | Risk Monitoring | `/dashboard` |
| Operations | Drift & Changes | Command Center | Drift History | `/drift` |
| Remediation | Action Plan | Command Center | Remediation Plan | `/remediation` |
| Identity | Identity Inventory | Identity Truth | Identity Inventory | `/identities` |
| _(not in sidebar)_ | — | Identity Truth | Non-Human Identities | `/workload-identities` |
| Governance | Governance Coverage | Identity Truth | Privileged Access | `/service-accounts` |
| Access Explainability | Access Graph | Access Explainability | Access Graph | `/access-graph` |
| Access Explainability | Effective Access Explorer | Access Explainability | Effective Access Explorer | `/effective-access` |
| Access Explainability | Sensitive Data Access | Access Explainability | Sensitive Data Access | `/sensitive-access` |
| Governance | Role Optimization | Access Explainability | Role Optimization | `/role-mining` |
| Data Security | Secrets & Keys | Access Explainability | Secrets & Keys | `/key-vaults` |
| Data Security | Storage Exposure | Access Explainability | Storage Exposure | `/storage-accounts` |
| Compliance | Frameworks & Controls | Evidence | Compliance Evidence | `/compliance` |
| Governance | Access Reviews | Evidence | Access Reviews | `/access-reviews` |
| Operations | Reports | Evidence | Snapshots | `/reports` |
| Compliance | Evidence Center | Evidence | Export Center | `/exports` |
| _(not in sidebar)_ | — | Platform | Connectors | `/settings/connections` |
| Operations | Activity Log | Platform | Audit Log | `/activity` |
| _(bottom section)_ | Settings | Platform | Tenant Settings | `/settings/general` |

---

## Dissolved Sections

| Old Section | Items Moved To |
|-------------|---------------|
| Governance | Identity Truth, Access Explainability, Evidence |
| Remediation | Command Center |
| Data Security | Access Explainability |
| Compliance | Evidence |
| Operations | Command Center, Evidence, Platform |

---

## Routes NOT in Sidebar (Still Functional in App.tsx)

These routes remain fully accessible via deep links, modals, or other UI entry points:

- `/integration-guide` — Cloud Integration Guide (reachable from onboarding/settings)
- `/identities/:id` — Identity Detail (deep link from identity tables)
- `/identities/compare` — Identity Comparison (deep link)
- `/workload-identities/:id` — Workload Identity Detail (deep link)
- `/identity-correlation` — Identity Correlation (deep link)
- `/groups` — Identity Groups (deep link)
- `/resources` — Resources (deep link)
- `/resources/detail` — Resource Detail (deep link)
- `/subscriptions` — Subscriptions (deep link)
- `/invoices` — Invoices (deep link)
- `/notifications` — Notification Center (bell icon in header)
- `/analytics` — Cross-Tenant Analytics (deep link)
- `/spns` → redirect to `/workload-identities?type=spn`
- `/app-registrations` → redirect to `/workload-identities?type=app_reg`
- `/rbac-hygiene` → redirect to `/effective-access`
- `/data-security` → redirect to `/sensitive-access`
- `/login` — Login page
- `/sso-callback` — SSO callback
- `/admin` — Admin portal (separate layout)

---

## Confirmation

No routes were deleted from `App.tsx`. Only the sidebar rendering in `Sidebar.tsx` was changed:
- 8 sections → 5 sections
- Bottom "Settings" link removed (now "Tenant Settings" inside PLATFORM section)
- All existing logic preserved: collapsed state, locked state, admin-only guards, active highlighting
- Admin-only guard applied to "Connectors" and "Tenant Settings" via conditional spread in items array

---

# Phase 12 — CISODashboard Modularization

## Summary

Extracted presentational JSX blocks from `CISODashboard.tsx` into 8 separate component files. Zero logic, API, UI structure, or behavioral changes. All data still flows from the parent via props.

## Line Count

| File | Lines |
|------|------:|
| `CISODashboard.tsx` (before) | 2,682 |
| `CISODashboard.tsx` (after) | 1,968 |
| **Extracted lines** | **714** |

## New File Structure

```
frontend/src/components/dashboard/
├── ciso-shared.tsx                                  (171 lines)
│   └── FONT, ScoreRing, Sparkline, CISOBadge, ProgressBar,
│       StatBox, SectionTitle, CISOCard, DN, pillarNav
├── executive/
│   ├── ExecutiveMetrics.tsx                          (77 lines)
│   │   └── 5-card metric grid (AGIRS ring, Total, Privileged, NHI, T0)
│   ├── HumanIdentityRiskTable.tsx                   (35 lines)
│   │   └── HIRI 5-factor breakdown card
│   ├── PhantomExposureTable.tsx                     (36 lines)
│   │   └── NHIRI phantom exposure card
│   └── GovernanceEffectivenessTable.tsx             (52 lines)
│       └── GEI progress bars + "Not configured" links
├── risk/
│   ├── RiskMonitoringTab.tsx                        (119 lines)
│   │   └── Full Tab 2: Risk Pillars + KPIs + Blast Radius
│   └── RiskMovementTab.tsx                          (149 lines)
│       └── Full Tab 6: Trajectory + Movement + Consequences + Scan Meta
└── compliance/
    └── ComplianceTab.tsx                            (170 lines)
        └── Full Tab 5: Frameworks + Export + Maturity + Progress
```

**Total across 8 extracted files: 809 lines**

## Component → Import Mapping

| Old Inline Component | New Import | Used In |
|---------------------|-----------|---------|
| `FONT`, `ScoreRing`, `Sparkline`, `CISOBadge`, `ProgressBar`, `StatBox`, `SectionTitle`, `CISOCard`, `DN`, `pillarNav` | `ciso-shared.tsx` | CISODashboard + all extracted components |
| 5-card metric grid (inline JSX in ExecSummaryTab) | `ExecutiveMetrics` | ExecSummaryTab |
| `HIRIBreakdownCard` | `HumanIdentityRiskTable` | ExecSummaryTab |
| `PhantomExposureCard` | `PhantomExposureTable` | ExecSummaryTab |
| `GEICard` | `GovernanceEffectivenessTable` | ExecSummaryTab |
| `IdentityRiskTab` | `RiskMonitoringTab` | renderTab() case 'risk' |
| `RiskMovementTab` (inline) | `RiskMovementTab` (imported) | renderTab() case 'movement' |
| `ComplianceEvidenceTab` | `ComplianceTab` | renderTab() case 'compliance' |

## What Stayed in CISODashboard.tsx

- `MiniComplianceCard`, `Gauge` (unused, retained for future use)
- `PreviewChangesPanel`, `CreateTicketModal`, `RemediationCard` (action-plan UI)
- `buildEmptyData`, `useCISOData` (data hook + empty state)
- `AGIRSScoreTriad`, `DangerousIdentitiesCard`, `HeroPanel` (unused, retained)
- `RiskDriverRow`, `ExposureMetricRow`, `ActionQueueItem`, `GovernanceRow` (sub-row helpers)
- `AutoFixDialog` (modal)
- `ExecSummaryTab`, `ActionPlanTab`, `ControlGovernanceTab` (tabs 1, 3, 4)
- `remediationNav` (navigation helper used by action-plan components)
- Main `CISODashboard` component + tab config

## Confirmation

- **Zero behavioral change** — all data flows, UI rendering, navigation, and interactivity are identical
- **Zero new abstractions** — `ciso-shared.tsx` is a mechanical relocation of existing code
- **Zero new hooks** — tab-level components retain their existing hooks; extracted executive components have no hooks (except GovernanceEffectivenessTable which retains its existing `useNavigate`)
- **Zero circular imports** — shared helpers in `ciso-shared.tsx` break the dependency cycle
- **TypeScript**: `npx tsc --noEmit` passes with zero errors

---

# Phase 13 — Snapshot Terminology Alignment

## Summary

Frontend-only abstraction layer so the UI never references "discovery", "scan", or "run" terminology. All user-facing strings now use "snapshot" language. Zero backend changes — no API routes, database tables, JSON field names, or auth logic were modified.

## Type Alias & API Wrappers

### `types/index.ts`
```ts
export type Snapshot = DiscoveryRun;
export type SnapshotsResponse = RunsResponse;
```

### `services/api.ts`
```ts
export const getSnapshots = async () => { ... };      // calls GET /runs
export const triggerSnapshot = async () => { ... };    // calls POST /runs/trigger
export const getSnapshotById = async (id) => { ... };  // calls GET /runs/:id/drift
/** @deprecated Use getSnapshots() instead */
export const getRuns = getSnapshots;
```

## Files Modified (22 files)

| File | Old String(s) | New String(s) |
|------|---------------|---------------|
| `components/StaleDataBanner.tsx` | "Discovery data is … old. Run a new discovery to refresh." | "Snapshot data is … old. Capture a new snapshot to refresh." |
| `components/ScanScheduleManager.tsx` | "Scan Schedules", "Loading scan schedules…", "Delete this scan schedule?", "No scan schedules configured. Add one to automate discovery." | "Snapshot Schedules", "Loading snapshot schedules…", "Delete this snapshot schedule?", "No snapshot schedules configured. Add one to automate snapshots." |
| `components/overview/ExecutiveRiskHeader.tsx` | "Last scan:" | "Last snapshot:" |
| `components/overview/DataIntegrityFooter.tsx` | "Last Scan", "Scan Duration" | "Last Snapshot", "Snapshot Duration" |
| `components/ui/DataQualityRibbon.tsx` | "Last scan:" | "Last snapshot:" |
| `components/dashboard/PostureScore.tsx` | "vs previous run" | "vs previous snapshot" |
| `components/StatsCard.tsx` | "+N from last run", "N fewer than last run", "No change from last run" | "+N from last snapshot", "N fewer than last snapshot", "No change from last snapshot" |
| `pages/NotificationCenter.tsx` | discovery_completed label: "Discovery" | "Snapshot" |
| `constants/design.ts` | "Platform & Discovery" | "Platform & Snapshots" |
| `utils/displayHelpers.ts` | "No scan completed" | "No snapshot captured" |
| `components/dashboard/risk/RiskMovementTab.tsx` | "No scan completed" | "No snapshot captured" |
| `utils/pdfGenerator.ts` | "Discovery Summary", "Trend vs previous run:", "Identity Discovery: Enumerate…", "from previous scan", "Days Since Scan" | "Snapshot Summary", "Trend vs previous snapshot:", "Identity Enumeration: Enumerate…", "from previous snapshot", "Days Since Snapshot" |
| `pages/Dashboard.tsx` | `discoveryRunning` (variable), `triggerDiscovery` (function) | `snapshotRunning`, `triggerSnapshot` |
| `pages/Identities.tsx` | `discoveryRuns` / `setDiscoveryRuns` (state) | `snapshots` / `setSnapshots` |
| `pages/DriftHistory.tsx` | `expandedRunId` / `toggleRow`, CSV headers "Current Run" / "Previous Run" | `expandedSnapshotId` / `toggleSnapshot`, "Current Snapshot" / "Previous Snapshot" |
| `pages/Settings.tsx` | "Discovery Completed", "Save & Run First Discovery", "Discovery Schedule", "Next run:", "Discovery Interval", "How often the discovery engine scans…", "Last scan:" / "No scan yet", "Scan Complete" / "Scan Failed", "identity discovery" | "Snapshot Completed", "Save & Capture First Snapshot", "Snapshot Schedule", "Next snapshot:", "Snapshot Interval", "How often a snapshot is captured…", "Last snapshot:" / "No snapshot yet", "Snapshot Complete" / "Snapshot Failed", "identity snapshots" |
| `pages/OnboardingWizard.tsx` | "Configure Discovery", "Discovery Frequency" (×2), "Saving & Starting Discovery…", "Complete Setup & Start Discovery" | "Configure Snapshots", "Snapshot Frequency" (×2), "Saving & Capturing First Snapshot…", "Complete Setup & Start Snapshot" |
| `pages/IdentityDetail.tsx` | "in previous run" (×2 tooltips) | "in previous snapshot" |
| `pages/admin/AdminMonitoring.tsx` | "discovery status", "Discovery Freshness", "Next run:" | "snapshot status", "Snapshot Freshness", "Next snapshot:" |
| `pages/SystemHealth.tsx` | "Next run:" | "Next snapshot:" |
| `pages/CrossTenantAnalytics.tsx` | "Last Discovery" | "Last Snapshot" |
| `pages/DataSecurity.tsx` | "Scanning…" | "Classifying…" |
| `pages/Overview.tsx` | "Last Scan", "No scan data" (×2) | "Last Snapshot", "No snapshot data" |
| `pages/CISODashboard.tsx` | "Azure RBAC scan", "No scan data" (×2) | "Azure RBAC", "No snapshot data" |

## Backend JSON Fields Preserved (NOT renamed)

These backend field names remain untouched throughout the frontend:

- `total_discovery_runs`, `latest_run`, `previous_run`, `current_run_id`
- `discovery_interval_hours`, `last_discovery_at`, `retention_discovery_days`
- `discovery_triggered`, `discovery_completed` (event keys)
- `next_run` (scheduler field)
- `run_completed_at`, `current_run_id`, `previous_run_id`
- `last_discovery` (cross-tenant analytics field)

## Confirmation

- **Zero behavioral change** — all API calls hit the same endpoints, all state logic is identical
- **Zero backend modifications** — no routes, tables, JSON shapes, or auth logic changed
- **Zero circular imports** — `types/index.ts` does not import from `services/api.ts`
- **TypeScript**: `npx tsc --noEmit` passes with zero errors

---

# Phase 14 — Risk Projection Panel

## Summary

Enterprise-grade Risk Projection panel added to the **Risk Movement tab only**. Shows projected AGIRS improvement if top remediation items are applied. No animations, no gradients, no pulse effects, no hero graphics, no call-to-action buttons, no auto-fix workflows.

## New File

```
frontend/src/components/dashboard/risk/RiskProjectionPanel.tsx  (113 lines)
```

## Modified File

```
frontend/src/components/dashboard/risk/RiskMovementTab.tsx
  + import { RiskProjectionPanel } from './RiskProjectionPanel';
  + <RiskProjectionPanel d={d} /> placed after Scan Metadata card
```

## Layout

**Section title**: "Risk Projection (If Top Remediations Applied)"

**Two-column card grid**:

| Left Card | Right Card |
|-----------|------------|
| Current AGIRS Score | Projected AGIRS Score |
| Numeric value (28pt mono) | Numeric value (28pt mono) |
| Tier label | Tier label |
| "Latest snapshot" | "+X.X improvement" (green) |

**Table below** (top 5 remediation items sorted by gain descending):

| Column | Source |
|--------|--------|
| Issue | `r.title` |
| Affected | `r.affected` (drillable to /identities) |
| Risk Contribution | `r.gain / totalGain × 100` (percentage) |
| Projected Impact | `+r.gain pts` |

## Data Source

All data from existing `TenantData` — no new backend APIs:
- `d.riskScore.current` / `d.riskScore.tier` — current AGIRS
- `d.projection.remediated.score` / `d.projection.remediated.tier` — projected AGIRS
- `d.remediations[]` — remediation items with `title`, `affected`, `gain`

## Graceful Hiding

Panel returns `null` (hidden entirely) when:
- `d.remediations.length === 0` — no remediation data available
- `totalGain <= 0` — no positive improvement possible

## Confirmation

- **No duplication** — Executive Posture tab does not render this panel
- **No UI clutter** — single card with table, uses existing CISO design tokens
- **No new state management** — pure presentational component, data from parent props
- **No animations/gradients/pulse** — confirmed via grep (zero matches)
- **No new backend APIs** — uses existing `d.remediations` and `d.projection`
- **No behavioral changes** — remediation engine untouched
- **TypeScript**: `npx tsc --noEmit` passes with zero errors

---

# Phase 15 — Enterprise Readiness Audit Sweep

**Date**: 2026-02-27
**Type**: Read-only audit — no changes implemented.

---

## 1. Remaining Gradients

| # | File | Line | Code | Severity | Proposed Correction |
|---|------|------|------|----------|---------------------|
| 1 | `components/overview/ExecutiveRiskHeader.tsx` | 60 | `background: 'var(--gradient-hero)'` | Medium | CSS variable `--gradient-hero` is undefined. Replace with solid background color or remove. |

**Total**: 1 finding. No `linear-gradient()`, `bg-gradient-to-*`, or Tailwind gradient classes found anywhere.

---

## 2. Remaining Animations (duration > 200ms)

| # | File | Line | Code | Severity | Proposed Correction |
|---|------|------|------|----------|---------------------|
| 1 | `pages/CISODashboard.tsx` | 1931 | `animation: 'pulse 2s infinite'` (green status dot) | Medium | Replace with static dot — no pulse on data displays. |
| 2 | `components/dashboard/risk/RiskMonitoringTab.tsx` | 77 | `animation: 'pulse 2s infinite'` (red alert dot) | Medium | Replace with static dot or remove. |
| 3 | `components/PillarDrilldownPanel.tsx` | 102 | `animation: 'pillarSlideIn 0.25s ease'` (panel slide) | Low | 250ms slide-in on panel open. Borderline — acceptable for panel transitions. |
| 4 | `App.css` | 12 | `animation: App-logo-spin infinite 20s linear` | Low | Legacy CRA boilerplate. Guarded by `prefers-reduced-motion`. Remove dead CSS. |

**Acceptable** (not flagged): `animate-spin` on loading spinners (14+ instances), `animate-pulse` on skeleton placeholders (13+ instances), `animate-bounce` on CopilotPanel typing indicator (1 instance). All are functional, brief-duration UX patterns.

---

## 3. Pulse Effects

| # | File | Line | Severity | Proposed Correction |
|---|------|------|----------|---------------------|
| 1 | `pages/CISODashboard.tsx` | 1931 | Medium | Same as §2 #1 — replace with static dot. |
| 2 | `components/dashboard/risk/RiskMonitoringTab.tsx` | 77 | Medium | Same as §2 #2 — replace with static dot. |

---

## 4. Duplicated Metric Displays Across Tabs

| # | Metric | Tabs Where Displayed | Severity | Proposed Correction |
|---|--------|---------------------|----------|---------------------|
| 1 | Identity counts (Critical, High, Total) | ExecSummaryTab (`ExecutiveMetrics`), RiskMonitoringTab (KPI cards), RiskMovementTab (movement table) | Low | Acceptable — each tab shows a different perspective (summary vs KPIs vs deltas). No action needed. |

**No true duplicates found.** AGIRS/HIRI/NHIRI/GEI are isolated to ExecSummaryTab. Risk score is isolated to RiskMovementTab. Remediation totals are isolated to ActionPlanTab. Compliance scores are isolated to ComplianceTab.

---

## 5. Pages Rendering Snapshot Data Without Immutable Badge

| # | File | Severity | Proposed Correction |
|---|------|----------|---------------------|
| 1 | `pages/Compliance.tsx` | Medium | Add "Data as of {snapshot_date}" header. |
| 2 | `pages/ServiceAccountGovernance.tsx` | Medium | Add snapshot context indicator. |
| 3 | `pages/AppRegistrations.tsx` | Medium | Fetches snapshot ID (line 427) but does not display it. Add badge. |
| 4 | `pages/Resources.tsx` | Medium | Fetches snapshot ID (line 165) but does not display it. Add badge. |
| 5 | `pages/SPNDashboard.tsx` | Medium | Fetches snapshot ID (line 495) but does not display it. Add badge. |
| 6 | `pages/CrossTenantAnalytics.tsx` | Medium | No snapshot context indicator. |
| 7 | `pages/RbacHygiene.tsx` | Medium | No snapshot context indicator. |
| 8 | `pages/SensitiveDataAccess.tsx` | Medium | No snapshot context indicator. |
| 9 | `pages/EffectiveAccessExplorer.tsx` | Medium | No snapshot context indicator. |
| 10 | `pages/DataSecurity.tsx` | Medium | No snapshot context indicator. |
| 11 | `pages/KeyVaultSecurity.tsx` | Medium | No snapshot context indicator. |
| 12 | `pages/StorageSecurity.tsx` | Medium | No snapshot context indicator. |
| 13 | `pages/RoleMining.tsx` | Medium | No snapshot context indicator. |
| 14 | `pages/AccessReviews.tsx` | Medium | No snapshot context indicator. |
| 15 | `pages/RemediationCenter.tsx` | Low | No snapshot context indicator. |

**Pages WITH snapshot context** (compliant): Dashboard.tsx, Identities.tsx, DriftHistory.tsx, Overview.tsx, CISODashboard.tsx, Reports.tsx, IdentityDetail.tsx (partial), SystemHealth.tsx (partial).

**Coverage**: 8 of 23 data-driven pages (35%) have snapshot context indicators.

---

## 6. Pages Missing Snapshot Context Indicator

Same as §5 above. 15 pages lack any "Data as of", "Last snapshot:", or freshness indicator.

---

## 7. Remaining "run", "scan", or "discovery" User-Facing Strings

| # | File | Line | String | Severity | Proposed Correction |
|---|------|------|--------|----------|---------------------|
| 1 | `pages/Overview.tsx` | 1011 | `"Scan coverage: {N}% subs"` | High | → "Snapshot coverage" |
| 2 | `components/dashboard/RiskVelocityChart.tsx` | 65 | `"Identity flow between risk levels per run"` | High | → "per snapshot" |
| 3 | `pages/IdentityDetail.tsx` | 2262 | `"Runs Observed"` | High | → "Snapshots Observed" |
| 4 | `constants/pricing.ts` | 24 | `"Detect configuration drift and identity changes between scans"` | Medium | → "between snapshots" |
| 5 | `pages/Documentation.tsx` | 57 | `"…settings, users, scans, exports…"` | Medium | → "snapshots" |
| 6 | `pages/Settings.tsx` | 1593 | `"Run data cleanup now?"` | Low | Context is data retention, not discovery. "Run" here means "execute". Acceptable — no change needed. |
| 7 | `pages/Settings.tsx` | 4052 | `"Run Cleanup Now"` | Low | Same as above — "Run" means "execute". Acceptable. |
| 8 | `components/overview/DataIntegrityFooter.tsx` | 39 | `"Total Scanned"` | Medium | → "Total Captured" or "Identities Captured" |

---

## 8. Unused Components After Phase 12

### Dead code in CISODashboard.tsx (5 components, never rendered):

| # | Component | Lines | Severity | Proposed Correction |
|---|-----------|-------|----------|---------------------|
| 1 | `MiniComplianceCard` | 47–73 | Low | Delete — never rendered. |
| 2 | `Gauge` | 75–102 | Low | Delete — never rendered. |
| 3 | `AGIRSScoreTriad` | 1125–1212 | Low | Delete — never rendered. |
| 4 | `DangerousIdentitiesCard` | 1214–1265 | Low | Delete — never rendered. |
| 5 | `HeroPanel` | 1267–1365 | Low | Delete — never rendered. |

### Unused exported component files (never imported anywhere):

| # | File | Severity |
|---|------|----------|
| 1 | `components/overview/GlobalRiskCards.tsx` | Low |
| 2 | `components/overview/CloudComparison.tsx` | Low |
| 3 | `components/overview/CategoryRiskGrid.tsx` | Low |
| 4 | `components/overview/CriticalIdentitiesList.tsx` | Low |
| 5 | `components/overview/InsightsPanel.tsx` | Low |
| 6 | `components/overview/ExecutiveRiskHeader.tsx` | Low |
| 7 | `components/overview/AttackSurfaceRadar.tsx` | Low |
| 8 | `components/overview/AttackOpportunitySnapshot.tsx` | Low |
| 9 | `components/overview/RiskReductionPlan.tsx` | Low |
| 10 | `components/overview/RiskMovementPanel.tsx` | Low |
| 11 | `components/overview/GovernanceMaturityIndicators.tsx` | Low |
| 12 | `components/overview/DataIntegrityFooter.tsx` | Low |
| 13 | `components/overview/CompliancePostureSummary.tsx` | Low |
| 14 | `components/dashboard/RiskVelocityChart.tsx` | Low |
| 15 | `components/dashboard/CustomizePanel.tsx` | Low |
| 16 | `components/dashboard/RiskDonutChart.tsx` | Low |
| 17 | `components/dashboard/CloudContextBanner.tsx` | Low |
| 18 | `components/dashboard/ConditionalAccessCard.tsx` | Low |
| 19 | `components/dashboard/AnomalyAlerts.tsx` | Low |
| 20 | `components/dashboard/IdentityCorrelationWidget.tsx` | Low |
| 21 | `components/dashboard/ServiceAccountGovernance.tsx` | Low |
| 22 | `components/dashboard/RemediationProgress.tsx` | Low |
| 23 | `components/dashboard/PostureScore.tsx` | Low |
| 24 | `components/dashboard/PlatformHealth.tsx` | Low |
| 25 | `components/dashboard/RoleUsageChart.tsx` | Low |
| 26 | `components/dashboard/ComplianceScorecard.tsx` | Low |
| 27 | `components/dashboard/RiskTrendChart.tsx` | Low |
| 28 | `components/dashboard/QuickActions.tsx` | Low |
| 29 | `components/dashboard/SOARActivity.tsx` | Low |
| 30 | `components/dashboard/RecentChanges.tsx` | Low |
| 31 | `components/dashboard/RiskHeatMap.tsx` | Low |
| 32 | `components/dashboard/CredentialHealth.tsx` | Low |
| 33 | `components/ConnectionSwitcher.tsx` | Low |
| 34 | `components/UpgradeGate.tsx` | Low |

**Total unused**: 5 inline + 34 files = **39 dead components**.

---

## 9. Dead Routes Not Reachable from UI

| # | Route | Component | Severity | Proposed Correction |
|---|-------|-----------|----------|---------------------|
| 1 | `/integration-guide` | `CloudIntegrationGuide` | Low | Add link from Settings → Connectors or remove route. |
| 2 | `/groups` | `IdentityGroups` | Medium | Add to sidebar or link from Identities page. |
| 3 | `/invoices` | `Invoices` | Low | Add link from Subscriptions/Billing or remove route. |

All other 41 routes are reachable via sidebar, links, redirects, or deep-link patterns.

---

## 10. Tables Not Following Standard (text-xs, px-3 py-2, uppercase headers)

| # | File | Line | Issue | Severity | Proposed Correction |
|---|------|------|-------|----------|---------------------|
| 1 | `pages/AccessReviews.tsx` | 753 | Inline styles with `padding: '8px 8px'` instead of `px-3 py-2.5`. | Low | Convert to Tailwind `px-3 py-2`. |
| 2 | `pages/RbacHygiene.tsx` | 573 | Inline styles with `fontSize: 13` (text-sm equivalent, not text-xs). | Low | Change to `fontSize: 12` or Tailwind `text-xs`. |
| 3 | `pages/CrossTenantAnalytics.tsx` | 237 | Uses `text-sm` (14px) instead of `text-xs` (12px). | Low | Change to `text-xs`. |

**Compliant tables**: Identities.tsx, ActivityLog.tsx, Resources.tsx, AppRegistrations.tsx — all follow text-xs + px-3 py-2 + uppercase headers.

---

## 11. Inconsistent Section Color Usage

**No inconsistencies found.** All 5 sidebar section colors match the Phase 11 specification exactly:

| Section | Expected | Actual (Sidebar.tsx) | Status |
|---------|----------|---------------------|--------|
| Command Center | `#2563eb` | `#2563eb` | Match |
| Identity Truth | `#8b5cf6` | `#8b5cf6` | Match |
| Access Explainability | `#0891b2` | `#0891b2` | Match |
| Evidence | `#ca8a04` | `#ca8a04` | Match |
| Platform | `#64748b` | `#64748b` | Match |

No other components hardcode section colors outside the sidebar.

---

## 12. Pages Exceeding 1500 Lines

| # | File | Lines | Severity | Proposed Correction |
|---|------|------:|----------|---------------------|
| 1 | `pages/Settings.tsx` | 5,206 | High | Extract tab sections into separate components (Connections, Notifications, Integrations, etc.) |
| 2 | `pages/IdentityDetail.tsx` | 3,299 | High | Extract tab contents (13 tabs) into separate component files. |
| 3 | `pages/Overview.tsx` | 2,450 | High | Extract sections (hero, pillars, identity grid, footer) into components. |
| 4 | `pages/CISODashboard.tsx` | 1,968 | Medium | Already reduced from 2,682 in Phase 12. Further extraction of remaining 5 inline tabs possible. |
| 5 | `pages/Identities.tsx` | 1,827 | Medium | Extract query builder, table, and filter sections. |

---

## Audit Summary

| Category | Findings | High | Medium | Low |
|----------|------:|-----:|-------:|----:|
| 1. Gradients | 1 | 0 | 1 | 0 |
| 2. Animations > 200ms | 4 | 0 | 2 | 2 |
| 3. Pulse effects | 2 | 0 | 2 | 0 |
| 4. Duplicated metrics | 0 | 0 | 0 | 0 |
| 5. Missing immutable badge | 15 | 0 | 14 | 1 |
| 6. Missing snapshot context | 15 | 0 | 14 | 1 |
| 7. "run/scan/discovery" strings | 8 | 3 | 3 | 2 |
| 8. Unused components | 39 | 0 | 0 | 39 |
| 9. Dead routes | 3 | 0 | 1 | 2 |
| 10. Non-standard tables | 3 | 0 | 0 | 3 |
| 11. Inconsistent colors | 0 | 0 | 0 | 0 |
| 12. Pages > 1500 lines | 5 | 3 | 2 | 0 |
| **TOTAL** | **95** | **6** | **39** | **50** |
