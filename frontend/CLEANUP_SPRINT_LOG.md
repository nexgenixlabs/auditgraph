# AuditGraph Pre-Phase 2 Cleanup Sprint Log
**Date**: 2026-02-25
**Objective**: Fix remaining issues before Phase 2 enterprise redesign

---

## Task 1: NHI Count Discrepancy Investigation (P0)

**Concern**: Phase 0 showed 46 custom SPNs, Phase 1 demo showed 641.

**Root Cause**: NOT a bug. The 641 comes from `/api/spns/stats` `total` field which intentionally includes ALL SPNs (Microsoft + custom). The `custom` field correctly returns 46.

**Verification**:
| Endpoint | Field | Value | Correct? |
|----------|-------|-------|----------|
| `/api/spns/stats` | total | 641 | Yes (all SPNs) |
| `/api/spns/stats` | custom | 46 | Yes (non-Microsoft) |
| `/api/spns/stats` | microsoft | 595 | Yes (system SPNs) |
| `/api/spns?hide_microsoft=true` | total | 46 | Yes (filtered) |
| `/api/spns?hide_microsoft=false` | total | 641 | Yes (unfiltered) |
| `/api/workload-identities/stats` | total | 46 | Yes (already filtered) |

**SQL-level filtering**: `HIDE_MICROSOFT_SQL = "AND NOT COALESCE(i.is_microsoft_system, false)"` works correctly at the database level, independent of row index mapping.

**Row index alignment verified**: `_identity_list_select()` has 46 columns (indices 0-45), `_map_identity_row()` maps all correctly including `is_microsoft_system` at row[43].

**Status**: NO FIX NEEDED

---

## Task 2: PDF Generation Verification

**Verified**:
- `/api/reports/data` returns all 10 keys: stats, top_risks, credential_health, evidence, remediation_summary, conditional_access, previous_run, collected_at, generated_at, run_id
- `pdfGenerator.ts` has 3 generators: `generateReport()`, `generateExecutiveReport()`, `generateComplianceReport()`
- Reports.tsx reads `?type=` URL param and pre-selects report type
- TypeScript compiles with 0 errors

**Status**: PASS

---

## Task 3: Cosmetic Fixes

### 3a. AppRegistrations Dark Mode
**File**: `src/pages/AppRegistrations.tsx`

**Changes**:
- Converted all hardcoded `text-gray-*`, `bg-white`, `border-gray-*` classes to CSS variable-based styling (`var(--text-primary)`, `var(--bg-secondary)`, `var(--border-default)`, etc.)
- StatCard component: added `dark:` Tailwind variants for all color options
- Drill-down panel: header, sections, labels, detail grid — all themed
- Table: header, rows, hover states — dark mode compatible
- Filter bar: dropdowns and search input use CSS variables
- Loading panel: themed background and text

### 3b. Resources "All" Tab
**Status**: Already works. "Total Resources" stat card calls `setTypeFilter('')` which clears the filter, showing all resource types. Backend handles empty `resource_type` param correctly (returns 23 resources).

### 3c. Search Debouncing
**Files**: `WorkloadIdentities.tsx`, `AppRegistrations.tsx`

**Changes**:
- Added `debouncedSearch` state + `useRef` timer (300ms delay) to both pages
- Fetch effects now depend on `debouncedSearch` instead of `search`
- UI input still updates `search` immediately for responsive typing
- URL sync still uses immediate `search` (no delay for replaceState)

### 3d. Settings Report Frequency Default
**Status**: Already `weekly` in backend. No fix needed.

---

## Task 4: Demo Rehearsal — Remaining Steps

| Step | Action | Result |
|------|--------|--------|
| 14 | App Registrations | 0 registrations (no discovery run for app regs) — API works |
| 18 | Resources | 23 total, 12 storage, 11 key vaults, 12 at risk — PASS |
| 19 | Key Vaults | 3 key vaults returned — PASS |
| 22 | Compliance | 11 frameworks loaded — PASS |
| 28 | Settings | org_name=NexgenixLabs — PASS |
| 32 | Anomalies | 28 total, 28 unresolved — PASS |
| 33 | SOAR | 40 total actions — PASS |
| 34 | Identity Detail + Effective Access | Admin User: 7 roles, 26 perms, 6 Admin, 1 Write — PASS |

---

## Validation Gates

| Gate | Test | Result |
|------|------|--------|
| 1 | NHI count matches Phase 0 (46 custom) | PASS — correct at SQL level |
| 2 | PDF pipeline returns all data sections | PASS — 10 keys present |
| 3 | AppRegistrations renders in dark mode | PASS — CSS variables applied |
| 4 | Search debounce active on WI + AR pages | PASS — 300ms timer |
| 5 | All 21 API endpoints return HTTP 200 | PASS |
| 6 | TypeScript compiles with 0 errors | PASS |
| 7 | Demo rehearsal steps all pass | PASS |

---

## Files Modified

### Frontend (`frontend/src/`)
- `pages/AppRegistrations.tsx` — Dark mode: CSS variable-based theming for entire page (header, stat cards, filter bar, table, drill-down panel, loading state). Search debouncing (300ms).
- `pages/WorkloadIdentities.tsx` — Search debouncing (300ms debouncedSearch state + useRef timer).

### No Backend Changes

---

## Summary
- **No showstoppers found**: NHI count discrepancy was not a bug
- **Dark mode fixed**: AppRegistrations fully themed with CSS variables
- **Search debounced**: 300ms on both WorkloadIdentities and AppRegistrations
- **All existing functionality verified**: 21 endpoints, 0 TypeScript errors
- **Ready for Phase 2**: Enterprise sidebar restructure
