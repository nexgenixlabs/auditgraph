# AuditGraph Phase 2 Build Log
**Date**: 2026-02-25
**Objective**: Sensitive Data Intelligence + Access Depth

## Tasks
- [x] Task 1: Data classification backend (database + API)
- [x] Task 2: Data classification frontend (tagging UI + inventory)
- [x] Task 3: Identity → Sensitive Resource access mapping
- [x] Task 4: Blast radius calculation + Evidence export
- [x] Task 5: Graph visualization verification
- [x] Task 6: Effective Access v2 improvements
- [x] Task 7: Validation

---

## Task 1: Data Classification Backend

### Database Changes (`database.py`)
Added 6 classification columns to both `azure_storage_accounts` and `azure_key_vaults` ALTER TABLE sections:
- `data_classification` VARCHAR(20) — PHI, PCI, or PII
- `classification_source` VARCHAR(20) — manual, auto_name, auto_tag
- `classification_confidence` VARCHAR(10) — high, medium, low
- `classified_by` VARCHAR(100)
- `classified_at` TIMESTAMPTZ
- `classification_notes` TEXT

### API Endpoints (`handlers.py` + `main.py`)
7 new endpoints added:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/resources/classifications` | List classified resources + stats |
| POST | `/api/resources/<id>/classify` | Manually classify resource |
| DELETE | `/api/resources/<id>/classify` | Remove classification |
| POST | `/api/resources/auto-classify` | Run pattern detection (PHI/PCI/PII) |
| GET | `/api/identities/<id>/sensitive-access` | Which sensitive resources identity can reach |
| GET | `/api/resources/<id>/access-map` | Which identities can access resource |
| GET | `/api/blast-radius/summary` | All identities with sensitive data access |

### Auto-Classification Patterns
- **PHI**: patient, health, medical, hipaa, ehr, emr, clinical, etc.
- **PCI**: payment, card, pci, transaction, billing, stripe, etc.
- **PII**: pii, personal, ssn, employee, hr-data, salary, etc.

### Bug Fix: ID Overlap
`classify_resource()` and `declassify_resource()` now filter by `discovery_run_id = ANY(%s)` to prevent updating stale rows in the wrong table when IDs overlap between `azure_storage_accounts` and `azure_key_vaults`.

---

## Task 2: Data Classification Frontend

### DataSecurity.tsx Changes
- **Sensitive Data Inventory section**: 4 cards (PHI/PCI/PII/Unclassified) with resource counts and identity access counts, clickable to filter
- **Classification column**: Added to resource table between Type and Risk columns
- **Classification filter dropdown**: Filter by PHI/PCI/PII/Unclassified
- **Classify button** in detail panel: Shows current classification or "+ Classify this resource" button
- **Declassify (Remove)** button for already-classified resources
- **Auto-Classify button** in page header
- **Classify modal**: PHI/PCI/PII selector buttons with notes field
- **Blast Radius table**: Shows all identities with sensitive data access, PHI/PCI/PII counts, highest access level, risk badges, clickable rows → identity detail
- **ClassificationBadge** component: Color-coded badges (PHI=red, PCI=amber, PII=blue)

### Backend Enhancement
- `/api/resources` now returns `data_classification` and `classification_source` fields
- New `classification` query parameter filter (PHI, PCI, PII, unclassified)

---

## Task 3: Identity → Sensitive Resource Access Mapping

### IdentityDetail.tsx — Sensitive Access Tab
- New tab `sensitive_access` added (16th tab)
- 4 summary cards: Total Sensitive, PHI count, PCI count, PII count
- Access table: Resource name, Type badge, Classification badge, Access Level badge (Admin/Write/Read), Role, Access Source (direct/resource_group/subscription/root), Risk
- Clickable rows → resource detail
- Empty state with link to Data Security page for classifying

### RBAC Scope Hierarchy Matching
Identity has access to classified resource if role assignment scope matches:
1. Direct resource path match
2. Resource group scope (RG-level)
3. Subscription scope
4. Root scope (`/`)

---

## Task 4: Blast Radius + Evidence Export

### Evidence Package Enhancement
`/api/export/evidence-package` now includes `sensitive_data_access` section with:
- `classified_resource_count`
- `classified_resources` array (name, path, classification, source, risk)
- `by_classification` breakdown

### New Export: Sensitive Data Access Map
`/api/export/sensitive-data` — full sensitive data export with:
- `classified_resources`: All classified resources with metadata
- `access_map`: Identity-to-resource access mappings (who can reach which classified resource via which role)

### Exports.tsx
- New "Sensitive Data Access Map" export card
- Updated HIPAA Evidence Package description to mention sensitive data access

---

## Task 5: Graph Visualization Verification
All 3 graph endpoints verified:
- `/api/identities/<id>/graph-data` — returns valid JSON (200)
- `/api/identities/<id>/attack-paths` — returns valid JSON (200)
- No modifications to graph components — unaffected by classification changes

---

## Task 6: Effective Access v2 Improvements

### IdentityDetail.tsx — Effective Access Tab Enhancement
- **Sensitive Data Exposure banner**: Red-bordered card shows when identity has access to classified resources, with PHI/PCI/PII count badges
- Cross-references data from `/api/identities/<id>/sensitive-access` endpoint
- Lazy-loaded on effective_access or sensitive_access tab selection

---

## Task 7: Validation

| Gate | Test | Result |
|------|------|--------|
| 1 | TypeScript compiles with 0 errors | PASS |
| 2 | Classification API (GET/POST/DELETE + auto) | PASS — all 4 return 200 |
| 3 | Sensitive access API (identity, resource, blast) | PASS — all 3 return 200 |
| 4 | Blast radius counts correct | PASS — 15 identities, 12 PHI, 4 PCI, 3 PII, 4 classified |
| 5 | Evidence export includes sensitive data | PASS — 4 classified resources in package |
| 6 | Classification filter works | PASS — PHI=2, PCI=1, PII=1, unclassified=19 |
| 7 | All 15 endpoints return 200 | PASS |

---

## Files Modified

### Backend (`backend/app/`)
- `database.py` — 6 classification columns on both resource tables
- `api/handlers.py` — 7 new handler functions, enhanced evidence export, classification in resource list, classification filter
- `main.py` — 7 new route registrations, 1 new export type

### Frontend (`frontend/src/`)
- `pages/DataSecurity.tsx` — Sensitive Data Inventory, classification badges, classify modal, blast radius table, auto-classify button, classification filter
- `pages/IdentityDetail.tsx` — Sensitive Access tab (16th tab), Effective Access sensitive data banner, sensitive access lazy fetch
- `pages/Exports.tsx` — Sensitive Data Access Map export card

## Demo Data
4 resources classified for demo:
- `auditgraphstoragetrack` (storage) → PHI
- `aglab-kv-1-jxrdm0pj` (key vault) → PHI
- `tfsabackenddev12345` (storage) → PCI
- `aglab-kv-10-gpzm27wy` (key vault) → PII

15 identities discovered with sensitive data access, highest exposure: Bhupathi Reddy Sangabattula (4 resources, Admin access).
