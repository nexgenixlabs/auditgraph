# AuditGraph – Week 5.1 Summary (Backend/API + Frontend/UI Stabilization)

## Goal
Stabilize the local developer experience and bring the repo closer to “production-grade MVP” standards:
- predictable backend startup
- clean API module layout
- React dashboard running reliably
- database schema aligned with API queries
- remove legacy artifacts and reduce “import-time” side effects

---

## What was wrong earlier

### 1) Import-time DB connections broke tooling
Some modules created DB connections during import (e.g., `db = Database()` at top level).
Impact:
- `python -c "import ..."` fails if DB is not reachable
- unit tests and linters break
- importing handlers/routes triggers DB connection unexpectedly

### 2) Schema mismatch between code and Postgres tables
- API handlers were querying columns that did not exist:
  - `identities.run_id` but schema used `identities.discovery_run_id`
  - `last_signin_datetime` referenced but schema uses different column (`last_sign_in`)

Result:
- `/api/stats`, `/api/identities/:id` initially crashed with `UndefinedColumn`

### 3) Missing table(s) required by API responses
`identity_roles` table didn’t exist initially, causing `/api/identities` failures.

### 4) Frontend dev command confusion
This frontend is CRA (`react-scripts`), so the correct command is:
- `npm start` (not `npm run dev`, unless we add an alias script)

---

## What enhancements we made

### Backend improvements
- Introduced `backend/app/api/handlers.py` and moved legacy endpoints into a clean handler module.
- Ensured env loading is safe for direct imports:
  - handlers load `.env.local` + fallback `.env`
- Ensured DB connections are created on-demand (`_db()`), avoiding import-time DB access.
- Fixed SQL queries to align with schema:
  - `run_id` → `discovery_run_id`
  - updated `/api/stats` query accordingly
- Added DB migration(s) to create missing tables:
  - `identity_roles` table added via migration `001_create_identity_roles.sql`
- Confirmed key endpoints:
  - `/api/stats`
  - `/api/identities`
  - `/api/identities/<identity_id>`
  - `/api/risks`

### Frontend improvements
- Confirmed dashboard runs with CRA:
  - `npm install`
  - `npm start`
- (Optional) Add `"dev": "react-scripts start"` alias later for consistency with Vite workflows.

### Repo hygiene improvements
- Standardized `.env.example` placeholder values (`REPLACE_ME`, `0000-...`).
- Removed legacy file:
  - `backend/app/legacy_api.py` deleted (replaced by handlers module)
- Added migrations and scripts folder under backend for repeatable setup.

---

## How to run locally (developer runbook)

### Backend (API)
From repo root:
```bash
cd backend
source venv/bin/activate
./venv/bin/python -m app.main
