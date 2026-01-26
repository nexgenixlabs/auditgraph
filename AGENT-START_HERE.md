# AGENT-START-HERE.md
## AuditGraph (MVP) — Single Source of Truth for All Agents

This file is the **baseline** for anyone working on this repo.  
If you’re an agent making changes, **read this first** and keep your work aligned.

---

## 1) Why we changed the structure (context)

We moved the repo to a **production-grade MVP** layout so:

- There’s **one obvious way to run** backend + frontend
- No “legacy vs new” code confusion
- Clear separation: **API routes vs handler logic**
- DB changes are **tracked via migrations**
- **No secrets** are committed (env examples use placeholders)
- Multiple agents can work without breaking each other

Earlier we had mixed/duplicate patterns and schema mismatches that caused:
- backend errors (missing tables/columns)
- frontend crashes (`toLowerCase()` on undefined)
- “Unknown identity” view due to API response shape mismatch

---

## 2) Current repo layout (what matters)

### Backend
- `backend/app/main.py`  
  **Single backend entrypoint**. Run this for the API service.
- `backend/app/api/routes.py`  
  **Only routing** (Flask blueprint routes).
- `backend/app/api/handlers.py`  
  **All endpoint logic** (DB queries + response shaping).
- `backend/app/database.py`  
  DB connection wrapper.
- `backend/migrations/`  
  SQL migrations (schema tracked here).
- `backend/scripts/`  
  Helper scripts (DB setup, sanity checks, etc.)

### Frontend
- `frontend/src/services/api.ts`  
  Centralized API calls.
- `frontend/src/pages/Identities.tsx`  
  List screen.
- `frontend/src/pages/IdentityDetail.tsx`  
  Detail screen.
- `frontend/package.json`  
  Uses CRA (`react-scripts`). Standard run is `npm start`.

### Docs
- `docs/weekly/week-5.1/`  
  Weekly log / summary for this iteration.

---

## 3) One-true run path (for all agents)

### Backend (Flask)
```bash
cd backend
source venv/bin/activate
set -a; source .env.local; set +a
python -m app.main
Frontend (CRA)
cd frontend
npm install
npm start
Note: CRA default runs on http://localhost:3000

4) Environment rules (no secrets in repo)
.env.local is local only and must be in .gitignore

.env.example / backend/.env.example contain placeholders only

Never commit:

AZURE_CLIENT_SECRET

DB_PASSWORD

tenant/subscription IDs that are sensitive in your org context

If you add docs with command examples, use placeholders like:

REPLACE_ME

00000000-0000-0000-0000-000000000000

5) Data model truth (important for UI + API)
These tables are the sources of roles
role_assignments → Azure RBAC role assignments (subscription/resource group/etc.)

entra_role_assignments → Entra admin roles (Global Admin, etc.)

This table may exist but is currently empty
identity_roles → (legacy-style join table) currently 0 rows in DEV DB

Do not assume identity_roles is populated.

✅ For demo, Identity Detail must aggregate roles from:

role_assignments

entra_role_assignments

6) API response shape contracts (frontend depends on this)
GET /api/identities
Returns:

{
  "run_id": 28,
  "count": 17,
  "identities": [
    {
      "identity_id": "...",
      "display_name": "...",
      "identity_type": "user|service_principal|managed_identity",
      "risk_level": "critical|high|medium|low|info",
      "credential_status": "Valid|Expired|Unknown",
      "credential_expiration": null,
      "created_datetime": null,
      "activity_status": "unknown|active|dormant",
      "role_count": 18
    }
  ]
}
GET /api/identities/<identity_id>
Returns:

{
  "run_id": 28,
  "identity": {
    "identity_id": "...",
    "display_name": "...",
    "identity_type": "...",
    "risk_level": "...",
    "risk_reasons": [],
    "enabled": true,
    "app_id": null,
    "object_id": "...",
    "last_sign_in": null,
    "credential_status": "Valid",
    "credential_expiration": null,
    "activity_status": "unknown",
    "tags": {}
  },
  "roles": [
    {
      "role_name": "...",
      "scope": "...",
      "scope_type": "...",
      "created_on": null,
      "source": "azure_rbac|entra"
    }
  ]
}
Frontend must treat identity detail as:

res.data.identity for the identity

res.data.roles for roles list

7) What we fixed recently (so agents don’t regress)
Backend fixes
Removed legacy_api.py to eliminate duplicate API patterns

Added/standardized handlers in backend/app/api/handlers.py

Fixed schema mismatches:

replaced old run_id usage with discovery_run_id

removed nonexistent column references (e.g., last_signin_datetime)

Added migrations and created missing tables (e.g., identity_roles)

Frontend fixes
Fixed crash: toLowerCase() called on undefined fields

risk level now defaults safely when missing

Fixed “Unknown identity” page

root cause: API detail response shape mismatch (identity wrapper)

Made Identity Detail read roles from response correctly

8) Current stage (MVP Demo)
✅ Stage: Read-only demo

Dashboard loads

Identities list loads

Identity detail loads and renders

Risk badges stable

Roles show (from Azure RBAC + Entra roles)

Top demo polish items (next)
Make dashboard tiles clickable (navigate + filter)

Display Entra roles separately from Azure RBAC roles (grouping + chips)

Add “Top risky identities” list on dashboard

Add Export (CSV) for identities/risks

Add a “Latest discovery run” panel (run id + timestamp + subscription)

9) Working agreement for agents (do/don’t)
DO
Keep backend logic in handlers.py

Keep routing in routes.py

Add DB changes via backend/migrations/

Keep API responses stable (don’t break frontend shape)

DON’T
Re-introduce legacy API patterns

Commit secrets (ever)

Change response shapes without updating frontend + docs together

10) Quick sanity checks (before pushing PR)
Backend API health
curl -s http://localhost:5001/api/health | jq
curl -s http://localhost:5001/api/stats | jq
curl -s http://localhost:5001/api/identities | jq '.count'
curl -s http://localhost:5001/api/identities/<id> | jq '.identity.display_name'
DB sanity
export PGSSLMODE=require
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "select count(*) from identities;"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "select count(*) from role_assignments;"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "select count(*) from entra_role_assignments;"
11) Contact / Owner notes
Owner: Bhupathi
Project: AuditGraph (MVP Demo)

If you’re an agent working on a feature, keep changes minimal, isolated, and aligned to this file.