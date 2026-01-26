.PHONY: help backend frontend api ui dev stop clean

help:
	@echo ""
	@echo "AuditGraph - Local Dev Commands"
	@echo "--------------------------------"
	@echo "make backend   -> setup backend venv + install deps"
	@echo "make api       -> run backend API (Flask) on :5001"
	@echo "make frontend  -> install frontend deps"
	@echo "make ui        -> run frontend UI (React) on :3000"
	@echo "make dev       -> run api + ui (two terminals recommended)"
	@echo "make clean     -> remove backend venv and frontend node_modules"
	@echo ""

backend:
	cd backend && python3 -m venv venv && ./venv/bin/pip install -r requirements.txt

api:
	cd backend && ./venv/bin/python -m app.main

frontend:
	cd frontend && npm install

ui:
	cd frontend && npm run dev

dev:
	@echo "Run these in two terminals:"
	@echo "  Terminal 1: make api"
	@echo "  Terminal 2: make ui"

clean:
	rm -rf backend/venv frontend/node_modules
✅ Outcome: repo looks mature + consistent, and you get a clean “entry point”.

Step 2 — Upgrade root README.md (investor/client friendly)
Replace your root README.md with this:

# AuditGraph

Cloud Identity Security Posture Management (CISPM) — discover and govern human + non-human identities across cloud environments.

## Local Development

### Prereqs
- Python 3.9+
- Node 18+ (recommended)
- Access to a Postgres database (Azure Postgres flexible server or local)

---

## Backend (API)

### 1) Setup
```bash
make backend
2) Configure env
Create backend/.env.local (not committed). Use backend/.env.example as reference.

3) Run API
make api
API runs on:

http://localhost:5001

Health:

http://localhost:5001/api/health

Frontend (UI)
1) Install deps
make frontend
2) Run UI
make ui
UI runs on:

http://localhost:3000

Discovery
Discovery currently runs on-demand (manual trigger / test script).
Automation (scheduled discovery + background jobs) will be added as a future milestone.

Security Notes
Never commit .env.local or any secrets.

Use least-privileged Azure service principals for discovery (read-only).


---

## Step 3 — Confirm env hygiene (quick check)
You should have:
- ✅ `backend/.env.local` (real secrets, ignored)
- ✅ `backend/.env.example` (dummy placeholders only, committed)
- ✅ `.env` at root should be ignored

**Important:** your `backend/.env.example` must NOT contain real secrets. Use placeholders like:
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
DB_PASSWORD=your-password


---

