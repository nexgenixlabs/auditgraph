# AuditGraph — Dev Environment Setup

> Last updated: 2026-05-02

---

## Local Architecture

```
Frontend (React)   →  localhost:3000
  ├── /api proxy   →  localhost:5001 (backend)
  └── /admin       →  admin portal (same app, different layout)

Backend (Flask)    →  localhost:5001
  └── PostgreSQL   →  localhost:5434
```

---

## Prerequisites

- Python 3.11+
- Node.js 20+
- Docker (for PostgreSQL)
- Git

---

## Database (Docker)

```bash
# Start PostgreSQL
docker run -d \
  --name auditgraph-db \
  -p 5434:5432 \
  -e POSTGRES_DB=auditgraph \
  -e POSTGRES_USER=auditgraph \
  -e POSTGRES_PASSWORD=auditgraph \
  postgres:15
```

Connection details:
- Host: `localhost`
- Port: `5434`
- Database: `auditgraph`
- User: `auditgraph`
- Password: `auditgraph`

---

## Backend

```bash
cd backend

# Create virtualenv
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Environment variables (create .env or export)
export DB_HOST=localhost
export DB_PORT=5434
export DB_NAME=auditgraph
export DB_USER=auditgraph
export DB_PASSWORD=auditgraph
export DB_ADMIN_USER=auditgraph
export DB_ADMIN_PASSWORD=auditgraph
export JWT_SECRET=dev-secret-change-me
export FLASK_ENV=development

# Start server
python -m app.main
# Runs on http://localhost:5001
```

---

## Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start dev server
npm start
# Runs on http://localhost:3000
# Proxies /api to localhost:5001
```

---

## Test Credentials

| Portal | Username | Password | Org | org_id |
|--------|----------|----------|-----|--------|
| Client | `azadmin` | `changeme` | AzureCredits | 2 |
| Client | `demoadmin@auditgraph.ai` | `changeme` | Demo | 3 |
| Admin | `techadmin` | `changeme` | Platform Admin | 1 |

> Note: `nexgenadmin` is a legacy user (org 1, no data) — do NOT use.

---

## Port Reference

| Service | Port | Notes |
|---------|------|-------|
| Frontend | 3000 | Vite/CRA dev server |
| Backend | 5001 | Flask local dev |
| Backend (Docker/prod) | 5000 | Gunicorn in container |
| PostgreSQL | 5434 | Docker mapped (internal 5432) |

---

## Key Environment Variables

| Variable | Dev Value | Purpose |
|----------|-----------|---------|
| `DB_HOST` | localhost | Database host |
| `DB_PORT` | 5434 | Database port |
| `DB_NAME` | auditgraph | Database name |
| `DB_USER` | auditgraph | App user (RLS enforced) |
| `DB_PASSWORD` | auditgraph | App user password |
| `DB_ADMIN_USER` | auditgraph | Admin user (bypasses RLS) |
| `DB_ADMIN_PASSWORD` | auditgraph | Admin user password |
| `JWT_SECRET` | (any string) | JWT signing key |
| `FLASK_ENV` | development | Enables debug mode |
| `DB_SSLMODE` | (unset locally) | Set to `require` in prod |

---

## Seeding Demo Data

After starting the backend, the app auto-creates orgs and users on first boot.
To populate identity/resource data:

```bash
cd backend
python scripts/seed_demo_tenant.py
```

> In production (Azure), this must run from within the VNet (DB has no public access).

---

## Common Issues

1. **Port 5001 in use (macOS)**: AirPlay Receiver uses 5000/5001. Disable in System Settings > General > AirDrop & Handoff.

2. **Database not ready**: Ensure Docker container is running: `docker ps | grep auditgraph-db`

3. **Login deadlock**: If auth hangs, ensure `auth_login()` closes DB connection before calling `generate_refresh_token()`.

4. **Frontend proxy 502**: Backend must be running before frontend can proxy `/api` calls.
