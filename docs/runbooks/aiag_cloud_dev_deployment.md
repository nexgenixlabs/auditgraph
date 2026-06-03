# AIAG Cloud Dev Deployment — Migrations 120 → 124

**Scope:** Apply the 5 new AIAG migrations to the cloud-dev Postgres (`auditgraph-db-dev`) without dropping anything, then deploy the new backend + frontend images.

**Pre-requisite:** Localhost validation runbook fully passed (`docs/runbooks/aiag_localhost_validation.md`).

---

## ⚠️ Constraints (from project memory)

1. **`deploy-dev.yml` does NOT apply SQL migrations.** API container runs gunicorn only; no `run_migrations` on boot.
2. **Migration image rebuild is BLOCKED locally** — `deploy/migration/Dockerfile` COPYs gitignored data dumps that aren't in the repo. Workaround for additive/idempotent migrations: `backend/scripts/apply_cloud_migration.py` reuses the existing job image with `az rest` command override.
3. **Custom-domain bindings get wiped on every `deploy-dev.yml` run.** After each deploy, re-bind app/admin/api hostnames per the snippet in `MEMORY.md`.
4. **No org data deletion.** Migrations 120-124 are all additive (ADD COLUMN, CREATE TABLE IF NOT EXISTS) — they will not touch any existing rows. **Verify by inspection before applying.**

---

## Step 1 — Verify migrations are additive

```bash
# From repo root
for n in 120 121 122 123 124; do
  echo "=== Migration $n ==="
  grep -E "^(DROP|TRUNCATE|DELETE FROM|UPDATE|ALTER.*DROP|RENAME)" backend/migrations/${n}_*.sql || echo "(no destructive statements found)"
done
```

Expected: only `CREATE TABLE IF NOT EXISTS`, `ALTER TABLE … ADD COLUMN IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`, `DROP POLICY IF EXISTS` (RLS reset before re-create), `CREATE POLICY`, `GRANT`. **No destructive ops on data.**

If anything else appears, **stop and review.**

## Step 2 — Apply via the existing migration job

```bash
cd backend
./venv/bin/python scripts/apply_cloud_migration.py \
  --migration 120_agent_classifications_enrichment.sql \
  --env dev

./venv/bin/python scripts/apply_cloud_migration.py \
  --migration 121_ai_data_reachability.sql \
  --env dev

./venv/bin/python scripts/apply_cloud_migration.py \
  --migration 122_ai_trust_score_history.sql \
  --env dev

./venv/bin/python scripts/apply_cloud_migration.py \
  --migration 123_ai_lifecycle_events.sql \
  --env dev

./venv/bin/python scripts/apply_cloud_migration.py \
  --migration 124_agent_activity_baseline.sql \
  --env dev
```

Each invocation:
1. Reads the SQL file
2. Base64-encodes it (prevents shell from eating `$$ DECLARE` blocks)
3. Starts the existing `migration-migrate` CA Job with an `az rest` command override that pipes the SQL into `psql`
4. Streams logs back

**Verify each migration before proceeding to the next.** If migration 121 fails, do not run 123.

## Step 3 — Verify schema in cloud-dev

```bash
# From any container with VNet access (or via Azure Cloud Shell)
PGPASSWORD=$PGPASSWORD psql \
  -h auditgraph-db-dev.postgres.database.azure.com \
  -U $PGUSER \
  -d auditgraph_dev \
  -c "
    \d agent_classifications
    \d ai_trust_score_history
    \d ai_board_scorecard_snapshots
    \d azure_sql_databases
    \d agent_data_reachability
    \d ai_agent_lifecycle_events
    \d agent_activity_events
    \d agent_behavior_baselines
  " 2>&1 | tail -80
```

Confirm:
- `agent_classifications` has the 3 new columns (`model_name`, `owner_display_name_at_classify`, `account_resource_id`)
- All 9 new tables exist with explicit PKs + sequences (migration 100 regression rule)
- All have RLS policies `tenant_strict_sel/ins/upd/del`

## Step 4 — Deploy backend + frontend

```bash
gh workflow run deploy-dev.yml --ref dev
```

Watch in Actions tab. Build → push to ACR → update CA → ~7 min total.

## Step 5 — Re-bind custom domains (mandatory after every deploy)

Per the documented IaC drift bug:

```bash
RG="cus-ag-nonprod-rg"
ENV="dev-cae"

for app in api app admin; do
  case $app in
    api)   CERT="mc-dev-cae-dev-api-auditgra-9758";   APP="auditgraph-api" ;;
    app)   CERT="mc-dev-cae-dev-app-auditgra-9258";   APP="auditgraph-app" ;;
    admin) CERT="mc-dev-cae-dev-admin-auditg-9066";   APP="auditgraph-admin" ;;
  esac
  az containerapp hostname bind \
    -n "$APP" -g "$RG" \
    --hostname "dev.${app}.auditgraph.ai" \
    --environment "$ENV" \
    --certificate "$CERT"
done
```

Verify: `curl -I https://dev.api.auditgraph.ai/api/health` should return `200`, not `ERR_CONNECTION_RESET`.

## Step 6 — Verify the 9 new endpoints serve

```bash
# Get a dev token via the login endpoint
TOKEN=$(curl -s -X POST https://dev.api.auditgraph.ai/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"techadmin","password":"changeme"}' \
  | jq -r .access_token)

for ep in \
  "/api/ai-security/board-scorecard" \
  "/api/data-security" \
  "/api/dashboard/ai-jml-snapshot" \
  "/api/ai-agents/activity/anomalies" \
  "/api/attack-paths?source_entity_type=ai_agent"; do
  echo -n "$ep -> "
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Authorization: Bearer $TOKEN" \
    "https://dev.api.auditgraph.ai$ep"
done
```

Expected: all `200`.

## Step 7 — Trigger discovery against `virtuallabs`

```bash
# Get tenant token
TENANT_TOKEN=$(curl -s -X POST https://dev.api.auditgraph.ai/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"<virtuallabs-admin>","password":"<password>"}' \
  | jq -r .access_token)

curl -X POST https://dev.api.auditgraph.ai/api/runs/trigger \
  -H "Authorization: Bearer $TENANT_TOKEN"
```

Wait for completion (~10-15 min depending on AI surface size). Then revisit the screens in the original screenshots — they should populate with real data instead of 404s.

## Rollback plan

If any migration fails:
1. **Do not** run subsequent migrations.
2. The failed migration is in `BEGIN; ... COMMIT;` — it rolls back automatically on syntax error.
3. If a CREATE TABLE succeeded but later policies fail: the table exists empty with RLS not enabled — fine, no data leak risk.
4. To fully revert: `DROP TABLE IF EXISTS <table>` is safe since these are all net-new and unused until backend deploys.
5. Roll back backend deploy: `az containerapp revision activate --name auditgraph-api --revision <prior-revision>`.

## After successful deploy

- Update [polish_plan_100m.md](polish_plan_100m.md) noting AIAG Tier 1+2+3 are live in dev.
- Take screenshots of the working pages and add to the Confluence release notes.
- Schedule the founder Trust Score threshold review (see `docs/runbooks/trust_score_thresholds_proposal.md`).
