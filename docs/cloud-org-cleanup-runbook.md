# Cloud Dev — Org Cleanup & Re-enrollment Runbook

**Purpose:** Complete removal of an organization and all its data from the **cloud dev** PostgreSQL before a fresh re-enrollment. Mirrors the local docker runbook but adapted for the VNet-only Azure deployment.

**Last verified:** May 2026 — cloud schema matches local sandbox (154 tables, 470 indexes).

**Critical context — what's different from local:**
- The PG server `cus-ag-nonprod-pg` is **VNet-only**; nothing outside the VNet can reach it. All cleanup scripts must run inside a **Container Apps Job** in `dev-cae`.
- The migration image (`cusagnonprodcr.azurecr.io/auditgraph-migration:<tag>`) bundles the same `backend/scripts/*` scripts the local runbook uses. We invoke them via job phases.
- "Restart services" means `az containerapp revision restart`, not `kill flask`.
- Browser cleanup is the same (Cmd+Shift+Delete for `auditgraph.ai`).

---

## Inventory

| Resource | Value |
|---|---|
| PG host | `cus-ag-nonprod-pg.postgres.database.azure.com` |
| Database | `auditgraph_dev` |
| Server admin | `auditgraph_dev_eastus2` (Azure-managed) |
| App admin role | `auditgraph_dev_admin` (BYPASSRLS) |
| App role | `auditgraph_dev_app` (NOBYPASSRLS, RLS-scoped) |
| Resource group | `cus-ag-nonprod-rg` |
| Container Apps env | `dev-cae` |
| Migration job | `migration-migrate` |
| ACR | `cusagnonprodcr.azurecr.io` |
| Client portal | `https://dev.app.auditgraph.ai` |
| Admin portal | `https://dev.admin.auditgraph.ai` |
| API | `https://dev.api.auditgraph.ai` |

---

## Pre-reqs (one-time)

```bash
az login
az account set --subscription "AzureSponsorshipCredit"

# Verify access
az containerapp job show -g cus-ag-nonprod-rg -n migration-migrate --query 'name' -o tsv
# expected: migration-migrate
```

---

## Step 0 — Find the Org

Cloud doesn't have a shell on the DB host. Run a list query via the migrate job using the same pattern we've used throughout (`patch-sql` phase + a temporary SQL file shipped in the image).

### Option A — Use bundled `999_list_users.sql` (lists all orgs + users)

```bash
az containerapp job update -g cus-ag-nonprod-rg -n migration-migrate \
  --set-env-vars PHASE=patch-sql PATCH_FROM=999 PATCH_TO=999 \
  --query 'name' -o tsv

EXEC=$(az containerapp job start --name migration-migrate -g cus-ag-nonprod-rg --query 'name' -o tsv | tail -1)
echo "exec: $EXEC"
until s=$(az containerapp job execution show -g cus-ag-nonprod-rg -n migration-migrate \
  --job-execution-name "$EXEC" --query 'properties.status' -o tsv); \
  [ -n "$s" ] && [ "$s" != "Running" ]; do sleep 8; done
echo "status: $s"

# Output appears in Log Analytics
WS_ID=$(az monitor log-analytics workspace show -g cus-ag-nonprod-rg -n cus-ag-nonprod-law --query customerId -o tsv)
az monitor log-analytics query -w "$WS_ID" --analytics-query \
  "ContainerAppConsoleLogs_CL | where ContainerName_s == 'migration-migrate' and TimeGenerated > ago(3m) and Log_s contains 'org=' | order by TimeGenerated asc | project Log_s" \
  -o tsv | tail -20
```

### Option B — Raw SELECT against PG (if you have psql in-VNet)

Connect from a VM inside `dev-vnet` and run:

```sql
SELECT id, name, slug, is_demo FROM organizations ORDER BY id;
```

---

## Step 1 — Delete the Org (`nuke_org.py` via CA Job)

The migration image already bundles `backend/scripts/nuke_org.py`. We run it via a dedicated phase.

> The bundled run.sh in the migration image currently doesn't have a `nuke-org` phase — add it once (see [§Appendix: adding nuke-org/verify-org phases](#appendix-adding-nuke-org--verify-org-phases-to-runsh)) and rebuild the image. After that, the workflow below is one-shot.

### Dry run first (always)

```bash
az containerapp job update -g cus-ag-nonprod-rg -n migration-migrate \
  --set-env-vars PHASE=nuke-org NUKE_ORG_ID=11 NUKE_DRY_RUN=1 \
  --query 'name' -o tsv

EXEC=$(az containerapp job start --name migration-migrate -g cus-ag-nonprod-rg --query 'name' -o tsv | tail -1)
until s=$(az containerapp job execution show -g cus-ag-nonprod-rg -n migration-migrate \
  --job-execution-name "$EXEC" --query 'properties.status' -o tsv); \
  [ -n "$s" ] && [ "$s" != "Running" ]; do sleep 8; done
echo "$s"

# Show what would have been deleted
sleep 25
az monitor log-analytics query -w "$WS_ID" --analytics-query \
  "ContainerAppConsoleLogs_CL | where ContainerName_s == 'migration-migrate' and TimeGenerated > ago(5m) | order by TimeGenerated asc | project Log_s" \
  -o tsv | tail -60
```

### Actual deletion (force mode — no interactive confirmation in CA Job)

```bash
az containerapp job update -g cus-ag-nonprod-rg -n migration-migrate \
  --set-env-vars PHASE=nuke-org NUKE_ORG_ID=11 NUKE_DRY_RUN=0 NUKE_FORCE=1 \
  --query 'name' -o tsv

EXEC=$(az containerapp job start --name migration-migrate -g cus-ag-nonprod-rg --query 'name' -o tsv | tail -1)
until s=$(az containerapp job execution show -g cus-ag-nonprod-rg -n migration-migrate \
  --job-execution-name "$EXEC" --query 'properties.status' -o tsv); \
  [ -n "$s" ] && [ "$s" != "Running" ]; do sleep 8; done
echo "nuke status: $s"
```

**What the script does** (same as local):
1. Inventories all 131 org-scoped tables
2. Disables immutability triggers on audit tables
3. Deletes rows FK-safe order (deepest children first, `organizations` row last)
4. Single transaction — rolls back on any error
5. Re-enables triggers after commit

---

## Step 2 — Verify & Fix (`verify_org_cleanup.py` via CA Job)

**Always run this after deletion.** Catches any leaks from tables added since `nuke_org.py` was last updated.

### Verify only

```bash
az containerapp job update -g cus-ag-nonprod-rg -n migration-migrate \
  --set-env-vars PHASE=verify-org VERIFY_ORG_ID=11 VERIFY_FIX=0 \
  --query 'name' -o tsv

az containerapp job start --name migration-migrate -g cus-ag-nonprod-rg --query 'name' -o tsv | tail -1
```

### Verify + auto-fix leaks

```bash
az containerapp job update -g cus-ag-nonprod-rg -n migration-migrate \
  --set-env-vars PHASE=verify-org VERIFY_ORG_ID=11 VERIFY_FIX=1 \
  --query 'name' -o tsv
EXEC=$(az containerapp job start --name migration-migrate -g cus-ag-nonprod-rg --query 'name' -o tsv | tail -1)
until s=$(az containerapp job execution show -g cus-ag-nonprod-rg -n migration-migrate \
  --job-execution-name "$EXEC" --query 'properties.status' -o tsv); \
  [ -n "$s" ] && [ "$s" != "Running" ]; do sleep 8; done
echo "verify status: $s"

# Output
sleep 25
WS_ID=$(az monitor log-analytics workspace show -g cus-ag-nonprod-rg -n cus-ag-nonprod-law --query customerId -o tsv)
az monitor log-analytics query -w "$WS_ID" --analytics-query \
  "ContainerAppConsoleLogs_CL | where ContainerName_s == 'migration-migrate' and TimeGenerated > ago(5m) and (Log_s contains 'CHECK' or Log_s contains 'LEAK' or Log_s contains 'PASS' or Log_s contains 'CLEAN' or Log_s contains 'RESULT') | order by TimeGenerated asc | project Log_s" \
  -o tsv | tail -40
```

The same **5 deep checks** as local:
1. Org record removed
2. Deep scan of all 154 tables (`organization_id`, `org_id`, `target_organization_id`, FK chains)
3. Orphan scan (rows in child tables whose parent identity/run was deleted)
4. Stale refresh tokens
5. Materialized views / caches

---

## Step 3 — Restart API + Clear Browser

The local runbook restarts Flask + React. Cloud equivalent:

```bash
LATEST=$(az containerapp revision list -g cus-ag-nonprod-rg -n auditgraph-api \
  --query "[?properties.active].name | [0]" -o tsv | tail -1)
az containerapp revision restart -g cus-ag-nonprod-rg -n auditgraph-api --revision "$LATEST"

# Wait for ready
until [ "$(curl -sS https://dev.api.auditgraph.ai/api/health --max-time 5 2>/dev/null | \
  python3 -c 'import sys,json; print(json.load(sys.stdin).get("status",""))' 2>/dev/null)" = "ready" ]; do
  sleep 5
done
echo "API ready"
```

**Browser cleanup (mandatory):**
- Chrome DevTools → Application → Clear Storage (select `auditgraph.ai`)
- Or: Cmd+Shift+Delete → Cookies + Site Data → past hour
- Hard refresh: Cmd+Shift+R

---

## Step 4 — Re-enroll

| Method | URL | Plan |
|---|---|---|
| **Self-signup** (Recommended) | `https://dev.app.auditgraph.ai/signup` | Free (500 identities, 2 subs) or Trial (unlimited, 30 days) |
| **Admin portal** | `https://dev.admin.auditgraph.ai` → Create Org | Pro |

---

## Full workflow (one block)

```bash
ORG=11
WS_ID=$(az monitor log-analytics workspace show -g cus-ag-nonprod-rg -n cus-ag-nonprod-law --query customerId -o tsv)

# 1. List orgs
az containerapp job update -g cus-ag-nonprod-rg -n migration-migrate \
  --set-env-vars PHASE=patch-sql PATCH_FROM=999 PATCH_TO=999 -o none
az containerapp job start --name migration-migrate -g cus-ag-nonprod-rg -o none
# wait + view in LAW

# 2. Dry-run nuke
az containerapp job update -g cus-ag-nonprod-rg -n migration-migrate \
  --set-env-vars PHASE=nuke-org NUKE_ORG_ID=$ORG NUKE_DRY_RUN=1 -o none
az containerapp job start --name migration-migrate -g cus-ag-nonprod-rg -o none

# 3. Actual delete
az containerapp job update -g cus-ag-nonprod-rg -n migration-migrate \
  --set-env-vars PHASE=nuke-org NUKE_ORG_ID=$ORG NUKE_DRY_RUN=0 NUKE_FORCE=1 -o none
az containerapp job start --name migration-migrate -g cus-ag-nonprod-rg -o none

# 4. Verify + fix
az containerapp job update -g cus-ag-nonprod-rg -n migration-migrate \
  --set-env-vars PHASE=verify-org VERIFY_ORG_ID=$ORG VERIFY_FIX=1 -o none
az containerapp job start --name migration-migrate -g cus-ag-nonprod-rg -o none

# 5. Restart API
LATEST=$(az containerapp revision list -g cus-ag-nonprod-rg -n auditgraph-api \
  --query "[?properties.active].name | [0]" -o tsv | tail -1)
az containerapp revision restart -g cus-ag-nonprod-rg -n auditgraph-api --revision "$LATEST"

# 6. Clear browser (Cmd+Shift+Delete), hard refresh (Cmd+Shift+R)
# 7. Re-enroll at https://dev.app.auditgraph.ai/signup
```

---

## Coverage — same as local (May 2026 baseline)

The cloud DB schema was rebuilt from a `pg_dump --schema-only` of local sandbox on 2026-05-20. Coverage is identical:
- 131 tables with `organization_id`
- 1 table `org_id` (`copilot_usage`)
- 1 table `target_organization_id` (`admin_audit_log`)
- 3 FK-only tables (`pim_activations`, `pim_eligible_assignments`, `graph_snapshots`)
- 18 global reference tables (skipped)
- 4 ad-hoc tables patched in after schema dump: `federated_credentials`, `identity_lineage_bindings`, plus the column-sync deltas

Refer to the local runbook for the full table list and column-name reference table — they're identical.

---

## Known leak sources

Same as local (May 2026 list). All fixed in current `nuke_org.py`:
- `discovered_resources` (14,232 rows on org=11)
- `identity_reachability` (6,012)
- `workload_attributions` (1,593)
- `federated_credentials` (448)
- `privilege_drift_events` (129)
- `identity_arm_connections`, `identity_exposures`, `connector_permissions` (new tables, 0 rows but watched)

**Cloud-specific extras to watch** (added after schema dump):
- `federated_credentials` — covered by 203 migration
- `identity_lineage_bindings` — covered by 984 patch

---

## Cloud-specific gotchas

| Symptom | Cause | Fix |
|---|---|---|
| `nuke-org` job fails with "permission denied" on `azure_pg_admin` setting | Script uses `session_replication_role` to disable triggers; only server admin has this on Azure PG | Run the job with `SERVER_ADMIN_USER` / `SERVER_ADMIN_PASSWORD` env vars (see Appendix), not the app admin role |
| Long-running scheduler holding locks during delete | The API replicas are running and may hold locks on identity/discovery_runs tables | Deactivate API revision before delete: `az containerapp revision deactivate -g cus-ag-nonprod-rg -n auditgraph-api --revision <name>`; reactivate after |
| LAW logs missing for the exec | Ingestion delay (typically 30-60s) | Wait, re-query with `TimeGenerated > ago(10m)` |
| API health 503 after restart | DB pool warm-up | First request takes ~2-5s; subsequent ones <200ms |
| Cookies not clearing | Cookies are `Domain=auditgraph.ai` (covers all subdomains) | Clear cookies for the apex domain, not just the subdomain |
| Re-signup hits "username taken" | User row leaked (rare — verify script should catch) | Manually run a `DELETE FROM users WHERE username='...'` via patch-sql phase |

---

## Demo Day flow (cloud edition)

### Day-before (dry run)

```bash
ORG=<your-test-org-id>
az containerapp job update -g cus-ag-nonprod-rg -n migration-migrate \
  --set-env-vars PHASE=nuke-org NUKE_ORG_ID=$ORG NUKE_DRY_RUN=0 NUKE_FORCE=1 -o none
az containerapp job start --name migration-migrate -g cus-ag-nonprod-rg -o none
# ... verify-org, restart API ...
# Signup at https://dev.app.auditgraph.ai/signup → Trial → enter Azure creds
# Wait ~9 min for scan
# Walk demo script end-to-end
# DO NOT scan again before demo day
```

### Demo day (live)

```bash
ORG=<demo-org-id>
az containerapp job update -g cus-ag-nonprod-rg -n migration-migrate \
  --set-env-vars PHASE=nuke-org NUKE_ORG_ID=$ORG NUKE_DRY_RUN=0 NUKE_FORCE=1 -o none
az containerapp job start --name migration-migrate -g cus-ag-nonprod-rg -o none
# (wait ~30s for nuke)
az containerapp job update -g cus-ag-nonprod-rg -n migration-migrate \
  --set-env-vars PHASE=verify-org VERIFY_ORG_ID=$ORG VERIFY_FIX=1 -o none
az containerapp job start --name migration-migrate -g cus-ag-nonprod-rg -o none

LATEST=$(az containerapp revision list -g cus-ag-nonprod-rg -n auditgraph-api --query "[?properties.active].name | [0]" -o tsv | tail -1)
az containerapp revision restart -g cus-ag-nonprod-rg -n auditgraph-api --revision "$LATEST"

# In front of client: https://dev.app.auditgraph.ai/signup → Trial
# Enter Azure credentials → watch progress modal (~9 min)
```

### Fallback: Demo Org (org=9)

If a live demo signup fails, fall back to the pre-seeded demo:
- Login: `demoadmin` / `changeme` at `https://dev.app.auditgraph.ai`
- Re-seed if needed (idempotent): trigger `migration-migrate` with PHASE=patch-sql + a seeded SQL OR sign-up a fresh tenant.

---

## Scan health checks post-enrollment

Use the same SQL as local, run via patch-sql phase with a temp file:

```sql
-- Replace <org_id>
SELECT
  (SELECT COUNT(*) FROM identities WHERE organization_id = <org_id>) AS identities,
  (SELECT COUNT(*) FROM security_findings WHERE organization_id = <org_id> AND severity='critical') AS critical_findings,
  (SELECT COUNT(*) FROM agent_classifications ac JOIN identities i ON i.id = ac.identity_db_id WHERE i.organization_id = <org_id>) AS ai_agents,
  (SELECT COUNT(*) FROM entra_role_assignments WHERE organization_id = <org_id>) AS entra_roles,
  (SELECT total_duration_seconds/60.0 FROM discovery_runs WHERE organization_id = <org_id> AND status='completed' ORDER BY started_at DESC LIMIT 1) AS scan_minutes;
```

**Expected:** identities 1000+, critical_findings 8–15, ai_agents 70+, entra_roles 50+, scan_minutes < 10.

---

## Appendix: adding `nuke-org` + `verify-org` phases to run.sh

The cloud migration image needs these phases added to `deploy/migration/run.sh`. Append once, rebuild the image, then the workflow above works.

```bash
run_nuke_org() {
  log "Phase: nuke-org (org_id=$NUKE_ORG_ID dry_run=$NUKE_DRY_RUN force=$NUKE_FORCE)"
  : "${DB_HOST:?}"; : "${DB_NAME:?}"
  : "${SERVER_ADMIN_USER:?required — script needs to disable immutability triggers}"
  : "${SERVER_ADMIN_PASSWORD:?required}"
  : "${NUKE_ORG_ID:?required}"
  export DB_HOST DB_PORT="${DB_PORT:-5432}" DB_NAME DB_SSLMODE="${DB_SSLMODE:-require}"
  export DB_ADMIN_USER="$SERVER_ADMIN_USER" DB_ADMIN_PASSWORD="$SERVER_ADMIN_PASSWORD"
  cd /app/backend
  ARGS="--org-id $NUKE_ORG_ID"
  [ "$NUKE_DRY_RUN" = "1" ] && ARGS="$ARGS --dry-run"
  [ "$NUKE_FORCE" = "1" ]   && ARGS="$ARGS --force"
  python3 scripts/nuke_org.py $ARGS
  ok "nuke-org done"
}

run_verify_org() {
  log "Phase: verify-org (org_id=$VERIFY_ORG_ID fix=$VERIFY_FIX)"
  : "${VERIFY_ORG_ID:?required}"
  : "${SERVER_ADMIN_USER:?required}"
  : "${SERVER_ADMIN_PASSWORD:?required}"
  export DB_HOST DB_PORT="${DB_PORT:-5432}" DB_NAME DB_SSLMODE="${DB_SSLMODE:-require}"
  export DB_ADMIN_USER="$SERVER_ADMIN_USER" DB_ADMIN_PASSWORD="$SERVER_ADMIN_PASSWORD"
  cd /app/backend
  ARGS="--org-id $VERIFY_ORG_ID"
  [ "$VERIFY_FIX" = "1" ] && ARGS="$ARGS --fix"
  python3 scripts/verify_org_cleanup.py $ARGS
  ok "verify-org done"
}
```

Add to the `case "$PHASE"` block:
```bash
nuke-org)    run_nuke_org ;;
verify-org)  run_verify_org ;;
```

Rebuild + push:
```bash
cp deploy/migration/run.sh /tmp/migration-build/deploy/migration/run.sh
cd /tmp/migration-build && az acr build \
  --registry cusagnonprodcr --image auditgraph-migration:v39 \
  --file deploy/migration/Dockerfile --platform linux/amd64 .
```

Then update the migration job image to `:v39`. Note that you also need to make sure the secrets `server-admin-pwd` is set on the job — and pass `SERVER_ADMIN_USER` / `SERVER_ADMIN_PASSWORD` env vars (they were on the job during full-reset; verify with `az containerapp job show ... --query 'properties.template.containers[0].env[].name'`).

---

## Differences vs local runbook (quick reference)

| Action | Local | Cloud |
|---|---|---|
| Find org | `python3 scripts/nuke_org.py --list` | `PHASE=patch-sql PATCH_FROM=999 PATCH_TO=999` via CA Job |
| Delete org | `python3 scripts/nuke_org.py --org-id N` | `PHASE=nuke-org NUKE_ORG_ID=N NUKE_FORCE=1` via CA Job |
| Verify + fix | `python3 scripts/verify_org_cleanup.py --org-id N --fix` | `PHASE=verify-org VERIFY_ORG_ID=N VERIFY_FIX=1` via CA Job |
| Restart API | `kill flask; flask run --port 5001 &` | `az containerapp revision restart -g cus-ag-nonprod-rg -n auditgraph-api --revision <name>` |
| Restart frontend | `cd frontend && npm start` | not needed (static nginx, auto-reload) |
| Re-enroll URL | `localhost:3000/signup` | `https://dev.app.auditgraph.ai/signup` |
| Clear cookies for | `localhost:3000` | apex `auditgraph.ai` (Domain= scope) |
