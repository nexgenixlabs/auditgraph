# Migration job image

Bundles backend + migration scripts + (optional) data dumps for one-shot Container Apps Jobs.
See [docs/RUNBOOK.md](../../docs/RUNBOOK.md) for the full deployment flow.

## Data files (gitignored — stage locally before build)

These files are NOT committed (too large / contain real data). Stage them before
running `az acr build`:

| File | How to generate | Required for |
|---|---|---|
| `sandbox_dump.json` | `LOCAL_DSN=... python3 backend/scripts/migrate_to_cloud_dev.py dump --orgs 1,2,9 --out sandbox_dump.json` | `restore` phase |
| `local_cols.json` | `LOCAL_DSN=... python3 backend/scripts/sync_schema_columns.py dump --out local_cols.json` | `sync-schema` phase |
| `local_schema.json` | `DSN=... python3 backend/scripts/schema_dump.py local_schema.json` | `diff-schema` phase |
| `local_schema.sql` | `pg_dump --schema-only --no-owner --no-acl <local_dsn> > local_schema.sql` | `apply-local-schema` / `full-reset` phases |

If a file isn't present, an empty placeholder works for `az acr build` to succeed —
but the corresponding phase will be a no-op / fail at runtime.

## Phases (PHASE env var)

| PHASE | Purpose |
|---|---|
| `reset-db` | DROP + CREATE DATABASE (server admin) |
| `setup-roles` | Create app/admin/legacy roles + grants (server admin) |
| `migrate` | Python DDL + SQL migrations (app admin) |
| `restore` | Load bundled `sandbox_dump.json` (server admin — needs `session_replication_role`) |
| `sync-schema` | Additive ADD COLUMN sync from `local_cols.json` |
| `diff-schema` | Compare `local_schema.json` vs current cloud state |
| `patch-sql` | Run a numeric range of SQL files: `PATCH_FROM=080 PATCH_TO=099` |
| `apply-local-schema` | Apply `local_schema.sql` verbatim (used in full-reset) |
| `full-reset` | reset-db → setup-roles → apply-local-schema (NUCLEAR — wipes everything) |
| `all` | setup-roles → migrate → restore |

See [docs/RUNBOOK.md](../../docs/RUNBOOK.md) and
[docs/cloud-org-cleanup-runbook.md](../../docs/cloud-org-cleanup-runbook.md) for
end-to-end runbooks.
