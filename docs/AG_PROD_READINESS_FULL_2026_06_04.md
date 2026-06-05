# AuditGraph — Production Readiness Report

Audit scope: commits b6e3766..15ae68b (Tier 1–4 AI-ISPM features), migrations 204–210, 5 new frontend pages, ~10 new endpoints in `backend/app/api/handlers.py`, and 6 new AI engines in `backend/app/engines/ai/`.

Date: 2026-06-04
Branch: dev
Auditor: production-readiness sub-agent

---

## Executive Summary

**Verdict: NO-GO for further customer-facing production deployments until the CRITICAL findings are remediated. Cloud-dev push is acceptable and expected.**

The feature work is well-architected — clear module boundaries, fixed catalogs, evidence-based scoring, defensible breach-cost sourcing. Code quality of the new AI engines is genuinely high (small functions, docstrings explaining "why", no TODO/FIXME debt). The PR-gate workflow, dual JWT secrets, bcrypt rounds=12, statement timeouts, CSP, strict CORS validation, and the existing RLS + auto-tenant trigger framework are best-in-class.

However, three production-blocking issues prevent customer-facing deployment:

1. **Multi-tenant RLS gap on 6 new org-scoped tables.** Migrations 204–210 add `ai_model_approvals`, `agent_invocations`, `ai_supply_chain_components`, `ai_supply_chain_links`, `threat_signals`, `threat_connectors` with `organization_id` columns but NO `ENABLE ROW LEVEL SECURITY` / policy statements. Migration 091 dynamically wires RLS for org-scoped tables but is tracked in `schema_migrations` and never re-runs. Net effect: when these migrations are applied, the new tables remain wide open — any tenant connecting as `auditgraph_app` can read every other tenant's row.
2. **Unauthenticated/unverified webhook ingest at `POST /api/ai-security/threat-signals`.** The migration even comments "partners HMAC-sign their webhooks" and stores `webhook_secret` on `threat_connectors`, but the handler reads no signature header and dispatches the body straight to vendor adapters. The endpoint is also `app.before_request(auth_middleware)`-protected so a partner couldn't post anyway without a session — meaning it's both insecure AND non-functional for its declared purpose.
3. **Zero automated test coverage and zero CI test gate for new modules.** `pr-gate.yml` runs only title-check, hardcoded-secret scan, and `tsc --noEmit`. No pytest, no lint (`npm run lint` is `echo`), no migration smoke test. Nothing for `abuse_scenarios.py`, `findings.py`, `multihop_xgraph.py`, `supply_chain.py`, `threat_connectors.py`, `model_registry.py`, `breach_cost.py` (~3000 LOC of new production logic).

Recommended go path: fix the 3 above; add ~10 unit tests for the engines and a multi-tenant integration test for RLS on the new tables; document the webhook auth path. Estimated ~2–3 engineering days.

---

## Findings by Severity

### CRITICAL (must fix before customer prod)

- **C-1. No RLS on 6 new multi-tenant tables.** Files: `backend/migrations/206_ai_model_registry.sql`, `208_agent_invocations.sql`, `209_ai_supply_chain.sql`, `210_threat_signals.sql`. None of these emit `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` or `CREATE POLICY`. Migration `091_rls_all_tables.sql` would cover them but `scripts/run_migrations.py` skips it if its version is recorded in `schema_migrations`. Confirmed: `grep -E "ENABLE ROW LEVEL SECURITY|CREATE POLICY" backend/migrations/20[4-9]_*.sql backend/migrations/210_*.sql` returns 0 matches. Impact: cross-tenant data leak via direct DB queries — model approvals, agent invocation graph, supply chain dependency graph, threat signals from partners all visible cross-tenant. Fix: add per-table `ENABLE ROW LEVEL SECURITY; FORCE ROW LEVEL SECURITY; CREATE POLICY org_strict_sel/ins/upd/del USING (organization_id = current_setting('app.current_organization_id', true)::integer)` blocks at the end of each new migration, OR a new migration 211 that re-runs the 091 loop unconditionally.

- **C-2. Webhook ingest endpoint accepts unsigned partner payloads.** File: `backend/app/api/handlers.py:44320` (`post_threat_signal_ingest_handler`). No signature verification despite `threat_connectors.webhook_secret` column existing for this purpose (`backend/migrations/210_threat_signals.sql:68–70`). Compare with the Stripe webhook handler at `backend/app/api/handlers.py:31262–31293` which correctly HMAC-verifies with `compare_digest`. Impact: a hostile actor with a valid tenant session can inject fabricated threat signals to manipulate AI Trust scores, Findings, and the Abuse Scenarios surface. Also: the endpoint is NOT in `PUBLIC_PATHS` (`backend/app/api/auth.py:74`), so the declared "partners HMAC-sign their webhooks" architecture is currently impossible because partners would have no auth. Fix: split into (a) authenticated tenant-test endpoint and (b) public `POST /api/v1/threat-signals/<connector_id>/ingest` with required `X-AG-Signature` header verified against the connector's `webhook_secret` before adapter dispatch; add to `PUBLIC_PATHS` only for the signed path.

- **C-3. Zero test coverage for ~3000 LOC of new logic.** Directories: `backend/tests/` has 62 test files but `grep -l 'abuse_scenarios\|model_registry\|multihop_xgraph\|supply_chain\|threat_connectors\|breach_cost\|compose_ai_findings'` returns nothing. Impact: silent regression on Tier 1–4 features (the headline AI-ISPM bet) with every refactor. Fix: add minimum unit tests for `breach_cost.compute_exposure` (regional fallback, has_factor=False path), `model_registry.classify_model` (fine-tune detection), `findings._fingerprint` (collision rate), `multihop_xgraph._bfs_from` (cycle guard, depth cap), `threat_connectors._azure_content_filter_adapter` (mapping coverage), and one integration test per detector in `findings.py`.

- **C-4. PR-gate has NO test/lint gates.** File: `.github/workflows/pr-gate.yml`. Gates are: (1) PR title contains `AG-\d+`, (2) hardcoded-secret regex grep, (3) `tsc --noEmit`. No `pytest`, no `mypy`, no `eslint`, no migration smoke. Frontend `npm run lint` resolves to `echo "(optional) add eslint later"` (`frontend/package.json`). Impact: anyone can merge code that doesn't run. Fix: add `pytest backend/tests -q` and `npx eslint --max-warnings=0 src/` (after wiring eslint) jobs to `pr-gate.yml`; gate `gate-summary.needs` on both.

- **C-5. `auto_set_tenant_id` trigger and `tenant_strict_*` policies expect a `tenant_id` column, not `organization_id`.** File: `backend/migrations/017_complete_rls_isolation.sql` covers tables with `tenant_id`; `backend/migrations/091_rls_all_tables.sql` separately covers tables with `organization_id`. The new tables use `organization_id` (correct) but neither runtime gets called for them post-creation. Confirmed at `backend/migrations/017_complete_rls_isolation.sql:80` and `:115`. Fix: the same migration referenced in C-1 should ALSO create `BEFORE INSERT` triggers that fill `organization_id` from `current_setting('app.current_organization_id', true)` when null, mirroring the `tenant_id` trigger pattern.

- **C-6. AI threat-signal evidence stored as plaintext JSONB, potentially contains user prompts / PII.** File: `backend/app/engines/ai/threat_connectors.py:99–108, 154–162, 207–215` — every adapter stores `evidence: {'raw': result}` containing the full upstream payload, which for Azure/Bedrock/Lakera often includes the original user prompt + AI output. Stored in `threat_signals.evidence` (`backend/migrations/210_threat_signals.sql:34`). Impact: untracked PII / customer prompts living in our DB; potential GDPR/HIPAA exposure (the very thing this product detects). Fix: strip `raw` from evidence at adapter level by default; gate full-payload retention behind a per-tenant `retain_partner_payloads` setting with a documented data-classification implication.

### HIGH (should fix before scaling beyond ~10 customers)

- **H-1. `compute_abuse_scenarios_org_rollup` is O(agents × per-agent queries).** File: `backend/app/engines/ai/abuse_scenarios.py:202–278`. Iterates `for aid in agent_ids: results.append(compute_abuse_scenarios(db, aid, org_id))` (line 236-240). Each per-agent call runs ~6 queries (`_load_agent_meta`, `_load_role_assignments`, `_load_reachability`, `_load_kv_secrets`, `_load_credentials`, `_load_federated_credentials`, `_load_supply_chain` with 3 sub-queries). For a tenant with 50 agents that's 50×9 ≈ 450 sequential round-trips per dashboard load. Fix: batch the loaders to take `identity_db_ids: list[int]` and `WHERE id = ANY(%s)`, returning `{id: data}`; compute scenarios in-memory.

- **H-2. `get_org_supply_chain_rollup` re-fetches per agent.** File: `backend/app/engines/ai/supply_chain.py:189–199`. Same pattern as H-1: `for a in agents: sc = get_agent_supply_chain(db, org_id, a['identity_db_id'])`. Each `get_agent_supply_chain` does a BFS loop with per-frontier queries (`backend/app/engines/ai/supply_chain.py:93–107`). With branching ≥ 2 and depth ≥ 4 this is N × log(D) round-trips per agent. Fix: load all `ai_supply_chain_links` for org once, walk in-memory.

- **H-3. `breach_cost._FACTOR_CACHE` never invalidates after process start.** File: `backend/app/engines/scoring/breach_cost.py:47, 98–101`. `invalidate_cache()` is exported but `grep` shows zero call sites in handlers or main. Settings UI lets admins edit factors but the running process won't see updates until restart. Impact: stale dashboard numbers, multi-worker drift after factor edits. Fix: call `invalidate_cache()` from the settings handler that writes `breach_cost_factors`; add a TTL (e.g., 15 min) for defensive freshness.

- **H-4. AI findings detectors don't bound result sets.** File: `backend/app/engines/ai/findings.py` — every `_detect_*` query has no `LIMIT`. A pathological tenant with 100k agents would return 100k rows per detector × 10 detectors = 1M rows materialized to Python lists before upsert. Combined with `_upsert_findings` (line 533–569) doing one round-trip per finding inside savepoints — worst-case 1M individual INSERTs. Fix: add `LIMIT 10000` per detector with a `truncated: true` flag; switch upsert to `execute_values` batch.

- **H-5. `_upsert_findings` does one INSERT + savepoint per finding.** File: `backend/app/engines/ai/findings.py:541–568`. Each row uses `SAVEPOINT _findings_upsert_sp / RELEASE / ROLLBACK TO SAVEPOINT` pattern. For 500 findings that's 1500 round-trips. Fix: `psycopg2.extras.execute_values` with `ON CONFLICT (organization_id, finding_fingerprint) DO UPDATE`; collect errors at the batch level.

- **H-6. No migration rollback (DOWN) scripts for 204–210.** Files: `backend/migrations/204_*.sql` through `210_*.sql`. Only `101_identities_org_id_constraints_rollback.sql` exists in the repo. If 204 deploys with bad data and breaks dashboards, rollback requires hand-crafted SQL during an incident. Fix: ship `2NN_*_rollback.sql` siblings (`DROP TABLE IF EXISTS ai_model_approvals CASCADE;` etc.) and document the unwind sequence in `docs/RUNBOOK.md`.

- **H-7. `agent_invocations` and `threat_signals` have no FK to `identities(id)`.** Files: `backend/migrations/208_agent_invocations.sql:35–38`, `210_threat_signals.sql:18–20`. `source_identity_db_id` / `target_identity_db_id` / `identity_db_id` are BIGINTs without REFERENCES. Identities get hard-deleted in some flows (or soft-deleted but discovery_run_id sweeps) — these tables will accumulate orphans referencing dead PKs forever. Fix: add `REFERENCES identities(id) ON DELETE CASCADE` (or `SET NULL` for the threat_signals case where the signal pre-dates discovery).

- **H-8. `ai_supply_chain_links.source_identity_db_id` also lacks FK.** File: `backend/migrations/209_ai_supply_chain.sql:50–52`. Compare with `target_component_id` on line 54 which does have `REFERENCES ... ON DELETE CASCADE`. Fix: add the missing FK with CASCADE.

- **H-9. Threat-signal ingest endpoint has no rate limit.** File: `backend/app/main.py:2404`. The route registers no `@rate_limit(...)`. Compare with auth endpoints which all have `@rate_limit(max_requests=10, window_seconds=60)`. A logged-in tenant user can flood `threat_signals` and DOS the dashboard. Fix: `@rate_limit(max_requests=100, window_seconds=60)` on the handler or route.

- **H-10. New routes lack rate limiting wholesale.** File: `backend/app/main.py:2350–2438`. None of the 14 new AI-security routes have `@rate_limit(...)`. The expensive ones (`/api/argus/multi-hop-reachability` with depth=6, supply-chain rollup, abuse-scenarios rollup) are the most attractive amplification targets. Fix: 30–60 req/min per IP for read endpoints; lower for the recompose endpoint.

- **H-11. Cross-handler authorization is per-role but inconsistent.** Files: `backend/app/api/handlers.py:44199` (`role not in ('admin','security_admin','auditor')`), `:44237` (`'admin','security_admin'`), `:44403–44405` (same), `:44554–44556` (`'admin','security_admin','auditor'`). Roles differ across handlers for the same workflow (e.g., auditor can submit a model for review but cannot decide; auditor can recompose findings but cannot approve). Fine in principle but undocumented anywhere. Fix: centralize in `auth.py` as named decorators (`require_security_admin`, `require_security_auditor`) used consistently across the 10 new endpoints.

- **H-12. Multi-hop BFS uses (start_id, target_id, depth+1) for cycle dedup, which under-prunes.** File: `backend/app/engines/ai/multihop_xgraph.py:341–344`. The `visited_pairs` set is keyed by `(start_id, target_id, depth+1)` — so the same target at the SAME depth via different paths is suppressed, but different depths re-explore. The intent appears to be "shortest path only" but the BFS will explode on dense graphs because expansion checks `if target_id in {p['identity_db_id'] for p in path}` (line 336) — set comprehension at every expansion. Fix: switch to BFS with `visited: dict[node] = min_depth_seen`; only expand when `depth + 1 < visited.get(target, inf)`.

- **H-13. `aggregate_exposure` calls `compute_exposure` (= cache lookup) per row.** File: `backend/app/engines/scoring/breach_cost.py:204–212`. Fine in isolation, but combined with `compute_abuse_scenarios` calling `aggregate_exposure` per scenario per agent (Tier 1 dashboards on a busy tenant), Decimal arithmetic on every row is meaningful CPU. Profile recommended. Fix: not urgent; consider memoizing `(cls, est_records)` → exposure or vectorizing on cohort lookups.

- **H-14. `tcdb_security_findings_org_fingerprint_unique` constraint introduced after fingerprint column existed.** File: `backend/migrations/207_security_findings_uniqueness.sql:11–19`. The DELETE-then-ADD pattern is correct, but the prior absence of the unique constraint means historical rows may have NULL `finding_fingerprint` that ON CONFLICT can't match. NULLs ARE allowed in unique constraints (only non-null collisions deduped). New `_upsert_findings` always sets fingerprint so the future is fine, but old rows with NULL fingerprint will accumulate duplicates per refresh. Fix: add `WHERE finding_fingerprint IS NULL` cleanup or mark them as `status = 'archived'`.

- **H-15. Threat-signal evidence JSONB has no size cap.** Files: `backend/app/engines/ai/threat_connectors.py` adapters + handler. Flask `MAX_CONTENT_LENGTH=5MB` is the only gate. A vendor that POSTs a 4.9MB payload pins it into JSONB indefinitely. Fix: cap `evidence` to ≤ 32KB after adapter normalization; reject payload if `len(json.dumps(evidence)) > 65536`.

- **H-16. Frontend new pages lack any accessibility attributes.** Files: `frontend/src/pages/AIFindings.tsx`, `AIModelRegistry.tsx`, `MultiHopXGraph.tsx`, `AISupplyChain.tsx`, `AIThreatConnectors.tsx`. `grep -n "aria-|role=" ` across all 5 files = 0 matches. Modals open without `role="dialog"`, no `aria-modal`, no keyboard focus trap. Fix: add `role="dialog" aria-modal="true" aria-labelledby="..."` to each drawer/modal; add `aria-label` to icon-only buttons.

- **H-17. Frontend uses `window.alert()` for error reporting.** Files: `AIFindings.tsx:82,93`, `AIModelRegistry.tsx:105,119,133`, `AIThreatConnectors.tsx:97`. 6 occurrences. Bad UX; can't screenshot; doesn't survive page reload state. Fix: integrate the existing toast/notification system (or `console.error` + inline error banner).

- **H-18. `secrets.compare_digest` not used in webhook framework.** Once C-2 is fixed, ensure the planned `verify_hmac` uses `hmac.compare_digest(expected, supplied)` to prevent timing attacks. The Stripe pattern at `backend/app/api/handlers.py:31292` is correct; copy it.

### MEDIUM (cleanup / hardening for Q3)

- **M-1. New AI engines use `__import__('json')` instead of `import json`.** Files: `backend/app/engines/ai/findings.py:561`, `backend/app/engines/ai/threat_connectors.py:379,488`. Code smell, slower, harder to grep. Fix: `import json` at top.

- **M-2. New AI engines import `datetime` inside functions.** Files: `backend/app/engines/ai/findings.py:99,151`, `backend/app/engines/ai/model_registry.py:151`. Top-level imports already exist (e.g. `findings.py` line 99 inside `compose_ai_findings`). Fix: hoist.

- **M-3. Engines do `cursor.close()` in `finally:` but pattern is inconsistent — some use try/finally, some don't.** `supply_chain.py:189–199` opens & closes a cursor twice in the same `get_org_supply_chain_rollup`. Fix: use `with db.conn.cursor() as cursor:` everywhere.

- **M-4. `_safe_handler` in handlers.py swallows exceptions silently.** File: `backend/app/api/handlers.py:347–354`. Logs only `logger.warning("Optional handler %s failed: %s", fn.__name__, exc)` — no `exc_info=True`. A truly silent handler corruption never reaches Sentry/ops. Fix: `logger.warning(..., exc_info=True)` to include the stack.

- **M-5. Many `except Exception: pass` in `abuse_scenarios.py`.** File: `backend/app/engines/ai/abuse_scenarios.py:386–387, 416–417, 456–457, 477–478, 497–498`. Five savepoint rollback paths swallow exceptions wholesale. Wrapping savepoints is good defensive practice, but logging nothing makes debugging impossible. Fix: `except Exception as exc: logger.debug("savepoint rollback: %s", exc)`.

- **M-6. `findings.py` and `threat_connectors.py` similarly swallow exceptions silently.** Files: `findings.py:454,568`, `threat_connectors.py:389`. Same pattern. Fix: as M-5.

- **M-7. Logger uses `logger.warning(..., exc)` without `exc_info=True` for adapter / detector failures.** Files: `findings.py:83,452,566`. Only `threat_connectors.py:346` correctly uses `exc_info=True`. Fix: standardize on `exc_info=True` for all caught exceptions.

- **M-8. Severity logic for `_scenario_credential_theft` is honest but the contract isn't tested.** File: `backend/app/engines/ai/abuse_scenarios.py:572–637`. Subtle "no credentials → low, even with PHI reach" decision is correct but undocumented in tests; a refactor could quietly break it.

- **M-9. `_load_kv_secrets` joins on lowercased `scope` substring.** File: `backend/app/engines/ai/abuse_scenarios.py:350`. `'/providers/microsoft.keyvault/vaults/' in (ra['scope'] or '').lower()` will false-positive on `/providers/Microsoft.KeyVault/vaults/foo/something/Microsoft.KeyVault/vaults/bar` style malformed scopes (unlikely from ARM, possible from imports). Fix: regex match `^/.+/providers/Microsoft\.KeyVault/vaults/[^/]+(/.*)?$` case-insensitive.

- **M-10. Multi-hop endpoint allows max_depth up to 6 with no per-tenant limit.** File: `backend/app/api/handlers.py:44293`. On a tenant with dense invocation graph (50 agents × 5 avg edges) depth=6 produces ~7M paths before the 500-cap kicks in. Fix: enforce `max_depth = min(int(request.args.get('max_depth', 4)), 4)` and document depth>4 as an admin-only feature flag.

- **M-11. `aggregate_exposure.uncovered` counter is in return dict but never surfaced.** File: `backend/app/engines/scoring/breach_cost.py:236`. Callers never read `uncovered` — but it's useful operational signal ("we have 14 classifications without cost factors"). Fix: surface in `/api/stats` or a dedicated `/api/admin/breach-cost/coverage` endpoint.

- **M-12. `model_registry.classify_model` checks `'preview' in name` AFTER baseline match.** File: `backend/app/engines/ai/model_registry.py:60–66`. So `gpt-4o-preview` classifies as 'baseline' (matched `gpt-4o` prefix first). Probably wrong — `preview` is usually pre-GA. Fix: move the preview/beta check before the baseline prefix loop.

- **M-13. `_detect_finetune_not_approved` uses `LIKE '%%-ft-%%'` over JOIN with `ai_model_approvals`.** File: `backend/app/engines/ai/findings.py:436–447`. Misses the alternative naming (`-ft:`, `-ft` suffix) that `model_registry.classify_model` correctly detects. Inconsistency = different verdicts. Fix: import the catalog from `model_registry.py` and reuse.

- **M-14. `compose_ai_findings` always uses latest run id but detectors don't all filter by run_id.** File: `backend/app/engines/ai/findings.py:315–326, 469–483`. `_detect_phi_pci_reach` and `_detect_multi_model` skip `discovery_run_id` filter (they need agent_data_reachability which is run-scoped via `identity_db_id`). Inconsistent — some detectors `run_ids: list`, others don't. Likely correct but fragile. Fix: comment explicitly which detectors are run-scoped and why.

- **M-15. `_resolve_identity_param` global middleware swallows all exceptions.** File: `backend/app/main.py:957–965`. `except Exception: pass` on every request. Fix: `logger.warning("identity param resolve failed: %s", exc, exc_info=True)`.

- **M-16. New routes don't appear in any docs.** Files: `docs/RUNBOOK.md`, `docs/technical-design-document.md`, `README.md` — `grep` for new endpoints returns zero. Fix: extend `docs/RUNBOOK.md` with the 14 new routes + their auth requirements + sample curls.

- **M-17. `frontend/src/utils/cisoViewModel.ts` has 3 `console.log` (`utils/cisoViewModel.ts:1293,1308,1363`).** Predate this PR but should be cleaned. Fix: `npx eslint --rule 'no-console: error'` after eslint is wired (see C-4).

- **M-18. `frontend/src/index.tsx` has commented `console.log` example.** File: `frontend/src/index.tsx:17`. Cosmetic.

- **M-19. New frontend pages use raw `fetch` instead of the wrapped client.** Files: all 5 new pages. The codebase has a global `window.fetch` interceptor for auth — but if any of these pages run before the interceptor is mounted (e.g. tests, SSR if ever added) they'll silently 401. Fix: import a shared `api` helper.

- **M-20. Frontend has no Suspense / error boundary around the new pages.** Files: 5 new pages. A `r.json()` parse error or thrown render error crashes the whole app. Fix: wrap each page in `<ErrorBoundary>`.

- **M-21. `MultiHopXGraph.tsx` has 543 lines; should be split.** Components, hooks, types in one file. Fix: extract `<ChainCard>`, `<InvocationGraphView>`, `<ChainDetailDrawer>` into separate files.

- **M-22. Modal/drawer Z-index and focus management not implemented.** Files: all 5 pages. Modal escape key, click-outside-to-close, focus trap absent. Fix: use a shared `<Drawer>` primitive.

- **M-23. Threat-signal vendor list hardcoded twice — DB and Python.** Files: `backend/migrations/210_threat_signals.sql:23–24` (CHECK constraint) and `backend/app/engines/ai/threat_connectors.py:45–47` (`SUPPORTED_VENDORS`). Drift risk when adding a vendor. Fix: a startup check `assert set(SUPPORTED_VENDORS) == set(_query_check_constraint())`.

- **M-24. Same drift risk between `signal_type` and `severity` constants.** Files: same as M-23.

- **M-25. `breach_cost_factors.notes` and `source` are TEXT (unbounded).** Could grow if customers customize. Fix: `TEXT CHECK (length(notes) <= 2000)` style soft cap.

- **M-26. `ai_model_approvals.justification` and `.review_notes` similarly unbounded.** Same as M-25.

- **M-27. `threat_signals.evidence` JSONB unbounded — see H-15.**

- **M-28. `agent_invocations.metadata` JSONB unbounded.** Same. Fix: enforce ≤ 8KB at INSERT time.

- **M-29. No `ai_model_approvals.expires_at` index for the "expired" sweep.** File: `backend/migrations/206_ai_model_registry.sql:48–51`. `effective_status` computation in `model_registry.list_registry` reads `expires_at < NOW()` in Python after fetching all rows — fine for v1, slow at 1000+ models. Fix: index later.

- **M-30. New tables granted to `auditgraph_app` even for non-write ones like `breach_cost_factors`.** File: `204_breach_cost_factors.sql:117` correctly grants only SELECT. But 206-210 grant `SELECT, INSERT, UPDATE` — DELETE is consistently NOT granted (good defensive pattern), worth documenting.

- **M-31. Multiple `BEGIN`/`COMMIT` blocks in migrations means partial state on failure.** Files: 204–210 each wrap in `BEGIN; ... COMMIT;`. The `\set ON_ERROR_STOP on` helps, but the runner uses `conn.autocommit = True` and `cur.execute(sql)` — psycopg2 then SPLITS on the explicit BEGIN/COMMIT into separate txns. A failure mid-script leaves partial state. Fix: drop the explicit BEGIN/COMMIT; rely on autocommit + each statement being idempotent (already mostly true).

- **M-32. Schema sync (`scripts/sync_schema.py`) presumably needs an update with the 6 new tables.** File: `backend/app/main.py:718–757`. The sync runs from a CSV of expected columns. New tables won't be in the CSV. Fix: regenerate the embedded schema CSV after migrations apply.

- **M-33. `model_registry.submit_for_review` UPSERT clobbers `requested_at` on every submit.** File: `backend/app/engines/ai/model_registry.py:200–212`. Including for already-pending rows. Fix: only update `requested_at` if status is currently terminal (`rejected`/`revoked`).

- **M-34. `_finding` uses `_fingerprint` with 32-char SHA-256 truncation.** File: `backend/app/engines/ai/findings.py:196`. Birthday collision probability is fine at this scale, but document the choice.

### LOW (nice-to-haves / lint)

- **L-1. `backend/app/api/handlers.py` is 46,867 lines.** Past the point of any reasonable navigation/IDE responsiveness. Split into per-domain modules. Tier work made it 1000+ lines bigger. Fix: roadmap a refactor.

- **L-2. `backend/app/database.py` is 30,618 lines.** Same as L-1.

- **L-3. Stale data dumps in repo.** `backend/discovery_results_20260123_142400.json` (likely transient debug dump from a discovery run), `backend/test_baseline_report.txt`. Fix: move to gitignore + clean from history.

- **L-4. `backend/=1.34.0` directory at repo root.** Looks like accidental `pip install foo=1.34.0` typo creating a directory. Confirmed at `backend/=1.34.0` from `ls`. Fix: `rm -rf backend/=1.34.0` and add to `.gitignore`.

- **L-5. `asdasd` file/directory in repo root.** From `ls` output. Fix: delete.

- **L-6. Untracked `backend/scripts/auditgraph_restart.sh`.** From `git status`. Either commit or .gitignore.

- **L-7. Markdown copy uses curly punctuation (em-dashes, en-dashes).** Files: most new migrations and engine docstrings. Fine for human reading; will break some pure-ASCII tooling.

- **L-8. Magic numbers in `breach_cost.format_dollar_short` thresholds.** File: `backend/app/engines/scoring/breach_cost.py:258–263`. Fine, but a named tuple of thresholds would be cleaner.

- **L-9. Some engine docstrings claim "no telemetry required" but `_load_credentials` uses `credential_status='expired'`.** Files: `findings.py:404–418`. Status comes from discovery, not telemetry — correct, but the marketing language deserves a doc clarification.

- **L-10. Naming: `agent_invocations.invocation_name` is sometimes called "tool name" in comments.** File: `208_agent_invocations.sql:43`. Pick one: `tool_or_invocation_name` or split.

- **L-11. `_BCRYPT_ROUNDS` constant duplicated in `handlers.py:20` and `database.py:85`.** Fix: import from a shared module.

- **L-12. `compute_exposure` returns Decimal — frontend gets strings due to Flask's default JSON encoder, then re-parses.** Fine, but `format_dollar_short` already handles display. The raw Decimal numeric strings are extra payload. Fix: serialize as float for transit if precision allows.

- **L-13. `ai_supply_chain_components.metadata` and `.risk_flags` not validated at schema level beyond JSONB.** Fix: optional `CHECK (jsonb_typeof(risk_flags) = 'array')`.

- **L-14. Multi-hop endpoint always returns `'computed_at'` even when empty.** Minor — caller can ignore.

- **L-15. `model_registry.decide_review` accepts a free-text `expires_at` without ISO validation.** File: `backend/app/engines/ai/model_registry.py:241–250`. Bad input becomes a Postgres parse error → 500. Fix: validate in handler before DB call.

- **L-16. `threat_connectors.config` JSONB has no schema validation.** Customers could store arbitrary stuff. Fix: per-vendor JSON Schema, validated at upsert.

- **L-17. New frontend pages use Tailwind utility classes with long literal strings — risk of duplication.** Fix: extract `<SevBadge>`, `<StatusPill>` etc.

- **L-18. `i18n` is not addressed in any new page.** Per audit prompt: noted but not blocking.

- **L-19. No `data-testid` attributes for E2E tests.** Files: all 5 new pages. Fix: add to interactive elements as we wire Playwright.

- **L-20. `frontend/package.json` includes `"express": "^5.2.1"` and `"http-proxy-middleware": "^3.0.5"` as runtime deps — looks unused.** Fix: `npm ls express` to confirm and remove.

---

## Area-by-Area Scorecard

| Area | Score | Notes |
|---|---|---|
| Code quality | B+ | New AI engines are well-written; clear catalogs; good docstrings; zero TODOs in new code. Held back by silent `except Exception: pass`, `__import__('json')` smells, and ever-growing handlers.py. |
| Security config | B | CORS strict, CSP defined, HSTS, dual JWT secrets with prod enforcement, bcrypt rounds=12, statement timeouts. Held back by webhook ingest auth gap and missing rate limits on new routes. |
| DB safety | D | This is the failing area. RLS gap on 6 new tables is a multi-tenant security blocker. No FKs on new join columns. No rollback scripts. JSONB columns unbounded. |
| Performance | C | N+1 in 2 of the 3 org rollup engines. Findings upsert not batched. Multi-hop BFS de-dup under-prunes. Breach cost cache reasonable but never invalidated. |
| Reliability | C+ | Idempotent migrations with `CREATE TABLE IF NOT EXISTS` + triggers. Idempotent compose/recompose. Savepoints used correctly. BUT: no rollback scripts; explicit BEGIN/COMMIT in autocommit runner; no migration smoke. |
| Observability | B- | Top-level handlers use `logger.error(..., exc_info=True)`. Engine internals silently swallow at savepoint rollback. Request IDs and timing middleware are wired. |
| Test coverage | F | Zero tests for ~3000 LOC of new logic. No PR-gate enforcement. |
| Frontend production | C- | TypeScript strict, no `console.log` debug noise in new pages, no exposed secrets. Held back by `alert()` UX, zero accessibility, no error boundaries, no test selectors, no eslint. |
| Documentation | D+ | New endpoints absent from `docs/RUNBOOK.md`, `docs/technical-design-document.md`, and `README.md`. Engine docstrings are good but external-facing docs missing. |
| CI/CD | C- | Strong dev-deploy IaC and bicep what-if. Hardcoded-secret scan helps. But no tests, no lint, no mypy, no migration smoke. Migration application is manual via `CA Job` per memory; bot deploys don't apply SQL. |

---

## Top 10 Specific Fixes (Prioritized)

1. **`backend/migrations/211_rls_on_new_tables.sql`** (new file) — emit `ENABLE ROW LEVEL SECURITY; FORCE ROW LEVEL SECURITY; CREATE POLICY org_strict_{sel,ins,upd,del}` on `ai_model_approvals`, `agent_invocations`, `ai_supply_chain_components`, `ai_supply_chain_links`, `threat_signals`, `threat_connectors`. Also add `BEFORE INSERT` triggers to auto-fill `organization_id` from session context. Verify with an integration test that org=2 cannot read org=3 rows. Effort: 2h. **(addresses C-1, C-5)**

2. **`backend/app/api/handlers.py:44320` + new route `/api/v1/threat-signals/<connector_uuid>/ingest`** — implement HMAC signature verification using `threat_connectors.webhook_secret` and `hmac.compare_digest`. Add `connector_uuid` UUID column to `threat_connectors`. Add to `PUBLIC_PATHS`. Keep existing tenant-authenticated endpoint for test purposes. Effort: 3h. **(addresses C-2)**

3. **`backend/tests/test_breach_cost.py`, `test_abuse_scenarios.py`, `test_findings.py`, `test_multihop.py`, `test_model_registry.py`, `test_threat_connectors.py`** — minimum 6 pytest files covering happy + edge path per module. Add `pytest backend/tests -q` job to `.github/workflows/pr-gate.yml`. Effort: 1d. **(addresses C-3, C-4)**

4. **`backend/app/engines/ai/abuse_scenarios.py` + `supply_chain.py`** — batch loaders to take `identity_db_ids: list[int]` and group results by id. Rewrite `compute_abuse_scenarios_org_rollup` and `get_org_supply_chain_rollup` to make exactly 6 (resp. 2) queries total per org. Effort: 4h. **(addresses H-1, H-2)**

5. **`backend/app/engines/ai/findings.py:533–569`** — replace per-row `INSERT ... ON CONFLICT` with `psycopg2.extras.execute_values`. Add `LIMIT 10000` per detector. Effort: 2h. **(addresses H-4, H-5)**

6. **`backend/app/engines/ai/threat_connectors.py` adapters + `210_threat_signals.sql`** — strip `'raw'` from evidence by default; cap stringified evidence at 32KB. Add `retain_partner_payloads` setting flag for full retention. Effort: 2h. **(addresses C-6, H-15)**

7. **`backend/app/main.py:2350–2438`** — add `@rate_limit(max_requests=30, window_seconds=60)` (read) and `@rate_limit(max_requests=10, window_seconds=60)` (mutation) to the 14 new routes. Effort: 30min. **(addresses H-9, H-10)**

8. **`backend/migrations/208_agent_invocations.sql`, `209_ai_supply_chain.sql`, `210_threat_signals.sql`** — add `REFERENCES identities(id) ON DELETE CASCADE` (or `SET NULL`) to `*_db_id` columns. Add rollback siblings `2NN_*_rollback.sql`. Effort: 1h. **(addresses H-6, H-7, H-8)**

9. **`backend/app/engines/scoring/breach_cost.py:98` + `backend/app/api/handlers.py` (settings handler)** — call `invalidate_cache()` whenever breach factors are written; add a 15-minute TTL. Effort: 30min. **(addresses H-3)**

10. **Frontend hardening sprint**: extract shared `<Drawer>`, `<ErrorBoundary>`, `<Toast>` primitives; replace 6 `alert()` calls with toasts; add `aria-modal`/`role="dialog"` to all drawers; wire eslint with `no-console` rule and add to PR gate. Effort: 1d. **(addresses H-16, H-17, M-19 through M-22, C-4 frontend portion)**

---

## Appendix: Items Confirmed Good

- **Dual JWT secrets** with prod assertion that they differ (`backend/app/api/auth.py:53–55`). Solid.
- **CORS validation at startup** rejects `*` + supports_credentials and requires https in prod (`backend/app/main.py:795–817`). Solid.
- **`add_security_headers`** sets CSP, HSTS, X-Frame-Options=DENY, X-Content-Type-Options, Referrer-Policy, Permissions-Policy (`backend/app/security/__init__.py:116–165`). Solid.
- **Connection pool** with statement timeout = 30s, options at connect time, `RESET` on checkout (`backend/app/database.py:158–288`). Solid.
- **Dual DB users + RLS framework** (`auditgraph_app` NOBYPASSRLS, `auditgraph_admin` BYPASSRLS), `Database(organization_id=N)` sets session context (`backend/app/database.py:471–489`). Solid foundation that new migrations failed to honor.
- **Demo write guard** carefully whitelists read-like POSTs (`backend/app/main.py:838–940`). Subtle but correct.
- **Request ID + timing middleware** (`backend/app/main.py:967–984`). Good for log correlation.
- **AI engine module organization** — engines under `backend/app/engines/ai/` with consistent public-API conventions and module-level constant catalogs. Good.
- **Migration 204 breach cost data** carries source citations + effective_date + supersede_date — defensible audit trail. Good.
- **`compose_ai_findings` uses fingerprint-based UPSERT** so re-running never loses status (`backend/app/engines/ai/findings.py:552–557`). Good.
- **Bcrypt cost factor 12 + env override** (`backend/app/database.py:85`, `backend/app/api/handlers.py:20`). Good.

---

End of report.
