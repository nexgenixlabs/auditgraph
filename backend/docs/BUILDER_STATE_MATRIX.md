# E2 — Builder State Matrix

Canonical reference for how each Phase 3 builder handles the four
partial-data states defined by `BuilderDataSource` in
`app/schemas/identity.py`.

## BuilderDataSource Enum

| Value     | Meaning |
|-----------|---------|
| `NONE`    | Skeleton table has **zero rows** for this identity. Every null field is an honest "we don't know". Confidence is `NONE`. |
| `PARTIAL` | Some rows/fields exist but the builder could not compute a high-confidence result. Confidence is `LOW`. |
| `FULL`    | Every required input field is populated and the row is within the freshness window. Confidence is `HIGH` (or block-specific). |
| `STALE`   | A row exists but its `updated_at` is older than `BUILDER_STALENESS_HOURS` (24h). Data returned as-is; consumers should show a "stale" badge. |

## Per-Builder Matrix

### B02 — ActivityBuilder (`activity_builder.py`)

| State | `data_source` | `activity_confidence` | `lifecycle_state` | `last_sign_in_at` | `last_activity_at` | `missing_signals` |
|-------|--------------|----------------------|-------------------|-------------------|--------------------|--------------------|
| 0 — No row | `NONE` | `NONE` | `PROVISIONED` (placeholder) | `null` | `null` | `["last_sign_in_at", "last_activity_at", "lifecycle_state"]` |
| 1 — Row, missing fields | `PARTIAL` | from row | from row | may be `null` | may be `null` | list of null field names |
| 2 — Full row | `FULL` | from row | from row | non-null | non-null | `[]` |
| 3 — Stale row | `STALE` | from row | from row | from row | from row | may have entries |

**Staleness check**: `identity_activity.updated_at` is compared against `BUILDER_STALENESS_HOURS` (24h). This is the **only** skeleton table with an `updated_at` column.

### B03 — OwnershipBuilder (`identity_profile_builder.py`)

| State | `data_source` | `confidence` | `owner_quality` | `owners` | `missing_signals` |
|-------|--------------|-------------|-----------------|----------|-------------------|
| 0 — No rows | `NONE` | `NONE` | `NO_OWNER` | `[]` | `["owners", "last_review_at"]` |
| 1 — Rows, missing owner_type | `PARTIAL` | `LOW` | derived | populated | `["owner_type"]` |
| 2 — Full rows | `FULL` | `HIGH` | derived | populated | `[]` |
| 3 — Stale | N/A | — | — | — | — |

**No staleness check**: `identity_owners` has no `updated_at` column. Staleness can only be detected at the engine level via `DataContext.is_stale`.

### B04 — GovernanceEngine (`governance_engine.py`)

Pure derivation — no database access. Data source is derived from the upstream `ActivityState` and `OwnershipBlock`.

| Upstream activity | Upstream ownership | Governance `data_source` | `missing_signals` |
|-------------------|-------------------|------------------------|-------------------|
| `NONE` | `NONE` | `NONE` | `["activity", "ownership"]` |
| `NONE` | any other | `PARTIAL` | `["activity"]` |
| any other | `NONE` | `PARTIAL` | `["ownership"]` |
| `FULL` | `FULL` | `FULL` | `[]` |
| any other combo | any other combo | `PARTIAL` | list of non-FULL upstreams |

### B05 — PrivilegeBuilder (`identity_profile_builder.py`)

| State | `data_source` | `confidence` | `privilege_level` | `scope_breadth` | `missing_signals` |
|-------|--------------|-------------|-------------------|-----------------|-------------------|
| 0 — No row | `NONE` | `NONE` | `STANDARD` (placeholder) | `RESOURCE` (placeholder) | `["privilege_level", "scope_breadth", "total_role_count"]` |
| 2 — Full row | `FULL` | `HIGH` | from row | from row | `[]` |
| 3 — Stale | N/A | — | — | — | — |

**No staleness check**: `identity_privilege_summary` has no `updated_at` column.

### Blast Radius — IdentityBlastRadiusEngine (`identity_blast_radius_engine.py`)

| State | `data_source` | `total_reachable` | `truncated` | `missing_signals` |
|-------|--------------|-------------------|-------------|-------------------|
| 0 — No edges | `NONE` | `0` | `false` | `["graph_edges"]` |
| 1 — Truncated | `PARTIAL` | > 0 | `true` | `["truncated_frontier"]` |
| 2 — Full traversal | `FULL` | ≥ 0 | `false` | `[]` |

## Consumer Contract

1. **Check `data_source` first** — if `NONE`, treat every enum default as a placeholder. The identity may not have been discovered yet.
2. **Check `missing_signals`** — for `PARTIAL`, this list tells you exactly which fields are unreliable.
3. **Check `confidence`** — `NONE` or `LOW` means the block's derived conclusions (e.g. `governance_classification`) should be displayed with a caveat.
4. **Stale data is usable** — show it with a visual indicator (e.g. "Last updated 36h ago") rather than hiding it.

## Acceptance Criteria (E2)

- [ ] 20+ contract tests pass (4 states × 5 builders)
- [ ] Every builder returns a valid response in all 4 states (zero 500s)
- [ ] `IdentityState` has no untyped `Optional` fields — every `Optional[X]` carries a `Field(description="null when...")` annotation
- [ ] `GET /api/v1/identities/{id}` on an identity with all skeleton tables empty returns HTTP 200 (not 500) with `data_source=NONE` blocks
- [ ] 21/21 A3 smoke regression passes
