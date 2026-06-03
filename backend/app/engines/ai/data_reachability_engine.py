"""
data_reachability_engine — Per-AI-agent Sensitive Data Reachability (AG-180, Tier 2A)
=====================================================================================

Computes, per AI agent in a discovery run, "which classified data this agent can
reach" rolled up by classification class (PHI / PCI / PII / SOURCE / HR / FINANCIAL
/ CONFIDENTIAL). The output table is `agent_data_reachability` (one row per
(org, run, identity_db_id, classification) tuple).

Why this exists
---------------
The board-level claim "Agent X can reach N PHI resources containing ~Y records,
with W of those resources writable" is the headline AI Identity Attack Graph
finding. It binds three streams that historically lived in different places:

  1. agent_classifications.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
     — the AI agent cohort for a run.
  2. RBAC role_assignments → scope coverage of classified data sources
     (storage accounts, SQL databases, Cosmos databases). Key Vault is
     INTENTIONALLY out of scope — vaults hold secrets, not "data
     classification" sensitive content.
  3. data_classification taxonomy (PHI / PCI / ...) on the data sources.

This engine is the single source of truth for that rollup. It is read-mostly:
one INSERT/UPSERT per (agent, classification) cell per refresh.

Design rules
------------
- NO fabricated record counts. `record_count_estimate` is summed when present
  and left NULL if ANY contributing resource has NULL. Honest accounting beats
  pretty dashboards.
- Vaults are excluded from the classified-resource scan; vault risk is
  modelled by the Trust Score (secrets dimension) and the AG-178 attack-path
  engine, not here.
- All SELECTs are wrapped in named SAVEPOINTs so a transient table-shape
  issue (e.g. SQL/Cosmos tables not yet present in older deployments)
  doesn't poison the outer transaction.
- Access resolution funnels through `services.access_resolution` (SSOT) so
  scope-coverage semantics match every other AG-* engine.

Public entry points
-------------------
- `refresh_data_reachability(db, run_id, organization_id)` — main driver.
- `classify_undiscovered_resources(db, run_id, organization_id)` — helper that
  back-fills missing classifications on storage / SQL / Cosmos rows using the
  SSOT `classify_resource()` from `constants/data_classification`.
- `get_agent_data_reachability(cursor, identity_db_id, organization_id)` —
  API-shaped read helper for the per-identity drawer.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from ...constants.data_classification import (
    ALL_CLASSES,
    classify_resource,
)
from ...services.access_resolution import (
    resolve_agent_resource_access_batch,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Access levels considered "writable" for the write_resource_count rollup.
# Reader access does NOT count — the board claim is specifically about
# blast-radius writes (modify/delete) on classified data.
_WRITE_ACCESS_LEVELS = frozenset({"contributor", "owner"})

# How many top resources we persist in agent_data_reachability.top_resources.
# Five is enough to render a drawer breadcrumb without bloating the JSONB.
_TOP_RESOURCES_PER_CLASS = 5

# Savepoint name prefix — unique to this engine to avoid collision with
# caller-held savepoints higher in the stack.
_SP_PREFIX = "ag180_dr"


# ─────────────────────────────────────────────────────────────────────────────
# Top-level: refresh_data_reachability
# ─────────────────────────────────────────────────────────────────────────────

def refresh_data_reachability(db, run_id: int, organization_id: int) -> dict:
    """Compute per-agent / per-classification data reachability for `run_id`.

    Returns a summary dict:
      {
        'evaluated_agents':       int,  # agents we computed a rollup for
        'classifications_seen':   list[str],  # distinct classes hit across all agents
        'total_rows_written':     int,  # rows upserted into agent_data_reachability
        'errors':                 int,  # per-resource / per-agent failures (logged)
      }

    The function is idempotent on (organization_id, discovery_run_id,
    identity_db_id, data_classification) thanks to the unique key on the
    rollup table — re-running over the same run replaces the prior rows.
    """
    summary: dict[str, Any] = {
        'evaluated_agents': 0,
        'classifications_seen': [],
        'total_rows_written': 0,
        'errors': 0,
    }
    classifications_seen: set[str] = set()

    cursor = db.cursor()

    # ── 1. Load AI agent cohort for this run ────────────────────────
    agents = _load_agents(cursor, run_id, organization_id, summary)
    if not agents:
        logger.info(
            "[AG-180] No AI agents in run=%s org=%s — nothing to compute",
            run_id, organization_id,
        )
        try:
            cursor.close()
        except Exception:
            pass
        return summary

    # ── 2. Load classified data resources for this run ──────────────
    # Each row is a dict {resource_id, resource_type, name, est_records,
    # data_classification}. resource_type ∈ {storage_account, sql_database,
    # cosmos_database}. Vaults are deliberately omitted.
    resources = _load_classified_resources(cursor, run_id, organization_id, summary)
    if not resources:
        logger.info(
            "[AG-180] No classified resources in run=%s org=%s — emitting zero rollup",
            run_id, organization_id,
        )

    # ── 3. Batch-resolve access for every (agent, resource) pair ────
    # access_resolution.resolve_agent_resource_access_batch issues a single
    # SQL query for role_assignments and matches in-Python — no N+1.
    agent_ids = [a['id'] for a in agents]
    resource_ids = [r['resource_id'] for r in resources]

    if agent_ids and resource_ids:
        try:
            access_map = resolve_agent_resource_access_batch(
                cursor, agent_ids, resource_ids,
            )
        except Exception as exc:  # pragma: no cover — pure-py shouldn't throw
            logger.warning("[AG-180] batch access resolution failed: %s", exc)
            summary['errors'] += 1
            access_map = {}
    else:
        access_map = {}

    # ── 4. Group reachable resources per agent / classification ─────
    # rollup[(identity_db_id, classification)] = list[dict{resource, level}]
    rollup: dict[tuple[int, str], list[dict[str, Any]]] = {}
    for agent in agents:
        iid = agent['id']
        for res in resources:
            key = (iid, res['resource_id'])
            access = access_map.get(key)
            if access is None:
                continue
            cls = (res.get('data_classification') or '').upper()
            if cls not in ALL_CLASSES:
                continue
            classifications_seen.add(cls)
            rollup.setdefault((iid, cls), []).append({
                'resource_id':   res['resource_id'],
                'resource_type': res['resource_type'],
                'name':          res.get('name'),
                'est_records':   res.get('est_records'),
                'access_level':  access['access_level'],
            })

    # ── 5. Upsert one row per (agent, classification) cell ──────────
    written = 0
    for (iid, cls), reachable in rollup.items():
        agent_meta = next((a for a in agents if a['id'] == iid), None)
        if not agent_meta:
            # Defensive — shouldn't happen since iid came from agents
            continue
        try:
            _upsert_rollup_row(
                cursor=cursor,
                organization_id=organization_id,
                run_id=run_id,
                identity_db_id=iid,
                identity_id=agent_meta['identity_id'],
                classification=cls,
                reachable=reachable,
            )
            written += 1
        except Exception as exc:
            logger.warning(
                "[AG-180] upsert failed for agent=%s class=%s: %s",
                iid, cls, exc,
            )
            summary['errors'] += 1
            try:
                cursor.connection.rollback()
            except Exception:
                pass

    try:
        cursor.connection.commit()
    except Exception as exc:  # pragma: no cover
        logger.warning("[AG-180] commit failed: %s", exc)
        summary['errors'] += 1

    summary['evaluated_agents'] = len(agents)
    summary['classifications_seen'] = sorted(classifications_seen)
    summary['total_rows_written'] = written

    try:
        cursor.close()
    except Exception:
        pass

    logger.info(
        "[AG-180] data reachability refreshed for run=%s org=%s "
        "agents=%d classes=%d rows=%d errors=%d",
        run_id, organization_id, summary['evaluated_agents'],
        len(summary['classifications_seen']), summary['total_rows_written'],
        summary['errors'],
    )
    return summary


# ─────────────────────────────────────────────────────────────────────────────
# Helper: classify_undiscovered_resources
# ─────────────────────────────────────────────────────────────────────────────

def classify_undiscovered_resources(db, run_id: int, organization_id: int) -> int:
    """Walk storage / SQL / Cosmos rows where `data_classification IS NULL`
    in the given run, and back-fill from the SSOT taxonomy
    (`classify_resource(name, tags)`).

    Only writes when `classify_resource` returns a non-None result —
    absence of signal stays absence of classification. Never invents a class.

    Returns the total number of rows updated across all three source tables.
    """
    cursor = db.cursor()
    total_updated = 0

    table_specs: tuple[dict[str, str], ...] = (
        {
            'table':      'azure_storage_accounts',
            'name_col':   'name',
            'tags_col':   'tags',
            'sp_suffix':  'storage',
        },
        {
            'table':      'azure_sql_databases',
            'name_col':   'database_name',
            'tags_col':   'tags',
            'sp_suffix':  'sql',
        },
        {
            'table':      'azure_cosmos_databases',
            'name_col':   'database_name',
            'tags_col':   'tags',
            'sp_suffix':  'cosmos',
        },
    )

    for spec in table_specs:
        sp_name = f"{_SP_PREFIX}_classify_{spec['sp_suffix']}"
        # 1) Read candidates inside a SAVEPOINT so missing tables don't kill
        # the outer transaction in older deployments.
        try:
            cursor.execute(f"SAVEPOINT {sp_name}")
            cursor.execute(
                f"""
                SELECT id, {spec['name_col']} AS name, {spec['tags_col']} AS tags
                  FROM {spec['table']}
                 WHERE organization_id = %s
                   AND discovery_run_id = %s
                   AND data_classification IS NULL
                """,
                (organization_id, run_id),
            )
            rows = cursor.fetchall()
            cursor.execute(f"RELEASE SAVEPOINT {sp_name}")
        except Exception as exc:
            logger.debug(
                "[AG-180] classify scan skipped for %s: %s",
                spec['table'], exc,
            )
            try:
                cursor.execute(f"ROLLBACK TO SAVEPOINT {sp_name}")
            except Exception:
                try:
                    cursor.connection.rollback()
                except Exception:
                    pass
            continue

        # 2) Per-row classify + UPDATE. We don't batch because the writes are
        # sparse (most resources don't classify) and we want each failure
        # isolated.
        for row in rows:
            rid, name, tags = _extract_classify_row(row)
            tags_dict = tags if isinstance(tags, dict) else None
            result = classify_resource(name, tags_dict, None)
            if result is None:
                continue
            cls = result['classification']
            confidence = result['confidence']
            source = result['source']
            try:
                cursor.execute(
                    f"""
                    UPDATE {spec['table']}
                       SET data_classification        = %s,
                           classification_confidence  = %s,
                           classification_source      = %s
                     WHERE id = %s
                    """,
                    (cls, confidence, source, rid),
                )
                if cursor.rowcount:
                    total_updated += 1
            except Exception as exc:
                logger.debug(
                    "[AG-180] classify UPDATE failed for %s id=%s: %s",
                    spec['table'], rid, exc,
                )
                try:
                    cursor.connection.rollback()
                except Exception:
                    pass

    try:
        cursor.connection.commit()
    except Exception as exc:  # pragma: no cover
        logger.warning("[AG-180] classify_undiscovered_resources commit failed: %s", exc)

    try:
        cursor.close()
    except Exception:
        pass

    logger.info(
        "[AG-180] classify_undiscovered_resources run=%s org=%s updated=%d",
        run_id, organization_id, total_updated,
    )
    return total_updated


# ─────────────────────────────────────────────────────────────────────────────
# Helper: get_agent_data_reachability (API read shape)
# ─────────────────────────────────────────────────────────────────────────────

def get_agent_data_reachability(
    cursor: Any,
    identity_db_id: int,
    organization_id: int,
) -> list[dict[str, Any]]:
    """Return the rollup rows for one agent shaped for API consumption.

    Shape per row:
      {
        'data_classification':   'PHI',
        'resource_count':        int,
        'write_resource_count':  int,
        'est_records':           int | None,
        'top_resources':         list[dict],
      }

    Rows are sorted by classification name for stable client rendering.
    Returns [] if the identity has no rollup yet (e.g. it's not an AI agent
    or the engine hasn't run since the latest discovery).
    """
    if not identity_db_id or not organization_id:
        return []

    sp_name = f"{_SP_PREFIX}_read_agent"
    rows: list[Any] = []
    try:
        cursor.execute(f"SAVEPOINT {sp_name}")
        cursor.execute(
            """
            SELECT data_classification,
                   resource_count,
                   write_resource_count,
                   est_records,
                   top_resources
              FROM agent_data_reachability
             WHERE identity_db_id = %s
               AND organization_id = %s
             ORDER BY data_classification ASC
            """,
            (int(identity_db_id), int(organization_id)),
        )
        rows = cursor.fetchall()
        cursor.execute(f"RELEASE SAVEPOINT {sp_name}")
    except Exception as exc:
        logger.debug(
            "[AG-180] get_agent_data_reachability read failed: %s", exc,
        )
        try:
            cursor.execute(f"ROLLBACK TO SAVEPOINT {sp_name}")
        except Exception:
            pass
        return []

    out: list[dict[str, Any]] = []
    for r in rows:
        cls, rc, wc, est, top = _extract_rollup_row(r)
        out.append({
            'data_classification':  cls,
            'resource_count':       int(rc or 0),
            'write_resource_count': int(wc or 0),
            'est_records':          int(est) if est is not None else None,
            'top_resources':        _coerce_top_resources(top),
        })
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Internal: load agents
# ─────────────────────────────────────────────────────────────────────────────

def _load_agents(
    cursor: Any,
    run_id: int,
    organization_id: int,
    summary: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return [{id, identity_id, display_name}] for every AI agent in run.

    Agents are identified by EITHER:
      - identities.agent_identity_type ∈ {'ai_agent', 'possible_ai_agent'}, OR
      - agent_classifications.agent_identity_type = 'ai_agent' (the table
        is the canonical store; the column is a denormalised cache).
    The LEFT JOIN + OR predicate covers both paths so a stale identities row
    (where agent_identity_type wasn't back-filled) still resolves.
    """
    sp_name = f"{_SP_PREFIX}_agents"
    try:
        cursor.execute(f"SAVEPOINT {sp_name}")
        cursor.execute(
            """
            SELECT i.id, i.identity_id, i.display_name
              FROM identities i
              LEFT JOIN agent_classifications ac
                     ON ac.identity_db_id = i.id
                    AND ac.discovery_run_id = i.discovery_run_id
             WHERE i.discovery_run_id = %s
               AND i.organization_id  = %s
               AND (
                    i.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
                 OR ac.agent_identity_type = 'ai_agent'
               )
            """,
            (run_id, organization_id),
        )
        rows = cursor.fetchall()
        cursor.execute(f"RELEASE SAVEPOINT {sp_name}")
    except Exception as exc:
        logger.warning("[AG-180] agent cohort query failed: %s", exc)
        summary['errors'] += 1
        try:
            cursor.execute(f"ROLLBACK TO SAVEPOINT {sp_name}")
        except Exception:
            try:
                cursor.connection.rollback()
            except Exception:
                pass
        return []

    out: list[dict[str, Any]] = []
    seen: set[int] = set()
    for r in rows:
        rid, ident_id, name = _extract_agent_row(r)
        if rid is None or rid in seen:
            continue
        seen.add(rid)
        out.append({
            'id':           int(rid),
            'identity_id':  ident_id or '',
            'display_name': name or '',
        })
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Internal: load classified resources
# ─────────────────────────────────────────────────────────────────────────────

def _load_classified_resources(
    cursor: Any,
    run_id: int,
    organization_id: int,
    summary: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return classified storage / SQL / Cosmos resources for the run.

    Each entry: {resource_id, resource_type, name, data_classification,
    est_records}. Key vaults are intentionally excluded — see module docstring.
    """
    out: list[dict[str, Any]] = []

    # ── Storage accounts ────────────────────────────────────────────
    sp_storage = f"{_SP_PREFIX}_res_storage"
    try:
        cursor.execute(f"SAVEPOINT {sp_storage}")
        cursor.execute(
            """
            SELECT resource_id, name, data_classification, record_count_estimate
              FROM azure_storage_accounts
             WHERE organization_id  = %s
               AND discovery_run_id = %s
               AND data_classification IS NOT NULL
            """,
            (organization_id, run_id),
        )
        for r in cursor.fetchall():
            rid, name, cls, est = _extract_resource_row(r)
            if not rid or not cls:
                continue
            out.append({
                'resource_id':         rid,
                'resource_type':       'storage_account',
                'name':                name,
                'data_classification': cls,
                'est_records':         est,
            })
        cursor.execute(f"RELEASE SAVEPOINT {sp_storage}")
    except Exception as exc:
        logger.debug("[AG-180] storage classification scan failed: %s", exc)
        summary['errors'] += 1
        try:
            cursor.execute(f"ROLLBACK TO SAVEPOINT {sp_storage}")
        except Exception:
            try:
                cursor.connection.rollback()
            except Exception:
                pass

    # ── Azure SQL databases ────────────────────────────────────────
    sp_sql = f"{_SP_PREFIX}_res_sql"
    try:
        cursor.execute(f"SAVEPOINT {sp_sql}")
        cursor.execute(
            """
            SELECT resource_id, database_name, data_classification, record_count_estimate
              FROM azure_sql_databases
             WHERE organization_id  = %s
               AND discovery_run_id = %s
               AND data_classification IS NOT NULL
            """,
            (organization_id, run_id),
        )
        for r in cursor.fetchall():
            rid, name, cls, est = _extract_resource_row(r)
            if not rid or not cls:
                continue
            out.append({
                'resource_id':         rid,
                'resource_type':       'sql_database',
                'name':                name,
                'data_classification': cls,
                'est_records':         est,
            })
        cursor.execute(f"RELEASE SAVEPOINT {sp_sql}")
    except Exception as exc:
        logger.debug("[AG-180] azure_sql_databases scan failed: %s", exc)
        # Not counted as a hard error — table may not exist yet in old envs.
        try:
            cursor.execute(f"ROLLBACK TO SAVEPOINT {sp_sql}")
        except Exception:
            try:
                cursor.connection.rollback()
            except Exception:
                pass

    # ── Cosmos databases ───────────────────────────────────────────
    sp_cosmos = f"{_SP_PREFIX}_res_cosmos"
    try:
        cursor.execute(f"SAVEPOINT {sp_cosmos}")
        cursor.execute(
            """
            SELECT resource_id, database_name, data_classification, record_count_estimate
              FROM azure_cosmos_databases
             WHERE organization_id  = %s
               AND discovery_run_id = %s
               AND data_classification IS NOT NULL
            """,
            (organization_id, run_id),
        )
        for r in cursor.fetchall():
            rid, name, cls, est = _extract_resource_row(r)
            if not rid or not cls:
                continue
            out.append({
                'resource_id':         rid,
                'resource_type':       'cosmos_database',
                'name':                name,
                'data_classification': cls,
                'est_records':         est,
            })
        cursor.execute(f"RELEASE SAVEPOINT {sp_cosmos}")
    except Exception as exc:
        logger.debug("[AG-180] azure_cosmos_databases scan failed: %s", exc)
        try:
            cursor.execute(f"ROLLBACK TO SAVEPOINT {sp_cosmos}")
        except Exception:
            try:
                cursor.connection.rollback()
            except Exception:
                pass

    return out


# ─────────────────────────────────────────────────────────────────────────────
# Internal: upsert one rollup row
# ─────────────────────────────────────────────────────────────────────────────

def _upsert_rollup_row(
    cursor: Any,
    organization_id: int,
    run_id: int,
    identity_db_id: int,
    identity_id: str,
    classification: str,
    reachable: list[dict[str, Any]],
) -> None:
    """Compute counts + top_resources + est_records and UPSERT into
    agent_data_reachability.

    Honest-records rule: if ANY contributing resource has NULL est_records,
    the rollup's est_records is NULL too — never silently substitute zero.
    """
    resource_count = len(reachable)
    write_count = sum(
        1 for r in reachable
        if r.get('access_level') in _WRITE_ACCESS_LEVELS
    )

    # est_records — honest NULL accounting
    est_sum: Optional[int]
    if any(r.get('est_records') is None for r in reachable):
        est_sum = None
    else:
        est_sum = sum(int(r.get('est_records') or 0) for r in reachable)

    # top_resources — sort by est_records desc (NULLs last), then by resource_id
    # so output is stable across runs even when several resources are unknown.
    def _sort_key(r: dict[str, Any]) -> tuple[int, int, str]:
        est = r.get('est_records')
        # (null_rank, -est, resource_id) — known records first, then larger first
        if est is None:
            return (1, 0, r.get('resource_id') or '')
        return (0, -int(est), r.get('resource_id') or '')

    top = sorted(reachable, key=_sort_key)[:_TOP_RESOURCES_PER_CLASS]
    top_payload = [
        {
            'resource_id':   r['resource_id'],
            'resource_type': r['resource_type'],
            'name':          r.get('name'),
            'est_records':   (int(r['est_records']) if r.get('est_records') is not None else None),
            'access_level':  r.get('access_level'),
        }
        for r in top
    ]

    cursor.execute(
        """
        INSERT INTO agent_data_reachability (
            organization_id, discovery_run_id, identity_db_id, identity_id,
            data_classification, resource_count, write_resource_count,
            est_records, top_resources, computed_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, NOW()
        )
        ON CONFLICT (organization_id, discovery_run_id, identity_db_id, data_classification)
        DO UPDATE SET
            identity_id          = EXCLUDED.identity_id,
            resource_count       = EXCLUDED.resource_count,
            write_resource_count = EXCLUDED.write_resource_count,
            est_records          = EXCLUDED.est_records,
            top_resources        = EXCLUDED.top_resources,
            computed_at          = NOW()
        """,
        (
            organization_id,
            run_id,
            identity_db_id,
            identity_id,
            classification,
            resource_count,
            write_count,
            est_sum,
            json.dumps(top_payload),
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Row extraction helpers — tolerate dict, tuple, or DictRow
# ─────────────────────────────────────────────────────────────────────────────

def _extract_agent_row(row: Any) -> tuple[Optional[int], str, str]:
    """Pull (id, identity_id, display_name)."""
    if row is None:
        return None, '', ''
    if isinstance(row, dict):
        rid = row.get('id')
        return (
            int(rid) if rid is not None else None,
            row.get('identity_id') or '',
            row.get('display_name') or '',
        )
    try:
        return (
            int(row[0]) if row[0] is not None else None,
            row[1] or '',
            row[2] or '',
        )
    except (IndexError, TypeError, KeyError, ValueError):
        return None, '', ''


def _extract_resource_row(row: Any) -> tuple[str, str, str, Optional[int]]:
    """Pull (resource_id, name, data_classification, record_count_estimate)."""
    if row is None:
        return '', '', '', None
    if isinstance(row, dict):
        est = row.get('record_count_estimate')
        return (
            row.get('resource_id') or '',
            row.get('name') or row.get('database_name') or '',
            (row.get('data_classification') or '').upper(),
            int(est) if est is not None else None,
        )
    try:
        est = row[3]
        return (
            row[0] or '',
            row[1] or '',
            (row[2] or '').upper(),
            int(est) if est is not None else None,
        )
    except (IndexError, TypeError, KeyError, ValueError):
        return '', '', '', None


def _extract_classify_row(row: Any) -> tuple[Optional[int], str, Any]:
    """Pull (id, name, tags) for the classify back-fill scan."""
    if row is None:
        return None, '', None
    if isinstance(row, dict):
        rid = row.get('id')
        return (
            int(rid) if rid is not None else None,
            row.get('name') or '',
            row.get('tags'),
        )
    try:
        return (
            int(row[0]) if row[0] is not None else None,
            row[1] or '',
            row[2],
        )
    except (IndexError, TypeError, KeyError, ValueError):
        return None, '', None


def _extract_rollup_row(row: Any) -> tuple[str, int, int, Optional[int], Any]:
    """Pull (classification, resource_count, write_count, est_records, top)."""
    if row is None:
        return '', 0, 0, None, None
    if isinstance(row, dict):
        est = row.get('est_records')
        return (
            row.get('data_classification') or '',
            int(row.get('resource_count') or 0),
            int(row.get('write_resource_count') or 0),
            int(est) if est is not None else None,
            row.get('top_resources'),
        )
    try:
        est = row[3]
        return (
            row[0] or '',
            int(row[1] or 0),
            int(row[2] or 0),
            int(est) if est is not None else None,
            row[4],
        )
    except (IndexError, TypeError, KeyError, ValueError):
        return '', 0, 0, None, None


def _coerce_top_resources(value: Any) -> list[dict[str, Any]]:
    """Decode the top_resources JSONB into a list[dict].

    psycopg2 returns JSONB as a Python list/dict already, but some cursor
    configurations hand back the raw string — handle both.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except Exception:
            return []
        if isinstance(parsed, list):
            return [v for v in parsed if isinstance(v, dict)]
    return []


__all__ = [
    'refresh_data_reachability',
    'classify_undiscovered_resources',
    'get_agent_data_reachability',
]
