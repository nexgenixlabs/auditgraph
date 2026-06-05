"""
ciso_advisor — Argus Layer 4: Board / CISO Advisor (AG-188)
============================================================

Customer asks "What should I fix this week?" → returns a ranked priority list
of 3-5 remediations with *measurable* impact (e.g. "P1: 892 ownerless SPNs
(-43% identity attack surface). P2: 6 AI agents w/ KV Admin (-credential-theft
path)").

The recommender is *signal-driven*: every priority maps 1:1 to a fired entry
in ``constants.ai_risk.RISK_SIGNALS``. We do NOT invent fix categories —
this engine is a *view* over the same signal catalogue that drives:
  - the AI Inventory CVSS-aligned risk score
  - ``argus.explain_risk_score`` (the per-identity waterfall)
  - ``scoring.agent_trust_scorer`` (the board-ready Trust dimensions)
  - the anomaly detector

Ranking formula (per signal):
    priority_score = affected_count * max_blast_radius * (signal_count * 1)

  - ``affected_count``      — number of distinct identities the signal fires on
                              right now (from real DB aggregates).
  - ``max_blast_radius``    — the worst ``identities.blast_radius_score``
                              across the affected cohort. Falls back to the
                              signal's RISK_SIGNALS weight scaled to a
                              comparable range when no blast_radius data is
                              available.
  - ``signal_count``        — 1 today; multiplied so the formula matches the
                              spec verbatim and so a future per-identity
                              co-occurrence aggregate can up-weight stacked
                              findings without a code change.

Top 5 are returned. If none fire, ``priorities`` is empty and ``message``
explains the healthy state.

No fake data contract:
  1. Every aggregate comes from a SQL COUNT/MAX/MIN against the live tables
     scoped by ``organization_id`` + the latest discovery run per connection.
     If a table is missing in the snapshot, the signal is silently skipped
     (the priority list shrinks; we never invent rows).
  2. ``framework_refs`` come from ``RISK_SIGNALS[*].nist`` + a conservative
     CIS Azure mapping reused from ``explain_risk_score._CIS_AZURE_BY_SIGNAL``
     so the two engines never contradict each other.
  3. ``impact`` is computed from the *measured* reduction (% of identities the
     fix would remove from the affected cohort) — when we cannot compute a
     percentage we say "reduces N identities" instead of fabricating one.
  4. ``link_to_queue`` is None until an actual ``remediation_queue`` row is
     created for the priority; we deliberately do not auto-create queue
     entries here (write-path is the caller's job).

Used by:
    - GET /api/argus/recommendations
    - Argus "What should I fix this week?" dashboard tile
    - Auditor pack executive summary (top 5 actions section)

All queries are SAVEPOINT-wrapped so a missing optional table cannot poison
the outer transaction.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from ...constants.ai_risk import RISK_SIGNALS, BROAD_PRIVILEGE_ROLES

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Framework-refs mapping — copied verbatim from explain_risk_score so the two
# engines stay in lock-step. (Local copy to keep ciso_advisor importable
# without dragging the L5 waterfall surface in.)
# ─────────────────────────────────────────────────────────────────────────────

_CIS_AZURE_BY_SIGNAL: dict[str, list[str]] = {
    'broad_owner_role':       ['CIS Azure 1.22', 'CIS Azure 1.23'],
    'key_vault_admin':        ['CIS Azure 8.5'],
    'storage_blob_owner':     ['CIS Azure 3.1', 'CIS Azure 3.7'],
    'sensitive_data_access':  ['CIS Azure 3.1', 'CIS Azure 4.1'],
    'no_telemetry':           ['CIS Azure 5.1.1', 'CIS Azure 5.4'],
    'unrestricted_egress':    ['CIS Azure 6.1'],
    'external_llm_access':    ['CIS Azure 6.1'],
    'expired_credential':     ['CIS Azure 1.14'],
    'dormant_agent':          ['CIS Azure 1.3'],
    'no_owner':               ['CIS Azure 1.22'],
}


# Maximum number of priorities to surface. The product spec says "3-5"; we
# return up to 5 and the UI can truncate further if needed.
_TOP_N = 5


# Key Vault role names that count as KV admin / secrets-bearing. Mirrors
# explain_risk_score._kv_evidence so the two engines agree on what "KV admin"
# means.
_KV_ADMIN_ROLES: tuple[str, ...] = (
    'Key Vault Administrator',
    'Key Vault Secrets Officer',
    'Key Vault Crypto Officer',
    'Key Vault Certificates Officer',
)

# Storage owner / write roles for storage_blob_owner + sensitive_data_access.
_STORAGE_OWNER_ROLES: tuple[str, ...] = ('Storage Blob Data Owner',)
_STORAGE_WRITE_ROLES: tuple[str, ...] = (
    'Storage Blob Data Contributor',
    'Storage Table Data Contributor',
    'Storage Queue Data Contributor',
    'Storage File Data SMB Share Contributor',
    'Cosmos DB Built-in Data Contributor',
    'SQL DB Contributor',
)


# ─────────────────────────────────────────────────────────────────────────────
# Savepoint helpers (identical to the L3 / L5 modules — local copy keeps this
# engine self-contained).
# ─────────────────────────────────────────────────────────────────────────────

def _sp(cursor: Any, name: str) -> bool:
    try:
        cursor.execute(f"SAVEPOINT {name}")
        return True
    except Exception as exc:
        logger.debug("ciso_advisor: SAVEPOINT %s failed: %s", name, exc)
        return False


def _release(cursor: Any, name: str) -> None:
    try:
        cursor.execute(f"RELEASE SAVEPOINT {name}")
    except Exception:
        pass


def _rollback(cursor: Any, name: str) -> None:
    try:
        cursor.execute(f"ROLLBACK TO SAVEPOINT {name}")
    except Exception:
        pass


def _cell(row: Any, idx: int, key: str) -> Any:
    """Tuple/dict-cursor agnostic cell access."""
    if row is None:
        return None
    if isinstance(row, dict):
        return row.get(key)
    try:
        return row[idx]
    except (IndexError, KeyError, TypeError):
        return None


def _latest_run_ids(cursor: Any, organization_id: int) -> list[int]:
    """Latest completed run per active cloud_connection_id (mirrors the
    handler helper). Empty list when the org has no runs yet.
    """
    sp = 'ciso_runs'
    if not _sp(cursor, sp):
        return []
    try:
        cursor.execute(
            """
            SELECT DISTINCT ON (dr.cloud_connection_id) dr.id
              FROM discovery_runs dr
              JOIN cloud_connections cc ON cc.id = dr.cloud_connection_id
             WHERE dr.status IN ('completed', 'partial')
               AND dr.organization_id = %s
               AND dr.cloud_connection_id IS NOT NULL
               AND dr.cloud_connection_id > 0
               AND cc.status = 'connected'
             ORDER BY dr.cloud_connection_id, dr.id DESC
            """,
            (organization_id,),
        )
        rows = cursor.fetchall() or []
        _release(cursor, sp)
    except Exception as exc:
        logger.debug("ciso_advisor: latest-run lookup failed: %s", exc)
        _rollback(cursor, sp)
        return []

    out: list[int] = []
    for r in rows:
        rid = _cell(r, 0, 'id')
        if rid is not None:
            try:
                out.append(int(rid))
            except (TypeError, ValueError):
                pass
    return out


def _total_identity_count(cursor: Any, organization_id: int,
                          run_ids: list[int]) -> int:
    """Total identities in the latest snapshot. Used as the denominator for
    the "reduces N% attack surface" impact string. Returns 0 on failure.
    """
    if not run_ids:
        return 0
    sp = 'ciso_total_ids'
    if not _sp(cursor, sp):
        return 0
    try:
        cursor.execute(
            """
            SELECT COUNT(*)
              FROM identities
             WHERE organization_id = %s
               AND discovery_run_id = ANY(%s)
            """,
            (organization_id, run_ids),
        )
        row = cursor.fetchone()
        _release(cursor, sp)
        if row is None:
            return 0
        v = _cell(row, 0, 'count')
        return int(v or 0)
    except Exception as exc:
        logger.debug("ciso_advisor: total identity count failed: %s", exc)
        _rollback(cursor, sp)
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Per-signal aggregate queries — each returns (affected_count, max_blast).
# A return of (0, 0) means the signal is healthy and is dropped from the
# ranking. A failed query (missing table, etc.) also returns (0, 0) so the
# priority list shrinks rather than fabricating a count.
# ─────────────────────────────────────────────────────────────────────────────

def _aggregate(
    cursor: Any,
    sp_name: str,
    sql: str,
    params: tuple,
) -> tuple[int, int]:
    """Run an aggregate query that returns (count, max_blast_radius_score).
    Tolerates missing tables — returns (0, 0) on any DB error.
    """
    if not _sp(cursor, sp_name):
        return (0, 0)
    try:
        cursor.execute(sql, params)
        row = cursor.fetchone()
        _release(cursor, sp_name)
    except Exception as exc:
        logger.debug("ciso_advisor: aggregate %s failed: %s", sp_name, exc)
        _rollback(cursor, sp_name)
        return (0, 0)
    if row is None:
        return (0, 0)
    cnt = _cell(row, 0, 'cnt')
    mbr = _cell(row, 1, 'max_blast')
    try:
        return (int(cnt or 0), int(mbr or 0))
    except (TypeError, ValueError):
        return (0, 0)


def _agg_no_owner(cursor: Any, organization_id: int,
                  run_ids: list[int]) -> tuple[int, int]:
    """Identities with no human owner. ``owner_count = 0`` AND
    ``owner_display_name IS NULL/empty`` AND no row in ``sp_ownership``.

    Excludes Microsoft-internal first-party SPNs so we don't ding Microsoft.
    """
    if not run_ids:
        return (0, 0)
    return _aggregate(
        cursor,
        'ciso_no_owner',
        """
        SELECT COUNT(*) AS cnt,
               COALESCE(MAX(i.blast_radius_score), 0) AS max_blast
          FROM identities i
         WHERE i.organization_id = %s
           AND i.discovery_run_id = ANY(%s)
           AND COALESCE(i.is_microsoft_system, false) = false
           AND COALESCE(i.owner_count, 0) = 0
           AND COALESCE(NULLIF(TRIM(i.owner_display_name), ''), '') = ''
           AND NOT EXISTS (
               SELECT 1 FROM sp_ownership o
                WHERE o.identity_db_id = i.id
                  AND (o.organization_id IS NULL OR o.organization_id = %s)
           )
        """,
        (organization_id, run_ids, organization_id),
    )


def _agg_key_vault_admin(cursor: Any, organization_id: int,
                         run_ids: list[int]) -> tuple[int, int]:
    """Identities holding any Key Vault admin / secrets-officer role."""
    if not run_ids:
        return (0, 0)
    return _aggregate(
        cursor,
        'ciso_kv_admin',
        """
        SELECT COUNT(DISTINCT i.id) AS cnt,
               COALESCE(MAX(i.blast_radius_score), 0) AS max_blast
          FROM identities i
          JOIN role_assignments ra ON ra.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND i.discovery_run_id = ANY(%s)
           AND ra.role_name = ANY(%s)
        """,
        (organization_id, run_ids, list(_KV_ADMIN_ROLES)),
    )


def _agg_broad_owner_role(cursor: Any, organization_id: int,
                          run_ids: list[int]) -> tuple[int, int]:
    """Identities holding Owner / Contributor / UAA at subscription scope.

    Subscription scope = path of the form '/subscriptions/<guid>' (exactly two
    slashes). Tighter scopes are excluded — they're real least-privilege.
    """
    if not run_ids:
        return (0, 0)
    return _aggregate(
        cursor,
        'ciso_broad_owner',
        """
        SELECT COUNT(DISTINCT i.id) AS cnt,
               COALESCE(MAX(i.blast_radius_score), 0) AS max_blast
          FROM identities i
          JOIN role_assignments ra ON ra.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND i.discovery_run_id = ANY(%s)
           AND ra.role_name = ANY(%s)
           AND ra.scope LIKE '/subscriptions/%%'
           AND (LENGTH(ra.scope) - LENGTH(REPLACE(ra.scope, '/', ''))) = 2
        """,
        (organization_id, run_ids, list(BROAD_PRIVILEGE_ROLES)),
    )


def _agg_storage_blob_owner(cursor: Any, organization_id: int,
                            run_ids: list[int]) -> tuple[int, int]:
    """Identities holding Storage Blob Data Owner."""
    if not run_ids:
        return (0, 0)
    return _aggregate(
        cursor,
        'ciso_blob_owner',
        """
        SELECT COUNT(DISTINCT i.id) AS cnt,
               COALESCE(MAX(i.blast_radius_score), 0) AS max_blast
          FROM identities i
          JOIN role_assignments ra ON ra.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND i.discovery_run_id = ANY(%s)
           AND ra.role_name = ANY(%s)
        """,
        (organization_id, run_ids, list(_STORAGE_OWNER_ROLES)),
    )


def _agg_sensitive_data_access(cursor: Any, organization_id: int,
                               run_ids: list[int]) -> tuple[int, int]:
    """Identities with write access to storage/SQL/Cosmos that excludes
    Storage Blob Data Owner (already counted in storage_blob_owner).
    """
    if not run_ids:
        return (0, 0)
    return _aggregate(
        cursor,
        'ciso_sensitive_data',
        """
        SELECT COUNT(DISTINCT i.id) AS cnt,
               COALESCE(MAX(i.blast_radius_score), 0) AS max_blast
          FROM identities i
          JOIN role_assignments ra ON ra.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND i.discovery_run_id = ANY(%s)
           AND ra.role_name = ANY(%s)
           AND NOT EXISTS (
               SELECT 1 FROM role_assignments ra2
                WHERE ra2.identity_db_id = i.id
                  AND ra2.role_name = ANY(%s)
           )
        """,
        (organization_id, run_ids,
         list(_STORAGE_WRITE_ROLES), list(_STORAGE_OWNER_ROLES)),
    )


def _agg_expired_credential(cursor: Any, organization_id: int,
                            run_ids: list[int]) -> tuple[int, int]:
    """Identities with at least one expired credential still attached."""
    if not run_ids:
        return (0, 0)
    return _aggregate(
        cursor,
        'ciso_expired_cred',
        """
        SELECT COUNT(*) AS cnt,
               COALESCE(MAX(i.blast_radius_score), 0) AS max_blast
          FROM identities i
         WHERE i.organization_id = %s
           AND i.discovery_run_id = ANY(%s)
           AND LOWER(COALESCE(i.credential_status, '')) = 'expired'
        """,
        (organization_id, run_ids),
    )


def _agg_dormant_agent(cursor: Any, organization_id: int,
                       run_ids: list[int]) -> tuple[int, int]:
    """Identities dormant 90+ days while still holding role assignments.

    Restricted to AI agents (agent_classifications) when the table exists,
    otherwise falls back to identity_category in ('service_principal',
    'managed_identity_*') so the signal still has signal in older snapshots.
    """
    if not run_ids:
        return (0, 0)
    # Try the AI-agent-scoped variant first; fall back if the table is absent.
    ai_scoped = _aggregate(
        cursor,
        'ciso_dormant_agent',
        """
        SELECT COUNT(DISTINCT i.id) AS cnt,
               COALESCE(MAX(i.blast_radius_score), 0) AS max_blast
          FROM identities i
          JOIN agent_classifications ac ON ac.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND i.discovery_run_id = ANY(%s)
           AND ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
           AND COALESCE(i.days_since_last_use, 0) >= 90
           AND EXISTS (
               SELECT 1 FROM role_assignments ra
                WHERE ra.identity_db_id = i.id
           )
        """,
        (organization_id, run_ids),
    )
    if ai_scoped[0] > 0:
        return ai_scoped
    return _aggregate(
        cursor,
        'ciso_dormant_spn',
        """
        SELECT COUNT(*) AS cnt,
               COALESCE(MAX(i.blast_radius_score), 0) AS max_blast
          FROM identities i
         WHERE i.organization_id = %s
           AND i.discovery_run_id = ANY(%s)
           AND i.identity_category IN ('service_principal',
                                       'managed_identity_system',
                                       'managed_identity_user')
           AND COALESCE(i.days_since_last_use, 0) >= 90
           AND EXISTS (
               SELECT 1 FROM role_assignments ra
                WHERE ra.identity_db_id = i.id
           )
        """,
        (organization_id, run_ids),
    )


# Map signal_key → aggregator. Order here is irrelevant; ranking is what
# orders priorities. Adding a new signal = add a row to RISK_SIGNALS, a row
# to _CIS_AZURE_BY_SIGNAL, and a row here.
_AGGREGATORS: dict[str, Any] = {
    'no_owner':              _agg_no_owner,
    'key_vault_admin':       _agg_key_vault_admin,
    'broad_owner_role':      _agg_broad_owner_role,
    'storage_blob_owner':    _agg_storage_blob_owner,
    'sensitive_data_access': _agg_sensitive_data_access,
    'expired_credential':    _agg_expired_credential,
    'dormant_agent':         _agg_dormant_agent,
}


# ─────────────────────────────────────────────────────────────────────────────
# Title + impact + remediation builders
# ─────────────────────────────────────────────────────────────────────────────

def _title_for(signal_key: str, affected_count: int) -> str:
    """Render a board-ready priority title from a signal + cohort size.

    Templates are signal-specific but deliberately concise. Numbers come from
    the live aggregate; never hardcoded.
    """
    n = affected_count
    s = '' if n == 1 else 's'
    if signal_key == 'no_owner':
        return f"{n} ownerless identit{'y' if n == 1 else 'ies'}"
    if signal_key == 'key_vault_admin':
        return f"{n} identit{'y' if n == 1 else 'ies'} with Key Vault admin / Secrets Officer role"
    if signal_key == 'broad_owner_role':
        return f"{n} identit{'y' if n == 1 else 'ies'} holding Owner / Contributor / UAA at subscription scope"
    if signal_key == 'storage_blob_owner':
        return f"{n} identit{'y' if n == 1 else 'ies'} holding Storage Blob Data Owner"
    if signal_key == 'sensitive_data_access':
        return f"{n} identit{'y' if n == 1 else 'ies'} with direct write access to storage / SQL / Cosmos"
    if signal_key == 'expired_credential':
        return f"{n} identit{'y' if n == 1 else 'ies'} with expired credentials still attached"
    if signal_key == 'dormant_agent':
        return f"{n} dormant identit{'y' if n == 1 else 'ies'} (90+ days) still permission-bearing"
    # Fallback — use the RISK_SIGNALS title plus the count.
    spec = RISK_SIGNALS.get(signal_key) or {}
    title = spec.get('title') or signal_key.replace('_', ' ').title()
    return f"{n} identit{'y' if n == 1 else 'ies'}: {title}"


def _impact_for(signal_key: str, affected_count: int, total_identities: int) -> str:
    """Render a measurable-impact string from real counts.

    When ``total_identities > 0`` we compute the % of the cohort the fix would
    remove. Otherwise we degrade gracefully to a count-only phrase. We never
    invent a percentage.
    """
    if affected_count <= 0:
        return "reduces 0 identities"
    if total_identities > 0:
        pct = round((affected_count / total_identities) * 100, 1)
        return f"reduces {pct}% identity attack surface ({affected_count}/{total_identities} identit{'y' if total_identities == 1 else 'ies'})"
    return f"reduces {affected_count} identit{'y' if affected_count == 1 else 'ies'}"


def _remediation_for(signal_key: str) -> str:
    """Concrete fix sourced from RISK_SIGNALS. Honest empty-string fallback."""
    spec = RISK_SIGNALS.get(signal_key) or {}
    return spec.get('remediation') or ''


def _framework_refs_for(signal_key: str) -> dict[str, list[str]]:
    """{nist, cis_azure, mitre} sourced from RISK_SIGNALS + the local CIS map.

    Returning an empty list per framework is honest — means the signal isn't
    formally mapped yet, not that the framework doesn't exist.
    """
    spec = RISK_SIGNALS.get(signal_key) or {}
    nist = list(spec.get('nist') or [])
    mitre = list(spec.get('mitre') or [])
    cis_azure = list(_CIS_AZURE_BY_SIGNAL.get(signal_key, []))
    return {'nist': nist, 'cis_azure': cis_azure, 'mitre': mitre}


def _max_blast_for_ranking(signal_key: str, raw_max_blast: int) -> int:
    """Blast-radius input to the ranking formula.

    When the cohort has at least one identity with a non-zero
    ``blast_radius_score`` we use that — that's the real measured radius.
    When all measured radii are zero (or the column hasn't been backfilled)
    we fall back to the signal's RISK_SIGNALS.weight so the ranking still
    differentiates between Key Vault admin (weight 150) and dormant_agent
    (weight 25) instead of treating them as equal.
    """
    if raw_max_blast > 0:
        return raw_max_blast
    spec = RISK_SIGNALS.get(signal_key) or {}
    w = spec.get('weight')
    if isinstance(w, int) and w > 0:
        return w
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def recommend_fixes(cursor: Any, organization_id: int) -> dict[str, Any]:
    """Return the top 5 remediation priorities for the caller's org.

    Args:
        cursor: open psycopg2 cursor (tuple or RealDictCursor — both work).
            Caller owns the transaction.
        organization_id: tenant scope. Required — passing ``None`` returns
            the healthy-state shape immediately (cannot meaningfully rank
            without an org).

    Returns:
        {
          'priorities':    list[dict],            # up to 5, ranked
          'message':       str,                   # set when priorities==[]
          'method':        'signal_aggregate_ranking',
          'total_identities': int,
          'generated_at':  ISO-8601 timestamp,
        }

        Each priority:
        {
          'rank':                int,             # 1-5
          'signal':              'no_owner',      # RISK_SIGNALS key
          'title':               'P1: 892 ownerless identities',
          'impact':              'reduces 43% identity attack surface ...',
          'affected_count':      int,
          'max_blast_radius':    int,
          'signal_count':        int,             # always 1 today
          'priority_score':      int,             # the ranking number
          'remediation_action':  str,             # from RISK_SIGNALS
          'link_to_queue':       None,            # populated by caller post-create
          'framework_refs':      {nist, cis_azure, mitre},
        }

    Honesty contract: if nothing fires, ``priorities=[]`` and ``message``
    explains the healthy state. We never fabricate counts.
    """
    if organization_id is None:
        return {
            'priorities':       [],
            'message':          'No critical fixes recommended.',
            'method':           'signal_aggregate_ranking',
            'total_identities': 0,
            'generated_at':     datetime.now(timezone.utc).isoformat(),
        }

    org = int(organization_id)
    run_ids = _latest_run_ids(cursor, org)
    if not run_ids:
        return {
            'priorities':       [],
            'message':          'No discovery runs yet — connect a cloud and run discovery to populate recommendations.',
            'method':           'signal_aggregate_ranking',
            'total_identities': 0,
            'generated_at':     datetime.now(timezone.utc).isoformat(),
        }

    total_identities = _total_identity_count(cursor, org, run_ids)

    # Compute the aggregate per signal. Drop signals that don't fire.
    candidates: list[dict[str, Any]] = []
    for signal_key, aggregator in _AGGREGATORS.items():
        try:
            affected, max_blast = aggregator(cursor, org, run_ids)
        except Exception as exc:
            logger.warning("ciso_advisor: aggregator %s raised: %s",
                           signal_key, exc, exc_info=False)
            affected, max_blast = (0, 0)
        if affected <= 0:
            continue

        # signal_count is 1 today — the formula multiplies so a future
        # per-identity co-occurrence rollup can up-weight stacked findings.
        signal_count = 1
        ranking_blast = _max_blast_for_ranking(signal_key, max_blast)
        priority_score = int(affected) * int(ranking_blast) * int(signal_count)
        if priority_score <= 0:
            # Defensive: ranking_blast can be 0 only when both the column is
            # un-populated AND the signal has no weight in RISK_SIGNALS.
            # Skip rather than rank with 0.
            continue

        candidates.append({
            'signal':             signal_key,
            'title':              _title_for(signal_key, int(affected)),
            'impact':             _impact_for(signal_key, int(affected), total_identities),
            'affected_count':     int(affected),
            'max_blast_radius':   int(ranking_blast),
            'signal_count':       int(signal_count),
            'priority_score':     int(priority_score),
            'remediation_action': _remediation_for(signal_key),
            'link_to_queue':      None,
            'framework_refs':     _framework_refs_for(signal_key),
        })

    if not candidates:
        return {
            'priorities':       [],
            'message':          'No critical fixes recommended.',
            'method':           'signal_aggregate_ranking',
            'total_identities': total_identities,
            'generated_at':     datetime.now(timezone.utc).isoformat(),
        }

    # Rank by priority_score desc, tiebreak on affected_count then weight.
    candidates.sort(
        key=lambda c: (
            -int(c['priority_score']),
            -int(c['affected_count']),
            -int((RISK_SIGNALS.get(c['signal']) or {}).get('weight') or 0),
        )
    )

    top = candidates[:_TOP_N]
    for i, p in enumerate(top, start=1):
        p['rank'] = i

    return {
        'priorities':       top,
        'method':           'signal_aggregate_ranking',
        'total_identities': total_identities,
        'generated_at':     datetime.now(timezone.utc).isoformat(),
    }


__all__ = ['recommend_fixes']
