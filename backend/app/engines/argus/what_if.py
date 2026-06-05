"""
what_if — Architectural What-If Simulator (AG-190, Argus Layer 6)
=================================================================

Customer asks "What if I remove `Contributor` on /subscriptions/<X> from
this agent?" and gets back an honest before/after projection:

    - current risk score    (with the role)
    - projected risk score  (without the role)
    - which signals stop firing
    - which persisted attack_paths the agent loses (its source paths whose
      path_type / target_resource_type no longer makes sense without that
      role)
    - reduction percentage
    - confidence flag = 'projected'  (this is an *architectural* projection,
      not a measurement — we have not actually mutated anything)

NO actual mutations. The role_assignments row is *not* deleted. We compute
the agent's current signal set, then re-run the SAME `detect_signals()` SSOT
with the targeted role assignment filtered out of the input list. The
projection is purely a re-evaluation of the existing scoring catalog against
a hypothetical role_assignments cohort.

Honesty contract:
    1. weights, signals, and stacking math come from `constants.ai_risk`
       (`RISK_SIGNALS`, `detect_signals`, `aggregate_access_levels`,
       `compute_signal_score`). No literals duplicated here.
    2. attack-path impact is derived from the persisted `attack_paths` table
       — we only flag paths whose source_entity_id matches the agent AND
       whose target_resource_type / path_type would be unreachable without
       this role. We do NOT re-run the AttackPathEngine; that would be a
       measurement, not a projection.
    3. when the role_assignment row does not exist (or doesn't belong to the
       caller's identity / org), we return None and the handler 404s.
    4. confidence is always 'projected' — never 'measured', 'high', etc.
    5. `warning` is always present in the response so the UI can render the
       "architectural projection" caveat verbatim.

Used by:
    - POST /api/argus/what-if/role-removal
    - Argus "What if I remove this role?" drawer in IdentityDetail.

No N+1: a single what-if call issues at most four SQL queries (identity,
role_assignments, attack_paths, sp_ownership) each wrapped in its own
SAVEPOINT.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from ...constants.ai_risk import (
    RISK_SIGNALS,
    aggregate_access_levels,
    compute_signal_score,
    detect_signals,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Public API — simulate_role_removal
# ─────────────────────────────────────────────────────────────────────────────

def simulate_role_removal(
    cursor: Any,
    identity_db_id: int,
    role_assignment_id: int,
    organization_id: int,
) -> Optional[dict[str, Any]]:
    """Project the agent's risk score WITHOUT a specified role assignment.

    Args:
        cursor: an open psycopg2 cursor (caller owns the transaction).
        identity_db_id: identities.id of the agent.
        role_assignment_id: role_assignments.id to set aside (NOT deleted).
        organization_id: tenant scope; required so cross-org callers cannot
            project against an identity they don't own.

    Returns:
        {
          'identity_id':        '<external GUID>',
          'display_name':       'agent-prod-01',
          'role_assignment': {
              'id':         42,
              'role_name':  'Contributor',
              'scope':      '/subscriptions/<sub>',
              'scope_type': 'subscription',
          },
          'current_score':      8.5,     # 0–10 CVSS-aligned score
          'projected_score':    7.0,
          'reduction_pct':      17.65,   # (current - projected) / current * 100
          'current_severity':   'high',
          'projected_severity': 'high',
          'removed_signals':    [{signal, weight, title}, ...],
          'remaining_signals':  [{signal, weight, title}, ...],
          'removed_paths':      [{path_id, path_type, target_resource_type,
                                  severity, risk_score, description}, ...],
          'confidence':         'projected',
          'warning':            'Architectural projection — assumes current discovery state',
          'generated_at':       ISO-8601 timestamp,
        }

        Returns None when the identity or role assignment cannot be located
        for this org (handler turns this into 404).
    """
    if not identity_db_id or not role_assignment_id or not organization_id:
        return None

    iid = int(identity_db_id)
    rid = int(role_assignment_id)
    org = int(organization_id)

    # ── 1) Identity metadata (the agent_meta input for detect_signals) ─────
    meta = _load_identity_meta(cursor, iid, org)
    if not meta:
        return None

    # ── 2) Load ALL role assignments + targeted role separately. We hold
    #       both: `current_roles` (with) and `projected_roles` (without).
    role_assignments = _load_role_assignments(cursor, iid)
    target = _load_target_role_assignment(cursor, iid, rid)
    if not target:
        return None

    # ── 3) Owner presence (sp_ownership) — used by the "no_owner" signal
    #       check that detect_signals does NOT itself touch; we leave the
    #       meta.owner_display_name alone since detect_signals reads that
    #       directly and that field doesn't change when a role is removed.
    #       (No-op kept here as documentation of why we don't reload it.)

    # ── 4) Compute the CURRENT signals + score (with the targeted role) ────
    current_levels = aggregate_access_levels(role_assignments)
    current_signals = detect_signals(meta, role_assignments, current_levels)
    current_scored = compute_signal_score(current_signals)
    current_score = float(current_scored.get('score') or 0.0)
    current_severity = current_scored.get('severity') or 'info'

    # ── 5) Project the cohort WITHOUT the targeted role.
    projected_roles = [
        ra for ra in role_assignments
        if int(ra.get('id') or 0) != rid
    ]
    projected_levels = aggregate_access_levels(projected_roles)
    projected_signals = detect_signals(meta, projected_roles, projected_levels)
    projected_scored = compute_signal_score(projected_signals)
    projected_score = float(projected_scored.get('score') or 0.0)
    projected_severity = projected_scored.get('severity') or 'info'

    # ── 6) Diff signals (set-difference by signal key) ─────────────────────
    current_keys = {(s.get('key') or '') for s in current_signals}
    projected_keys = {(s.get('key') or '') for s in projected_signals}
    removed_keys = current_keys - projected_keys

    removed_signals = _serialize_signal_diff(current_signals, removed_keys)
    remaining_signals = _serialize_signal_diff(
        projected_signals,
        projected_keys,
    )

    # ── 7) Persisted attack-path impact. We flag only paths where this
    #       agent is the source AND the path's plausible reachability
    #       depends on the targeted role's scope / role family. We do NOT
    #       re-run AttackPathEngine — that would be a measurement, not a
    #       projection.
    removed_paths = _attack_paths_dependent_on_role(
        cursor=cursor,
        identity_external_id=meta.get('identity_id') or '',
        organization_id=org,
        target_role=target,
    )

    # ── 8) Reduction percentage (guard div-by-zero; honest 0 when score = 0)
    if current_score > 0:
        reduction_pct = round(
            max(0.0, (current_score - projected_score) / current_score) * 100.0,
            2,
        )
    else:
        reduction_pct = 0.0

    return {
        'identity_id':        meta.get('identity_id') or '',
        'display_name':       meta.get('display_name') or '',
        'role_assignment': {
            'id':         int(target.get('id') or rid),
            'role_name':  target.get('role_name') or '',
            'scope':      target.get('scope') or '',
            'scope_type': target.get('scope_type') or '',
        },
        'current_score':      current_score,
        'projected_score':    projected_score,
        'reduction_pct':      reduction_pct,
        'current_severity':   current_severity,
        'projected_severity': projected_severity,
        'removed_signals':    removed_signals,
        'remaining_signals':  remaining_signals,
        'removed_paths':      removed_paths,
        'confidence':         'projected',
        'warning':            'Architectural projection — assumes current discovery state',
        'generated_at':       datetime.now(timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Data loaders — each wrapped in its own SAVEPOINT
# ─────────────────────────────────────────────────────────────────────────────

def _load_identity_meta(cursor: Any, iid: int, org: int) -> Optional[dict[str, Any]]:
    """Load identities row scoped to the org. None if not found."""
    sp = 'ag190_load_identity'
    try:
        cursor.execute(f"SAVEPOINT {sp}")
        cursor.execute(
            """
            SELECT id, identity_id, display_name, owner_display_name,
                   last_sign_in, last_activity_date,
                   credential_status, credential_expiration,
                   detected_platform
              FROM identities
             WHERE id = %s
               AND organization_id = %s
            """,
            (iid, org),
        )
        row = cursor.fetchone()
        cursor.execute(f"RELEASE SAVEPOINT {sp}")
    except Exception as exc:
        logger.warning("[AG-190] identity meta load failed: %s", exc)
        try:
            cursor.execute(f"ROLLBACK TO SAVEPOINT {sp}")
        except Exception:
            pass
        return None
    if not row:
        return None

    cols = [
        'id', 'identity_id', 'display_name', 'owner_display_name',
        'last_sign_in', 'last_activity_date', 'credential_status',
        'credential_expiration', 'detected_platform',
    ]
    rec = _row_to_dict(row, cols)
    # Mirror explain_risk_score: detect_signals expects credential_risk = 'expired'
    cs = (rec.get('credential_status') or '').lower()
    if cs == 'expired':
        rec['credential_risk'] = 'expired'
    return rec


def _load_role_assignments(cursor: Any, iid: int) -> list[dict[str, Any]]:
    """Load all role_assignments for this identity, including the id column
    so we can filter the targeted row out for the projection.
    """
    sp = 'ag190_load_roles'
    try:
        cursor.execute(f"SAVEPOINT {sp}")
        cursor.execute(
            """
            SELECT id, role_name, scope, scope_type, created_on
              FROM role_assignments
             WHERE identity_db_id = %s
            """,
            (iid,),
        )
        rows = cursor.fetchall()
        cursor.execute(f"RELEASE SAVEPOINT {sp}")
    except Exception as exc:
        logger.debug("[AG-190] role_assignments load failed: %s", exc)
        try:
            cursor.execute(f"ROLLBACK TO SAVEPOINT {sp}")
        except Exception:
            pass
        return []

    out: list[dict[str, Any]] = []
    cols = ['id', 'role_name', 'scope', 'scope_type', 'created_on']
    for r in rows:
        out.append(_row_to_dict(r, cols))
    return out


def _load_target_role_assignment(
    cursor: Any,
    iid: int,
    rid: int,
) -> Optional[dict[str, Any]]:
    """Confirm the targeted role_assignment belongs to this identity.
    None when the row doesn't exist or belongs to a different identity —
    callers must NOT be able to project removal of a role they don't own.
    """
    sp = 'ag190_load_target'
    try:
        cursor.execute(f"SAVEPOINT {sp}")
        cursor.execute(
            """
            SELECT id, role_name, scope, scope_type, created_on
              FROM role_assignments
             WHERE id = %s
               AND identity_db_id = %s
            """,
            (rid, iid),
        )
        row = cursor.fetchone()
        cursor.execute(f"RELEASE SAVEPOINT {sp}")
    except Exception as exc:
        logger.warning("[AG-190] target role load failed: %s", exc)
        try:
            cursor.execute(f"ROLLBACK TO SAVEPOINT {sp}")
        except Exception:
            pass
        return None
    if not row:
        return None
    cols = ['id', 'role_name', 'scope', 'scope_type', 'created_on']
    return _row_to_dict(row, cols)


def _attack_paths_dependent_on_role(
    *,
    cursor: Any,
    identity_external_id: str,
    organization_id: int,
    target_role: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return persisted attack_paths rows whose existence depends on the
    targeted role being held by this agent.

    Dependency criteria (intentionally conservative — false negatives are
    fine; false positives must be avoided):
      - Path source is the agent (source_entity_id matches).
      - The path's `target_resource_id` falls inside the targeted role's
        scope (string-prefix containment) OR
        the path's `path_type` matches a family that the targeted role
        enables (broad subscription roles enable direct_escalation /
        ownership_chain / lateral_movement; key-vault / storage roles
        enable sensitive_data_exposure).

    We never invent a path. If `attack_paths` is empty for this agent we
    return [] honestly.
    """
    if not identity_external_id:
        return []

    role_name = (target_role.get('role_name') or '')
    scope = (target_role.get('scope') or '').lower()

    # Which persisted path families plausibly depend on this role?
    relevant_path_types = _path_types_enabled_by_role(role_name)

    sp = 'ag190_load_paths'
    try:
        cursor.execute(f"SAVEPOINT {sp}")
        cursor.execute(
            """
            SELECT path_id, path_type, severity, risk_score,
                   description, target_resource_id, target_resource_type
              FROM attack_paths
             WHERE organization_id = %s
               AND source_entity_id = %s
            """,
            (organization_id, identity_external_id),
        )
        rows = cursor.fetchall()
        cursor.execute(f"RELEASE SAVEPOINT {sp}")
    except Exception as exc:
        logger.debug("[AG-190] attack_paths load failed: %s", exc)
        try:
            cursor.execute(f"ROLLBACK TO SAVEPOINT {sp}")
        except Exception:
            pass
        return []

    cols = [
        'path_id', 'path_type', 'severity', 'risk_score',
        'description', 'target_resource_id', 'target_resource_type',
    ]
    paths = [_row_to_dict(r, cols) for r in rows]

    out: list[dict[str, Any]] = []
    for p in paths:
        ptype = (p.get('path_type') or '')
        target_id = (p.get('target_resource_id') or '').lower()

        scope_match = bool(scope and target_id and scope in target_id)
        family_match = ptype in relevant_path_types

        if scope_match or family_match:
            out.append({
                'path_id':              str(p.get('path_id') or ''),
                'path_type':            ptype,
                'target_resource_type': p.get('target_resource_type') or '',
                'target_resource_id':   p.get('target_resource_id') or '',
                'severity':             p.get('severity') or '',
                'risk_score':           int(p.get('risk_score') or 0),
                'description':          p.get('description') or '',
            })
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Role → enabled-path-family mapping
# ─────────────────────────────────────────────────────────────────────────────

# Conservative mapping from role families to the persisted attack_paths
# path_type values they enable. Derived from the path families that
# attack_path_engine.AttackPathEngine actually emits (direct_escalation /
# ownership_chain / pim_escalation / lateral_movement /
# sensitive_data_exposure / external_identity_risk /
# ai_agent_exfiltration). We only mark a path family as "enabled by this
# role" when removing the role would plausibly invalidate the path — i.e.
# the role is the load-bearing privilege.

_BROAD_SUB_ROLES = frozenset({
    'Owner',
    'Contributor',
    'User Access Administrator',
})

_KV_ADMIN_ROLES = frozenset({
    'Key Vault Administrator',
    'Key Vault Secrets Officer',
    'Key Vault Crypto Officer',
    'Key Vault Certificates Officer',
})

_STORAGE_OWNER_ROLES = frozenset({
    'Storage Blob Data Owner',
})

_STORAGE_WRITE_ROLES = frozenset({
    'Storage Blob Data Contributor',
    'Storage Table Data Contributor',
    'Storage Queue Data Contributor',
    'Storage File Data SMB Share Contributor',
    'Cosmos DB Built-in Data Contributor',
    'SQL DB Contributor',
})


def _path_types_enabled_by_role(role_name: str) -> set[str]:
    """Return the set of attack_paths.path_type values whose existence
    plausibly depends on the agent holding this role.

    The empty set is honest — "we don't have a known dependency" — and the
    caller falls back to scope-containment matching.
    """
    if not role_name:
        return set()
    if role_name in _BROAD_SUB_ROLES:
        return {
            'direct_escalation',
            'ownership_chain',
            'lateral_movement',
            'pim_escalation',
            'ai_agent_exfiltration',
        }
    if role_name in _KV_ADMIN_ROLES:
        return {'sensitive_data_exposure', 'ai_agent_exfiltration'}
    if role_name in _STORAGE_OWNER_ROLES or role_name in _STORAGE_WRITE_ROLES:
        return {'sensitive_data_exposure', 'ai_agent_exfiltration'}
    return set()


# ─────────────────────────────────────────────────────────────────────────────
# Diff serialization
# ─────────────────────────────────────────────────────────────────────────────

def _serialize_signal_diff(
    signals: list[dict[str, Any]],
    keys: set[str],
) -> list[dict[str, Any]]:
    """Render a set of signal keys as the [{signal, weight, title}, ...]
    contract used by the response. Weights are pulled from RISK_SIGNALS so
    the simulator never invents a weight; an unresolved spec yields
    weight=None and the consumer can surface that honestly.
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for s in signals:
        key = s.get('key') or ''
        if key not in keys or key in seen:
            continue
        seen.add(key)
        spec = RISK_SIGNALS.get(key) or {}
        weight: Optional[int] = None
        if isinstance(spec.get('weight'), int):
            weight = int(spec['weight'])
        out.append({
            'signal':   key,
            'weight':   weight,
            'title':    spec.get('title') or key.replace('_', ' ').title(),
            'evidence': s.get('evidence') or '',
        })
    # Heaviest first so the UI shows the biggest change at the top.
    out.sort(key=lambda r: (r.get('weight') if r.get('weight') is not None else -1),
             reverse=True)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Small helpers
# ─────────────────────────────────────────────────────────────────────────────

def _row_to_dict(row: Any, columns: list[str]) -> dict[str, Any]:
    """Coerce a psycopg2 row (dict, tuple, or DictRow) into a plain dict.

    Mirrors the helpers in explain_risk_score / agent_trust_scorer — caller
    can use any cursor factory.
    """
    if row is None:
        return {}
    if isinstance(row, dict):
        return {c: row.get(c) for c in columns}
    try:
        return {columns[i]: row[i] for i in range(min(len(columns), len(row)))}
    except (IndexError, TypeError, KeyError):
        return {}


__all__ = ['simulate_role_removal']
