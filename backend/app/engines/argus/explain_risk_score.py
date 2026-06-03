"""
explain_risk_score — Risk Score Waterfall (AG-189, Argus Layer 5)
==================================================================

Customer asks "Why is risk score 530?" and gets back an honest, evidence-cited
waterfall: every fired signal, the points it contributes, and the specific
role / scope / resource that triggers it. No fabricated weights.

Reuses the SSOT signal logic from `constants.ai_risk` — the same
`detect_signals()` function that drives the AI Inventory CVSS-aligned score,
the Trust Score (`scoring.agent_trust_scorer`), and the anomaly detector. We
do NOT invent a parallel scoring catalog. This engine is a *view* on the
same signals: it re-groups them into a per-row waterfall with graph evidence
and MITRE / framework tags pulled from canonical sources.

Used by:
    - GET /api/argus/explain-risk-score/<identity_id>
    - Argus "Why is this risk score what it is?" drawer
    - Auditor pack per-identity evidence breakdown

Honesty contract:
    1. weights come from `RISK_SIGNALS[*].weight` ONLY. No literals in this file.
    2. evidence strings cite concrete graph rows (role name + scope + since DATE),
       never templated placeholders.
    3. when a signal fires but the underlying weight cannot be resolved from
       RISK_SIGNALS, weight is None and evidence says "Detected but weight not
       assigned" — never silently zero, never invented.
    4. MITRE techniques come from constants.mitre.enrich_path_node_with_mitre
       and constants.mitre.get_technique. Never hardcoded strings.

No N+1: a single agent expand uses at most five queries (identities,
role_assignments+key_vaults+storage_accounts+data_reachability join), each
wrapped in its own SAVEPOINT so a missing optional table cannot poison the
outer transaction.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from ...constants.ai_risk import (
    RISK_SIGNALS,
    aggregate_access_levels,
    detect_signals,
)
from ...constants.mitre import (
    enrich_path_node_with_mitre,
    get_technique,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Public: explain_risk_score (single identity, full waterfall)
# ─────────────────────────────────────────────────────────────────────────────

def explain_risk_score(
    cursor: Any,
    identity_db_id: int,
    organization_id: int,
) -> Optional[dict[str, Any]]:
    """Return a per-signal waterfall breakdown of the identity's risk score.

    Args:
        cursor: an open psycopg2 cursor (caller owns the transaction).
        identity_db_id: identities.id (FK target for role_assignments).
        organization_id: tenant scope; required so the evidence queries
            cannot leak across orgs even if a caller passes a cross-tenant id.

    Returns:
        {
            'identity_id':    str,                  # external GUID
            'display_name':   str,
            'total_score':    int,                  # sum of contribution weights
            'contributions':  list[dict],           # see below
            'method':         'signal_decomposition',
            'generated_at':   ISO-8601 timestamp,
        }

        Each contribution:
        {
            'signal':           'key_vault_admin',
            'label':            'Holds Key Vault Administrator or Secrets Officer',
            'weight':           150,                # int OR None when unresolved
            'evidence':         'Holds Key Vault Administrator on /subscriptions/... since 2026-04-12',
            'role_name':        'Key Vault Administrator' | None,
            'scope':            '/subscriptions/.../resourceGroups/.../...' | None,
            'mitre_techniques': ['T1552.001', 'T1555.006'],
            'framework_refs':   {
                'nist':     ['SC-12 (Cryptographic Key Establishment)', ...],
                'cis_azure':['CIS Azure 8.5'],
                'mitre':    ['T1552.001', ...],
            },
        }

        Returns None when the identity cannot be located in this org's scope.
    """
    if not identity_db_id or not organization_id:
        return None

    iid = int(identity_db_id)
    org = int(organization_id)

    # ── 1) Identity metadata (agent_meta input for detect_signals) ─────────
    meta = _load_identity_meta(cursor, iid, org)
    if not meta:
        return None

    # ── 2) Role assignments + per-role created_on (for "since DATE" evidence)
    role_assignments = _load_role_assignments(cursor, iid)

    # ── 3) Aggregate access levels (same call detect_signals expects) ──────
    access_levels = aggregate_access_levels(role_assignments)

    # ── 4) Fire the SAME signals that drive the score ──────────────────────
    fired = detect_signals(meta, role_assignments, access_levels)

    # ── 5) Per-signal evidence lookups (KV name + since DATE, storage name,
    #       sensitive data classification reachable, etc.) — keyed by signal.
    kv_ctx = _kv_evidence(cursor, iid, org, role_assignments)
    storage_ctx = _storage_evidence(cursor, iid, org, role_assignments)
    sensitive_ctx = _sensitive_data_evidence(cursor, iid, org)

    # ── 6) Build the contribution rows ─────────────────────────────────────
    contributions: list[dict[str, Any]] = []
    total = 0
    for sig in fired:
        key = sig.get('key') or ''
        spec = RISK_SIGNALS.get(key)
        weight: Optional[int] = None
        if spec and isinstance(spec.get('weight'), int):
            weight = int(spec['weight'])

        # Resolve concrete graph evidence + role_name/scope per signal.
        row = _build_contribution(
            signal_key=key,
            sig=sig,
            spec=spec,
            role_assignments=role_assignments,
            meta=meta,
            kv_ctx=kv_ctx,
            storage_ctx=storage_ctx,
            sensitive_ctx=sensitive_ctx,
        )
        row['weight'] = weight

        # MITRE techniques via canonical helper (no hardcoded strings).
        row['mitre_techniques'] = _resolve_mitre_for_signal(
            signal_key=key,
            spec=spec,
            role_name=row.get('role_name'),
            meta=meta,
            sensitive_ctx=sensitive_ctx,
        )

        # Framework refs come from RISK_SIGNALS spec (NIST + MITRE) and from
        # risk_catalog for CIS where applicable. We never invent control IDs.
        row['framework_refs'] = _framework_refs(spec, row['mitre_techniques'], key)

        contributions.append(row)
        if weight is not None:
            total += weight

    # Sort heaviest contributions first — matches the waterfall UI.
    contributions.sort(
        key=lambda c: (c.get('weight') if c.get('weight') is not None else -1),
        reverse=True,
    )

    return {
        'identity_id':   meta.get('identity_id') or '',
        'display_name':  meta.get('display_name') or '',
        'total_score':   int(total),
        'contributions': contributions,
        'method':        'signal_decomposition',
        'generated_at':  datetime.now(timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Data loaders — each wrapped in its own SAVEPOINT
# ─────────────────────────────────────────────────────────────────────────────

def _load_identity_meta(cursor: Any, iid: int, org: int) -> Optional[dict[str, Any]]:
    """Read the identity row scoped to the org. None if not found."""
    sp = 'ag189_load_identity'
    try:
        cursor.execute(f"SAVEPOINT {sp}")
        cursor.execute(
            """
            SELECT id, identity_id, display_name, owner_display_name,
                   last_sign_in, last_activity_date,
                   credential_status, credential_expiration,
                   COALESCE(credential_status, '') AS credential_risk
              FROM identities
             WHERE id = %s
               AND organization_id = %s
            """,
            (iid, org),
        )
        row = cursor.fetchone()
        cursor.execute(f"RELEASE SAVEPOINT {sp}")
    except Exception as exc:
        logger.warning("[AG-189] identity meta load failed: %s", exc)
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
        'credential_expiration', 'credential_risk',
    ]
    rec = _row_to_dict(row, cols)

    # detect_signals expects credential_risk as 'expired' | other. Map the
    # canonical column credential_status -> credential_risk for the signal.
    cs = (rec.get('credential_status') or '').lower()
    if cs == 'expired':
        rec['credential_risk'] = 'expired'
    return rec


def _load_role_assignments(cursor: Any, iid: int) -> list[dict[str, Any]]:
    """Load all role_assignments for this identity, with created_on for
    "since DATE" evidence strings. Empty list on failure.
    """
    sp = 'ag189_load_roles'
    try:
        cursor.execute(f"SAVEPOINT {sp}")
        cursor.execute(
            """
            SELECT role_name, scope, scope_type, created_on
              FROM role_assignments
             WHERE identity_db_id = %s
            """,
            (iid,),
        )
        rows = cursor.fetchall()
        cursor.execute(f"RELEASE SAVEPOINT {sp}")
    except Exception as exc:
        logger.debug("[AG-189] role_assignments load failed: %s", exc)
        try:
            cursor.execute(f"ROLLBACK TO SAVEPOINT {sp}")
        except Exception:
            pass
        return []

    out: list[dict[str, Any]] = []
    cols = ['role_name', 'scope', 'scope_type', 'created_on']
    for r in rows:
        out.append(_row_to_dict(r, cols))
    return out


def _kv_evidence(
    cursor: Any,
    iid: int,
    org: int,
    role_assignments: list[dict[str, Any]],
) -> Optional[dict[str, Any]]:
    """Pick the worst Key Vault role this identity holds and look up the
    Key Vault `name` from azure_key_vaults so the evidence string reads
    "Holds KV Admin on kv-prod-secrets since DATE" — not just a raw URI.
    """
    kv_admin_roles = {
        'Key Vault Administrator',
        'Key Vault Secrets Officer',
        'Key Vault Crypto Officer',
        'Key Vault Certificates Officer',
    }
    candidates = [
        ra for ra in role_assignments
        if (ra.get('role_name') or '') in kv_admin_roles
    ]
    if not candidates:
        return None

    # Prefer Administrator > Secrets Officer > others (descending privilege).
    rank = {
        'Key Vault Administrator': 4,
        'Key Vault Secrets Officer': 3,
        'Key Vault Crypto Officer': 2,
        'Key Vault Certificates Officer': 1,
    }
    candidates.sort(key=lambda ra: rank.get(ra.get('role_name') or '', 0), reverse=True)
    best = candidates[0]
    scope = best.get('scope') or ''
    kv_name = _resource_name_from_scope(scope, 'vaults')

    # If scope is a vault, try resolving the friendly name from the discovered
    # KV inventory (handles odd casing / synthetic ids).
    if kv_name:
        sp = 'ag189_kv_lookup'
        try:
            cursor.execute(f"SAVEPOINT {sp}")
            cursor.execute(
                """
                SELECT name
                  FROM azure_key_vaults
                 WHERE organization_id = %s
                   AND (LOWER(resource_id) = LOWER(%s) OR LOWER(name) = LOWER(%s))
                 LIMIT 1
                """,
                (org, scope, kv_name),
            )
            row = cursor.fetchone()
            cursor.execute(f"RELEASE SAVEPOINT {sp}")
            if row:
                kv_name = _row_to_dict(row, ['name']).get('name') or kv_name
        except Exception as exc:
            logger.debug("[AG-189] kv name lookup failed: %s", exc)
            try:
                cursor.execute(f"ROLLBACK TO SAVEPOINT {sp}")
            except Exception:
                pass

    return {
        'role_name':  best.get('role_name'),
        'scope':      scope or None,
        'kv_name':    kv_name,
        'created_on': best.get('created_on'),
    }


def _storage_evidence(
    cursor: Any,
    iid: int,
    org: int,
    role_assignments: list[dict[str, Any]],
) -> Optional[dict[str, Any]]:
    """Resolve the storage-account name behind a Storage Blob Data Owner role
    (or the strongest data-write role) for `storage_blob_owner` /
    `sensitive_data_access` evidence.
    """
    owner_roles = {'Storage Blob Data Owner'}
    write_roles = {
        'Storage Blob Data Contributor',
        'Storage Table Data Contributor',
        'Storage Queue Data Contributor',
        'Storage File Data SMB Share Contributor',
        'Cosmos DB Built-in Data Contributor',
        'SQL DB Contributor',
    }
    # Prefer Owner; fall back to a write role for sensitive_data_access.
    chosen = next(
        (ra for ra in role_assignments
         if (ra.get('role_name') or '') in owner_roles),
        None,
    )
    if chosen is None:
        chosen = next(
            (ra for ra in role_assignments
             if (ra.get('role_name') or '') in write_roles),
            None,
        )
    if chosen is None:
        return None

    scope = chosen.get('scope') or ''
    storage_name = _resource_name_from_scope(scope, 'storageAccounts')

    if storage_name:
        sp = 'ag189_storage_lookup'
        try:
            cursor.execute(f"SAVEPOINT {sp}")
            cursor.execute(
                """
                SELECT name, data_classification
                  FROM azure_storage_accounts
                 WHERE organization_id = %s
                   AND (LOWER(resource_id) = LOWER(%s) OR LOWER(name) = LOWER(%s))
                 LIMIT 1
                """,
                (org, scope, storage_name),
            )
            row = cursor.fetchone()
            cursor.execute(f"RELEASE SAVEPOINT {sp}")
            if row:
                rec = _row_to_dict(row, ['name', 'data_classification'])
                storage_name = rec.get('name') or storage_name
        except Exception as exc:
            logger.debug("[AG-189] storage name lookup failed: %s", exc)
            try:
                cursor.execute(f"ROLLBACK TO SAVEPOINT {sp}")
            except Exception:
                pass

    return {
        'role_name':    chosen.get('role_name'),
        'scope':        scope or None,
        'storage_name': storage_name,
        'created_on':   chosen.get('created_on'),
    }


def _sensitive_data_evidence(
    cursor: Any,
    iid: int,
    org: int,
) -> Optional[dict[str, Any]]:
    """Return aggregate sensitive-data reachability for the identity.

    Sourced from `agent_data_reachability` (the canonical AG-180 rollup
    table). Used to enrich the `sensitive_data_access` evidence and to
    upgrade MITRE tagging on the same signal (T1530 only fires when the
    reachable storage is classified).
    """
    sp = 'ag189_sensitive_lookup'
    try:
        cursor.execute(f"SAVEPOINT {sp}")
        cursor.execute(
            """
            SELECT data_classification,
                   resource_count,
                   write_resource_count
              FROM agent_data_reachability
             WHERE identity_db_id = %s
               AND organization_id = %s
             ORDER BY resource_count DESC
            """,
            (iid, org),
        )
        rows = cursor.fetchall()
        cursor.execute(f"RELEASE SAVEPOINT {sp}")
    except Exception as exc:
        logger.debug("[AG-189] sensitive data lookup failed: %s", exc)
        try:
            cursor.execute(f"ROLLBACK TO SAVEPOINT {sp}")
        except Exception:
            pass
        return None

    if not rows:
        return None

    cols = ['data_classification', 'resource_count', 'write_resource_count']
    parsed = [_row_to_dict(r, cols) for r in rows]
    classifications = [p.get('data_classification') for p in parsed if p.get('data_classification')]
    total_resources = sum(int(p.get('resource_count') or 0) for p in parsed)
    total_writes = sum(int(p.get('write_resource_count') or 0) for p in parsed)
    return {
        'classifications': classifications,
        'total_resources': total_resources,
        'total_writes':    total_writes,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Contribution builder + evidence formatting
# ─────────────────────────────────────────────────────────────────────────────

def _build_contribution(
    *,
    signal_key: str,
    sig: dict[str, Any],
    spec: Optional[dict[str, Any]],
    role_assignments: list[dict[str, Any]],
    meta: dict[str, Any],
    kv_ctx: Optional[dict[str, Any]],
    storage_ctx: Optional[dict[str, Any]],
    sensitive_ctx: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """Map a fired signal to the {signal, label, evidence, role_name, scope}
    shape consumed by the waterfall UI. Evidence strings cite concrete graph
    rows where possible. Honesty: if the signal fires but the supporting row
    isn't found, the evidence comes verbatim from detect_signals — no
    fabrication.
    """
    label = (spec or {}).get('title') or signal_key.replace('_', ' ').title()

    # Honest fallback when RISK_SIGNALS doesn't define a weight.
    if spec is None or not isinstance(spec.get('weight'), int):
        return {
            'signal':    signal_key,
            'label':     label,
            'evidence':  'Detected but weight not assigned',
            'role_name': None,
            'scope':     None,
        }

    role_name: Optional[str] = None
    scope: Optional[str] = None
    evidence: str = sig.get('evidence') or ''

    if signal_key == 'key_vault_admin' and kv_ctx:
        role_name = kv_ctx.get('role_name')
        scope = kv_ctx.get('scope')
        kv_label = kv_ctx.get('kv_name') or scope or 'an unknown Key Vault'
        evidence = (
            f"Holds {role_name} on {kv_label}"
            f"{_since_clause(kv_ctx.get('created_on'))}"
        )

    elif signal_key == 'storage_blob_owner' and storage_ctx:
        role_name = storage_ctx.get('role_name')
        scope = storage_ctx.get('scope')
        st_label = storage_ctx.get('storage_name') or scope or 'an unknown storage account'
        evidence = (
            f"Holds {role_name} on {st_label}"
            f"{_since_clause(storage_ctx.get('created_on'))}"
        )

    elif signal_key == 'sensitive_data_access':
        if storage_ctx:
            role_name = storage_ctx.get('role_name')
            scope = storage_ctx.get('scope')
        if sensitive_ctx and sensitive_ctx.get('classifications'):
            classes = ', '.join(sorted({c for c in sensitive_ctx['classifications']}))
            n = sensitive_ctx.get('total_resources', 0)
            target = (storage_ctx or {}).get('storage_name') or scope or ''
            target_clause = f" on {target}" if target else ''
            evidence = (
                f"Write access reaches {n} classified resource(s) "
                f"[{classes}]{target_clause}"
                f"{_since_clause((storage_ctx or {}).get('created_on'))}"
            )
        elif storage_ctx:
            target = storage_ctx.get('storage_name') or scope or ''
            target_clause = f" on {target}" if target else ''
            evidence = (
                f"Holds {role_name}{target_clause}"
                f"{_since_clause(storage_ctx.get('created_on'))}"
            )

    elif signal_key == 'broad_owner_role':
        broad = next(
            (ra for ra in role_assignments
             if (ra.get('role_name') or '') in {'Owner', 'Contributor', 'User Access Administrator'}
             and (ra.get('scope') or '').startswith('/subscriptions/')
             and (ra.get('scope') or '').count('/') == 2),
            None,
        )
        if broad:
            role_name = broad.get('role_name')
            scope = broad.get('scope')
            evidence = (
                f"Holds {role_name} on {scope}"
                f"{_since_clause(broad.get('created_on'))}"
            )

    elif signal_key == 'no_owner':
        evidence = 'No human owner assigned in sp_ownership or identities.owner_display_name'

    elif signal_key == 'no_telemetry':
        evidence = 'No sign-in / activity / Graph audit log entries in the lookback window'

    elif signal_key == 'unrestricted_egress':
        # Find a scope that matches an internet-facing pattern.
        from ...constants.ai_risk import INTERNET_EGRESS_SCOPE_PATTERNS
        offending = next(
            (ra for ra in role_assignments
             if any(pat in (ra.get('scope') or '').lower()
                    for pat in INTERNET_EGRESS_SCOPE_PATTERNS)),
            None,
        )
        if offending:
            role_name = offending.get('role_name')
            scope = offending.get('scope')
            evidence = (
                f"Role scope reaches internet-facing resource: {scope}"
                f"{_since_clause(offending.get('created_on'))}"
            )

    elif signal_key == 'expired_credential':
        exp = meta.get('credential_expiration')
        if exp is not None:
            evidence = f"Credential expired at {_iso(exp)}"

    elif signal_key == 'dormant_agent':
        last = meta.get('last_activity_date') or meta.get('last_sign_in')
        if last is not None:
            evidence = f"No activity since {_iso(last)}"

    # If we still have nothing, fall back to detect_signals' own evidence so
    # the row is at least cited; never fabricate a fake graph reference.
    if not evidence:
        evidence = sig.get('evidence') or 'Signal fired (no additional evidence loaded)'

    return {
        'signal':    signal_key,
        'label':     label,
        'evidence':  evidence,
        'role_name': role_name,
        'scope':     scope,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Framework + MITRE resolution
# ─────────────────────────────────────────────────────────────────────────────

# Conservative CIS Azure Foundations Benchmark mapping per signal — derived
# from existing risk_catalog.cis tags (RBAC + KV + Storage + Networking
# control families). Each entry references a real CIS Azure v2.1 control;
# no invented IDs.
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


def _framework_refs(
    spec: Optional[dict[str, Any]],
    mitre_ids: list[str],
    signal_key: str,
) -> dict[str, list[str]]:
    """Return {nist, cis_azure, mitre} for one signal.

    NIST + MITRE come from RISK_SIGNALS (spec); CIS Azure from the local
    mapping derived from risk_catalog. Returning an empty list for a
    framework is honest — it means the signal isn't formally mapped to that
    framework yet, not that the framework doesn't exist.
    """
    nist = list((spec or {}).get('nist') or [])
    cis_azure = list(_CIS_AZURE_BY_SIGNAL.get(signal_key, []))
    return {
        'nist':      nist,
        'cis_azure': cis_azure,
        'mitre':     list(mitre_ids),
    }


def _resolve_mitre_for_signal(
    *,
    signal_key: str,
    spec: Optional[dict[str, Any]],
    role_name: Optional[str],
    meta: dict[str, Any],
    sensitive_ctx: Optional[dict[str, Any]],
) -> list[str]:
    """Resolve MITRE technique IDs for this signal via constants.mitre.

    Honors the existing contract from enrich_path_node_with_mitre:
        - storage_account techniques only fire when sensitive data is present
        - network_egress techniques only fire when egress is unrestricted

    Falls back to the per-signal mitre list in RISK_SIGNALS (which is also
    the canonical source) and validates every ID via get_technique() — IDs
    that aren't in MITRE_TECHNIQUES are dropped, never invented.
    """
    techniques: list[dict] = []

    if signal_key == 'broad_owner_role' and role_name:
        techniques = enrich_path_node_with_mitre(
            'role_assignment', role_name=role_name,
        )
    elif signal_key == 'key_vault_admin' and role_name:
        techniques = enrich_path_node_with_mitre(
            'kv_secret', role_name=role_name,
        )
    elif signal_key == 'storage_blob_owner' and role_name:
        techniques = enrich_path_node_with_mitre(
            'storage_account',
            role_name=role_name,
            has_sensitive_data=bool(sensitive_ctx and sensitive_ctx.get('classifications')),
        )
    elif signal_key == 'sensitive_data_access':
        techniques = enrich_path_node_with_mitre(
            'storage_account',
            role_name=role_name,
            has_sensitive_data=bool(sensitive_ctx and sensitive_ctx.get('classifications')),
        )
    elif signal_key == 'unrestricted_egress':
        techniques = enrich_path_node_with_mitre(
            'network_egress', egress_open=True,
        )
    elif signal_key == 'external_llm_access':
        techniques = enrich_path_node_with_mitre(
            'network_egress', egress_open=True,
        )

    ids = [t['id'] for t in techniques if t and t.get('id')]

    # Augment with the per-signal mitre list from RISK_SIGNALS — these are
    # the techniques the signal canonically maps to. Validate each via
    # get_technique() so unregistered IDs are dropped (no fabrication).
    for tid in ((spec or {}).get('mitre') or []):
        if tid in ids:
            continue
        if get_technique(tid):
            ids.append(tid)
    return ids


# ─────────────────────────────────────────────────────────────────────────────
# Small helpers
# ─────────────────────────────────────────────────────────────────────────────

def _row_to_dict(row: Any, columns: list[str]) -> dict[str, Any]:
    """Coerce a psycopg2 row (dict, tuple, or DictRow) into a plain dict.

    Mirrors the helper in agent_trust_scorer — tolerates mixed cursor
    factories so callers don't have to wrap RealDictCursor.
    """
    if row is None:
        return {}
    if isinstance(row, dict):
        return {c: row.get(c) for c in columns}
    try:
        return {columns[i]: row[i] for i in range(min(len(columns), len(row)))}
    except (IndexError, TypeError, KeyError):
        return {}


def _iso(value: Any) -> str:
    """Best-effort ISO-8601 / YYYY-MM-DD render of a datetime / str value."""
    if value is None:
        return ''
    if isinstance(value, datetime):
        return value.date().isoformat()
    try:
        dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return dt.date().isoformat()
    except Exception:
        return str(value)


def _since_clause(created_on: Any) -> str:
    """Render ' since YYYY-MM-DD' when the role created_on is available.

    Empty string when unknown — we never invent a date.
    """
    iso = _iso(created_on)
    if not iso:
        return ''
    return f" since {iso}"


def _resource_name_from_scope(scope: str, segment: str) -> Optional[str]:
    """Pull the resource name immediately following /<segment>/ in an ARM scope.

    e.g. _resource_name_from_scope(
        '/subscriptions/.../providers/Microsoft.KeyVault/vaults/kv-prod-secrets',
        'vaults',
    ) -> 'kv-prod-secrets'
    """
    if not scope or not segment:
        return None
    parts = scope.split('/')
    marker = f'/{segment}/'.lower()
    if marker not in scope.lower():
        return None
    try:
        # Find the index of `segment` case-insensitively.
        lower = [p.lower() for p in parts]
        idx = lower.index(segment.lower())
        if idx + 1 < len(parts):
            return parts[idx + 1] or None
    except ValueError:
        return None
    return None


__all__ = ['explain_risk_score']
