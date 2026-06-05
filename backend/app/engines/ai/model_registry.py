"""AI Model Registry (Tier 2.2) — approval workflow for AI model deployments.

Joins discovered model deployments (azure_ai_model_deployments) with the
approval table (ai_model_approvals) to surface a unified registry view:
every model the org runs, its approval status, who uses it, and what the
auto-classified risk band looks like.

Auto-classification (heuristic):
  - 'baseline' — well-known OpenAI base models (gpt-4o, gpt-4o-mini,
    dall-e-3, text-embedding-3-large/small, whisper-1). Low risk.
  - 'medium'   — preview / less-validated base models.
  - 'finetune' — name contains '-ft-' (Azure / OpenAI naming convention
    for fine-tuned variants). Always treated as needing approval —
    fine-tunes embed customer data and behavior outside vendor control.
  - 'custom'   — non-OpenAI vendor (model_format ≠ OpenAI/Azure/Microsoft).
  - 'high'     — fallback for unrecognised models.

The classification is advisory — the actual approval state is whatever
exists in ai_model_approvals.

Architecture rule: classification rules live in this module, NOT in
random places throughout handlers. Single source of truth.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Risk classification rules
# ─────────────────────────────────────────────────────────────────────────────

BASELINE_MODEL_PREFIXES = (
    'gpt-4o', 'gpt-4-turbo', 'gpt-4', 'gpt-3.5-turbo',
    'text-embedding-3-large', 'text-embedding-3-small',
    'text-embedding-ada-002',
    'dall-e-3', 'dall-e-2',
    'whisper-1',
)

VERIFIED_VENDORS = frozenset({'openai', 'azureopenai', 'microsoft', ''})


def classify_model(model_name: Optional[str], model_format: Optional[str]) -> str:
    """Return one of: baseline | medium | high | custom | finetune."""
    name = (model_name or '').lower().strip()
    vendor = (model_format or '').lower().strip()

    # Fine-tunes — strongest signal (always need approval)
    if '-ft-' in name or '-ft:' in name or name.endswith('-ft'):
        return 'finetune'

    # Non-verified vendor → custom (likely a third-party model on Azure ML)
    if vendor and vendor not in VERIFIED_VENDORS:
        return 'custom'

    # Verified-vendor baseline catalogue
    for prefix in BASELINE_MODEL_PREFIXES:
        if name.startswith(prefix):
            return 'baseline'

    # Preview / experimental — verified vendor but not in the known list
    if 'preview' in name or 'beta' in name:
        return 'medium'

    return 'high'


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def list_registry(db, org_id: int) -> list[dict[str, Any]]:
    """Return every discovered model × approval state, joined.

    Aggregates per (model_name, model_format, model_version) so the same
    model deployed in N accounts shows up once with the union of
    deployments + the count of agents who use it.
    """
    cursor = db.conn.cursor()
    try:
        cursor.execute("""
            WITH dep AS (
                SELECT
                    model_name,
                    COALESCE(model_format, '') AS model_format,
                    COALESCE(model_version, '') AS model_version,
                    COUNT(*) AS deployment_count,
                    COUNT(DISTINCT account_resource_id) AS account_count,
                    MAX(sku_capacity) AS max_capacity,
                    MIN(ingested_at) AS first_seen,
                    MAX(ingested_at) AS last_seen
                FROM azure_ai_model_deployments
                WHERE organization_id = %s
                GROUP BY model_name, COALESCE(model_format, ''), COALESCE(model_version, '')
            ),
            usage AS (
                SELECT
                    aimd.model_name,
                    COALESCE(aimd.model_format,'') AS model_format,
                    COALESCE(aimd.model_version,'') AS model_version,
                    COUNT(DISTINCT ac.identity_db_id) AS agent_count
                FROM azure_ai_model_deployments aimd
                JOIN agent_classifications ac
                  ON ac.account_resource_id = aimd.account_resource_id
                 AND ac.organization_id = aimd.organization_id
                WHERE aimd.organization_id = %s
                GROUP BY aimd.model_name, COALESCE(aimd.model_format,''), COALESCE(aimd.model_version,'')
            )
            SELECT
                dep.model_name, dep.model_format, dep.model_version,
                dep.deployment_count, dep.account_count, dep.max_capacity,
                dep.first_seen, dep.last_seen,
                COALESCE(u.agent_count, 0) AS agent_count,
                ama.id AS approval_id,
                ama.status AS approval_status,
                ama.risk_classification AS approval_risk_class,
                ama.requested_by, ama.requested_at,
                ama.reviewed_by, ama.reviewed_at,
                ama.justification, ama.review_notes,
                ama.expires_at
            FROM dep
            LEFT JOIN usage u
              ON u.model_name = dep.model_name
             AND u.model_format = dep.model_format
             AND u.model_version = dep.model_version
            LEFT JOIN ai_model_approvals ama
              ON ama.organization_id = %s
             AND ama.model_name = dep.model_name
             AND COALESCE(ama.model_format,'') = dep.model_format
             AND COALESCE(ama.model_version,'') = dep.model_version
            ORDER BY dep.model_name
        """, (org_id, org_id, org_id))
        rows = cursor.fetchall()
    finally:
        cursor.close()

    out = []
    for r in rows:
        (mname, mfmt, mver, dcount, acount, maxcap, first_seen, last_seen,
         agent_count, approval_id, status, approval_risk,
         req_by, req_at, rev_by, rev_at, justification, notes, expires_at) = r
        auto_risk = classify_model(mname, mfmt or None)
        # Effective status:
        # - if no approval row: 'unverified'
        # - if approval row + expires_at is in the past: 'expired'
        # - else: the row's status
        from datetime import datetime, timezone
        effective_status = status or 'unverified'
        if status == 'approved' and expires_at is not None:
            try:
                if expires_at < datetime.now(timezone.utc):
                    effective_status = 'expired'
            except Exception:
                pass

        out.append({
            'model_name': mname,
            'model_format': mfmt or None,
            'model_version': mver or None,
            'deployment_count': dcount,
            'account_count': acount,
            'max_capacity': maxcap,
            'agent_count': agent_count,
            'first_seen': first_seen.isoformat() if first_seen else None,
            'last_seen':  last_seen.isoformat() if last_seen else None,

            'auto_classification': auto_risk,
            'approval': {
                'id': approval_id,
                'status': status or 'unverified',
                'effective_status': effective_status,
                'risk_classification': approval_risk or auto_risk,
                'requested_by': req_by,
                'requested_at': req_at.isoformat() if req_at else None,
                'reviewed_by': rev_by,
                'reviewed_at': rev_at.isoformat() if rev_at else None,
                'justification': justification,
                'review_notes': notes,
                'expires_at': expires_at.isoformat() if expires_at else None,
            },
        })
    return out


def submit_for_review(db, org_id: int, model_name: str, model_format: Optional[str],
                       model_version: Optional[str], requested_by: str,
                       justification: Optional[str]) -> dict[str, Any]:
    """Move a model from 'unverified' to 'pending_review'.

    Upserts ai_model_approvals row.
    """
    cursor = db.conn.cursor()
    try:
        auto_risk = classify_model(model_name, model_format)
        cursor.execute("""
            INSERT INTO ai_model_approvals
                (organization_id, model_name, model_format, model_version,
                 status, risk_classification, requested_by, requested_at,
                 justification)
            VALUES (%s, %s, %s, %s, 'pending_review', %s, %s, NOW(), %s)
            ON CONFLICT (organization_id, model_name, model_format, model_version)
            DO UPDATE SET
                status = 'pending_review',
                risk_classification = COALESCE(ai_model_approvals.risk_classification, EXCLUDED.risk_classification),
                requested_by = EXCLUDED.requested_by,
                requested_at = NOW(),
                justification = EXCLUDED.justification
            RETURNING id, status, risk_classification, requested_by, requested_at
        """, (org_id, model_name, model_format or '', model_version or '',
              auto_risk, requested_by, justification))
        row = cursor.fetchone()
        db.conn.commit()
        return {
            'id': row[0], 'status': row[1], 'risk_classification': row[2],
            'requested_by': row[3], 'requested_at': row[4].isoformat() if row[4] else None,
        }
    finally:
        cursor.close()


def decide_review(db, org_id: int, model_name: str, model_format: Optional[str],
                    model_version: Optional[str], decision: str,
                    reviewed_by: str, review_notes: Optional[str],
                    expires_at: Optional[str]) -> dict[str, Any]:
    """Approve / reject a pending model.

    decision must be one of: 'approved', 'rejected'.
    """
    if decision not in ('approved', 'rejected'):
        raise ValueError(f"decision must be 'approved' or 'rejected', got {decision}")
    cursor = db.conn.cursor()
    try:
        cursor.execute("""
            UPDATE ai_model_approvals
               SET status = %s,
                   reviewed_by = %s,
                   reviewed_at = NOW(),
                   review_notes = %s,
                   expires_at = %s
             WHERE organization_id = %s
               AND model_name = %s
               AND COALESCE(model_format, '') = %s
               AND COALESCE(model_version, '') = %s
         RETURNING id, status, reviewed_by, reviewed_at, expires_at
        """, (decision, reviewed_by, review_notes, expires_at,
              org_id, model_name, model_format or '', model_version or ''))
        row = cursor.fetchone()
        if not row:
            return {}
        db.conn.commit()
        return {
            'id': row[0], 'status': row[1], 'reviewed_by': row[2],
            'reviewed_at': row[3].isoformat() if row[3] else None,
            'expires_at': row[4].isoformat() if row[4] else None,
        }
    finally:
        cursor.close()


def revoke(db, org_id: int, model_name: str, model_format: Optional[str],
            model_version: Optional[str], reviewed_by: str,
            notes: Optional[str]) -> dict[str, Any]:
    """Revoke a previously approved model."""
    cursor = db.conn.cursor()
    try:
        cursor.execute("""
            UPDATE ai_model_approvals
               SET status = 'revoked',
                   reviewed_by = %s,
                   reviewed_at = NOW(),
                   review_notes = %s
             WHERE organization_id = %s
               AND model_name = %s
               AND COALESCE(model_format, '') = %s
               AND COALESCE(model_version, '') = %s
         RETURNING id, status, reviewed_at
        """, (reviewed_by, notes,
              org_id, model_name, model_format or '', model_version or ''))
        row = cursor.fetchone()
        if not row:
            return {}
        db.conn.commit()
        return {'id': row[0], 'status': row[1],
                'reviewed_at': row[2].isoformat() if row[2] else None}
    finally:
        cursor.close()


def get_summary(rows: Iterable[dict]) -> dict[str, Any]:
    """Aggregate counts per status for the registry header."""
    counts = {'approved': 0, 'pending_review': 0, 'rejected': 0,
              'revoked': 0, 'unverified': 0, 'expired': 0}
    by_risk = {'baseline': 0, 'medium': 0, 'high': 0, 'custom': 0, 'finetune': 0}
    total_models = 0
    total_deployments = 0
    total_agents_using = 0
    for r in rows or []:
        total_models += 1
        total_deployments += int(r.get('deployment_count') or 0)
        total_agents_using = max(total_agents_using, int(r.get('agent_count') or 0))
        s = (r.get('approval', {}) or {}).get('effective_status') or 'unverified'
        if s in counts:
            counts[s] += 1
        rc = r.get('auto_classification') or 'baseline'
        if rc in by_risk:
            by_risk[rc] += 1
    return {
        'total_models': total_models,
        'total_deployments': total_deployments,
        'agents_using_models': total_agents_using,
        'by_status': counts,
        'by_risk_class': by_risk,
    }


__all__ = [
    'classify_model', 'list_registry', 'submit_for_review',
    'decide_review', 'revoke', 'get_summary',
    'BASELINE_MODEL_PREFIXES', 'VERIFIED_VENDORS',
]
