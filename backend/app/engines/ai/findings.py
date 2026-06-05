"""AI Findings catalog (Tier 2.3).

Composes existing AuditGraph detectors into AI-specific findings written
to `security_findings`. The detectors aren't new — they're all reading
data we already discover. What's new is the unified Findings surface so
a CISO has ONE place to triage AI risk (not 7 scattered widgets).

Each finding carries:
  - finding_fingerprint  (stable identity for dedup across runs)
  - entity_type / entity_id  (the AI agent / model / OAuth app)
  - severity                 (critical | high | medium | low)
  - title + description       (one-liner + 1-2 sentence detail)
  - recommended_fix
  - metadata                  (raw evidence — counts, IDs, links)
  - finding_type              (one of FINDING_TYPES — fixed catalog)

Architecture rules:
- Detectors are PURE functions: (cursor, org_id, run_ids) → list[dict].
  No side effects in the detector itself; the composer writes.
- Detection thresholds live in this module's constants, NOT scattered.
- Findings are upserted by fingerprint so re-running idempotent.
- Status workflow (open → acknowledged → suppressed → resolved) lives
  on the existing security_findings table — this module never
  overwrites status.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ─── Fixed catalogue of AI finding types ────────────────────────────
# Adding new types requires deliberate review (don't grow this to 50).
FINDING_TYPES = {
    'ai_agent_no_owner':              {'severity': 'high',     'title': 'AI agent has no human owner'},
    'ai_agent_kv_admin':              {'severity': 'critical', 'title': 'AI agent holds Key Vault Administrator'},
    'ai_agent_blob_owner':            {'severity': 'critical', 'title': 'AI agent has Storage Blob Data Owner on classified data'},
    'ai_agent_sub_owner':             {'severity': 'critical', 'title': 'AI agent holds subscription-scope Owner/Contributor'},
    'ai_agent_reaches_phi':           {'severity': 'high',     'title': 'AI agent reaches PHI classified data'},
    'ai_agent_reaches_pci':           {'severity': 'high',     'title': 'AI agent reaches PCI cardholder data'},
    'ai_agent_public_endpoint':       {'severity': 'high',     'title': 'AI agent on public-network Cognitive Services endpoint'},
    'ai_agent_stale':                 {'severity': 'medium',   'title': 'AI agent dormant 30+ days'},
    'ai_agent_expired_credentials':   {'severity': 'high',     'title': 'AI agent credentials expired'},
    'ai_finetune_not_approved':       {'severity': 'high',     'title': 'Fine-tuned model in production without approval'},
    'ai_custom_model_not_approved':   {'severity': 'high',     'title': 'Custom-vendor model in production without approval'},
    'ai_multi_model_agent':           {'severity': 'medium',   'title': 'AI agent uses ≥3 distinct models'},
}


# ─── Public API ─────────────────────────────────────────────────────

def compose_ai_findings(db, org_id: int, run_id: Optional[int] = None) -> dict[str, Any]:
    """Run all AI detectors + upsert findings to security_findings.

    Returns:
      {
        'composed_at': ISO,
        'detected_count': N,
        'by_severity': {critical, high, medium, low},
        'by_type': {finding_type: count, ...},
        'findings': [...]   # full payloads
      }
    """
    cursor = db.conn.cursor()
    try:
        # Anchor every finding to the latest run when none specified
        if run_id is None:
            cursor.execute(
                "SELECT MAX(id) FROM discovery_runs WHERE organization_id = %s "
                "AND status IN ('completed','partial')", (org_id,))
            row = cursor.fetchone()
            run_id = (row and row[0]) or None
        run_ids = [run_id] if run_id else []

        findings: list[dict[str, Any]] = []
        for fn in _DETECTORS:
            try:
                findings.extend(fn(cursor, org_id, run_ids))
            except Exception as exc:
                logger.warning("AI finding detector %s failed: %s", fn.__name__, exc)

        # Upsert to security_findings
        upserted = _upsert_findings(cursor, org_id, run_id, findings)
        db.conn.commit()

        # Aggregate
        by_sev = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        by_type: dict[str, int] = {}
        for f in findings:
            sev = f.get('severity', 'low')
            if sev in by_sev:
                by_sev[sev] += 1
            t = f.get('finding_type')
            by_type[t] = by_type.get(t, 0) + 1

        from datetime import datetime, timezone
        return {
            'composed_at': datetime.now(timezone.utc).isoformat(),
            'discovery_run_id': run_id,
            'detected_count': len(findings),
            'upserted_count': upserted,
            'by_severity': by_sev,
            'by_type': by_type,
            'findings': findings,
        }
    finally:
        cursor.close()


def list_ai_findings(db, org_id: int, status: Optional[str] = None,
                      severity: Optional[str] = None,
                      finding_type: Optional[str] = None,
                      limit: int = 200) -> list[dict[str, Any]]:
    """Read AI findings from security_findings (post-compose)."""
    cursor = db.conn.cursor()
    try:
        where = ["organization_id = %s", "finding_type = ANY(%s)"]
        params: list[Any] = [org_id, list(FINDING_TYPES.keys())]
        if status:
            where.append("status = %s")
            params.append(status)
        if severity:
            where.append("severity = %s")
            params.append(severity)
        if finding_type:
            where.append("finding_type = %s")
            params.append(finding_type)
        where_sql = " AND ".join(where)

        cursor.execute(f"""
            SELECT finding_id, entity_type, entity_id, finding_type, severity,
                   risk_score, title, description, recommended_fix,
                   status, metadata,
                   first_detected_at, last_detected_at, occurrence_count
              FROM security_findings
             WHERE {where_sql}
             ORDER BY CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high'     THEN 2
                        WHEN 'medium'   THEN 3
                        WHEN 'low'      THEN 4
                        ELSE 5
                      END,
                      last_detected_at DESC
             LIMIT %s
        """, params + [limit])
        rows = cursor.fetchall()
    finally:
        cursor.close()
    return [
        {
            'finding_id': str(r[0]) if r[0] else None,
            'entity_type': r[1], 'entity_id': r[2],
            'finding_type': r[3], 'severity': r[4], 'risk_score': r[5],
            'title': r[6], 'description': r[7], 'recommended_fix': r[8],
            'status': r[9], 'metadata': r[10] or {},
            'first_detected_at': r[11].isoformat() if r[11] else None,
            'last_detected_at':  r[12].isoformat() if r[12] else None,
            'occurrence_count':  r[13],
        }
        for r in rows
    ]


def update_ai_finding_status(db, org_id: int, finding_id: str, new_status: str,
                              changed_by: str) -> bool:
    """Move a finding through its lifecycle: open → acknowledged →
    suppressed → resolved (or back to open)."""
    if new_status not in ('open', 'acknowledged', 'suppressed', 'resolved'):
        return False
    cursor = db.conn.cursor()
    try:
        cursor.execute("""
            UPDATE security_findings
               SET status = %s,
                   status_changed_by = %s,
                   status_changed_at = NOW()
             WHERE organization_id = %s AND finding_id = %s::uuid
               AND finding_type = ANY(%s)
        """, (new_status, changed_by, org_id, finding_id, list(FINDING_TYPES.keys())))
        n = cursor.rowcount
        db.conn.commit()
        return n > 0
    finally:
        cursor.close()


# ─── Detectors ──────────────────────────────────────────────────────

def _fingerprint(*parts: Any) -> str:
    """Stable fingerprint for finding dedup. Hash of pipe-joined parts."""
    s = '|'.join(str(p or '') for p in parts)
    return hashlib.sha256(s.encode()).hexdigest()[:32]


def _detect_no_owner(cursor, org_id, run_ids) -> list[dict]:
    if not run_ids:
        return []
    cursor.execute("""
        SELECT DISTINCT ON (i.identity_id)
               i.id, i.identity_id, i.display_name
          FROM identities i
          JOIN agent_classifications ac ON ac.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND i.discovery_run_id = ANY(%s)
           AND NOT COALESCE(i.is_microsoft_system, false)
           AND i.deleted_at IS NULL
           AND ac.agent_identity_type IN ('ai_agent','possible_ai_agent','ai_privileged_human')
           AND (ac.owner_display_name_at_classify IS NULL OR ac.owner_display_name_at_classify = '')
        ORDER BY i.identity_id, i.discovery_run_id DESC
    """, (org_id, run_ids))
    return [
        _finding('ai_agent_no_owner', 'ai_agent', r[1], r[2] or r[1],
                 description=f"AI agent '{r[2] or r[1]}' has no recorded human owner. "
                             f"Orphaned agents cannot be reviewed, attested to, or retired.",
                 recommended_fix="Assign a human owner via the Identity Detail → Ownership tab.",
                 metadata={'identity_db_id': r[0], 'identity_id': r[1]},
                 fingerprint_parts=[r[1], 'no_owner'])
        for r in cursor.fetchall()
    ]


def _detect_kv_admin(cursor, org_id, run_ids) -> list[dict]:
    if not run_ids:
        return []
    cursor.execute("""
        SELECT DISTINCT i.identity_id, i.display_name, ra.role_name, ra.scope
          FROM identities i
          JOIN agent_classifications ac ON ac.identity_db_id = i.id
          JOIN role_assignments ra ON ra.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND i.discovery_run_id = ANY(%s)
           AND NOT COALESCE(i.is_microsoft_system, false)
           AND i.deleted_at IS NULL
           AND ac.agent_identity_type IN ('ai_agent','possible_ai_agent','ai_privileged_human')
           AND LOWER(ra.role_name) IN ('key vault administrator', 'key vault secrets officer')
    """, (org_id, run_ids))
    return [
        _finding('ai_agent_kv_admin', 'ai_agent', r[0], r[1] or r[0],
                 description=f"AI agent '{r[1] or r[0]}' holds {r[2]} on {r[3]}. "
                             f"Under prompt-injection or credential compromise this "
                             f"grants exfiltration of ALL secrets in that vault.",
                 recommended_fix=f"Scope {r[2]} to specific secrets, or downgrade to "
                                 f"Key Vault Secrets User.",
                 metadata={'role_name': r[2], 'scope': r[3]},
                 fingerprint_parts=[r[0], 'kv_admin', r[3]])
        for r in cursor.fetchall()
    ]


def _detect_blob_owner_on_classified(cursor, org_id, run_ids) -> list[dict]:
    if not run_ids:
        return []
    cursor.execute("""
        SELECT DISTINCT i.identity_id, i.display_name, ra.role_name, ra.scope,
               sa.data_classification, sa.record_count_estimate
          FROM identities i
          JOIN agent_classifications ac ON ac.identity_db_id = i.id
          JOIN role_assignments ra ON ra.identity_db_id = i.id
          JOIN azure_storage_accounts sa
            ON sa.resource_id = ra.scope
           AND sa.organization_id = i.organization_id
           AND sa.data_classification IS NOT NULL
         WHERE i.organization_id = %s
           AND i.discovery_run_id = ANY(%s)
           AND NOT COALESCE(i.is_microsoft_system, false)
           AND i.deleted_at IS NULL
           AND ac.agent_identity_type IN ('ai_agent','possible_ai_agent','ai_privileged_human')
           AND LOWER(ra.role_name) IN ('storage blob data owner','storage blob data contributor')
    """, (org_id, run_ids))
    return [
        _finding('ai_agent_blob_owner', 'ai_agent', r[0], r[1] or r[0],
                 description=f"AI agent '{r[1] or r[0]}' has write access to "
                             f"{r[4]} storage ({(r[5] or 0):,} records) via {r[2]}.",
                 recommended_fix=f"Downgrade {r[2]} → Storage Blob Data Reader; "
                                 f"validate DPIA/BAA covers AI access to {r[4]}.",
                 metadata={'role_name': r[2], 'scope': r[3],
                           'classification': r[4], 'records': r[5]},
                 fingerprint_parts=[r[0], 'blob_owner_classified', r[3]])
        for r in cursor.fetchall()
    ]


def _detect_sub_owner(cursor, org_id, run_ids) -> list[dict]:
    if not run_ids:
        return []
    cursor.execute("""
        SELECT DISTINCT i.identity_id, i.display_name, ra.role_name, ra.scope
          FROM identities i
          JOIN agent_classifications ac ON ac.identity_db_id = i.id
          JOIN role_assignments ra ON ra.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND i.discovery_run_id = ANY(%s)
           AND NOT COALESCE(i.is_microsoft_system, false)
           AND i.deleted_at IS NULL
           AND ac.agent_identity_type IN ('ai_agent','possible_ai_agent','ai_privileged_human')
           AND LOWER(ra.role_name) IN ('owner','contributor','user access administrator')
           AND ra.scope LIKE '/subscriptions/%%'
           AND ra.scope NOT LIKE '/subscriptions/%%/resourceGroups/%%'
    """, (org_id, run_ids))
    return [
        _finding('ai_agent_sub_owner', 'ai_agent', r[0], r[1] or r[0],
                 description=f"AI agent '{r[1] or r[0]}' holds {r[2]} at subscription scope. "
                             f"Compromise grants full subscription control.",
                 recommended_fix=f"Scope {r[2]} down to a single resource group or resource.",
                 metadata={'role_name': r[2], 'scope': r[3]},
                 fingerprint_parts=[r[0], 'sub_owner', r[3]])
        for r in cursor.fetchall()
    ]


def _detect_phi_pci_reach(cursor, org_id, run_ids) -> list[dict]:
    cursor.execute("""
        SELECT DISTINCT i.identity_id, i.display_name, adr.data_classification, adr.est_records
          FROM identities i
          JOIN agent_classifications ac ON ac.identity_db_id = i.id
          JOIN agent_data_reachability adr ON adr.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND NOT COALESCE(i.is_microsoft_system, false)
           AND i.deleted_at IS NULL
           AND ac.agent_identity_type IN ('ai_agent','possible_ai_agent','ai_privileged_human')
           AND adr.data_classification IN ('PHI','PCI')
           AND COALESCE(adr.est_records, 0) > 0
    """, (org_id,))
    findings = []
    for r in cursor.fetchall():
        cls = r[2]
        ftype = 'ai_agent_reaches_phi' if cls == 'PHI' else 'ai_agent_reaches_pci'
        findings.append(_finding(
            ftype, 'ai_agent', r[0], r[1] or r[0],
            description=f"AI agent '{r[1] or r[0]}' has RBAC reach into {cls}-classified "
                        f"data ({(r[3] or 0):,} records). Under prompt injection or "
                        f"credential compromise, this is the blast radius.",
            recommended_fix=f"Restrict role scope to non-{cls} resources, or apply "
                            f"a Conditional Access policy on the workload identity.",
            metadata={'classification': cls, 'records': r[3]},
            fingerprint_parts=[r[0], f'reaches_{cls.lower()}']
        ))
    return findings


def _detect_public_endpoint(cursor, org_id, run_ids) -> list[dict]:
    if not run_ids:
        return []
    cursor.execute("""
        SELECT DISTINCT i.identity_id, i.display_name, csa.name
          FROM identities i
          JOIN agent_classifications ac ON ac.identity_db_id = i.id
          JOIN azure_cognitive_services_accounts csa
            ON csa.resource_id = ac.account_resource_id
           AND csa.organization_id = i.organization_id
         WHERE i.organization_id = %s
           AND i.discovery_run_id = ANY(%s)
           AND NOT COALESCE(i.is_microsoft_system, false)
           AND i.deleted_at IS NULL
           AND ac.agent_identity_type IN ('ai_agent','possible_ai_agent','ai_privileged_human')
           AND LOWER(COALESCE(csa.public_network_access, '')) = 'enabled'
    """, (org_id, run_ids))
    return [
        _finding('ai_agent_public_endpoint', 'ai_agent', r[0], r[1] or r[0],
                 description=f"AI agent '{r[1] or r[0]}' runs on Cognitive Services "
                             f"account '{r[2]}' with public_network_access=Enabled.",
                 recommended_fix=f"Disable public network on {r[2]}; switch to "
                                 f"Private Endpoint only.",
                 metadata={'cognitive_services_account': r[2]},
                 fingerprint_parts=[r[0], 'public_endpoint', r[2]])
        for r in cursor.fetchall()
    ]


def _detect_stale_agent(cursor, org_id, run_ids) -> list[dict]:
    if not run_ids:
        return []
    cursor.execute("""
        SELECT DISTINCT ON (i.identity_id)
               i.identity_id, i.display_name,
               EXTRACT(DAY FROM NOW() - COALESCE(i.last_sign_in, i.last_activity_date))::INT
          FROM identities i
          JOIN agent_classifications ac ON ac.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND i.discovery_run_id = ANY(%s)
           AND NOT COALESCE(i.is_microsoft_system, false)
           AND i.deleted_at IS NULL
           AND ac.agent_identity_type IN ('ai_agent','possible_ai_agent','ai_privileged_human')
           AND (i.last_sign_in IS NOT NULL OR i.last_activity_date IS NOT NULL)
           AND COALESCE(i.last_sign_in, i.last_activity_date) < NOW() - INTERVAL '30 days'
         ORDER BY i.identity_id, i.discovery_run_id DESC
    """, (org_id, run_ids))
    return [
        _finding('ai_agent_stale', 'ai_agent', r[0], r[1] or r[0],
                 description=f"AI agent '{r[1] or r[0]}' has not been active for {r[2]} days. "
                             f"Stale agents with retained RBAC are an unmonitored attack surface.",
                 recommended_fix="Review whether this agent is still needed. If yes, "
                                 "rotate credentials and re-attest ownership. If no, retire it.",
                 metadata={'days_inactive': r[2]},
                 fingerprint_parts=[r[0], 'stale'])
        for r in cursor.fetchall()
    ]


def _detect_expired_credentials(cursor, org_id, run_ids) -> list[dict]:
    if not run_ids:
        return []
    cursor.execute("""
        SELECT DISTINCT ON (i.identity_id) i.identity_id, i.display_name, i.credential_expiration
          FROM identities i
          JOIN agent_classifications ac ON ac.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND i.discovery_run_id = ANY(%s)
           AND NOT COALESCE(i.is_microsoft_system, false)
           AND i.deleted_at IS NULL
           AND ac.agent_identity_type IN ('ai_agent','possible_ai_agent','ai_privileged_human')
           AND COALESCE(i.credential_status, '') = 'expired'
         ORDER BY i.identity_id, i.discovery_run_id DESC
    """, (org_id, run_ids))
    return [
        _finding('ai_agent_expired_credentials', 'ai_agent', r[0], r[1] or r[0],
                 description=f"AI agent '{r[1] or r[0]}' has expired credentials. "
                             f"Either rotate or retire — expired credentials suggest the agent "
                             f"is unowned or the rotation pipeline is broken.",
                 recommended_fix="Rotate the workload identity's secret, or migrate to "
                                 "managed identity / workload-identity-federation.",
                 metadata={'expired_at': r[2].isoformat() if r[2] else None},
                 fingerprint_parts=[r[0], 'expired_creds'])
        for r in cursor.fetchall()
    ]


def _detect_finetune_not_approved(cursor, org_id, run_ids) -> list[dict]:
    """Fine-tuned models without an approved row in ai_model_approvals."""
    try:
        cursor.execute("SAVEPOINT _ai_find_ft_sp")
        cursor.execute("""
            SELECT DISTINCT aimd.model_name, aimd.model_format, aimd.account_name
              FROM azure_ai_model_deployments aimd
              LEFT JOIN ai_model_approvals ama
                ON ama.organization_id = aimd.organization_id
               AND ama.model_name = aimd.model_name
               AND COALESCE(ama.model_format,'') = COALESCE(aimd.model_format,'')
               AND ama.status = 'approved'
               AND (ama.expires_at IS NULL OR ama.expires_at > NOW())
             WHERE aimd.organization_id = %s
               AND LOWER(COALESCE(aimd.model_name,'')) LIKE '%%-ft-%%'
               AND ama.id IS NULL
        """, (org_id,))
        rows = cursor.fetchall()
        cursor.execute("RELEASE SAVEPOINT _ai_find_ft_sp")
    except Exception as exc:
        logger.warning("finetune-not-approved detector failed: %s", exc)
        try: cursor.execute("ROLLBACK TO SAVEPOINT _ai_find_ft_sp")
        except Exception: pass
        return []
    return [
        _finding('ai_finetune_not_approved', 'ai_model', r[0], r[0],
                 description=f"Fine-tuned model '{r[0]}' is deployed in production but "
                             f"has no approval in the Model Registry. Fine-tunes embed "
                             f"customer data + behaviour outside vendor catalogs.",
                 recommended_fix=f"Submit '{r[0]}' for review in the Model Registry. "
                                 f"Approval requires documented training-data provenance.",
                 metadata={'model_name': r[0], 'vendor': r[1], 'account': r[2]},
                 fingerprint_parts=[r[0], 'ft_not_approved'])
        for r in rows
    ]


def _detect_multi_model(cursor, org_id, run_ids) -> list[dict]:
    cursor.execute("""
        SELECT i.identity_id, i.display_name, COUNT(DISTINCT aimd.model_name) AS n
          FROM identities i
          JOIN agent_classifications ac ON ac.identity_db_id = i.id
          JOIN azure_ai_model_deployments aimd
            ON aimd.account_resource_id = ac.account_resource_id
           AND aimd.organization_id = ac.organization_id
         WHERE i.organization_id = %s
           AND NOT COALESCE(i.is_microsoft_system, false)
           AND i.deleted_at IS NULL
           AND ac.agent_identity_type IN ('ai_agent','possible_ai_agent','ai_privileged_human')
         GROUP BY i.identity_id, i.display_name
        HAVING COUNT(DISTINCT aimd.model_name) >= 3
    """, (org_id,))
    return [
        _finding('ai_multi_model_agent', 'ai_agent', r[0], r[1] or r[0],
                 description=f"AI agent '{r[1] or r[0]}' uses {r[2]} distinct models. "
                             f"Multi-model agents expand the prompt/tool attack surface "
                             f"and complicate vendor-risk attribution.",
                 recommended_fix="Document why this agent needs multiple models. "
                                 "Consider splitting into role-specific agents.",
                 metadata={'model_count': r[2]},
                 fingerprint_parts=[r[0], 'multi_model'])
        for r in cursor.fetchall()
    ]


_DETECTORS = (
    _detect_no_owner,
    _detect_kv_admin,
    _detect_blob_owner_on_classified,
    _detect_sub_owner,
    _detect_phi_pci_reach,
    _detect_public_endpoint,
    _detect_stale_agent,
    _detect_expired_credentials,
    _detect_finetune_not_approved,
    _detect_multi_model,
)


# ─── Helpers ────────────────────────────────────────────────────────

def _finding(ftype, entity_type, entity_id, entity_name, description,
              recommended_fix, metadata, fingerprint_parts) -> dict:
    cat = FINDING_TYPES[ftype]
    fp = _fingerprint(*fingerprint_parts)
    risk_score = {'critical': 90, 'high': 70, 'medium': 45, 'low': 20}.get(cat['severity'], 30)
    return {
        'finding_type':        ftype,
        'entity_type':         entity_type,
        'entity_id':           entity_id,
        'identity_id':         entity_id,
        'severity':            cat['severity'],
        'risk_score':          risk_score,
        'title':               cat['title'],
        'description':         description,
        'recommended_fix':     recommended_fix,
        'metadata':            metadata,
        'finding_fingerprint': fp,
    }


def _upsert_findings(cursor, org_id, run_id, findings) -> int:
    """Upsert by (organization_id, finding_fingerprint).

    On conflict: bump occurrence_count, update last_detected_at, and
    refresh description/metadata if they changed. NEVER touches status.
    """
    if not findings:
        return 0
    n = 0
    for f in findings:
        try:
            cursor.execute("SAVEPOINT _findings_upsert_sp")
            cursor.execute("""
                INSERT INTO security_findings
                    (organization_id, entity_type, entity_id, identity_id,
                     finding_type, severity, risk_score, title, description,
                     recommended_fix, metadata, discovery_run_id,
                     finding_fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                ON CONFLICT (organization_id, finding_fingerprint) DO UPDATE SET
                    last_detected_at = NOW(),
                    occurrence_count = security_findings.occurrence_count + 1,
                    description      = EXCLUDED.description,
                    metadata         = EXCLUDED.metadata,
                    discovery_run_id = EXCLUDED.discovery_run_id
            """, (org_id, f['entity_type'], f['entity_id'], f['identity_id'],
                  f['finding_type'], f['severity'], f['risk_score'],
                  f['title'], f['description'], f['recommended_fix'],
                  __import__('json').dumps(f['metadata']),
                  run_id, f['finding_fingerprint']))
            n += 1
            cursor.execute("RELEASE SAVEPOINT _findings_upsert_sp")
        except Exception as exc:
            logger.warning("upsert finding failed: %s", exc)
            try: cursor.execute("ROLLBACK TO SAVEPOINT _findings_upsert_sp")
            except Exception: pass
    return n


__all__ = [
    'FINDING_TYPES', 'compose_ai_findings', 'list_ai_findings',
    'update_ai_finding_status',
]
