"""
Threat-source partner connector framework (Tier 4).

Per Reviewer #2: AuditGraph doesn't detect prompt injection / jailbreaks.
Partners do. This module ingests signals from partners (Azure Content
Filter, Bedrock Guardrails, Lakera, OpenAI Moderation, NeMo Guardrails)
and normalizes them so they feed:

  - Findings catalog (new finding types ai_threat_prompt_injection, etc.)
  - Abuse Scenarios (recent_threat_signals evidence field)
  - Trust Score (future: telemetry dimension upgrade from PARTIAL → FULL
    when active threat coverage exists)

Each adapter is a pure transformation function:
  vendor_payload (dict) → list[NormalizedSignal]

The ingestion endpoint dispatches by `vendor` query param to the right
adapter. New vendors are added by registering an adapter; no schema
changes needed.

NormalizedSignal shape:
  {
    'vendor': str,
    'signal_type': str,           # prompt_injection|jailbreak|... (catalog)
    'severity': str,              # critical|high|medium|low|info
    'score': float | None,        # 0-1 vendor confidence
    'title': str,
    'description': str | None,
    'evidence': dict,             # vendor-specific raw data
    'external_id': str | None,    # vendor incident id for dedup
    'occurred_at': ISO str | None,
    'identity_id': str | None,    # affected agent identity_id
    'identity_db_id': int | None,
  }
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


SUPPORTED_VENDORS = ('azure_content_filter', 'bedrock_guardrails',
                      'lakera_guard', 'openai_moderation', 'nemo_guardrails',
                      'custom')

# Catalogued signal types — same fixed catalog discipline as Findings.
SIGNAL_TYPES = ('prompt_injection', 'jailbreak', 'data_leakage',
                'toxic_content', 'pii_in_output', 'hallucination',
                'off_topic', 'custom')

SEVERITY_LEVELS = ('critical', 'high', 'medium', 'low', 'info')


# ─────────────────────────────────────────────────────────────────────────────
# Adapters — one per partner
# ─────────────────────────────────────────────────────────────────────────────

def _azure_content_filter_adapter(payload: dict) -> list[dict]:
    """Azure OpenAI content filter response (also Azure AI Content Safety).

    Expected shape (simplified):
      {
        "agent_identity_id": "...",
        "request_id": "abc-123",
        "filter_results": {
          "prompt_injection": {"detected": true, "severity": "high"},
          "jailbreak": {"detected": false}
        },
        "occurred_at": "2026-06-04T..."
      }
    """
    out = []
    agent_id = payload.get('agent_identity_id') or payload.get('agent_id')
    req_id   = payload.get('request_id') or payload.get('id')
    occurred = payload.get('occurred_at')
    filters  = payload.get('filter_results') or payload.get('content_filter_results') or {}

    severity_map = {'safe': 'info', 'low': 'low', 'medium': 'medium', 'high': 'high'}

    for filter_key, result in filters.items():
        if not isinstance(result, dict):
            continue
        if not result.get('detected') and not result.get('filtered'):
            continue
        signal_type = _normalize_azure_filter_key(filter_key)
        if not signal_type:
            continue
        severity = severity_map.get(
            (result.get('severity') or '').lower(), 'medium')
        out.append({
            'vendor': 'azure_content_filter',
            'signal_type': signal_type,
            'severity': severity,
            'score': result.get('score'),
            'title': f"Azure Content Filter: {signal_type.replace('_', ' ')}",
            'description': result.get('reason') or
                f"Azure detected {signal_type} (severity={severity})",
            'evidence': {'azure_filter': filter_key,
                         'request_id': req_id,
                         'raw': result},
            'external_id': f"acf:{req_id}:{filter_key}" if req_id else None,
            'occurred_at': occurred,
            'identity_id': agent_id,
            'identity_db_id': None,
        })
    return out


def _normalize_azure_filter_key(k: str) -> Optional[str]:
    k = (k or '').lower()
    if 'prompt' in k and 'inject' in k: return 'prompt_injection'
    if 'jailbreak' in k:                return 'jailbreak'
    if 'self_harm' in k or 'self-harm' in k: return 'toxic_content'
    if 'hate' in k or 'violence' in k or 'sexual' in k: return 'toxic_content'
    if 'protected_material' in k or 'leakage' in k: return 'data_leakage'
    if 'indirect_attack' in k: return 'prompt_injection'
    return None


def _bedrock_guardrails_adapter(payload: dict) -> list[dict]:
    """AWS Bedrock Guardrails CloudWatch event."""
    out = []
    agent_id = payload.get('agent_identity_id') or payload.get('agent_id')
    detail   = payload.get('detail') or payload
    occurred = payload.get('time') or payload.get('occurred_at')
    inv_id   = detail.get('invocationId') or detail.get('invocation_id')

    for assessment in (detail.get('assessments') or []):
        for policy_kind in ('contentPolicy', 'wordPolicy', 'sensitiveInformationPolicy',
                             'topicPolicy'):
            policy = assessment.get(policy_kind) or {}
            filters = policy.get('filters') or []
            for f in filters:
                if not (f.get('action') == 'BLOCKED' or f.get('detected')):
                    continue
                signal_type = _normalize_bedrock_filter_type(f.get('type', ''), policy_kind)
                if not signal_type:
                    continue
                severity = (f.get('strength') or 'MEDIUM').lower()
                if severity == 'high':   severity = 'high'
                elif severity == 'low':  severity = 'low'
                else: severity = 'medium'
                out.append({
                    'vendor': 'bedrock_guardrails',
                    'signal_type': signal_type,
                    'severity': severity,
                    'score': f.get('confidence'),
                    'title': f"Bedrock Guardrails: {f.get('type','filter')} blocked",
                    'description': f"Bedrock policy '{policy_kind}' filter "
                                   f"'{f.get('type')}' fired (action={f.get('action')})",
                    'evidence': {'policy': policy_kind,
                                 'filter_type': f.get('type'),
                                 'invocation_id': inv_id,
                                 'raw': f},
                    'external_id': f"bgr:{inv_id}:{policy_kind}:{f.get('type')}" if inv_id else None,
                    'occurred_at': occurred,
                    'identity_id': agent_id,
                    'identity_db_id': None,
                })
    return out


def _normalize_bedrock_filter_type(t: str, policy_kind: str) -> Optional[str]:
    t = (t or '').upper()
    pk = (policy_kind or '').lower()
    if 'PROMPT_ATTACK' in t or 'JAILBREAK' in t: return 'jailbreak'
    if 'INJECT' in t:                            return 'prompt_injection'
    if pk == 'sensitiveinformationpolicy':       return 'pii_in_output'
    if t in ('HATE','VIOLENCE','SEXUAL','MISCONDUCT'): return 'toxic_content'
    if pk == 'topicpolicy':                       return 'off_topic'
    return None


def _lakera_guard_adapter(payload: dict) -> list[dict]:
    """Lakera Guard /v2/guard response."""
    out = []
    agent_id  = payload.get('agent_identity_id') or payload.get('agent_id')
    occurred  = payload.get('created_at') or payload.get('occurred_at')
    flag_id   = payload.get('flag_id') or payload.get('id')
    results   = payload.get('results') or payload.get('payload') or {}

    type_map = {
        'prompt_injection': 'prompt_injection',
        'jailbreak':        'jailbreak',
        'pii':              'pii_in_output',
        'unknown_links':    'data_leakage',
        'moderated_content':'toxic_content',
    }

    for k, v in (results.items() if isinstance(results, dict) else []):
        if not isinstance(v, dict):
            continue
        if not (v.get('detected') or v.get('flagged')):
            continue
        signal_type = type_map.get(k)
        if not signal_type:
            continue
        score = v.get('score') or v.get('confidence')
        severity = 'high' if (score or 0) >= 0.8 else 'medium' if (score or 0) >= 0.5 else 'low'
        out.append({
            'vendor': 'lakera_guard',
            'signal_type': signal_type,
            'severity': severity,
            'score': score,
            'title': f"Lakera Guard: {signal_type.replace('_',' ')} detected",
            'description': v.get('description') or
                f"Lakera flagged {signal_type} (score={score})",
            'evidence': {'lakera_key': k, 'flag_id': flag_id, 'raw': v},
            'external_id': f"lkr:{flag_id}:{k}" if flag_id else None,
            'occurred_at': occurred,
            'identity_id': agent_id,
            'identity_db_id': None,
        })
    return out


def _openai_moderation_adapter(payload: dict) -> list[dict]:
    """OpenAI /v1/moderations response."""
    out = []
    agent_id = payload.get('agent_identity_id') or payload.get('agent_id')
    occurred = payload.get('occurred_at')
    mid      = payload.get('id')

    for r in (payload.get('results') or []):
        if not r.get('flagged'):
            continue
        cats   = r.get('categories') or {}
        scores = r.get('category_scores') or {}
        for cat, flagged in cats.items():
            if not flagged:
                continue
            score = scores.get(cat) or 0
            severity = ('high' if score >= 0.8 else 'medium' if score >= 0.5 else 'low')
            signal_type = ('toxic_content' if cat in
                ('hate','harassment','sexual','self-harm','violence') else 'custom')
            out.append({
                'vendor': 'openai_moderation',
                'signal_type': signal_type,
                'severity': severity,
                'score': score,
                'title': f"OpenAI Moderation: {cat}",
                'description': f"OpenAI flagged content as {cat} (score={score:.3f})",
                'evidence': {'category': cat, 'all_scores': scores, 'moderation_id': mid},
                'external_id': f"oam:{mid}:{cat}" if mid else None,
                'occurred_at': occurred,
                'identity_id': agent_id,
                'identity_db_id': None,
            })
    return out


def _nemo_guardrails_adapter(payload: dict) -> list[dict]:
    """NVIDIA NeMo Guardrails event (input rail / output rail / dialog rail)."""
    out = []
    agent_id = payload.get('agent_identity_id') or payload.get('agent_id')
    occurred = payload.get('timestamp') or payload.get('occurred_at')
    eid      = payload.get('event_id') or payload.get('id')

    rail = (payload.get('rail') or '').lower()
    action = (payload.get('action') or '').lower()
    rail_type = (payload.get('type') or '').lower()

    if action not in ('blocked', 'flagged'):
        return out

    signal_type = 'custom'
    if 'inject' in rail_type or 'jailbreak' in rail_type:
        signal_type = 'jailbreak' if 'jailbreak' in rail_type else 'prompt_injection'
    elif rail == 'output' and 'pii' in rail_type:
        signal_type = 'pii_in_output'
    elif 'topic' in rail_type:
        signal_type = 'off_topic'
    elif 'hallucin' in rail_type:
        signal_type = 'hallucination'

    out.append({
        'vendor': 'nemo_guardrails',
        'signal_type': signal_type,
        'severity': payload.get('severity', 'medium'),
        'score': payload.get('confidence'),
        'title': f"NeMo Guardrails: {rail} rail {action} ({rail_type})",
        'description': payload.get('reason') or
            f"NeMo {rail} rail flagged {rail_type}",
        'evidence': {'rail': rail, 'rail_type': rail_type, 'action': action,
                     'raw': payload},
        'external_id': f"nem:{eid}" if eid else None,
        'occurred_at': occurred,
        'identity_id': agent_id,
        'identity_db_id': None,
    })
    return out


def _custom_adapter(payload: dict) -> list[dict]:
    """Pass-through for customers who normalize on their side."""
    sig = {
        'vendor': 'custom',
        'signal_type': payload.get('signal_type', 'custom'),
        'severity': payload.get('severity', 'medium'),
        'score': payload.get('score'),
        'title': payload.get('title') or 'Custom threat signal',
        'description': payload.get('description'),
        'evidence': payload.get('evidence') or {'raw': payload},
        'external_id': payload.get('external_id'),
        'occurred_at': payload.get('occurred_at'),
        'identity_id': payload.get('identity_id'),
        'identity_db_id': None,
    }
    if sig['signal_type'] not in SIGNAL_TYPES:
        sig['signal_type'] = 'custom'
    if sig['severity'] not in SEVERITY_LEVELS:
        sig['severity'] = 'medium'
    return [sig]


ADAPTERS: dict[str, Callable[[dict], list[dict]]] = {
    'azure_content_filter': _azure_content_filter_adapter,
    'bedrock_guardrails':   _bedrock_guardrails_adapter,
    'lakera_guard':         _lakera_guard_adapter,
    'openai_moderation':    _openai_moderation_adapter,
    'nemo_guardrails':      _nemo_guardrails_adapter,
    'custom':               _custom_adapter,
}


# ─────────────────────────────────────────────────────────────────────────────
# Public ingest API
# ─────────────────────────────────────────────────────────────────────────────

def ingest_signals(db, org_id: int, vendor: str, payload: dict) -> dict[str, Any]:
    """Run the right adapter + persist all returned signals.

    Returns:
      {ingested: N, signals: [...], skipped: M}
    """
    adapter = ADAPTERS.get(vendor)
    if not adapter:
        return {'error': f'Unknown vendor: {vendor}'}

    try:
        raw_signals = adapter(payload) or []
    except Exception as exc:
        logger.error("adapter %s failed: %s", vendor, exc, exc_info=True)
        return {'error': f'Adapter parsing failed: {exc}'}

    # Resolve identity_db_id for each signal (best-effort)
    cursor = db.conn.cursor()
    try:
        ingested = []
        for sig in raw_signals:
            if sig.get('identity_id') and not sig.get('identity_db_id'):
                cursor.execute("""
                    SELECT id FROM identities
                     WHERE organization_id = %s AND identity_id = %s
                     ORDER BY discovery_run_id DESC LIMIT 1
                """, (org_id, sig['identity_id']))
                row = cursor.fetchone()
                if row:
                    sig['identity_db_id'] = row[0]

            try:
                cursor.execute("SAVEPOINT _ts_ins")
                cursor.execute("""
                    INSERT INTO threat_signals
                        (organization_id, identity_db_id, identity_id,
                         vendor, signal_type, severity, score,
                         title, description, evidence,
                         external_id, occurred_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                    ON CONFLICT (organization_id, vendor, external_id) DO NOTHING
                    RETURNING id
                """, (org_id, sig.get('identity_db_id'), sig.get('identity_id'),
                       sig['vendor'], sig['signal_type'], sig['severity'],
                       sig.get('score'),
                       sig['title'], sig.get('description'),
                       __import__('json').dumps(sig.get('evidence') or {}),
                       sig.get('external_id'), sig.get('occurred_at')))
                row = cursor.fetchone()
                cursor.execute("RELEASE SAVEPOINT _ts_ins")
                if row:
                    sig['id'] = row[0]
                    ingested.append(sig)
            except Exception as exc:
                logger.warning("threat signal insert failed: %s", exc)
                try: cursor.execute("ROLLBACK TO SAVEPOINT _ts_ins")
                except Exception: pass

        db.conn.commit()
        return {
            'ingested': len(ingested),
            'skipped':  len(raw_signals) - len(ingested),
            'signals':  ingested,
        }
    finally:
        cursor.close()


def list_signals(db, org_id: int, identity_id: Optional[str] = None,
                  vendor: Optional[str] = None, severity: Optional[str] = None,
                  limit: int = 200) -> list[dict]:
    """Read signals with optional filters."""
    cursor = db.conn.cursor()
    try:
        where = ['organization_id = %s']
        params: list[Any] = [org_id]
        if identity_id:
            where.append('identity_id = %s')
            params.append(identity_id)
        if vendor:
            where.append('vendor = %s')
            params.append(vendor)
        if severity:
            where.append('severity = %s')
            params.append(severity)
        where_sql = ' AND '.join(where)
        cursor.execute(f"""
            SELECT id, identity_id, vendor, signal_type, severity, score,
                   title, description, evidence,
                   external_id, occurred_at, received_at, status
              FROM threat_signals
             WHERE {where_sql}
             ORDER BY received_at DESC
             LIMIT %s
        """, params + [limit])
        rows = cursor.fetchall()
    finally:
        cursor.close()
    return [
        {
            'id': r[0], 'identity_id': r[1], 'vendor': r[2],
            'signal_type': r[3], 'severity': r[4],
            'score': float(r[5]) if r[5] is not None else None,
            'title': r[6], 'description': r[7],
            'evidence': r[8] or {},
            'external_id': r[9],
            'occurred_at': r[10].isoformat() if r[10] else None,
            'received_at': r[11].isoformat() if r[11] else None,
            'status': r[12],
        }
        for r in rows
    ]


def get_connector_health(db, org_id: int) -> list[dict]:
    """Return one row per registered connector with health stats.

    SECURITY (PENTEST F-002): `webhook_secret` is NEVER returned. Callers
    receive `webhook_secret_set: bool` only. Any callers of this function
    that need the secret to verify a signature must read it from the DB
    via a dedicated, server-internal accessor.

    Likewise, `config` is sanitized — any keys that look like credentials
    are stripped before serialization.
    """
    cursor = db.conn.cursor()
    try:
        cursor.execute("""
            SELECT vendor, display_name, is_enabled,
                   last_signal_at, total_signals, config, created_at,
                   webhook_secret
              FROM threat_connectors
             WHERE organization_id = %s
             ORDER BY vendor
        """, (org_id,))
        rows = cursor.fetchall()
    finally:
        cursor.close()
    return [
        {
            'vendor': r[0], 'display_name': r[1],
            'is_enabled': bool(r[2]),
            'last_signal_at': r[3].isoformat() if r[3] else None,
            'total_signals': int(r[4] or 0),
            'config': _sanitize_config(r[5] or {}),
            'created_at': r[6].isoformat() if r[6] else None,
            'webhook_secret_set': bool(r[7]),
        }
        for r in rows
    ]


_SENSITIVE_CONFIG_KEYS = (
    'secret', 'token', 'key', 'password', 'credential',
    'webhook_secret', 'api_key', 'apikey', 'bearer',
)


def _sanitize_config(config: dict) -> dict:
    """Strip credential-looking keys from a config dict before egress."""
    if not isinstance(config, dict):
        return {}
    out = {}
    for k, v in config.items():
        kl = str(k).lower()
        if any(s in kl for s in _SENSITIVE_CONFIG_KEYS):
            out[k] = '***REDACTED***'
        else:
            out[k] = v
    return out


def upsert_connector(db, org_id: int, vendor: str, display_name: str,
                      is_enabled: bool = True, config: Optional[dict] = None,
                      webhook_secret: Optional[str] = None) -> dict:
    """Register or update a connector.

    SECURITY: webhook_secret goes to its own column (not config JSONB).
    When provided, it overwrites the existing value. When None, the
    existing value is preserved (so callers don't accidentally null it).
    """
    cursor = db.conn.cursor()
    try:
        # Sanitize config — never accept credential-looking keys into JSONB
        clean_config = {}
        if config and isinstance(config, dict):
            for k, v in config.items():
                kl = str(k).lower()
                if not any(s in kl for s in _SENSITIVE_CONFIG_KEYS):
                    clean_config[k] = v

        cursor.execute("""
            INSERT INTO threat_connectors
                (organization_id, vendor, display_name, is_enabled, config, webhook_secret)
            VALUES (%s, %s, %s, %s, %s::jsonb, %s)
            ON CONFLICT (organization_id, vendor) DO UPDATE SET
                display_name = EXCLUDED.display_name,
                is_enabled   = EXCLUDED.is_enabled,
                config       = EXCLUDED.config,
                webhook_secret = COALESCE(EXCLUDED.webhook_secret, threat_connectors.webhook_secret)
            RETURNING id, vendor, display_name, is_enabled, total_signals, (webhook_secret IS NOT NULL)
        """, (org_id, vendor, display_name, is_enabled,
              __import__('json').dumps(clean_config),
              webhook_secret))
        row = cursor.fetchone()
        db.conn.commit()
        return {'id': row[0], 'vendor': row[1], 'display_name': row[2],
                'is_enabled': bool(row[3]), 'total_signals': int(row[4]),
                'webhook_secret_set': bool(row[5])}
    finally:
        cursor.close()


__all__ = ['SUPPORTED_VENDORS', 'SIGNAL_TYPES', 'SEVERITY_LEVELS',
            'ADAPTERS', 'ingest_signals', 'list_signals',
            'get_connector_health', 'upsert_connector']
