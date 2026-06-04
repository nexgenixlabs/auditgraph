"""
AI Abuse Scenarios — Tier 2.1 (headline AI-ISPM feature).

Treats prompt injection / credential theft / owner departure / tool abuse /
upstream supply-chain compromise as THREAT SOURCES (per second reviewer's
positioning). For each AI agent computes the IDENTITY CONSEQUENCE under
each scenario — what could happen if the threat succeeds.

This is the layer AuditGraph uniquely owns: we don't detect prompt
injection (partner job — Lakera, Azure Content Filter, Bedrock
Guardrails). We tell you the blast radius IF it succeeds, derived from
architecture (no telemetry dependency).

Design rules
────────────
1. Compute on-demand, no new table. Results always reflect current
   architecture; no stale snapshots to invalidate.
2. Every consequence cites EVIDENCE — secret count from azure_key_vaults
   row, record count from agent_data_reachability row, dollar from
   breach_cost_factors. Never fabricated.
3. Per-agent endpoint feeds the AI Inventory drawer. Org rollup feeds the
   AI Risk page ("worst-case agent under each scenario").
4. Each scenario maps to real MITRE techniques — auditable by a defender.
5. 5 scenarios are FIXED + NAMED. Adding more requires deliberate catalog
   review (we don't want this to grow into 50 cargo-culted findings).

Module API:
    compute_abuse_scenarios(db, identity_db_id, org_id) -> dict
        Returns {scenarios: [...], worst_score: int, computed_at: str}.
        Each scenario carries: name, severity, blast_radius, evidence,
        recommendation, mitre_techniques.

    compute_abuse_scenarios_org_rollup(db, org_id) -> dict
        Returns {by_scenario: {scenario_key: {worst_agents: [...]}}, ...}
        for the org-wide AI Risk page.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from ..scoring.breach_cost import (
    compute_exposure,
    aggregate_exposure,
    format_dollar_short,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Scenario catalogue — order matters (display order in UI)
# ─────────────────────────────────────────────────────────────────────────────

SCENARIOS = [
    {
        'key':   'prompt_injection',
        'label': 'Prompt Injection Compromise',
        'description': (
            'A prompt-injection attack tricks the agent into executing '
            'attacker-chosen tool calls. AuditGraph computes what an '
            'attacker would reach if this succeeded against THIS agent.'
        ),
        'threat_source': 'prompt injection',
        'mitre': ['T1213', 'T1552', 'T1530'],
        'mitre_names': ['Data from Information Repositories',
                        'Unsecured Credentials',
                        'Data from Cloud Storage'],
    },
    {
        'key':   'credential_theft',
        'label': 'Service Principal Credential Theft',
        'description': (
            'An attacker steals one of the agent\'s authentication '
            'credentials (client secret, certificate, or federated token). '
            'AuditGraph counts the auth surfaces and the resulting reach.'
        ),
        'threat_source': 'credential theft',
        'mitre': ['T1552.004', 'T1078.004'],
        'mitre_names': ['Unsecured Credentials: Private Keys',
                        'Valid Accounts: Cloud Accounts'],
    },
    {
        'key':   'owner_departure',
        'label': 'Owner Departure / Orphaning',
        'description': (
            'The human owner leaves the company or rotates roles. '
            'Without backup ownership, the agent becomes orphaned — no '
            'one reviews privilege drift, no one accepts risk.'
        ),
        'threat_source': 'owner departure',
        'mitre': ['T1098'],
        'mitre_names': ['Account Manipulation'],
    },
    {
        'key':   'tool_abuse',
        'label': 'Tool Abuse',
        'description': (
            'The agent\'s attached tools (RBAC role assignments) are '
            'invoked maliciously — either via prompt injection, '
            'credential compromise, or insider misuse. We rank the '
            'attached tools by blast radius.'
        ),
        'threat_source': 'tool abuse',
        'mitre': ['T1098'],
        'mitre_names': ['Account Manipulation'],
    },
    {
        'key':   'supply_chain',
        'label': 'Upstream Supply Chain Compromise',
        'description': (
            'The Azure OpenAI / Cognitive Services account hosting this '
            'agent is compromised — either the account itself or a '
            'hosted model. All co-tenants on the account share the blast '
            'radius.'
        ),
        'threat_source': 'supply chain',
        'mitre': ['T1199'],
        'mitre_names': ['Trusted Relationship'],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def compute_abuse_scenarios(db, identity_db_id: int, org_id: int) -> dict[str, Any]:
    """Compute all 5 abuse scenarios for one AI agent.

    Returns:
        {
            'identity_db_id': N,
            'scenarios': [
                {key, label, severity, blast_radius, evidence,
                 recommendation, mitre_techniques, mitre_names},
                ...
            ],
            'worst_severity': 'critical'|'high'|'medium'|'low',
            'computed_at': ISO timestamp
        }
    """
    cursor = db.conn.cursor()
    try:
        agent_meta = _load_agent_meta(cursor, identity_db_id, org_id)
        if not agent_meta:
            return _empty_result(identity_db_id)

        role_assignments = _load_role_assignments(cursor, identity_db_id)
        reachability     = _load_reachability(cursor, identity_db_id)
        kv_secrets       = _load_kv_secrets(cursor, role_assignments, org_id)
        credentials      = _load_credentials(cursor, identity_db_id)
        federated_creds  = _load_federated_credentials(cursor, identity_db_id)
        supply_chain     = _load_supply_chain(cursor, agent_meta, org_id)

        scenarios = [
            _scenario_prompt_injection(db, agent_meta, role_assignments,
                                       reachability, kv_secrets),
            _scenario_credential_theft(db, agent_meta, role_assignments,
                                       reachability, credentials, federated_creds),
            _scenario_owner_departure(db, agent_meta),
            _scenario_tool_abuse(db, agent_meta, role_assignments, reachability, kv_secrets),
            _scenario_supply_chain(db, agent_meta, supply_chain),
        ]

        worst_rank = max((_SEV_RANK.get(s['severity'], 0) for s in scenarios), default=0)
        worst_severity = _RANK_SEV.get(worst_rank, 'low')

        return {
            'identity_db_id': identity_db_id,
            'identity_id':    agent_meta.get('identity_id'),
            'display_name':   agent_meta.get('display_name'),
            'scenarios':      scenarios,
            'worst_severity': worst_severity,
            'computed_at':    datetime.now(timezone.utc).isoformat(),
        }
    finally:
        cursor.close()


def compute_abuse_scenarios_org_rollup(db, org_id: int) -> dict[str, Any]:
    """Org-wide rollup: for each scenario, return the worst-affected AI agents.

    Used by the AI Risk page hero panel: "If prompt injection compromises
    your worst agent, exposure is $X. Top 3 agents at risk: [...]".

    Returns:
        {
            'by_scenario': {
                'prompt_injection': {
                    'label': ...,
                    'worst_severity': 'critical',
                    'worst_agents': [{display_name, severity, headline, ...}],
                    'count_by_severity': {critical: N, high: M, ...},
                },
                ...
            },
            'computed_at': ISO timestamp
        }
    """
    cursor = db.conn.cursor()
    try:
        # 1) list AI agents in the latest snapshot for the org
        cursor.execute(
            """
            SELECT DISTINCT ON (i.identity_id) i.id
              FROM identities i
              JOIN agent_classifications ac ON ac.identity_db_id = i.id
             WHERE i.organization_id = %s
               AND ac.agent_identity_type IN ('ai_agent','possible_ai_agent','ai_privileged_human')
               AND NOT COALESCE(i.is_microsoft_system, false)
               AND i.deleted_at IS NULL
             ORDER BY i.identity_id, i.discovery_run_id DESC
            """,
            (org_id,),
        )
        agent_ids = [r[0] for r in cursor.fetchall()]
    finally:
        cursor.close()

    if not agent_ids:
        return {
            'by_scenario': {s['key']: {
                'label': s['label'],
                'worst_severity': 'none',
                'worst_agents': [],
                'count_by_severity': {},
            } for s in SCENARIOS},
            'agents_evaluated': 0,
            'computed_at': datetime.now(timezone.utc).isoformat(),
        }

    # 2) compute scenarios for each agent (O(agents) — small cohort in v1)
    results = []
    for aid in agent_ids:
        try:
            results.append(compute_abuse_scenarios(db, aid, org_id))
        except Exception as exc:
            logger.warning("abuse_scenarios per-agent failed for id=%s: %s", aid, exc)

    # 3) bucket by scenario
    by_scenario: dict[str, Any] = {}
    for catalogue in SCENARIOS:
        skey = catalogue['key']
        rows = []
        sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for r in results:
            for s in r.get('scenarios', []):
                if s.get('key') != skey:
                    continue
                rows.append({
                    'identity_id':  r.get('identity_id'),
                    'display_name': r.get('display_name'),
                    'severity':     s.get('severity'),
                    'headline':     s.get('headline'),
                    'dollar_mid':   s.get('blast_radius', {}).get('dollar_mid'),
                    'dollar_display': s.get('blast_radius', {}).get('dollar_mid_display'),
                })
                if s.get('severity') in sev_counts:
                    sev_counts[s.get('severity')] += 1
        rows.sort(key=lambda x: (-_SEV_RANK.get(x.get('severity'), 0),
                                  -(x.get('dollar_mid') or 0)))
        worst_rank = _SEV_RANK.get(rows[0]['severity'], 0) if rows else 0
        by_scenario[skey] = {
            'label': catalogue['label'],
            'description': catalogue['description'],
            'mitre_techniques': catalogue['mitre'],
            'worst_severity': _RANK_SEV.get(worst_rank, 'none'),
            'worst_agents': rows[:5],
            'count_by_severity': sev_counts,
        }

    return {
        'by_scenario': by_scenario,
        'agents_evaluated': len(results),
        'computed_at': datetime.now(timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Severity ranking
# ─────────────────────────────────────────────────────────────────────────────

_SEV_RANK = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
_RANK_SEV = {0: 'none', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}


# ─────────────────────────────────────────────────────────────────────────────
# Data loaders — one query each, no N+1
# ─────────────────────────────────────────────────────────────────────────────

def _load_agent_meta(cursor, identity_db_id: int, org_id: int) -> Optional[dict]:
    cursor.execute(
        """
        SELECT i.id, i.identity_id, i.display_name,
               i.owner_display_name, COALESCE(i.owner_count, 0),
               i.last_sign_in, i.last_activity_date,
               i.credential_status, i.credential_expiration,
               ac.account_resource_id, ac.detected_platform, ac.model_name,
               ac.owner_display_name_at_classify, ac.agent_identity_type
          FROM identities i
          LEFT JOIN agent_classifications ac ON ac.identity_db_id = i.id
         WHERE i.id = %s AND i.organization_id = %s
        """,
        (identity_db_id, org_id),
    )
    row = cursor.fetchone()
    if not row:
        return None
    cols = ('id', 'identity_id', 'display_name',
            'owner_display_name', 'owner_count',
            'last_sign_in', 'last_activity_date',
            'credential_status', 'credential_expiration',
            'account_resource_id', 'detected_platform', 'model_name',
            'owner_display_name_at_classify', 'agent_identity_type')
    return dict(zip(cols, row))


def _load_role_assignments(cursor, identity_db_id: int) -> list[dict]:
    cursor.execute(
        """
        SELECT role_name, scope, scope_type
          FROM role_assignments
         WHERE identity_db_id = %s
        """,
        (identity_db_id,),
    )
    return [{'role_name': r[0], 'scope': r[1], 'scope_type': r[2]}
            for r in cursor.fetchall()]


def _load_reachability(cursor, identity_db_id: int) -> list[dict]:
    cursor.execute(
        """
        SELECT data_classification, est_records, write_resource_count, resource_count
          FROM agent_data_reachability
         WHERE identity_db_id = %s
        """,
        (identity_db_id,),
    )
    return [{'classification': r[0], 'est_records': r[1] or 0,
             'write_resource_count': r[2] or 0, 'resource_count': r[3] or 0}
            for r in cursor.fetchall()]


def _load_kv_secrets(cursor, role_assignments: list[dict], org_id: int) -> dict:
    """For every KV scope the agent has access to, look up secrets_total."""
    kv_scopes = [ra['scope'] for ra in role_assignments
                 if ra.get('scope') and '/providers/microsoft.keyvault/vaults/' in (ra['scope'] or '').lower()]
    if not kv_scopes:
        return {'vault_count': 0, 'secrets_total': 0, 'vault_names': []}
    cursor.execute(
        """
        SELECT name, COALESCE(secrets_total, 0)
          FROM azure_key_vaults
         WHERE organization_id = %s
           AND resource_id = ANY(%s)
        """,
        (org_id, kv_scopes),
    )
    rows = cursor.fetchall()
    return {
        'vault_count':   len(rows),
        'secrets_total': sum(r[1] for r in rows),
        'vault_names':   [r[0] for r in rows],
    }


def _load_credentials(cursor, identity_db_id: int) -> dict:
    """Auth surfaces — client secrets + certificates."""
    try:
        cursor.execute("SAVEPOINT _abuse_creds_sp")
        cursor.execute(
            """
            SELECT credential_type, end_datetime
              FROM credentials
             WHERE identity_db_id = %s
             ORDER BY end_datetime ASC NULLS LAST
            """,
            (identity_db_id,),
        )
        rows = cursor.fetchall()
        cursor.execute("RELEASE SAVEPOINT _abuse_creds_sp")
    except Exception:
        try: cursor.execute("ROLLBACK TO SAVEPOINT _abuse_creds_sp")
        except Exception: pass
        rows = []
    secrets = sum(1 for r in rows if (r[0] or '').lower() in ('password', 'secret', 'client_secret'))
    certs   = sum(1 for r in rows if (r[0] or '').lower() in ('certificate', 'x509cert', 'cert'))
    earliest_expiry = None
    for r in rows:
        if r[1] is not None:
            earliest_expiry = r[1]
            break
    return {
        'secret_count': secrets,
        'cert_count':   certs,
        'earliest_expiry': earliest_expiry.isoformat() if earliest_expiry else None,
    }


def _load_federated_credentials(cursor, identity_db_id: int) -> dict:
    try:
        cursor.execute("SAVEPOINT _abuse_fed_sp")
        cursor.execute(
            """
            SELECT issuer, subject, audiences, issuer_type
              FROM federated_credentials
             WHERE identity_db_id = %s
            """,
            (identity_db_id,),
        )
        rows = cursor.fetchall()
        cursor.execute("RELEASE SAVEPOINT _abuse_fed_sp")
    except Exception:
        try: cursor.execute("ROLLBACK TO SAVEPOINT _abuse_fed_sp")
        except Exception: pass
        rows = []
    has_weak = False
    for r in rows:
        subject = (r[1] or '').strip()
        # Wildcard subject = weak (any external IdP token can impersonate)
        if subject == '*' or subject == '':
            has_weak = True
            break
    return {
        'count': len(rows),
        'has_weak_audience': has_weak,
    }


def _load_supply_chain(cursor, agent_meta: dict, org_id: int) -> dict:
    """Discover the Cognitive Services account this agent uses, the count
    of OTHER agents on that same account, and the model deployments."""
    account = agent_meta.get('account_resource_id')
    if not account:
        return {'account_name': None, 'co_tenants': 0,
                'model_count': 0, 'finetune_count': 0,
                'public_network': False}
    # Cog Services account posture
    public_network = False
    try:
        cursor.execute("SAVEPOINT _abuse_sc_csa")
        cursor.execute(
            """
            SELECT LOWER(COALESCE(public_network_access, ''))
              FROM azure_cognitive_services_accounts
             WHERE organization_id = %s AND resource_id = %s
            """,
            (org_id, account),
        )
        r = cursor.fetchone()
        public_network = bool(r and r[0] == 'enabled')
        cursor.execute("RELEASE SAVEPOINT _abuse_sc_csa")
    except Exception:
        try: cursor.execute("ROLLBACK TO SAVEPOINT _abuse_sc_csa")
        except Exception: pass

    # Other agents on the same account
    try:
        cursor.execute("SAVEPOINT _abuse_sc_co")
        cursor.execute(
            """
            SELECT COUNT(DISTINCT identity_db_id) - 1
              FROM agent_classifications
             WHERE organization_id = %s
               AND account_resource_id = %s
               AND identity_db_id != %s
            """,
            (org_id, account, agent_meta.get('id')),
        )
        co = cursor.fetchone()
        co_tenants = max(0, int(co[0] or 0))
        cursor.execute("RELEASE SAVEPOINT _abuse_sc_co")
    except Exception:
        try: cursor.execute("ROLLBACK TO SAVEPOINT _abuse_sc_co")
        except Exception: pass
        co_tenants = 0

    # Models hosted (incl. fine-tunes)
    try:
        cursor.execute("SAVEPOINT _abuse_sc_models")
        cursor.execute(
            """
            SELECT COUNT(DISTINCT model_name),
                   COUNT(*) FILTER (WHERE LOWER(COALESCE(model_name,'')) LIKE '%%-ft-%%')
              FROM azure_ai_model_deployments
             WHERE organization_id = %s AND account_resource_id = %s
            """,
            (org_id, account),
        )
        m = cursor.fetchone()
        model_count    = int((m and m[0]) or 0)
        finetune_count = int((m and m[1]) or 0)
        cursor.execute("RELEASE SAVEPOINT _abuse_sc_models")
    except Exception:
        try: cursor.execute("ROLLBACK TO SAVEPOINT _abuse_sc_models")
        except Exception: pass
        model_count = finetune_count = 0

    # Account name (last path segment)
    account_name = account.rsplit('/', 1)[-1] if account else None
    return {
        'account_name': account_name,
        'co_tenants': co_tenants,
        'model_count': model_count,
        'finetune_count': finetune_count,
        'public_network': public_network,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Scenarios
# ─────────────────────────────────────────────────────────────────────────────

def _scenario_prompt_injection(db, meta, ras, reach, kv) -> dict[str, Any]:
    """Under prompt injection, what does this agent reach?"""
    catalogue = next(s for s in SCENARIOS if s['key'] == 'prompt_injection')

    # Build dollar consequence from reachability
    # (dedup via MAX per classification matches Business Impact policy)
    dedup_rows = [{'data_classification': r['classification'], 'est_records': r['est_records']}
                  for r in reach if r['est_records'] > 0]
    agg = aggregate_exposure(db, dedup_rows)
    has_kv_admin = any((ra.get('role_name') or '').lower() in
                       ('key vault administrator', 'key vault secrets officer')
                       for ra in ras)
    has_blob_owner = any((ra.get('role_name') or '').lower() in
                         ('storage blob data owner',) for ra in ras)
    write_count = sum(r['write_resource_count'] for r in reach)

    # Severity: critical if can exfil secrets OR write to PHI;
    # high if read-only to PHI/PCI; medium if PII/financial only; low if no reach.
    severity = 'low'
    if has_kv_admin and kv['secrets_total'] > 0:
        severity = 'critical'
    elif has_blob_owner and write_count > 0:
        severity = 'critical'
    elif any(r['classification'] in ('PHI', 'PCI') for r in reach):
        severity = 'high'
    elif any(r['classification'] in ('PII', 'FINANCIAL') for r in reach):
        severity = 'medium'

    # Headline + evidence
    parts = []
    if has_kv_admin and kv['vault_count'] > 0:
        parts.append(f"can exfil {kv['secrets_total']} secrets across {kv['vault_count']} vault(s)")
    for r in reach:
        if r['est_records'] > 0:
            verb = 'write' if r['write_resource_count'] > 0 else 'read'
            parts.append(f"{verb} {r['est_records']:,} {r['classification']} records")
    headline = '; '.join(parts) if parts else 'No reachable secrets or classified data'

    recommendation = _pi_recommendation(has_kv_admin, has_blob_owner, write_count, reach)

    return {
        **_scenario_envelope(catalogue, severity, headline),
        'evidence': {
            'kv_secrets_reachable': kv['secrets_total'],
            'kv_vault_count':       kv['vault_count'],
            'kv_vault_names':       kv['vault_names'],
            'data_reach':           reach,
            'has_kv_admin':         has_kv_admin,
            'has_blob_owner':       has_blob_owner,
        },
        'blast_radius': _band_from_agg(agg),
        'recommendation': recommendation,
    }


def _scenario_credential_theft(db, meta, ras, reach, creds, fed) -> dict[str, Any]:
    catalogue = next(s for s in SCENARIOS if s['key'] == 'credential_theft')

    surfaces = []
    if creds['secret_count'] > 0:
        surfaces.append(f"{creds['secret_count']} client secret(s)")
    if creds['cert_count'] > 0:
        surfaces.append(f"{creds['cert_count']} certificate(s)")
    if fed['count'] > 0:
        surfaces.append(f"{fed['count']} federated credential(s)" +
                        (' [weak audience]' if fed['has_weak_audience'] else ''))
    has_any = bool(surfaces)
    has_weak_federated = fed['has_weak_audience']

    # Severity logic — if there are NO discoverable auth surfaces, there's
    # nothing for an attacker to steal, so severity stays LOW regardless of
    # reach. Reach only amplifies risk when paired with a stealable
    # credential. (Managed identities authenticate via Azure-managed
    # tokens we don't see in this table; if discovery hasn't surfaced any
    # credential the honest answer is "not observed" not "high".)
    has_phi_pci_reach = any(r['classification'] in ('PHI','PCI') and r['est_records']>0 for r in reach)
    has_any_reach     = any(r['est_records'] > 0 for r in reach)

    if not has_any:
        # No discoverable credentials. Honest empty-state: severity is low,
        # not high — there's no observable attack surface.
        severity = 'low'
    elif has_weak_federated and has_phi_pci_reach:
        severity = 'critical'
    elif has_phi_pci_reach:
        severity = 'high'
    elif has_any_reach:
        severity = 'medium'
    else:
        severity = 'low'

    dedup_rows = [{'data_classification': r['classification'], 'est_records': r['est_records']}
                  for r in reach if r['est_records'] > 0]
    agg = aggregate_exposure(db, dedup_rows)

    headline = ' · '.join(surfaces) if surfaces else 'No discoverable auth surfaces'
    if creds.get('earliest_expiry'):
        headline += f" · earliest expiry {creds['earliest_expiry'][:10]}"

    rec = []
    if creds['secret_count'] > 0:
        rec.append("Rotate client secrets ≤90 days; migrate to certificate or workload-identity-federation")
    if has_weak_federated:
        rec.append("Tighten federated credential subject/audience — wildcard means any IdP can impersonate")
    if not has_any:
        rec.append("No credentials discovered — verify discovery coverage")
    if has_phi_pci_reach:
        rec.append("Enable Conditional Access on the workload identity (MFA-equivalent for SPNs)")

    return {
        **_scenario_envelope(catalogue, severity, headline),
        'evidence': {
            'client_secrets':      creds['secret_count'],
            'certificates':        creds['cert_count'],
            'federated_credentials': fed['count'],
            'has_weak_federated_audience': has_weak_federated,
            'earliest_credential_expiry': creds.get('earliest_expiry'),
        },
        'blast_radius': _band_from_agg(agg),
        'recommendation': ' · '.join(rec) if rec else 'No action required',
    }


def _scenario_owner_departure(db, meta) -> dict[str, Any]:
    catalogue = next(s for s in SCENARIOS if s['key'] == 'owner_departure')

    owner_name = (meta.get('owner_display_name')
                  or meta.get('owner_display_name_at_classify')
                  or '').strip()
    owner_count = int(meta.get('owner_count') or 0)
    has_owner = bool(owner_name) or owner_count > 0

    # Owner staleness — when's the agent's last sign-in (proxy for engagement)
    last_act = meta.get('last_sign_in') or meta.get('last_activity_date')
    days_inactive = None
    if last_act is not None:
        try:
            if isinstance(last_act, datetime):
                la = last_act if last_act.tzinfo else last_act.replace(tzinfo=timezone.utc)
            else:
                la = datetime.fromisoformat(str(last_act).replace('Z', '+00:00'))
                if la.tzinfo is None:
                    la = la.replace(tzinfo=timezone.utc)
            days_inactive = (datetime.now(timezone.utc) - la).days
        except Exception:
            pass

    # Severity:
    # - critical: no owner at all
    # - high: owner exists but agent inactive >90 days (review broken)
    # - medium: single owner (no 2-of-2 redundancy)
    # - low:  multiple owners
    if not has_owner:
        severity = 'critical'
    elif days_inactive is not None and days_inactive >= 90:
        severity = 'high'
    elif owner_count <= 1:
        severity = 'medium'
    else:
        severity = 'low'

    parts = []
    if not has_owner:
        parts.append('No human owner assigned')
    else:
        parts.append(f"Owner: {owner_name}" if owner_name else f"{owner_count} owner(s) on record")
    if days_inactive is not None:
        parts.append(f"agent activity last seen {days_inactive}d ago")
    headline = ' · '.join(parts)

    rec = []
    if not has_owner:
        rec.append("Assign a human owner via the Identity Detail → Ownership tab")
    elif owner_count <= 1:
        rec.append("Add a backup owner (2-of-2) so review continues if primary leaves")
    if days_inactive and days_inactive >= 90:
        rec.append(f"Agent dormant {days_inactive}d — review whether it can be retired")

    return {
        **_scenario_envelope(catalogue, severity, headline),
        'evidence': {
            'owner_present': has_owner,
            'owner_count':   owner_count,
            'owner_name':    owner_name or None,
            'days_inactive': days_inactive,
        },
        'blast_radius': _band_neutral(),
        'recommendation': ' · '.join(rec) if rec else 'Ownership posture acceptable',
    }


def _scenario_tool_abuse(db, meta, ras, reach, kv) -> dict[str, Any]:
    catalogue = next(s for s in SCENARIOS if s['key'] == 'tool_abuse')

    # Rank tools by potential blast — use a fixed priv tier mapping
    priv_tier = {
        'owner':                              4,
        'user access administrator':          4,
        'key vault administrator':            4,
        'key vault secrets officer':          4,
        'storage blob data owner':            4,
        'storage blob data contributor':      3,
        'cognitive services contributor':     3,
        'contributor':                        3,
        'storage blob data reader':           2,
        'key vault secrets user':             2,
        'cognitive services openai contributor': 3,
        'cognitive services openai user':     1,
        'reader':                             1,
    }
    ranked = []
    for ra in ras:
        rn = (ra.get('role_name') or '').lower()
        tier = priv_tier.get(rn, 1)
        ranked.append({'role_name': ra.get('role_name'), 'scope': ra.get('scope'), 'tier': tier})
    ranked.sort(key=lambda x: -x['tier'])
    top_tools = ranked[:3]

    # Severity = top tool's tier
    top_tier = top_tools[0]['tier'] if top_tools else 0
    severity = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'low'}.get(top_tier, 'low')

    dedup_rows = [{'data_classification': r['classification'], 'est_records': r['est_records']}
                  for r in reach if r['est_records'] > 0]
    agg = aggregate_exposure(db, dedup_rows)

    headline = f"Top tool: {top_tools[0]['role_name']}" if top_tools else 'No tools attached'
    if top_tools and kv['secrets_total'] > 0 and top_tools[0]['tier'] >= 4:
        headline += f" — could exfil {kv['secrets_total']} secrets"

    rec_parts = []
    if top_tier >= 4:
        rec_parts.append(f"Drop or scope-restrict: {top_tools[0]['role_name']}")
    if len([t for t in top_tools if t['tier'] >= 3]) >= 2:
        rec_parts.append("Multiple high-priv tools — apply principle of least privilege")

    return {
        **_scenario_envelope(catalogue, severity, headline),
        'evidence': {
            'top_tools':         top_tools,
            'total_role_count':  len(ras),
            'highest_priv_tier': top_tier,
        },
        'blast_radius': _band_from_agg(agg),
        'recommendation': ' · '.join(rec_parts) if rec_parts else 'Tools within acceptable privilege tier',
    }


def _scenario_supply_chain(db, meta, sc) -> dict[str, Any]:
    catalogue = next(s for s in SCENARIOS if s['key'] == 'supply_chain')

    has_finetune = sc['finetune_count'] > 0
    is_public    = sc['public_network']

    # Severity:
    # - critical: public network + fine-tunes (unverified models reachable from public)
    # - high:     public network OR fine-tunes + co-tenants
    # - medium:   private endpoint + fine-tunes
    # - low:      private endpoint + base models only
    if is_public and has_finetune:
        severity = 'critical'
    elif is_public or (has_finetune and sc['co_tenants'] > 0):
        severity = 'high'
    elif has_finetune:
        severity = 'medium'
    else:
        severity = 'low'

    parts = []
    if sc['account_name']:
        parts.append(f"Account: {sc['account_name']}")
    parts.append(f"{sc['model_count']} model(s)")
    if has_finetune:
        parts.append(f"incl. {sc['finetune_count']} fine-tune(s)")
    if sc['co_tenants'] > 0:
        parts.append(f"+{sc['co_tenants']} other agents share this account")
    if is_public:
        parts.append('public network endpoint enabled')
    headline = ' · '.join(parts) if parts else 'No upstream supply chain detected'

    rec = []
    if is_public:
        rec.append('Move to Private Endpoint only; restrict public_network_access=Disabled')
    if has_finetune:
        rec.append('Approve fine-tuned models via Model Registry (Tier 2.2) before deployment')
    if sc['co_tenants'] > 0:
        rec.append(f"Co-tenant blast: {sc['co_tenants']} other agent(s) compromised if account is")

    return {
        **_scenario_envelope(catalogue, severity, headline),
        'evidence': {
            'account_name': sc['account_name'],
            'co_tenants_on_account': sc['co_tenants'],
            'model_count': sc['model_count'],
            'finetune_count': sc['finetune_count'],
            'public_network_endpoint': is_public,
        },
        'blast_radius': _band_neutral(),
        'recommendation': ' · '.join(rec) if rec else 'Upstream supply chain posture acceptable',
    }


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _scenario_envelope(catalogue: dict, severity: str, headline: str) -> dict[str, Any]:
    return {
        'key':         catalogue['key'],
        'label':       catalogue['label'],
        'description': catalogue['description'],
        'threat_source': catalogue['threat_source'],
        'severity':    severity,
        'headline':    headline,
        'mitre_techniques': catalogue['mitre'],
        'mitre_names':      catalogue['mitre_names'],
    }


def _band_from_agg(agg: dict) -> dict[str, Any]:
    if not agg or agg.get('covered', 0) <= 0:
        return _band_neutral()
    return {
        'dollar_low':      float(agg['total_exposure_low']),
        'dollar_mid':      float(agg['total_exposure_mid']),
        'dollar_high':     float(agg['total_exposure_high']),
        'dollar_low_display':  format_dollar_short(agg['total_exposure_low']),
        'dollar_mid_display':  format_dollar_short(agg['total_exposure_mid']),
        'dollar_high_display': format_dollar_short(agg['total_exposure_high']),
        'records':         agg['total_records'],
    }


def _band_neutral() -> dict[str, Any]:
    return {
        'dollar_low': 0, 'dollar_mid': 0, 'dollar_high': 0,
        'dollar_low_display': '$0', 'dollar_mid_display': '$0',
        'dollar_high_display': '$0',
        'records': 0,
    }


def _pi_recommendation(has_kv_admin: bool, has_blob_owner: bool,
                       write_count: int, reach: list[dict]) -> str:
    parts = []
    if has_kv_admin:
        parts.append('Drop Key Vault Administrator → scope to specific secrets the agent needs')
    if has_blob_owner or write_count > 0:
        parts.append('Drop Storage Blob Data Owner → Reader, or scope to non-classified containers')
    if any(r['classification'] == 'PHI' and r['est_records'] > 0 for r in reach):
        parts.append('Validate this agent has a DPIA / BAA covering PHI access')
    if not parts:
        parts.append('Posture acceptable — agent has no high-priv reach to sensitive data')
    return ' · '.join(parts)


def _empty_result(identity_db_id: int) -> dict[str, Any]:
    return {
        'identity_db_id': identity_db_id,
        'identity_id': None,
        'display_name': None,
        'scenarios': [],
        'worst_severity': 'none',
        'computed_at': datetime.now(timezone.utc).isoformat(),
        'error': 'Identity not found',
    }


__all__ = ['SCENARIOS', 'compute_abuse_scenarios', 'compute_abuse_scenarios_org_rollup']
