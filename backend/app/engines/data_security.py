"""
Data Security Attack Surface — Component-based risk scoring for Storage Accounts and Key Vaults.

Each resource is scored across 4 components. Each component has:
- max_score: maximum contribution
- drivers: list of checks (name, points, detected)
- critical_override: condition that forces overall risk to critical

Storage Account Components (max 100):
  1. Network Exposure   (max 30): public blob, network rules, PEs, TLS
  2. Auth Posture        (max 25): shared key, SAS policy, cross-tenant
  3. Logging & Audit     (max 20): diagnostic logging, audit posture
  4. Data Protection     (max 25): CMK, infra encryption, key rotation

Key Vault Components (max 100):
  1. Network Exposure   (max 25): public access, network rules, PEs
  2. Vault Protection   (max 25): soft delete, purge protection, RBAC auth
  3. Identity Access    (max 25): access policy count, over-privileged
  4. Secret Hygiene     (max 25): expired/expiring secrets, keys, certs

Blast Radius:
  (privileged_identity_count * 5) + (dependency_count * 10) + network_exposure_score
"""
import logging

logger = logging.getLogger(__name__)


# ── Tier thresholds ─────────────────────────────────────────────

def _risk_level(score):
    if score >= 70:
        return 'critical'
    if score >= 50:
        return 'high'
    if score >= 30:
        return 'medium'
    if score >= 10:
        return 'low'
    return 'info'


# ═══════════════════════════════════════════════════════════════════
# Storage Account Risk Engine
# ═══════════════════════════════════════════════════════════════════

def score_storage_account(data):
    """
    Compute component-based risk for a storage account dict.
    Returns (total_score, risk_level, risk_components dict, critical_overrides list, risk_reasons list).
    """
    components = {}
    critical_overrides = []
    all_reasons = []

    # ── 1. Network Exposure (max 30) ──────────────────────────────
    drivers = []
    if data.get('public_blob_access'):
        drivers.append({'name': 'Public blob access enabled', 'points': 12})
        critical_overrides.append('Public blob access on internet-facing storage')
    if str(data.get('default_network_action', 'Allow')) == 'Allow':
        drivers.append({'name': 'Firewall allows all traffic', 'points': 8})
    tls = data.get('minimum_tls_version', 'TLS1_2')
    if tls not in ('TLS1_2', 'TLS1_3'):
        drivers.append({'name': f'Weak TLS version: {tls}', 'points': 5})
    if data.get('private_endpoint_count', 0) == 0:
        drivers.append({'name': 'No private endpoints configured', 'points': 5})
    net_raw = sum(d['points'] for d in drivers)
    net_score = min(net_raw, 30)
    components['network_exposure'] = {
        'score': net_score, 'max': 30,
        'drivers': drivers, 'pct': round(net_score / 30 * 100),
    }

    # ── 2. Auth Posture (max 25) ──────────────────────────────────
    drivers = []
    if data.get('shared_key_access'):
        drivers.append({'name': 'Shared key access enabled', 'points': 10})
    if data.get('shared_key_access') and not data.get('sas_policy_enabled'):
        drivers.append({'name': 'No SAS expiration policy', 'points': 8})
    if not data.get('https_only', True):
        drivers.append({'name': 'HTTP traffic allowed', 'points': 5})
    if data.get('allow_cross_tenant_replication'):
        drivers.append({'name': 'Cross-tenant replication enabled', 'points': 2})
    auth_raw = sum(d['points'] for d in drivers)
    auth_score = min(auth_raw, 25)
    components['auth_posture'] = {
        'score': auth_score, 'max': 25,
        'drivers': drivers, 'pct': round(auth_score / 25 * 100),
    }

    # ── 3. Logging & Audit (max 20) ───────────────────────────────
    drivers = []
    has_shared = data.get('shared_key_access')
    has_diag = data.get('diagnostic_logging_enabled')
    has_sas = data.get('sas_policy_enabled')
    if has_shared and not has_diag:
        drivers.append({'name': 'Shared key without diagnostic logging — unauditable', 'points': 12})
    if has_shared and has_diag and not has_sas:
        drivers.append({'name': 'Logging enabled but no SAS policy — partially auditable', 'points': 5})
    if not has_diag:
        drivers.append({'name': 'Diagnostic logging not enabled', 'points': 8})
    log_raw = sum(d['points'] for d in drivers)
    log_score = min(log_raw, 20)
    components['logging_audit'] = {
        'score': log_score, 'max': 20,
        'drivers': drivers, 'pct': round(log_score / 20 * 100),
    }

    # ── 4. Data Protection (max 25) ───────────────────────────────
    drivers = []
    if not data.get('customer_managed_keys'):
        drivers.append({'name': 'No customer-managed encryption keys', 'points': 10})
    if not data.get('infrastructure_encryption'):
        drivers.append({'name': 'No infrastructure encryption', 'points': 5})
    if data.get('key_rotation_stale'):
        drivers.append({'name': 'Storage keys not rotated in 90+ days', 'points': 10})
    dp_raw = sum(d['points'] for d in drivers)
    dp_score = min(dp_raw, 25)
    components['data_protection'] = {
        'score': dp_score, 'max': 25,
        'drivers': drivers, 'pct': round(dp_score / 25 * 100),
    }

    # ── Aggregate ─────────────────────────────────────────────────
    total = net_score + auth_score + log_score + dp_score
    level = 'critical' if critical_overrides else _risk_level(total)

    # Build flat risk_reasons for backward compat
    for comp_name, comp in components.items():
        for d in comp['drivers']:
            all_reasons.append(f"{d['name']} (+{d['points']})")

    return total, level, components, critical_overrides, all_reasons


# ═══════════════════════════════════════════════════════════════════
# Key Vault Risk Engine
# ═══════════════════════════════════════════════════════════════════

def score_key_vault(data):
    """
    Compute component-based risk for a key vault dict.
    Returns (total_score, risk_level, risk_components dict, critical_overrides list, risk_reasons list).
    """
    components = {}
    critical_overrides = []
    all_reasons = []

    # ── 1. Network Exposure (max 25) ──────────────────────────────
    drivers = []
    pub = str(data.get('public_network_access', 'Enabled'))
    net_action = str(data.get('default_network_action', 'Allow'))
    if pub != 'Disabled' and 'Allow' in net_action:
        drivers.append({'name': 'Public network allows all traffic', 'points': 12})
    if data.get('private_endpoint_count', 0) == 0:
        drivers.append({'name': 'No private endpoints configured', 'points': 8})
    if pub != 'Disabled' and data.get('ip_rules_count', 0) == 0 and data.get('vnet_rules_count', 0) == 0:
        drivers.append({'name': 'No IP or VNet restrictions', 'points': 5})
    net_raw = sum(d['points'] for d in drivers)
    net_score = min(net_raw, 25)
    components['network_exposure'] = {
        'score': net_score, 'max': 25,
        'drivers': drivers, 'pct': round(net_score / 25 * 100),
    }

    # ── 2. Vault Protection (max 25) ──────────────────────────────
    drivers = []
    if not data.get('soft_delete_enabled'):
        drivers.append({'name': 'Soft delete disabled', 'points': 12})
        critical_overrides.append('Key vault without soft delete — secrets at risk of permanent loss')
    if not data.get('purge_protection'):
        drivers.append({'name': 'Purge protection disabled', 'points': 8})
    if not data.get('enable_rbac_authorization'):
        drivers.append({'name': 'Using access policies instead of RBAC', 'points': 5})
    vp_raw = sum(d['points'] for d in drivers)
    vp_score = min(vp_raw, 25)
    components['vault_protection'] = {
        'score': vp_score, 'max': 25,
        'drivers': drivers, 'pct': round(vp_score / 25 * 100),
    }

    # ── 3. Identity Access (max 25) ───────────────────────────────
    drivers = []
    policy_count = data.get('access_policy_count', 0)
    if policy_count > 10:
        drivers.append({'name': f'{policy_count} access policies (excessive)', 'points': 10})
    elif policy_count > 5:
        drivers.append({'name': f'{policy_count} access policies (elevated)', 'points': 5})
    if not data.get('enable_rbac_authorization') and policy_count > 0:
        # Check for overly broad policies
        policies = data.get('access_policies', [])
        if isinstance(policies, str):
            import json
            try:
                policies = json.loads(policies)
            except Exception:
                policies = []
        broad_count = 0
        for p in (policies or []):
            perms = p.get('permissions', {})
            all_perms = []
            for k in ('keys', 'secrets', 'certificates', 'storage'):
                vals = perms.get(k, [])
                if isinstance(vals, list):
                    all_perms.extend(vals)
            if 'all' in all_perms or 'All' in all_perms:
                broad_count += 1
        if broad_count > 0:
            drivers.append({'name': f'{broad_count} policies with "All" permissions', 'points': 10})
    if not data.get('enable_rbac_authorization') and policy_count == 0:
        drivers.append({'name': 'Access policies mode with zero policies — unconfigured', 'points': 5})
    ia_raw = sum(d['points'] for d in drivers)
    ia_score = min(ia_raw, 25)
    components['identity_access'] = {
        'score': ia_score, 'max': 25,
        'drivers': drivers, 'pct': round(ia_score / 25 * 100),
    }

    # ── 4. Secret Hygiene (max 25) ────────────────────────────────
    drivers = []
    exp_secrets = data.get('secrets_expired', 0)
    exp_keys = data.get('keys_expired', 0)
    exp_certs = data.get('certs_expired', 0)
    total_expired = exp_secrets + exp_keys + exp_certs
    if total_expired > 0:
        drivers.append({'name': f'{total_expired} expired items (secrets/keys/certs)', 'points': min(total_expired * 3, 12)})
    soon_secrets = data.get('secrets_expiring_soon', 0)
    soon_keys = data.get('keys_expiring_soon', 0)
    soon_certs = data.get('certs_expiring_soon', 0)
    total_soon = soon_secrets + soon_keys + soon_certs
    if total_soon > 0:
        drivers.append({'name': f'{total_soon} items expiring within 30 days', 'points': min(total_soon * 2, 8)})
    total_items = data.get('secrets_total', 0) + data.get('keys_total', 0) + data.get('certs_total', 0)
    if total_items == 0:
        drivers.append({'name': 'Empty vault — no secrets, keys, or certificates', 'points': 5})
    sh_raw = sum(d['points'] for d in drivers)
    sh_score = min(sh_raw, 25)
    components['secret_hygiene'] = {
        'score': sh_score, 'max': 25,
        'drivers': drivers, 'pct': round(sh_score / 25 * 100),
    }

    # ── Aggregate ─────────────────────────────────────────────────
    total = net_score + vp_score + ia_score + sh_score
    level = 'critical' if critical_overrides else _risk_level(total)

    for comp_name, comp in components.items():
        for d in comp['drivers']:
            all_reasons.append(f"{d['name']} (+{d['points']})")

    return total, level, components, critical_overrides, all_reasons


# ═══════════════════════════════════════════════════════════════════
# Blast Radius Calculator
# ═══════════════════════════════════════════════════════════════════

def compute_blast_radius(privileged_identity_count, dependency_count, network_exposure_score):
    """
    Blast Radius = (privileged_identity_count * 5) + (dependency_count * 10) + network_exposure_score
    """
    return (privileged_identity_count * 5) + (dependency_count * 10) + network_exposure_score


# ═══════════════════════════════════════════════════════════════════
# Identity Exposure Enhancement (Phase 89)
# ═══════════════════════════════════════════════════════════════════

def enhance_risk_with_identity_exposure(base_score, risk_components, resource_data,
                                         privileged_identity_count, network_exposure_score):
    """
    Enhance a resource's risk score based on identity exposure.

    Modifiers for Storage Accounts:
      - Network-exposed + >5 privileged identities = +15 pts
      - Public blob + any privileged identity = +10 pts

    Modifiers for Key Vaults:
      - High access policy count (>5) + network-exposed = +15 pts
      - Secrets exist + >5 privileged identities = +10 pts

    Adds 'identity_exposure' component to risk_components.
    Returns (adjusted_score, adjusted_level, updated_risk_components).
    """
    drivers = []
    bonus = 0
    resource_type = resource_data.get('resource_type', '')

    is_network_exposed = network_exposure_score > 10
    public_blob = resource_data.get('public_blob_access', False)

    if resource_type == 'storage_account' or public_blob is not None:
        # Storage account modifiers
        if is_network_exposed and privileged_identity_count > 5:
            bonus += 15
            drivers.append({
                'name': f'Network-exposed with {privileged_identity_count} privileged identities',
                'points': 15,
            })
        if public_blob and privileged_identity_count > 0:
            bonus += 10
            drivers.append({
                'name': f'Public blob access with {privileged_identity_count} privileged identities',
                'points': 10,
            })
    else:
        # Key vault modifiers
        ap_count = resource_data.get('access_policy_count', 0)
        secrets_total = resource_data.get('secrets_total', 0)
        if ap_count > 5 and is_network_exposed:
            bonus += 15
            drivers.append({
                'name': f'{ap_count} access policies on network-exposed vault',
                'points': 15,
            })
        if secrets_total > 0 and privileged_identity_count > 5:
            bonus += 10
            drivers.append({
                'name': f'{secrets_total} secrets with {privileged_identity_count} privileged identities',
                'points': 10,
            })

    adjusted_score = min(base_score + bonus, 100)
    risk_components['identity_exposure'] = {
        'score': bonus, 'max': 25,
        'drivers': drivers, 'pct': round(bonus / 25 * 100),
    }
    adjusted_level = 'critical' if risk_components.get('identity_exposure', {}).get('score', 0) >= 15 and adjusted_score >= 70 else _risk_level(adjusted_score)

    return adjusted_score, adjusted_level, risk_components


# ═══════════════════════════════════════════════════════════════════
# Summary Aggregator
# ═══════════════════════════════════════════════════════════════════

def compute_data_security_summary(storage_accounts, key_vaults):
    """
    Aggregate summary stats from scored resources.
    Returns dict with total, by_risk, avg_score, component_averages, top_risks.
    """
    all_resources = []
    for sa in storage_accounts:
        all_resources.append({
            'type': 'storage_account',
            'name': sa.get('name', ''),
            'risk_score': sa.get('risk_score', 0),
            'risk_level': sa.get('risk_level', 'info'),
            'risk_components': sa.get('risk_components', {}),
            'resource_id': sa.get('resource_id', ''),
        })
    for kv in key_vaults:
        all_resources.append({
            'type': 'key_vault',
            'name': kv.get('name', ''),
            'risk_score': kv.get('risk_score', 0),
            'risk_level': kv.get('risk_level', 'info'),
            'risk_components': kv.get('risk_components', {}),
            'resource_id': kv.get('resource_id', ''),
        })

    total = len(all_resources)
    by_risk = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for r in all_resources:
        lvl = r['risk_level']
        if lvl in by_risk:
            by_risk[lvl] += 1

    scores = [r['risk_score'] for r in all_resources]
    avg_score = round(sum(scores) / max(len(scores), 1))

    # Component averages
    comp_keys_sa = ['network_exposure', 'auth_posture', 'logging_audit', 'data_protection']
    comp_keys_kv = ['network_exposure', 'vault_protection', 'identity_access', 'secret_hygiene']

    sa_comp_avgs = {}
    for ck in comp_keys_sa:
        vals = [r['risk_components'].get(ck, {}).get('pct', 0) for r in all_resources if r['type'] == 'storage_account']
        sa_comp_avgs[ck] = round(sum(vals) / max(len(vals), 1)) if vals else 0

    kv_comp_avgs = {}
    for ck in comp_keys_kv:
        vals = [r['risk_components'].get(ck, {}).get('pct', 0) for r in all_resources if r['type'] == 'key_vault']
        kv_comp_avgs[ck] = round(sum(vals) / max(len(vals), 1)) if vals else 0

    # Top risks (top 5 by score)
    top_risks = sorted(all_resources, key=lambda r: r['risk_score'], reverse=True)[:5]

    return {
        'total': total,
        'storage_accounts': len(storage_accounts),
        'key_vaults': len(key_vaults),
        'by_risk': by_risk,
        'at_risk': by_risk['critical'] + by_risk['high'],
        'avg_score': avg_score,
        'component_averages': {
            'storage': sa_comp_avgs,
            'key_vault': kv_comp_avgs,
        },
        'top_risks': top_risks,
    }
