"""
AWS Data Security Attack Surface — Component-based risk scoring for S3 Buckets, KMS Keys, and Lambda Functions.

Each resource is scored across 4 components (max 100 total).
Same pattern as data_security.py (Azure resources).

S3 Bucket Components:
  1. Public Exposure   (max 30): public access block, policy, ACL
  2. Encryption        (max 25): SSE config, KMS, bucket key
  3. Logging           (max 20): access logging, versioning, lifecycle
  4. Data Protection   (max 25): MFA delete, lifecycle expiry, key rotation

KMS Key Components:
  1. Key Management    (max 30): rotation, state, disabled
  2. Access Policy     (max 25): wildcard principal, excessive grants
  3. Configuration     (max 25): origin, age, spec
  4. Compliance        (max 20): tags, manager type, age

Lambda Function Components:
  1. Execution Privilege (max 30): admin role, PassRole, VPC
  2. Secrets Exposure    (max 25): env var secrets, KMS, public invoke
  3. Runtime             (max 25): deprecated runtime, timeout, DLQ
  4. Hygiene             (max 20): tags, code size, staleness
"""
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

DEPRECATED_RUNTIMES = {
    'python2.7', 'python3.6', 'python3.7',
    'nodejs10.x', 'nodejs12.x', 'nodejs14.x',
    'dotnetcore2.1', 'dotnetcore3.1',
    'ruby2.5', 'ruby2.7',
    'java8', 'go1.x',
}

ADMIN_POLICY_PATTERNS = {
    'AdministratorAccess', 'arn:aws:iam::aws:policy/AdministratorAccess',
}

PASSROLE_PATTERN = 'iam:PassRole'


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
# S3 Bucket Risk Engine
# ═══════════════════════════════════════════════════════════════════

def score_s3_bucket(data):
    """
    Compute component-based risk for an S3 bucket dict.
    Returns (total_score, risk_level, risk_components, critical_overrides, risk_reasons).
    """
    components = {}
    critical_overrides = []
    all_reasons = []

    # ── 1. Public Exposure (max 30) ──────────────────────────────
    drivers = []
    if not data.get('public_access_block_enabled'):
        drivers.append({'name': 'Public access block not enabled', 'points': 15})
        critical_overrides.append('S3 bucket missing public access block')
    if data.get('policy_status_is_public'):
        drivers.append({'name': 'Bucket policy allows public access', 'points': 10})
    if data.get('acl_grants_public'):
        drivers.append({'name': 'ACL grants public access', 'points': 5})
    net_raw = sum(d['points'] for d in drivers)
    net_score = min(net_raw, 30)
    components['public_exposure'] = {
        'score': net_score, 'max': 30,
        'drivers': drivers, 'pct': round(net_score / 30 * 100),
    }

    # ── 2. Encryption (max 25) ───────────────────────────────────
    drivers = []
    if not data.get('encryption_enabled'):
        drivers.append({'name': 'Server-side encryption not enabled', 'points': 15})
        critical_overrides.append('S3 bucket has no encryption')
    elif data.get('encryption_algorithm') == 'AES256':
        drivers.append({'name': 'Using SSE-S3 instead of KMS encryption', 'points': 5})
    if not data.get('bucket_key_enabled'):
        drivers.append({'name': 'S3 Bucket Key not enabled', 'points': 5})
    enc_raw = sum(d['points'] for d in drivers)
    enc_score = min(enc_raw, 25)
    components['encryption'] = {
        'score': enc_score, 'max': 25,
        'drivers': drivers, 'pct': round(enc_score / 25 * 100),
    }

    # ── 3. Logging (max 20) ──────────────────────────────────────
    drivers = []
    if not data.get('logging_enabled'):
        drivers.append({'name': 'Server access logging not enabled', 'points': 10})
    if not data.get('versioning_enabled'):
        drivers.append({'name': 'Versioning not enabled', 'points': 5})
    if (data.get('lifecycle_rules_count') or 0) == 0:
        drivers.append({'name': 'No lifecycle rules configured', 'points': 5})
    log_raw = sum(d['points'] for d in drivers)
    log_score = min(log_raw, 20)
    components['logging'] = {
        'score': log_score, 'max': 20,
        'drivers': drivers, 'pct': round(log_score / 20 * 100),
    }

    # ── 4. Data Protection (max 25) ──────────────────────────────
    drivers = []
    if not data.get('mfa_delete'):
        drivers.append({'name': 'MFA Delete not enabled', 'points': 5})
    if (data.get('lifecycle_rules_count') or 0) == 0:
        drivers.append({'name': 'No lifecycle expiration configured', 'points': 10})
    if data.get('encryption_enabled') and not data.get('kms_key_id'):
        drivers.append({'name': 'No KMS key rotation possible (SSE-S3)', 'points': 10})
    dp_raw = sum(d['points'] for d in drivers)
    dp_score = min(dp_raw, 25)
    components['data_protection'] = {
        'score': dp_score, 'max': 25,
        'drivers': drivers, 'pct': round(dp_score / 25 * 100),
    }

    # ── Aggregate ─────────────────────────────────────────────────
    total = net_score + enc_score + log_score + dp_score
    has_any_driver = any(comp['drivers'] for comp in components.values())
    if has_any_driver and total == 0:
        total = 1
    level = 'critical' if critical_overrides else _risk_level(total)

    for comp in components.values():
        for d in comp['drivers']:
            all_reasons.append(f"{d['name']} (+{d['points']})")

    return total, level, components, critical_overrides, all_reasons


# ═══════════════════════════════════════════════════════════════════
# KMS Key Risk Engine
# ═══════════════════════════════════════════════════════════════════

def score_kms_key(data):
    """
    Compute component-based risk for a KMS key dict.
    Returns (total_score, risk_level, risk_components, critical_overrides, risk_reasons).
    """
    components = {}
    critical_overrides = []
    all_reasons = []

    # ── 1. Key Management (max 30) ───────────────────────────────
    drivers = []
    if not data.get('rotation_enabled'):
        drivers.append({'name': 'Automatic key rotation not enabled', 'points': 15})
    key_state = data.get('key_state', '')
    if key_state == 'PendingDeletion':
        drivers.append({'name': 'Key is pending deletion', 'points': 10})
        critical_overrides.append('KMS key pending deletion — data loss risk')
    if key_state == 'Disabled':
        drivers.append({'name': 'Key is disabled', 'points': 5})
    km_raw = sum(d['points'] for d in drivers)
    km_score = min(km_raw, 30)
    components['key_management'] = {
        'score': km_score, 'max': 30,
        'drivers': drivers, 'pct': round(km_score / 30 * 100),
    }

    # ── 2. Access Policy (max 25) ────────────────────────────────
    drivers = []
    policy = data.get('key_policy') or {}
    has_wildcard = False
    if isinstance(policy, dict):
        # Check Statement blocks for Principal: '*'
        for stmt in policy.get('Statement', []):
            principal = stmt.get('Principal', '')
            if principal == '*':
                has_wildcard = True
                break
            if isinstance(principal, dict):
                if principal.get('AWS') == '*' or '*' in (principal.get('AWS') if isinstance(principal.get('AWS'), list) else []):
                    has_wildcard = True
                    break
        # Fallback: string check for JSON-serialized policy
        if not has_wildcard:
            policy_str = str(policy)
            if "'*'" in policy_str and "'Principal'" in policy_str:
                has_wildcard = True
    else:
        has_wildcard = '*' in str(policy)
    if has_wildcard:
        drivers.append({'name': 'Key policy has wildcard principal', 'points': 15})
        critical_overrides.append('KMS key policy allows wildcard principal access')
    grants = data.get('grants_count', 0) or 0
    if grants > 10:
        drivers.append({'name': f'Excessive grants ({grants})', 'points': 5})
    # Cross-account detection from policy
    policy_text = str(data.get('key_policy', ''))
    if 'arn:aws:iam::' in policy_text:
        # Check if any principal ARN has a different account
        import re
        account_ids = re.findall(r'arn:aws:iam::(\d+)', policy_text)
        own_account = data.get('aws_account_id', '')
        cross = [a for a in account_ids if a and a != own_account]
        if cross:
            drivers.append({'name': 'Cross-account access in key policy', 'points': 5})
    ap_raw = sum(d['points'] for d in drivers)
    ap_score = min(ap_raw, 25)
    components['access_policy'] = {
        'score': ap_score, 'max': 25,
        'drivers': drivers, 'pct': round(ap_score / 25 * 100),
    }

    # ── 3. Configuration (max 25) ────────────────────────────────
    drivers = []
    if data.get('origin') == 'EXTERNAL':
        drivers.append({'name': 'External key material origin', 'points': 10})
    if not data.get('rotation_enabled') and data.get('key_state') == 'Enabled':
        # Old key without rotation
        drivers.append({'name': 'Enabled key without rotation', 'points': 10})
    if data.get('key_usage') == 'ENCRYPT_DECRYPT' and data.get('key_spec', '').startswith('RSA'):
        drivers.append({'name': 'Asymmetric key used for encryption', 'points': 5})
    cfg_raw = sum(d['points'] for d in drivers)
    cfg_score = min(cfg_raw, 25)
    components['configuration'] = {
        'score': cfg_score, 'max': 25,
        'drivers': drivers, 'pct': round(cfg_score / 25 * 100),
    }

    # ── 4. Compliance (max 20) ───────────────────────────────────
    drivers = []
    tags = data.get('tags') or {}
    if not tags or (isinstance(tags, dict) and len(tags) == 0):
        drivers.append({'name': 'No tags on key', 'points': 5})
    if data.get('key_manager') == 'AWS':
        drivers.append({'name': 'AWS-managed key (limited control)', 'points': 5})
    # Age check — if created_at available
    created = data.get('created_at')
    if created:
        try:
            if isinstance(created, str):
                created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
            else:
                created_dt = created
            if created_dt.tzinfo is None:
                created_dt = created_dt.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created_dt).days
            if age_days > 365:
                drivers.append({'name': f'Key age {age_days} days (>365)', 'points': 10})
        except Exception:
            pass
    comp_raw = sum(d['points'] for d in drivers)
    comp_score = min(comp_raw, 20)
    components['compliance'] = {
        'score': comp_score, 'max': 20,
        'drivers': drivers, 'pct': round(comp_score / 20 * 100),
    }

    # ── Aggregate ─────────────────────────────────────────────────
    total = km_score + ap_score + cfg_score + comp_score
    has_any_driver = any(comp['drivers'] for comp in components.values())
    if has_any_driver and total == 0:
        total = 1
    level = 'critical' if critical_overrides else _risk_level(total)

    for comp in components.values():
        for d in comp['drivers']:
            all_reasons.append(f"{d['name']} (+{d['points']})")

    return total, level, components, critical_overrides, all_reasons


# ═══════════════════════════════════════════════════════════════════
# Lambda Function Risk Engine
# ═══════════════════════════════════════════════════════════════════

def score_lambda_function(data):
    """
    Compute component-based risk for a Lambda function dict.
    Returns (total_score, risk_level, risk_components, critical_overrides, risk_reasons).
    """
    components = {}
    critical_overrides = []
    all_reasons = []

    # ── 1. Execution Privilege (max 30) ──────────────────────────
    drivers = []
    role_arn = data.get('execution_role_arn', '') or ''
    role_name = data.get('execution_role_name', '') or ''
    if any(p in role_name for p in ('Admin', 'FullAccess', 'PowerUser')):
        drivers.append({'name': 'Execution role has admin-level privileges', 'points': 15})
        critical_overrides.append('Lambda has admin execution role')
    # PassRole check would need policy doc — flag if role name suggests it
    if not data.get('vpc_id'):
        drivers.append({'name': 'Function not in VPC', 'points': 5})
    if data.get('resource_policy_is_public'):
        drivers.append({'name': 'Resource policy allows public invocation', 'points': 10})
    ep_raw = sum(d['points'] for d in drivers)
    ep_score = min(ep_raw, 30)
    components['execution_privilege'] = {
        'score': ep_score, 'max': 30,
        'drivers': drivers, 'pct': round(ep_score / 30 * 100),
    }

    # ── 2. Secrets Exposure (max 25) ─────────────────────────────
    drivers = []
    if data.get('has_secrets_in_env'):
        drivers.append({'name': 'Secrets detected in environment variables', 'points': 15})
        critical_overrides.append('Lambda has secrets in environment variables')
    env_count = data.get('environment_variables_count', 0) or 0
    if env_count > 0 and not data.get('kms_key_arn'):
        drivers.append({'name': 'Environment variables not encrypted with KMS', 'points': 5})
    if data.get('resource_policy_is_public'):
        drivers.append({'name': 'Public invoke enabled', 'points': 5})
    se_raw = sum(d['points'] for d in drivers)
    se_score = min(se_raw, 25)
    components['secrets_exposure'] = {
        'score': se_score, 'max': 25,
        'drivers': drivers, 'pct': round(se_score / 25 * 100),
    }

    # ── 3. Runtime (max 25) ──────────────────────────────────────
    drivers = []
    runtime = data.get('runtime', '') or ''
    if runtime in DEPRECATED_RUNTIMES:
        drivers.append({'name': f'Deprecated runtime: {runtime}', 'points': 10})
    timeout = data.get('timeout', 0) or 0
    if timeout > 300:
        drivers.append({'name': f'Excessive timeout: {timeout}s', 'points': 5})
    memory = data.get('memory_size', 0) or 0
    if memory > 3008:
        drivers.append({'name': f'Large memory allocation: {memory}MB', 'points': 5})
    # DLQ check — no dead letter config
    if not data.get('dead_letter_config'):
        drivers.append({'name': 'No dead letter queue configured', 'points': 5})
    rt_raw = sum(d['points'] for d in drivers)
    rt_score = min(rt_raw, 25)
    components['runtime'] = {
        'score': rt_score, 'max': 25,
        'drivers': drivers, 'pct': round(rt_score / 25 * 100),
    }

    # ── 4. Hygiene (max 20) ──────────────────────────────────────
    drivers = []
    tags = data.get('tags') or {}
    if not tags or (isinstance(tags, dict) and len(tags) == 0):
        drivers.append({'name': 'No tags on function', 'points': 5})
    code_size = data.get('code_size', 0) or 0
    if code_size > 50 * 1024 * 1024:  # > 50MB
        drivers.append({'name': 'Large deployment package', 'points': 5})
    # Staleness check
    last_modified = data.get('last_modified')
    if last_modified:
        try:
            if isinstance(last_modified, str):
                lm = datetime.fromisoformat(last_modified.replace('Z', '+00:00'))
            else:
                lm = last_modified
            if lm.tzinfo is None:
                lm = lm.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - lm).days
            if age_days > 180:
                drivers.append({'name': f'Function not modified in {age_days} days', 'points': 5})
        except Exception:
            pass
    hy_raw = sum(d['points'] for d in drivers)
    hy_score = min(hy_raw, 20)
    components['hygiene'] = {
        'score': hy_score, 'max': 20,
        'drivers': drivers, 'pct': round(hy_score / 20 * 100),
    }

    # ── Aggregate ─────────────────────────────────────────────────
    total = ep_score + se_score + rt_score + hy_score
    has_any_driver = any(comp['drivers'] for comp in components.values())
    if has_any_driver and total == 0:
        total = 1
    level = 'critical' if critical_overrides else _risk_level(total)

    for comp in components.values():
        for d in comp['drivers']:
            all_reasons.append(f"{d['name']} (+{d['points']})")

    return total, level, components, critical_overrides, all_reasons
