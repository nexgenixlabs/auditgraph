"""
Governance Service — Single Source of Truth

Canonical derivation of the three identity-dimension classification:
  1. Governance State:  Orphaned | Policy Violation | Ungoverned | Governed
  2. Lifecycle State:   Disabled | Dormant | Active | Provisioned
  3. Privilege Level:   Highly Privileged | Privileged | Standard

ALL screens (Identity Inventory, Executive Posture, CISO Summary, AGIRS)
MUST consume these functions.  No inline governance logic is permitted elsewhere.

Title Case contract:  Every value is emitted in Title Case (e.g. "Orphaned",
"Highly Privileged") and the frontend matches on exact strings.
"""

from datetime import datetime, timezone

from app.constants.roles import GRAPH_ACTIVITY_IMPLIES_USAGE


# ── Constants ───────────────────────────────────────────────────────────────

GOVERNANCE_STATES = ('Orphaned', 'Policy Violation', 'Ungoverned', 'Governed')
LIFECYCLE_STATES = ('Disabled', 'Dormant', 'Active', 'Provisioned')
PRIVILEGE_LEVELS = ('Highly Privileged', 'Privileged', 'Standard')


# ── Helpers ─────────────────────────────────────────────────────────────────

def _resolve_privilege_tier_int(raw):
    """Normalize privilege_tier to int 0..3 regardless of source representation.

    Accepts:
      * None → 3 (Standard)
      * int 0..3 → passthrough
      * str 'T0'/'T1'/'T2'/'T3' (any case) → 0/1/2/3
      * str '0'/'1'/'2'/'3' → 0/1/2/3
      * anything else → 3
    """
    if raw is None:
        return 3
    if isinstance(raw, bool):  # bool is a subclass of int — reject
        return 3
    if isinstance(raw, int):
        return raw if 0 <= raw <= 3 else 3
    s = str(raw).strip().upper()
    return {'T0': 0, 'T1': 1, 'T2': 2, 'T3': 3,
            '0': 0, '1': 1, '2': 2, '3': 3}.get(s, 3)


def resolve_last_seen_days(row):
    """Return number of days since last observed activity, or None if unknown.

    Checks last_activity_date, last_sign_in, last_seen_auth (in order)
    and returns the smallest delta.
    """
    candidates = ['last_activity_date', 'last_sign_in', 'last_seen_auth']
    for field in candidates:
        val = row.get(field) if hasattr(row, 'get') else None
        if val:
            try:
                if isinstance(val, datetime):
                    return (datetime.now(timezone.utc) - val).days
                parsed = datetime.fromisoformat(str(val).replace('Z', '+00:00'))
                return (datetime.now(timezone.utc) - parsed).days
            except Exception:
                continue
    return None


# ── Governance State ────────────────────────────────────────────────────────

def derive_governance_state(row, privilege_tier,
                            # Forward-compatible parameters (not yet in schema)
                            policy_coverage=False,
                            active_breach=False,
                            owner_last_active_days_ago=None,
                            owner_has_reviewed=False):
    """Strict ordered governance evaluation chain.

    Azure reality: 60-80 % of SPNs have no owner (created via automation).
    This function surfaces that truth rather than hiding it behind defaults.

    Parameters
    ----------
    row : dict-like
        Must support .get() with keys: owner_count, recommended_action,
        activity_status, last_activity_date, last_sign_in, last_seen_auth.
    privilege_tier : int
        0 = T0, 1 = T1, 2 = T2, 3 = T3.
    policy_coverage : bool
        (Future) True if governance policies are applied. Currently unused.
    active_breach : bool
        (Future) True if an active policy breach is detected. Currently unused.
    owner_last_active_days_ago : int | None
        (Future) Days since the identity's owner was last active.
    owner_has_reviewed : bool
        (Future) True if the owner has performed an access review.

    Returns
    -------
    str
        One of GOVERNANCE_STATES — always Title Case.
    """
    owner_ct = int(row.get('owner_count') or 0) if hasattr(row, 'get') else 0
    rec_action = (row.get('recommended_action') or '').upper() if hasattr(row, 'get') else ''
    activity = (row.get('activity_status') or 'unknown').lower() if hasattr(row, 'get') else 'unknown'

    # 1. No owner in directory — Orphaned only if also no activity.
    #    Active identities without owners are Ungoverned (need owner
    #    assignment), not Orphaned. Aligns with GovernanceEngine._classify.
    if owner_ct == 0:
        last_seen_days = resolve_last_seen_days(row)
        no_recent_activity = (last_seen_days is None or last_seen_days > 180)
        if activity in ('never_used', 'unknown') and no_recent_activity:
            return 'Orphaned'
        return 'Ungoverned'

    # 2. Active risk / policy violation signal
    if rec_action == 'AT_RISK' or active_breach:
        return 'Policy Violation'

    # 3. Identity is stale or never used → governance gap
    if activity in ('stale', 'never_used'):
        return 'Ungoverned'

    # 4. Recommended action indicates governance concern
    if rec_action in ('UNUSED', 'STALE', 'NEEDS_REVIEW', 'ORPHANED'):
        return 'Ungoverned'

    # 5. Last seen 90+ days ago → stale governance regardless of owner
    last_seen_days = resolve_last_seen_days(row)
    if last_seen_days is not None and last_seen_days > 90:
        return 'Ungoverned'

    # 6. Privileged identity with inactive activity → governance gap
    if privilege_tier <= 1 and activity == 'inactive':
        return 'Ungoverned'

    # 7. (Future) Owner hasn't reviewed and last active 180+ days ago
    if owner_last_active_days_ago is not None and owner_last_active_days_ago > 180 and not owner_has_reviewed:
        return 'Ungoverned'

    # 8. All conditions passed — identity is genuinely governed
    return 'Governed'


# ── Lifecycle State ─────────────────────────────────────────────────────────

def derive_lifecycle_state(enabled, activity_status):
    """Derive lifecycle state from enabled flag and activity status.

    Returns Title Case string: Disabled | Dormant | Active | Provisioned.
    """
    if not enabled:
        return 'Disabled'
    activity = (activity_status or 'unknown').lower()
    if activity in ('stale', 'never_used'):
        return 'Dormant'
    if activity in ('active', 'recently_created', 'inactive', 'likely_active'):
        return 'Active'
    return 'Provisioned'


# ── Privilege Level ─────────────────────────────────────────────────────────

def derive_privilege_level(privilege_tier):
    """Derive privilege level from numeric tier.

    Returns Title Case string: Highly Privileged | Privileged | Standard.
    """
    if privilege_tier == 0:
        return 'Highly Privileged'
    if privilege_tier == 1:
        return 'Privileged'
    return 'Standard'


# ── Aggregation ─────────────────────────────────────────────────────────────

def compute_governance_counts(rows, privilege_tier_key='privilege_tier'):
    """Iterate rows and return governance state counts using the canonical derivation.

    Parameters
    ----------
    rows : iterable of dict-like
        Each row must support .get() for the governance-relevant fields.
    privilege_tier_key : str
        Key to read privilege_tier from each row.

    Returns
    -------
    dict
        {
            'Orphaned': int,
            'Policy Violation': int,
            'Ungoverned': int,
            'Governed': int,
            'total': int,
            'ungoverned_pct': float,
        }
    """
    counts = {s: 0 for s in GOVERNANCE_STATES}
    total = 0

    for row in rows:
        raw = row.get(privilege_tier_key) if hasattr(row, 'get') else None
        tier = _resolve_privilege_tier_int(raw)
        state = derive_governance_state(row, tier)
        counts[state] = counts.get(state, 0) + 1
        total += 1

    ungoverned_total = counts['Orphaned'] + counts['Policy Violation'] + counts['Ungoverned']
    counts['total'] = total
    counts['ungoverned_pct'] = round((ungoverned_total / total) * 100, 1) if total > 0 else 0.0

    return counts


# ── Multi-source Last Seen ──────────────────────────────────────────────────

def resolve_last_seen_multisource(row):
    """Return the best available last-seen signal across all sources.

    Never returns "Never Used" if any activity signal exists.

    Returns dict with keys: display, source, available, confidence.
    """
    def _to_dt(v):
        if not v:
            return None
        if isinstance(v, datetime):
            return v
        try:
            return datetime.fromisoformat(str(v).replace('Z', '+00:00'))
        except Exception:
            return None

    sources = []

    # Source 1: Direct AAD sign-in (often None without premium license)
    for field in ('last_sign_in', 'last_sign_in_datetime'):
        val = row.get(field) if hasattr(row, 'get') else None
        dt = _to_dt(val)
        if dt:
            sources.append(('AAD sign-in', dt, 'high'))
            break

    # Source 2: AuditGraph observed activity
    for field in ('last_activity_date', 'last_seen_auth', 'observed_last_used'):
        val = row.get(field) if hasattr(row, 'get') else None
        dt = _to_dt(val)
        if dt:
            sources.append(('AuditGraph observed', dt, 'high'))
            break

    # Source 3: Non-interactive sign-in
    val = row.get('last_noninteractive_signin') if hasattr(row, 'get') else None
    dt = _to_dt(val)
    if dt:
        sources.append(('Non-interactive sign-in', dt, 'high'))

    # Source 4: ARM deployment / resource write activity
    for field in ('last_observed_ip_date', 'last_arm_activity', 'last_deployment_date'):
        val = row.get(field) if hasattr(row, 'get') else None
        dt = _to_dt(val)
        if dt:
            sources.append(('ARM activity', dt, 'inferred'))
            break

    # Source 5: Lineage behavioral signal
    for field in ('lineage_last_seen', 'last_lineage_event'):
        val = row.get(field) if hasattr(row, 'get') else None
        dt = _to_dt(val)
        if dt:
            sources.append(('Lineage activity', dt, 'inferred'))
            break

    if not sources:
        return {
            'display': None,
            'source': 'No activity signal available',
            'available': False,
            'confidence': None,
        }

    # Pick the most recent signal
    best_label, best_dt, best_conf = max(sources, key=lambda x: x[1])
    now = datetime.now(timezone.utc)
    # Ensure best_dt is timezone-aware
    if best_dt.tzinfo is None:
        best_dt = best_dt.replace(tzinfo=timezone.utc)
    days = (now - best_dt).days

    if days == 0:
        display = 'Today'
    elif days == 1:
        display = 'Yesterday'
    elif days < 30:
        display = f'{days} days ago'
    else:
        display = best_dt.strftime('%b %d, %Y')

    return {
        'display': display,
        'source': best_label,
        'available': True,
        'confidence': best_conf,
        'timestamp': best_dt.isoformat(),
    }


# ── Remediation Actions ────────────────────────────────────────────────────

def derive_remediation_actions(governance_state, privilege_level, lifecycle_state,
                               has_mfa=False, has_credentials_expiring=False,
                               attack_path_count=0, sensitive_access_count=0):
    """Derive ordered remediation actions from identity governance state.

    Returns list of dicts sorted by priority (P0 first).
    """
    actions = []

    if governance_state == 'Orphaned':
        actions.append({
            'priority': 'P0', 'impact': 'High',
            'action': 'Assign an owner',
            'reason': 'No owner is assigned. This identity has no accountability.',
            'framework': 'ISO 27001', 'effort': 'Quick win',
        })

    if governance_state in ('Orphaned', 'Ungoverned') and privilege_level in ('Privileged', 'Highly Privileged'):
        actions.append({
            'priority': 'P0', 'impact': 'High',
            'action': 'Review and reduce privilege scope',
            'reason': f'Identity is {governance_state.lower()} with {privilege_level.lower()} access. Unmonitored privilege is the highest-risk combination.',
            'framework': 'CIS Controls v8', 'effort': 'Medium',
        })

    if governance_state == 'Policy Violation':
        actions.append({
            'priority': 'P0', 'impact': 'Critical',
            'action': 'Resolve active policy breach',
            'reason': 'A confirmed policy violation is active on this identity.',
            'framework': 'SOC 2', 'effort': 'Immediate',
        })

    if lifecycle_state == 'Dormant':
        actions.append({
            'priority': 'P1', 'impact': 'Medium',
            'action': 'Disable or remove identity',
            'reason': 'No recent activity detected. Dormant identities with live roles are unnecessary exposure.',
            'framework': 'NIST SP 800-207', 'effort': 'Quick win',
        })

    if not has_mfa and privilege_level in ('Privileged', 'Highly Privileged'):
        actions.append({
            'priority': 'P1', 'impact': 'High',
            'action': 'Enforce MFA',
            'reason': 'Privileged identity without MFA is a critical authentication gap.',
            'framework': 'NIST SP 800-63B', 'effort': 'Quick win',
        })

    if has_credentials_expiring:
        actions.append({
            'priority': 'P1', 'impact': 'Medium',
            'action': 'Rotate expiring credentials',
            'reason': 'One or more credentials are approaching expiry.',
            'framework': 'CIS Controls v8', 'effort': 'Quick win',
        })

    if attack_path_count > 0:
        actions.append({
            'priority': 'P1', 'impact': 'High',
            'action': f'Investigate {attack_path_count} active attack path{"s" if attack_path_count > 1 else ""}',
            'reason': 'This identity is part of a confirmed privilege escalation or lateral movement path.',
            'framework': 'MITRE ATT&CK', 'effort': 'Medium',
        })

    if sensitive_access_count > 0 and governance_state in ('Orphaned', 'Ungoverned'):
        actions.append({
            'priority': 'P1', 'impact': 'High',
            'action': 'Review sensitive resource access',
            'reason': f'Identity can reach {sensitive_access_count} sensitive resource(s) without active governance.',
            'framework': 'SOC 2', 'effort': 'Medium',
        })

    if not actions:
        actions.append({
            'priority': 'P2', 'impact': 'Low',
            'action': 'No immediate remediation required',
            'reason': 'This identity meets current governance requirements.',
            'framework': None, 'effort': None,
        })

    return sorted(actions, key=lambda x: x['priority'])


# ── Sensitive Access from Roles ─────────────────────────────────────────────

SENSITIVE_ROLE_PATTERNS = [
    ('Owner', 'Full control — read, write, delete, manage access', 'High'),
    ('User Access Administrator', 'Can grant any permission to any identity', 'High'),
    ('Key Vault', 'Can access secrets, keys, and certificates', 'High'),
    ('Contributor', 'Read and write access to all resource types', 'Medium'),
    ('Storage Blob Data', 'Can read/write blob storage data — potential PII/PHI exposure', 'Medium'),
    ('SQL', 'Can read or write database contents', 'Medium'),
    ('Cognitive Services', 'Can access AI training data and outputs', 'Medium'),
    ('Backup', 'Can access backup data including encrypted snapshots', 'Medium'),
]


def derive_sensitive_access_from_roles(roles):
    """Derive sensitive access entries from RBAC role assignments.

    Does not require a pre-classified resource inventory.
    Returns list of sensitive access dicts.
    """
    sensitive = []
    for role in roles:
        role_name = role.get('role_name', '') or role.get('display_name', '') or ''
        scope = role.get('scope', '') or ''
        for pattern, description, sensitivity in SENSITIVE_ROLE_PATTERNS:
            if pattern.lower() in role_name.lower():
                sensitive.append({
                    'role': role_name,
                    'scope': scope,
                    'description': description,
                    'sensitivity': sensitivity,
                })
                break
    return sensitive


# ── Canonical Identity State Engine ───────────────────────────────────────

def _resolve_owner_count_from_row(row):
    """Extract owner count from row, falling back to owners list length."""
    if hasattr(row, 'get'):
        count = row.get('owner_count')
        if count is not None:
            return int(count)
        owners = row.get('owners') or []
        return len(owners) if isinstance(owners, list) else 0
    return 0


def _normalize_role_key(name: str) -> str:
    """
    Canonical key for the role_usage dict.
    Must match exactly what the frontend uses for lookup.
    Rule: lowercase, stripped. Applied at both write and read.
    """
    return (name or "").strip().lower()


# Lowercase variant for case-insensitive set membership.
_GRAPH_ACTIVITY_IMPLIES_USAGE_LOWER = frozenset(
    _normalize_role_key(r) for r in GRAPH_ACTIVITY_IMPLIES_USAGE
)


def infer_role_usage(roles, auth_activity):
    """Infer per-role usage from the canonical classification model.

    This function is a *consumer* of ``role_usage_classification`` set by
    the handler enrichment loop — it does NOT compute its own classification.
    When ``role_usage_classification`` is present, it is authoritative.

    When called in a legacy path where the handler has not yet enriched the
    roles, it falls back to a conservative heuristic that respects the 90-day
    observation window and never blanket-credits identity-level activity to
    individual roles.

    Role-name keys are normalized via ``_normalize_role_key`` — the frontend
    must apply the same normalization at lookup time.

    Parameters
    ----------
    roles : list[dict]
        Role assignments (each must have role_name + last_used_at + scope).
    auth_activity : dict
        Activity breakdown from build_identity_state.

    Returns
    -------
    dict[str, dict]
        ``{normalized_role_name: {used: bool, confidence: str, evidence: str}}``
    """
    identity_active = auth_activity.get('any_activity_observed', False)
    _OBSERVATION_WINDOW_DAYS = 90

    # Determine identity-level activity source for context (not for attribution)
    _identity_signal = None
    if auth_activity.get('interactive_signin'):
        _identity_signal = 'Interactive sign-in observed'
    elif auth_activity.get('arm_activity'):
        _identity_signal = 'ARM activity observed'
    elif auth_activity.get('non_interactive_signin'):
        _identity_signal = 'Non-interactive sign-in observed'
    elif auth_activity.get('auditgraph_scan'):
        _identity_signal = 'AuditGraph scan observation'
    elif auth_activity.get('lineage_activity'):
        _identity_signal = 'Lineage activity observed'
    elif auth_activity.get('token_usage'):
        _identity_signal = 'Token activity observed'

    now = datetime.now(timezone.utc)

    results = {}
    for role in (roles or []):
        role_name_raw = (
            role.get('role_name')
            or role.get('display_name')
            or role.get('name')
            or ''
        )
        role_name = _normalize_role_key(role_name_raw)
        if not role_name:
            continue

        # Authoritative: use handler-computed classification if available
        classification = role.get('role_usage_classification', '')

        if classification == 'proven':
            results[role_name] = {
                'used': True,
                'confidence': 'high',
                'evidence': 'Role-scoped ARM activity confirmed (proven)',
            }
        elif classification == 'likely':
            results[role_name] = {
                'used': True,
                'confidence': 'medium',
                'evidence': 'Role-scoped activity detected but overlapping roles prevent deterministic attribution',
            }
        elif classification in ('unknown', 'no_observed_usage',
                                'telemetry_blind', 'insufficient_coverage'):
            # Handler already classified — respect it
            results[role_name] = {
                'used': False,
                'confidence': 'none',
                'evidence': {
                    'unknown': f'Identity active ({_identity_signal}) but no role-specific evidence',
                    'no_observed_usage': 'No activity signal within observation window',
                    'telemetry_blind': 'No telemetry connectors — cannot determine usage',
                    'insufficient_coverage': 'Coverage data unavailable',
                }.get(classification, 'No activity signal correlated to this role'),
            }
        else:
            # Legacy fallback: classification not set by handler.
            # Respect observation window for P1 — stale P1 is NOT proof.
            p1 = role.get('last_used_at')
            _p1_recent = False
            if p1:
                try:
                    if isinstance(p1, datetime):
                        _p1_recent = (now - p1).days <= _OBSERVATION_WINDOW_DAYS
                    elif isinstance(p1, str):
                        dt = datetime.fromisoformat(p1.replace('Z', '+00:00'))
                        _p1_recent = (now - dt).days <= _OBSERVATION_WINDOW_DAYS
                except Exception:
                    pass

            if _p1_recent:
                results[role_name] = {
                    'used': True,
                    'confidence': 'medium',
                    'evidence': 'Role-level activity record (within window)',
                }
            elif identity_active:
                results[role_name] = {
                    'used': False,
                    'confidence': 'none',
                    'evidence': f'Identity active ({_identity_signal}) but no role-specific evidence',
                }
            else:
                results[role_name] = {
                    'used': False,
                    'confidence': 'none',
                    'evidence': 'No activity signal correlated to this role',
                }
    return results


def build_identity_state(row, roles=None, attack_path_count=0):
    """Canonical identity state object.

    All Identity Details tabs consume this.  No tab computes independently.

    Parameters
    ----------
    row : dict-like
        Identity row with all available fields.
    roles : list[dict] | None
        RBAC role assignments for sensitive-access derivation.
    attack_path_count : int
        Pre-counted attack paths for this identity.

    Returns
    -------
    dict
        Unified state consumed by every Identity Details tab.
    """
    roles = roles or []

    # --- Privilege tier (int) ---
    _priv_raw = row.get('privilege_tier') if hasattr(row, 'get') else None
    _priv_tier_int = _resolve_privilege_tier_int(_priv_raw)

    # --- Activity resolution (multi-source) ---
    last_seen_info = resolve_last_seen_multisource(row)

    # Compute days since last seen for dormancy check
    _days = None
    if last_seen_info['available'] and last_seen_info['display']:
        disp = last_seen_info['display']
        if disp == 'Today':
            _days = 0
        elif disp == 'Yesterday':
            _days = 1
        elif disp.endswith(' days ago'):
            try:
                _days = int(disp.split()[0])
            except (ValueError, IndexError):
                _days = None

    # --- Auth activity breakdown ---
    def _has(field):
        return bool(row.get(field) if hasattr(row, 'get') else None)

    # AuditGraph scan signal: connector SPN authenticates during every scan.
    # Triggered when observed_last_used is set OR last_activity_source is 'auditgraph_scan'.
    _last_activity_source = (row.get('last_activity_source') or '') if hasattr(row, 'get') else ''
    auditgraph_scan_observed = (
        _has('observed_last_used')
        or str(_last_activity_source).lower() == 'auditgraph_scan'
    )

    # ARM role-assignment inference: if activity_status was set to
    # 'likely_active' by the discovery engine (e.g. recent role assignments),
    # treat that as an ARM activity signal even without raw date fields.
    _raw_status = (row.get('activity_status') or 'unknown').lower() if hasattr(row, 'get') else 'unknown'
    _arm_from_status = _raw_status in ('likely_active', 'active', 'recently_created')

    auth_activity = {
        'interactive_signin': _has('last_sign_in') or _has('last_sign_in_datetime'),
        'non_interactive_signin': _has('last_noninteractive_signin'),
        'arm_activity': _has('last_observed_ip_date') or _has('last_arm_activity') or _has('last_deployment_date') or _arm_from_status,
        'token_usage': _has('last_token_issued') or _has('last_oidc_token'),
        'lineage_activity': _has('lineage_last_seen') or _has('last_lineage_event'),
        'auditgraph_scan': auditgraph_scan_observed,
        'confidence': last_seen_info.get('confidence') or ('low' if _arm_from_status else ('medium' if _raw_status != 'unknown' else 'none')),
    }
    auth_activity['any_activity_observed'] = any([
        auth_activity['interactive_signin'],
        auth_activity['non_interactive_signin'],
        auth_activity['arm_activity'],
        auth_activity['token_usage'],
        auth_activity['lineage_activity'],
        auth_activity['auditgraph_scan'],
    ])

    # --- Activity label ---
    if auth_activity['any_activity_observed']:
        _disp = last_seen_info.get('display') or ''
        _src = last_seen_info.get('source') or ''
        if auth_activity['interactive_signin']:
            activity_label = 'Active'
            activity_detail = f'Last active {_disp} via sign-in'
        elif auth_activity['arm_activity']:
            activity_label = 'Active'
            activity_detail = f'Last active {_disp} via ARM activity'
        elif auth_activity['non_interactive_signin']:
            activity_label = 'Active'
            activity_detail = f'Last active {_disp} via non-interactive sign-in'
        elif auth_activity['token_usage']:
            activity_label = 'Active'
            activity_detail = f'Last active {_disp} via token issuance'
        elif auth_activity['lineage_activity']:
            activity_label = 'Active'
            activity_detail = f'Last active {_disp} via lineage signal'
        elif auth_activity['auditgraph_scan']:
            activity_label = 'Active'
            activity_detail = f'Last active {_disp} via AuditGraph scan'
        else:
            activity_label = 'Active (inferred)'
            activity_detail = f'Last active {_disp}'
    else:
        # Map from DB activity_status when no telemetry signals are available
        if _raw_status == 'never_used':
            activity_label = 'Never Used'
            activity_detail = 'No ARM activity, no credentials used, no role changes observed.'
        elif _raw_status == 'recently_created':
            activity_label = 'Recently Created'
            activity_detail = 'Created within 30 days — insufficient history for activity inference.'
        elif _raw_status == 'stale':
            activity_label = 'Stale'
            activity_detail = 'No recent ARM or credential activity detected via static analysis.'
        else:
            activity_label = 'Not Observed'
            activity_detail = 'No ARM deployment, credential, or lineage activity detected via static analysis.'

    # --- Lifecycle state (override dormant when any signal exists) ---
    enabled_val = bool(row.get('enabled', True)) if hasattr(row, 'get') else True
    raw_activity_status = (row.get('activity_status') or 'unknown') if hasattr(row, 'get') else 'unknown'
    lifecycle_state = derive_lifecycle_state(enabled_val, raw_activity_status)
    if lifecycle_state == 'Dormant' and auth_activity['any_activity_observed']:
        lifecycle_state = 'Active'

    # --- Is dormant ---
    is_dormant = lifecycle_state == 'Dormant' or (
        lifecycle_state == 'Disabled' and not auth_activity['any_activity_observed']
    )

    # --- Governance state ---
    governance_state = derive_governance_state(row, _priv_tier_int)

    # --- Privilege level ---
    privilege_level = derive_privilege_level(_priv_tier_int)

    # --- Risk score (normalize >100 to 0-100) ---
    raw_score = int(row.get('risk_score') or 0) if hasattr(row, 'get') else 0
    risk_score = min(raw_score, 100)
    if risk_score >= 90:
        risk_label = 'Critical'
    elif risk_score >= 70:
        risk_label = 'High'
    elif risk_score >= 40:
        risk_label = 'Medium'
    else:
        risk_label = 'Low'

    # --- Remediation actions ---
    sensitive_access = derive_sensitive_access_from_roles(roles)
    has_cred_expiring = bool(row.get('credential_expiration') if hasattr(row, 'get') else False)
    remediation_actions = derive_remediation_actions(
        governance_state=governance_state,
        privilege_level=privilege_level,
        lifecycle_state=lifecycle_state,
        has_mfa=bool(row.get('ca_mfa_enforced', False) if hasattr(row, 'get') else False),
        has_credentials_expiring=has_cred_expiring,
        attack_path_count=attack_path_count,
        sensitive_access_count=len(sensitive_access),
    )

    return {
        # Activity signals
        'last_seen': last_seen_info['display'],
        'last_seen_display': last_seen_info['display'],
        'last_seen_source': last_seen_info['source'],
        'last_seen_available': last_seen_info['available'],
        'last_seen_confidence': last_seen_info['confidence'],
        'last_seen_timestamp': last_seen_info.get('timestamp'),
        'activity_label': activity_label,
        'activity_detail': activity_detail,
        'auth_activity': auth_activity,
        'is_dormant': is_dormant,

        # Core state dimensions
        'lifecycle_state': lifecycle_state,
        'governance_state': governance_state,
        'privilege_level': privilege_level,

        # Risk
        'risk_score': risk_score,
        'risk_label': risk_label,

        # Derived content
        'remediation_actions': remediation_actions,
        'sensitive_access': sensitive_access,
        'role_usage': infer_role_usage(roles, auth_activity),
    }
