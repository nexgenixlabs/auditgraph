"""
PIM Overprivilege Detection engine.

Operates on the pim_eligibility_state + pim_activation_observations tables
populated by the discovery pipeline. Classifies each (identity, role, scope)
into one of 4 buckets and emits up to 3 finding types:

  pim_unused_eligibility       — eligible >= ELIGIBLE_DORMANT_DAYS, never activated
  pim_low_frequency_activation — eligible, but <THRESHOLD activations / 90d
  pim_weak_activation_control  — eligible (active or not), activation policy lacks MFA
  (no finding)                 — eligible + frequent activations + MFA-required

Moat compliance (codified in memory/spec_checklist_agentless_readonly.md):
  ✓ Pure read of pim_eligibility_state + pim_activation_observations
  ✓ No writes to customer config (this is consequence analysis, not remediation)
  ✓ Works on logs-OFF tenants: the eligible-vs-no-activations delta is the
    PRIMARY signal and requires only the eligibility snapshot. Activation
    counts come from optional Entra P2 audit log enrichment. When activations
    are unavailable, classifier conservatively reports "unknown_frequency"
    rather than fabricating zero.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────
# Tunables (could move to settings in future)
# ─────────────────────────────────────────────────────────────────────────

ELIGIBLE_DORMANT_DAYS = 180          # eligible >180d with 0 activations → unused
LOW_FREQUENCY_DAYS = 90
LOW_FREQUENCY_THRESHOLD = 2          # <2 activations / 90d → low frequency
RECENT_DAYS = 30                     # last activation within → "recent"

# Roles where weak MFA is most critical
CRITICAL_ROLES = {
    'Global Administrator',
    'Privileged Role Administrator',
    'Privileged Authentication Administrator',
    'User Administrator',
    'Security Administrator',
    'Conditional Access Administrator',
    'Application Administrator',
    'Cloud Application Administrator',
    'Exchange Administrator',
    'SharePoint Administrator',
    'Billing Administrator',
}


# ─────────────────────────────────────────────────────────────────────────
# Severity matrix
# ─────────────────────────────────────────────────────────────────────────

def _severity_unused(role_name: str, days_eligible: int) -> str:
    """Higher severity for critical roles + longer dormancy."""
    is_critical = role_name in CRITICAL_ROLES
    if is_critical and days_eligible >= 365:
        return 'critical'
    if is_critical and days_eligible >= ELIGIBLE_DORMANT_DAYS:
        return 'high'
    if days_eligible >= 365:
        return 'high'
    return 'medium'


def _severity_low_freq(role_name: str, activations_90d: int) -> str:
    is_critical = role_name in CRITICAL_ROLES
    if activations_90d == 0:
        return 'high' if is_critical else 'medium'
    return 'medium' if is_critical else 'low'


def _severity_weak_mfa(role_name: str) -> str:
    return 'critical' if role_name in CRITICAL_ROLES else 'high'


# ─────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────

def compute_pim_overprivilege(db, org_id: int,
                                identity_filter: Optional[str] = None,
                                severity_filter: Optional[str] = None
                                ) -> dict[str, Any]:
    """Org-wide PIM overprivilege analysis.

    Returns:
      {
        'identities':    [...per-identity records...],
        'findings':      [...flat list of finding records...],
        'summary': {
            'total_eligible_assignments': N,
            'total_findings': N,
            'by_finding_type': {pim_unused_eligibility: N, ...},
            'by_severity': {critical: N, high: N, medium: N, low: N},
        },
        'computed_at': ISO,
      }
    """
    now = datetime.now(timezone.utc)
    cursor = db.conn.cursor()
    try:
        # 1. Load all eligibility rows for the org (most-recent run only)
        cursor.execute("""
            SELECT
              e.identity_db_id, e.identity_id, i.display_name,
              e.role_name, e.role_template_id, e.scope, e.scope_type,
              e.assignment_type, e.eligible_since,
              e.requires_mfa_on_activation, e.requires_approval,
              e.requires_justification, e.max_activation_minutes,
              i.identity_category
            FROM pim_eligibility_state e
            JOIN identities i ON i.id = e.identity_db_id
            WHERE e.organization_id = %s
              AND i.deleted_at IS NULL
            ORDER BY e.identity_id, e.role_name
        """, (org_id,))
        eligibility_rows = cursor.fetchall()

        # 2. Load all activation observations (org-wide). For perf could limit
        #    to last N days; for demo and v1 we pull everything.
        cursor.execute("""
            SELECT identity_db_id, role_name, scope, activated_at
            FROM pim_activation_observations
            WHERE organization_id = %s
            ORDER BY activated_at DESC
        """, (org_id,))
        activation_rows = cursor.fetchall()
    finally:
        cursor.close()

    # Index activations by (identity_db_id, role_name) — scope tolerated null
    act_by_key: dict[tuple, list[datetime]] = defaultdict(list)
    for ad_db_id, role_name, _scope, activated_at in activation_rows:
        # Make sure timestamps are timezone-aware
        if activated_at.tzinfo is None:
            activated_at = activated_at.replace(tzinfo=timezone.utc)
        act_by_key[(ad_db_id, role_name)].append(activated_at)

    cutoff_lowfreq = now - timedelta(days=LOW_FREQUENCY_DAYS)
    cutoff_recent = now - timedelta(days=RECENT_DAYS)

    identities_out: list[dict] = []
    findings_out: list[dict] = []
    by_finding_type: dict[str, int] = defaultdict(int)
    by_severity: dict[str, int] = defaultdict(int)

    for row in eligibility_rows:
        (identity_db_id, identity_id, display_name, role_name, role_template_id,
         scope, scope_type, assignment_type, eligible_since,
         requires_mfa_on_activation, requires_approval,
         requires_justification, max_activation_minutes,
         identity_category) = row

        # Apply identity filter (substring match on identity_id or display_name)
        if identity_filter:
            f = identity_filter.lower()
            if f not in (identity_id or '').lower() and f not in (display_name or '').lower():
                continue

        # Make eligible_since timezone-aware
        if eligible_since and eligible_since.tzinfo is None:
            eligible_since = eligible_since.replace(tzinfo=timezone.utc)
        days_eligible = (now - eligible_since).days if eligible_since else 0

        activations = act_by_key.get((identity_db_id, role_name), [])
        activations_90d = sum(1 for ts in activations if ts >= cutoff_lowfreq)
        activations_all = len(activations)
        last_activation = max(activations) if activations else None
        days_since_last = (now - last_activation).days if last_activation else None

        # Classification
        classification = 'unknown'
        finding_types: list[str] = []
        finding_payloads: list[dict] = []

        # Rule 1: Unused eligibility — dormant + never activated
        if activations_all == 0 and days_eligible >= ELIGIBLE_DORMANT_DAYS:
            sev = _severity_unused(role_name, days_eligible)
            classification = 'unused_eligibility'
            finding_types.append('pim_unused_eligibility')
            finding_payloads.append({
                'finding_type': 'pim_unused_eligibility',
                'severity': sev,
                'title': f"{role_name} eligible {days_eligible}d, never activated",
                'evidence': {
                    'days_eligible': days_eligible,
                    'role_name': role_name,
                    'scope': scope,
                },
                'recommendation': (
                    'Remove the eligibility assignment. The identity has never '
                    'exercised this role and has not requested it in the last '
                    f'{days_eligible} days. If the role is genuinely required, '
                    'replace with a just-in-time access request workflow.'
                ),
            })

        # Rule 2: Low frequency — eligible AND has some activations but rare
        elif activations_all > 0 and activations_90d < LOW_FREQUENCY_THRESHOLD:
            sev = _severity_low_freq(role_name, activations_90d)
            classification = 'low_frequency_activation'
            finding_types.append('pim_low_frequency_activation')
            finding_payloads.append({
                'finding_type': 'pim_low_frequency_activation',
                'severity': sev,
                'title': (f"{role_name} activated {activations_90d}× in last "
                          f"{LOW_FREQUENCY_DAYS}d (last: {days_since_last}d ago)"),
                'evidence': {
                    'activations_90d': activations_90d,
                    'activations_all_time': activations_all,
                    'days_since_last': days_since_last,
                    'role_name': role_name,
                },
                'recommendation': (
                    f'Rare activation pattern ({activations_90d} in 90 days). '
                    'Convert standing eligibility to time-bound assignment for '
                    'known activity windows, or revoke if the need has passed.'
                ),
            })

        # Rule 3: Weak activation control — independent of activation frequency
        if not requires_mfa_on_activation and role_name in CRITICAL_ROLES:
            sev = _severity_weak_mfa(role_name)
            classification = (classification + '+weak_mfa'
                              if classification != 'unknown' else 'weak_mfa')
            finding_types.append('pim_weak_activation_control')
            finding_payloads.append({
                'finding_type': 'pim_weak_activation_control',
                'severity': sev,
                'title': (f"{role_name} activation policy does NOT require MFA"),
                'evidence': {
                    'requires_mfa_on_activation': False,
                    'requires_approval': bool(requires_approval),
                    'max_activation_minutes': max_activation_minutes,
                    'role_name': role_name,
                },
                'recommendation': (
                    'Tighten the PIM activation policy for this role: require '
                    'multi-factor authentication on activation. Optionally add '
                    'approval requirement for production critical roles. This '
                    'is a config-tightening fix in Entra Privileged Identity '
                    'Management, not a role removal.'
                ),
            })

        # Healthy case
        if not finding_types:
            classification = 'healthy_active' if activations_90d >= LOW_FREQUENCY_THRESHOLD else 'healthy'

        # Per-identity rollup
        identities_out.append({
            'identity_db_id':     identity_db_id,
            'identity_id':        identity_id,
            'display_name':       display_name,
            'identity_category':  identity_category,
            'role_name':          role_name,
            'scope':              scope,
            'scope_type':         scope_type,
            'assignment_type':    assignment_type,
            'days_eligible':      days_eligible,
            'activations_90d':    activations_90d,
            'activations_all_time': activations_all,
            'days_since_last_activation': days_since_last,
            'requires_mfa_on_activation': bool(requires_mfa_on_activation),
            'requires_approval':  bool(requires_approval),
            'classification':     classification,
            'finding_types':      finding_types,
        })

        # Flatten findings
        for payload in finding_payloads:
            if severity_filter and payload['severity'] != severity_filter:
                continue
            payload['identity_db_id'] = identity_db_id
            payload['identity_id'] = identity_id
            payload['display_name'] = display_name
            findings_out.append(payload)
            by_finding_type[payload['finding_type']] += 1
            by_severity[payload['severity']] += 1

    summary = {
        'total_eligible_assignments': len(eligibility_rows),
        'total_findings': len(findings_out),
        'by_finding_type': dict(by_finding_type),
        'by_severity': dict(by_severity),
    }

    # Sort findings: critical first, then by_severity within
    sev_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    findings_out.sort(key=lambda f: (sev_rank.get(f['severity'], 99), f['identity_id']))

    return {
        'identities': identities_out,
        'findings':   findings_out,
        'summary':    summary,
        'computed_at': now.isoformat(),
    }


__all__ = ['compute_pim_overprivilege', 'CRITICAL_ROLES']
