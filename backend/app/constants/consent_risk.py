"""
AG-81: OAuth Consent Grant Risk Scoring

Scope-breadth + consent-type + age → CVSS-aligned risk score for consent grants.
Mirrors the ai_risk.py shape so the scoring stays consistent across the product.

Risk inputs:
  1. Scope breadth — which Graph / API scopes the app holds. Categorized into
     tiers by what an attacker who compromises the app could do.
  2. Consent type — AllPrincipals (admin-consented for whole tenant) vs
     Principal (single user) — admin consent is broader blast radius.
  3. Age + activity — long-lived grants with no recent activity = stale risk.

Output: severity (critical/high/medium/low) + CVSS-aligned 0-10 + structured
high_risk_scopes list for evidence/audit display.
"""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from typing import Optional


# ─── Scope tiers ───────────────────────────────────────────────────────
# Source: Microsoft Graph permissions reference + Vercel/Context.ai breach
# postmortem. Scopes ranked by what an attacker can do if they compromise
# the SP holding the grant.

# TIER 1 — full-tenant takeover potential
CRITICAL_SCOPES = frozenset({
    # Directory write — can grant any role
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Application.ReadWrite.OwnedBy",
    # Privileged ID
    "PrivilegedAccess.ReadWrite.AzureAD",
    "PrivilegedAccess.ReadWrite.AzureResources",
    # Access reviews + policy
    "Policy.ReadWrite.ConditionalAccess",
    "Policy.ReadWrite.AuthenticationMethod",
})

# TIER 2 — broad data exfil OR full directory read
HIGH_SCOPES = frozenset({
    # Mail
    "Mail.Read",
    "Mail.ReadWrite",
    "Mail.Send",
    "Mail.ReadBasic",
    "Mail.ReadWrite.Shared",
    # Files
    "Files.Read.All",
    "Files.ReadWrite.All",
    "Sites.Read.All",
    "Sites.ReadWrite.All",
    "Sites.FullControl.All",
    # Directory read (still big — full user/group enumeration)
    "Directory.Read.All",
    "Group.Read.All",
    "Group.ReadWrite.All",
    "GroupMember.ReadWrite.All",
    "User.ReadWrite.All",
    # OAuth + offline access
    "offline_access",
    # Calendar / contacts (PII)
    "Calendars.Read",
    "Calendars.ReadWrite",
    "Contacts.Read",
    "Contacts.ReadWrite",
    # Audit logs
    "AuditLog.Read.All",
    # Teams
    "TeamMember.ReadWrite.All",
    "ChannelMessage.Read.All",
    "Chat.Read.All",
    "ChatMessage.Read.All",
})

# TIER 3 — moderate read; per-user mailbox / file scope etc.
MEDIUM_SCOPES = frozenset({
    "User.Read.All",
    "User.ReadBasic.All",
    "Files.Read",
    "Files.ReadWrite",
    "Mail.ReadBasic",
    "Sites.Read",
    "openid",
    "profile",
    "email",
})

# Mention for completeness — everything else falls into 'low'.


# ─── Risk score computation ────────────────────────────────────────────

def categorize_scope(scope: str) -> str:
    """Return 'critical' | 'high' | 'medium' | 'low' for one scope."""
    s = (scope or '').strip()
    if not s:
        return 'low'
    if s in CRITICAL_SCOPES:
        return 'critical'
    if s in HIGH_SCOPES:
        return 'high'
    if s in MEDIUM_SCOPES:
        return 'medium'
    # Heuristic fallback for unknown scopes — anything ending in
    # .ReadWrite.All or .FullControl.All gets treated as high-risk by
    # default; .Read.All as medium. Bare .Read / .Send tail to low.
    sl = s.lower()
    if sl.endswith('.readwrite.all') or sl.endswith('.fullcontrol.all'):
        return 'high'
    if sl.endswith('.read.all'):
        return 'medium'
    return 'low'


def compute_consent_risk(
    *,
    scopes: list,
    consent_type: Optional[str] = None,
    grant_type: Optional[str] = None,
    created_datetime: Optional[datetime] = None,
    last_activity_at: Optional[datetime] = None,
    verified_publisher: Optional[bool] = None,
    publisher_name: Optional[str] = None,
) -> dict:
    """Compute CVSS-aligned risk for a single consent grant.

    Args:
      scopes: list of scope strings (e.g. ['Mail.Read', 'Files.ReadWrite.All'])
      consent_type: 'AllPrincipals' (admin, broader) or 'Principal' (single user)
      grant_type: 'application' (always admin) or 'delegated' (user/admin)
      created_datetime: when the grant was created
      last_activity_at: most recent observed sign-in for this client app
      verified_publisher: bool from MS Graph
        verifiedPublisher.isPublisherVerified. None = not enriched yet.
        Unverified + high-risk scope is the consent-phishing signature.
      publisher_name: publisher display name (used to recognize Microsoft
        and avoid double-counting trust).

    Returns: {
      'risk_score': int (0-10 × 10 for sort granularity),
      'risk_level': 'critical' | 'high' | 'medium' | 'low',
      'cvss': float (0.0-10.0),
      'high_risk_scopes': [scope, ...]  (subset that's high/critical),
      'age_days': int | None,
      'dormant': bool  (no activity in 90+ days),
      'publisher_trust': 'microsoft' | 'verified' | 'unverified' | 'unknown',
      'reasons': [str, ...]  (human-readable evidence lines),
    }
    """
    reasons: list[str] = []
    high_risk_scopes: list[str] = []
    max_tier = 'low'

    tier_rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}

    for s in (scopes or []):
        cat = categorize_scope(s)
        if tier_rank[cat] > tier_rank[max_tier]:
            max_tier = cat
        if cat in ('critical', 'high'):
            high_risk_scopes.append(s)

    # Base CVSS by tier of highest scope
    base = {'critical': 9.0, 'high': 7.0, 'medium': 4.5, 'low': 2.0}[max_tier]

    # Modifier: count of high-risk scopes (more = broader compromise surface)
    n_priv = len(high_risk_scopes)
    if n_priv >= 5:
        base += 0.8
        reasons.append(f"{n_priv} high-risk scopes (broad compromise surface)")
    elif n_priv >= 3:
        base += 0.5
        reasons.append(f"{n_priv} high-risk scopes")
    elif n_priv >= 1:
        base += 0.2

    # Modifier: admin consent (AllPrincipals OR application grant) =
    # whole-tenant blast radius.
    if (consent_type == 'AllPrincipals') or (grant_type == 'application'):
        base += 0.5
        if max_tier in ('critical', 'high'):
            reasons.append("Admin-consented (entire tenant)")

    # Modifier: offline_access amplifies refresh-token persistence — once
    # an attacker has refresh_token they can keep getting access tokens.
    if any((s or '').strip() == 'offline_access' for s in (scopes or [])):
        base += 0.3
        if max_tier != 'low':
            reasons.append("Includes offline_access (refresh-token persistence)")

    # Age + dormancy
    age_days = None
    dormant = False
    if created_datetime is not None:
        now = datetime.now(timezone.utc)
        try:
            ct = created_datetime if isinstance(created_datetime, datetime) else \
                 datetime.fromisoformat(str(created_datetime).replace('Z', '+00:00'))
            if ct.tzinfo is None:
                ct = ct.replace(tzinfo=timezone.utc)
            age_days = (now - ct).days
        except Exception:
            age_days = None

    if last_activity_at is not None:
        try:
            la = last_activity_at if isinstance(last_activity_at, datetime) else \
                 datetime.fromisoformat(str(last_activity_at).replace('Z', '+00:00'))
            if la.tzinfo is None:
                la = la.replace(tzinfo=timezone.utc)
            dormant = (datetime.now(timezone.utc) - la).days >= 90
        except Exception:
            pass
    elif age_days is not None and age_days >= 90:
        # No activity record AND grant is old — treat as dormant
        dormant = True

    if dormant and max_tier in ('critical', 'high'):
        base += 0.4
        reasons.append("Dormant — no observed activity in 90+ days, high-risk scope still active")

    # Publisher trust modifier — AG-85. MS Graph exposes
    # verifiedPublisher.isPublisherVerified on every Application/SP.
    # Microsoft-published apps are explicitly trusted (publisher_name
    # starts with "Microsoft"). Verified third parties get a small
    # trust bump. Unverified apps with high-risk scope match the
    # consent-phishing signature so we surcharge them.
    pname = (publisher_name or '').strip()
    pname_l = pname.lower()
    if pname and (pname_l == 'microsoft' or pname_l.startswith('microsoft ')):
        publisher_trust = 'microsoft'
        # Microsoft first-party — known and trusted, no modifier.
    elif verified_publisher is True:
        publisher_trust = 'verified'
        base -= 0.3
        if max_tier in ('critical', 'high'):
            reasons.append(f"Verified publisher: {pname or 'attested via MS Graph'}")
    elif verified_publisher is False:
        publisher_trust = 'unverified'
        if max_tier in ('critical', 'high'):
            base += 0.5
            reasons.append(
                "Unverified publisher with high-risk scope — consent-phishing signature"
            )
        else:
            base += 0.2
    else:
        publisher_trust = 'unknown'  # enrichment not yet run

    cvss = max(0.0, min(10.0, round(base, 1)))

    # Severity label follows CVSS 3.1 bands so the column stays auditor-defensible.
    if cvss >= 9.0:
        severity = 'critical'
    elif cvss >= 7.0:
        severity = 'high'
    elif cvss >= 4.0:
        severity = 'medium'
    else:
        severity = 'low'

    return {
        'risk_score': int(cvss * 10),       # 0-100 for sort granularity
        'risk_level': severity,
        'cvss': cvss,
        'high_risk_scopes': high_risk_scopes,
        'age_days': age_days,
        'dormant': dormant,
        'publisher_trust': publisher_trust,
        'reasons': reasons,
    }
