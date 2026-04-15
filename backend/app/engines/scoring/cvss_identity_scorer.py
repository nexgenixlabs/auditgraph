"""
CVSSIdentityScorer — 5-dimension identity risk scoring engine.

Standards alignment:
  - NIST SP 800-63B    (dormancy thresholds)
  - NIST SP 800-207    (blast radius, least privilege)
  - CIS Controls v8    (governance §5.3, credential hygiene §5.2)
  - CVSS v3.1          (severity band naming, max-based composition)
  - MITRE ATT&CK v14   (technique mapping per dimension)

All score methods are pure functions — no side effects, no external API calls.
Inputs come from identity_list, identity_role_assignments,
identity_credentials, identity_owners, and identity_activity tables.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── CVSS Severity Bands ─────────────────────────────────────────────

def cvss_band(score: float) -> str:
    """Map a 0–10 score to a CVSS v3.1 severity label."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def _clamp(val: float) -> float:
    return max(0.0, min(10.0, val))


# ── Privileged role lookup tables ────────────────────────────────────

# Exact-match role names → score  (case-insensitive matching applied at call site)
_ROLE_SCORE_EXACT: Dict[str, float] = {
    "user access administrator": 9.5,
    "global administrator":      9.5,
    "privileged role administrator": 9.5,
    "owner":                     9.0,
    "contributor":               7.0,
    "application administrator": 7.5,
    "cloud application administrator": 7.5,
    "user administrator":        7.0,
    "security administrator":    7.0,
    "exchange administrator":    6.5,
    "sharepoint administrator":  6.5,
    "key vault administrator":   6.5,
    "key vault secrets officer":  6.5,
    "key vault crypto officer":   6.5,
    "storage blob data owner":   6.5,
    "storage blob data contributor": 5.0,
    "network contributor":       5.0,
    "virtual machine contributor": 5.0,
    "sql db contributor":        5.0,
    "sql server contributor":    5.0,
}

# Role name substring patterns → score (tried after exact match fails)
_ROLE_SCORE_PATTERNS: List[tuple] = [
    ("owner", 6.0),
    ("contributor", 5.0),
    ("administrator", 5.5),
    ("data contributor", 5.0),
    ("data owner", 6.0),
    ("writer", 4.0),
    ("operator", 3.5),
    ("reader", 2.0),
]

# Scope level in role assignments → blast radius score
_SCOPE_SCORE: Dict[str, float] = {
    "tenant_wide":       10.0,
    "management_group":  10.0,
    "managementgroup":   10.0,
    "subscription":      8.5,
    "resource_group":    5.5,
    "resourcegroup":     5.5,
    "resource":          3.0,
}

# Environment tier multipliers
_ENV_MULTIPLIER: Dict[str, float] = {
    "production": 1.3,
    "corporate":  1.2,
    "ci_cd":      1.15,
    "platform":   1.1,
    "dev":        1.0,
    "unknown":    1.05,
}

# Credential rotation_status → score
_CRED_STATUS_SCORE: Dict[str, float] = {
    "expired":       8.0,
    "expiring_soon": 5.0,
    "current":       0.5,
    "no_credentials": 0.0,
}

# NHI identity types (non-human)
_NHI_TYPES = frozenset([
    "service_principal", "application", "managed_identity",
    "managed_identity_system", "managed_identity_user",
])


class CVSSIdentityScorer:
    """Compute per-identity CVSS-aligned risk scores from DB-resident data.

    Usage::

        scorer = CVSSIdentityScorer()
        result = scorer.score_identity(identity_row, roles, credentials, owners, activity)
        # result keys: severity_score, cvss_band, blast_radius_score,
        #              privilege_score, dormancy_score, governance_score,
        #              credential_score, env_multiplier, score_computed_at
    """

    # ── Dimension 1: Blast Radius ────────────────────────────────────
    # NIST SP 800-207 §2.1 — scope of compromise impact
    # MITRE: T1098.003

    def compute_blast_radius_score(
        self,
        roles: List[Dict[str, Any]],
        privilege_summary: Optional[Dict[str, Any]] = None,
    ) -> float:
        """Score based on widest scope × privilege impact across all role assignments.

        Blast radius is scope modulated by what the role can actually do.
        A Reader at subscription scope can only view — limited blast radius.
        An Owner at subscription scope can destroy everything.
        """
        if not roles:
            return 0.0

        max_scope = 0.0
        for role in roles:
            scope_level = (role.get("scope_level") or "resource").lower()
            base_scope = _SCOPE_SCORE.get(scope_level, 3.0)
            role_name = (role.get("role_name") or "").lower().strip()

            # Determine role impact factor (0.0 – 1.0)
            # Full-control roles get 1.0; read-only roles get a fraction
            if role_name in (
                "owner", "user access administrator",
                "user access admin", "global administrator",
                "privileged role administrator",
            ):
                impact = 1.0
            elif "contributor" in role_name or "administrator" in role_name:
                impact = 0.85
            elif "writer" in role_name or "operator" in role_name:
                impact = 0.6
            elif "reader" in role_name:
                impact = 0.3  # Read-only — can view but not modify/delete
            else:
                impact = 0.5  # Unknown role — moderate assumption

            scope_score = base_scope * impact

            # Boost: Owner/UAA at subscription = true tenant-wide danger
            if scope_level in ("subscription", "tenant_wide", "management_group") and impact >= 1.0:
                scope_score = max(scope_score, 9.5)

            max_scope = max(max_scope, scope_score)

        # Also consider blast_radius_resource_count from privilege summary
        if privilege_summary:
            rc = privilege_summary.get("blast_radius_resource_count", 0) or 0
            if rc >= 500:
                max_scope = max(max_scope, 9.0)
            elif rc >= 100:
                max_scope = max(max_scope, 7.0)
            elif rc >= 20:
                max_scope = max(max_scope, 5.0)

        return _clamp(max_scope)

    # ── Dimension 2: Privilege Exposure ──────────────────────────────
    # NIST SP 800-207 §3.3 — least privilege violation
    # MITRE: T1078.004

    def compute_privilege_score(self, roles: List[Dict[str, Any]]) -> float:
        """Score based on most dangerous role held."""
        if not roles:
            return 1.0  # No roles at all — still a minimal presence risk

        max_priv = 0.0
        for role in roles:
            role_name = (role.get("role_name") or "").lower().strip()

            # Try exact match first
            if role_name in _ROLE_SCORE_EXACT:
                max_priv = max(max_priv, _ROLE_SCORE_EXACT[role_name])
                continue

            # Try substring pattern match
            matched = False
            for pattern, score in _ROLE_SCORE_PATTERNS:
                if pattern in role_name:
                    max_priv = max(max_priv, score)
                    matched = True
                    break

            if not matched:
                # Unknown role — assume minimal risk
                max_priv = max(max_priv, 1.0)

        return _clamp(max_priv)

    # ── Dimension 3: Dormancy Risk ───────────────────────────────────
    # NIST SP 800-63B §4.1.3 — authentication currency
    # MITRE: T1078.001

    def compute_dormancy_score(
        self,
        identity: Dict[str, Any],
        activity: Optional[Dict[str, Any]] = None,
    ) -> float:
        """Score based on how recently the identity was active."""
        now = datetime.now(timezone.utc)

        # Resolve last activity date from multiple sources (waterfall)
        last_activity = None
        sources = [
            activity.get("last_sign_in_at") if activity else None,
            activity.get("last_activity_at") if activity else None,
            identity.get("last_seen"),
        ]
        for src in sources:
            if src is not None:
                if isinstance(src, str):
                    try:
                        last_activity = datetime.fromisoformat(
                            src.replace("Z", "+00:00")
                        )
                    except (ValueError, TypeError):
                        continue
                elif isinstance(src, datetime):
                    last_activity = src if src.tzinfo else src.replace(tzinfo=timezone.utc)
                if last_activity:
                    break

        if last_activity is None:
            return 8.0  # Never authenticated — high dormancy risk

        days = (now - last_activity).days

        if days > 365:
            return 9.0   # NIST: severely stale
        if days > 180:
            return 7.5
        if days > 90:
            return 6.0   # NIST 800-63B 90-day threshold
        if days > 30:
            return 3.0
        return 0.5        # Active within 30 days

    # ── Dimension 4: Governance Gaps ─────────────────────────────────
    # CIS Controls v8 Control 5.3 — account governance
    # MITRE: T1098.001

    def compute_governance_score(
        self,
        owners: List[Dict[str, Any]],
        privilege_level: str = "standard",
    ) -> float:
        """Score based on ownership and review status."""
        owner_count = len(owners) if owners else 0

        if owner_count == 0:
            # Unowned identity — severity depends on privilege level
            pl = (privilege_level or "standard").lower()
            if pl == "highly_privileged":
                return 9.5  # No accountability for highly privileged identity
            if pl == "privileged":
                return 6.0  # Privileged but unowned — moderate governance gap
            return 2.0      # Unowned but standard/no-privilege — low risk

        # Has owners — check review freshness
        now = datetime.now(timezone.utc)
        latest_review = None
        for owner in owners:
            review_at = owner.get("last_review_at")
            if review_at is not None:
                if isinstance(review_at, str):
                    try:
                        review_at = datetime.fromisoformat(
                            review_at.replace("Z", "+00:00")
                        )
                    except (ValueError, TypeError):
                        continue
                elif isinstance(review_at, datetime):
                    if not review_at.tzinfo:
                        review_at = review_at.replace(tzinfo=timezone.utc)
                else:
                    continue
                if latest_review is None or review_at > latest_review:
                    latest_review = review_at

        if latest_review is None:
            return 5.0  # Owned but never reviewed

        days_since_review = (now - latest_review).days
        if days_since_review > 90:
            return 3.0
        return 0.5  # Recently reviewed — low risk

    # ── Dimension 5: Credential Risk ─────────────────────────────────
    # CIS Controls v8 Control 5.2 — credential hygiene
    # MITRE: T1528

    def compute_credential_score(
        self,
        identity_type: str,
        credentials: List[Dict[str, Any]],
    ) -> float:
        """Score based on credential rotation status.

        Only applies to NHI (SPNs, App Registrations, MSIs).
        Human users return 0.0 — Entra ID handles their auth.
        """
        it = (identity_type or "").lower().replace(" ", "_")
        if it not in _NHI_TYPES and it not in ("spn", "app"):
            return 0.0  # Human identity — N/A

        if not credentials:
            return 0.0  # No credentials to evaluate

        # Use worst credential status
        max_score = 0.0
        for cred in credentials:
            status = (cred.get("rotation_status") or "current").lower()
            max_score = max(max_score, _CRED_STATUS_SCORE.get(status, 0.5))

        return _clamp(max_score)

    # ── Environment Multiplier ───────────────────────────────────────

    def compute_env_multiplier(
        self,
        env_tier: str,
        identity_type: str = "",
        privilege_score: float = 0.0,
    ) -> float:
        """Return environment context amplifier.

        Standard-privilege managed identities in production/corporate are
        routine automation — no amplification.  Only privileged managed
        identities or human users get the full environment weight.
        """
        tier = (env_tier or "unknown").lower()
        base = _ENV_MULTIPLIER.get(tier, 1.05)

        # Managed identities with standard privilege are expected in
        # production and should not be penalised for being there.
        it = (identity_type or "").lower().replace(" ", "_")
        is_managed = it in (
            "managed_identity", "managed_identity_system",
            "managed_identity_user",
        )
        if is_managed and privilege_score < 4.0:
            return 1.0

        return base

    # ── Final Score Composition ──────────────────────────────────────

    def score_identity(
        self,
        identity: Dict[str, Any],
        roles: List[Dict[str, Any]],
        credentials: List[Dict[str, Any]],
        owners: List[Dict[str, Any]],
        activity: Optional[Dict[str, Any]] = None,
        privilege_summary: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Compute all scoring fields for a single identity.

        Returns a dict with keys matching the identity_list columns
        added by migration 090.
        """
        blast = self.compute_blast_radius_score(roles, privilege_summary)
        priv = self.compute_privilege_score(roles)
        dormancy = self.compute_dormancy_score(identity, activity)
        gov = self.compute_governance_score(
            owners,
            privilege_level=identity.get("privilege_level", "standard"),
        )
        cred = self.compute_credential_score(
            identity.get("identity_type", ""),
            credentials,
        )
        env_mult = self.compute_env_multiplier(
            identity.get("env_tier", "unknown"),
            identity_type=identity.get("identity_type", ""),
            privilege_score=priv,
        )

        # ── Privilege-modulated composition ─────────────────────────
        # Threat dimensions (blast, privilege) measure actual danger.
        # Hygiene dimensions (dormancy, governance, credential) measure
        # poor practice.  A dormant Reader (priv<4) is concerning
        # (MEDIUM) but not CRITICAL — only privileged dormant identities
        # represent critical risk.
        threat = max(blast, priv)
        hygiene = max(dormancy, gov, cred)

        if threat >= 7.0:
            # Highly privileged — any hygiene gap IS critical
            base = max(threat, hygiene)
        elif threat >= 4.0:
            # Medium privilege — hygiene capped at HIGH
            base = max(threat, min(hygiene, 7.5))
        else:
            # Standard privilege — hygiene capped at upper-MEDIUM
            # A dormant Reader is concerning but NOT critical
            base = max(threat, min(hygiene, 5.5))

        final = _clamp(base * env_mult)

        return {
            "blast_radius_score": round(blast, 2),
            "privilege_score":    round(priv, 2),
            "dormancy_score":     round(dormancy, 2),
            "governance_score":   round(gov, 2),
            "credential_score":   round(cred, 2),
            "env_multiplier":     round(env_mult, 2),
            "severity_score":     round(final, 2),
            "cvss_band":          cvss_band(final),
            "score_computed_at":  datetime.now(timezone.utc),
        }
