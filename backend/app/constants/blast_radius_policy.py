"""
Blast Radius / Reachability Policy Constants.

Centralizes all thresholds used for reachability risk flag computation.
Imported by the scheduler pipeline and the drill-down API handler.

To override per-tenant, store matching keys in the `settings` table
(key = threshold name, value = integer). The `get_thresholds()` helper
merges tenant overrides on top of defaults.
"""

# ═══════════════════════════════════════════════════════════════════
# Risk Flag Thresholds (defaults)
# ═══════════════════════════════════════════════════════════════════

# broad_blast_radius: identity can reach >= N resources
BROAD_BLAST_RADIUS_THRESHOLD = 50
BROAD_BLAST_RADIUS_CRITICAL_THRESHOLD = 100  # severity escalates to HIGH

# privileged_wide_reach: privileged role + >= N subscriptions
PRIVILEGED_WIDE_REACH_SUBSCRIPTION_THRESHOLD = 3
PRIVILEGED_WIDE_REACH_CRITICAL_SUBSCRIPTION_THRESHOLD = 5  # severity escalates to CRITICAL

# ai_excessive_blast: AI agent identity + >= N resources
AI_EXCESSIVE_BLAST_THRESHOLD = 20

# dormant_high_blast: dormant/inactive identity + >= N resources
DORMANT_HIGH_BLAST_THRESHOLD = 10
DORMANT_HIGH_BLAST_SEVERE_THRESHOLD = 30  # severity escalates to HIGH

# ═══════════════════════════════════════════════════════════════════
# Scope hierarchy for reachability analysis
# ═══════════════════════════════════════════════════════════════════

SCOPE_RANK = {
    'management_group': 4,
    'subscription': 3,
    'resource_group': 2,
    'resource': 1,
}

# ═══════════════════════════════════════════════════════════════════
# Exposure level classification (blast radius risk score buckets)
# ═══════════════════════════════════════════════════════════════════

EXPOSURE_CRITICAL_THRESHOLD = 80
EXPOSURE_HIGH_THRESHOLD = 60
EXPOSURE_MEDIUM_THRESHOLD = 40

# ═══════════════════════════════════════════════════════════════════
# Model limitations (static caveats for transparency)
# ═══════════════════════════════════════════════════════════════════

MODEL_LIMITATIONS = [
    "Reachability based on RBAC scope expansion only — ARM hierarchy inferred from scope strings",
    "Network-level restrictions (NSGs, firewalls, private endpoints) not evaluated",
    "Data-plane access controls (ACLs, SAS policies) not factored into reachability",
    "Resource enumeration limited to discovered storage accounts and key vaults",
    "Conditional Access policies not applied to reachability paths",
    "Group nesting depth limited to direct RBAC inheritance from entra_groups",
]

# ═══════════════════════════════════════════════════════════════════
# Dormant / inactive activity statuses
# ═══════════════════════════════════════════════════════════════════

DORMANT_ACTIVITY_STATUSES = frozenset({
    'dormant', 'inactive', 'stale', 'never_used',
})

# ═══════════════════════════════════════════════════════════════════
# AI identity types
# ═══════════════════════════════════════════════════════════════════

AI_IDENTITY_TYPES = frozenset({
    'ai_agent', 'possible_ai_agent',
})

# ═══════════════════════════════════════════════════════════════════
# Resource enumeration safety limit
# ═══════════════════════════════════════════════════════════════════

MAX_REACHABLE_RESOURCES_PER_IDENTITY = 5000

# Drill-down sample limit (don't return all resources in API)
DRILL_DOWN_RESOURCE_SAMPLE_LIMIT = 50

# ═══════════════════════════════════════════════════════════════════
# Settings key prefix for tenant overrides
# ═══════════════════════════════════════════════════════════════════

THRESHOLD_SETTING_KEYS = {
    'blast_radius_broad_threshold': 'BROAD_BLAST_RADIUS_THRESHOLD',
    'blast_radius_privileged_sub_threshold': 'PRIVILEGED_WIDE_REACH_SUBSCRIPTION_THRESHOLD',
    'blast_radius_ai_threshold': 'AI_EXCESSIVE_BLAST_THRESHOLD',
    'blast_radius_dormant_threshold': 'DORMANT_HIGH_BLAST_THRESHOLD',
}


def get_thresholds(db=None, org_id=None):
    """Return thresholds dict, merging tenant overrides from settings table.

    Args:
        db: Database connection (optional — if None, returns defaults)
        org_id: organization ID (optional)

    Returns:
        dict with all threshold values
    """
    defaults = {
        'broad_blast_radius_threshold': BROAD_BLAST_RADIUS_THRESHOLD,
        'broad_blast_radius_critical_threshold': BROAD_BLAST_RADIUS_CRITICAL_THRESHOLD,
        'privileged_wide_reach_subscription_threshold': PRIVILEGED_WIDE_REACH_SUBSCRIPTION_THRESHOLD,
        'privileged_wide_reach_critical_subscription_threshold': PRIVILEGED_WIDE_REACH_CRITICAL_SUBSCRIPTION_THRESHOLD,
        'ai_excessive_blast_threshold': AI_EXCESSIVE_BLAST_THRESHOLD,
        'dormant_high_blast_threshold': DORMANT_HIGH_BLAST_THRESHOLD,
        'dormant_high_blast_severe_threshold': DORMANT_HIGH_BLAST_SEVERE_THRESHOLD,
    }

    if db and org_id:
        try:
            for setting_key, const_name in THRESHOLD_SETTING_KEYS.items():
                val = db.get_setting(setting_key)
                if val is not None:
                    try:
                        defaults[setting_key] = int(val)
                    except (ValueError, TypeError):
                        pass
        except Exception:
            pass  # Settings table may not exist; use defaults

    return defaults
