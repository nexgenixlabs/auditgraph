"""
Attack Path Risk Scorer — v1

Scores an identity→role→scope→blast-radius chain on a 0-100 scale.
Inputs are pre-extracted path components (scope level, role tier,
identity verdict, Key Vault exposure, credential state).
No network scanning. No lateral movement simulation.
"""


def score_attack_path(path_components: dict) -> dict:
    """Score an attack path 0-100 based on:

    - Role privilege tier
    - Scope level (subscription > RG > resource)
    - Identity verdict
    - Key Vault exposure
    - Credential state

    Returns {'path_risk_score': int, 'path_risk_tier': str}.
    """
    score = 0

    # Scope level — base score
    scope_scores = {
        'subscription': 40,
        'resource_group': 25,
        'resource': 10,
        'directory': 35,  # Entra directory roles
    }
    score += scope_scores.get(
        path_components.get('highest_scope_level', 'resource'), 10
    )

    # Role tier — additive
    tier_scores = {
        'KEY_VAULT': 25,
        'HIGH': 20,
        'MEDIUM': 10,
        'LOW': 5,
    }
    score += tier_scores.get(
        path_components.get('role_tier', 'LOW'), 5
    )

    # Identity verdict — additive
    verdict_scores = {
        'ORPHANED': 20,
        'AT_RISK': 15,
        'STALE': 10,
        'UNUSED': 8,
        'HEALTHY': 0,
    }
    score += verdict_scores.get(
        path_components.get('identity_verdict', 'HEALTHY'), 0
    )

    # Key Vault critical items — additive (capped at 15)
    kv_items = path_components.get('keyvault_critical_items', 0)
    score += min(kv_items * 5, 15)

    # No owner amplifier
    if path_components.get('has_no_owner', False):
        score += 5

    # Cap at 100
    score = min(score, 100)

    # Tier assignment
    if score >= 75:
        tier = 'CRITICAL'
    elif score >= 50:
        tier = 'HIGH'
    elif score >= 25:
        tier = 'MEDIUM'
    else:
        tier = 'LOW'

    return {'path_risk_score': score, 'path_risk_tier': tier}
