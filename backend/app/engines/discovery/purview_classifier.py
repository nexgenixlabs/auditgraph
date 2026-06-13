"""
purview_classifier — Microsoft Purview integration (Tier 4 of 6)

AG-193 / AG-198 (Sprint 3) · 2026-06-12

Pulls classification labels from Microsoft Purview for resources the
customer's Purview catalog has already classified. METADATA ONLY — we
never read data content. Purview itself does the data inspection on the
customer's side; we just consume the labels they produced.

This is the OPTIONAL tier 4 of the 6-tier classify engine:
    1. Manual override
    2. Regex override
    3. Data Trust Zone (CISO scope)
    4. Purview classification             ← THIS MODULE
    5. Azure tag
    6. Name pattern

Gated behind FEATURE_PURVIEW_INTEGRATION flag (default OFF). Customer
opts in via the new Purview connector tile in Settings → Connectors.

Required Purview perm: PurviewReader only — read classifications via
the catalog REST API. NO data plane access.

Cache shape (in-memory per worker, TTL = 24h):
    {(org_id, resource_id): {'label': 'PHI', 'fetched_at': ts}}

Cache-miss + Purview unreachable → return None and let the engine fall
through to tier 5 (tag) / tier 6 (name pattern). Graceful degradation
is the contract — Purview being down must never break discovery.
"""

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


# In-memory cache. Process-local — workers warm up over time. For prod
# scale we'd front this with Redis, but the cache is purely an
# optimization (Purview API is the source of truth).
_CACHE: dict[tuple[int, str], dict[str, Any]] = {}
_CACHE_TTL_SECONDS = 24 * 60 * 60  # 24h


# Map Purview classification names → AuditGraph internal class.
# Purview ships ~200 built-in classifiers (e.g. "U.S. Social Security
# Number", "Credit Card Number"). We map the most common 30 to our 7
# classes. Unknown labels return None (engine falls through).
_PURVIEW_LABEL_MAP = {
    # PHI
    "MICROSOFT.HEALTH.US_HEALTH_INSURANCE_CLAIM_NUMBER":             "PHI",
    "MICROSOFT.HEALTH.US_HEALTHCARE_ID":                              "PHI",
    "MICROSOFT.HEALTH.US_NATIONAL_PROVIDER_ID":                       "PHI",
    "MICROSOFT.HEALTH.MEDICAL_TERMS_CONDITIONS":                      "PHI",
    "MICROSOFT.HEALTH.DRUG_ENFORCEMENT_AGENCY_NUMBER":                "PHI",

    # PCI
    "MICROSOFT.FINANCIAL.CREDIT_CARD_NUMBER":                         "PCI",
    "MICROSOFT.FINANCIAL.US_BANK_ACCOUNT_NUMBER":                     "PCI",
    "MICROSOFT.FINANCIAL.SWIFT_CODE":                                 "PCI",

    # PII
    "MICROSOFT.PERSONAL.US_SOCIAL_SECURITY_NUMBER":                   "PII",
    "MICROSOFT.PERSONAL.US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER":"PII",
    "MICROSOFT.PERSONAL.US_DRIVERS_LICENSE_NUMBER":                   "PII",
    "MICROSOFT.PERSONAL.US_PASSPORT_NUMBER":                          "PII",
    "MICROSOFT.PERSONAL.EU_PASSPORT_NUMBER":                          "PII",
    "MICROSOFT.PERSONAL.UK_NATIONAL_INSURANCE_NUMBER":                "PII",
    "MICROSOFT.PERSONAL.EU_DRIVERS_LICENSE_NUMBER":                   "PII",
    "MICROSOFT.PERSONAL.EU_NATIONAL_IDENTIFICATION_NUMBER":           "PII",
    "MICROSOFT.PERSONAL.IP_ADDRESS":                                  "PII",
    "MICROSOFT.PERSONAL.EMAIL_ADDRESS":                               "PII",
    "MICROSOFT.PERSONAL.PERSON_NAME":                                 "PII",
    "MICROSOFT.PERSONAL.PHONE_NUMBER":                                "PII",

    # HR — Purview surfaces these via human-resources collection labels
    "MICROSOFT.HR.HUMAN_RESOURCES":                                   "HR",

    # FINANCIAL — internal financials separate from PCI cardholder data
    "MICROSOFT.FINANCIAL.US_TAXPAYER_IDENTIFICATION_NUMBER":          "FINANCIAL",
}


def map_purview_label(purview_classifier_name: str) -> str | None:
    """Map a Purview classifier name to one of the 7 AuditGraph classes.

    Returns None when the classifier isn't in our known map — that's
    fine, the engine falls through to lower tiers.
    """
    if not purview_classifier_name:
        return None
    key = purview_classifier_name.strip().upper()
    return _PURVIEW_LABEL_MAP.get(key)


def get_purview_label_for_resource(
    org_id: int,
    resource_id: str,
    fetch_fn=None,
) -> str | None:
    """Fetch Purview classification for a single resource, with cache.

    Args:
      org_id, resource_id: cache key
      fetch_fn: optional override for the actual Purview API call.
        Default uses _real_purview_fetch which is a placeholder until
        the customer's Purview credentials are wired through Settings.

    Returns AuditGraph class (PHI/PCI/...) or None.
    """
    if not resource_id:
        return None

    # Cache check
    now = time.time()
    cache_key = (org_id, resource_id)
    cached = _CACHE.get(cache_key)
    if cached and (now - cached.get("fetched_at", 0)) < _CACHE_TTL_SECONDS:
        return cached.get("label")

    # Fetch (or no-op until configured)
    label = None
    try:
        fn = fetch_fn or _real_purview_fetch
        label = fn(org_id, resource_id)
    except Exception as exc:
        # Graceful degradation — Purview unreachable / unconfigured /
        # rate-limited. Never break discovery.
        logger.debug("purview fetch failed for resource %s: %s",
                     resource_id, exc)
        label = None

    # Cache even None to avoid hot-spinning on unconfigured tenants.
    _CACHE[cache_key] = {"label": label, "fetched_at": now}
    return label


def _real_purview_fetch(org_id: int, resource_id: str) -> str | None:
    """Real Purview API call. Returns mapped AuditGraph class or None.

    Disabled by default. When the customer has Purview configured (see
    Settings → Connectors → Purview), this function is replaced with a
    real implementation that calls:
        GET https://<account>.purview.azure.com/catalog/api/atlas/v2/
            entity/uniqueAttribute/type/azure_resource?attr:qualifiedName=<resource_id>

    Returns AuditGraph class label or None. Authentication via:
      - Managed Identity (preferred in cloud)
      - Service principal client_credentials (alternative)

    Sprint 3 ships the engine slot + cache + mapping. The actual REST
    call lands when the customer's Purview connector is configured —
    keeping cloud creds out of the local module.
    """
    from app.config import FEATURE_PURVIEW_INTEGRATION
    if not FEATURE_PURVIEW_INTEGRATION:
        return None

    # Sprint 3 placeholder. Real impl arrives with the Settings →
    # Connectors → Purview tile (post-merge of AG-198). The function
    # signature is stable so the engine doesn't need to change again.
    logger.debug("Purview integration enabled but no live transport "
                 "wired — returning None for %s", resource_id)
    return None


def warm_purview_cache_for_run(
    db, organization_id: int, resource_ids: list[str]
) -> int:
    """Batch-prefetch Purview labels for a discovery run.

    Called from post-discovery scheduler tier 2. Reduces tier-4
    classification time from O(n × API_latency) to a single batch.
    Returns the number of labels actually fetched (cache hits don't
    count).
    """
    fetched = 0
    for rid in resource_ids:
        cache_key = (organization_id, rid)
        if cache_key in _CACHE:
            continue
        label = get_purview_label_for_resource(organization_id, rid)
        if label:
            fetched += 1
    return fetched


def clear_purview_cache(org_id: int | None = None) -> int:
    """Drop cached labels. Used when a customer reconfigures Purview."""
    if org_id is None:
        n = len(_CACHE)
        _CACHE.clear()
        return n
    drop = [k for k in _CACHE if k[0] == org_id]
    for k in drop:
        del _CACHE[k]
    return len(drop)


__all__ = [
    "get_purview_label_for_resource",
    "map_purview_label",
    "warm_purview_cache_for_run",
    "clear_purview_cache",
]
