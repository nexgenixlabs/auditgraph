"""Breach-cost computation (Tier 1.1 — Risk-in-$).

The single source of truth for converting "N records of classification X" into
a defensible dollar exposure band. All cost factors live in the
``breach_cost_factors`` table — this module never hardcodes numbers.

Contract for callers
────────────────────
    >>> from app.engines.scoring.breach_cost import compute_exposure
    >>> compute_exposure(db, classification='PHI', est_records=120_000, region='global')
    {
        'classification': 'PHI',
        'est_records': 120000,
        'region': 'global',
        'cost_per_record_low':  Decimal('408.00'),
        'cost_per_record_mid':  Decimal('471.00'),
        'cost_per_record_high': Decimal('535.00'),
        'estimated_exposure_low':  Decimal('48960000.00'),
        'estimated_exposure_mid':  Decimal('56520000.00'),
        'estimated_exposure_high': Decimal('64200000.00'),
        'regulatory_band_low':  Decimal('100.00'),
        'regulatory_band_high': Decimal('1500000.00'),
        'source': 'IBM Cost of a Data Breach 2023 — Healthcare; ...',
        'source_year': 2023,
        'notes': 'Healthcare = most expensive sector for 13th consecutive year...',
        'has_factor': True,
    }

If the classification has no cost factor (e.g., classification IS NULL or
an unknown label), ``has_factor=False`` and the exposure fields are 0 so
callers can render "—" rather than fabricating a number.

Region fallback: if a regional row (e.g. ``region='eu'``) exists for the
classification it wins; otherwise the global row is used. This lets a
healthcare customer in the EU override PHI cost without losing the global
PII default.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, Iterable, Optional


# ---- Module-level cache --------------------------------------------------
# Factors change at most once per quarter; cache them once per process to
# avoid hitting the DB on every dashboard request.
_FACTOR_CACHE: Optional[Dict[str, Dict[str, Any]]] = None


def _load_factors(db) -> Dict[str, Dict[str, Any]]:
    """Load active breach cost factors keyed by (classification, region).

    Returns a dict ``{(classification_upper, region_lower): row_dict}``.
    """
    global _FACTOR_CACHE
    if _FACTOR_CACHE is not None:
        return _FACTOR_CACHE

    cursor = db.conn.cursor()
    try:
        cursor.execute(
            """
            SELECT data_classification, region,
                   cost_per_record_low, cost_per_record_mid, cost_per_record_high,
                   regulatory_band_low, regulatory_band_high,
                   source, source_year, notes
              FROM breach_cost_factors
             WHERE is_active = TRUE
            """
        )
        rows = cursor.fetchall()
    except Exception:
        # Table missing or RLS blocked — fail soft. Callers will get
        # has_factor=False and render "—".
        cursor.close()
        return {}
    cursor.close()

    cache: Dict[str, Dict[str, Any]] = {}
    for (cls, region, lo, mid, hi, reg_lo, reg_hi, src, year, notes) in rows:
        key = f"{(cls or '').upper()}|{(region or 'global').lower()}"
        cache[key] = {
            'classification': cls,
            'region': region,
            'cost_per_record_low':  lo,
            'cost_per_record_mid':  mid,
            'cost_per_record_high': hi,
            'regulatory_band_low':  reg_lo,
            'regulatory_band_high': reg_hi,
            'source': src,
            'source_year': year,
            'notes': notes,
        }
    _FACTOR_CACHE = cache
    return cache


def invalidate_cache() -> None:
    """Reset the factor cache; call after a settings update or test."""
    global _FACTOR_CACHE
    _FACTOR_CACHE = None


def _lookup(factors: Dict[str, Dict[str, Any]], classification: str, region: str) -> Optional[Dict[str, Any]]:
    """Region-aware factor lookup with fallback to 'global'."""
    cls = (classification or '').upper()
    if not cls:
        return None
    # Exact region match wins
    hit = factors.get(f"{cls}|{(region or 'global').lower()}")
    if hit:
        return hit
    # Fallback to global
    return factors.get(f"{cls}|global")


def compute_exposure(
    db,
    classification: Optional[str],
    est_records: Optional[int],
    region: str = 'global',
) -> Dict[str, Any]:
    """Compute the dollar exposure band for N records of classification X.

    Returns a dict with low/mid/high estimates (Decimals). Never raises
    on missing factors — returns ``has_factor=False`` with zero exposure.

    Args:
        db: Database instance (used to lazy-load the factor cache).
        classification: Data class label ('PHI', 'PCI', 'PII', etc.).
            Case-insensitive. NULL/empty returns has_factor=False.
        est_records: Estimated record count. NULL/0 returns has_factor=False
            even when the factor row exists (no records → no exposure).
        region: Region code ('global', 'eu', 'us'). Falls back to 'global'
            when no regional row exists for the classification.
    """
    out: Dict[str, Any] = {
        'classification': classification,
        'est_records': est_records or 0,
        'region': region,
        'cost_per_record_low':  Decimal('0'),
        'cost_per_record_mid':  Decimal('0'),
        'cost_per_record_high': Decimal('0'),
        'estimated_exposure_low':  Decimal('0'),
        'estimated_exposure_mid':  Decimal('0'),
        'estimated_exposure_high': Decimal('0'),
        'regulatory_band_low':  Decimal('0'),
        'regulatory_band_high': Decimal('0'),
        'source': None,
        'source_year': None,
        'notes': None,
        'has_factor': False,
    }
    if not classification or not est_records or est_records <= 0:
        return out

    factor = _lookup(_load_factors(db), classification, region)
    if not factor:
        return out

    records = Decimal(int(est_records))
    out.update({
        'cost_per_record_low':  factor['cost_per_record_low'],
        'cost_per_record_mid':  factor['cost_per_record_mid'],
        'cost_per_record_high': factor['cost_per_record_high'],
        'estimated_exposure_low':  factor['cost_per_record_low']  * records,
        'estimated_exposure_mid':  factor['cost_per_record_mid']  * records,
        'estimated_exposure_high': factor['cost_per_record_high'] * records,
        'regulatory_band_low':  factor['regulatory_band_low']  or Decimal('0'),
        'regulatory_band_high': factor['regulatory_band_high'] or Decimal('0'),
        'source': factor['source'],
        'source_year': factor['source_year'],
        'notes': factor['notes'],
        'has_factor': True,
    })
    return out


def aggregate_exposure(
    db,
    rows: Iterable[Dict[str, Any]],
    region: str = 'global',
) -> Dict[str, Any]:
    """Sum dollar exposure across many (classification, records) entries.

    Each input row needs ``data_classification`` and ``est_records`` keys.
    Useful for org-level rollup on the Executive Posture page.

    Returns a dict with:
      - total_records
      - total_exposure_low / mid / high
      - by_classification: per-class breakdown
      - covered: count of rows that had a factor (vs unknowns)
      - uncovered: count of rows that didn't resolve to a factor
    """
    total_lo = Decimal('0')
    total_mid = Decimal('0')
    total_hi = Decimal('0')
    total_records = 0
    covered = 0
    uncovered = 0
    by_cls: Dict[str, Dict[str, Any]] = {}

    for row in rows or []:
        cls = (row.get('data_classification') or '').upper()
        recs = row.get('est_records') or 0
        result = compute_exposure(db, cls, recs, region=region)
        total_records += result['est_records']
        if result['has_factor']:
            covered += 1
            total_lo  += result['estimated_exposure_low']
            total_mid += result['estimated_exposure_mid']
            total_hi  += result['estimated_exposure_high']
            entry = by_cls.setdefault(cls, {
                'classification': cls,
                'est_records': 0,
                'exposure_low': Decimal('0'),
                'exposure_mid': Decimal('0'),
                'exposure_high': Decimal('0'),
                'source': result['source'],
                'source_year': result['source_year'],
            })
            entry['est_records'] += result['est_records']
            entry['exposure_low']  += result['estimated_exposure_low']
            entry['exposure_mid']  += result['estimated_exposure_mid']
            entry['exposure_high'] += result['estimated_exposure_high']
        else:
            uncovered += 1

    return {
        'total_records': total_records,
        'total_exposure_low':  total_lo,
        'total_exposure_mid':  total_mid,
        'total_exposure_high': total_hi,
        'covered': covered,
        'uncovered': uncovered,
        'region': region,
        'by_classification': list(by_cls.values()),
    }


def format_dollar_short(amount) -> str:
    """Render a Decimal/int as a short dollar string for dashboard chips.

        12345        → '$12.3K'
        1234567      → '$1.23M'
        1234567890   → '$1.23B'
        0            → '$0'

    Used by API serializers — frontend should never re-format dollars.
    """
    try:
        n = float(amount or 0)
    except (TypeError, ValueError):
        return '$0'
    if n <= 0:
        return '$0'
    if n >= 1_000_000_000:
        return f"${n/1_000_000_000:.2f}B"
    if n >= 1_000_000:
        return f"${n/1_000_000:.2f}M"
    if n >= 1_000:
        return f"${n/1_000:.1f}K"
    return f"${n:.0f}"
