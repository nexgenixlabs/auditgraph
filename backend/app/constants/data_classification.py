"""
Data Classification Taxonomy

Promotes the small _SENSITIVE_DATA_INDICATORS frozenset from azure_discovery.py
into a full classification taxonomy with PHI / PCI / PII / SOURCE / HR / FINANCIAL /
CONFIDENTIAL classes.

A resource is classified by (in order):
  1. settings_overrides — per-tenant regex patterns from settings table (highest)
  2. Azure tag passthrough — values on tags like 'classification', 'sensitivity',
     'data-classification', 'pii', 'phi' map directly to a class
  3. name_patterns — regex matches against the resource name

If no signal is found, classify_resource() returns None. Defaults are NEVER
invented — absence of signal means absence of classification.

All input is passed in (resource name, tag dict, per-tenant settings dict).
No DB queries here.
"""

from __future__ import annotations

import re
from typing import Any, Iterable


# ── Class identifiers (string constants) ──────────────────────────

PHI = "PHI"
PCI = "PCI"
PII = "PII"
SOURCE = "SOURCE"
HR = "HR"
FINANCIAL = "FINANCIAL"
CONFIDENTIAL = "CONFIDENTIAL"

ALL_CLASSES = (PHI, PCI, PII, SOURCE, HR, FINANCIAL, CONFIDENTIAL)


# ── Frontend color map (hex, exported via API) ────────────────────

CLASS_COLORS: dict[str, str] = {
    PHI: "#dc2626",          # red-600
    PCI: "#ea580c",          # orange-600
    PII: "#d97706",          # amber-600
    SOURCE: "#7c3aed",       # violet-600
    HR: "#0891b2",           # cyan-600
    FINANCIAL: "#059669",    # emerald-600
    CONFIDENTIAL: "#475569", # slate-600
}


# ── Per-class taxonomy ────────────────────────────────────────────
# Patterns drawn from common naming conventions only.
# name_patterns:  case-insensitive regex strings, matched against resource name
# tag_values:     case-insensitive exact or prefix matches against tag values

TAXONOMY: dict[str, dict[str, Any]] = {
    PHI: {
        "label": "Protected Health Information",
        "color": CLASS_COLORS[PHI],
        "description": (
            "Patient health data subject to HIPAA. Disclosure or unauthorized "
            "access carries regulatory penalties and patient-safety risk."
        ),
        "name_patterns": [
            r"\bphi\b",
            r"\bhipaa\b",
            r"\bpatient(s)?\b",
            r"\bhealth\b",
            r"\bclinical\b",
            r"\bmedical\b",
            r"\behr\b",
            r"\bemr\b",
            r"\bepic\b",
            r"\bcerner\b",
        ],
        "tag_values": ["phi", "hipaa", "protected-health", "health"],
        "regulations": ["HIPAA", "HITECH"],
    },
    PCI: {
        "label": "Payment Card Information",
        "color": CLASS_COLORS[PCI],
        "description": (
            "Cardholder data in PCI-DSS scope: PANs, CVVs, expiry dates, "
            "and supporting payment processing systems."
        ),
        "name_patterns": [
            r"\bpci\b",
            r"\bcard(holder)?\b",
            r"\bcardno\b",
            r"\bcc(num)?\b",
            r"\bpan\b",
            r"\bcvv\b",
            r"\bpayment(s)?\b",
            r"\bcheckout\b",
            r"\bmerchant\b",
        ],
        "tag_values": ["pci", "pci-dss", "cardholder", "payment"],
        "regulations": ["PCI-DSS"],
    },
    PII: {
        "label": "Personally Identifiable Information",
        "color": CLASS_COLORS[PII],
        "description": (
            "Identifiers tied to natural persons: names, addresses, government IDs, "
            "contact details. Subject to GDPR / CCPA and similar privacy regimes."
        ),
        "name_patterns": [
            r"\bpii\b",
            r"\bssn\b",
            r"\bsin\b",
            r"\bnino\b",
            r"\bpassport\b",
            r"\b(driver|driving)[-_ ]?licen[cs]e\b",
            r"\bcustomer(s)?\b",
            r"\buser(s)?[-_ ]?(data|info|profile)\b",
            r"\bsubscriber(s)?\b",
            r"\bcontact(s)?\b",
            r"\bgdpr\b",
        ],
        "tag_values": ["pii", "personal", "gdpr", "ccpa", "privacy"],
        "regulations": ["GDPR", "CCPA"],
    },
    SOURCE: {
        "label": "Source Code & IP",
        "color": CLASS_COLORS[SOURCE],
        "description": (
            "Source code repositories, build artifacts, and intellectual property. "
            "Leakage risks competitive disclosure and embedded-secret exposure."
        ),
        "name_patterns": [
            r"\bsrc\b",
            r"\bsource\b",
            r"\bsourcecode\b",
            r"\bgit\b",
            r"\bgithub\b",
            r"\bgitlab\b",
            r"\bbitbucket\b",
            r"\brepo(s|sitory)?\b",
            r"\bartifacts?\b",
            r"\bbuilds?\b",
            r"\bci[-_]?cd\b",
        ],
        "tag_values": ["source", "source-code", "ip", "intellectual-property"],
        "regulations": [],
    },
    HR: {
        "label": "Human Resources Data",
        "color": CLASS_COLORS[HR],
        "description": (
            "Employee records: payroll, performance, benefits, salary. "
            "Subject to employment-law and privacy obligations."
        ),
        "name_patterns": [
            r"\bhr\b",
            r"\bemployee(s)?\b",
            r"\bpayroll\b",
            r"\bsalary\b",
            r"\bsalaries\b",
            r"\bcompensation\b",
            r"\bbenefits\b",
            r"\bperformance[-_]?review\b",
            r"\bworkday\b",
            r"\bbamboohr\b",
        ],
        "tag_values": ["hr", "employee", "payroll"],
        "regulations": [],
    },
    FINANCIAL: {
        "label": "Financial Data",
        "color": CLASS_COLORS[FINANCIAL],
        "description": (
            "Financial records: general ledger, accounts payable/receivable, "
            "tax filings, investor reports. Subject to SOX where applicable."
        ),
        "name_patterns": [
            r"\bfinance\b",
            r"\bfinancial(s)?\b",
            r"\baccounting\b",
            r"\bledger\b",
            r"\binvoice(s)?\b",
            r"\binvoicing\b",
            r"\bbilling\b",
            r"\btax(es)?\b",
            r"\bgl\b",
            r"\bap[-_]?ar\b",
            r"\bsox\b",
        ],
        "tag_values": ["financial", "finance", "sox"],
        "regulations": ["SOX"],
    },
    CONFIDENTIAL: {
        "label": "Confidential / Restricted",
        "color": CLASS_COLORS[CONFIDENTIAL],
        "description": (
            "Generic confidential, restricted, or secret content not covered by a "
            "more specific class. Catch-all for organizationally sensitive data."
        ),
        "name_patterns": [
            r"\bconfidential\b",
            r"\brestricted\b",
            r"\bsecret(s)?\b",
            r"\bprivate\b",
            r"\binternal[-_]?only\b",
        ],
        "tag_values": [
            "confidential",
            "restricted",
            "secret",
            "private",
            "internal-only",
        ],
        "regulations": [],
    },
}


# ── Tag keys we inspect (case-insensitive) ────────────────────────

_TAG_KEYS = ("classification", "sensitivity", "data-classification", "pii", "phi")


# ── Compiled regex cache for builtin patterns ─────────────────────

_COMPILED_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    cls: [re.compile(p, re.IGNORECASE) for p in spec["name_patterns"]]
    for cls, spec in TAXONOMY.items()
}


# ── Helpers ───────────────────────────────────────────────────────


def _norm(value: Any) -> str:
    """Lowercase, strip; safe for non-strings."""
    if value is None:
        return ""
    return str(value).strip().lower()


def _tag_class(tag_key: str, tag_value: str) -> str | None:
    """Map an Azure tag (key, value) to a class, if it carries a classification signal.

    Two paths:
      - Key is in _TAG_KEYS — value is interpreted directly (e.g. tag
        'classification' = 'PHI' → PHI). Also handles boolean-style keys
        like 'pii'='true' → PII.
      - Otherwise, value is matched against per-class tag_values lists.
    """
    key = _norm(tag_key)
    val = _norm(tag_value)
    if not val:
        return None

    if key in _TAG_KEYS:
        # Direct value match against class id (PHI/PCI/...) or label
        for cls in ALL_CLASSES:
            if val == cls.lower():
                return cls
        # Boolean-style: tag 'phi'='true' / 'pii'='yes'
        if key in ("phi", "pii") and val in ("true", "yes", "1"):
            return PHI if key == "phi" else PII
        # Value passthrough against tag_values
        for cls, spec in TAXONOMY.items():
            for tv in spec["tag_values"]:
                tv_n = tv.lower()
                if val == tv_n or val.startswith(tv_n + "-") or val.startswith(tv_n + "_"):
                    return cls
        return None

    # Non-classification key, but value still might match a known tag_value
    for cls, spec in TAXONOMY.items():
        for tv in spec["tag_values"]:
            tv_n = tv.lower()
            if val == tv_n or val.startswith(tv_n + "-") or val.startswith(tv_n + "_"):
                return cls
    return None


def _compile_overrides(
    settings_overrides: dict | None,
) -> list[tuple[str, re.Pattern[str]]]:
    """Compile per-tenant override patterns: list of (classification, compiled_regex).

    Shape:
      {'patterns': [{'classification': 'PHI', 'regex': '...'}, ...]}

    Invalid entries are skipped silently — never raise on bad config.
    """
    if not settings_overrides:
        return []
    patterns = settings_overrides.get("patterns")
    if not isinstance(patterns, list):
        return []

    out: list[tuple[str, re.Pattern[str]]] = []
    for entry in patterns:
        if not isinstance(entry, dict):
            continue
        cls = entry.get("classification")
        rx = entry.get("regex")
        if not isinstance(cls, str) or not isinstance(rx, str):
            continue
        cls_upper = cls.strip().upper()
        if cls_upper not in TAXONOMY:
            continue
        try:
            out.append((cls_upper, re.compile(rx, re.IGNORECASE)))
        except re.error:
            continue
    return out


# ── Public API ────────────────────────────────────────────────────


def classify_resource(
    name: str,
    tags: dict | None,
    settings_overrides: dict | None = None,
) -> dict | None:
    """Classify a single resource by name + tags + optional per-tenant overrides.

    Returns a dict {classification, confidence, source} or None when no signal
    is found. No defaults are invented.

    Precedence (highest → lowest):
      1. settings_overrides regex match            → source='override', confidence='high'
      2. Tag passthrough (classification/sensitivity/etc.) → source='tag', confidence='high'
      3. Tag value match against per-class tag_values    → source='tag', confidence='medium'
      4. Built-in name_patterns regex match              → source='name_pattern', confidence='medium'
    """
    name_str = name if isinstance(name, str) else ""

    # 1. Per-tenant overrides — read first, always win
    for cls, rx in _compile_overrides(settings_overrides):
        if name_str and rx.search(name_str):
            return {
                "classification": cls,
                "confidence": "high",
                "source": "override",
            }

    # 2 + 3. Tag-based signals
    if isinstance(tags, dict):
        for k, v in tags.items():
            key_n = _norm(k)
            cls = _tag_class(k, v)
            if cls is None:
                continue
            # High confidence if it came from a recognised classification key,
            # medium if it was a freeform tag value that happened to match.
            confidence = "high" if key_n in _TAG_KEYS else "medium"
            return {
                "classification": cls,
                "confidence": confidence,
                "source": "tag",
            }

    # 4. Name-pattern fallback
    if name_str:
        lowered = name_str  # regexes are IGNORECASE
        for cls, patterns in _COMPILED_PATTERNS.items():
            for rx in patterns:
                if rx.search(lowered):
                    return {
                        "classification": cls,
                        "confidence": "medium",
                        "source": "name_pattern",
                    }

    return None


def classify_resources_batch(
    rows: list[dict],
    settings: dict,
) -> list[dict]:
    """Bulk-classify a list of discovery rows.

    Each input row may include:
      - 'name'              (str)         — resource name
      - 'tags'              (dict | None) — Azure tags
      - 'resource_group'    (str | None)  — optional; classified as a secondary signal
                                            when the primary name yields no result

    The returned list contains shallow copies with these added keys:
      - 'classification'           : str | None
      - 'classification_confidence': str | None
      - 'classification_source'    : str | None

    settings is a dict that may contain 'patterns' override list (same shape
    classify_resource expects). It's passed through unchanged.
    """
    if not isinstance(rows, list):
        return []

    overrides = settings if isinstance(settings, dict) else None
    out: list[dict] = []

    for row in rows:
        if not isinstance(row, dict):
            out.append(row)
            continue

        name = row.get("name")
        tags = row.get("tags")
        result = classify_resource(name, tags, overrides)

        # Secondary: try resource_group name if primary name had no signal
        if result is None:
            rg = row.get("resource_group")
            if isinstance(rg, str) and rg:
                result = classify_resource(rg, None, overrides)

        enriched = dict(row)
        if result is None:
            enriched["classification"] = None
            enriched["classification_confidence"] = None
            enriched["classification_source"] = None
        else:
            enriched["classification"] = result["classification"]
            enriched["classification_confidence"] = result["confidence"]
            enriched["classification_source"] = result["source"]
        out.append(enriched)

    return out


# ── Introspection helpers (for API exposure) ──────────────────────


def get_taxonomy_summary() -> list[dict]:
    """Return taxonomy as a JSON-friendly list — for frontend consumption.

    Excludes compiled regex objects; includes raw pattern strings, colors,
    descriptions, and regulations.
    """
    return [
        {
            "id": cls,
            "label": spec["label"],
            "color": spec["color"],
            "description": spec["description"],
            "name_patterns": list(spec["name_patterns"]),
            "tag_values": list(spec["tag_values"]),
            "regulations": list(spec["regulations"]),
        }
        for cls, spec in TAXONOMY.items()
    ]


def supported_tag_keys() -> tuple[str, ...]:
    """Tag keys whose values are interpreted as direct classification signals."""
    return _TAG_KEYS


__all__ = (
    "PHI",
    "PCI",
    "PII",
    "SOURCE",
    "HR",
    "FINANCIAL",
    "CONFIDENTIAL",
    "ALL_CLASSES",
    "CLASS_COLORS",
    "TAXONOMY",
    "classify_resource",
    "classify_resources_batch",
    "get_taxonomy_summary",
    "supported_tag_keys",
)
