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
            r"\bclaim(s)?\b",
            r"\bcoverage\b",
            r"\beligibility\b",
            r"\bencounter(s)?\b",
            r"\bdiagnosis\b",
            r"\brx\b",
            r"\bpharmacy\b",
            r"\bcarehub\b",
            r"\bcarequery\b",
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
    scope_rules: list[dict] | None = None,
    subscription_id: str | None = None,
    resource_group: str | None = None,
    purview_label: str | None = None,
    manual_override: str | None = None,
) -> dict | None:
    """Classify a single resource — AG-CLASSIFICATION-ZONES 6-tier engine.

    AG-193 (2026-06-12) — extends the original 3-tier engine to support
    Data Trust Zones (CISO-asserted scope rules) and reserves a Purview
    integration slot. Adds numeric confidence (0-100) on every return
    value so the UI can render High/Med/Low rollup tiles.

    Precedence (highest → lowest, first match wins):
      1. manual_override         conf 100  source='manual'
      2. settings_overrides      conf  95  source='regex_override'
      3. scope_rules (Data Trust Zone)  conf 100  source='scope_rule'
      4. purview_label           conf  95  source='purview'
      5. Azure tag               conf  80  source='tag'  (60 when value-only)
      6. Built-in name pattern   conf  45  source='name_pattern'

    Returns a dict:
      {classification, confidence (int 0-100), source, rule_id (when scope/manual)}
    or None when no signal is found. No defaults are invented.

    `scope_rules` shape: list of {classification, scope_type, scope_value, id}
    matching the data_trust_zones row format. Caller filters out revoked.
    """
    name_str = name if isinstance(name, str) else ""

    # ── Tier 1: per-resource manual override ─────────────────────
    if manual_override and isinstance(manual_override, str):
        cls_u = manual_override.strip().upper()
        if cls_u in TAXONOMY:
            return {
                "classification": cls_u,
                "confidence": 100,
                "source": "manual",
            }

    # ── Tier 2: per-tenant regex override ────────────────────────
    for cls, rx in _compile_overrides(settings_overrides):
        if name_str and rx.search(name_str):
            return {
                "classification": cls,
                "confidence": 95,
                "source": "regex_override",
            }

    # ── Tier 3: Data Trust Zone (CISO scope assertion) ───────────
    #
    # AG-193 follow-up (2026-06-12): broad RG-only zones no longer
    # rubber-stamp confidence 100. Precedence inside this tier:
    #   3a. resource_name_pattern  → 100 (per-resource pattern; precise)
    #   3b. broad zone + name corroborates the asserted class → 100
    #   3c. broad zone, name silent on the class → 60 (Medium)
    if scope_rules:
        match = _match_scope_rules(
            scope_rules, name_str, subscription_id, resource_group
        )
        if match is not None:
            rule_scope = _norm(match.get("scope_type"))
            cls = match["classification"]
            if rule_scope == "resource_name_pattern":
                conf = 100  # per-resource pattern — precise
            elif _name_corroborates(name_str, cls):
                conf = 100  # zone + name agree
            else:
                conf = 60   # zone asserts; name is silent
            return {
                "classification": cls,
                "confidence": conf,
                "source": "scope_rule",
                "rule_id": match.get("id"),
                "scope_type": rule_scope,
            }

    # ── Tier 4: Purview classification (slot reserved) ───────────
    if purview_label and isinstance(purview_label, str):
        cls_u = purview_label.strip().upper()
        if cls_u in TAXONOMY:
            return {
                "classification": cls_u,
                "confidence": 95,
                "source": "purview",
            }

    # ── Tier 5: Azure tag ────────────────────────────────────────
    if isinstance(tags, dict):
        for k, v in tags.items():
            key_n = _norm(k)
            cls = _tag_class(k, v)
            if cls is None:
                continue
            # 80 when key is a recognised classification key,
            # 60 when only the value happened to match a known token.
            conf = 80 if key_n in _TAG_KEYS else 60
            return {
                "classification": cls,
                "confidence": conf,
                "source": "tag",
            }

    # ── Tier 6: built-in name pattern ────────────────────────────
    if name_str:
        for cls, patterns in _COMPILED_PATTERNS.items():
            for rx in patterns:
                if rx.search(name_str):
                    return {
                        "classification": cls,
                        "confidence": 45,
                        "source": "name_pattern",
                    }

    return None


# ── Scope-rule matcher (Tier 3) ──────────────────────────────────

def _match_scope_rules(
    scope_rules: list[dict],
    name: str | None,
    subscription_id: str | None,
    resource_group: str | None,
) -> dict | None:
    """Find the first scope rule that matches the resource.

    Match order within scope_rules iteration (first match wins; caller
    controls ordering — most-specific first by convention):
      - resource_name_pattern  glob match against resource name
      - subscription           literal
      - resource_group         literal
      - subscription_pattern   glob (fnmatch — '*' wildcard)
      - resource_group_pattern glob

    Resource-name patterns are intentionally checked FIRST inside any
    given rule so a more-precise zone wins over a broad RG zone when
    multiple rules match.
    """
    if not scope_rules:
        return None
    import fnmatch

    name_n = _norm(name)
    sub_n = _norm(subscription_id)
    rg_n = _norm(resource_group)

    for rule in scope_rules:
        if not isinstance(rule, dict):
            continue
        st = _norm(rule.get("scope_type"))
        sv_raw = rule.get("scope_value")
        if not isinstance(sv_raw, str):
            continue
        sv = sv_raw.strip().lower()
        if not sv:
            continue

        if st == "resource_name_pattern" and name_n and fnmatch.fnmatch(name_n, sv):
            return rule
        if st == "subscription" and sub_n and sub_n == sv:
            return rule
        if st == "resource_group" and rg_n and rg_n == sv:
            return rule
        if st == "subscription_pattern" and sub_n and fnmatch.fnmatch(sub_n, sv):
            return rule
        if st == "resource_group_pattern" and rg_n and fnmatch.fnmatch(rg_n, sv):
            return rule

    return None


def _name_corroborates(name: str, classification: str) -> bool:
    """Does the resource name contain a keyword for `classification`?

    Used to decide whether a broad scope rule (RG/sub level) is backed
    by per-resource naming evidence. When True, the broad zone earns
    confidence 100; when False, the broad zone is recorded at 60 (Medium)
    so the UI can flag it as 'zone-asserted, name-unverified'.
    """
    if not name:
        return False
    patterns = _COMPILED_PATTERNS.get(classification, [])
    return any(rx.search(name) for rx in patterns)


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
