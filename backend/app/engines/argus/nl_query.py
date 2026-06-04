"""
nl_query — Natural-Language Query Translator (AG-185, Argus Layer 1)
====================================================================

Translates plain-English questions about identities into structured
**Identity Query Builder** filter groups. The translation is rule-based
(no LLM call in the MVP) — we recognise a curated set of intents that
match the named shortcut chips in the AG-185 acceptance criteria, plus a
keyword fallback that maps free-text tokens to known field/value pairs.

Public entry point
------------------
:func:`translate_nl_query` returns a dict of the shape::

    {
        'filters': [
            {'field': 'agent_identity_type', 'op': 'equals',   'value': 'ai_agent'},
            {'field': 'has_role_name',       'op': 'contains', 'value': 'Key Vault Administrator'},
        ],
        'description': 'AI agents with Key Vault Administrator role',
        'confidence':  'high',
        'intent':      'ai_agents_with_kv_admin',
    }

Or ``None`` when nothing matches — the caller (the handler) must surface
that empty state honestly rather than fabricating an answer.

Design rules
------------

1. **No hardcoded answer data.** This module *only* emits filter structure.
   The handler then feeds those filters into the existing
   ``/api/identities/query`` builder, which runs the query against the
   live discovery snapshot. We never inline identity / role / resource
   names that aren't echoes of the user's own input.
2. **Pattern-driven, not regex-soup.** Intents are matched by simple
   token containment + ordering checks so the rule set is auditable.
3. **Fields must be query-builder-known.** Each emitted field name MUST
   resolve in ``QUERY_FIELD_MAP``, ``QUERY_COMPUTED_FIELDS``, or the
   small set of `nl_query`-specific synthetic fields the matching
   handler knows how to expand (``has_role_name``, ``has_role_contains``,
   ``sort_order``). The handler is responsible for rewriting the
   synthetic fields before invoking the query builder.
4. **No DB access.** This module is a pure transformation. The handler
   opens / closes its own cursor.
5. **Module-level logger.** Tag every accepted intent + free-text miss
   so the Argus audit trail captures what we recognised.

The six named shortcuts (AC for AG-185) are implemented as their own
intent functions so each one is reviewable in isolation; the free-text
fallback fires only when no shortcut matched.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic field names (handler-expanded)
#
# These are NOT real columns in QUERY_FIELD_MAP — the calling handler
# rewrites them into either a real field filter or an additional SQL
# constraint before invoking the query-builder. They live here so the
# *engine* can describe intent without forcing every shortcut into the
# raw column shape.
# ─────────────────────────────────────────────────────────────────────────────

SYNTHETIC_FIELD_HAS_ROLE_NAME = 'has_role_name'           # exact role name match
SYNTHETIC_FIELD_HAS_ROLE_CONTAINS = 'has_role_contains'   # role name LIKE
SYNTHETIC_FIELD_SORT_ORDER = 'sort_order'                 # value = field name to sort by
SYNTHETIC_FIELD_META = 'meta_question'                    # non-filter intent (e.g. posture drop)

# Synthetic fields the handler is required to understand. The engine is
# allowed to emit any of these — anything else MUST be a known column.
SYNTHETIC_FIELDS = frozenset({
    SYNTHETIC_FIELD_HAS_ROLE_NAME,
    SYNTHETIC_FIELD_HAS_ROLE_CONTAINS,
    SYNTHETIC_FIELD_SORT_ORDER,
    SYNTHETIC_FIELD_META,
})


# ─────────────────────────────────────────────────────────────────────────────
# Keyword vocabularies
#
# Tokens are matched case-insensitively against the user's normalised
# query string (lower-case, single-spaced). We keep these explicit so the
# rule set is reviewable.
# ─────────────────────────────────────────────────────────────────────────────

# AI-agent / agentic identity tokens. Matches phrases like "AI agent",
# "agentic identity", "LLM agent", "copilot agent", "ai assistants".
AI_AGENT_TOKENS = (
    'ai agent', 'ai agents',
    'ai-agent', 'ai-agents',
    'agentic',
    'llm agent', 'llm agents',
    'copilot agent',
    'ai assistant', 'ai assistants',
)

# "Ownerless" / "orphan" tokens — match the agent_orphan_detector vocabulary
# so this layer agrees with the rest of the platform.
OWNERLESS_TOKENS = (
    'ownerless', 'no owner', 'no owners', 'unowned',
    'orphan', 'orphans', 'orphaned',
)

# Key-Vault admin keywords. We map all of these onto the canonical
# Azure role name "Key Vault Administrator". The role label here is
# the one stored in role_assignments.role_name verbatim, so the
# query-builder's LIKE wildcard ('contains') will hit. We never
# substitute a different role.
KV_ADMIN_ROLE_TOKENS = (
    'kv admin', 'kv-admin',
    'key vault admin', 'key vault administrator',
    'keyvault admin', 'keyvault administrator',
)
KV_ADMIN_CANONICAL = 'Key Vault Administrator'

# OAuth consent grant tokens — used for shortcut #2 ("OAuth grants
# matching Vercel"). When this fires we route the request to the
# dedicated /api/connected-apps/vercel-scenario handler rather than the
# generic identity query builder, because OAuth grants are not
# identities.
OAUTH_GRANT_TOKENS = (
    'oauth grant', 'oauth grants',
    'oauth consent', 'consent grant', 'consent grants',
)
VERCEL_TOKENS = (
    'vercel', 'context.ai', 'context ai',
)

# Production-DB keywords. We DON'T hardcode SKUs — the role-name LIKE
# match catches SQL Contributor / Cosmos DB roles; the prod scope is
# handled by the caller via tag-based filtering once we have it. For
# the MVP shortcut we filter on identity_category=service_principal
# AND has_role_contains some DB role.
SPN_TOKENS = ('spn', 'spns', 'service principal', 'service principals')
PROD_DB_ROLE_TOKENS = (
    'prod db', 'prod dbs', 'prod database', 'prod databases',
    'production db', 'production database',
    'sql admin', 'sql contributor',
    'cosmos contributor', 'cosmos admin', 'cosmos db',
    'data plane', 'database',
)
DB_ROLE_LIKE_KEYWORDS = ('sql', 'cosmos', 'database', 'mongo', 'postgres')

# "Posture drop" / "why is posture down" tokens — this is a meta-question,
# not an identity filter, so we route it to the meta intent and let the
# handler decide how to answer (drift + risk-score-trajectory APIs).
POSTURE_DROP_TOKENS = (
    'posture drop', 'posture dropped', 'posture down',
    'why is posture', 'posture decrease',
    'why did posture',
)

# "Highest business risk" tokens — translate to a sort intent so the
# query builder returns the same row set ordered by risk_score DESC.
HIGHEST_RISK_TOKENS = (
    'highest business risk', 'highest risk', 'most risky',
    'top risk', 'top risks',
    'biggest risk', 'riskiest',
)

# ── AG-T1.4: AI-ISPM-aligned shortcut vocabularies ──
# Data-classification reach (PHI / PCI / PII)
DATA_CLASS_TOKENS_PHI = ('phi', 'protected health', 'patient data', 'health record', 'health records')
DATA_CLASS_TOKENS_PCI = ('pci', 'cardholder', 'card data', 'payment data')
DATA_CLASS_TOKENS_PII = ('pii', 'personal data', 'personal info', 'personally identifiable')
DATA_CLASS_REACH_TOKENS = ('reach', 'reaching', 'reaches', 'can access', 'have access', 'have read', 'have write')

# Multi-model AI usage
MULTI_MODEL_TOKENS = (
    'multi-model', 'multi model', 'multiple models', 'multi-modal', 'multimodal',
    'multi-model agent', 'multi-model agents',
)

# Subscription-scope privilege containment
SUB_OWNER_TOKENS = (
    'subscription owner', 'sub owner', 'sub-owner',
    'subscription contributor', 'sub contributor',
    'tenant-wide', 'tenant wide',
)

# Dangerous Graph permissions — independent of the Vercel-specific intent
DANGEROUS_GRAPH_TOKENS = (
    'dangerous graph', 'risky graph', 'high-risk graph', 'high risk graph',
    'mail.readwrite', 'files.readwrite', 'sites.fullcontrol',
    'dangerous oauth', 'risky oauth', 'high-risk oauth',
    'dangerous permission', 'dangerous permissions',
)


# ─────────────────────────────────────────────────────────────────────────────
# Lightweight tokenisation helper
# ─────────────────────────────────────────────────────────────────────────────

_WS_RE = re.compile(r'\s+')

def _normalise(text: str) -> str:
    """Lower-case + collapse whitespace. Returns '' for falsy input."""
    if not text or not isinstance(text, str):
        return ''
    return _WS_RE.sub(' ', text.strip().lower())


def _contains_any(text: str, tokens: tuple[str, ...]) -> Optional[str]:
    """Return the first token found in `text`, or None."""
    for t in tokens:
        if t in text:
            return t
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Intent matchers — one function per named shortcut. Each returns either
# a complete translation dict or None.
# ─────────────────────────────────────────────────────────────────────────────

def _match_ai_agents_with_kv_admin(text: str) -> Optional[dict[str, Any]]:
    """Shortcut #1: "AI agents with KV admin"."""
    if not _contains_any(text, AI_AGENT_TOKENS):
        return None
    if not _contains_any(text, KV_ADMIN_ROLE_TOKENS):
        return None
    return {
        'intent': 'ai_agents_with_kv_admin',
        'filters': [
            {'field': 'agent_identity_type', 'op': 'equals', 'value': 'ai_agent'},
            {'field': SYNTHETIC_FIELD_HAS_ROLE_CONTAINS, 'op': 'contains',
             'value': KV_ADMIN_CANONICAL},
        ],
        'description': f"AI agents holding the {KV_ADMIN_CANONICAL} role",
        'confidence': 'high',
    }


def _match_oauth_grants_matching_vercel(text: str) -> Optional[dict[str, Any]]:
    """Shortcut #2: "OAuth grants matching Vercel".

    OAuth consent grants are NOT identities — they live in their own
    table. We emit a ``meta_question`` intent that the handler routes to
    the existing /api/connected-apps/vercel-scenario endpoint. The engine
    still owns the recognition step so /api/argus/nl-query is the single
    entry point.
    """
    has_oauth = _contains_any(text, OAUTH_GRANT_TOKENS) is not None
    has_vercel = _contains_any(text, VERCEL_TOKENS) is not None
    # Accept either "oauth … vercel" or just "vercel scenario / playbook"
    if not (has_oauth or has_vercel):
        return None
    if not has_vercel and 'oauth' not in text and 'consent' not in text:
        return None
    return {
        'intent': 'oauth_grants_matching_vercel',
        'filters': [
            {'field': SYNTHETIC_FIELD_META, 'op': 'equals',
             'value': 'oauth_vercel_scenario'},
        ],
        'description': 'OAuth consent grants matching the Vercel / Context.ai pattern',
        'confidence': 'high',
        'meta_route': '/api/connected-apps/vercel-scenario',
    }


def _match_ownerless_ai_agents(text: str) -> Optional[dict[str, Any]]:
    """Shortcut #3: "Ownerless AI agents"."""
    if not _contains_any(text, OWNERLESS_TOKENS):
        return None
    if not _contains_any(text, AI_AGENT_TOKENS):
        return None
    return {
        'intent': 'ownerless_ai_agents',
        'filters': [
            {'field': 'agent_identity_type', 'op': 'equals', 'value': 'ai_agent'},
            {'field': 'owner_count', 'op': 'equals', 'value': 0},
        ],
        'description': 'AI agents with no assigned owner',
        'confidence': 'high',
    }


def _match_spns_reaching_prod_dbs(text: str) -> Optional[dict[str, Any]]:
    """Shortcut #4: "SPNs reaching prod DBs".

    We can't infer "prod" reliably from role-name alone, so the filter
    set is conservative: service-principal-category identities that hold
    a database-flavoured role. The handler may layer on scope/tag
    filters once the prod-scope catalog ships.
    """
    if not _contains_any(text, SPN_TOKENS):
        return None
    # "reaching … db" / "prod db" / direct mention of a DB role
    if not (_contains_any(text, PROD_DB_ROLE_TOKENS)
            or 'reach' in text and any(k in text for k in DB_ROLE_LIKE_KEYWORDS)):
        return None
    # Emit multiple has_role_contains conditions (OR-joined by the
    # handler) — we hand back one filter per candidate role and let the
    # handler decide how to combine them. For the MVP we deliver them
    # in a single OR-group via the 'in' operator on the synthetic field.
    return {
        'intent': 'spns_reaching_prod_dbs',
        'filters': [
            {'field': 'identity_category', 'op': 'equals', 'value': 'service_principal'},
            {'field': SYNTHETIC_FIELD_HAS_ROLE_CONTAINS, 'op': 'in',
             'value': ['SQL', 'Cosmos', 'Database', 'PostgreSQL', 'MongoDB']},
        ],
        'description': 'Service principals holding a database-plane role',
        'confidence': 'medium',
    }


def _match_posture_drop_reason(text: str) -> Optional[dict[str, Any]]:
    """Shortcut #5: "Posture drop reason" — meta-question."""
    if not _contains_any(text, POSTURE_DROP_TOKENS):
        return None
    return {
        'intent': 'posture_drop_reason',
        'filters': [
            {'field': SYNTHETIC_FIELD_META, 'op': 'equals',
             'value': 'posture_drop_reason'},
        ],
        'description': 'Why did the posture score change recently',
        'confidence': 'high',
        'meta_route': '/api/dashboard/posture',
    }


def _match_highest_business_risk(text: str) -> Optional[dict[str, Any]]:
    """Shortcut #6: "Highest business risk"."""
    if not _contains_any(text, HIGHEST_RISK_TOKENS):
        return None
    return {
        'intent': 'highest_business_risk',
        'filters': [
            {'field': 'risk_level', 'op': 'in', 'value': ['critical', 'high']},
            {'field': SYNTHETIC_FIELD_SORT_ORDER, 'op': 'equals', 'value': 'risk_score'},
        ],
        'description': 'Identities ranked by business risk (critical/high), sorted by risk score',
        'confidence': 'high',
    }


# ─── AG-T1.4: AI-ISPM intents ─────────────────────────────────────────

def _match_ai_agents_reaching_class(text: str) -> Optional[dict[str, Any]]:
    """Shortcut: "AI agents reaching PHI / PCI / PII"."""
    if not _contains_any(text, AI_AGENT_TOKENS):
        return None
    if not _contains_any(text, DATA_CLASS_REACH_TOKENS):
        return None
    if _contains_any(text, DATA_CLASS_TOKENS_PHI):
        cls = 'PHI'
    elif _contains_any(text, DATA_CLASS_TOKENS_PCI):
        cls = 'PCI'
    elif _contains_any(text, DATA_CLASS_TOKENS_PII):
        cls = 'PII'
    else:
        return None
    return {
        'intent': f'ai_agents_reaching_{cls.lower()}',
        'filters': [
            {'field': 'agent_identity_type', 'op': 'equals', 'value': 'ai_agent'},
            {'field': SYNTHETIC_FIELD_META, 'op': 'equals',
             'value': f'data_reachability_class_{cls}'},
        ],
        'description': f'AI agents with read or write access to {cls}-classified resources',
        'confidence': 'high',
    }


def _match_multi_model_ai(text: str) -> Optional[dict[str, Any]]:
    """Shortcut: "Multi-model AI agents" — agents tied to ≥3 model deployments."""
    if not _contains_any(text, MULTI_MODEL_TOKENS):
        return None
    if not _contains_any(text, AI_AGENT_TOKENS) and 'model' not in text:
        return None
    return {
        'intent': 'multi_model_ai_agents',
        'filters': [
            {'field': 'agent_identity_type', 'op': 'equals', 'value': 'ai_agent'},
            {'field': SYNTHETIC_FIELD_META, 'op': 'equals',
             'value': 'multi_model_threshold_3'},
        ],
        'description': 'AI agents tied to ≥3 distinct model deployments (multi-model)',
        'confidence': 'high',
    }


def _match_ai_with_sub_owner(text: str) -> Optional[dict[str, Any]]:
    """Shortcut: "AI agents with subscription Owner"."""
    if not _contains_any(text, AI_AGENT_TOKENS):
        return None
    if not _contains_any(text, SUB_OWNER_TOKENS):
        return None
    return {
        'intent': 'ai_agents_with_subscription_owner',
        'filters': [
            {'field': 'agent_identity_type', 'op': 'equals', 'value': 'ai_agent'},
            {'field': SYNTHETIC_FIELD_HAS_ROLE_NAME, 'op': 'equals', 'value': 'Owner'},
            {'field': SYNTHETIC_FIELD_META, 'op': 'equals',
             'value': 'scope_subscription'},
        ],
        'description': 'AI agents holding Owner at subscription scope',
        'confidence': 'high',
    }


def _match_dangerous_oauth_grants(text: str) -> Optional[dict[str, Any]]:
    """Shortcut: "OAuth apps with dangerous Graph permissions" — distinct from Vercel."""
    if not _contains_any(text, DANGEROUS_GRAPH_TOKENS):
        # Also accept "oauth apps" + "dangerous"/"risky"
        if not (_contains_any(text, OAUTH_GRANT_TOKENS)
                and any(t in text for t in ('dangerous', 'risky', 'high-risk', 'high risk'))):
            return None
    return {
        'intent': 'oauth_apps_dangerous_graph',
        'filters': [
            {'field': SYNTHETIC_FIELD_META, 'op': 'equals',
             'value': 'oauth_dangerous_graph_permissions'},
        ],
        'description': 'OAuth consent grants carrying high-risk Microsoft Graph scopes',
        'confidence': 'high',
        'meta_route': '/api/consent-grants?risk_level=critical,high',
    }


# Ordered list of named-shortcut matchers. The first to return a non-None
# wins; ordering reflects specificity (compound intents before generic).
NAMED_SHORTCUTS = (
    _match_ai_agents_with_kv_admin,
    # AG-T1.4: AI-ISPM intents — declared early so they win over the
    # generic ai-agent fallback that fires on the bare "AI agent" token.
    _match_ai_agents_reaching_class,
    _match_multi_model_ai,
    _match_ai_with_sub_owner,
    _match_dangerous_oauth_grants,
    _match_ownerless_ai_agents,           # before generic AI-agent fallback
    _match_oauth_grants_matching_vercel,
    _match_spns_reaching_prod_dbs,
    _match_posture_drop_reason,
    _match_highest_business_risk,
)


# ─────────────────────────────────────────────────────────────────────────────
# Free-text fallback — keyword scan against known field values
#
# We map a small dictionary of stand-alone tokens to filter conditions.
# This catches phrases like "show critical SPNs", "dormant guests",
# "stale identities" without needing a full intent rule. Confidence is
# 'low' because the mapping is heuristic.
# ─────────────────────────────────────────────────────────────────────────────

# (token, field, op, value)
FREE_TEXT_TOKEN_MAP = (
    # risk level
    ('critical',        'risk_level',        'equals', 'critical'),
    ('high risk',       'risk_level',        'equals', 'high'),
    ('medium risk',     'risk_level',        'equals', 'medium'),
    ('low risk',        'risk_level',        'equals', 'low'),
    # identity category
    ('service principal',     'identity_category', 'equals', 'service_principal'),
    ('service principals',    'identity_category', 'equals', 'service_principal'),
    ('spn',                   'identity_category', 'equals', 'service_principal'),
    ('spns',                  'identity_category', 'equals', 'service_principal'),
    ('managed identity',      'identity_category', 'equals', 'managed_identity_system'),
    ('user assigned',         'identity_category', 'equals', 'managed_identity_user'),
    ('guest',                 'identity_category', 'equals', 'guest'),
    ('guests',                'identity_category', 'equals', 'guest'),
    ('human',                 'identity_category', 'equals', 'human_user'),
    ('humans',                'identity_category', 'equals', 'human_user'),
    # status / activity
    ('dormant',         'activity_status',   'equals', 'inactive'),
    ('inactive',        'activity_status',   'equals', 'inactive'),
    ('stale',           'activity_status',   'equals', 'stale'),
    ('never used',      'activity_status',   'equals', 'never_used'),
    ('never signed in', 'activity_status',   'equals', 'never_used'),
    ('disabled',        'status',            'equals', 'disabled'),
    # credentials
    ('expired',         'credential_risk',   'equals', 'expired'),
    ('expiring',        'credential_risk',   'equals', 'expiring_soon'),
    # federation
    ('federated',       'is_federated',      'equals', True),
    # cloud
    ('azure',           'cloud',             'equals', 'azure'),
    ('aws',             'cloud',             'equals', 'aws'),
    ('gcp',             'cloud',             'equals', 'gcp'),
)


def _match_free_text(text: str) -> Optional[dict[str, Any]]:
    """Best-effort token scan. Returns a low-confidence filter set when
    at least one keyword matches; otherwise None.

    The "AI agents" token is included here as a *fallback* — a bare
    "list AI agents" query that didn't hit any named shortcut still gets
    a structured filter.
    """
    hits: list[dict[str, Any]] = []
    matched_tokens: list[str] = []

    # AI-agent fallback (only if no specific shortcut already matched).
    if _contains_any(text, AI_AGENT_TOKENS):
        hits.append({'field': 'agent_identity_type', 'op': 'equals', 'value': 'ai_agent'})
        matched_tokens.append('ai agent')

    for token, field, op, value in FREE_TEXT_TOKEN_MAP:
        if token in text:
            hits.append({'field': field, 'op': op, 'value': value})
            matched_tokens.append(token)

    if not hits:
        return None

    # De-duplicate by (field, op, value)
    seen = set()
    deduped = []
    for h in hits:
        key = (h['field'], h['op'], str(h['value']))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(h)

    return {
        'intent': 'free_text',
        'filters': deduped,
        'description': 'Free-text match on: ' + ', '.join(matched_tokens),
        'confidence': 'low',
    }


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def translate_nl_query(text: str) -> Optional[dict[str, Any]]:
    """Translate a free-text identity question into a query-builder filter set.

    Args:
        text: the user's question (plain English, any length).

    Returns:
        A translation dict (see module docstring) or ``None`` when the
        question is unrecognised. ``None`` is the honest "I don't know"
        answer — the caller MUST surface that as an empty result rather
        than running an unscoped query.
    """
    norm = _normalise(text)
    if not norm:
        logger.debug("nl_query: empty input")
        return None

    # 1. Named-shortcut matchers (high-confidence intents)
    for matcher in NAMED_SHORTCUTS:
        try:
            result = matcher(norm)
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning("nl_query: shortcut %s raised %s",
                           matcher.__name__, exc, exc_info=True)
            continue
        if result is not None:
            logger.info("nl_query: matched intent=%s confidence=%s",
                        result.get('intent'), result.get('confidence'))
            return result

    # 2. Free-text fallback (low-confidence keyword scan)
    fallback = _match_free_text(norm)
    if fallback is not None:
        logger.info("nl_query: free-text fallback hit tokens=%s",
                    fallback.get('description'))
        return fallback

    # 3. Unknown — never fabricate
    logger.info("nl_query: no match for query=%r", text[:200])
    return None


# Exposed for the handler's test suite.
__all__ = [
    'translate_nl_query',
    'SYNTHETIC_FIELDS',
    'SYNTHETIC_FIELD_HAS_ROLE_NAME',
    'SYNTHETIC_FIELD_HAS_ROLE_CONTAINS',
    'SYNTHETIC_FIELD_SORT_ORDER',
    'SYNTHETIC_FIELD_META',
]
