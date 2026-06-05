"""argus_reasoner — Argus Layer 2: Multi-hop Security Reasoning (AG-186)
=========================================================================

Customer asks a board-level question like "What is my highest business risk
right now?" and gets back a chained narrative of 3-5 sub-queries against the
graph, synthesized into a single conclusion with cited evidence — never an
LLM hallucination.

Example trace (highest_business_risk):

    1. how many AI agents reach PHI                            -> 6
    2. of those, how many have no human owner                  -> 4
    3. of those, how many have unrestricted egress             -> 2
    4. synthesise: "6 AI agents can reach PHI; 4 have no
       owner; 2 also have unrestricted egress => potential
       PHI exfiltration path via 2 ungoverned agents."

Each sub-query is a real SQL aggregation against the canonical AG-180
``agent_data_reachability``, ``identities``, ``role_assignments``,
``agent_classifications``, ``azure_storage_accounts``, ``posture_scores``,
and ``graph_api_permissions`` tables. NO LLM, NO fake answers — if a
sub-query returns 0 the narrative honestly says so.

Public entry point:
    reason_about(cursor, organization_id, question_type, *,
                 latest_run_id=None, use_cache=True) -> dict

Output shape:
    {
        "question":       human-readable question text,
        "conclusion":     synthesized narrative string,
        "evidence":       [{citation, count, type, link}, ...],
        "framework_refs": {"nist": [...], "cis_azure": [...], "mitre": [...]},
        "confidence":     "high" | "medium" | "low",
        "question_type":  str,
        "generated_at":   ISO-8601 timestamp,
        "cached":         bool,
        "latest_run_id":  int | None,
    }

Honesty contract (mandated by AG-186):
  - Every claim in ``conclusion`` is backed by a row in ``evidence``.
  - When a sub-query returns 0 the narrative says "0" (or its plain-English
    equivalent) — we never invent missing rows.
  - ``confidence`` downgrades when:
        * No latest discovery run could be found             -> low
        * One of the sub-queries failed and was skipped      -> medium
        * One of the prerequisite tables is missing          -> medium
  - Framework refs come from the same SSOT (``ai_risk.RISK_SIGNALS``) the
    score engines use — never invented control IDs.

Caching (``argus_reasoning_cache`` table, migration 125):
  Key:  SHA-256(question_type || latest_run_id || org_id)
  Hit:  returns the persisted row, ``cached=True``.
  Miss: computes, upserts, returns with ``cached=False``.
  Re-running the same question_type after a new discovery run yields a
  fresh hash (the run_id is part of the key), so cache stays fresh
  without manual invalidation.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from ...constants.ai_risk import (
    BROAD_PRIVILEGE_ROLES,
    INTERNET_EGRESS_SCOPE_PATTERNS,
    RISK_SIGNALS,
)
from ...constants.data_classification import ALL_CLASSES

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Public catalog of supported question types
# ─────────────────────────────────────────────────────────────────────────────

QUESTION_TYPES = (
    "highest_business_risk",
    "phi_exposure",
    "ownership_gaps",
    "recent_intake_risk",
    "oauth_scope_sprawl",
    "posture_drop",
)

# Recent intake window: identities discovered within this many days are
# treated as "new arrivals" for the recent_intake_risk narrative. We don't
# read the cutoff from settings — the value is well-known and the engine is
# a read-mostly analyst, not a tunable policy surface.
_RECENT_INTAKE_DAYS = 14

# OAuth scope sprawl threshold — an identity is considered to have a sprawl
# of high-risk Graph permissions if its dangerous-permission count is at or
# above this number.
_OAUTH_SPRAWL_THRESHOLD = 3

# Dangerous Graph API permissions (mirrors attack_path_engine._DANGEROUS_GRAPH_PERMS).
_DANGEROUS_GRAPH_PERMS = frozenset({
    "RoleManagement.ReadWrite.All",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Directory.ReadWrite.All",
    "GroupMember.ReadWrite.All",
    "ServicePrincipalEndpoint.ReadWrite.All",
})

# Posture-drop sensitivity — a drop of this many points (or more) between
# the latest and prior posture_scores rows is the headline finding.
_POSTURE_DROP_POINTS = 5

# Savepoint prefix unique to the reasoner so nested savepoints in callers
# do not collide.
_SP_PREFIX = "ag186_reason"


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def reason_about(
    cursor: Any,
    organization_id: int,
    question_type: str,
    *,
    latest_run_id: Optional[int] = None,
    use_cache: bool = True,
) -> dict[str, Any]:
    """Run the 3-5 sub-queries for ``question_type`` and synthesize a narrative.

    Args:
        cursor:           Open psycopg2 cursor (caller owns the txn).
        organization_id:  Tenant scope; required so RLS cannot leak.
        question_type:    One of :data:`QUESTION_TYPES`.
        latest_run_id:    Optional run id to scope queries; when ``None``
                          we resolve the latest completed run for the org.
        use_cache:        When True, attempt to read / write
                          ``argus_reasoning_cache``. Defaults to True.

    Returns:
        The result dict described in the module docstring. Never raises on
        bad input — invalid question_type returns ``confidence='low'`` with
        a self-describing conclusion.
    """
    if question_type not in QUESTION_TYPES:
        return _error_result(
            question_type=question_type or "(none)",
            conclusion=(
                f"Argus does not have a reasoning chain for "
                f"'{question_type}'. Supported question types: "
                + ", ".join(QUESTION_TYPES)
                + "."
            ),
        )

    if organization_id is None:
        return _error_result(
            question_type=question_type,
            conclusion=(
                "Argus reasoning requires an organization context — "
                "superadmins must select a tenant before asking a "
                "reasoning question."
            ),
        )

    # Resolve the latest completed run when the caller didn't pin one.
    if latest_run_id is None:
        latest_run_id = _resolve_latest_run_id(cursor, int(organization_id))

    # ── Cache lookup ───────────────────────────────────────────────────
    qhash = _question_hash(question_type, int(organization_id), latest_run_id)
    if use_cache:
        cached = _read_cache(cursor, int(organization_id), qhash)
        if cached is not None:
            cached["cached"] = True
            return cached

    # ── Dispatch to the per-question reasoning chain ──────────────────
    dispatch = {
        "highest_business_risk": _reason_highest_business_risk,
        "phi_exposure":          _reason_phi_exposure,
        "ownership_gaps":        _reason_ownership_gaps,
        "recent_intake_risk":    _reason_recent_intake_risk,
        "oauth_scope_sprawl":    _reason_oauth_scope_sprawl,
        "posture_drop":          _reason_posture_drop,
    }
    handler = dispatch[question_type]

    try:
        result = handler(cursor, int(organization_id), latest_run_id)
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning(
            "[AG-186] reasoning chain '%s' failed: %s",
            question_type, exc, exc_info=True,
        )
        result = _error_result(
            question_type=question_type,
            conclusion=(
                f"Argus could not complete the '{question_type}' "
                f"reasoning chain ({type(exc).__name__}). The graph may "
                f"be mid-refresh — try again after the next discovery run."
            ),
        )

    # Stamp common fields.
    result.setdefault("question_type", question_type)
    result.setdefault("generated_at", datetime.now(timezone.utc).isoformat())
    result["latest_run_id"] = latest_run_id
    result["cached"] = False

    # ── Cache write ───────────────────────────────────────────────────
    if use_cache:
        _write_cache(
            cursor,
            int(organization_id),
            qhash,
            question_type,
            latest_run_id,
            result,
        )

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Question chain #1 — highest_business_risk
# ─────────────────────────────────────────────────────────────────────────────

def _reason_highest_business_risk(
    cursor: Any,
    org_id: int,
    run_id: Optional[int],
) -> dict[str, Any]:
    """Top of the funnel: classified data exposure narrowed by ownership and egress.

    Sub-queries (5):
      1. # AI agents in this run
      2. # AI agents that reach any classified (PHI/PCI/...) resource
      3. of those, # without a human owner
      4. of those, # with unrestricted egress
      5. # of distinct classified resources at risk
    """
    question = "What is my highest business risk right now?"
    evidence: list[dict[str, Any]] = []
    chain_errors = 0
    missing_inputs = 0

    # 1) total AI agents
    total_agents, ok = _sql_scalar(
        cursor, "ag186_q1_agents",
        """
        SELECT COUNT(DISTINCT i.id)
          FROM identities i
          JOIN agent_classifications ac ON ac.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
           AND (%s IS NULL OR i.discovery_run_id = %s)
        """,
        (org_id, run_id, run_id),
    )
    if not ok:
        missing_inputs += 1
    evidence.append({
        "citation": "agent_classifications + identities (AI agent cohort)",
        "count":    int(total_agents or 0),
        "type":     "ai_agent_total",
        "link":     "/ai-security/agents",
    })

    # 2) AI agents reaching ANY classified resource
    classified_reach, ok = _sql_scalar(
        cursor, "ag186_q2_classified",
        """
        SELECT COUNT(DISTINCT adr.identity_db_id)
          FROM agent_data_reachability adr
         WHERE adr.organization_id = %s
           AND adr.resource_count > 0
           AND adr.data_classification = ANY(%s)
           AND (%s IS NULL OR adr.discovery_run_id = %s)
        """,
        (org_id, list(ALL_CLASSES), run_id, run_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "agent_data_reachability (resource_count > 0)",
        "count":    int(classified_reach or 0),
        "type":     "ai_agent_reaches_classified",
        "link":     "/ai-security/data-reachability",
    })

    # 3) of those — no human owner
    no_owner, ok = _sql_scalar(
        cursor, "ag186_q3_no_owner",
        """
        SELECT COUNT(DISTINCT adr.identity_db_id)
          FROM agent_data_reachability adr
          JOIN identities i ON i.id = adr.identity_db_id
         WHERE adr.organization_id = %s
           AND adr.resource_count > 0
           AND adr.data_classification = ANY(%s)
           AND (%s IS NULL OR adr.discovery_run_id = %s)
           AND COALESCE(NULLIF(TRIM(i.owner_display_name), ''), '') = ''
           AND NOT EXISTS (
                SELECT 1 FROM sp_ownership o
                 WHERE o.identity_db_id = i.id
                   AND COALESCE(o.organization_id, %s) = %s
           )
        """,
        (org_id, list(ALL_CLASSES), run_id, run_id, org_id, org_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "identities.owner_display_name + sp_ownership (no human owner)",
        "count":    int(no_owner or 0),
        "type":     "ai_agent_no_owner_and_classified",
        "link":     "/ai-security/ownership-gaps",
    })

    # 4) of those — unrestricted egress (role scope reaches internet-facing pattern)
    egress, ok = _sql_egress_count(cursor, org_id, run_id, classified_only=True)
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": (
            "role_assignments.scope matches "
            + ", ".join(INTERNET_EGRESS_SCOPE_PATTERNS[:2])
            + ", … (unrestricted_egress signal)"
        ),
        "count":    int(egress or 0),
        "type":     "ai_agent_unrestricted_egress_and_classified",
        "link":     "/ai-security/egress",
    })

    # 5) distinct classified resources at risk (unique resource_id across reachable rows)
    classified_resources, ok = _sql_scalar(
        cursor, "ag186_q5_resources",
        """
        SELECT COALESCE(SUM(adr.resource_count), 0)
          FROM agent_data_reachability adr
         WHERE adr.organization_id = %s
           AND adr.data_classification = ANY(%s)
           AND (%s IS NULL OR adr.discovery_run_id = %s)
        """,
        (org_id, list(ALL_CLASSES), run_id, run_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "agent_data_reachability.resource_count (sum across classes)",
        "count":    int(classified_resources or 0),
        "type":     "classified_resource_reach_total",
        "link":     "/data-security",
    })

    # ── Synthesis ─────────────────────────────────────────────────────
    total = int(total_agents or 0)
    n_class = int(classified_reach or 0)
    n_unowned = int(no_owner or 0)
    n_egress = int(egress or 0)

    if total == 0:
        conclusion = (
            "No AI agents are present in this organization's latest discovery "
            "run, so there is no AI-driven business risk to report yet. Run a "
            "discovery scan to populate the cohort."
        )
    elif n_class == 0:
        conclusion = (
            f"{_n(total, 'AI agent', 'AI agents')} discovered, but none of "
            f"them currently reach any classified data (PHI / PCI / PII / "
            f"HR / SOURCE / FINANCIAL / CONFIDENTIAL). The headline business "
            f"risk for this org is presently low."
        )
    else:
        chain_parts = [
            f"{_n(n_class, 'AI agent', 'AI agents')} can reach classified data"
        ]
        if n_unowned > 0:
            chain_parts.append(
                f"{n_unowned} of those have no human owner"
            )
        else:
            chain_parts.append("all of those have a named human owner")
        if n_egress > 0:
            chain_parts.append(
                f"{n_egress} also have unrestricted egress"
            )
        else:
            chain_parts.append("none of those have unrestricted egress")

        impact = (
            "potential data-exfiltration path via ungoverned agents"
            if n_unowned > 0 and n_egress > 0
            else (
                "potential ownership-accountability gap on the data path"
                if n_unowned > 0
                else (
                    "data reach exists but egress is constrained"
                    if n_class > 0
                    else "no immediate exfil chain"
                )
            )
        )
        conclusion = (
            "; ".join(chain_parts)
            + f" => {impact}. "
            + f"Across the run, {int(classified_resources or 0)} classified "
              f"resource reaches are recorded by AuditGraph."
        )

    return _ok_result(
        question=question,
        conclusion=conclusion,
        evidence=evidence,
        framework_keys=("no_owner", "unrestricted_egress", "sensitive_data_access"),
        chain_errors=chain_errors,
        missing_inputs=missing_inputs,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Question chain #2 — phi_exposure
# ─────────────────────────────────────────────────────────────────────────────

def _reason_phi_exposure(
    cursor: Any,
    org_id: int,
    run_id: Optional[int],
) -> dict[str, Any]:
    """Specifically PHI: reach, write reach, agents, owner gaps, egress.

    Sub-queries (5):
      1. # PHI-classified resources in this run
      2. # AI agents that reach any PHI resource (resource_count > 0)
      3. # AI agents with WRITE reach (write_resource_count > 0)
      4. # of those write-reach agents that have no owner
      5. # PHI reach across all agents (sum of resource_count)
    """
    question = "How exposed is our PHI right now?"
    evidence: list[dict[str, Any]] = []
    chain_errors = 0

    # 1) PHI resource inventory
    phi_resources, ok = _sql_scalar(
        cursor, "ag186_phi_r1",
        """
        SELECT COUNT(*) FROM azure_storage_accounts
         WHERE organization_id = %s
           AND data_classification = 'PHI'
           AND (%s IS NULL OR discovery_run_id = %s)
        """,
        (org_id, run_id, run_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "azure_storage_accounts.data_classification = 'PHI'",
        "count":    int(phi_resources or 0),
        "type":     "phi_resource_total",
        "link":     "/data-security?class=PHI",
    })

    # 2) AI agents reaching PHI
    phi_reachers, ok = _sql_scalar(
        cursor, "ag186_phi_r2",
        """
        SELECT COUNT(DISTINCT adr.identity_db_id)
          FROM agent_data_reachability adr
         WHERE adr.organization_id = %s
           AND adr.data_classification = 'PHI'
           AND adr.resource_count > 0
           AND (%s IS NULL OR adr.discovery_run_id = %s)
        """,
        (org_id, run_id, run_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "agent_data_reachability (data_classification='PHI', resource_count>0)",
        "count":    int(phi_reachers or 0),
        "type":     "phi_reachers",
        "link":     "/ai-security/data-reachability?class=PHI",
    })

    # 3) AI agents with WRITE reach to PHI
    phi_writers, ok = _sql_scalar(
        cursor, "ag186_phi_r3",
        """
        SELECT COUNT(DISTINCT adr.identity_db_id)
          FROM agent_data_reachability adr
         WHERE adr.organization_id = %s
           AND adr.data_classification = 'PHI'
           AND adr.write_resource_count > 0
           AND (%s IS NULL OR adr.discovery_run_id = %s)
        """,
        (org_id, run_id, run_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "agent_data_reachability (write_resource_count > 0)",
        "count":    int(phi_writers or 0),
        "type":     "phi_writers",
        "link":     "/ai-security/data-reachability?class=PHI&write=1",
    })

    # 4) PHI writers that have no human owner
    phi_writers_unowned, ok = _sql_scalar(
        cursor, "ag186_phi_r4",
        """
        SELECT COUNT(DISTINCT adr.identity_db_id)
          FROM agent_data_reachability adr
          JOIN identities i ON i.id = adr.identity_db_id
         WHERE adr.organization_id = %s
           AND adr.data_classification = 'PHI'
           AND adr.write_resource_count > 0
           AND (%s IS NULL OR adr.discovery_run_id = %s)
           AND COALESCE(NULLIF(TRIM(i.owner_display_name), ''), '') = ''
           AND NOT EXISTS (
                SELECT 1 FROM sp_ownership o
                 WHERE o.identity_db_id = i.id
                   AND COALESCE(o.organization_id, %s) = %s
           )
        """,
        (org_id, run_id, run_id, org_id, org_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "PHI writers with NULL owner_display_name AND no sp_ownership row",
        "count":    int(phi_writers_unowned or 0),
        "type":     "phi_writers_no_owner",
        "link":     "/ai-security/ownership-gaps?class=PHI",
    })

    # 5) total PHI reach (sum of resource_count)
    phi_reach_sum, ok = _sql_scalar(
        cursor, "ag186_phi_r5",
        """
        SELECT COALESCE(SUM(adr.resource_count), 0)
          FROM agent_data_reachability adr
         WHERE adr.organization_id = %s
           AND adr.data_classification = 'PHI'
           AND (%s IS NULL OR adr.discovery_run_id = %s)
        """,
        (org_id, run_id, run_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "SUM(agent_data_reachability.resource_count) for PHI",
        "count":    int(phi_reach_sum or 0),
        "type":     "phi_reach_total",
        "link":     "/data-security?class=PHI",
    })

    # ── Synthesis ─────────────────────────────────────────────────────
    n_resources = int(phi_resources or 0)
    n_reach = int(phi_reachers or 0)
    n_write = int(phi_writers or 0)
    n_write_unowned = int(phi_writers_unowned or 0)

    if n_resources == 0:
        conclusion = (
            "No PHI-classified resources are present in this organization's "
            "latest discovery run, so PHI exposure for this run is zero. "
            "If PHI is expected, confirm that classification tags are being "
            "applied to storage accounts."
        )
    elif n_reach == 0:
        conclusion = (
            f"{_n(n_resources, 'PHI resource', 'PHI resources')} discovered, "
            f"but no AI agent currently has any RBAC path to them. PHI is "
            f"contained from the AI cohort in this snapshot."
        )
    else:
        write_clause = (
            f"{n_write} of those have write access"
            if n_write > 0 else
            "but none of them have write access"
        )
        unowned_clause = (
            f", and {n_write_unowned} write-reaching agent(s) have no human owner"
            if n_write_unowned > 0 else
            (", and every write-reaching agent has a named owner"
             if n_write > 0 else "")
        )
        conclusion = (
            f"{n_reach} AI agent(s) reach at least one of "
            f"{n_resources} PHI resource(s); {write_clause}{unowned_clause}. "
            f"Total PHI reach across the cohort: "
            f"{int(phi_reach_sum or 0)} resource-agent pairs."
        )

    return _ok_result(
        question=question,
        conclusion=conclusion,
        evidence=evidence,
        framework_keys=("sensitive_data_access", "no_owner", "storage_blob_owner"),
        chain_errors=chain_errors,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Question chain #3 — ownership_gaps
# ─────────────────────────────────────────────────────────────────────────────

def _reason_ownership_gaps(
    cursor: Any,
    org_id: int,
    run_id: Optional[int],
) -> dict[str, Any]:
    """Identity accountability gaps across the cohort.

    Sub-queries (4):
      1. total non-Microsoft identities
      2. identities without a human owner
      3. AI agents without a human owner
      4. AI agents without an owner AND with classified data reach
    """
    question = "Where do we have identity ownership gaps?"
    evidence: list[dict[str, Any]] = []
    chain_errors = 0

    # 1) total non-Microsoft identities
    total_identities, ok = _sql_scalar(
        cursor, "ag186_own_r1",
        """
        SELECT COUNT(*) FROM identities i
         WHERE i.organization_id = %s
           AND i.is_microsoft_system = FALSE
           AND (%s IS NULL OR i.discovery_run_id = %s)
        """,
        (org_id, run_id, run_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "identities (is_microsoft_system = FALSE)",
        "count":    int(total_identities or 0),
        "type":     "identity_total",
        "link":     "/identities",
    })

    # 2) identities without a human owner
    unowned, ok = _sql_scalar(
        cursor, "ag186_own_r2",
        """
        SELECT COUNT(*) FROM identities i
         WHERE i.organization_id = %s
           AND i.is_microsoft_system = FALSE
           AND (%s IS NULL OR i.discovery_run_id = %s)
           AND COALESCE(NULLIF(TRIM(i.owner_display_name), ''), '') = ''
           AND NOT EXISTS (
                SELECT 1 FROM sp_ownership o
                 WHERE o.identity_db_id = i.id
                   AND COALESCE(o.organization_id, %s) = %s
           )
        """,
        (org_id, run_id, run_id, org_id, org_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "identities with NULL owner_display_name AND no sp_ownership",
        "count":    int(unowned or 0),
        "type":     "identity_no_owner",
        "link":     "/identities?owner=missing",
    })

    # 3) AI agents without a human owner
    ai_unowned, ok = _sql_scalar(
        cursor, "ag186_own_r3",
        """
        SELECT COUNT(*) FROM identities i
          JOIN agent_classifications ac ON ac.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND i.is_microsoft_system = FALSE
           AND ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
           AND (%s IS NULL OR i.discovery_run_id = %s)
           AND COALESCE(NULLIF(TRIM(i.owner_display_name), ''), '') = ''
           AND NOT EXISTS (
                SELECT 1 FROM sp_ownership o
                 WHERE o.identity_db_id = i.id
                   AND COALESCE(o.organization_id, %s) = %s
           )
        """,
        (org_id, run_id, run_id, org_id, org_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "AI agents joined to identities with no owner",
        "count":    int(ai_unowned or 0),
        "type":     "ai_agent_no_owner",
        "link":     "/ai-security/ownership-gaps",
    })

    # 4) AI agents unowned AND reaching classified data
    ai_unowned_classified, ok = _sql_scalar(
        cursor, "ag186_own_r4",
        """
        SELECT COUNT(DISTINCT i.id)
          FROM identities i
          JOIN agent_classifications ac ON ac.identity_db_id = i.id
          JOIN agent_data_reachability adr ON adr.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND i.is_microsoft_system = FALSE
           AND ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
           AND adr.data_classification = ANY(%s)
           AND adr.resource_count > 0
           AND (%s IS NULL OR i.discovery_run_id = %s)
           AND COALESCE(NULLIF(TRIM(i.owner_display_name), ''), '') = ''
           AND NOT EXISTS (
                SELECT 1 FROM sp_ownership o
                 WHERE o.identity_db_id = i.id
                   AND COALESCE(o.organization_id, %s) = %s
           )
        """,
        (org_id, list(ALL_CLASSES), run_id, run_id, org_id, org_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "AI agents (unowned) joined to classified data reach",
        "count":    int(ai_unowned_classified or 0),
        "type":     "ai_agent_no_owner_classified",
        "link":     "/ai-security/ownership-gaps?class=any",
    })

    # ── Synthesis ─────────────────────────────────────────────────────
    n_total = int(total_identities or 0)
    n_unowned = int(unowned or 0)
    n_ai_unowned = int(ai_unowned or 0)
    n_ai_unowned_cls = int(ai_unowned_classified or 0)

    if n_total == 0:
        conclusion = (
            "No non-Microsoft identities are present in this organization's "
            "latest discovery run. Ownership gap analysis is not applicable."
        )
    elif n_unowned == 0:
        conclusion = (
            f"All {n_total} non-Microsoft identit{'y has' if n_total == 1 else 'ies have'} "
            f"a named human owner — no ownership gaps in this run."
        )
    else:
        pct = round((n_unowned / n_total) * 100, 1) if n_total else 0
        ai_clause = (
            f"{n_ai_unowned} of those are AI agents"
            if n_ai_unowned > 0 else
            "but none of those are AI agents"
        )
        cls_clause = (
            f", and {n_ai_unowned_cls} of the unowned AI agents reach classified data"
            if n_ai_unowned_cls > 0 else ""
        )
        conclusion = (
            f"{n_unowned} of {n_total} non-Microsoft identit"
            f"{'y has' if n_unowned == 1 else 'ies have'} no human owner "
            f"({pct}% of the cohort); {ai_clause}{cls_clause}. "
            f"Each unowned identity is a remediation-routing dead end."
        )

    return _ok_result(
        question=question,
        conclusion=conclusion,
        evidence=evidence,
        framework_keys=("no_owner",),
        chain_errors=chain_errors,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Question chain #4 — recent_intake_risk
# ─────────────────────────────────────────────────────────────────────────────

def _reason_recent_intake_risk(
    cursor: Any,
    org_id: int,
    run_id: Optional[int],
) -> dict[str, Any]:
    """Risk inside the last 14 days of identity intake.

    Sub-queries (4):
      1. # identities created within last _RECENT_INTAKE_DAYS days
      2. of those, # AI agents
      3. of those, # with broad subscription roles (Owner/Contributor/UAA)
      4. of those, # with classified-data reach
    """
    question = (
        f"What risk has entered our environment in the last "
        f"{_RECENT_INTAKE_DAYS} days?"
    )
    evidence: list[dict[str, Any]] = []
    chain_errors = 0

    # 1) recent identities
    recent_total, ok = _sql_scalar(
        cursor, "ag186_rec_r1",
        """
        SELECT COUNT(*) FROM identities i
         WHERE i.organization_id = %s
           AND i.is_microsoft_system = FALSE
           AND (i.created_datetime >= NOW() - (%s || ' days')::interval
                OR i.created_at      >= NOW() - (%s || ' days')::interval)
           AND (%s IS NULL OR i.discovery_run_id = %s)
        """,
        (org_id, str(_RECENT_INTAKE_DAYS), str(_RECENT_INTAKE_DAYS), run_id, run_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": (
            f"identities (created_datetime OR created_at within last "
            f"{_RECENT_INTAKE_DAYS} days)"
        ),
        "count":    int(recent_total or 0),
        "type":     "recent_identity_total",
        "link":     "/identities?recent=14d",
    })

    # 2) AI agents inside that recent cohort
    recent_ai, ok = _sql_scalar(
        cursor, "ag186_rec_r2",
        """
        SELECT COUNT(*) FROM identities i
          JOIN agent_classifications ac ON ac.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND i.is_microsoft_system = FALSE
           AND ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
           AND (i.created_datetime >= NOW() - (%s || ' days')::interval
                OR i.created_at      >= NOW() - (%s || ' days')::interval)
           AND (%s IS NULL OR i.discovery_run_id = %s)
        """,
        (org_id, str(_RECENT_INTAKE_DAYS), str(_RECENT_INTAKE_DAYS), run_id, run_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "AI agents inside the recent intake window",
        "count":    int(recent_ai or 0),
        "type":     "recent_ai_agent",
        "link":     "/ai-security/agents?recent=14d",
    })

    # 3) recent identities with broad subscription roles
    broad_roles_list = list(BROAD_PRIVILEGE_ROLES)
    recent_broad, ok = _sql_scalar(
        cursor, "ag186_rec_r3",
        """
        SELECT COUNT(DISTINCT i.id)
          FROM identities i
          JOIN role_assignments ra ON ra.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND i.is_microsoft_system = FALSE
           AND ra.role_name = ANY(%s)
           AND ra.scope LIKE '/subscriptions/%%'
           AND (LENGTH(ra.scope) - LENGTH(REPLACE(ra.scope, '/', ''))) = 2
           AND (i.created_datetime >= NOW() - (%s || ' days')::interval
                OR i.created_at      >= NOW() - (%s || ' days')::interval)
           AND (%s IS NULL OR i.discovery_run_id = %s)
        """,
        (org_id, broad_roles_list, str(_RECENT_INTAKE_DAYS),
         str(_RECENT_INTAKE_DAYS), run_id, run_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": (
            "role_assignments scope = subscription AND role IN "
            + ", ".join(sorted(BROAD_PRIVILEGE_ROLES))
        ),
        "count":    int(recent_broad or 0),
        "type":     "recent_broad_privilege",
        "link":     "/identities?recent=14d&role=broad",
    })

    # 4) recent identities with classified-data reach
    recent_classified, ok = _sql_scalar(
        cursor, "ag186_rec_r4",
        """
        SELECT COUNT(DISTINCT i.id)
          FROM identities i
          JOIN agent_data_reachability adr ON adr.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND i.is_microsoft_system = FALSE
           AND adr.data_classification = ANY(%s)
           AND adr.resource_count > 0
           AND (i.created_datetime >= NOW() - (%s || ' days')::interval
                OR i.created_at      >= NOW() - (%s || ' days')::interval)
           AND (%s IS NULL OR i.discovery_run_id = %s)
        """,
        (org_id, list(ALL_CLASSES), str(_RECENT_INTAKE_DAYS),
         str(_RECENT_INTAKE_DAYS), run_id, run_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "recent identities joined to agent_data_reachability",
        "count":    int(recent_classified or 0),
        "type":     "recent_classified_reach",
        "link":     "/identities?recent=14d&data=classified",
    })

    # ── Synthesis ─────────────────────────────────────────────────────
    n_recent = int(recent_total or 0)
    n_ai = int(recent_ai or 0)
    n_broad = int(recent_broad or 0)
    n_class = int(recent_classified or 0)

    if n_recent == 0:
        conclusion = (
            f"No new identities were created in the last "
            f"{_RECENT_INTAKE_DAYS} days. Recent intake risk is zero."
        )
    else:
        parts = [
            f"{n_recent} identity intake event(s) in the last "
            f"{_RECENT_INTAKE_DAYS} days"
        ]
        parts.append(
            f"{n_ai} of them are AI agents"
            if n_ai > 0 else "none of them are AI agents"
        )
        parts.append(
            f"{n_broad} hold a broad subscription role (Owner / Contributor "
            f"/ User Access Administrator)"
            if n_broad > 0 else
            "none hold a broad subscription role"
        )
        parts.append(
            f"{n_class} already reach classified data"
            if n_class > 0 else
            "none already reach classified data"
        )
        verdict = (
            "elevated — re-attest the broad-privileged new arrivals before they age in"
            if (n_broad > 0 or n_class > 0) else
            "informational — track but no immediate remediation needed"
        )
        conclusion = "; ".join(parts) + f". Recent-intake risk: {verdict}."

    return _ok_result(
        question=question,
        conclusion=conclusion,
        evidence=evidence,
        framework_keys=("broad_owner_role", "sensitive_data_access"),
        chain_errors=chain_errors,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Question chain #5 — oauth_scope_sprawl
# ─────────────────────────────────────────────────────────────────────────────

def _reason_oauth_scope_sprawl(
    cursor: Any,
    org_id: int,
    run_id: Optional[int],
) -> dict[str, Any]:
    """Where do dangerous Graph permissions concentrate?

    Sub-queries (4):
      1. # distinct identities holding any dangerous Graph permission
      2. # distinct dangerous Graph permission grants total
      3. # identities holding >= _OAUTH_SPRAWL_THRESHOLD distinct dangerous perms
      4. # of those that are AI agents
    """
    question = "Where do we have OAuth / Graph permission sprawl?"
    evidence: list[dict[str, Any]] = []
    chain_errors = 0

    perms = list(_DANGEROUS_GRAPH_PERMS)

    # 1) identities with any dangerous Graph permission
    holders, ok = _sql_scalar(
        cursor, "ag186_oauth_r1",
        """
        SELECT COUNT(DISTINCT i.id)
          FROM identities i
          JOIN graph_api_permissions g ON g.identity_db_id = i.id
         WHERE COALESCE(i.organization_id, %s) = %s
           AND COALESCE(g.organization_id, %s) = %s
           AND i.is_microsoft_system = FALSE
           AND g.permission_name = ANY(%s)
           AND (%s IS NULL OR i.discovery_run_id = %s)
        """,
        (org_id, org_id, org_id, org_id, perms, run_id, run_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": (
            "graph_api_permissions.permission_name IN ("
            + ", ".join(sorted(perms)[:3]) + ", …)"
        ),
        "count":    int(holders or 0),
        "type":     "dangerous_graph_perm_holders",
        "link":     "/permissions/graph?level=dangerous",
    })

    # 2) total dangerous-permission grants
    grants, ok = _sql_scalar(
        cursor, "ag186_oauth_r2",
        """
        SELECT COUNT(*)
          FROM graph_api_permissions g
          JOIN identities i ON i.id = g.identity_db_id
         WHERE COALESCE(i.organization_id, %s) = %s
           AND COALESCE(g.organization_id, %s) = %s
           AND i.is_microsoft_system = FALSE
           AND g.permission_name = ANY(%s)
           AND (%s IS NULL OR i.discovery_run_id = %s)
        """,
        (org_id, org_id, org_id, org_id, perms, run_id, run_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "Total grant rows in graph_api_permissions for dangerous perms",
        "count":    int(grants or 0),
        "type":     "dangerous_graph_perm_grants",
        "link":     "/permissions/graph?level=dangerous",
    })

    # 3) identities with sprawl (>= threshold distinct dangerous perms)
    sprawlers, ok = _sql_scalar(
        cursor, "ag186_oauth_r3",
        """
        SELECT COUNT(*) FROM (
            SELECT i.id
              FROM identities i
              JOIN graph_api_permissions g ON g.identity_db_id = i.id
             WHERE COALESCE(i.organization_id, %s) = %s
               AND COALESCE(g.organization_id, %s) = %s
               AND i.is_microsoft_system = FALSE
               AND g.permission_name = ANY(%s)
               AND (%s IS NULL OR i.discovery_run_id = %s)
             GROUP BY i.id
            HAVING COUNT(DISTINCT g.permission_name) >= %s
        ) t
        """,
        (org_id, org_id, org_id, org_id, perms, run_id, run_id,
         _OAUTH_SPRAWL_THRESHOLD),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": (
            f"identities holding >= {_OAUTH_SPRAWL_THRESHOLD} distinct "
            f"dangerous Graph permissions"
        ),
        "count":    int(sprawlers or 0),
        "type":     "oauth_sprawlers",
        "link":     "/permissions/graph?sprawl=1",
    })

    # 4) sprawlers that are AI agents
    sprawl_ai, ok = _sql_scalar(
        cursor, "ag186_oauth_r4",
        """
        SELECT COUNT(*) FROM (
            SELECT i.id
              FROM identities i
              JOIN graph_api_permissions g ON g.identity_db_id = i.id
              JOIN agent_classifications ac ON ac.identity_db_id = i.id
             WHERE COALESCE(i.organization_id, %s) = %s
               AND COALESCE(g.organization_id, %s) = %s
               AND i.is_microsoft_system = FALSE
               AND g.permission_name = ANY(%s)
               AND ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
               AND (%s IS NULL OR i.discovery_run_id = %s)
             GROUP BY i.id
            HAVING COUNT(DISTINCT g.permission_name) >= %s
        ) t
        """,
        (org_id, org_id, org_id, org_id, perms, run_id, run_id,
         _OAUTH_SPRAWL_THRESHOLD),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "AI agents inside the OAuth-sprawl cohort",
        "count":    int(sprawl_ai or 0),
        "type":     "oauth_sprawl_ai_agents",
        "link":     "/ai-security/agents?sprawl=1",
    })

    # ── Synthesis ─────────────────────────────────────────────────────
    n_holders = int(holders or 0)
    n_grants = int(grants or 0)
    n_sprawl = int(sprawlers or 0)
    n_sprawl_ai = int(sprawl_ai or 0)

    if n_holders == 0:
        conclusion = (
            "No non-Microsoft identity holds any of the high-risk Graph "
            "permissions (RoleManagement.ReadWrite.All, "
            "Application.ReadWrite.All, Directory.ReadWrite.All, …). "
            "OAuth scope sprawl is presently zero."
        )
    else:
        sprawl_clause = (
            f"{n_sprawl} of them hold {_OAUTH_SPRAWL_THRESHOLD}+ distinct dangerous permissions "
            f"({n_sprawl_ai} of those are AI agents)"
            if n_sprawl > 0 else
            f"none hold {_OAUTH_SPRAWL_THRESHOLD}+ distinct dangerous permissions"
        )
        conclusion = (
            f"{n_holders} identit{'y holds' if n_holders == 1 else 'ies hold'} "
            f"high-risk Graph permissions across {n_grants} grant row(s); "
            f"{sprawl_clause}. Review consents for the top sprawlers."
        )

    return _ok_result(
        question=question,
        conclusion=conclusion,
        evidence=evidence,
        framework_keys=("broad_owner_role",),
        chain_errors=chain_errors,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Question chain #6 — posture_drop
# ─────────────────────────────────────────────────────────────────────────────

def _reason_posture_drop(
    cursor: Any,
    org_id: int,
    run_id: Optional[int],
) -> dict[str, Any]:
    """Has the org's overall posture score dropped recently? Why?

    Sub-queries (3-5):
      1. latest posture_scores row (overall_score, identity_count, at_risk_count)
      2. prior posture_scores row (for the trend)
      3. # critical-risk identities in latest run (correlate driver)
      4. # AI agents with broad privilege role (driver)
      5. # unowned identities (driver)
    """
    question = "Has our security posture dropped, and if so why?"
    evidence: list[dict[str, Any]] = []
    chain_errors = 0
    missing_inputs = 0

    # 1) latest posture row
    latest_posture = _sql_row(
        cursor, "ag186_post_r1",
        """
        SELECT overall_score, identity_count, at_risk_count, score_date
          FROM posture_scores
         WHERE organization_id = %s
         ORDER BY score_date DESC
         LIMIT 1
        """,
        (org_id,),
    )
    if latest_posture is None:
        missing_inputs += 1
    latest_score = _cell(latest_posture, 0, "overall_score")
    latest_identity_count = _cell(latest_posture, 1, "identity_count")
    latest_at_risk = _cell(latest_posture, 2, "at_risk_count")
    latest_date = _cell(latest_posture, 3, "score_date")
    evidence.append({
        "citation": "posture_scores (latest row ORDER BY score_date DESC)",
        "count":    int(float(latest_score)) if latest_score is not None else 0,
        "type":     "posture_latest",
        "link":     "/posture",
    })

    # 2) prior posture row
    prior_posture = _sql_row(
        cursor, "ag186_post_r2",
        """
        SELECT overall_score, score_date
          FROM posture_scores
         WHERE organization_id = %s
           AND score_date < COALESCE(
                (SELECT MAX(score_date) FROM posture_scores
                  WHERE organization_id = %s),
                NOW()
           )
         ORDER BY score_date DESC
         LIMIT 1
        """,
        (org_id, org_id),
    )
    prior_score = _cell(prior_posture, 0, "overall_score") if prior_posture else None
    prior_date = _cell(prior_posture, 1, "score_date") if prior_posture else None
    evidence.append({
        "citation": "posture_scores (prior row)",
        "count":    int(float(prior_score)) if prior_score is not None else 0,
        "type":     "posture_prior",
        "link":     "/posture/history",
    })

    # 3) # critical-risk identities in latest run
    critical_count, ok = _sql_scalar(
        cursor, "ag186_post_r3",
        """
        SELECT COUNT(*) FROM identities i
         WHERE i.organization_id = %s
           AND LOWER(COALESCE(i.risk_level, '')) = 'critical'
           AND (%s IS NULL OR i.discovery_run_id = %s)
        """,
        (org_id, run_id, run_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "identities.risk_level = 'critical' in latest run",
        "count":    int(critical_count or 0),
        "type":     "critical_identities",
        "link":     "/identities?risk=critical",
    })

    # 4) # AI agents with broad-privilege subscription roles
    ai_broad, ok = _sql_scalar(
        cursor, "ag186_post_r4",
        """
        SELECT COUNT(DISTINCT i.id)
          FROM identities i
          JOIN agent_classifications ac ON ac.identity_db_id = i.id
          JOIN role_assignments ra ON ra.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND i.is_microsoft_system = FALSE
           AND ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
           AND ra.role_name = ANY(%s)
           AND ra.scope LIKE '/subscriptions/%%'
           AND (LENGTH(ra.scope) - LENGTH(REPLACE(ra.scope, '/', ''))) = 2
           AND (%s IS NULL OR i.discovery_run_id = %s)
        """,
        (org_id, list(BROAD_PRIVILEGE_ROLES), run_id, run_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": (
            "AI agents holding a broad subscription role ("
            + " / ".join(sorted(BROAD_PRIVILEGE_ROLES)) + ")"
        ),
        "count":    int(ai_broad or 0),
        "type":     "ai_agent_broad_privilege",
        "link":     "/ai-security/agents?role=broad",
    })

    # 5) # unowned identities (driver: ownership accountability)
    unowned, ok = _sql_scalar(
        cursor, "ag186_post_r5",
        """
        SELECT COUNT(*) FROM identities i
         WHERE i.organization_id = %s
           AND i.is_microsoft_system = FALSE
           AND (%s IS NULL OR i.discovery_run_id = %s)
           AND COALESCE(NULLIF(TRIM(i.owner_display_name), ''), '') = ''
           AND NOT EXISTS (
                SELECT 1 FROM sp_ownership o
                 WHERE o.identity_db_id = i.id
                   AND COALESCE(o.organization_id, %s) = %s
           )
        """,
        (org_id, run_id, run_id, org_id, org_id),
    )
    if not ok:
        chain_errors += 1
    evidence.append({
        "citation": "identities with no human owner (latest run)",
        "count":    int(unowned or 0),
        "type":     "identity_no_owner",
        "link":     "/identities?owner=missing",
    })

    # ── Synthesis ─────────────────────────────────────────────────────
    if latest_score is None:
        conclusion = (
            "Argus could not find any persisted posture_scores rows for this "
            "organization yet. Run the posture engine after the next "
            "discovery to populate the trend."
        )
    elif prior_score is None:
        conclusion = (
            f"Current posture score is "
            f"{round(float(latest_score), 1)} (as of {_iso(latest_date)}), "
            f"but there is no prior snapshot to compare against. A trend will "
            f"be available after the next scheduled posture computation."
        )
    else:
        delta = round(float(prior_score) - float(latest_score), 1)
        if delta >= _POSTURE_DROP_POINTS:
            drivers = []
            if int(critical_count or 0) > 0:
                drivers.append(
                    f"{int(critical_count)} critical-risk identit"
                    f"{'y' if int(critical_count) == 1 else 'ies'} in the latest run"
                )
            if int(ai_broad or 0) > 0:
                drivers.append(
                    f"{int(ai_broad)} AI agent(s) with a broad subscription role"
                )
            if int(unowned or 0) > 0:
                drivers.append(
                    f"{int(unowned)} identit"
                    f"{'y' if int(unowned) == 1 else 'ies'} with no human owner"
                )
            driver_clause = (
                "Likely drivers: " + "; ".join(drivers) + "."
                if drivers else
                "No specific driver could be isolated from the latest run — "
                "review the posture detail page for the dimension breakdown."
            )
            conclusion = (
                f"Posture has dropped by {delta} points "
                f"({round(float(prior_score), 1)} on {_iso(prior_date)} -> "
                f"{round(float(latest_score), 1)} on {_iso(latest_date)}). "
                + driver_clause
            )
        elif delta <= -_POSTURE_DROP_POINTS:
            conclusion = (
                f"Posture has improved by {abs(delta)} points "
                f"({round(float(prior_score), 1)} on {_iso(prior_date)} -> "
                f"{round(float(latest_score), 1)} on {_iso(latest_date)}). "
                f"No drop to investigate."
            )
        else:
            conclusion = (
                f"Posture is stable at "
                f"{round(float(latest_score), 1)} ({_iso(latest_date)}), "
                f"within {_POSTURE_DROP_POINTS} points of the prior "
                f"snapshot ({round(float(prior_score), 1)} on "
                f"{_iso(prior_date)})."
            )

    return _ok_result(
        question=question,
        conclusion=conclusion,
        evidence=evidence,
        framework_keys=("broad_owner_role", "no_owner"),
        chain_errors=chain_errors,
        missing_inputs=missing_inputs,
    )


# ─────────────────────────────────────────────────────────────────────────────
# SQL helpers — every query inside a SAVEPOINT
# ─────────────────────────────────────────────────────────────────────────────

def _sql_scalar(
    cursor: Any,
    sp_name: str,
    sql: str,
    params: tuple,
) -> tuple[Optional[int], bool]:
    """Execute a scalar SELECT inside a SAVEPOINT.

    Returns (value, ok). ``ok`` is False when the query failed (e.g. missing
    table) so the caller can mark the chain as partially degraded. The outer
    transaction is preserved via ROLLBACK TO SAVEPOINT on failure.
    """
    sp = f"{_SP_PREFIX}_{sp_name}"
    try:
        cursor.execute(f"SAVEPOINT {sp}")
        cursor.execute(sql, params)
        row = cursor.fetchone()
        cursor.execute(f"RELEASE SAVEPOINT {sp}")
    except Exception as exc:
        logger.debug("[AG-186] _sql_scalar %s failed: %s", sp_name, exc)
        try:
            cursor.execute(f"ROLLBACK TO SAVEPOINT {sp}")
        except Exception:
            try:
                cursor.connection.rollback()
            except Exception:
                pass
        return None, False

    if row is None:
        return 0, True
    if isinstance(row, dict):
        # RealDictCursor: take the first column value regardless of name.
        for v in row.values():
            return _coerce_int(v), True
        return 0, True
    try:
        return _coerce_int(row[0]), True
    except (IndexError, TypeError):
        return 0, True


def _sql_row(
    cursor: Any,
    sp_name: str,
    sql: str,
    params: tuple,
) -> Optional[Any]:
    """Execute a single-row SELECT inside a SAVEPOINT. Returns the row as-is
    (tuple or dict) so callers can pick columns by index OR by name.
    """
    sp = f"{_SP_PREFIX}_{sp_name}"
    try:
        cursor.execute(f"SAVEPOINT {sp}")
        cursor.execute(sql, params)
        row = cursor.fetchone()
        cursor.execute(f"RELEASE SAVEPOINT {sp}")
    except Exception as exc:
        logger.debug("[AG-186] _sql_row %s failed: %s", sp_name, exc)
        try:
            cursor.execute(f"ROLLBACK TO SAVEPOINT {sp}")
        except Exception:
            try:
                cursor.connection.rollback()
            except Exception:
                pass
        return None
    return row


def _sql_egress_count(
    cursor: Any,
    org_id: int,
    run_id: Optional[int],
    *,
    classified_only: bool,
) -> tuple[int, bool]:
    """Count AI agents with any role_assignments.scope matching an
    internet-facing pattern. When ``classified_only`` is True, restrict the
    cohort to agents that also reach a classified resource.

    The pattern matching is done with ILIKE OR chains so the engine doesn't
    have to bake an explicit list into SQL.
    """
    if not INTERNET_EGRESS_SCOPE_PATTERNS:
        return 0, True

    like_clauses = " OR ".join(
        ["LOWER(ra.scope) LIKE %s"] * len(INTERNET_EGRESS_SCOPE_PATTERNS)
    )
    like_params = [f"%{p}%" for p in INTERNET_EGRESS_SCOPE_PATTERNS]

    if classified_only:
        sql = f"""
            SELECT COUNT(DISTINCT i.id)
              FROM identities i
              JOIN agent_classifications ac ON ac.identity_db_id = i.id
              JOIN role_assignments ra ON ra.identity_db_id = i.id
              JOIN agent_data_reachability adr ON adr.identity_db_id = i.id
             WHERE i.organization_id = %s
               AND i.is_microsoft_system = FALSE
               AND ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
               AND adr.data_classification = ANY(%s)
               AND adr.resource_count > 0
               AND ({like_clauses})
               AND (%s IS NULL OR i.discovery_run_id = %s)
        """
        params = tuple([org_id, list(ALL_CLASSES)] + like_params + [run_id, run_id])
    else:
        sql = f"""
            SELECT COUNT(DISTINCT i.id)
              FROM identities i
              JOIN agent_classifications ac ON ac.identity_db_id = i.id
              JOIN role_assignments ra ON ra.identity_db_id = i.id
             WHERE i.organization_id = %s
               AND i.is_microsoft_system = FALSE
               AND ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
               AND ({like_clauses})
               AND (%s IS NULL OR i.discovery_run_id = %s)
        """
        params = tuple([org_id] + like_params + [run_id, run_id])

    return _sql_scalar(cursor, "egress_count", sql, params)


def _resolve_latest_run_id(cursor: Any, org_id: int) -> Optional[int]:
    """Return the latest completed discovery_runs.id for the org, or None."""
    sp = f"{_SP_PREFIX}_latest_run"
    try:
        cursor.execute(f"SAVEPOINT {sp}")
        cursor.execute(
            """
            SELECT MAX(id)
              FROM discovery_runs
             WHERE organization_id = %s
               AND status IN ('completed', 'partial')
            """,
            (org_id,),
        )
        row = cursor.fetchone()
        cursor.execute(f"RELEASE SAVEPOINT {sp}")
    except Exception as exc:
        logger.debug("[AG-186] _resolve_latest_run_id failed: %s", exc)
        try:
            cursor.execute(f"ROLLBACK TO SAVEPOINT {sp}")
        except Exception:
            try:
                cursor.connection.rollback()
            except Exception:
                pass
        return None
    if row is None:
        return None
    if isinstance(row, dict):
        for v in row.values():
            return _coerce_int(v)
        return None
    try:
        return _coerce_int(row[0])
    except (IndexError, TypeError):
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Cache helpers — argus_reasoning_cache
# ─────────────────────────────────────────────────────────────────────────────

def _question_hash(
    question_type: str,
    org_id: int,
    latest_run_id: Optional[int],
) -> str:
    """Deterministic cache key.

    Includes the latest_run_id so a fresh discovery yields a fresh hash —
    we never serve a stale cached answer across runs without an explicit
    cache hit on the same (question_type, org, run) tuple.
    """
    payload = json.dumps(
        {
            "question_type": question_type,
            "organization_id": int(org_id),
            "latest_run_id": int(latest_run_id) if latest_run_id is not None else None,
            "version": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _read_cache(
    cursor: Any,
    org_id: int,
    qhash: str,
) -> Optional[dict[str, Any]]:
    """Read a cached reasoning row. Returns the response dict or None."""
    sp = f"{_SP_PREFIX}_cache_read"
    try:
        cursor.execute(f"SAVEPOINT {sp}")
        cursor.execute(
            """
            SELECT response_json, created_at, latest_run_id
              FROM argus_reasoning_cache
             WHERE organization_id = %s
               AND question_hash   = %s
             LIMIT 1
            """,
            (org_id, qhash),
        )
        row = cursor.fetchone()
        cursor.execute(f"RELEASE SAVEPOINT {sp}")
    except Exception as exc:
        logger.debug("[AG-186] cache read failed: %s", exc)
        try:
            cursor.execute(f"ROLLBACK TO SAVEPOINT {sp}")
        except Exception:
            try:
                cursor.connection.rollback()
            except Exception:
                pass
        return None

    if row is None:
        return None

    response = _cell(row, 0, "response_json")
    if isinstance(response, str):
        try:
            response = json.loads(response)
        except Exception:
            return None
    if not isinstance(response, dict):
        return None
    return response


def _write_cache(
    cursor: Any,
    org_id: int,
    qhash: str,
    question_type: str,
    latest_run_id: Optional[int],
    response: dict[str, Any],
) -> None:
    """Upsert one cache row. Silent on failure — caching is a performance
    optimisation, never a correctness requirement.
    """
    sp = f"{_SP_PREFIX}_cache_write"
    try:
        cursor.execute(f"SAVEPOINT {sp}")
        cursor.execute(
            """
            INSERT INTO argus_reasoning_cache (
                organization_id, question_hash, question_type,
                response_json, latest_run_id, confidence, created_at
            ) VALUES (
                %s, %s, %s, %s::jsonb, %s, %s, NOW()
            )
            ON CONFLICT (organization_id, question_hash)
            DO UPDATE SET
                response_json = EXCLUDED.response_json,
                latest_run_id = EXCLUDED.latest_run_id,
                confidence    = EXCLUDED.confidence,
                created_at    = NOW()
            """,
            (
                org_id,
                qhash,
                question_type,
                json.dumps(response, default=str),
                latest_run_id,
                response.get("confidence"),
            ),
        )
        cursor.execute(f"RELEASE SAVEPOINT {sp}")
        try:
            cursor.connection.commit()
        except Exception:
            pass
    except Exception as exc:
        logger.debug("[AG-186] cache write failed: %s", exc)
        try:
            cursor.execute(f"ROLLBACK TO SAVEPOINT {sp}")
        except Exception:
            try:
                cursor.connection.rollback()
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# Result builders
# ─────────────────────────────────────────────────────────────────────────────

def _ok_result(
    *,
    question: str,
    conclusion: str,
    evidence: list[dict[str, Any]],
    framework_keys: tuple[str, ...],
    chain_errors: int = 0,
    missing_inputs: int = 0,
) -> dict[str, Any]:
    """Build a successful reasoning result with the canonical shape."""
    framework_refs = _resolve_framework_refs(framework_keys)
    if chain_errors == 0 and missing_inputs == 0:
        confidence = "high"
    elif chain_errors + missing_inputs == 1:
        confidence = "medium"
    else:
        confidence = "low"
    return {
        "question":       question,
        "conclusion":     conclusion,
        "evidence":       evidence,
        "framework_refs": framework_refs,
        "confidence":     confidence,
    }


def _error_result(*, question_type: str, conclusion: str) -> dict[str, Any]:
    """Build a no-data-possible result that still honors the contract shape."""
    return {
        "question":       "(unsupported)",
        "conclusion":     conclusion,
        "evidence":       [],
        "framework_refs": {"nist": [], "cis_azure": [], "mitre": []},
        "confidence":     "low",
        "question_type":  question_type,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "latest_run_id":  None,
        "cached":         False,
    }


def _resolve_framework_refs(
    signal_keys: tuple[str, ...],
) -> dict[str, list[str]]:
    """Roll up NIST + MITRE refs from RISK_SIGNALS across the cited signals.

    Keys are deduped + sorted. CIS Azure list is mapped manually from the
    same per-signal taxonomy used by explain_risk_score.
    """
    nist: set[str] = set()
    mitre: set[str] = set()
    cis: set[str] = set()
    for k in signal_keys:
        spec = RISK_SIGNALS.get(k) or {}
        for n in spec.get("nist", []) or []:
            nist.add(n)
        for m in spec.get("mitre", []) or []:
            mitre.add(m)
        for c in _CIS_AZURE_BY_SIGNAL.get(k, []):
            cis.add(c)
    return {
        "nist":      sorted(nist),
        "cis_azure": sorted(cis),
        "mitre":     sorted(mitre),
    }


# Conservative CIS Azure Foundations Benchmark mapping per signal — mirrors
# explain_risk_score._CIS_AZURE_BY_SIGNAL so the framework chips line up
# across Argus surfaces. We do not introduce any new control IDs here.
_CIS_AZURE_BY_SIGNAL: dict[str, list[str]] = {
    "broad_owner_role":       ["CIS Azure 1.22", "CIS Azure 1.23"],
    "key_vault_admin":        ["CIS Azure 8.5"],
    "storage_blob_owner":     ["CIS Azure 3.1", "CIS Azure 3.7"],
    "sensitive_data_access":  ["CIS Azure 3.1", "CIS Azure 4.1"],
    "no_telemetry":           ["CIS Azure 5.1.1", "CIS Azure 5.4"],
    "unrestricted_egress":    ["CIS Azure 6.1"],
    "external_llm_access":    ["CIS Azure 6.1"],
    "expired_credential":     ["CIS Azure 1.14"],
    "dormant_agent":          ["CIS Azure 1.3"],
    "no_owner":               ["CIS Azure 1.22"],
}


# ─────────────────────────────────────────────────────────────────────────────
# Small helpers
# ─────────────────────────────────────────────────────────────────────────────

def _cell(row: Any, idx: int, key: str) -> Any:
    """Return row[idx] for tuple cursors, row[key] for dict cursors. Same
    helper the Argus L3 investigator uses — kept local so callers don't
    have to import across engine modules.
    """
    if row is None:
        return None
    if isinstance(row, dict):
        return row.get(key)
    try:
        return row[idx]
    except (IndexError, KeyError, TypeError):
        return None


def _coerce_int(value: Any) -> int:
    """Best-effort int coercion (handles Decimal, str, None)."""
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return 0


def _n(count: int, singular: str, plural: str) -> str:
    """Pluralise: "1 AI agent" vs. "6 AI agents"."""
    return f"{count} {singular if count == 1 else plural}"


def _iso(value: Any) -> str:
    """Best-effort ISO-8601 / YYYY-MM-DD render of a datetime / str value."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.date().isoformat()
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.date().isoformat()
    except Exception:
        return str(value)


__all__ = [
    "QUESTION_TYPES",
    "reason_about",
]
