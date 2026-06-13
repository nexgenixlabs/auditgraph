"""
board_scorecard_engine — Org-wide AI Agent governance scorecard (AG-179)
=========================================================================

Produces the single dict the boardroom view + auditor pack render from. The
scorecard is a *roll-up* over per-agent Trust Scores computed by
`agent_trust_scorer.compute_agent_trust_batch` — this module owns the
aggregation rules, distribution buckets, and "top 10 worst" selection.

Output shape (returned by compute_board_scorecard):

    {
      total_agents:          int,
      with_owner_pct:        float,   # ownership PASS rate
      with_telemetry_pct:    float,   # telemetry != NONE rate
      private_network_pct:   float,   # egress PASS rate
      least_privilege_pct:   float,   # secrets in {NONE, LOW} rate
      policy_compliant_pct:  float,   # oversight PASS rate
      distribution: {
        strong:    int,  # trust >= 85
        good:      int,  # 70..84
        elevated:  int,  # 50..69
        critical:  int,  # < 50
      },
      top_10_worst: [
        {identity_id, display_name, trust_score, top_dimension_fail}, ...
      ],
      exceptions_pending: int,
    }

Empty-state contract: if the tenant has zero classified AI agents, returns
every field at zero / empty list. NEVER fabricates data.

AI agent set: identities joined to agent_classifications where
`agent_identity_type` ∈ {'ai_agent', 'possible_ai_agent'}, scoped to
organization_id, excluding Microsoft system SPNs and soft-deleted rows.
The deduplication-by-identity_id rule matches the existing
`get_agent_identity_count` and `get_agent_risk_summary` handlers so all
three surfaces report the same denominator.
"""

from __future__ import annotations

import logging
from typing import Any

from .agent_trust_scorer import compute_agent_trust_batch

logger = logging.getLogger(__name__)


# Distribution band cutoffs. These match the board-ready labels in
# product_polish_gap and align with PostureScorer's bands so a single trust
# story is told across the product.
_BAND_STRONG_MIN = 85
_BAND_GOOD_MIN   = 70
_BAND_ELEV_MIN   = 50

# Maximum count of "top worst" agents to return.
_TOP_WORST_LIMIT = 10


# ─────────────────────────────────────────────────────────────────────────────
# Public entry
# ─────────────────────────────────────────────────────────────────────────────

def compute_board_scorecard(cursor: Any, organization_id: int) -> dict[str, Any]:
    """Compute the org-wide AI agent scorecard for `organization_id`.

    `cursor` is a psycopg2-style cursor already scoped to the caller's
    organization (RLS applies). We additionally filter every query by
    organization_id so admin / superadmin contexts also produce correct
    per-org rollups when RLS is bypassed.
    """
    if not organization_id:
        return _empty_scorecard()

    # 1) Resolve the cohort — dedupe by identity_id, take the latest
    # discovery_run snapshot per identity (the same rule the agent count and
    # agent_risk_summary handlers use).
    try:
        cursor.execute(
            """
            SELECT i.id, i.identity_id, i.display_name,
                   i.owner_display_name, i.last_seen_auth
              FROM (
                SELECT DISTINCT ON (i.identity_id)
                       i.id, i.identity_id, i.display_name,
                       i.owner_display_name, i.last_seen_auth
                  FROM identities i
                  JOIN agent_classifications ac ON ac.identity_db_id = i.id
                 WHERE ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
                   AND i.organization_id = %s
                   AND NOT COALESCE(i.is_microsoft_system, false)
                   AND i.deleted_at IS NULL
                 ORDER BY i.identity_id, i.discovery_run_id DESC
              ) AS i
            """,
            (organization_id,),
        )
        rows = cursor.fetchall()
    except Exception as exc:
        logger.warning("compute_board_scorecard cohort query failed: %s", exc)
        return _empty_scorecard()

    cohort = [_row(r, ["id", "identity_id", "display_name", "owner_display_name", "last_seen_auth"]) for r in rows]
    cohort = [c for c in cohort if c.get("id") is not None]
    total = len(cohort)

    # Exceptions pending — done independently so the count is meaningful even
    # when there are zero AI agents (an org could have accepted-then-deleted
    # exceptions still in the queue). Graceful fallback to 0 if the table
    # doesn't exist.
    exceptions_pending = _count_pending_exceptions(cursor, organization_id)

    if total == 0:
        out = _empty_scorecard()
        out["exceptions_pending"] = exceptions_pending
        return out

    # 2) Batch-compute trust for the whole cohort (one DB roundtrip per
    # source table — see agent_trust_scorer).
    trust = compute_agent_trust_batch(cursor, [c["id"] for c in cohort])

    # 3) Aggregate.
    with_owner       = 0
    with_telemetry   = 0
    private_network  = 0
    least_privilege  = 0
    policy_compliant = 0

    distribution = {"strong": 0, "good": 0, "elevated": 0, "critical": 0}

    # (trust_score, identity_id, display_name, top_dim_fail, owner, last_seen)
    sortable: list[tuple[int, str, str, str | None, str | None, str | None]] = []

    for entry in cohort:
        iid = int(entry["id"])
        t = trust.get(iid)
        if not t:
            continue
        score = int(t.get("trust_score") or 0)

        if t["ownership"]["grade"] == "PASS":
            with_owner += 1
        if t["telemetry"]["grade"] in ("PARTIAL", "FULL"):
            with_telemetry += 1
        if t["egress"]["grade"] == "PASS":
            private_network += 1
        if t["secrets"]["grade"] in ("NONE", "LOW"):
            least_privilege += 1
        if t["oversight"]["grade"] == "PASS":
            policy_compliant += 1

        if   score >= _BAND_STRONG_MIN: distribution["strong"]   += 1
        elif score >= _BAND_GOOD_MIN:   distribution["good"]     += 1
        elif score >= _BAND_ELEV_MIN:   distribution["elevated"] += 1
        else:                           distribution["critical"] += 1

        last_seen_iso = None
        if entry.get("last_seen_auth"):
            try:
                last_seen_iso = entry["last_seen_auth"].isoformat()
            except Exception:
                last_seen_iso = str(entry["last_seen_auth"])
        sortable.append((
            score,
            entry.get("identity_id") or "",
            entry.get("display_name") or "",
            _top_dimension_fail(t),
            entry.get("owner_display_name"),
            last_seen_iso,
        ))

    # 4) Top-10 worst (lowest trust first; deterministic tiebreak on identity_id).
    sortable.sort(key=lambda row: (row[0], row[1]))
    top_10_worst = [
        {
            "identity_id":        sid,
            "display_name":       dname,
            "trust_score":        sc,
            "top_dimension_fail": dim,
            "owner":              owner,
            "last_seen":          last_seen,
        }
        for (sc, sid, dname, dim, owner, last_seen) in sortable[:_TOP_WORST_LIMIT]
    ]

    # AG-BOARD-V3 (2026-06-10): board-room metrics for the executive view.
    # Governance score = mean of the 5 KPIs (an honest summary that moves
    # the moment any pillar slips). Critical AI Risks = the 3 risk classes
    # the board actually asks about: ownerless agents, internet-accessible
    # agents (egress fail), agents reaching sensitive data (data_access fail).
    kpis = [
        _pct(with_owner, total), _pct(with_telemetry, total),
        _pct(private_network, total), _pct(least_privilege, total),
        _pct(policy_compliant, total),
    ]
    governance_score = round(sum(kpis) / len(kpis), 1) if kpis else 0.0

    ownerless = 0
    internet_accessible = 0
    sensitive_data_reachable = 0
    for entry in cohort:
        iid = int(entry["id"])
        t = trust.get(iid)
        if not t:
            continue
        if t["ownership"]["grade"] != "PASS":
            ownerless += 1
        if t["egress"]["grade"] != "PASS":
            internet_accessible += 1
        if t.get("data_access", {}).get("grade") in ("FAIL", "HIGH", "CRITICAL"):
            sensitive_data_reachable += 1

    return {
        "total_agents":             total,
        "governance_score":         governance_score,
        "with_owner_pct":           _pct(with_owner, total),
        "with_telemetry_pct":       _pct(with_telemetry, total),
        "private_network_pct":      _pct(private_network, total),
        "least_privilege_pct":      _pct(least_privilege, total),
        "policy_compliant_pct":     _pct(policy_compliant, total),
        "distribution":             distribution,
        "top_10_worst":             top_10_worst,
        "exceptions_pending":       exceptions_pending,
        "critical_risks": {
            "ownerless":                ownerless,
            "internet_accessible":      internet_accessible,
            "sensitive_data_reachable": sensitive_data_reachable,
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _count_pending_exceptions(cursor: Any, organization_id: int) -> int:
    """Return count of ai_governance_exceptions in 'pending' state for the org.

    Returns 0 gracefully if the table doesn't exist (older deployments) —
    consumers should treat 0 as "no queue", not "error".
    """
    try:
        cursor.execute(
            """
            SELECT COUNT(*)
              FROM ai_governance_exceptions
             WHERE organization_id = %s
               AND status = 'pending'
            """,
            (organization_id,),
        )
        row = cursor.fetchone()
    except Exception as exc:  # pragma: no cover — table may not exist yet
        logger.debug("ai_governance_exceptions pending count skipped: %s", exc)
        return 0
    if not row:
        return 0
    if isinstance(row, dict):
        # COUNT(*) under RealDictCursor typically comes back as {"count": N}
        return int(next(iter(row.values()), 0) or 0)
    try:
        return int(row[0] or 0)
    except (IndexError, TypeError, ValueError):
        return 0


def _top_dimension_fail(trust: dict[str, Any]) -> str | None:
    """Return the dimension key with the worst grade, or None if all pass.

    Ranking: secrets CRITICAL > secrets HIGH > ownership/egress/oversight FAIL >
    secrets MEDIUM > telemetry NONE > secrets LOW > telemetry PARTIAL.
    """
    secrets_grade = trust["secrets"]["grade"]
    if secrets_grade == "CRITICAL": return "secrets"
    if secrets_grade == "HIGH":     return "secrets"
    if trust["ownership"]["grade"] == "FAIL": return "ownership"
    if trust["egress"]["grade"]    == "FAIL": return "egress"
    if trust["oversight"]["grade"] == "FAIL": return "oversight"
    if secrets_grade == "MEDIUM":   return "secrets"
    if trust["telemetry"]["grade"] == "NONE": return "telemetry"
    if secrets_grade == "LOW":      return "secrets"
    if trust["telemetry"]["grade"] == "PARTIAL": return "telemetry"
    return None


def _pct(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(100.0 * numerator / denominator, 1)


def _row(row: Any, columns: list[str]) -> dict[str, Any]:
    """Coerce a psycopg2 row into a dict (mirrors the helper in scorer)."""
    if row is None:
        return {}
    if isinstance(row, dict):
        return {c: row.get(c) for c in columns}
    try:
        return {columns[i]: row[i] for i in range(min(len(columns), len(row)))}
    except (IndexError, TypeError, KeyError):
        return {}


def _empty_scorecard() -> dict[str, Any]:
    """Zero/empty result used when the org has no AI agents.

    Per the AG-179 spec, this is the contract: do NOT fabricate metrics.
    Front-end + auditor pack inspect total_agents == 0 to render the
    "no AI agents detected" empty-state.
    """
    return {
        "total_agents":         0,
        "with_owner_pct":       0.0,
        "with_telemetry_pct":   0.0,
        "private_network_pct":  0.0,
        "least_privilege_pct":  0.0,
        "policy_compliant_pct": 0.0,
        "distribution":         {"strong": 0, "good": 0, "elevated": 0, "critical": 0},
        "top_10_worst":         [],
        "exceptions_pending":   0,
    }


def persist_board_scorecard_snapshot(
    cursor: Any,
    organization_id: int,
    discovery_run_id: int | None = None,
) -> bool:
    """Persist a scorecard rollup to ai_board_scorecard_snapshots.

    Called after each discovery run so the trend charts on /board-scorecard,
    /identity-scorecard, /dashboard have data to render. Without this hook
    the snapshot table stays empty and every trend widget shows "Baseline
    established. Trend data available after next scan" forever.

    Per-run snapshots (post-migration 220): every discovery run writes its
    own row. A 6h-cadence tenant gets 4 rows/day → trend lights up after
    the 2nd scan. A 24h-cadence tenant gets 1 row/day → trend lights up
    after day 2. The (org, discovery_run_id) partial unique index in
    migration 220 prevents a single run from accidentally writing twice
    if the hook fires more than once for the same run_id.

    Returns True on success, False on caught failure.
    """
    import json
    if not organization_id:
        return False
    try:
        result = compute_board_scorecard(cursor, organization_id)
    except Exception as exc:
        logger.warning("persist_board_scorecard_snapshot compute failed org=%s: %s", organization_id, exc)
        return False

    dist = result.get("distribution") or {}
    try:
        cursor.execute(
            """
            INSERT INTO ai_board_scorecard_snapshots
              (organization_id, snapshot_date, total_agents,
               with_owner_pct, with_telemetry_pct, private_network_pct,
               least_privilege_pct, policy_compliant_pct,
               distribution_strong, distribution_good,
               distribution_elevated, distribution_critical,
               top_10_worst_json, exceptions_pending, computed_at,
               discovery_run_id)
            VALUES (%s, CURRENT_DATE, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s::jsonb, %s, NOW(), %s)
            ON CONFLICT (organization_id, discovery_run_id)
            WHERE discovery_run_id IS NOT NULL
            DO UPDATE SET
              total_agents          = EXCLUDED.total_agents,
              with_owner_pct        = EXCLUDED.with_owner_pct,
              with_telemetry_pct    = EXCLUDED.with_telemetry_pct,
              private_network_pct   = EXCLUDED.private_network_pct,
              least_privilege_pct   = EXCLUDED.least_privilege_pct,
              policy_compliant_pct  = EXCLUDED.policy_compliant_pct,
              distribution_strong   = EXCLUDED.distribution_strong,
              distribution_good     = EXCLUDED.distribution_good,
              distribution_elevated = EXCLUDED.distribution_elevated,
              distribution_critical = EXCLUDED.distribution_critical,
              top_10_worst_json     = EXCLUDED.top_10_worst_json,
              exceptions_pending    = EXCLUDED.exceptions_pending,
              computed_at           = NOW()
            """,
            (
                organization_id,
                int(result.get("total_agents", 0) or 0),
                float(result.get("with_owner_pct", 0) or 0),
                float(result.get("with_telemetry_pct", 0) or 0),
                float(result.get("private_network_pct", 0) or 0),
                float(result.get("least_privilege_pct", 0) or 0),
                float(result.get("policy_compliant_pct", 0) or 0),
                int(dist.get("strong", 0) or 0),
                int(dist.get("good", 0) or 0),
                int(dist.get("elevated", 0) or 0),
                int(dist.get("critical", 0) or 0),
                json.dumps(result.get("top_10_worst", []) or []),
                int(result.get("exceptions_pending", 0) or 0),
                discovery_run_id,
            ),
        )
        return True
    except Exception as exc:
        logger.warning("persist_board_scorecard_snapshot insert failed org=%s run=%s: %s",
                       organization_id, discovery_run_id, exc)
        return False


__all__ = ["compute_board_scorecard", "persist_board_scorecard_snapshot"]
