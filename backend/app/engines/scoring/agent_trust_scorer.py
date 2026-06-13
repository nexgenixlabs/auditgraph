"""
agent_trust_scorer — Per-AI-agent Trust Score engine (AG-179, Tier 1B)
=======================================================================

Computes a 0–100 Trust Score per AI agent across five governance dimensions:

    1. Ownership   — does a human own this agent?  (PASS / FAIL)
    2. Secrets     — Key Vault privilege tier      (NONE / LOW / MEDIUM /
                                                    HIGH / CRITICAL)
    3. Egress      — outbound network posture      (PASS / FAIL)
    4. Telemetry   — diagnostic / sign-in evidence (NONE / PARTIAL / FULL)
    5. Oversight   — governance exception, owner-attested, etc. (PASS / FAIL)

Trust Score = 100 − Σ dimension_penalty
where penalty values come from the `settings` table (system scope) — never
hardcoded in source. Defaults live in DEFAULTS and are the fallback only.

Used by:
    - board_scorecard_engine.compute_board_scorecard
    - AI Agent detail view (per-agent trust card)
    - Auditor pack (per-agent evidence rows)

No N+1: compute_agent_trust_batch issues exactly four SQL queries regardless
of cohort size (one per source table: identities, role_assignments,
sp_ownership, ai_governance_exceptions).

This module reuses the SSOT signal logic from `constants.ai_risk`
(`detect_signals`, `aggregate_access_levels`) and re-groups the fired
RISK_SIGNALS into the five board-ready Trust dimensions. We do NOT invent
a parallel signal catalogue — Trust is a *view* on the same signals.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from ...constants.ai_risk import (
    BROAD_PRIVILEGE_ROLES,
    INTERNET_EGRESS_SCOPE_PATTERNS,
    aggregate_access_levels,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Defaults (FALLBACK ONLY — runtime values come from settings.get_system_setting)
# ─────────────────────────────────────────────────────────────────────────────
# Penalty schedule per dimension grade. Keys are the grade labels returned
# by the compute_* helpers below. Values sum to 100 in the worst case
# (CRITICAL secrets + FAIL ownership + FAIL egress + NONE telemetry + FAIL
# oversight = 35 + 20 + 20 + 5 + 20 = 100) so Trust never goes negative.
#
# Telemetry NONE penalty is intentionally soft (5) — we cannot reliably
# observe diagnostic-settings coverage in v1; the evidence string says
# "heuristic" so consumers know not to over-index.

# Founder-signed-off thresholds (2026-06-03) — see
# docs/runbooks/trust_score_thresholds_proposal.md
# Worst-case (all FAIL) anchors to ~22/100 — the "42/100" demo number
# corresponds to an agent failing some dimensions and passing others.
DEFAULTS: dict[str, Any] = {
    "ownership_penalty_fail":     15,   # signed-off
    "secrets_penalty_critical":   30,   # signed-off
    "secrets_penalty_high":       22,   # signed-off
    "secrets_penalty_medium":     12,   # signed-off
    "secrets_penalty_low":         5,
    "secrets_penalty_none":        0,
    "egress_penalty_fail":        18,   # signed-off
    "telemetry_penalty_none":      5,   # soft penalty; tooltip explains heuristic
    "telemetry_penalty_partial":   2,
    "telemetry_penalty_full":      0,
    "oversight_penalty_fail":     10,   # signed-off (low because attestation flow is new)
    "telemetry_window_days":      30,
    # ── AG-T1.3: 4 new dimensions (5 → 9) ──
    # Worst-case all-FAIL across 9 dimensions ≈ 100 (was 78 with 5 dimensions).
    # New penalties pre-signed-off for v1; tunable via settings.
    "data_access_penalty_critical": 12,  # writes to PHI
    "data_access_penalty_high":      8,  # reads PHI/PCI
    "data_access_penalty_medium":    4,  # reads PII or financial
    "data_access_penalty_none":      0,
    "network_penalty_fail":          5,  # public-network endpoint
    "model_exposure_penalty_multi":  3,  # ≥3 distinct models in use
    "model_exposure_penalty_one":    0,
    "supply_chain_penalty_fail":     2,  # custom / fine-tuned / unverified vendor
    # Calibration version — bump when thresholds change. Surfaced in the
    # API response so audit trails are clear post-recalibration.
    "calibration_version":     "2026-06-04-9d",
}

DEFAULTS_JSON_STRING = json.dumps(DEFAULTS)


# Key Vault role → secrets grade. Mirrors RISK_SIGNALS["key_vault_admin"]
# but explicitly tiered so the dimension grade is actionable.
_KV_ROLE_TO_GRADE: dict[str, str] = {
    "Key Vault Administrator":          "CRITICAL",
    "Key Vault Secrets Officer":        "CRITICAL",
    "Key Vault Crypto Officer":         "HIGH",
    "Key Vault Certificates Officer":   "HIGH",
    "Key Vault Secrets User":           "MEDIUM",
    "Key Vault Crypto User":            "MEDIUM",
    "Key Vault Reader":                 "LOW",
}

_GRADE_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# ─────────────────────────────────────────────────────────────────────────────
# Public: dimension catalogue (weights resolved at compute-time from settings)
# ─────────────────────────────────────────────────────────────────────────────

AGENT_TRUST_DIMENSIONS: list[dict[str, Any]] = [
    {
        "key":         "ownership",
        "label":       "Ownership",
        "signal_keys": ["no_owner"],
        # `weight` resolved from settings at runtime in _resolve_weights().
        # The literal here is a *documentation* placeholder so callers reading
        # AGENT_TRUST_DIMENSIONS see what max each dimension can contribute.
        "weight":      DEFAULTS["ownership_penalty_fail"],
    },
    {
        "key":         "secrets",
        "label":       "Secrets",
        "signal_keys": ["key_vault_admin"],
        "weight":      DEFAULTS["secrets_penalty_critical"],
    },
    {
        "key":         "egress",
        "label":       "Egress",
        "signal_keys": ["unrestricted_egress", "external_llm_access"],
        "weight":      DEFAULTS["egress_penalty_fail"],
    },
    {
        "key":         "telemetry",
        "label":       "Telemetry",
        "signal_keys": ["no_telemetry"],
        "weight":      DEFAULTS["telemetry_penalty_none"],
    },
    {
        "key":         "oversight",
        "label":       "Oversight",
        "signal_keys": ["broad_owner_role", "dormant_agent"],
        "weight":      DEFAULTS["oversight_penalty_fail"],
    },
    # AG-T1.3: 4 new dimensions (5 → 9)
    {
        "key":         "data_access",
        "label":       "Data Access",
        "signal_keys": ["reaches_phi", "reaches_pci", "reaches_pii"],
        "weight":      DEFAULTS["data_access_penalty_critical"],
    },
    {
        "key":         "network",
        "label":       "Network",
        "signal_keys": ["public_endpoint"],
        "weight":      DEFAULTS["network_penalty_fail"],
    },
    {
        "key":         "model_exposure",
        "label":       "Model Exposure",
        "signal_keys": ["multi_model_usage"],
        "weight":      DEFAULTS["model_exposure_penalty_multi"],
    },
    {
        "key":         "supply_chain",
        "label":       "Supply Chain",
        # AG-PHASE-ENGINE-DEPTH (2026-06-10): added CI/CD federated
        # signals so the dim fires for non-AI NHIs too. For AI agents
        # this becomes "model provenance"; for NHIs it becomes
        # "Origin / Lineage". Same dim, scope-aware label is handled
        # in the UI (Identity Trust page reads the dim from the
        # identity_scope when rendering).
        "signal_keys": ["unverified_model_provenance",
                          "unverified_federated_origin",
                          "ci_cd_with_owner_role"],
        "weight":      DEFAULTS["supply_chain_penalty_fail"],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Settings resolution
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_weights(cursor: Any) -> dict[str, Any]:
    """Read `agent_trust_weights` setting → merged dict over DEFAULTS.

    The setting stores a JSON-encoded subset of DEFAULTS. Unknown keys are
    ignored; missing keys fall back to DEFAULTS. This lets ops tune
    individual penalties without having to restate the full schedule.

    cursor is used (not a Database instance) so this is callable from any
    transaction context — including inside compute_board_scorecard where
    the caller already holds a cursor.
    """
    weights = dict(DEFAULTS)
    try:
        cursor.execute(
            "SELECT value FROM settings "
            "WHERE key = %s AND organization_id IS NULL",
            ("agent_trust_weights",),
        )
        row = cursor.fetchone()
    except Exception as exc:  # pragma: no cover — settings table may not exist
        logger.debug("trust weights settings lookup failed: %s", exc)
        return weights

    if not row:
        return weights

    raw = row[0] if not isinstance(row, dict) else row.get("value")
    if not raw:
        return weights

    try:
        parsed = json.loads(raw)
    except Exception:
        logger.warning("agent_trust_weights setting is not valid JSON — ignoring")
        return weights

    if not isinstance(parsed, dict):
        return weights

    for k, v in parsed.items():
        if k in DEFAULTS:
            weights[k] = v
    return weights


# ─────────────────────────────────────────────────────────────────────────────
# Dimension grade helpers (pure — no DB)
# ─────────────────────────────────────────────────────────────────────────────

def _grade_ownership(agent_meta: dict, has_sp_owner: bool) -> dict[str, str]:
    """Owner present iff identities.owner_display_name OR a sp_ownership row.

    The dual check is the same one identity-detail uses (`owner_count` plus
    `owner_display_name`) — we accept either signal so an SPN with a synced
    app-registration owner but no separate sp_ownership row still passes.
    """
    name = (agent_meta.get("owner_display_name") or "").strip()
    if name or has_sp_owner:
        evidence = f"Owner = {name}" if name else "Owner assignment in sp_ownership"
        return {"grade": "PASS", "evidence": evidence}
    return {"grade": "FAIL", "evidence": "No human owner assigned"}


def _grade_secrets(role_assignments: list[dict]) -> dict[str, Any]:
    """Highest Key Vault tier across all role assignments.

    Returns role_name + scope of the worst-case grant so the evidence string
    is actionable ("you have X on Y").
    """
    best_grade = "NONE"
    best_role: Optional[str] = None
    best_scope: Optional[str] = None
    for ra in role_assignments:
        role_name = ra.get("role_name") or ""
        grade = _KV_ROLE_TO_GRADE.get(role_name)
        if not grade:
            continue
        if _GRADE_RANK[grade] > _GRADE_RANK[best_grade]:
            best_grade = grade
            best_role = role_name
            best_scope = ra.get("scope") or None

    if best_grade == "NONE":
        return {
            "grade":     "NONE",
            "role_name": None,
            "scope":     None,
            "evidence":  "No Key Vault role assignments",
        }
    return {
        "grade":     best_grade,
        "role_name": best_role,
        "scope":     best_scope,
        "evidence":  f"{best_role} on {best_scope}" if best_scope else (best_role or ""),
    }


def _grade_egress(role_assignments: list[dict], agent_meta: dict) -> dict[str, str]:
    """FAIL if any role scope hits an internet-facing resource type, OR if
    `detected_platform` indicates an external LLM provider.

    Matches the `unrestricted_egress` + `external_llm_access` signals from
    RISK_SIGNALS but presents them as a single PASS/FAIL board-grade.
    """
    # Internet egress: scope matches a known external-resource pattern.
    aggregated = aggregate_access_levels(role_assignments)
    if aggregated.get("internet_egress") == "unrestricted":
        offending = ""
        for ra in role_assignments:
            scope = (ra.get("scope") or "").lower()
            for pat in INTERNET_EGRESS_SCOPE_PATTERNS:
                if pat in scope:
                    offending = ra.get("scope") or ""
                    break
            if offending:
                break
        return {
            "grade":    "FAIL",
            "evidence": f"Role scope reaches internet-facing resource: {offending}"
                        if offending else "Role scope reaches internet-facing resource",
        }

    # External LLM provider (platform heuristic — same as RISK_SIGNALS).
    plat = (agent_meta.get("detected_platform") or "").lower()
    if plat in {"anthropic", "openai"} or "openai" in plat:
        return {
            "grade":    "FAIL",
            "evidence": f"Detected platform = {plat} (external LLM endpoint)",
        }

    return {"grade": "PASS", "evidence": "No internet-facing scopes or external LLM platform detected"}


def _grade_telemetry(agent_meta: dict, window_days: int) -> dict[str, str]:
    """PARTIAL if last_sign_in OR last_activity_date is within `window_days`.
    NONE otherwise. FULL is NOT returnable in v1 — that requires
    diagnostic-settings discovery (Phase v1.1). The evidence string flags
    this as a heuristic so consumers can render the tooltip.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=int(window_days))

    candidates = [
        agent_meta.get("last_sign_in"),
        agent_meta.get("last_activity_date"),
    ]
    most_recent: Optional[datetime] = None
    for c in candidates:
        if c is None:
            continue
        try:
            if isinstance(c, datetime):
                dt = c if c.tzinfo else c.replace(tzinfo=timezone.utc)
            else:
                dt = datetime.fromisoformat(str(c).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue
        if most_recent is None or dt > most_recent:
            most_recent = dt

    if most_recent is not None and most_recent >= cutoff:
        return {
            "grade":    "PARTIAL",
            "evidence": f"Sign-in/activity within {window_days}d at {most_recent.isoformat()} "
                        f"(heuristic — diagnostic-settings coverage not yet measured)",
        }
    return {
        "grade":    "NONE",
        "evidence": f"No sign-in or activity in the last {window_days} days "
                    f"(heuristic — diagnostic-settings coverage not yet measured)",
    }


def _grade_oversight(role_assignments: list[dict],
                     agent_meta: dict,
                     has_exception: bool) -> dict[str, str]:
    """FAIL on any of:
      - Holds a broad-privilege role at subscription scope (Owner/Contributor/UAA),
      - No active governance exception covers a known broad-role assignment,
      - Dormant 90+ days while still permission-bearing.

    Otherwise PASS. The presence of an *approved* exception does NOT remove
    the underlying control failure but DOES upgrade Oversight (the org has
    explicitly accepted the risk).
    """
    reasons: list[str] = []

    # 1) Broad-privilege at subscription scope.
    for ra in role_assignments:
        scope = ra.get("scope") or ""
        if (ra.get("role_name") in BROAD_PRIVILEGE_ROLES
                and scope.startswith("/subscriptions/")
                and scope.count("/") == 2):
            reasons.append(f"{ra.get('role_name')} on {scope}")
            break

    # 2) Dormant ≥ 90d (regardless of telemetry — pure activity check).
    last_act = agent_meta.get("last_activity_date") or agent_meta.get("last_sign_in")
    if last_act is not None:
        try:
            if isinstance(last_act, datetime):
                la = last_act if last_act.tzinfo else last_act.replace(tzinfo=timezone.utc)
            else:
                la = datetime.fromisoformat(str(last_act).replace("Z", "+00:00"))
                if la.tzinfo is None:
                    la = la.replace(tzinfo=timezone.utc)
            if (datetime.now(timezone.utc) - la).days >= 90:
                reasons.append(f"Dormant since {la.date().isoformat()}")
        except Exception:
            pass

    if not reasons:
        if has_exception:
            return {"grade": "PASS",
                    "evidence": "Approved governance exception on file"}
        return {"grade": "PASS",
                "evidence": "No broad-privilege or dormancy concerns detected"}

    if has_exception:
        return {"grade": "PASS",
                "evidence": "Risk-accepted via governance exception: " + "; ".join(reasons)}
    return {"grade": "FAIL", "evidence": "; ".join(reasons)}


# ─────────────────────────────────────────────────────────────────────────────
# Penalty resolver — given a dimension result, return the numeric penalty
# ─────────────────────────────────────────────────────────────────────────────

def _penalty(dim_key: str, grade: str, weights: dict[str, Any]) -> float:
    if dim_key == "ownership":
        return float(weights["ownership_penalty_fail"]) if grade == "FAIL" else 0.0
    if dim_key == "secrets":
        return float({
            "CRITICAL": weights["secrets_penalty_critical"],
            "HIGH":     weights["secrets_penalty_high"],
            "MEDIUM":   weights["secrets_penalty_medium"],
            "LOW":      weights["secrets_penalty_low"],
            "NONE":     weights["secrets_penalty_none"],
        }.get(grade, 0))
    if dim_key == "egress":
        return float(weights["egress_penalty_fail"]) if grade == "FAIL" else 0.0
    if dim_key == "telemetry":
        return float({
            "NONE":    weights["telemetry_penalty_none"],
            "PARTIAL": weights["telemetry_penalty_partial"],
            "FULL":    weights["telemetry_penalty_full"],
        }.get(grade, 0))
    if dim_key == "oversight":
        return float(weights["oversight_penalty_fail"]) if grade == "FAIL" else 0.0
    # AG-T1.3: 4 new dimensions
    if dim_key == "data_access":
        return float({
            "CRITICAL": weights["data_access_penalty_critical"],
            "HIGH":     weights["data_access_penalty_high"],
            "MEDIUM":   weights["data_access_penalty_medium"],
            "NONE":     weights["data_access_penalty_none"],
        }.get(grade, 0))
    if dim_key == "network":
        return float(weights["network_penalty_fail"]) if grade == "FAIL" else 0.0
    if dim_key == "model_exposure":
        return float({
            "MULTI": weights["model_exposure_penalty_multi"],
            "ONE":   weights["model_exposure_penalty_one"],
            "NONE":  0.0,
        }.get(grade, 0))
    if dim_key == "supply_chain":
        return float(weights["supply_chain_penalty_fail"]) if grade == "FAIL" else 0.0
    return 0.0


# ─────────────────────────────────────────────────────────────────────────────
# AG-T1.3: New dimension grade helpers
# ─────────────────────────────────────────────────────────────────────────────

def _grade_data_access(reachability: list[dict]) -> dict[str, Any]:
    """Grade reachable data classifications.

    CRITICAL: writes to PHI
    HIGH:     reads PHI or PCI
    MEDIUM:   reads PII or FINANCIAL
    NONE:     no classified reachability

    Reachability rows come from agent_data_reachability (loaded by the
    batch query). Each row has data_classification, est_records,
    write_resource_count.
    """
    has_phi_write = False
    has_phi_read = False
    has_pci_read = False
    has_pii_read = False
    has_fin_read = False
    worst_cls = None
    worst_records = 0

    for r in reachability:
        cls = (r.get("data_classification") or "").upper()
        if not cls:
            continue
        w = int(r.get("write_resource_count") or 0)
        recs = int(r.get("est_records") or 0)
        if recs > worst_records:
            worst_records = recs
            worst_cls = cls
        if cls == "PHI":
            if w > 0:
                has_phi_write = True
            else:
                has_phi_read = True
        elif cls == "PCI":
            has_pci_read = True
        elif cls == "PII":
            has_pii_read = True
        elif cls == "FINANCIAL":
            has_fin_read = True

    if has_phi_write:
        return {"grade": "CRITICAL",
                "evidence": f"Write access to PHI ({worst_records:,} records)" if worst_records else "Write access to PHI"}
    if has_phi_read or has_pci_read:
        cls = "PHI" if has_phi_read else "PCI"
        return {"grade": "HIGH",
                "evidence": f"Read access to {cls} ({worst_records:,} records)" if worst_records else f"Read access to {cls}"}
    if has_pii_read or has_fin_read:
        cls = "PII" if has_pii_read else "FINANCIAL"
        return {"grade": "MEDIUM",
                "evidence": f"Read access to {cls} ({worst_records:,} records)" if worst_records else f"Read access to {cls}"}
    return {"grade": "NONE",
            "evidence": "No classified data reachability"}


def _grade_network(network_flags: dict) -> dict[str, str]:
    """FAIL if the AI agent's linked Cog Services account is public-network-exposed.

    network_flags['public_endpoint'] is set by the batch query.
    """
    if network_flags.get("public_endpoint"):
        acct = network_flags.get("account_name") or "linked Cognitive Services account"
        return {"grade": "FAIL",
                "evidence": f"{acct} has public_network_access = Enabled"}
    if network_flags.get("private_endpoint"):
        return {"grade": "PASS",
                "evidence": "Private Endpoint only (no public-network exposure)"}
    return {"grade": "PASS",
            "evidence": "No public network exposure on linked AI resources"}


def _grade_model_exposure(model_count: int) -> dict[str, Any]:
    """MULTI if the agent uses ≥3 distinct models; ONE if 1-2; NONE if 0.

    Multi-model usage expands the prompt/tool attack surface.
    """
    if model_count >= 3:
        return {"grade": "MULTI",
                "count": model_count,
                "evidence": f"{model_count} distinct models in use (multi-model agent expands attack surface)"}
    if model_count >= 1:
        return {"grade": "ONE",
                "count": model_count,
                "evidence": f"{model_count} model(s) in use"}
    return {"grade": "NONE",
            "count": 0,
            "evidence": "No model deployments detected"}


def _grade_supply_chain(provenance: dict) -> dict[str, str]:
    """FAIL if the agent uses fine-tuned or non-Microsoft-OpenAI models without
    explicit vendor approval. Provenance is set by the batch query.
    """
    if provenance.get("has_finetune"):
        return {"grade": "FAIL",
                "evidence": f"Uses fine-tuned model: {provenance.get('finetune_name','(unknown)')}"}
    if provenance.get("has_unverified_vendor"):
        return {"grade": "FAIL",
                "evidence": f"Uses model from unverified vendor: {provenance.get('vendor','(unknown)')}"}
    return {"grade": "PASS",
            "evidence": "All models from verified vendor (Microsoft / OpenAI base catalog)"}


# ─────────────────────────────────────────────────────────────────────────────
# Public: single-agent trust score
# ─────────────────────────────────────────────────────────────────────────────

def compute_agent_trust(cursor: Any, identity_db_id: int) -> dict[str, Any]:
    """Compute the full Trust result for one AI agent.

    For repeated cohort use (board scorecard, AI Agents list page) prefer
    `compute_agent_trust_batch` — single-call form re-queries settings and
    role_assignments per call.
    """
    if not identity_db_id:
        return _empty_result()
    results = compute_agent_trust_batch(cursor, [int(identity_db_id)])
    return results.get(int(identity_db_id), _empty_result())


# ─────────────────────────────────────────────────────────────────────────────
# Public: batch trust score (single query per source table)
# ─────────────────────────────────────────────────────────────────────────────

def compute_agent_trust_batch(
    cursor: Any,
    identity_db_ids: Iterable[int],
) -> dict[int, dict[str, Any]]:
    """Compute Trust for many identities at once with no N+1.

    Issues exactly four SQL queries regardless of cohort size:
      1. identities (agent_meta)
      2. role_assignments (all RBAC for the cohort)
      3. sp_ownership (presence check)
      4. ai_governance_exceptions (active status, gracefully absent)
    """
    ids = [int(i) for i in identity_db_ids if i is not None]
    if not ids:
        return {}

    weights = _resolve_weights(cursor)
    window_days = int(weights.get("telemetry_window_days",
                                   DEFAULTS["telemetry_window_days"]))

    # 1) Agent metadata.
    meta_by_id: dict[int, dict[str, Any]] = {}
    try:
        cursor.execute(
            """
            SELECT id,
                   identity_id,
                   display_name,
                   owner_display_name,
                   owner_count,
                   last_sign_in,
                   last_activity_date,
                   credential_status,
                   credential_expiration,
                   organization_id,
                   discovery_run_id,
                   /* AG-PHASE-ENGINE-DEPTH (2026-06-10): supply chain
                      signals for non-AI NHIs need these fields. */
                   federated_issuer_types,
                   has_federated_credentials
              FROM identities
             WHERE id = ANY(%s)
            """,
            (ids,),
        )
        rows = cursor.fetchall()
    except Exception as exc:  # pragma: no cover — DB shape issue
        logger.warning("compute_agent_trust_batch: identities query failed: %s", exc)
        return {i: _empty_result() for i in ids}

    for r in rows:
        rec = _row_to_dict(r, [
            "id", "identity_id", "display_name", "owner_display_name",
            "owner_count", "last_sign_in", "last_activity_date",
            "credential_status", "credential_expiration",
            "organization_id", "discovery_run_id",
            "federated_issuer_types", "has_federated_credentials",
        ])
        meta_by_id[int(rec["id"])] = rec

    # AG-PHASE-ENGINE-DEPTH (2026-06-10): batch-fetch federated_credentials
    # subjects per identity so detect_signals can flag permissive subject
    # patterns. Best-effort: failures don't break the rest of the batch.
    try:
        cursor.execute(
            """
            SELECT identity_db_id, subject
              FROM federated_credentials
             WHERE identity_db_id = ANY(%s)
            """,
            (ids,),
        )
        for r in cursor.fetchall():
            rec_id = r['identity_db_id'] if isinstance(r, dict) else r[0]
            subj = r['subject'] if isinstance(r, dict) else r[1]
            if rec_id in meta_by_id:
                meta_by_id[rec_id].setdefault('federated_subjects', []).append(subj or '')
    except Exception:
        # federated_credentials table may not exist on older tenants — silent skip
        pass

    # 2) Role assignments.
    roles_by_id: dict[int, list[dict[str, Any]]] = {i: [] for i in ids}
    try:
        cursor.execute(
            """
            SELECT identity_db_id, role_name, scope
              FROM role_assignments
             WHERE identity_db_id = ANY(%s)
            """,
            (ids,),
        )
        for r in cursor.fetchall():
            rec = _row_to_dict(r, ["identity_db_id", "role_name", "scope"])
            iid = rec.get("identity_db_id")
            if iid is None:
                continue
            roles_by_id.setdefault(int(iid), []).append(rec)
    except Exception as exc:  # pragma: no cover
        logger.warning("compute_agent_trust_batch: role_assignments query failed: %s", exc)

    # 3) sp_ownership presence (boolean flag per identity).
    owner_flag: dict[int, bool] = {i: False for i in ids}
    try:
        cursor.execute(
            """
            SELECT DISTINCT identity_db_id
              FROM sp_ownership
             WHERE identity_db_id = ANY(%s)
            """,
            (ids,),
        )
        for r in cursor.fetchall():
            rec = _row_to_dict(r, ["identity_db_id"])
            iid = rec.get("identity_db_id")
            if iid is not None:
                owner_flag[int(iid)] = True
    except Exception as exc:  # pragma: no cover — table may not exist
        logger.debug("sp_ownership lookup skipped: %s", exc)

    # 4) Active governance exceptions (per identity_db_id).
    excp_flag: dict[int, bool] = {i: False for i in ids}
    try:
        cursor.execute(
            """
            SELECT DISTINCT identity_db_id
              FROM ai_governance_exceptions
             WHERE identity_db_id = ANY(%s)
               AND status = 'approved'
               AND (expires_at IS NULL OR expires_at > NOW())
            """,
            (ids,),
        )
        for r in cursor.fetchall():
            rec = _row_to_dict(r, ["identity_db_id"])
            iid = rec.get("identity_db_id")
            if iid is not None:
                excp_flag[int(iid)] = True
    except Exception as exc:  # pragma: no cover — table optional
        logger.debug("ai_governance_exceptions lookup skipped: %s", exc)

    # ─── AG-T1.3: 3 more queries for the new dimensions ───────────────
    # 5) Data reachability — one row per (identity, classification).
    reach_by_id: dict[int, list[dict[str, Any]]] = {i: [] for i in ids}
    try:
        cursor.execute(
            """
            SELECT identity_db_id, data_classification, est_records, write_resource_count
              FROM agent_data_reachability
             WHERE identity_db_id = ANY(%s)
            """,
            (ids,),
        )
        for r in cursor.fetchall():
            rec = _row_to_dict(r, ["identity_db_id", "data_classification",
                                   "est_records", "write_resource_count"])
            iid = rec.get("identity_db_id")
            if iid is not None:
                reach_by_id.setdefault(int(iid), []).append(rec)
    except Exception as exc:  # pragma: no cover
        logger.debug("agent_data_reachability lookup skipped: %s", exc)

    # 6) Network posture — public-network status of the linked Cog Services
    #    account. JOIN identity → agent_classifications.account_resource_id →
    #    azure_cognitive_services_accounts. A NULL account means no Cog
    #    Services link (e.g., human ai_privileged_human) — treat as PASS.
    network_by_id: dict[int, dict[str, Any]] = {i: {"public_endpoint": False,
                                                     "private_endpoint": False,
                                                     "account_name": None}
                                                for i in ids}
    try:
        cursor.execute(
            """
            SELECT ac.identity_db_id,
                   csa.name,
                   LOWER(COALESCE(csa.public_network_access, '')) AS public_access,
                   COALESCE(csa.private_endpoint_count, 0) AS pec
              FROM agent_classifications ac
              JOIN azure_cognitive_services_accounts csa
                ON csa.resource_id = ac.account_resource_id
               AND csa.organization_id = ac.organization_id
             WHERE ac.identity_db_id = ANY(%s)
            """,
            (ids,),
        )
        for r in cursor.fetchall():
            rec = _row_to_dict(r, ["identity_db_id", "name", "public_access", "pec"])
            iid = rec.get("identity_db_id")
            if iid is None:
                continue
            network_by_id[int(iid)] = {
                "account_name":      rec.get("name"),
                "public_endpoint":   rec.get("public_access") == "enabled",
                "private_endpoint":  (rec.get("pec") or 0) > 0,
            }
    except Exception as exc:  # pragma: no cover — schema older than expected
        logger.debug("cog services network lookup skipped: %s", exc)

    # 7) Model exposure + supply chain — count distinct models per agent
    #    AND check provenance (fine-tunes / non-Microsoft vendors).
    models_by_id: dict[int, dict[str, Any]] = {i: {"count": 0,
                                                    "has_finetune": False,
                                                    "finetune_name": None,
                                                    "has_unverified_vendor": False,
                                                    "vendor": None}
                                               for i in ids}
    try:
        cursor.execute(
            """
            SELECT ac.identity_db_id,
                   COUNT(DISTINCT aimd.model_name)                              AS model_count,
                   BOOL_OR(LOWER(COALESCE(aimd.model_name, '')) LIKE '%%-ft-%%') AS has_ft,
                   MAX(CASE WHEN LOWER(COALESCE(aimd.model_name, '')) LIKE '%%-ft-%%'
                            THEN aimd.model_name END)                            AS ft_name,
                   BOOL_OR(LOWER(COALESCE(aimd.model_format, '')) NOT IN
                           ('openai', 'azureopenai', 'microsoft', ''))           AS has_unverified,
                   MAX(CASE WHEN LOWER(COALESCE(aimd.model_format, '')) NOT IN
                                 ('openai', 'azureopenai', 'microsoft', '')
                            THEN aimd.model_format END)                          AS vendor
              FROM agent_classifications ac
              JOIN azure_ai_model_deployments aimd
                ON aimd.account_resource_id = ac.account_resource_id
               AND aimd.organization_id = ac.organization_id
             WHERE ac.identity_db_id = ANY(%s)
             GROUP BY ac.identity_db_id
            """,
            (ids,),
        )
        for r in cursor.fetchall():
            rec = _row_to_dict(r, ["identity_db_id", "model_count",
                                   "has_ft", "ft_name",
                                   "has_unverified", "vendor"])
            iid = rec.get("identity_db_id")
            if iid is None:
                continue
            models_by_id[int(iid)] = {
                "count":                  int(rec.get("model_count") or 0),
                "has_finetune":           bool(rec.get("has_ft")),
                "finetune_name":          rec.get("ft_name"),
                "has_unverified_vendor":  bool(rec.get("has_unverified")),
                "vendor":                 rec.get("vendor"),
            }
    except Exception as exc:  # pragma: no cover
        logger.debug("model deployments lookup skipped: %s", exc)

    # Compose result per id.
    out: dict[int, dict[str, Any]] = {}
    for iid in ids:
        meta = meta_by_id.get(iid)
        if not meta:
            out[iid] = _empty_result()
            continue
        ras = roles_by_id.get(iid, [])

        ownership = _grade_ownership(meta, owner_flag.get(iid, False))
        secrets   = _grade_secrets(ras)
        egress    = _grade_egress(ras, meta)
        telemetry = _grade_telemetry(meta, window_days)
        oversight = _grade_oversight(ras, meta, excp_flag.get(iid, False))
        # AG-T1.3: 4 new dimensions
        data_access    = _grade_data_access(reach_by_id.get(iid, []))
        network        = _grade_network(network_by_id.get(iid, {}))
        model_exposure = _grade_model_exposure(models_by_id.get(iid, {}).get("count", 0))
        supply_chain   = _grade_supply_chain(models_by_id.get(iid, {}))

        penalty = (
            _penalty("ownership", ownership["grade"], weights)
            + _penalty("secrets",  secrets["grade"],  weights)
            + _penalty("egress",   egress["grade"],   weights)
            + _penalty("telemetry", telemetry["grade"], weights)
            + _penalty("oversight", oversight["grade"], weights)
            + _penalty("data_access",    data_access["grade"],    weights)
            + _penalty("network",        network["grade"],        weights)
            + _penalty("model_exposure", model_exposure["grade"], weights)
            + _penalty("supply_chain",   supply_chain["grade"],   weights)
        )
        score = int(round(max(0.0, min(100.0, 100.0 - penalty))))

        out[iid] = {
            "trust_score": score,
            "ownership":   ownership,
            "secrets":     secrets,
            "egress":      egress,
            "telemetry":   telemetry,
            "oversight":   oversight,
            # AG-T1.3
            "data_access":    data_access,
            "network":        network,
            "model_exposure": model_exposure,
            "supply_chain":   supply_chain,
        }
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _empty_result() -> dict[str, Any]:
    """Neutral result used when the identity cannot be loaded."""
    return {
        "trust_score": 0,
        "ownership": {"grade": "FAIL", "evidence": "Identity not found"},
        "secrets":   {"grade": "NONE", "role_name": None, "scope": None,
                      "evidence": "Identity not found"},
        "egress":    {"grade": "FAIL", "evidence": "Identity not found"},
        "telemetry": {"grade": "NONE", "evidence": "Identity not found"},
        "oversight": {"grade": "FAIL", "evidence": "Identity not found"},
        # AG-T1.3
        "data_access":    {"grade": "NONE",  "evidence": "Identity not found"},
        "network":        {"grade": "PASS",  "evidence": "Identity not found"},
        "model_exposure": {"grade": "NONE",  "count": 0, "evidence": "Identity not found"},
        "supply_chain":   {"grade": "PASS",  "evidence": "Identity not found"},
    }


def _row_to_dict(row: Any, columns: list[str]) -> dict[str, Any]:
    """Coerce a psycopg2 row (dict, tuple, or DictRow) into a plain dict.

    Mirrors the helper in access_resolution._extract_* — tolerating mixed
    cursor factories means callers don't have to wrap RealDictCursor.
    """
    if row is None:
        return {}
    if isinstance(row, dict):
        return {c: row.get(c) for c in columns}
    try:
        return {columns[i]: row[i] for i in range(min(len(columns), len(row)))}
    except (IndexError, TypeError, KeyError):
        return {}


def compute_org_trust_rollup(cursor: Any, org_id: int,
                              trust_below: int = 50,
                              identity_scope: str = 'nhi') -> dict[str, Any]:
    """Org-wide Identity Trust rollup.

    AG-PHASE2 (2026-06-09): scope-aware. Was NHI-only; now accepts
    'human', 'nhi', 'ai', or 'all' so the same scorer powers the new
    per-type Trust pages (Human Trust, NHI Trust, AI Trust) without
    duplicating the engine.

    Args:
      org_id: tenant scope
      trust_below: threshold for "low trust" bucket
      identity_scope:
        'human' → human_user + guest
        'nhi'   → service_principal + managed_identity_system + managed_identity_user (default — preserves legacy behavior)
        'ai'    → identities with agent_classifications.agent_identity_type IN ('ai_agent','possible_ai_agent')
        'all'   → everything except microsoft_system
    """
    if identity_scope == 'human':
        cat_filter = "i.identity_category IN ('human_user', 'guest')"
        join_clause = ""
    elif identity_scope == 'ai':
        cat_filter = "ac.agent_identity_type IN ('ai_agent','possible_ai_agent')"
        join_clause = "JOIN agent_classifications ac ON ac.identity_db_id = i.id"
    elif identity_scope == 'all':
        cat_filter = "i.identity_category IS NOT NULL"
        join_clause = ""
    else:  # 'nhi' default
        cat_filter = ("i.identity_category IN "
                      "('service_principal','managed_identity_system','managed_identity_user')")
        join_clause = ""

    cursor.execute(f"""
        SELECT i.id, i.identity_id, i.display_name
          FROM identities i
          {join_clause}
         WHERE i.organization_id = %s
           AND i.deleted_at IS NULL
           AND {cat_filter}
           AND NOT COALESCE(i.is_microsoft_system, false)
    """, (org_id,))
    # Tolerate both RealDictCursor and tuple cursor.
    rows = cursor.fetchall()
    if rows and isinstance(rows[0], dict):
        meta = {r['id']: (r['identity_id'], r['display_name']) for r in rows}
    else:
        meta = {r[0]: (r[1], r[2]) for r in rows}
    ids = list(meta.keys())
    if not ids:
        return _empty_rollup(trust_below)

    results = compute_agent_trust_batch(cursor, ids)

    by_band = {'strong': 0, 'good': 0, 'elevated': 0, 'critical': 0}
    by_dim_failing: dict[str, int] = {}
    worst: list[dict[str, Any]] = []
    below_count = 0

    for ident_id, t in results.items():
        score = t.get('trust_score')
        if score is None:
            continue
        # Map score → band (matches AgentTrustScoreCard.tsx)
        if   score >= 80: by_band['strong']   += 1
        elif score >= 65: by_band['good']     += 1
        elif score >= 40: by_band['elevated'] += 1
        else:             by_band['critical'] += 1
        if score < trust_below:
            below_count += 1

        # Tally failing dims. FAIL/HIGH/CRITICAL/MULTI/PARTIAL are real failures.
        # NONE is treated as "absence" — counts as failing only for shared dims
        # (telemetry, ownership, secrets, data_access, oversight, egress,
        # network). For AI-specific dims (model_exposure, supply_chain), NONE
        # means "not applicable to this identity type", not a failure.
        ai_only_dims = {'model_exposure', 'supply_chain'}
        failing_dims = []
        for dim_def in AGENT_TRUST_DIMENSIONS:
            dim_name = dim_def['key']
            dim = t.get(dim_name)
            if isinstance(dim, dict):
                grade = (dim.get('grade') or '').upper()
                is_failure = grade in ('FAIL', 'HIGH', 'CRITICAL', 'MULTI', 'PARTIAL')
                if grade == 'NONE' and dim_name not in ai_only_dims:
                    is_failure = True
                if is_failure:
                    by_dim_failing[dim_name] = by_dim_failing.get(dim_name, 0) + 1
                    failing_dims.append(dim_name)

        idn, dn = meta.get(ident_id, (None, None))
        worst.append({
            'identity_db_id': ident_id,
            'identity_id':    idn,
            'display_name':   dn or idn,
            'trust_score':    score,
            'failing_dims':   failing_dims,
            'failing_count':  len(failing_dims),
        })

    worst.sort(key=lambda x: (x['trust_score'], -x['failing_count']))
    return {
        'total_evaluated':       len([r for r in results.values()
                                       if r.get('trust_score') is not None]),
        'by_band':               by_band,
        'by_dim_failing':        by_dim_failing,
        'below_threshold_count': below_count,
        'threshold':             trust_below,
        'worst_identities':      worst[:25],
        'computed_at':           datetime.now(timezone.utc).isoformat(),
    }


def _empty_rollup(trust_below: int) -> dict[str, Any]:
    return {
        'total_evaluated':       0,
        'by_band':               {'strong': 0, 'good': 0, 'elevated': 0, 'critical': 0},
        'by_dim_failing':        {},
        'below_threshold_count': 0,
        'threshold':             trust_below,
        'worst_identities':      [],
        'computed_at':           datetime.now(timezone.utc).isoformat(),
    }


__all__ = [
    "AGENT_TRUST_DIMENSIONS",
    "DEFAULTS",
    "DEFAULTS_JSON_STRING",
    "compute_agent_trust",
    "compute_agent_trust_batch",
    "compute_org_trust_rollup",
]
