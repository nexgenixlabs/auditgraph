"""
Fix Prioritizer — Loads identity data, evaluates fixes, ranks top 3.

Also provides org-level top 3 for the CISO dashboard.

Priority formula:
    priority_score = risk_reduction_pct × 0.6
                   + (1 / effort_minutes) × 100 × 0.3
                   + len(framework_badges) × 5 × 0.1

All scoring delegates to CVSSIdentityScorer via FixSimulator (SSOT).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.engines.scoring.cvss_identity_scorer import cvss_band
from app.engines.scoring.posture_scorer import PostureScorer
from app.engines.remediation.fix_catalogue import (
    EXCESSIVE_ROLES,
    FIX_CATALOGUE,
    FixType,
    NHI_TYPES,
    WIDE_SCOPE_LEVELS,
)
from app.engines.remediation.fix_simulator import FixSimulator

logger = logging.getLogger(__name__)


class FixPrioritizer:
    """Evaluate, simulate, and rank remediation fixes for identities."""

    def __init__(self) -> None:
        self.simulator = FixSimulator()

    # ═════════════════════════════════════════════════════════════════
    # Per-identity top 3
    # ═════════════════════════════════════════════════════════════════

    def get_top_3_fixes(
        self,
        cursor: Any,
        identity_id: str,
        org_id: int,
        run_ids: List[int],
    ) -> List[Dict[str, Any]]:
        """Load full identity data, evaluate all fix types, return top 3."""
        identity = self._load_full_identity(
            cursor, identity_id, org_id, run_ids,
        )
        if not identity:
            return []

        current_score = identity["severity_score"]
        if current_score <= 0:
            return []

        candidates: List[Dict[str, Any]] = []

        # 1. ESTABLISH_OWNERSHIP — orphaned / unowned
        if identity.get("governance") == "Orphaned":
            sim = self.simulator.simulate_establish_ownership(identity)
            fix = self._build_fix(
                FixType.ESTABLISH_OWNERSHIP, identity,
                current_score, sim,
            )
            if fix:
                candidates.append(fix)

        # 2. REVOKE_EXCESSIVE_ROLE — find best single role removal
        best_revoke = self._evaluate_best_revoke(identity, current_score)
        if best_revoke:
            candidates.append(best_revoke)

        # 3. REDUCE_SCOPE — any role at subscription+ scope
        has_sub_scope = any(
            (r.get("scope_level") or "").lower() in WIDE_SCOPE_LEVELS
            for r in (identity.get("roles") or [])
        )
        if has_sub_scope:
            sim = self.simulator.simulate_reduce_scope(identity)
            fix = self._build_fix(
                FixType.REDUCE_SCOPE, identity,
                current_score, sim,
            )
            if fix:
                candidates.append(fix)

        # 4. ROTATE_CREDENTIALS — NHI only, credential age > 90 days
        it = (identity.get("identity_type") or "").lower().replace(" ", "_")
        if it in NHI_TYPES and identity.get("credential_max_age_days", 0) > 90:
            sim = self.simulator.simulate_rotate_credentials(identity)
            fix = self._build_fix(
                FixType.ROTATE_CREDENTIALS, identity,
                current_score, sim,
            )
            if fix:
                candidates.append(fix)

        # 5. ENABLE_PIM — human users with privilege_score >= 7.0
        if it in ("human_user", "guest") and identity.get("privilege_score", 0) >= 7.0:
            sim = self.simulator.simulate_enable_pim(identity)
            fix = self._build_fix(
                FixType.ENABLE_PIM, identity,
                current_score, sim,
            )
            if fix:
                candidates.append(fix)

        # Compute priority scores and rank
        for c in candidates:
            defn = FIX_CATALOGUE[FixType(c["fix_type"])]
            c["priority_score"] = round(
                c["risk_reduction_pct"] * 0.6
                + (1.0 / defn.effort_minutes) * 100 * 0.3
                + len(defn.framework_badges) * 5 * 0.1,
                2,
            )

        ranked = sorted(
            candidates,
            key=lambda x: x["priority_score"],
            reverse=True,
        )
        return ranked[:3]

    def get_top_3_fixes_with_projection(
        self,
        cursor: Any,
        identity_id: str,
        org_id: int,
        run_ids: List[int],
    ) -> Dict[str, Any]:
        """Return (fixes, identity, projected_impact) in one pass.

        Avoids double _load_full_identity call by sharing the loaded
        identity between fix evaluation and impact projection.
        """
        identity = self._load_full_identity(
            cursor, identity_id, org_id, run_ids,
        )
        if not identity:
            return {"fixes": [], "identity": None, "projected_impact": None}

        current_score = identity["severity_score"]
        if current_score <= 0:
            return {"fixes": [], "identity": identity, "projected_impact": None}

        # Evaluate fixes (same logic as get_top_3_fixes but reuses identity)
        candidates: List[Dict[str, Any]] = []

        if identity.get("governance") == "Orphaned":
            sim = self.simulator.simulate_establish_ownership(identity)
            fix = self._build_fix(
                FixType.ESTABLISH_OWNERSHIP, identity, current_score, sim,
            )
            if fix:
                candidates.append(fix)

        best_revoke = self._evaluate_best_revoke(identity, current_score)
        if best_revoke:
            candidates.append(best_revoke)

        has_sub_scope = any(
            (r.get("scope_level") or "").lower() in WIDE_SCOPE_LEVELS
            for r in (identity.get("roles") or [])
        )
        if has_sub_scope:
            sim = self.simulator.simulate_reduce_scope(identity)
            fix = self._build_fix(
                FixType.REDUCE_SCOPE, identity, current_score, sim,
            )
            if fix:
                candidates.append(fix)

        it = (identity.get("identity_type") or "").lower().replace(" ", "_")
        if it in NHI_TYPES and identity.get("credential_max_age_days", 0) > 90:
            sim = self.simulator.simulate_rotate_credentials(identity)
            fix = self._build_fix(
                FixType.ROTATE_CREDENTIALS, identity, current_score, sim,
            )
            if fix:
                candidates.append(fix)

        if it in ("human_user", "guest") and identity.get("privilege_score", 0) >= 7.0:
            sim = self.simulator.simulate_enable_pim(identity)
            fix = self._build_fix(
                FixType.ENABLE_PIM, identity, current_score, sim,
            )
            if fix:
                candidates.append(fix)

        for c in candidates:
            defn = FIX_CATALOGUE[FixType(c["fix_type"])]
            c["priority_score"] = round(
                c["risk_reduction_pct"] * 0.6
                + (1.0 / defn.effort_minutes) * 100 * 0.3
                + len(defn.framework_badges) * 5 * 0.1,
                2,
            )

        ranked = sorted(
            candidates, key=lambda x: x["priority_score"], reverse=True,
        )[:3]

        projected = self.compute_projected_impact(
            ranked, identity, cursor, org_id,
        )

        return {
            "fixes": ranked,
            "identity": identity,
            "projected_impact": projected,
        }

    def compute_projected_impact(
        self,
        fixes: List[Dict[str, Any]],
        identity: Dict[str, Any],
        cursor: Any,
        org_id: int,
    ) -> Optional[Dict[str, Any]]:
        """Sequentially apply all fixes and compute final projected state.

        Uses simulate_with_updated_dims for chaining: each fix updates
        the running identity dimensions before the next fix is applied.
        """
        if not fixes or not identity:
            return None

        current_score = identity["severity_score"]
        current_band = identity.get("cvss_band", "INFO")
        env_tier = (identity.get("env_tier") or "unknown").lower()

        # Build a running copy of dims for sequential application
        running = {
            "blast_radius_score": identity["blast_radius_score"],
            "privilege_score": identity["privilege_score"],
            "dormancy_score": identity["dormancy_score"],
            "governance_score": identity["governance_score"],
            "credential_score": identity["credential_score"],
            "env_multiplier": identity.get("env_multiplier", 1.0),
            "roles": list(identity.get("roles") or []),
            "identity_type": identity.get("identity_type", ""),
            "privilege_level": identity.get("privilege_level", "standard"),
        }

        for fix in fixes:
            result = self.simulator.simulate_with_updated_dims(
                fix["fix_type"], running,
            )
            # Update running dims for next fix in chain
            running.update(result)

        simulated_score = running["severity_score"]
        simulated_band = cvss_band(simulated_score)
        reduction_pct = round(
            (current_score - simulated_score) / current_score * 100, 1,
        ) if current_score > 0 else 0.0

        # Posture score delta estimate
        bw = PostureScorer.BAND_WEIGHTS
        ew = PostureScorer.ENV_WEIGHTS
        env_w = ew.get(env_tier, 1.0)

        # Get identity count for posture delta
        try:
            cursor.execute(
                "SELECT COUNT(*) FROM identity_list "
                "WHERE organization_id = %s "
                "AND NOT COALESCE(is_microsoft_system, false) "
                "AND score_computed_at IS NOT NULL",
                (org_id,),
            )
            identity_count = cursor.fetchone()[0] or 1
        except Exception:
            identity_count = 1

        old_contribution = current_score * bw.get(current_band, 0) * env_w
        new_contribution = simulated_score * bw.get(simulated_band, 0) * env_w
        posture_delta = round(
            (old_contribution - new_contribution) / identity_count, 2,
        )

        return {
            "simulated_score": round(simulated_score, 2),
            "simulated_band": simulated_band,
            "risk_reduction_pct": reduction_pct,
            "posture_score_delta": posture_delta,
        }

    # ═════════════════════════════════════════════════════════════════
    # Org-level top 3 (CISO dashboard)
    # ═════════════════════════════════════════════════════════════════

    def get_org_top_3(
        self,
        cursor: Any,
        org_id: int,
    ) -> List[Dict[str, Any]]:
        """Aggregate top 3 fix actions across the whole org."""

        # ── Action 1: ESTABLISH ownership ──
        cursor.execute(
            "SELECT COUNT(*) FROM identity_list "
            "WHERE organization_id = %s "
            "AND NOT COALESCE(is_microsoft_system, false) "
            "AND governance = 'Orphaned' "
            "AND cvss_band IN ('CRITICAL','HIGH','MEDIUM')",
            (org_id,),
        )
        ownership_gap_count = cursor.fetchone()[0] or 0

        ownership_risk_pct = 0.0
        if ownership_gap_count > 0:
            cursor.execute(
                "SELECT severity_score, governance_score, "
                "blast_radius_score, privilege_score, "
                "dormancy_score, credential_score, env_multiplier "
                "FROM identity_list "
                "WHERE organization_id = %s "
                "AND NOT COALESCE(is_microsoft_system, false) "
                "AND governance = 'Orphaned' "
                "AND cvss_band IN ('CRITICAL','HIGH','MEDIUM')",
                (org_id,),
            )
            rows = cursor.fetchall()
            total_current = sum(r[0] for r in rows)
            total_simulated = sum(
                min(
                    max(r[2], r[3], r[4], 0.5, r[5]) * r[6],
                    10.0,
                )
                for r in rows
            )
            if total_current > 0:
                ownership_risk_pct = round(
                    (total_current - total_simulated)
                    / total_current * 100,
                    1,
                )

        # ── Action 2: REMOVE unauthorized access paths ──
        attack_path_count = 0
        try:
            cursor.execute(
                "SELECT COUNT(*) FROM attack_paths "
                "WHERE organization_id = %s",
                (org_id,),
            )
            attack_path_count = cursor.fetchone()[0] or 0
        except Exception:
            pass

        remove_risk_pct = round(
            min(attack_path_count * 0.5, 15.0), 1,
        ) if attack_path_count > 0 else 0.0

        # ── Action 3: REDUCE excessive access ──
        excess_scope_count = 0
        reduce_risk_pct = 0.0
        try:
            cursor.execute(
                "SELECT COUNT(DISTINCT il.identity_id), "
                "COALESCE(AVG(il.severity_score), 0) "
                "FROM identity_list il "
                "JOIN role_assignments ra "
                "  ON ra.principal_id = il.identity_id "
                "  AND ra.organization_id = il.organization_id "
                "WHERE il.organization_id = %s "
                "AND NOT COALESCE(il.is_microsoft_system, false) "
                "AND ra.scope_type = 'subscription' "
                "AND il.privilege_score >= 5.0",
                (org_id,),
            )
            row = cursor.fetchone()
            excess_scope_count = row[0] or 0
            avg_severity = float(row[1] or 0)
            # ~9% reduction from scope narrowing, scaled by severity
            if excess_scope_count > 0 and avg_severity > 0:
                reduce_risk_pct = round(avg_severity * 0.9, 1)
        except Exception:
            pass

        return [
            {
                "rank": 1,
                "verb": "ESTABLISH",
                "title": "Establish ownership for service principals",
                "description": (
                    f"Eliminates ownership gaps and enforces "
                    f"accountability across {ownership_gap_count} "
                    f"at-risk identities."
                ),
                "risk_reduction_pct": ownership_risk_pct,
                "affected_identities": ownership_gap_count,
                "effort_estimate": "2-4 hours",
                "execution_safety": "Safe",
                "framework_badges": ["CIS v8 5.3", "SOC 2"],
            },
            {
                "rank": 2,
                "verb": "REMOVE",
                "title": "Remove unauthorized access paths",
                "description": (
                    f"Closes hidden backdoors from identities "
                    f"with live access. Closes {attack_path_count} "
                    f"hidden access paths."
                ),
                "risk_reduction_pct": remove_risk_pct,
                "affected_identities": attack_path_count,
                "effort_estimate": "30 min per path",
                "execution_safety": "Caution",
                "framework_badges": ["SOC 2"],
            },
            {
                "rank": 3,
                "verb": "REDUCE",
                "title": "Reduce excessive access across identities",
                "description": (
                    f"Eliminates excessive permission exposure "
                    f"across subscriptions for {excess_scope_count} "
                    f"identities."
                ),
                "risk_reduction_pct": reduce_risk_pct,
                "affected_identities": excess_scope_count,
                "effort_estimate": "1-2 hours",
                "execution_safety": "Caution",
                "framework_badges": ["CIS NIST"],
            },
        ]

    # ═════════════════════════════════════════════════════════════════
    # Internal helpers
    # ═════════════════════════════════════════════════════════════════

    def _load_full_identity(
        self,
        cursor: Any,
        identity_id: str,
        org_id: int,
        run_ids: List[int],
    ) -> Optional[Dict[str, Any]]:
        """Load identity + roles + credential age + attack path count."""

        # 1. identity_list — CVSS scores + metadata
        cursor.execute(
            "SELECT identity_id, display_name, identity_type, "
            "privilege_level, governance, lifecycle_state, "
            "env_tier, severity_score, cvss_band, "
            "blast_radius_score, privilege_score, dormancy_score, "
            "governance_score, credential_score, env_multiplier "
            "FROM identity_list "
            "WHERE identity_id = %s AND organization_id = %s",
            (identity_id, org_id),
        )
        row = cursor.fetchone()
        if not row:
            return None

        identity = {
            "identity_id": row[0],
            "organization_id": org_id,
            "display_name": row[1],
            "identity_type": row[2],
            "privilege_level": row[3],
            "governance": row[4],
            "lifecycle_state": row[5],
            "env_tier": row[6],
            "severity_score": float(row[7] or 0),
            "cvss_band": row[8],
            "blast_radius_score": float(row[9] or 0),
            "privilege_score": float(row[10] or 0),
            "dormancy_score": float(row[11] or 0),
            "governance_score": float(row[12] or 0),
            "credential_score": float(row[13] or 0),
            "env_multiplier": float(row[14] or 1.0),
        }

        # 2. Get identities.id for role assignment FK
        cursor.execute(
            "SELECT id FROM identities "
            "WHERE identity_id = %s AND discovery_run_id = ANY(%s) "
            "ORDER BY discovery_run_id DESC LIMIT 1",
            (identity_id, run_ids),
        )
        id_row = cursor.fetchone()
        identity_db_id = id_row[0] if id_row else None

        # 3. RBAC roles (scope_type → scope_level for scorer compat)
        roles: List[Dict[str, Any]] = []
        if identity_db_id:
            cursor.execute(
                "SELECT id, role_name, scope, scope_type, "
                "COALESCE(usage_status, 'unknown') "
                "FROM role_assignments "
                "WHERE identity_db_id = %s",
                (identity_db_id,),
            )
            for rr in cursor.fetchall():
                roles.append({
                    "role_assignment_id": rr[0],
                    "role_name": rr[1],
                    "scope": rr[2],
                    "scope_level": rr[3],  # subscription/resource_group/resource
                    "usage_evidence": rr[4],
                    "source": "rbac",
                })

            # Entra roles (always tenant_wide scope)
            cursor.execute(
                "SELECT id, role_name, "
                "COALESCE(usage_status, 'unknown') "
                "FROM entra_role_assignments "
                "WHERE identity_db_id = %s",
                (identity_db_id,),
            )
            for er in cursor.fetchall():
                roles.append({
                    "role_assignment_id": er[0],
                    "role_name": er[1],
                    "scope": "/",
                    "scope_level": "tenant_wide",
                    "usage_evidence": er[2],
                    "source": "entra",
                })

        identity["roles"] = roles

        # 4. Credential max age (legacy identity_credentials table)
        credential_max_age_days = 0
        try:
            cursor.execute(
                "SELECT MAX(EXTRACT(EPOCH FROM (NOW() - created_at)) / 86400)::int "
                "FROM identity_credentials "
                "WHERE identity_id = %s AND organization_id = %s",
                (identity_id, org_id),
            )
            age_row = cursor.fetchone()
            if age_row and age_row[0]:
                credential_max_age_days = age_row[0]
        except Exception:
            pass
        identity["credential_max_age_days"] = credential_max_age_days

        # 5. Attack path count
        attack_path_count = 0
        try:
            cursor.execute(
                "SELECT COUNT(*) FROM attack_paths "
                "WHERE organization_id = %s "
                "AND source_entity_id = %s",
                (org_id, identity_id),
            )
            ap_row = cursor.fetchone()
            if ap_row:
                attack_path_count = ap_row[0] or 0
        except Exception:
            pass
        identity["attack_path_count"] = attack_path_count

        return identity

    def _evaluate_best_revoke(
        self,
        identity: Dict[str, Any],
        current_score: float,
    ) -> Optional[Dict[str, Any]]:
        """Find the single role revocation with largest delta."""
        roles = identity.get("roles") or []
        best_fix: Optional[Dict[str, Any]] = None
        best_delta = 0.0

        for i, role in enumerate(roles):
            rn = (role.get("role_name") or "").lower().strip()
            sl = (role.get("scope_level") or "").lower()
            usage = (role.get("usage_evidence") or "").lower()
            no_usage = usage in ("", "none", "never_used", "unknown")

            if rn not in EXCESSIVE_ROLES:
                continue
            if sl not in WIDE_SCOPE_LEVELS:
                continue
            if not no_usage:
                continue

            sim = self.simulator.simulate_revoke_role(identity, i)
            delta = current_score - sim
            if delta > best_delta:
                best_delta = delta
                best_fix = self._build_fix(
                    FixType.REVOKE_EXCESSIVE_ROLE, identity,
                    current_score, sim,
                    role_detail=role,
                )

        return best_fix

    def _build_fix(
        self,
        fix_type: FixType,
        identity: Dict[str, Any],
        current_score: float,
        sim_score: float,
        role_detail: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Assemble a fix result dict. Returns None if no improvement."""
        delta_pts = current_score - sim_score
        if delta_pts <= 0:
            return None

        defn = FIX_CATALOGUE[fix_type]
        delta_pct = round(
            delta_pts / current_score * 100, 1,
        ) if current_score > 0 else 0.0

        safety = self._compute_safety(fix_type, identity)

        return {
            "fix_type": fix_type.value,
            "verb": defn.verb,
            "title": defn.title,
            "description": self._build_description(
                fix_type, identity, role_detail,
            ),
            "risk_reduction_pct": delta_pct,
            "risk_reduction_pts": round(-delta_pts, 2),
            "current_score": round(current_score, 2),
            "simulated_score": round(sim_score, 2),
            "simulated_band": cvss_band(sim_score),
            "effort_minutes": defn.effort_minutes,
            "execution_safety": safety["tier"],
            "safety_reason": safety.get("reason"),
            "framework_badges": defn.framework_badges,
            "impacted_paths": identity.get("attack_path_count", 0),
            "scope": self._build_scope(fix_type, identity, role_detail),
            "role_detail": {
                "role_name": role_detail.get("role_name"),
                "scope": role_detail.get("scope"),
                "scope_level": role_detail.get("scope_level"),
            } if role_detail else None,
            "priority_score": 0.0,  # filled by caller
        }

    def _compute_safety(
        self,
        fix_type: FixType,
        identity: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Upgrade safety tier for production or CRITICAL identities."""
        base = FIX_CATALOGUE[fix_type].execution_safety
        env = (identity.get("env_tier") or "").lower()
        score = identity.get("severity_score", 0)

        if env == "production" and fix_type in (
            FixType.REVOKE_EXCESSIVE_ROLE, FixType.REDUCE_SCOPE,
        ):
            return {
                "tier": "Requires Manual Review",
                "reason": "Production environment — CISO approval required",
            }
        if score >= 9.0 and fix_type == FixType.REVOKE_EXCESSIVE_ROLE:
            return {
                "tier": "Requires Manual Review",
                "reason": "CRITICAL identity — elevated approval required",
            }
        return {"tier": base, "reason": None}

    def _build_description(
        self,
        fix_type: FixType,
        identity: Dict[str, Any],
        role_detail: Optional[Dict[str, Any]] = None,
    ) -> str:
        name = identity.get("display_name", "this identity")
        if fix_type == FixType.ESTABLISH_OWNERSHIP:
            return (
                f"Assign an accountable owner to {name}. "
                f"No owner is currently designated — removes governance "
                f"gap and closes accountability chain."
            )
        if fix_type == FixType.REVOKE_EXCESSIVE_ROLE:
            role_name = (role_detail or {}).get("role_name", "privileged role")
            return (
                f"Remove {role_name} from {name}. "
                f"No usage evidence found — role is stale "
                f"and creates unnecessary blast radius."
            )
        if fix_type == FixType.REDUCE_SCOPE:
            return (
                f"Reduce {name} role assignments from "
                f"subscription scope to resource group scope. "
                f"Eliminates lateral movement across subscription."
            )
        if fix_type == FixType.ROTATE_CREDENTIALS:
            return (
                f"Rotate credentials for {name}. "
                f"Current credentials exceed 90-day rotation "
                f"policy per CIS Controls v8 5.2."
            )
        if fix_type == FixType.ENABLE_PIM:
            return (
                f"Enable Azure PIM for {name}. "
                f"Converts standing privileged access to "
                f"just-in-time access with audit trail."
            )
        return ""

    def _build_scope(
        self,
        fix_type: FixType,
        identity: Dict[str, Any],
        role_detail: Optional[Dict[str, Any]] = None,
    ) -> str:
        if fix_type == FixType.REVOKE_EXCESSIVE_ROLE and role_detail:
            sl = (role_detail.get("scope_level") or "").lower()
            if sl in ("subscription", "management_group", "tenant_wide"):
                return f"1 role · {sl} scope"
            return "1 role"
        return "1 identity"
