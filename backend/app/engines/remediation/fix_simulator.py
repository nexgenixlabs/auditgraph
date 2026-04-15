"""
Fix Simulator — Delta computation for each fix type.

SSOT rule: all scoring logic delegates to CVSSIdentityScorer.
This module never replicates scoring formulas inline.

Each simulate_* method:
  1. Mutates the affected inputs (roles, owners, credentials)
  2. Calls the SSOT scorer to recompute the changed dimension(s)
  3. Recomposes the final score using privilege-modulated composition
  4. Returns the simulated severity_score (0.0–10.0)
"""

from __future__ import annotations

from typing import Any, Dict, List

from app.engines.scoring.cvss_identity_scorer import CVSSIdentityScorer, _clamp


class FixSimulator:
    """Stateless simulator. One CVSSIdentityScorer instance is shared."""

    def __init__(self) -> None:
        self.scorer = CVSSIdentityScorer()

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _final_score(
        blast: float,
        priv: float,
        dormancy: float,
        gov: float,
        cred: float,
        env_mult: float,
    ) -> float:
        """Compose final severity from 5 dimensions + env multiplier.

        Uses privilege-modulated composition: hygiene dimensions
        (dormancy, governance, credential) are capped based on the
        identity's privilege/blast threat level.
        """
        threat = max(blast, priv)
        hygiene = max(dormancy, gov, cred)

        if threat >= 7.0:
            base = max(threat, hygiene)
        elif threat >= 4.0:
            base = max(threat, min(hygiene, 7.5))
        else:
            base = max(threat, min(hygiene, 5.5))

        return _clamp(base * env_mult)

    # ── Sequential simulation (returns all dims for chaining) ───────

    def simulate_with_updated_dims(
        self,
        fix_type: str,
        identity_data: Dict[str, Any],
        role_index: int = -1,
    ) -> Dict[str, Any]:
        """Apply a fix and return ALL updated dimension scores.

        Enables sequential chaining: apply fix 1 → update dims → apply fix 2.
        Delegates to the same scorer methods as the individual simulate_* methods.
        """
        # Copy mutable fields
        blast = identity_data.get("blast_radius_score", 0.0)
        priv = identity_data.get("privilege_score", 0.0)
        dorm = identity_data.get("dormancy_score", 0.0)
        gov = identity_data.get("governance_score", 0.0)
        cred = identity_data.get("credential_score", 0.0)
        env_mult = identity_data.get("env_multiplier", 1.0)
        roles = list(identity_data.get("roles") or [])
        identity_type = identity_data.get("identity_type", "")
        priv_level = identity_data.get("privilege_level", "standard")

        if fix_type == "ESTABLISH_OWNERSHIP":
            mock_owners = [{
                "owner_id": "sim",
                "has_reviewed": True,
                "last_review_at": "2026-04-12T00:00:00Z",
            }]
            gov = self.scorer.compute_governance_score(
                mock_owners, privilege_level=priv_level,
            )

        elif fix_type == "REVOKE_EXCESSIVE_ROLE":
            if 0 <= role_index < len(roles):
                roles = [r for i, r in enumerate(roles) if i != role_index]
            blast = self.scorer.compute_blast_radius_score(roles)
            priv = self.scorer.compute_privilege_score(roles)

        elif fix_type == "REDUCE_SCOPE":
            simulated_roles = []
            for r in roles:
                sl = (r.get("scope_level") or "").lower()
                if sl in ("subscription", "management_group",
                           "managementgroup", "tenant_wide"):
                    simulated_roles.append({**r, "scope_level": "resource_group"})
                else:
                    simulated_roles.append(r)
            roles = simulated_roles
            blast = self.scorer.compute_blast_radius_score(roles)

        elif fix_type == "ROTATE_CREDENTIALS":
            fresh_creds = [{"rotation_status": "current"}]
            cred = self.scorer.compute_credential_score(identity_type, fresh_creds)

        elif fix_type == "ENABLE_PIM":
            gov = max(gov - 2.0, 0.5)

        severity = self._final_score(blast, priv, dorm, gov, cred, env_mult)

        return {
            "severity_score": severity,
            "blast_radius_score": blast,
            "privilege_score": priv,
            "dormancy_score": dorm,
            "governance_score": gov,
            "credential_score": cred,
            "env_multiplier": env_mult,
            "roles": roles,
            "identity_type": identity_type,
            "privilege_level": priv_level,
        }

    # ── 1. ESTABLISH_OWNERSHIP ───────────────────────────────────────

    def simulate_establish_ownership(
        self, identity_data: Dict[str, Any],
    ) -> float:
        """Simulate assigning an owner with a recent review.

        Affected dimension: governance_score only.
        """
        mock_owners = [{
            "owner_id": "sim",
            "has_reviewed": True,
            "last_review_at": "2026-04-12T00:00:00Z",
        }]
        new_gov = self.scorer.compute_governance_score(
            mock_owners,
            privilege_level=identity_data.get("privilege_level", "standard"),
        )
        return self._final_score(
            identity_data["blast_radius_score"],
            identity_data["privilege_score"],
            identity_data["dormancy_score"],
            new_gov,
            identity_data["credential_score"],
            identity_data.get("env_multiplier", 1.0),
        )

    # ── 2. REVOKE_EXCESSIVE_ROLE ─────────────────────────────────────

    def simulate_revoke_role(
        self,
        identity_data: Dict[str, Any],
        role_index: int,
    ) -> float:
        """Simulate removing a single role assignment.

        Affected dimensions: blast_radius_score, privilege_score.
        """
        roles = list(identity_data.get("roles") or [])
        remaining = [r for i, r in enumerate(roles) if i != role_index]
        new_blast = self.scorer.compute_blast_radius_score(remaining)
        new_priv = self.scorer.compute_privilege_score(remaining)
        return self._final_score(
            new_blast,
            new_priv,
            identity_data["dormancy_score"],
            identity_data["governance_score"],
            identity_data["credential_score"],
            identity_data.get("env_multiplier", 1.0),
        )

    # ── 3. REDUCE_SCOPE ─────────────────────────────────────────────

    def simulate_reduce_scope(
        self, identity_data: Dict[str, Any],
    ) -> float:
        """Simulate downgrading all wide-scope roles to resource_group.

        Affected dimension: blast_radius_score only.
        """
        simulated_roles = []
        for r in (identity_data.get("roles") or []):
            sl = (r.get("scope_level") or "").lower()
            if sl in ("subscription", "management_group",
                       "managementgroup", "tenant_wide"):
                simulated_roles.append({**r, "scope_level": "resource_group"})
            else:
                simulated_roles.append(r)
        new_blast = self.scorer.compute_blast_radius_score(simulated_roles)
        return self._final_score(
            new_blast,
            identity_data["privilege_score"],
            identity_data["dormancy_score"],
            identity_data["governance_score"],
            identity_data["credential_score"],
            identity_data.get("env_multiplier", 1.0),
        )

    # ── 4. ROTATE_CREDENTIALS ───────────────────────────────────────

    def simulate_rotate_credentials(
        self, identity_data: Dict[str, Any],
    ) -> float:
        """Simulate fresh credential rotation (all → 'current').

        Affected dimension: credential_score only.
        """
        fresh_creds = [{"rotation_status": "current"}]
        new_cred = self.scorer.compute_credential_score(
            identity_data.get("identity_type", ""),
            fresh_creds,
        )
        return self._final_score(
            identity_data["blast_radius_score"],
            identity_data["privilege_score"],
            identity_data["dormancy_score"],
            identity_data["governance_score"],
            new_cred,
            identity_data.get("env_multiplier", 1.0),
        )

    # ── 5. ENABLE_PIM ───────────────────────────────────────────────

    def simulate_enable_pim(
        self, identity_data: Dict[str, Any],
    ) -> float:
        """Simulate PIM activation (JIT reduces governance risk by 2.0 pts).

        Affected dimension: governance_score only (floor 0.5).
        """
        current_gov = identity_data.get("governance_score", 5.0)
        new_gov = max(current_gov - 2.0, 0.5)
        return self._final_score(
            identity_data["blast_radius_score"],
            identity_data["privilege_score"],
            identity_data["dormancy_score"],
            new_gov,
            identity_data["credential_score"],
            identity_data.get("env_multiplier", 1.0),
        )
