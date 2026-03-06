"""
Phase 5: Identity Blast Radius Engine

Simulates compromise of each identity and calculates reachable resources,
sensitive assets, and escalation potential.  Produces a blast-radius view
that feeds the Identity Detail UI and the /api/blast-radius endpoints.

Data sources (SELECT only — never mutates upstream tables):
  - identities + role_assignments      → RBAC scope expansion
  - entra_role_assignments             → Entra directory privilege
  - azure_storage_accounts / key_vaults → resource enumeration + classification
  - attack_paths                        → privilege escalation path count
  - fix_recommendations                 → blast radius reduction estimate

Safety limits (imported from AttackPathEngine where applicable):
  MAX_BLAST_RADIUS_IDENTITIES = 1000  — cap identities per run
  MAX_BLAST_RADIUS_RESOURCES  = 5000  — cap resources per identity
"""

import logging
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ── Safety limits ─────────────────────────────────────────────────────
MAX_BLAST_RADIUS_IDENTITIES = 1000
MAX_BLAST_RADIUS_RESOURCES = 5000

# ── Privilege weights for risk scoring ────────────────────────────────
_ENTRA_ROLE_WEIGHT = {
    'Global Administrator': 50,
    'Privileged Role Administrator': 45,
    'Privileged Authentication Administrator': 40,
    'Application Administrator': 35,
    'Cloud Application Administrator': 35,
    'User Administrator': 30,
    'Exchange Administrator': 28,
    'Security Administrator': 30,
    'Hybrid Identity Administrator': 25,
}

_RBAC_ROLE_WEIGHT = {
    'Owner': 40,
    'User Access Administrator': 38,
    'Contributor': 25,
}

_SCOPE_WEIGHT = {
    'management_group': 15,
    'subscription': 10,
    'resource_group': 5,
    'resource': 2,
}

# ── Remediation confidence per fix_type ───────────────────────────────
_REMEDIATION_CONFIDENCE = {
    'remove_role': 'high',
    'enable_mfa': 'high',
    'rotate_credential': 'high',
    'cleanup_disabled_account': 'high',
    'restrict_guest': 'high',
    'disable_public_access': 'high',
    'enable_purge_protection': 'high',
    'narrow_scope': 'medium',
    'enable_pim': 'medium',
    'review_sensitive_access': 'medium',
    'add_private_endpoint': 'medium',
    'segment_lateral_movement': 'medium',
    'harden_pim_policy': 'medium',
    'audit_ownership_chain': 'low',
    'assign_owner': 'low',
}


class BlastRadiusEngine:
    """Calculate blast radius for every non-system identity in a discovery run."""

    def __init__(self, db):
        self.db = db

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, run_id: int) -> List[Dict]:
        """Compute blast radius for all identities in the given run.

        Returns list of result dicts ready for save_blast_radius_results().
        """
        identities = self._load_identities(run_id)
        if not identities:
            logger.info(f"Blast radius: no identities for run #{run_id}")
            return []

        if len(identities) > MAX_BLAST_RADIUS_IDENTITIES:
            logger.warning(
                f"Blast radius: identity count ({len(identities)}) exceeds "
                f"MAX_BLAST_RADIUS_IDENTITIES ({MAX_BLAST_RADIUS_IDENTITIES}), truncating"
            )
            identities = identities[:MAX_BLAST_RADIUS_IDENTITIES]

        # Pre-load shared data for the run
        rbac_by_identity = self._load_rbac_assignments(run_id)
        entra_by_identity = self._load_entra_assignments(run_id)
        resources = self._load_resources(run_id)
        escalation_counts = self._load_escalation_counts(run_id)
        fix_recs = self._load_fix_recommendations(run_id)

        results: List[Dict] = []
        for ident in identities:
            idb_id = ident['id']
            identity_id = ident['identity_id']

            rbac = rbac_by_identity.get(idb_id, [])
            entra = entra_by_identity.get(idb_id, [])

            # Step 1-2: Expand scopes from RBAC assignments
            scopes = self._expand_scopes(rbac)

            # Step 3: Enumerate reachable resources
            reachable = self._enumerate_reachable(scopes, resources)

            # Step 4: Identify sensitive resources
            sensitive_count, sensitive_types = self._detect_sensitive(reachable)

            # Step 5: Escalation path count
            esc_count = escalation_counts.get(identity_id, 0)

            # Step 6: Resource breakdown
            breakdown = self._build_breakdown(reachable)

            # Step 7: Risk score
            risk_score = self._compute_risk_score(
                rbac, entra, reachable, sensitive_count,
                ident['identity_category'], esc_count,
            )

            # Step 8: Exposure level
            exposure = self._classify_exposure(risk_score)

            # Step 9: Risk domain
            risk_domain = self._determine_risk_domain(
                rbac, entra, sensitive_count, reachable,
            )

            # Step 10: Blast radius reduction + remediation confidence
            reduction, confidence = self._estimate_reduction(
                identity_id, reachable, fix_recs,
            )

            # Subscription + RG counts
            sub_ids: Set[str] = set()
            rg_ids: Set[str] = set()
            for r in reachable:
                if r.get('subscription_id'):
                    sub_ids.add(r['subscription_id'])
                if r.get('resource_group'):
                    rg_ids.add(r['resource_group'])

            results.append({
                'identity_id': idb_id,
                'identity_name': ident['display_name'],
                'identity_type': ident['identity_category'],
                'reachable_resource_count': len(reachable),
                'reachable_subscription_count': len(sub_ids),
                'reachable_resource_group_count': len(rg_ids),
                'sensitive_resource_count': sensitive_count,
                'sensitive_data_types': sorted(sensitive_types),
                'resource_breakdown': breakdown,
                'privilege_escalation_paths': esc_count,
                'risk_domain': risk_domain,
                'identity_exposure_level': exposure,
                'blast_radius_reduction': reduction,
                'remediation_confidence': confidence,
                'risk_score': risk_score,
            })

        results.sort(key=lambda r: r['risk_score'], reverse=True)
        logger.info(
            f"Blast radius engine: {len(results)} result(s) for run #{run_id}"
        )
        return results

    # ------------------------------------------------------------------
    # Data loaders
    # ------------------------------------------------------------------

    def _load_identities(self, run_id: int) -> List[Dict]:
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT id, identity_id, display_name, identity_category
                FROM identities
                WHERE discovery_run_id = %s
                  AND is_microsoft_system = FALSE
                ORDER BY id
            """, (run_id,))
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
        finally:
            cursor.close()

    def _load_rbac_assignments(self, run_id: int) -> Dict[int, List[Dict]]:
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT ra.identity_db_id, ra.role_name, ra.scope, ra.scope_type
                FROM role_assignments ra
                JOIN identities i ON i.id = ra.identity_db_id
                WHERE i.discovery_run_id = %s
            """, (run_id,))
            cols = [d[0] for d in cursor.description]
            grouped: Dict[int, List[Dict]] = {}
            for row in cursor.fetchall():
                d = dict(zip(cols, row))
                grouped.setdefault(d['identity_db_id'], []).append(d)
            return grouped
        finally:
            cursor.close()

    def _load_entra_assignments(self, run_id: int) -> Dict[int, List[Dict]]:
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT era.identity_db_id, era.role_name
                FROM entra_role_assignments era
                JOIN identities i ON i.id = era.identity_db_id
                WHERE i.discovery_run_id = %s
            """, (run_id,))
            cols = [d[0] for d in cursor.description]
            grouped: Dict[int, List[Dict]] = {}
            for row in cursor.fetchall():
                d = dict(zip(cols, row))
                grouped.setdefault(d['identity_db_id'], []).append(d)
            return grouped
        finally:
            cursor.close()

    def _load_resources(self, run_id: int) -> List[Dict]:
        """Load storage accounts + key vaults as the resource universe."""
        resources: List[Dict] = []
        cursor = self.db.conn.cursor()
        try:
            for table, rtype in [
                ('azure_storage_accounts', 'storage_account'),
                ('azure_key_vaults', 'key_vault'),
            ]:
                try:
                    cursor.execute(f"""
                        SELECT resource_id, name, resource_group, subscription_id,
                               data_classification
                        FROM {table}
                        WHERE discovery_run_id = %s
                    """, (run_id,))
                    cols = [d[0] for d in cursor.description]
                    for row in cursor.fetchall():
                        d = dict(zip(cols, row))
                        d['resource_type'] = rtype
                        resources.append(d)
                except Exception:
                    pass  # Table may not exist yet
            return resources
        finally:
            cursor.close()

    def _load_escalation_counts(self, run_id: int) -> Dict[str, int]:
        """Count persisted attack paths per source_entity_id."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT source_entity_id, COUNT(*) as cnt
                FROM attack_paths
                WHERE discovery_run_id = %s
                GROUP BY source_entity_id
            """, (run_id,))
            return {row[0]: row[1] for row in cursor.fetchall()}
        except Exception:
            return {}
        finally:
            cursor.close()

    def _load_fix_recommendations(self, run_id: int) -> Dict[str, List[Dict]]:
        """Load open fix recommendations grouped by entity_id."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT entity_id, fix_type, risk_reduction_score
                FROM fix_recommendations
                WHERE discovery_run_id = %s AND status = 'open'
            """, (run_id,))
            cols = [d[0] for d in cursor.description]
            grouped: Dict[str, List[Dict]] = {}
            for row in cursor.fetchall():
                d = dict(zip(cols, row))
                grouped.setdefault(d['entity_id'], []).append(d)
            return grouped
        except Exception:
            # Table or columns may not exist yet — graceful fallback
            return {}
        finally:
            cursor.close()

    # ------------------------------------------------------------------
    # Scope expansion + resource enumeration
    # ------------------------------------------------------------------

    def _expand_scopes(self, rbac: List[Dict]) -> Dict[str, Set[str]]:
        """Expand RBAC assignments into sets of reachable scope prefixes.

        Returns {scope_type: set_of_scope_strings}.
        """
        scopes: Dict[str, Set[str]] = {
            'subscription': set(),
            'resource_group': set(),
            'resource': set(),
            'management_group': set(),
        }
        for ra in rbac:
            st = ra.get('scope_type', '')
            scope = (ra.get('scope') or '').lower()
            if st in scopes and scope:
                scopes[st].add(scope)
                # Subscription scope implies all RGs and resources underneath
                if st in ('subscription', 'management_group'):
                    scopes['subscription'].add(scope)
        return scopes

    def _enumerate_reachable(
        self, scopes: Dict[str, Set[str]], resources: List[Dict],
    ) -> List[Dict]:
        """Determine which resources are reachable given expanded scopes."""
        reachable: List[Dict] = []
        for res in resources:
            if len(reachable) >= MAX_BLAST_RADIUS_RESOURCES:
                logger.warning(
                    f"Blast radius: resource cap ({MAX_BLAST_RADIUS_RESOURCES}) reached"
                )
                break

            res_id = (res.get('resource_id') or '').lower()
            res_sub = (res.get('subscription_id') or '').lower()
            res_rg = (res.get('resource_group') or '').lower()

            matched = False
            # Subscription-scope: identity has access to entire sub
            for sub_scope in scopes.get('subscription', set()):
                if res_sub and res_sub in sub_scope:
                    matched = True
                    break
            if not matched:
                for mg_scope in scopes.get('management_group', set()):
                    if res_sub and res_sub in mg_scope:
                        matched = True
                        break
            # Resource-group scope
            if not matched:
                for rg_scope in scopes.get('resource_group', set()):
                    if res_rg and res_rg.lower() in rg_scope:
                        matched = True
                        break
            # Direct resource scope
            if not matched:
                for r_scope in scopes.get('resource', set()):
                    if res_id and res_id in r_scope:
                        matched = True
                        break

            if matched:
                reachable.append(res)
        return reachable

    # ------------------------------------------------------------------
    # Sensitive data detection
    # ------------------------------------------------------------------

    def _detect_sensitive(
        self, reachable: List[Dict],
    ) -> tuple:
        """Count sensitive resources and collect data types."""
        count = 0
        types: Set[str] = set()
        for r in reachable:
            classification = r.get('data_classification')
            if classification:
                count += 1
                types.add(classification)
        return count, types

    # ------------------------------------------------------------------
    # Resource breakdown
    # ------------------------------------------------------------------

    def _build_breakdown(self, reachable: List[Dict]) -> Dict[str, int]:
        breakdown: Dict[str, int] = {}
        type_map = {
            'storage_account': 'storage_accounts',
            'key_vault': 'key_vaults',
        }
        for r in reachable:
            key = type_map.get(r.get('resource_type', ''), r.get('resource_type', 'other'))
            breakdown[key] = breakdown.get(key, 0) + 1
        return breakdown

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def _compute_risk_score(
        self,
        rbac: List[Dict],
        entra: List[Dict],
        reachable: List[Dict],
        sensitive_count: int,
        identity_category: str,
        escalation_count: int,
    ) -> int:
        """Compute blast radius risk score (0-100).

        Components:
          - Entra role privilege weight (max across roles)
          - RBAC role privilege weight (max across roles)
          - Scope weight (max across assignments)
          - Resource count weight
          - Sensitive data weight
          - External identity weight
          - Escalation path weight
        """
        score = 0.0

        # Entra role weight — take the highest
        if entra:
            entra_max = max(
                _ENTRA_ROLE_WEIGHT.get(e.get('role_name', ''), 0)
                for e in entra
            )
            score += entra_max

        # RBAC role weight — take the highest
        if rbac:
            rbac_max = max(
                _RBAC_ROLE_WEIGHT.get(ra.get('role_name', ''), 0)
                for ra in rbac
            )
            score += rbac_max

        # Scope weight — take the highest
        if rbac:
            scope_max = max(
                _SCOPE_WEIGHT.get(ra.get('scope_type', ''), 0)
                for ra in rbac
            )
            score += scope_max

        # Resource count weight — logarithmic scale, max +10
        if reachable:
            import math
            resource_w = min(10, int(math.log2(max(len(reachable), 1)) * 2))
            score += resource_w

        # Sensitive data exposure
        if sensitive_count > 0:
            score += 15

        # External identity bonus
        if identity_category in ('guest',):
            score += 10

        # Escalation paths
        if escalation_count > 0:
            score += min(10, escalation_count * 3)

        return min(100, max(0, int(score)))

    # ------------------------------------------------------------------
    # Exposure level classification
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_exposure(risk_score: int) -> str:
        if risk_score >= 80:
            return 'CRITICAL'
        if risk_score >= 60:
            return 'HIGH'
        if risk_score >= 40:
            return 'MEDIUM'
        return 'LOW'

    # ------------------------------------------------------------------
    # Risk domain
    # ------------------------------------------------------------------

    @staticmethod
    def _determine_risk_domain(
        rbac: List[Dict],
        entra: List[Dict],
        sensitive_count: int,
        reachable: List[Dict],
    ) -> str:
        """Pick the primary risk domain based on what drives the blast radius."""
        if entra:
            max_entra = max(
                _ENTRA_ROLE_WEIGHT.get(e.get('role_name', ''), 0)
                for e in entra
            )
            if max_entra >= 35:
                return 'identity'
        if sensitive_count > 0:
            return 'data'
        if rbac:
            max_rbac = max(
                _RBAC_ROLE_WEIGHT.get(ra.get('role_name', ''), 0)
                for ra in rbac
            )
            if max_rbac >= 25:
                return 'access'
        if len(reachable) > 0:
            return 'network'
        return 'governance'

    # ------------------------------------------------------------------
    # Blast radius reduction + remediation confidence
    # ------------------------------------------------------------------

    def _estimate_reduction(
        self,
        identity_id: str,
        reachable: List[Dict],
        fix_recs: Dict[str, List[Dict]],
    ) -> tuple:
        """Estimate how many reachable resources would be removed by applying fixes.

        Returns (reduction_count, confidence_level).
        """
        recs = fix_recs.get(identity_id, [])
        if not recs:
            return 0, None

        total_current = len(reachable)
        # Sum risk_reduction_score as a proxy for resource reduction percentage
        total_reduction_pct = 0
        best_confidence = 'low'
        confidence_rank = {'high': 3, 'medium': 2, 'low': 1}

        for r in recs:
            rrs = r.get('risk_reduction_score') or 0
            total_reduction_pct += rrs
            fix_type = r.get('fix_type', '')
            conf = _REMEDIATION_CONFIDENCE.get(fix_type, 'low')
            if confidence_rank.get(conf, 0) > confidence_rank.get(best_confidence, 0):
                best_confidence = conf

        # Cap at 95% — never claim full elimination
        reduction_pct = min(95, total_reduction_pct)
        estimated_reduction = int(total_current * reduction_pct / 100)

        return estimated_reduction, best_confidence
