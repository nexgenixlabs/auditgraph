"""
AGIRS — AuditGraph Identity Risk Score Engine

Three-axis composite scoring model for CISO-ready identity risk posture:
  - HIRI (40%) — Human Identity Risk Index
  - NHIRI (40%) — Non-Human Identity Risk Index
  - GEI (20%) — Governance Effectiveness Index

Also computes per-identity Blast Radius Danger Score.
"""
import json
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ── HIRI deduction weights ────────────────────────────────────────
H1_GHOST_WEIGHT = 3
H2_DORMANT_PRIV_WEIGHT = 5
H3_OVER_PRIV_WEIGHT = 4
H4_EXT_GUEST_WEIGHT = 6
H5_ZOMBIE_WEIGHT = 7

# ── NHIRI deduction weights ───────────────────────────────────────
N1_ORPHANED_WEIGHT = 4
N2_DORMANT_NHI_WEIGHT = 3
N3_ZOMBIE_NHI_WEIGHT = 6
N4_EXPIRED_CRED_WEIGHT = 2
N5_OWNERLESS_APP_WEIGHT = 5

# ── Scope multipliers ────────────────────────────────────────────
SCOPE_MULT = {
    'management_group': 2.0,
    'subscription': 1.5,
    'resource_group': 1.0,
    'resource': 1.0,
}

# ── Blast Radius constants ────────────────────────────────────────
TIER_WEIGHT = {'T0': 10, 'T1': 7, 'T2': 4, 'T3': 1}
SCOPE_BR = {'tenant': 3.0, 'subscription': 2.0, 'resource_group': 1.5, 'resource': 1.0}
DORMANCY_MULT = {'stale': 2.0, 'never_used': 2.5, 'inactive': 1.5}

# ── Privileged Entra roles (T0/T1) ───────────────────────────────
T0_ENTRA_ROLES = {
    'global administrator', 'privileged role administrator',
    'privileged authentication administrator',
    'application administrator', 'cloud application administrator',
    'hybrid identity administrator', 'domain name administrator',
    'external identity provider administrator',
}
T1_ENTRA_ROLES = {
    'user administrator', 'exchange administrator',
    'sharepoint administrator', 'teams administrator',
    'security administrator', 'conditional access administrator',
    'authentication administrator', 'helpdesk administrator',
}
T2_RBAC_ROLES = {'owner', 'contributor', 'user access administrator'}


class AGIRSEngine:
    """Compute the AGIRS composite identity risk score for a tenant."""

    def __init__(self, db):
        self.db = db

    def compute(self, organization_id: int, run_id: int) -> Dict:
        """Run full AGIRS computation, persist results, and update blast_radius_score on identities.

        DEPRECATED: Use compute_only() via RiskSummaryEngine instead.
        This method is kept for backward compatibility but now delegates to compute_only().
        """
        run_ids = self._get_run_ids_for_org(organization_id)
        if not run_ids:
            logger.warning(f"AGIRS: No completed runs for organization {organization_id}")
            return self._empty_result()

        result = self.compute_only(organization_id, run_ids)

        # Persist to legacy agirs_scores table (backward compat)
        try:
            self.db.save_agirs_scores(run_id, result)
        except Exception as e:
            logger.warning(f"AGIRS: failed to save to legacy agirs_scores: {e}")

        return result

    def compute_only(self, organization_id: int, run_ids: List[int]) -> Dict:
        """Compute AGIRS scores without persisting to agirs_scores table.

        Called by RiskSummaryEngine as the canonical AGIRS computation path.
        Results are persisted to risk_summary table by the caller.
        """
        cursor = self.db.conn.cursor()
        try:
            if not run_ids:
                run_ids = self._get_run_ids_for_org(organization_id)
            if not run_ids:
                logger.warning(f"AGIRS: No completed runs for organization {organization_id}")
                return self._empty_result()

            hiri = self._compute_hiri(cursor, run_ids)
            nhiri = self._compute_nhiri(cursor, run_ids)
            gei = self._compute_gei(cursor, run_ids)

            agirs_score = round(0.40 * hiri['score'] + 0.40 * nhiri['score'] + 0.20 * gei['score'], 2)

            # Compute + persist blast radius scores on identities
            self._update_blast_radius_scores(cursor, run_ids)
            self.db._commit()

            # Get top dangerous identities
            dangerous = self._get_top_dangerous(cursor, run_ids, n=5)

            return {
                'agirs_score': agirs_score,
                'hiri_score': hiri['score'],
                'nhiri_score': nhiri['score'],
                'gei_score': gei['score'],
                'hiri_breakdown': hiri,
                'nhiri_breakdown': nhiri,
                'gei_breakdown': gei,
                'dangerous_identities': dangerous,
                'human_count': hiri['human_count'],
                'nhi_count': nhiri['nhi_count'],
            }

        except Exception as e:
            logger.error(f"AGIRS computation failed: {e}")
            self.db._rollback()
            raise
        finally:
            cursor.close()

    def _get_run_ids_for_org(self, organization_id: int) -> List[int]:
        """Get latest completed discovery run IDs for this organization."""
        cursor = self.db.conn.cursor()
        try:
            return self._get_run_ids(cursor, organization_id)
        finally:
            cursor.close()

    def _get_run_ids(self, cursor, organization_id: int) -> List[int]:
        """Get latest completed discovery run IDs for this organization."""
        cursor.execute("""
            SELECT id FROM discovery_runs
            WHERE status = 'completed' AND organization_id = %s
            ORDER BY completed_at DESC LIMIT 10
        """, (organization_id,))
        rows = cursor.fetchall()
        return [r[0] for r in rows] if rows else []

    # ── HIRI ──────────────────────────────────────────────────────

    def _compute_hiri(self, cursor, run_ids: List[int]) -> Dict:
        """Human Identity Risk Index — deduction model per 100 humans."""
        rid_tuple = tuple(run_ids)

        # Total human count (human_user + guest)
        cursor.execute("""
            SELECT COUNT(*) FROM identities
            WHERE discovery_run_id IN %s
              AND identity_category IN ('human_user', 'guest')
              AND COALESCE(deleted_at, '9999-01-01') > NOW()
        """, (rid_tuple,))
        human_count = cursor.fetchone()[0] or 0

        if human_count == 0:
            return {'score': 100.0, 'human_count': 0,
                    'h1_ghost': 0, 'h2_dormant_priv': 0, 'h3_over_priv': 0,
                    'h4_ext_guest': 0, 'h5_zombie': 0, 'deduction_details': []}

        # H1: Ghost humans (disabled/deleted but still has roles)
        cursor.execute("""
            SELECT COUNT(*) FROM identities i
            WHERE i.discovery_run_id IN %s
              AND i.identity_category IN ('human_user', 'guest')
              AND (i.enabled = FALSE OR i.deleted_at IS NOT NULL OR i.status IN ('disabled', 'deleted'))
              AND (
                  EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id)
                  OR EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id)
              )
        """, (rid_tuple,))
        h1_ghost = cursor.fetchone()[0] or 0

        # H2: Dormant privileged (stale >90d + has T0/T1/T2 role)
        cursor.execute("""
            SELECT COUNT(*) FROM identities i
            WHERE i.discovery_run_id IN %s
              AND i.identity_category IN ('human_user', 'guest')
              AND i.activity_status IN ('stale', 'never_used')
              AND (
                  EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id)
                  OR EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id
                      AND LOWER(ra.role_name) IN ('owner', 'contributor', 'user access administrator'))
              )
        """, (rid_tuple,))
        h2_dormant_priv = cursor.fetchone()[0] or 0

        # H3: Over-privileged (risk_score >= 70 OR tier = 'T0')
        cursor.execute("""
            SELECT COUNT(*) FROM identities i
            WHERE i.discovery_run_id IN %s
              AND i.identity_category IN ('human_user', 'guest')
              AND (COALESCE(i.risk_score, 0) >= 70 OR i.tier = 'T0')
        """, (rid_tuple,))
        h3_over_priv = cursor.fetchone()[0] or 0

        # H4: External guests with privileged roles
        cursor.execute("""
            SELECT COUNT(*) FROM identities i
            WHERE i.discovery_run_id IN %s
              AND i.identity_category = 'guest'
              AND (
                  EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id)
                  OR EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id
                      AND LOWER(ra.role_name) IN ('owner', 'contributor', 'user access administrator'))
              )
        """, (rid_tuple,))
        h4_ext_guest = cursor.fetchone()[0] or 0

        # H5: Zombie personas (from identity_links — disabled+active pair)
        h5_zombie = 0
        try:
            cursor.execute("""
                SELECT COUNT(DISTINCT il_disabled.human_identity_id)
                FROM identity_links il_disabled
                JOIN identity_links il_active
                    ON il_disabled.human_identity_id = il_active.human_identity_id
                    AND il_disabled.identity_db_id != il_active.identity_db_id
                JOIN identities i_disabled ON i_disabled.id = il_disabled.identity_db_id
                JOIN identities i_active ON i_active.id = il_active.identity_db_id
                WHERE (i_disabled.enabled = FALSE OR i_disabled.deleted_at IS NOT NULL)
                  AND i_active.enabled = TRUE
                  AND i_active.deleted_at IS NULL
                  AND i_disabled.discovery_run_id IN %s
            """, (rid_tuple,))
            h5_zombie = cursor.fetchone()[0] or 0
        except Exception:
            pass  # identity_links table may not exist

        # Normalize: deductions per 100 humans, capped at 500
        raw = (h1_ghost * H1_GHOST_WEIGHT +
               h2_dormant_priv * H2_DORMANT_PRIV_WEIGHT +
               h3_over_priv * H3_OVER_PRIV_WEIGHT +
               h4_ext_guest * H4_EXT_GUEST_WEIGHT +
               h5_zombie * H5_ZOMBIE_WEIGHT)
        normalized = min(raw / max(human_count, 1) * 100, 500)
        score = round(max(100 - normalized, 0), 2)

        return {
            'score': score,
            'human_count': human_count,
            'h1_ghost': h1_ghost,
            'h2_dormant_priv': h2_dormant_priv,
            'h3_over_priv': h3_over_priv,
            'h4_ext_guest': h4_ext_guest,
            'h5_zombie': h5_zombie,
            'deduction_details': [
                {'factor': 'Ghost humans', 'count': h1_ghost, 'weight': H1_GHOST_WEIGHT, 'deduction': h1_ghost * H1_GHOST_WEIGHT},
                {'factor': 'Dormant privileged', 'count': h2_dormant_priv, 'weight': H2_DORMANT_PRIV_WEIGHT, 'deduction': h2_dormant_priv * H2_DORMANT_PRIV_WEIGHT},
                {'factor': 'Over-privileged', 'count': h3_over_priv, 'weight': H3_OVER_PRIV_WEIGHT, 'deduction': h3_over_priv * H3_OVER_PRIV_WEIGHT},
                {'factor': 'External guests with priv', 'count': h4_ext_guest, 'weight': H4_EXT_GUEST_WEIGHT, 'deduction': h4_ext_guest * H4_EXT_GUEST_WEIGHT},
                {'factor': 'Zombie personas', 'count': h5_zombie, 'weight': H5_ZOMBIE_WEIGHT, 'deduction': h5_zombie * H5_ZOMBIE_WEIGHT},
            ],
        }

    # ── NHIRI ─────────────────────────────────────────────────────

    def _compute_nhiri(self, cursor, run_ids: List[int]) -> Dict:
        """Non-Human Identity Risk Index — per-NHI deduction with scope multipliers."""
        rid_tuple = tuple(run_ids)

        # Total NHI count
        cursor.execute("""
            SELECT COUNT(*) FROM identities
            WHERE discovery_run_id IN %s
              AND identity_category IN ('service_principal', 'managed_identity_system', 'managed_identity_user')
              AND COALESCE(is_microsoft_system, FALSE) = FALSE
              AND COALESCE(deleted_at, '9999-01-01') > NOW()
        """, (rid_tuple,))
        nhi_count = cursor.fetchone()[0] or 0

        if nhi_count == 0:
            return {'score': 100.0, 'nhi_count': 0,
                    'phantom_breakdown': {'orphaned': 0, 'dormant': 0, 'zombie_nhi': 0, 'expired_creds': 0, 'ownerless_apps': 0},
                    'deduction_details': []}

        # N1: Orphaned NHI (no owner)
        n1_orphaned = 0
        try:
            cursor.execute("""
                SELECT COUNT(*) FROM identities i
                WHERE i.discovery_run_id IN %s
                  AND i.identity_category IN ('service_principal', 'managed_identity_system', 'managed_identity_user')
                  AND COALESCE(i.is_microsoft_system, FALSE) = FALSE
                  AND NOT EXISTS (SELECT 1 FROM spn_owners so WHERE so.identity_db_id = i.id)
            """, (rid_tuple,))
            n1_orphaned = cursor.fetchone()[0] or 0
        except Exception:
            pass

        # N2: Dormant NHI (inactive >60d + has privileges)
        cursor.execute("""
            SELECT COUNT(*) FROM identities i
            WHERE i.discovery_run_id IN %s
              AND i.identity_category IN ('service_principal', 'managed_identity_system', 'managed_identity_user')
              AND COALESCE(i.is_microsoft_system, FALSE) = FALSE
              AND i.activity_status IN ('stale', 'never_used', 'inactive')
              AND (
                  EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id)
                  OR EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id)
              )
        """, (rid_tuple,))
        n2_dormant = cursor.fetchone()[0] or 0

        # N3: Zombie NHI (inactive + high priv + valid creds)
        cursor.execute("""
            SELECT COUNT(*) FROM identities i
            WHERE i.discovery_run_id IN %s
              AND i.identity_category IN ('service_principal', 'managed_identity_system', 'managed_identity_user')
              AND COALESCE(i.is_microsoft_system, FALSE) = FALSE
              AND i.activity_status IN ('stale', 'never_used')
              AND COALESCE(i.risk_score, 0) >= 70
              AND i.credential_count > 0
              AND (i.credential_expiration IS NULL OR i.credential_expiration > NOW())
        """, (rid_tuple,))
        n3_zombie = cursor.fetchone()[0] or 0

        # N4: Expired/expiring credentials
        cursor.execute("""
            SELECT COUNT(*) FROM identities i
            WHERE i.discovery_run_id IN %s
              AND i.identity_category IN ('service_principal', 'managed_identity_system', 'managed_identity_user')
              AND COALESCE(i.is_microsoft_system, FALSE) = FALSE
              AND i.credential_count > 0
              AND i.credential_expiration IS NOT NULL
              AND i.credential_expiration < NOW() + INTERVAL '30 days'
        """, (rid_tuple,))
        n4_expired = cursor.fetchone()[0] or 0

        # N5: Ownerless app registrations with high-risk perms
        n5_ownerless_apps = 0
        try:
            cursor.execute("""
                SELECT COUNT(*) FROM app_registrations ar
                WHERE ar.discovery_run_id IN %s
                  AND COALESCE(ar.owner_count, 0) = 0
                  AND COALESCE(ar.has_high_risk_permissions, FALSE) = TRUE
            """, (rid_tuple,))
            n5_ownerless_apps = cursor.fetchone()[0] or 0
        except Exception:
            pass

        # Apply average scope multiplier (1.5 for mix of subscription-level)
        avg_scope_mult = 1.3  # Moderate default

        raw = (n1_orphaned * N1_ORPHANED_WEIGHT +
               n2_dormant * N2_DORMANT_NHI_WEIGHT +
               n3_zombie * N3_ZOMBIE_NHI_WEIGHT +
               n4_expired * N4_EXPIRED_CRED_WEIGHT +
               n5_ownerless_apps * N5_OWNERLESS_APP_WEIGHT) * avg_scope_mult
        normalized = min(raw / max(nhi_count, 1) * 100, 500)
        score = round(max(100 - normalized, 0), 2)

        return {
            'score': score,
            'nhi_count': nhi_count,
            'phantom_breakdown': {
                'orphaned': n1_orphaned,
                'dormant': n2_dormant,
                'zombie_nhi': n3_zombie,
                'expired_creds': n4_expired,
                'ownerless_apps': n5_ownerless_apps,
            },
            'deduction_details': [
                {'factor': 'Orphaned NHI', 'count': n1_orphaned, 'weight': N1_ORPHANED_WEIGHT, 'deduction': round(n1_orphaned * N1_ORPHANED_WEIGHT * avg_scope_mult, 1)},
                {'factor': 'Dormant NHI', 'count': n2_dormant, 'weight': N2_DORMANT_NHI_WEIGHT, 'deduction': round(n2_dormant * N2_DORMANT_NHI_WEIGHT * avg_scope_mult, 1)},
                {'factor': 'Zombie NHI', 'count': n3_zombie, 'weight': N3_ZOMBIE_NHI_WEIGHT, 'deduction': round(n3_zombie * N3_ZOMBIE_NHI_WEIGHT * avg_scope_mult, 1)},
                {'factor': 'Expired credentials', 'count': n4_expired, 'weight': N4_EXPIRED_CRED_WEIGHT, 'deduction': round(n4_expired * N4_EXPIRED_CRED_WEIGHT * avg_scope_mult, 1)},
                {'factor': 'Ownerless high-risk apps', 'count': n5_ownerless_apps, 'weight': N5_OWNERLESS_APP_WEIGHT, 'deduction': round(n5_ownerless_apps * N5_OWNERLESS_APP_WEIGHT * avg_scope_mult, 1)},
            ],
        }

    # ── GEI ───────────────────────────────────────────────────────

    def _compute_gei(self, cursor, run_ids: List[int]) -> Dict:
        """Governance Effectiveness Index — 4 components, 25% each."""
        rid_tuple = tuple(run_ids)
        components = []

        # 1. Ownership Coverage: % of SPNs with >=1 owner
        ownership_score = 0
        ownership_configured = True
        try:
            cursor.execute("""
                SELECT
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE EXISTS (
                        SELECT 1 FROM spn_owners so WHERE so.identity_db_id = i.id
                    )) as owned
                FROM identities i
                WHERE i.discovery_run_id IN %s
                  AND i.identity_category = 'service_principal'
                  AND COALESCE(i.is_microsoft_system, FALSE) = FALSE
            """, (rid_tuple,))
            row = cursor.fetchone()
            total_spn, owned = (row[0] or 0), (row[1] or 0)
            ownership_score = round(owned / max(total_spn, 1) * 100, 1)
        except Exception:
            ownership_configured = False
        components.append({'name': 'Ownership Coverage', 'score': ownership_score, 'configured': ownership_configured})

        # 2. PIM Adoption: % of T0/T1 identities covered by PIM
        pim_score = 0
        pim_configured = True
        try:
            cursor.execute("""
                SELECT
                    COUNT(DISTINCT i.id) as t0_t1_count,
                    COUNT(DISTINCT pea.identity_db_id) as pim_covered
                FROM identities i
                LEFT JOIN pim_eligible_assignments pea ON pea.identity_db_id = i.id
                WHERE i.discovery_run_id IN %s
                  AND i.tier IN ('T0', 'T1')
            """, (rid_tuple,))
            row = cursor.fetchone()
            t0_t1_count, pim_covered = (row[0] or 0), (row[1] or 0)
            if t0_t1_count > 0:
                pim_score = round(pim_covered / t0_t1_count * 100, 1)
            else:
                pim_configured = False
        except Exception:
            pim_configured = False
        components.append({'name': 'PIM Adoption', 'score': pim_score, 'configured': pim_configured})

        # 3. Access Review Completion: % of SA attestations completed on time
        review_score = 0
        review_configured = False
        try:
            cursor.execute("""
                SELECT COUNT(*) as total,
                       COUNT(*) FILTER (WHERE status = 'attested') as completed
                FROM sa_attestations
            """)
            row = cursor.fetchone()
            total_att, completed = (row[0] or 0), (row[1] or 0)
            if total_att > 0:
                review_configured = True
                review_score = round(completed / total_att * 100, 1)
        except Exception:
            pass
        components.append({'name': 'Access Reviews', 'score': review_score, 'configured': review_configured})

        # 4. Monitoring Coverage: % of NHIs with P2 telemetry sign-in data
        monitoring_score = 0
        monitoring_configured = True
        try:
            cursor.execute("""
                SELECT
                    COUNT(*) as total_nhi,
                    COUNT(*) FILTER (WHERE EXISTS (
                        SELECT 1 FROM workload_activity_stats was
                        WHERE was.identity_db_id = i.id AND was.total_sign_ins > 0
                    )) as has_p2
                FROM identities i
                WHERE i.discovery_run_id IN %s
                  AND i.identity_category IN ('service_principal', 'managed_identity_system', 'managed_identity_user')
                  AND COALESCE(i.is_microsoft_system, FALSE) = FALSE
            """, (rid_tuple,))
            row = cursor.fetchone()
            total_nhi, has_p2 = (row[0] or 0), (row[1] or 0)
            if total_nhi > 0:
                monitoring_score = round(has_p2 / total_nhi * 100, 1)
            else:
                monitoring_configured = False
        except Exception:
            monitoring_configured = False
        components.append({'name': 'Monitoring (P2)', 'score': monitoring_score, 'configured': monitoring_configured})

        # Weighted average (equal 25% each)
        gei_score = round(sum(c['score'] for c in components) / 4, 2)

        return {
            'score': gei_score,
            'components': components,
        }

    # ── Blast Radius Danger Score ─────────────────────────────────

    def _update_blast_radius_scores(self, cursor, run_ids: List[int]):
        """Compute and persist blast_radius_score on each identity."""
        rid_tuple = tuple(run_ids)

        # Ensure column exists
        try:
            cursor.execute("ALTER TABLE identities ADD COLUMN IF NOT EXISTS blast_radius_score NUMERIC(7,2) DEFAULT 0")
            self.db._commit()
        except Exception:
            self.db._rollback()

        # Fetch identities with their tier, activity, scope info
        cursor.execute("""
            SELECT
                i.id,
                COALESCE(i.tier, 'T3') as tier,
                COALESCE(i.activity_status, 'unknown') as activity_status,
                -- Highest scope: check for subscription-level or higher
                (SELECT CASE
                    WHEN EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id
                        AND (ra.scope IS NULL OR ra.scope = '/' OR
                             (ra.scope LIKE '/subscriptions/%%' AND ra.scope NOT LIKE '/subscriptions/%%/resourceGroups/%%')))
                    THEN 'subscription'
                    WHEN EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id
                        AND LOWER(era.role_name) IN ('global administrator', 'privileged role administrator'))
                    THEN 'tenant'
                    ELSE 'resource'
                END) as scope_level,
                -- Cross-subscription check
                (SELECT COUNT(DISTINCT ra.scope) FROM role_assignments ra WHERE ra.identity_db_id = i.id
                    AND ra.scope LIKE '/subscriptions/%%') > 1 as cross_subscription,
                -- Multi-tenant app check
                COALESCE(i.sign_in_audience, '') LIKE '%%multi%%' as multi_tenant_app
            FROM identities i
            WHERE i.discovery_run_id IN %s
              AND COALESCE(i.deleted_at, '9999-01-01') > NOW()
        """, (rid_tuple,))

        updates = []
        for row in cursor.fetchall():
            id_, tier, activity, scope_level, cross_sub, multi_tenant = row
            privilege_weight = TIER_WEIGHT.get(tier, 1)
            scope_mult = SCOPE_BR.get(scope_level, 1.0)
            dormancy_mult = DORMANCY_MULT.get(activity, 1.0)
            exposure_mult = 1.0
            if cross_sub:
                exposure_mult *= 1.5
            if multi_tenant:
                exposure_mult *= 1.3

            score = round(privilege_weight * scope_mult * dormancy_mult * exposure_mult, 2)
            updates.append((score, id_))

        # Batch update
        if updates:
            from psycopg2.extras import execute_batch
            execute_batch(cursor, "UPDATE identities SET blast_radius_score = %s WHERE id = %s", updates)

    def _get_top_dangerous(self, cursor, run_ids: List[int], n: int = 5, category: str = 'all') -> List[Dict]:
        """Get top N identities by blast_radius_score."""
        rid_tuple = tuple(run_ids)
        cat_filter = ""
        if category == 'human':
            cat_filter = "AND i.identity_category IN ('human_user', 'guest')"
        elif category == 'nhi':
            cat_filter = "AND i.identity_category IN ('service_principal', 'managed_identity_system', 'managed_identity_user')"

        cursor.execute(f"""
            SELECT
                i.id,
                i.identity_id,
                i.display_name,
                i.identity_category,
                COALESCE(i.blast_radius_score, 0) as blast_radius_score,
                COALESCE(i.risk_score, 0) as risk_score,
                COALESCE(i.tier, 'T3') as tier,
                COALESCE(i.activity_status, 'unknown') as activity_status
            FROM identities i
            WHERE i.discovery_run_id IN %s
              AND COALESCE(i.deleted_at, '9999-01-01') > NOW()
              AND COALESCE(i.blast_radius_score, 0) > 0
              {cat_filter}
            ORDER BY i.blast_radius_score DESC
            LIMIT %s
        """, (rid_tuple, n))

        results = []
        for row in cursor.fetchall():
            id_, identity_id, name, category, br_score, risk, tier, activity = row
            risk_factors = []
            if tier in ('T0', 'T1'):
                risk_factors.append(f'{tier} Privilege')
            if activity in ('stale', 'never_used'):
                risk_factors.append(f'Dormant ({activity})')
            if risk >= 70:
                risk_factors.append(f'Risk score {risk}')

            # Check for specific factors
            try:
                cursor.execute("""
                    SELECT
                        NOT EXISTS (SELECT 1 FROM spn_owners so WHERE so.identity_db_id = %s) as no_owner,
                        (SELECT string_agg(DISTINCT ra.role_name, ', ')
                         FROM role_assignments ra WHERE ra.identity_db_id = %s
                         AND LOWER(ra.role_name) IN ('owner', 'contributor', 'user access administrator')) as priv_roles
                """, (id_, id_))
                detail = cursor.fetchone()
                if detail and detail[0]:
                    risk_factors.append('No owner')
                if detail and detail[1]:
                    risk_factors.append(detail[1])
            except Exception:
                pass

            results.append({
                'id': id_,
                'identity_id': identity_id,
                'display_name': name or 'Unknown',
                'identity_category': category,
                'blast_radius_score': float(br_score),
                'risk_score': int(risk),
                'tier': tier,
                'key_risk_factors': risk_factors[:5],
            })

        return results

    def _empty_result(self) -> Dict:
        return {
            'agirs_score': None,
            'hiri_score': None,
            'nhiri_score': None,
            'gei_score': None,
            'hiri_breakdown': None,
            'nhiri_breakdown': None,
            'gei_breakdown': None,
            'dangerous_identities': [],
            'human_count': 0,
            'nhi_count': 0,
        }
