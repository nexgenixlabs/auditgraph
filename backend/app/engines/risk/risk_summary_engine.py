"""
Canonical Risk Summary Engine

Computes all risk metrics from a single source of truth (discovery run data)
and persists them to the risk_summary table. This ensures dashboard widgets
always display deterministic, pre-computed values rather than live queries.

AGIRS (AuditGraph Identity Risk Score) computation is absorbed here as the
single canonical source. The separate agirs_scores table is deprecated.
"""

import logging
import json

logger = logging.getLogger(__name__)


class RiskSummaryEngine:
    """Single-pass computation of all canonical risk metrics for a discovery run."""

    def __init__(self, db, organization_id, run_ids):
        self.db = db
        self.org_id = organization_id
        self.run_ids = run_ids

    def compute(self) -> dict:
        """Compute ALL canonical risk metrics from discovery data.

        Returns a dict matching the risk_summary table columns.
        """
        summary = {}

        # ── Phase 1: Identity risk counts (own cursor, own transaction) ──
        self._compute_identity_counts(summary)

        # ── Phase 2: AGIRS (AGIRSEngine uses its own cursor + commit) ──
        self._compute_agirs(summary)

        # ── Phase 3: Remaining metrics (own cursor) ──
        self._compute_remaining_metrics(summary)

        # ── Sanity check + fallback (Step 3 & 4) ──
        self._validate_and_fix_agirs(summary)

        # ── Step 1: Log computed scores before persistence ──
        logger.info(
            "RiskSummaryEngine computed scores: HIRI=%.2f NHIRI=%.2f GEI=%.2f AGIRS=%.2f "
            "(org=%s run_ids=%s total_identities=%d)",
            summary.get('hiri_score') or 0,
            summary.get('nhiri_score') or 0,
            summary.get('gei_score') or 0,
            summary.get('agirs_score') or 0,
            self.org_id,
            self.run_ids,
            summary.get('total_identities', 0),
        )

        return summary

    def _compute_identity_counts(self, summary: dict):
        """Core identity risk counts — isolated cursor."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT
                    COUNT(DISTINCT i.id) FILTER (WHERE
                        NOT COALESCE(i.is_microsoft_system, false)
                        AND (i.deleted_at IS NOT NULL OR i.enabled = false
                         OR COALESCE(i.status,'active') IN ('disabled','deleted'))
                        AND (EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id)
                             OR EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id))
                    ) as ghost_count,
                    COUNT(*) FILTER (WHERE
                        COALESCE(i.identity_category,'') IN ('service_principal','managed_identity_user')
                        AND (i.owner_count = 0 OR i.owner_count IS NULL)
                        AND NOT COALESCE(i.is_microsoft_system, false)
                    ) as orphaned_spn_count,
                    COUNT(*) FILTER (WHERE
                        NOT COALESCE(i.is_microsoft_system, false)
                        AND (EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id
                            AND LOWER(era.role_name) IN ('global administrator',
                                'privileged role administrator','application administrator',
                                'cloud application administrator','user administrator',
                                'exchange administrator','security administrator'))
                        OR EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id
                            AND LOWER(ra.role_name) IN ('owner','contributor','user access administrator')))
                    ) as over_privileged_count,
                    COUNT(*) FILTER (WHERE
                        NOT COALESCE(i.is_microsoft_system, false)
                        AND i.activity_status IN ('stale','never_used')
                        AND (EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id)
                             OR EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id))
                    ) as dormant_privileged_count,
                    COUNT(*) FILTER (WHERE
                        NOT COALESCE(i.is_microsoft_system, false)
                        AND (COALESCE(i.blast_radius_score,0) >= 70
                        OR COALESCE(i.exposure_score,0) >= 80)
                    ) as high_blast_radius_count,
                    COUNT(*) FILTER (WHERE NOT COALESCE(i.is_microsoft_system, false)) as customer_count,
                    COUNT(*) FILTER (WHERE COALESCE(i.is_microsoft_system, false)) as microsoft_count,
                    COUNT(*) as total_count
                FROM identities i
                WHERE i.discovery_run_id = ANY(%s)
            """, (self.run_ids,))
            r = cursor.fetchone()

            summary['ghost_accounts'] = r[0] or 0
            summary['orphaned_spns'] = r[1] or 0
            summary['over_privileged'] = r[2] or 0
            summary['dormant_privileged'] = r[3] or 0
            summary['high_blast_radius'] = r[4] or 0
            summary['customer_identities'] = r[5] or 0
            summary['microsoft_identities'] = r[6] or 0
            summary['total_identities'] = r[7] or 0

            # External exposure (guests with privileged access)
            try:
                cursor.execute("""
                    SELECT COUNT(*) FROM identities i
                    WHERE i.discovery_run_id = ANY(%s)
                      AND i.identity_category = 'guest'
                      AND (EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id)
                           OR EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id))
                """, (self.run_ids,))
                summary['external_exposure'] = cursor.fetchone()[0] or 0
            except Exception:
                summary['external_exposure'] = 0

        finally:
            cursor.close()

    def _compute_agirs(self, summary: dict):
        """Compute AGIRS via AGIRSEngine — isolated from outer cursors.

        AGIRSEngine opens its own cursor and calls _commit() internally
        (for blast_radius_score updates), so it MUST run in its own phase
        to avoid corrupting other cursors' transaction state.
        """
        try:
            from app.engines.risk.agirs_engine import AGIRSEngine
            agirs_engine = AGIRSEngine(self.db)
            agirs_result = agirs_engine.compute_only(self.org_id, self.run_ids)

            if agirs_result and agirs_result.get('agirs_score') is not None:
                summary['agirs_score'] = agirs_result['agirs_score']
                summary['hiri_score'] = agirs_result.get('hiri_score')
                summary['nhiri_score'] = agirs_result.get('nhiri_score')
                summary['gei_score'] = agirs_result.get('gei_score')
                summary['hiri_breakdown'] = agirs_result.get('hiri_breakdown')
                summary['nhiri_breakdown'] = agirs_result.get('nhiri_breakdown')
                summary['gei_breakdown'] = agirs_result.get('gei_breakdown')
                summary['dangerous_identities'] = agirs_result.get('dangerous_identities', [])
                summary['human_count'] = agirs_result.get('human_count', 0)
                summary['nhi_count'] = agirs_result.get('nhi_count', 0)

                logger.info(
                    "AGIRSEngine returned: HIRI=%.2f NHIRI=%.2f GEI=%.2f AGIRS=%.2f "
                    "(humans=%d nhis=%d)",
                    summary.get('hiri_score') or 0,
                    summary.get('nhiri_score') or 0,
                    summary.get('gei_score') or 0,
                    summary.get('agirs_score') or 0,
                    summary.get('human_count', 0),
                    summary.get('nhi_count', 0),
                )
            else:
                logger.warning(
                    "AGIRSEngine returned empty result for org=%s run_ids=%s",
                    self.org_id, self.run_ids,
                )
                summary['agirs_score'] = None
                summary['agirs_tier'] = None
        except Exception as e:
            logger.error(
                "AGIRS computation failed for org=%s run_ids=%s: %s",
                self.org_id, self.run_ids, e, exc_info=True,
            )
            summary['agirs_score'] = None
            summary['agirs_tier'] = None

    def _compute_remaining_metrics(self, summary: dict):
        """Attack paths, resources, subscriptions, privileged roles, posture score.

        Runs AFTER AGIRSEngine (which may have committed the transaction),
        so this opens a fresh cursor.
        """
        cursor = self.db.conn.cursor()
        try:
            # Attack path count — from attack_paths table (same source as /api/attack-paths page)
            try:
                cursor.execute("SAVEPOINT rse_ap")
                cursor.execute("""
                    SELECT COUNT(*) FROM attack_paths
                    WHERE organization_id = %s AND discovery_run_id = ANY(%s)
                """, (self.org_id, self.run_ids))
                summary['attack_paths'] = cursor.fetchone()[0] or 0
                cursor.execute("RELEASE SAVEPOINT rse_ap")
            except Exception:
                try:
                    cursor.execute("ROLLBACK TO SAVEPOINT rse_ap")
                except Exception:
                    pass
                summary['attack_paths'] = 0

            # Resource counts
            for table, key in [('azure_storage_accounts', 'storage_accounts'),
                               ('azure_key_vaults', 'key_vaults')]:
                try:
                    cursor.execute("SAVEPOINT rse_%s" % key)
                    cursor.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE discovery_run_id = ANY(%s)",
                        (self.run_ids,)
                    )
                    summary[key] = cursor.fetchone()[0] or 0
                    cursor.execute("RELEASE SAVEPOINT rse_%s" % key)
                except Exception:
                    try:
                        cursor.execute("ROLLBACK TO SAVEPOINT rse_%s" % key)
                    except Exception:
                        pass
                    summary[key] = 0

            summary['total_resources'] = summary.get('storage_accounts', 0) + summary.get('key_vaults', 0)

            # Subscription count
            try:
                cursor.execute("SAVEPOINT rse_sub")
                cursor.execute("""
                    SELECT COUNT(DISTINCT SPLIT_PART(ra.scope, '/', 3))
                    FROM role_assignments ra
                    JOIN identities i ON i.id = ra.identity_db_id
                    WHERE i.discovery_run_id = ANY(%s)
                      AND ra.scope LIKE '/subscriptions/%%'
                """, (self.run_ids,))
                summary['subscriptions'] = cursor.fetchone()[0] or 0
                cursor.execute("RELEASE SAVEPOINT rse_sub")
            except Exception:
                try:
                    cursor.execute("ROLLBACK TO SAVEPOINT rse_sub")
                except Exception:
                    pass
                summary['subscriptions'] = 0

            # Privileged role count
            try:
                cursor.execute("SAVEPOINT rse_priv")
                cursor.execute("""
                    SELECT COUNT(DISTINCT era.role_name)
                    FROM entra_role_assignments era
                    JOIN identities i ON i.id = era.identity_db_id
                    WHERE i.discovery_run_id = ANY(%s)
                """, (self.run_ids,))
                summary['privileged_roles'] = cursor.fetchone()[0] or 0
                cursor.execute("RELEASE SAVEPOINT rse_priv")
            except Exception:
                try:
                    cursor.execute("ROLLBACK TO SAVEPOINT rse_priv")
                except Exception:
                    pass
                summary['privileged_roles'] = 0

            # Identity risk score from posture_scores
            try:
                cursor.execute("SAVEPOINT rse_irs")
                cursor.execute("""
                    SELECT posture_score FROM posture_scores
                    WHERE organization_id = %s ORDER BY created_at DESC LIMIT 1
                """, (self.org_id,))
                ps_row = cursor.fetchone()
                summary['identity_risk_score'] = round(ps_row[0]) if ps_row else None
                cursor.execute("RELEASE SAVEPOINT rse_irs")
            except Exception:
                try:
                    cursor.execute("ROLLBACK TO SAVEPOINT rse_irs")
                except Exception:
                    pass
                summary['identity_risk_score'] = None

        finally:
            cursor.close()

    def _validate_and_fix_agirs(self, summary: dict):
        """Pillar deduction model — authoritative AGIRS computation.

        AGIRS = 100 - Σ(risk_exposure × pillar_weight)
        The HIRI/NHIRI/GEI composite scores are retained for drill-down
        analysis but are NOT used to compute the displayed AGIRS score.
        """
        # Use customer-only count as denominator — Microsoft first-party
        # identities are excluded from all risk counts, so the denominator
        # must also exclude them to avoid diluting risk percentages.
        total_ids = summary.get('customer_identities') or summary.get('total_identities', 0)
        if total_ids > 0:
            PILLAR_WEIGHTS = {
                'effective_privilege':  (30, summary.get('over_privileged', 0)),
                'ownership_governance': (10, summary.get('orphaned_spns', 0) + summary.get('ghost_accounts', 0)),
                'usage_dormancy':       (10, summary.get('dormant_privileged', 0) + summary.get('ghost_accounts', 0)),
                'credential_risk':      (20, ((summary.get('nhiri_breakdown') or {}).get('phantom_breakdown') or {}).get('expired_creds', 0)),
                'trust_federation':     (10, summary.get('external_exposure', 0)),
                'external_exposure':    (10, summary.get('external_exposure', 0)),
                'attack_path_exposure': (10, summary.get('attack_paths', 0)),
            }

            pillar_score = 100.0
            for _pname, (weight, affected) in PILLAR_WEIGHTS.items():
                if _pname == 'attack_path_exposure':
                    risk_pct = min(100.0, (affected / max(total_ids, 1)) * 5)
                else:
                    risk_pct = min(100.0, affected / max(total_ids, 1) * 100)
                risk_pct = round(risk_pct, 1)
                pillar_score -= round((risk_pct / 100.0) * weight, 1)

            pillar_score = max(0.0, min(100.0, round(pillar_score, 1)))
            summary['agirs_score'] = pillar_score
            logger.info(
                "AGIRS pillar deduction model: %.1f (total_ids=%d)",
                pillar_score, total_ids,
            )

        # Enterprise-calibrated tier thresholds
        if summary.get('agirs_score') is not None:
            s = summary['agirs_score']
            summary['agirs_tier'] = (
                'A' if s >= 92 else
                'B' if s >= 80 else
                'C' if s >= 65 else
                'D' if s >= 45 else 'F'
            )
        else:
            summary['agirs_tier'] = None

    def persist(self, summary: dict):
        """Save computed summary to risk_summary table.

        Step 2: Logs what is being written for verification.
        """
        run_id = self.run_ids[0] if self.run_ids else None
        if not run_id:
            logger.warning("RiskSummaryEngine: no run_id to persist")
            return None

        # Step 2: Log persistence details
        logger.info(
            "RiskSummaryEngine persisting to risk_summary: run_id=%d org=%s "
            "agirs_score=%s hiri_score=%s nhiri_score=%s gei_score=%s agirs_tier=%s",
            run_id, self.org_id,
            summary.get('agirs_score'),
            summary.get('hiri_score'),
            summary.get('nhiri_score'),
            summary.get('gei_score'),
            summary.get('agirs_tier'),
        )

        result_id = self.db.save_risk_summary(self.org_id, run_id, summary)

        if result_id:
            logger.info(
                "RiskSummaryEngine persisted successfully: risk_summary.id=%d", result_id
            )
        else:
            logger.error(
                "RiskSummaryEngine persistence FAILED: save_risk_summary returned None"
            )

        return result_id
