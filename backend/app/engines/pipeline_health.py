"""
Pipeline Health Tracker — Stage-level metrics and degradation detection.

Provides a StageMetrics context manager that tracks per-stage ingestion
metrics (fetched, matched, persisted, failed) and automatically computes
health status on completion.

Usage:
    from app.engines.pipeline_health import PipelineHealthTracker

    tracker = PipelineHealthTracker(run_id=211, org_id=10, db=db)

    with tracker.stage('entra_role_collection', order=3) as stage:
        stage.fetched = 175
        stage.matched = 144
        # ... do work ...
        stage.persisted = 144
        stage.failed = 0

    # After all stages:
    tracker.finalize()  # Persists all metrics + summary to DB

Health classification:
    healthy:  failure_rate <= 5% AND no abnormal drops
    degraded: failure_rate > 5% OR persisted dropped >20% vs prior run
    failed:   exception thrown OR failure_rate > 50% OR persisted == 0 when fetched > 0
    skipped:  stage explicitly skipped (scan mode exclusion)
"""

import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════
# Thresholds
# ═══════════════════════════════════════════════════════════════════

FAILURE_RATE_DEGRADED = 5.0    # >5% failed → degraded
FAILURE_RATE_FAILED = 50.0     # >50% failed → failed
DROP_VS_PRIOR_DEGRADED = 20.0  # >20% drop vs prior → degraded
DROP_VS_PRIOR_FAILED = 80.0    # >80% drop vs prior → failed

# Pipeline stage definitions with canonical ordering
PIPELINE_STAGES = {
    'identity_discovery': {'order': 1, 'critical': True},
    'rbac_collection': {'order': 2, 'critical': True},
    'entra_role_collection': {'order': 3, 'critical': True},
    'credential_collection': {'order': 4, 'critical': True},
    'pim_collection': {'order': 5, 'critical': False},
    'ca_policy_collection': {'order': 6, 'critical': False},
    'app_registration_discovery': {'order': 7, 'critical': False},
    'resource_inventory': {'order': 8, 'critical': False},
    'resource_scope_extraction': {'order': 9, 'critical': False},
    'optimization_materialization': {'order': 10, 'critical': False},
    'workload_attribution': {'order': 11, 'critical': False},
    'privilege_drift_detection': {'order': 12, 'critical': False},
    'reachability_computation': {'order': 13, 'critical': False},
    'blast_radius_analysis': {'order': 14, 'critical': False},
    'risk_evaluation': {'order': 15, 'critical': False},
    'anomaly_detection': {'order': 16, 'critical': False},
    'posture_score': {'order': 17, 'critical': False},
}


# ═══════════════════════════════════════════════════════════════════
# Stage Metrics Dataclass
# ═══════════════════════════════════════════════════════════════════

@dataclass
class StageMetrics:
    """Mutable metrics for a single pipeline stage."""
    name: str
    order: int = 0
    critical: bool = False

    # Counters (set by pipeline code)
    fetched: int = 0
    matched: int = 0
    persisted: int = 0
    failed: int = 0
    skipped: int = 0

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: int = 0

    # Health (computed)
    health_status: str = 'healthy'
    degradation_reason: Optional[str] = None
    error_message: Optional[str] = None

    # Prior comparison
    prior_run_persisted: Optional[int] = None
    delta_vs_prior: Optional[float] = None

    # Extra metadata
    extra: Dict = field(default_factory=dict)

    @property
    def failure_rate(self) -> float:
        if self.fetched == 0:
            return 0.0
        return (self.failed / self.fetched) * 100.0

    def compute_health(self):
        """Classify health status based on metrics."""
        # Already marked as failed by exception
        if self.health_status == 'failed':
            return

        # Skipped stages
        if self.health_status == 'skipped':
            return

        # Zero fetched = nothing to evaluate (possibly skipped)
        if self.fetched == 0 and self.failed == 0:
            self.health_status = 'healthy'
            return

        # Check failure rate
        rate = self.failure_rate
        if rate > FAILURE_RATE_FAILED:
            self.health_status = 'failed'
            self.degradation_reason = f'Failure rate {rate:.1f}% exceeds {FAILURE_RATE_FAILED}% threshold'
            return

        if rate > FAILURE_RATE_DEGRADED:
            self.health_status = 'degraded'
            self.degradation_reason = f'Failure rate {rate:.1f}% exceeds {FAILURE_RATE_DEGRADED}% threshold'
            return

        # Total persistence failure (fetched > 0 but persisted == 0)
        if self.fetched > 0 and self.persisted == 0 and self.matched > 0:
            self.health_status = 'failed'
            self.degradation_reason = (
                f'Zero records persisted despite {self.fetched} fetched '
                f'and {self.matched} matched — likely persistence error'
            )
            return

        # Check drop vs prior run
        if self.prior_run_persisted is not None and self.prior_run_persisted > 0:
            if self.persisted == 0:
                drop_pct = 100.0
            else:
                drop_pct = ((self.prior_run_persisted - self.persisted) / self.prior_run_persisted) * 100.0
            self.delta_vs_prior = -drop_pct if drop_pct > 0 else abs(drop_pct)

            if drop_pct > DROP_VS_PRIOR_FAILED:
                self.health_status = 'failed'
                self.degradation_reason = (
                    f'Output dropped {drop_pct:.0f}% vs prior run '
                    f'({self.persisted} vs {self.prior_run_persisted})'
                )
                return

            if drop_pct > DROP_VS_PRIOR_DEGRADED:
                self.health_status = 'degraded'
                self.degradation_reason = (
                    f'Output dropped {drop_pct:.0f}% vs prior run '
                    f'({self.persisted} vs {self.prior_run_persisted})'
                )
                return

        self.health_status = 'healthy'


# ═══════════════════════════════════════════════════════════════════
# Pipeline Health Tracker
# ═══════════════════════════════════════════════════════════════════

class PipelineHealthTracker:
    """Track pipeline stage metrics for a discovery run.

    Usage:
        tracker = PipelineHealthTracker(run_id=211, org_id=10, db=db)

        with tracker.stage('entra_role_collection') as s:
            s.fetched = 175
            s.matched = 144
            s.persisted = 144

        tracker.finalize()
    """

    def __init__(self, run_id: int, org_id: int, db=None):
        self.run_id = run_id
        self.org_id = org_id
        self.db = db
        self.stages: Dict[str, StageMetrics] = {}
        self._finalized = False

    @contextmanager
    def stage(self, name: str, order: int = None, critical: bool = None):
        """Context manager that tracks a pipeline stage.

        Args:
            name: Stage identifier (should match PIPELINE_STAGES keys)
            order: Execution order (auto-resolved from PIPELINE_STAGES)
            critical: Whether this is a critical stage (auto-resolved)

        Yields:
            StageMetrics instance — caller sets .fetched, .persisted, etc.
        """
        stage_def = PIPELINE_STAGES.get(name, {})
        if order is None:
            order = stage_def.get('order', len(self.stages) + 1)
        if critical is None:
            critical = stage_def.get('critical', False)

        metrics = StageMetrics(
            name=name,
            order=order,
            critical=critical,
            started_at=datetime.now(timezone.utc),
        )
        self.stages[name] = metrics

        start = time.monotonic()
        try:
            yield metrics
        except Exception as e:
            metrics.health_status = 'failed'
            metrics.error_message = str(e)[:500]
            metrics.degradation_reason = f'Stage threw exception: {type(e).__name__}'
            # Log at appropriate severity
            if critical:
                logger.error(
                    "PIPELINE_STAGE_FAILED stage=%s run=%d org=%d error=%s",
                    name, self.run_id, self.org_id, str(e)[:200],
                )
            else:
                logger.warning(
                    "PIPELINE_STAGE_FAILED stage=%s run=%d org=%d error=%s",
                    name, self.run_id, self.org_id, str(e)[:200],
                )
            raise
        finally:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            metrics.duration_ms = elapsed_ms
            metrics.completed_at = datetime.now(timezone.utc)
            metrics.compute_health()

            # Structured log for every stage completion
            log_fn = logger.info if metrics.health_status == 'healthy' else logger.warning
            log_fn(
                "PIPELINE_STAGE_%s stage=%s run=%d org=%d "
                "fetched=%d matched=%d persisted=%d failed=%d "
                "failure_rate=%.1f%% duration_ms=%d",
                metrics.health_status.upper(),
                name, self.run_id, self.org_id,
                metrics.fetched, metrics.matched,
                metrics.persisted, metrics.failed,
                metrics.failure_rate, elapsed_ms,
            )

    def mark_skipped(self, name: str, reason: str = 'scan_mode_exclusion'):
        """Mark a stage as intentionally skipped."""
        stage_def = PIPELINE_STAGES.get(name, {})
        metrics = StageMetrics(
            name=name,
            order=stage_def.get('order', len(self.stages) + 1),
            critical=stage_def.get('critical', False),
            health_status='skipped',
            degradation_reason=reason,
        )
        self.stages[name] = metrics

    def get_summary(self) -> Dict:
        """Generate pipeline health summary dict."""
        total_stages = len(self.stages)
        healthy_count = sum(1 for s in self.stages.values() if s.health_status == 'healthy')
        degraded_count = sum(1 for s in self.stages.values() if s.health_status == 'degraded')
        failed_count = sum(1 for s in self.stages.values() if s.health_status == 'failed')
        skipped_count = sum(1 for s in self.stages.values() if s.health_status == 'skipped')

        # Overall health
        if failed_count > 0:
            # Any critical stage failed = overall failed
            critical_failed = any(
                s.health_status == 'failed' and s.critical
                for s in self.stages.values()
            )
            overall = 'failed' if critical_failed else 'degraded'
        elif degraded_count > 0:
            overall = 'degraded'
        else:
            overall = 'healthy'

        # Collect issues
        issues = []
        for s in sorted(self.stages.values(), key=lambda x: x.order):
            if s.health_status in ('degraded', 'failed'):
                issues.append({
                    'stage': s.name,
                    'status': s.health_status,
                    'reason': s.degradation_reason,
                    'failure_rate': round(s.failure_rate, 1),
                    'fetched': s.fetched,
                    'persisted': s.persisted,
                    'failed': s.failed,
                })

        return {
            'overall_health': overall,
            'total_stages': total_stages,
            'healthy': healthy_count,
            'degraded': degraded_count,
            'failed': failed_count,
            'skipped': skipped_count,
            'issues': issues,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }

    def load_prior_metrics(self):
        """Load prior run's stage metrics for comparison."""
        if not self.db:
            return

        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                SELECT stage_name, records_persisted
                FROM pipeline_stage_metrics
                WHERE organization_id = %s
                  AND discovery_run_id = (
                      SELECT MAX(discovery_run_id) FROM pipeline_stage_metrics
                      WHERE organization_id = %s AND discovery_run_id < %s
                  )
            """, (self.org_id, self.org_id, self.run_id))
            for row in cursor.fetchall():
                stage_name, prior_persisted = row
                if stage_name in self.stages:
                    self.stages[stage_name].prior_run_persisted = prior_persisted
            cursor.close()
        except Exception as e:
            logger.debug("Failed to load prior pipeline metrics: %s", e)
            try:
                self.db.conn.rollback()
            except Exception:
                pass

    def finalize(self):
        """Persist all stage metrics to DB and attach summary to discovery run."""
        if self._finalized:
            return
        self._finalized = True

        if not self.db:
            logger.warning("PipelineHealthTracker.finalize() called without DB — metrics not persisted")
            return

        # Load prior run data for comparison
        self.load_prior_metrics()

        # Recompute health with prior data
        for s in self.stages.values():
            if s.health_status not in ('failed', 'skipped'):
                s.compute_health()

        summary = self.get_summary()

        # Persist per-stage metrics
        try:
            cursor = self.db.conn.cursor()
            for s in self.stages.values():
                cursor.execute("""
                    INSERT INTO pipeline_stage_metrics (
                        discovery_run_id, organization_id, stage_name, stage_order,
                        records_fetched, records_matched, records_persisted,
                        records_failed, records_skipped, failure_rate,
                        started_at, completed_at, duration_ms,
                        health_status, degradation_reason, error_message,
                        prior_run_persisted, delta_vs_prior, extra
                    ) VALUES (
                        %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s,
                        %s, %s, %s,
                        %s, %s, %s
                    )
                    ON CONFLICT (discovery_run_id, stage_name)
                    DO UPDATE SET
                        records_fetched = EXCLUDED.records_fetched,
                        records_matched = EXCLUDED.records_matched,
                        records_persisted = EXCLUDED.records_persisted,
                        records_failed = EXCLUDED.records_failed,
                        records_skipped = EXCLUDED.records_skipped,
                        failure_rate = EXCLUDED.failure_rate,
                        started_at = EXCLUDED.started_at,
                        completed_at = EXCLUDED.completed_at,
                        duration_ms = EXCLUDED.duration_ms,
                        health_status = EXCLUDED.health_status,
                        degradation_reason = EXCLUDED.degradation_reason,
                        error_message = EXCLUDED.error_message,
                        prior_run_persisted = EXCLUDED.prior_run_persisted,
                        delta_vs_prior = EXCLUDED.delta_vs_prior,
                        extra = EXCLUDED.extra
                """, (
                    self.run_id, self.org_id, s.name, s.order,
                    s.fetched, s.matched, s.persisted,
                    s.failed, s.skipped, round(s.failure_rate, 2),
                    s.started_at, s.completed_at, s.duration_ms,
                    s.health_status, s.degradation_reason, s.error_message,
                    s.prior_run_persisted, s.delta_vs_prior,
                    '{}',
                ))
            cursor.close()
            self.db._commit()
        except Exception as e:
            logger.error("Failed to persist pipeline_stage_metrics: %s", e)
            try:
                self.db.conn.rollback()
            except Exception:
                pass

        # Attach summary to discovery_runs (only if not yet finalized with snapshot_hash)
        try:
            import json
            cursor = self.db.conn.cursor()
            cursor.execute("""
                UPDATE discovery_runs
                SET pipeline_health_summary = %s
                WHERE id = %s AND snapshot_hash IS NULL
            """, (json.dumps(summary), self.run_id))
            self.db._commit()
            cursor.close()
        except Exception as e:
            # Immutability trigger may block this — non-fatal
            logger.debug("pipeline_health_summary update skipped (immutable run): %s", e)
            try:
                self.db.conn.rollback()
            except Exception:
                pass

        # Log overall health
        if summary['overall_health'] != 'healthy':
            logger.warning(
                "PIPELINE_HEALTH_%s run=%d org=%d stages=%d degraded=%d failed=%d issues=%s",
                summary['overall_health'].upper(),
                self.run_id, self.org_id,
                summary['total_stages'], summary['degraded'], summary['failed'],
                [i['stage'] for i in summary['issues']],
            )
        else:
            logger.info(
                "PIPELINE_HEALTH_HEALTHY run=%d org=%d stages=%d",
                self.run_id, self.org_id, summary['total_stages'],
            )

        return summary
