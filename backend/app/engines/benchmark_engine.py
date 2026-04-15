"""Phase 14: Cross-Tenant Security Benchmarking Engine.

Computes aggregated security benchmarks from tenant posture metrics
while preserving strict tenant isolation. Only aggregated, anonymised
metrics are stored in the benchmarks table.
"""

import logging

logger = logging.getLogger(__name__)


class BenchmarkEngine:
    """Computes cross-tenant security benchmarks using aggregated metrics."""

    def __init__(self, db):
        self.db = db

    def collect_tenant_posture(self, org_id):
        """Collect posture metrics for a single tenant and store them.

        Called after dashboard summary computation in the pipeline.
        Uses the org-scoped DB connection (RLS enforced).
        """
        try:
            summary = self.db.get_dashboard_summary()
            risk_score = summary.get('risk_score', 0)
            critical_findings = summary.get('critical_findings', 0)
            high_findings = summary.get('high_findings', 0)
            nhi_exposure = (
                summary.get('secrets_without_expiry', 0) +
                summary.get('unused_service_principals', 0)
            )
            escalation_paths = summary.get('identities_with_attack_paths', 0)
            identity_count = summary.get('total_identities', 0)

            # Compute average blast radius from simulations
            blast_radius_avg = self._compute_avg_blast_radius()

            self.db.save_tenant_posture_metrics(
                org_id=org_id,
                risk_score=risk_score,
                critical_findings=critical_findings,
                high_findings=high_findings,
                blast_radius_avg=blast_radius_avg,
                nhi_exposure=nhi_exposure,
                escalation_paths=escalation_paths,
                identity_count=identity_count,
            )

            logger.info(f"Posture metrics collected for org {org_id}: risk_score={risk_score}")
            return {
                'risk_score': risk_score,
                'critical_findings': critical_findings,
                'high_findings': high_findings,
                'blast_radius_avg': blast_radius_avg,
                'nhi_exposure': nhi_exposure,
                'escalation_paths': escalation_paths,
            }
        except Exception as e:
            logger.error(f"Failed to collect posture metrics for org {org_id}: {e}")
            return None

    def compute_security_benchmarks(self):
        """Compute aggregated benchmarks from all tenant posture metrics.

        Privacy safeguard: Only stores anonymised aggregates (averages,
        percentiles, sample sizes). No tenant-specific data is exposed.

        Must run with admin DB connection (bypasses RLS to read all tenants).
        """
        try:
            metrics = self.db.get_all_tenant_posture_latest()
            if not metrics:
                logger.info("No posture metrics available for benchmarking")
                return {}

            sample_size = len(metrics)

            benchmarks = {}
            for metric_name, extractor in BENCHMARK_METRICS.items():
                values = [extractor(m) for m in metrics]
                values = [v for v in values if v is not None]
                if not values:
                    continue

                values.sort()
                avg = sum(values) / len(values)
                p25 = self._percentile(values, 25)
                p50 = self._percentile(values, 50)
                p75 = self._percentile(values, 75)

                benchmarks[metric_name] = {
                    'metric_value': round(avg, 2),
                    'sample_size': sample_size,
                    'percentile_25': round(p25, 2),
                    'percentile_50': round(p50, 2),
                    'percentile_75': round(p75, 2),
                }

            # Store benchmarks
            for metric_name, data in benchmarks.items():
                self.db.upsert_security_benchmark(metric_name, **data)

            logger.info(f"Security benchmarks computed: {len(benchmarks)} metrics, {sample_size} tenants")
            return benchmarks

        except Exception as e:
            logger.error(f"Failed to compute security benchmarks: {e}")
            return {}

    def get_tenant_benchmark_comparison(self, org_id):
        """Compare a tenant's posture against aggregated benchmarks.

        Returns the tenant's metrics alongside industry averages and percentiles.
        Privacy safeguard: Only returns aggregated benchmark data, never
        other tenants' individual metrics.
        """
        # Get tenant's latest posture
        tenant_metrics = self.db.get_latest_tenant_posture(org_id)
        if not tenant_metrics:
            return {'error': 'No posture metrics available for this organization'}

        # Get aggregated benchmarks
        benchmarks = self.db.get_security_benchmarks()

        comparison = {}
        for metric_name, benchmark in benchmarks.items():
            tenant_value = None
            if metric_name == 'avg_risk_score':
                tenant_value = tenant_metrics.get('risk_score', 0)
            elif metric_name == 'avg_critical_findings':
                tenant_value = tenant_metrics.get('critical_findings', 0)
            elif metric_name == 'avg_blast_radius':
                tenant_value = tenant_metrics.get('blast_radius_avg', 0)
            elif metric_name == 'avg_nhi_exposure':
                tenant_value = tenant_metrics.get('nhi_exposure', 0)
            elif metric_name == 'avg_escalation_paths':
                tenant_value = tenant_metrics.get('escalation_paths', 0)
            elif metric_name == 'avg_high_findings':
                tenant_value = tenant_metrics.get('high_findings', 0)

            # Calculate percentile rank
            percentile = self._calculate_percentile_rank(
                tenant_value, benchmark
            ) if tenant_value is not None else None

            comparison[metric_name] = {
                'your_value': tenant_value,
                'industry_average': benchmark.get('metric_value', 0),
                'percentile': percentile,
                'sample_size': benchmark.get('sample_size', 0),
                'percentile_25': benchmark.get('percentile_25'),
                'percentile_50': benchmark.get('percentile_50'),
                'percentile_75': benchmark.get('percentile_75'),
            }

        return {
            'your_risk_score': tenant_metrics.get('risk_score', 0),
            'industry_average': comparison.get('avg_risk_score', {}).get('industry_average', 0),
            'percentile': comparison.get('avg_risk_score', {}).get('percentile', 50),
            'metrics': comparison,
            'collected_at': str(tenant_metrics.get('created_at', '')),
        }

    def _compute_avg_blast_radius(self):
        """Compute average blast radius from attack simulations."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                SELECT COALESCE(AVG(blast_radius), 0)
                FROM attack_simulations
            """)
            row = cursor.fetchone()
            cursor.close()
            return float(row[0]) if row else 0.0
        except Exception:
            return 0.0

    @staticmethod
    def _percentile(sorted_values, p):
        """Calculate the p-th percentile of a sorted list."""
        if not sorted_values:
            return 0
        k = (len(sorted_values) - 1) * (p / 100.0)
        f = int(k)
        c = f + 1
        if c >= len(sorted_values):
            return sorted_values[-1]
        return sorted_values[f] + (k - f) * (sorted_values[c] - sorted_values[f])

    @staticmethod
    def _calculate_percentile_rank(value, benchmark):
        """Calculate what percentile a value falls in (higher = worse for risk metrics)."""
        if value is None:
            return 50
        p25 = benchmark.get('percentile_25', 0) or 0
        p50 = benchmark.get('percentile_50', 0) or 0
        p75 = benchmark.get('percentile_75', 0) or 0
        avg = benchmark.get('metric_value', 0) or 0

        if avg == 0 and value == 0:
            return 50

        # Estimate percentile rank based on quartile boundaries
        if value <= p25:
            return 25
        elif value <= p50:
            return 50
        elif value <= p75:
            return 75
        else:
            return 90


# Metric extractors: map benchmark name → lambda to extract from posture row
BENCHMARK_METRICS = {
    'avg_risk_score': lambda m: m.get('risk_score'),
    'avg_critical_findings': lambda m: m.get('critical_findings'),
    'avg_high_findings': lambda m: m.get('high_findings'),
    'avg_blast_radius': lambda m: m.get('blast_radius_avg'),
    'avg_nhi_exposure': lambda m: m.get('nhi_exposure'),
    'avg_escalation_paths': lambda m: m.get('escalation_paths'),
}
