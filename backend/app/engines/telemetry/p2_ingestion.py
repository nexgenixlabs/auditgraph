"""
P2 Telemetry Ingestion Service — ingests Entra ID P2 service principal sign-in logs
from Microsoft Graph API and computes per-identity activity statistics.

Requires: AuditLog.Read.All permission on the registered app.
"""

import json
from datetime import datetime, timedelta


class P2TelemetryService:
    """Ingest service principal sign-in logs from MS Graph and compute activity stats."""

    def __init__(self, credential, db):
        self.credential = credential
        self.db = db

    def _get_graph_client(self):
        """Build an authenticated requests session for MS Graph."""
        import requests
        token = self.credential.get_token("https://graph.microsoft.com/.default")
        session = requests.Session()
        session.headers.update({
            "Authorization": f"Bearer {token.token}",
            "Content-Type": "application/json",
        })
        return session

    def ingest_signin_logs(self, run_id, tenant_id, lookback_days=30):
        """Fetch service principal sign-in logs from MS Graph and bulk-insert."""
        session = self._get_graph_client()
        cutoff = (datetime.utcnow() - timedelta(days=lookback_days)).strftime('%Y-%m-%dT%H:%M:%SZ')

        # Build object_id → db_id lookup from current run
        # Graph sign-in events use servicePrincipalId which is the SP's object_id, not appId
        cursor = self.db.conn.cursor()
        cursor.execute(
            "SELECT id, object_id, identity_id FROM identities WHERE discovery_run_id = %s",
            (run_id,)
        )
        id_map = {}
        for row in cursor.fetchall():
            if row[1]:  # object_id (primary match for sign-in events)
                id_map[row[1]] = row[0]
            if row[2]:  # identity_id / appId (fallback)
                id_map[row[2]] = row[0]
        cursor.close()

        url = (
            "https://graph.microsoft.com/beta/auditLogs/signIns"
            f"?$filter=signInEventTypes/any(t:t eq 'servicePrincipal') and createdDateTime ge {cutoff}"
            "&$top=999"
            "&$orderby=createdDateTime desc"
        )

        total_ingested = 0
        while url:
            try:
                resp = session.get(url, timeout=120)
                if resp.status_code != 200:
                    print(f"  ⚠️ Graph sign-in API error: {resp.status_code} — {resp.text[:200]}")
                    break
                data = resp.json()
            except Exception as e:
                print(f"  ⚠️ Graph sign-in request failed: {e}")
                break

            events = data.get('value', [])
            if not events:
                break

            rows = []
            for evt in events:
                sp_id = evt.get('servicePrincipalId') or evt.get('appId') or ''
                identity_db_id = id_map.get(sp_id)

                status_obj = evt.get('status', {})
                status = 'success' if status_obj.get('errorCode', 0) == 0 else 'failure'
                error_code = status_obj.get('errorCode')
                failure_reason = status_obj.get('failureReason')

                location = evt.get('location', {})
                risk_level = (evt.get('riskLevelDuringSignIn') or 'none').lower()
                if risk_level == 'hidden':
                    risk_level = 'none'

                ca_status = 'notApplied'
                ca_policies = evt.get('appliedConditionalAccessPolicies', [])
                if ca_policies:
                    results = [p.get('result', '') for p in ca_policies]
                    if 'success' in results:
                        ca_status = 'success'
                    elif 'failure' in results:
                        ca_status = 'failure'

                rows.append((
                    tenant_id,
                    identity_db_id,
                    sp_id,
                    evt.get('id'),
                    evt.get('createdDateTime'),
                    status,
                    error_code,
                    failure_reason,
                    evt.get('resourceDisplayName'),
                    evt.get('resourceId'),
                    evt.get('ipAddress'),
                    location.get('city'),
                    location.get('countryOrRegion'),
                    evt.get('appDisplayName'),
                    evt.get('clientAppUsed'),
                    evt.get('isInteractive', False),
                    risk_level,
                    evt.get('riskDetail'),
                    ca_status,
                    run_id,
                ))

            if rows:
                cursor = self.db.conn.cursor()
                from psycopg2.extras import execute_values
                execute_values(cursor, """
                    INSERT INTO workload_signin_events
                    (tenant_id, identity_db_id, identity_id, sign_in_id, created_datetime,
                     status, error_code, failure_reason, resource_display_name, resource_id,
                     ip_address, location_city, location_country, app_display_name,
                     client_app_type, is_interactive, risk_level, risk_detail,
                     conditional_access_status, discovery_run_id)
                    VALUES %s
                    ON CONFLICT DO NOTHING
                """, rows)
                self.db.conn.commit()
                cursor.close()
                total_ingested += len(rows)

            url = data.get('@odata.nextLink')

        print(f"  ✓ Ingested {total_ingested} P2 sign-in events")
        return total_ingested

    def compute_activity_stats(self, run_id, tenant_id, lookback_days=30):
        """Aggregate sign-in events into per-identity activity stats for the period."""
        cursor = self.db.conn.cursor()
        period_end = datetime.utcnow().date()
        period_start = period_end - timedelta(days=lookback_days)

        try:
            cursor.execute("""
                INSERT INTO workload_activity_stats
                (tenant_id, identity_db_id, identity_id, period_start, period_end,
                 total_sign_ins, successful_sign_ins, failed_sign_ins,
                 unique_resources, unique_ips, unique_locations,
                 peak_hour, off_hours_pct, avg_daily_sign_ins,
                 risk_sign_ins, ca_failures, discovery_run_id)
                SELECT
                    e.tenant_id,
                    e.identity_db_id,
                    e.identity_id,
                    %s AS period_start,
                    %s AS period_end,
                    COUNT(*) AS total_sign_ins,
                    COUNT(*) FILTER (WHERE e.status = 'success') AS successful_sign_ins,
                    COUNT(*) FILTER (WHERE e.status = 'failure') AS failed_sign_ins,
                    COUNT(DISTINCT e.resource_id) AS unique_resources,
                    COUNT(DISTINCT e.ip_address) AS unique_ips,
                    COUNT(DISTINCT e.location_country) AS unique_locations,
                    MODE() WITHIN GROUP (ORDER BY EXTRACT(HOUR FROM e.created_datetime)::int) AS peak_hour,
                    ROUND(
                        100.0 * COUNT(*) FILTER (
                            WHERE EXTRACT(HOUR FROM e.created_datetime) < 6
                               OR EXTRACT(HOUR FROM e.created_datetime) >= 20
                        ) / NULLIF(COUNT(*), 0), 1
                    ) AS off_hours_pct,
                    ROUND(COUNT(*)::numeric / NULLIF(%s, 0), 1) AS avg_daily_sign_ins,
                    COUNT(*) FILTER (WHERE e.risk_level NOT IN ('none', '')) AS risk_sign_ins,
                    COUNT(*) FILTER (WHERE e.conditional_access_status = 'failure') AS ca_failures,
                    %s AS discovery_run_id
                FROM workload_signin_events e
                WHERE e.discovery_run_id = %s
                  AND e.identity_db_id IS NOT NULL
                  AND e.created_datetime >= %s
                GROUP BY e.tenant_id, e.identity_db_id, e.identity_id
                ON CONFLICT (identity_db_id, period_start, period_end)
                DO UPDATE SET
                    total_sign_ins = EXCLUDED.total_sign_ins,
                    successful_sign_ins = EXCLUDED.successful_sign_ins,
                    failed_sign_ins = EXCLUDED.failed_sign_ins,
                    unique_resources = EXCLUDED.unique_resources,
                    unique_ips = EXCLUDED.unique_ips,
                    unique_locations = EXCLUDED.unique_locations,
                    peak_hour = EXCLUDED.peak_hour,
                    off_hours_pct = EXCLUDED.off_hours_pct,
                    avg_daily_sign_ins = EXCLUDED.avg_daily_sign_ins,
                    risk_sign_ins = EXCLUDED.risk_sign_ins,
                    ca_failures = EXCLUDED.ca_failures,
                    discovery_run_id = EXCLUDED.discovery_run_id,
                    computed_at = NOW()
            """, (period_start, period_end, lookback_days, run_id, run_id,
                  datetime.combine(period_start, datetime.min.time())))
            stats_count = cursor.rowcount
            self.db.conn.commit()
            print(f"  ✓ Computed activity stats for {stats_count} identities")
            return stats_count
        except Exception as e:
            self.db.conn.rollback()
            print(f"  ⚠️ Activity stats computation error: {e}")
            return 0
        finally:
            cursor.close()
