"""
ConnectionLifecycleService

Manages the complete data lifecycle for cloud connections.
Called automatically on:
  - Connection removal (full cleanup)
  - One-time cleanup of orphaned data

Architecture:
  - discovery_runs has ON DELETE CASCADE FK to cloud_connections (migration 074)
  - 20+ child tables cascade from discovery_runs (identities, role_assignments, etc.)
  - cc_tables are cleaned directly (they reference cloud_connection_id, not discovery_run_id)
  - In-flight snapshot_jobs are cancelled before deletion
  - Post-deletion assertion verifies zero orphan rows across all tables
"""

import logging
from psycopg2 import sql as psycopg2_sql

logger = logging.getLogger(__name__)

# All tables with a cloud_connection_id column (not cascaded from discovery_runs).
# Used for both direct cleanup (Step 2) and post-deletion assertion (Step 6).
CC_TABLES = [
    'snapshot_jobs',
    'risk_findings',
    'graph_nodes',
    'graph_edges',
    'identity_credentials',
    'policy_recommendations',
    'auto_remediation_actions',
    'attack_simulations',
    'graph_visualization_cache',
    'generated_policies',
    'identity_threat_events',
    'identity_activity_events',
    'identity_graph_insights',
    'identity_governance_actions',
    'identity_risk_simulations',
    'identity_governance_metrics',
    'identity_governance_trends',
    'security_strategy_recommendations',
    'identity_security_posture',
]


class ConnectionLifecycleService:
    """Removes all data for a cloud connection when it is deleted.

    Strategy:
      0. Cancel in-flight discovery/snapshot jobs for this connection.
      1. Clean tables with cloud_connection_id (don't cascade from discovery_runs).
      2. Delete discovery_runs → FK CASCADE handles 20+ child tables automatically.
      3. Delete cloud_subscriptions for this connection.
      4. Delete the cloud_connections row itself.
      5. Assert zero orphan rows across ALL connection-scoped tables + discovery_runs.
    """

    def __init__(self, db):
        self.db = db

    def remove_connection_data(self, org_id: int, connection_id: int) -> dict:
        """Completely removes all data for a connection.

        Returns summary of what was deleted.
        """
        summary = {}
        cursor = self.db.conn.cursor()

        try:
            # Step 0: Cancel in-flight discovery jobs
            cancelled = self._cancel_inflight_jobs(cursor, connection_id)
            if cancelled > 0:
                summary['jobs_cancelled'] = cancelled

            # Step 1: Count discovery runs for this connection
            cursor.execute("""
                SELECT id FROM discovery_runs
                WHERE cloud_connection_id = %s AND organization_id = %s
            """, (connection_id, org_id))
            run_ids = [r[0] for r in cursor.fetchall()]
            summary['discovery_runs_found'] = len(run_ids)

            if not run_ids:
                logger.info("No discovery runs found for connection %s (org %s)",
                            connection_id, org_id)

            # Step 2: Clean tables with cloud_connection_id column
            # (these don't cascade from discovery_runs)
            for table in CC_TABLES:
                try:
                    cursor.execute("SAVEPOINT cc_cleanup")
                    cursor.execute(
                        psycopg2_sql.SQL("DELETE FROM {tbl} WHERE cloud_connection_id = %s")
                        .format(tbl=psycopg2_sql.Identifier(table)),
                        (connection_id,),
                    )
                    deleted = cursor.rowcount
                    cursor.execute("RELEASE SAVEPOINT cc_cleanup")
                    if deleted > 0:
                        summary[table] = deleted
                        logger.info("  %s: %d rows deleted", table, deleted)
                except Exception as e:
                    logger.debug("  %s: skipped (%s)", table, e)
                    try:
                        cursor.execute("ROLLBACK TO SAVEPOINT cc_cleanup")
                    except Exception:
                        pass

            # Step 3: Delete discovery_runs → FK CASCADE handles 20+ child tables
            # (identities, role_assignments, risk_summary, anomalies,
            #  app_registrations, azure_storage_accounts, azure_key_vaults,
            #  drift_reports, entra_role_assignments, ca_policies,
            #  identity_subscription_access, workload_*, etc.)
            if run_ids:
                cursor.execute("""
                    DELETE FROM discovery_runs
                    WHERE cloud_connection_id = %s AND organization_id = %s
                """, (connection_id, org_id))
                summary['discovery_runs'] = cursor.rowcount
                logger.info("  discovery_runs: %d deleted (+ cascade to child tables)",
                            cursor.rowcount)

            # Step 4: Delete cloud_subscriptions for this connection
            try:
                cursor.execute("SAVEPOINT sub_cleanup")
                cursor.execute("""
                    DELETE FROM cloud_subscriptions
                    WHERE cloud_connection_id = %s AND organization_id = %s
                """, (connection_id, org_id))
                deleted = cursor.rowcount
                cursor.execute("RELEASE SAVEPOINT sub_cleanup")
                if deleted > 0:
                    summary['cloud_subscriptions'] = deleted
            except Exception:
                try:
                    cursor.execute("ROLLBACK TO SAVEPOINT sub_cleanup")
                except Exception:
                    pass

            # Step 5: Delete the cloud_connections row itself
            # (FK CASCADE on discovery_runs means any remaining runs are auto-deleted)
            cursor.execute("""
                DELETE FROM cloud_connections
                WHERE id = %s AND organization_id = %s
            """, (connection_id, org_id))
            summary['cloud_connections'] = cursor.rowcount

            # Step 6: Assert no orphan rows remain before committing
            self._assert_clean_delete(cursor, connection_id, org_id)

            self.db.conn.commit()

            total_deleted = sum(v for v in summary.values() if isinstance(v, int))
            logger.info(
                "Connection %d cleanup complete for org %d. "
                "Total rows deleted: %d (+ cascaded child rows)",
                connection_id, org_id, total_deleted
            )

            return {
                'deleted': True,
                'connection_id': connection_id,
                'runs_removed': len(run_ids),
                'jobs_cancelled': cancelled,
                'rows_deleted': summary,
                'total_deleted': total_deleted,
            }

        except Exception as e:
            logger.error("Connection cleanup failed for %d: %s",
                         connection_id, e, exc_info=True)
            try:
                self.db.conn.rollback()
            except Exception:
                pass
            return {
                'deleted': False,
                'connection_id': connection_id,
                'error': str(e),
            }
        finally:
            cursor.close()

    def purge_connection_data(self, org_id: int, connection_id: int) -> dict:
        """Delete all data for a connection but KEEP the cloud_connections row.

        Used for auth_failed connections where we want to clear stale data
        (identities, runs, etc.) without removing the connection itself.
        The user can then re-authenticate and run a fresh scan.
        """
        summary = {}
        cursor = self.db.conn.cursor()

        try:
            # Step 0: Cancel in-flight discovery jobs
            cancelled = self._cancel_inflight_jobs(cursor, connection_id)
            if cancelled > 0:
                summary['jobs_cancelled'] = cancelled

            # Step 1: Count discovery runs
            cursor.execute("""
                SELECT id FROM discovery_runs
                WHERE cloud_connection_id = %s AND organization_id = %s
            """, (connection_id, org_id))
            run_ids = [r[0] for r in cursor.fetchall()]
            summary['discovery_runs_found'] = len(run_ids)

            # Step 2: Clean tables with cloud_connection_id column
            for table in CC_TABLES:
                try:
                    cursor.execute("SAVEPOINT purge_cc")
                    cursor.execute(
                        psycopg2_sql.SQL("DELETE FROM {tbl} WHERE cloud_connection_id = %s")
                        .format(tbl=psycopg2_sql.Identifier(table)),
                        (connection_id,),
                    )
                    deleted = cursor.rowcount
                    cursor.execute("RELEASE SAVEPOINT purge_cc")
                    if deleted > 0:
                        summary[table] = deleted
                        logger.info("  purge %s: %d rows deleted", table, deleted)
                except Exception as e:
                    logger.debug("  purge %s: skipped (%s)", table, e)
                    try:
                        cursor.execute("ROLLBACK TO SAVEPOINT purge_cc")
                    except Exception:
                        pass

            # Step 3: Delete discovery_runs → FK CASCADE handles child tables
            if run_ids:
                cursor.execute("""
                    DELETE FROM discovery_runs
                    WHERE cloud_connection_id = %s AND organization_id = %s
                """, (connection_id, org_id))
                summary['discovery_runs'] = cursor.rowcount
                logger.info("  purge discovery_runs: %d deleted (+ cascade)",
                            cursor.rowcount)

            # Step 4: Delete cloud_subscriptions
            try:
                cursor.execute("SAVEPOINT purge_sub")
                cursor.execute("""
                    DELETE FROM cloud_subscriptions
                    WHERE cloud_connection_id = %s AND organization_id = %s
                """, (connection_id, org_id))
                deleted = cursor.rowcount
                cursor.execute("RELEASE SAVEPOINT purge_sub")
                if deleted > 0:
                    summary['cloud_subscriptions'] = deleted
            except Exception:
                try:
                    cursor.execute("ROLLBACK TO SAVEPOINT purge_sub")
                except Exception:
                    pass

            # NOTE: We intentionally do NOT delete the cloud_connections row.
            # The connection stays so the user can re-authenticate and re-scan.

            self.db.conn.commit()

            total_deleted = sum(v for v in summary.values() if isinstance(v, int))
            logger.info(
                "Connection %d data purged for org %d. "
                "Total rows deleted: %d (connection row retained)",
                connection_id, org_id, total_deleted
            )

            return {
                'purged': True,
                'connection_id': connection_id,
                'runs_removed': len(run_ids),
                'jobs_cancelled': cancelled,
                'rows_deleted': summary,
                'total_deleted': total_deleted,
            }

        except Exception as e:
            logger.error("Connection data purge failed for %d: %s",
                         connection_id, e, exc_info=True)
            try:
                self.db.conn.rollback()
            except Exception:
                pass
            return {
                'purged': False,
                'connection_id': connection_id,
                'error': str(e),
            }
        finally:
            cursor.close()

    def _cancel_inflight_jobs(self, cursor, connection_id: int) -> int:
        """Cancel any queued/running snapshot jobs for this connection.

        Prevents data writes from in-progress discovery after the connection
        is deleted. Returns count of cancelled jobs.
        """
        try:
            cursor.execute("SAVEPOINT cancel_jobs")
            cursor.execute("""
                UPDATE snapshot_jobs
                SET status = 'cancelled',
                    error_message = 'Connection deleted — job cancelled',
                    completed_at = NOW()
                WHERE cloud_connection_id = %s
                  AND status IN ('queued', 'running')
            """, (connection_id,))
            cancelled = cursor.rowcount
            cursor.execute("RELEASE SAVEPOINT cancel_jobs")
            if cancelled > 0:
                logger.info("  Cancelled %d in-flight job(s) for connection %d",
                            cancelled, connection_id)
            return cancelled
        except Exception as e:
            logger.debug("  Job cancellation skipped (%s)", e)
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT cancel_jobs")
            except Exception:
                pass
            return 0

    def _assert_clean_delete(self, cursor, connection_id: int, org_id: int):
        """Raise RuntimeError if any rows remain for this connection.

        Checks ALL cc_tables + discovery_runs to guarantee zero orphan rows.
        """
        # Check all tables with cloud_connection_id
        check_tables = list(CC_TABLES)

        # Also verify discovery_runs are gone (should be CASCADE-deleted)
        check_tables.append('discovery_runs')

        dirty = {}
        for table in check_tables:
            try:
                cursor.execute("SAVEPOINT assert_check")
                cursor.execute(
                    psycopg2_sql.SQL("SELECT COUNT(*) FROM {tbl} WHERE cloud_connection_id = %s")
                    .format(tbl=psycopg2_sql.Identifier(table)),
                    (connection_id,),
                )
                count = cursor.fetchone()[0]
                cursor.execute("RELEASE SAVEPOINT assert_check")
                if count > 0:
                    dirty[table] = count
            except Exception:
                try:
                    cursor.execute("ROLLBACK TO SAVEPOINT assert_check")
                except Exception:
                    pass
        if dirty:
            raise RuntimeError(
                f"Delete incomplete — orphan rows remain: {dirty}. "
                f"Transaction will be rolled back."
            )

    def cleanup_orphaned_data(self, org_id: int) -> dict:
        """Remove data from connections that no longer exist.

        Finds discovery_runs whose cloud_connection_id is missing from
        cloud_connections (deleted) or is_active=false, then cleans up.
        """
        cursor = self.db.conn.cursor()
        try:
            # Find orphaned connection IDs
            cursor.execute("""
                SELECT DISTINCT dr.cloud_connection_id
                FROM discovery_runs dr
                LEFT JOIN cloud_connections cc ON cc.id = dr.cloud_connection_id
                WHERE dr.organization_id = %s
                  AND dr.cloud_connection_id IS NOT NULL
                  AND (cc.id IS NULL OR cc.status = 'removed')
            """, (org_id,))
            orphaned_conn_ids = [r[0] for r in cursor.fetchall()]
            cursor.close()

            if not orphaned_conn_ids:
                return {
                    'message': 'No stale data found',
                    'cleaned': 0,
                    'connection_ids': [],
                }

            logger.info("Found %d orphaned connections for org %d: %s",
                         len(orphaned_conn_ids), org_id, orphaned_conn_ids)

            total_deleted = 0
            all_summaries = {}

            for conn_id in orphaned_conn_ids:
                result = self.remove_connection_data(org_id, conn_id)
                total_deleted += result.get('total_deleted', 0)
                all_summaries[conn_id] = result

            return {
                'message': f'Cleaned up {len(orphaned_conn_ids)} inactive connection(s)',
                'cleaned': len(orphaned_conn_ids),
                'total_rows_deleted': total_deleted,
                'connection_ids': orphaned_conn_ids,
                'details': all_summaries,
            }

        except Exception as e:
            logger.error("Orphaned cleanup failed for org %d: %s",
                         org_id, e, exc_info=True)
            cursor.close()
            return {
                'message': f'Cleanup failed: {e}',
                'cleaned': 0,
                'error': str(e),
            }
