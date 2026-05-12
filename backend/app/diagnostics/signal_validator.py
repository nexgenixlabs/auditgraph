"""12-Signal Validation — confirms all identity risk signals are collected,
computed, and stored correctly for a given organization."""

import logging
import random
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

PRIVILEGED_ROLES = (
    'Owner', 'Contributor', 'Global Administrator',
    'Privileged Role Administrator',
    'User Access Administrator',
)


class SignalValidator:
    """Validate the 12 identity risk signals against live DB data."""

    def __init__(self, conn):
        self.conn = conn

    # ------------------------------------------------------------------
    # public
    # ------------------------------------------------------------------
    def validate_all(self, org_id: int) -> dict:
        checks = [
            self._check_1_privileged_role,
            self._check_2_role_scope,
            self._check_3_account_type,
            self._check_4_account_enabled,
            self._check_5_mfa_sspr,
            self._check_6_owner_present,
            self._check_7_last_sign_in,
            self._check_8_federated_credentials,
            self._check_9_secret_cert_expiry,
            self._check_10_dormancy,
            self._check_11_orphan,
            self._check_12_blast_radius,
        ]
        signals = []
        for fn in checks:
            try:
                signals.append(fn(org_id))
            except Exception as exc:
                self.conn.rollback()
                signals.append({
                    'signal_number': checks.index(fn) + 1,
                    'name': fn.__doc__ or fn.__name__,
                    'status': 'FAIL',
                    'detail': f'Exception: {exc}',
                    'rows_checked': 0,
                })

        passed = sum(1 for s in signals if s['status'] == 'PASS')
        warned = sum(1 for s in signals if s['status'] == 'WARN')
        failed = sum(1 for s in signals if s['status'] == 'FAIL')

        return {
            'org_id': org_id,
            'run_at': datetime.now(timezone.utc).isoformat(),
            'signals': signals,
            'summary': {
                'total': len(signals),
                'passed': passed,
                'warned': warned,
                'failed': failed,
            },
        }

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _cur(self):
        return self.conn.cursor()

    def _table_exists(self, table: str) -> bool:
        cur = self._cur()
        cur.execute(
            "SELECT EXISTS(SELECT 1 FROM information_schema.tables "
            "WHERE table_schema='public' AND table_name=%s)",
            (table,),
        )
        exists = cur.fetchone()[0]
        cur.close()
        return exists

    def _column_exists(self, table: str, column: str) -> bool:
        cur = self._cur()
        cur.execute(
            "SELECT EXISTS(SELECT 1 FROM information_schema.columns "
            "WHERE table_schema='public' AND table_name=%s AND column_name=%s)",
            (table, column),
        )
        exists = cur.fetchone()[0]
        cur.close()
        return exists

    # ------------------------------------------------------------------
    # Signal checks
    # ------------------------------------------------------------------
    def _check_1_privileged_role(self, org_id: int) -> dict:
        """Privileged Role Assignment"""
        cur = self._cur()
        cur.execute("""
            SELECT COUNT(*) FROM role_assignments ra
            JOIN identities i ON i.id = ra.identity_db_id
            WHERE i.organization_id = %s
              AND ra.role_name IN %s
        """, (org_id, PRIVILEGED_ROLES))
        count = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(DISTINCT ra.identity_db_id) FROM role_assignments ra
            JOIN identities i ON i.id = ra.identity_db_id
            WHERE i.organization_id = %s
              AND ra.role_name IN %s
        """, (org_id, PRIVILEGED_ROLES))
        identity_count = cur.fetchone()[0]
        cur.close()

        if count > 0:
            return {
                'signal_number': 1,
                'name': 'Privileged Role Assignment',
                'status': 'PASS',
                'detail': f'Found {count} privileged role assignments across {identity_count} identities',
                'rows_checked': count,
            }
        return {
            'signal_number': 1,
            'name': 'Privileged Role Assignment',
            'status': 'WARN',
            'detail': 'Zero privileged role assignments found — data may not have populated yet',
            'rows_checked': 0,
        }

    def _check_2_role_scope(self, org_id: int) -> dict:
        """Role Scope"""
        cur = self._cur()
        cur.execute("""
            SELECT COUNT(*) FROM role_assignments ra
            JOIN identities i ON i.id = ra.identity_db_id
            WHERE i.organization_id = %s
        """, (org_id,))
        total = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM role_assignments ra
            JOIN identities i ON i.id = ra.identity_db_id
            WHERE i.organization_id = %s
              AND (ra.scope IS NULL OR ra.scope = '')
        """, (org_id,))
        missing = cur.fetchone()[0]
        cur.close()

        if total == 0:
            return {
                'signal_number': 2,
                'name': 'Role Scope',
                'status': 'WARN',
                'detail': 'No role_assignments rows for this org',
                'rows_checked': 0,
            }
        if missing == 0:
            return {
                'signal_number': 2,
                'name': 'Role Scope',
                'status': 'PASS',
                'detail': f'All {total} role assignments have scope populated',
                'rows_checked': total,
            }
        return {
            'signal_number': 2,
            'name': 'Role Scope',
            'status': 'FAIL',
            'detail': f'{missing}/{total} role assignments have null or empty scope',
            'rows_checked': total,
        }

    def _check_3_account_type(self, org_id: int) -> dict:
        """Account Type (Guest vs Member)"""
        cur = self._cur()
        # identity_type is the column; for users, identity_category distinguishes Guest/Member
        cur.execute("""
            SELECT COUNT(*) FROM identities
            WHERE organization_id = %s
              AND identity_type IS NOT NULL
        """, (org_id,))
        populated = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM identities
            WHERE organization_id = %s
              AND identity_type IS NULL
        """, (org_id,))
        null_count = cur.fetchone()[0]
        cur.close()

        if populated == 0:
            return {
                'signal_number': 3,
                'name': 'Account Type',
                'status': 'WARN',
                'detail': 'No identities found for this org',
                'rows_checked': 0,
            }
        if null_count == 0:
            return {
                'signal_number': 3,
                'name': 'Account Type',
                'status': 'PASS',
                'detail': f'All {populated} identities have identity_type populated',
                'rows_checked': populated,
            }
        return {
            'signal_number': 3,
            'name': 'Account Type',
            'status': 'FAIL',
            'detail': f'{null_count} identities have NULL identity_type',
            'rows_checked': populated + null_count,
        }

    def _check_4_account_enabled(self, org_id: int) -> dict:
        """Account Enabled"""
        cur = self._cur()
        cur.execute("""
            SELECT COUNT(*) FROM identities
            WHERE organization_id = %s
        """, (org_id,))
        total = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM identities
            WHERE organization_id = %s
              AND enabled IS NULL
        """, (org_id,))
        null_count = cur.fetchone()[0]
        cur.close()

        if total == 0:
            return {
                'signal_number': 4,
                'name': 'Account Enabled',
                'status': 'WARN',
                'detail': 'No identities found for this org',
                'rows_checked': 0,
            }
        if null_count == 0:
            return {
                'signal_number': 4,
                'name': 'Account Enabled',
                'status': 'PASS',
                'detail': f'All {total} identities have enabled flag set',
                'rows_checked': total,
            }
        return {
            'signal_number': 4,
            'name': 'Account Enabled',
            'status': 'WARN',
            'detail': f'{null_count}/{total} identities have NULL enabled flag',
            'rows_checked': total,
        }

    def _check_5_mfa_sspr(self, org_id: int) -> dict:
        """MFA / SSPR Registered"""
        # MFA/SSPR are tracked via ca_mfa_enforced on identities
        has_col = self._column_exists('identities', 'ca_mfa_enforced')
        if not has_col:
            return {
                'signal_number': 5,
                'name': 'MFA / SSPR Registered',
                'status': 'FAIL',
                'detail': 'Column ca_mfa_enforced missing from identities table',
                'rows_checked': 0,
            }

        cur = self._cur()
        # Only check human identities (User, Guest, Member)
        cur.execute("""
            SELECT COUNT(*) FROM identities
            WHERE organization_id = %s
              AND identity_category IN ('user', 'guest')
        """, (org_id,))
        human_count = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM identities
            WHERE organization_id = %s
              AND identity_category IN ('user', 'guest')
              AND ca_mfa_enforced IS NOT NULL
        """, (org_id,))
        populated = cur.fetchone()[0]
        cur.close()

        if human_count == 0:
            return {
                'signal_number': 5,
                'name': 'MFA / SSPR Registered',
                'status': 'WARN',
                'detail': 'No human identities found for this org',
                'rows_checked': 0,
            }
        return {
            'signal_number': 5,
            'name': 'MFA / SSPR Registered',
            'status': 'PASS' if populated > 0 else 'WARN',
            'detail': f'{populated}/{human_count} human identities have MFA enforcement data',
            'rows_checked': human_count,
        }

    def _check_6_owner_present(self, org_id: int) -> dict:
        """Owner Present (SPN/App)"""
        cur = self._cur()
        cur.execute("""
            SELECT COUNT(*) FROM identities
            WHERE organization_id = %s
              AND identity_category IN ('service_principal', 'application', 'managed_identity')
        """, (org_id,))
        spn_count = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM identities
            WHERE organization_id = %s
              AND identity_category IN ('service_principal', 'application', 'managed_identity')
              AND owner_count IS NOT NULL
        """, (org_id,))
        with_owner_data = cur.fetchone()[0]
        cur.close()

        if spn_count == 0:
            return {
                'signal_number': 6,
                'name': 'Owner Present (SPN/App)',
                'status': 'WARN',
                'detail': 'No service principal identities found for this org',
                'rows_checked': 0,
            }
        return {
            'signal_number': 6,
            'name': 'Owner Present (SPN/App)',
            'status': 'PASS' if with_owner_data > 0 else 'WARN',
            'detail': f'{with_owner_data}/{spn_count} SPNs have owner_count populated',
            'rows_checked': spn_count,
        }

    def _check_7_last_sign_in(self, org_id: int) -> dict:
        """Last Sign-In Age"""
        cur = self._cur()
        cur.execute("""
            SELECT COUNT(*) FROM identities
            WHERE organization_id = %s
              AND identity_category IN ('user', 'guest')
        """, (org_id,))
        human_count = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM identities
            WHERE organization_id = %s
              AND identity_category IN ('user', 'guest')
              AND last_sign_in IS NOT NULL
        """, (org_id,))
        with_signin = cur.fetchone()[0]
        cur.close()

        if human_count == 0:
            return {
                'signal_number': 7,
                'name': 'Last Sign-In Age',
                'status': 'WARN',
                'detail': 'No human identities found for this org',
                'rows_checked': 0,
            }
        return {
            'signal_number': 7,
            'name': 'Last Sign-In Age',
            'status': 'PASS' if with_signin > 0 else 'WARN',
            'detail': f'{with_signin}/{human_count} human identities have last_sign_in populated',
            'rows_checked': human_count,
        }

    def _check_8_federated_credentials(self, org_id: int) -> dict:
        """Federated Credential Presence"""
        # Check federated_credentials table
        if not self._table_exists('federated_credentials'):
            # Fallback: check has_federated_credentials column on identities
            has_col = self._column_exists('identities', 'has_federated_credentials')
            if not has_col:
                return {
                    'signal_number': 8,
                    'name': 'Federated Credential Presence',
                    'status': 'FAIL',
                    'detail': 'Neither federated_credentials table nor has_federated_credentials column found',
                    'rows_checked': 0,
                }

        cur = self._cur()
        cur.execute("""
            SELECT COUNT(*) FROM federated_credentials
            WHERE organization_id = %s
        """, (org_id,))
        fc_count = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(DISTINCT identity_db_id) FROM federated_credentials
            WHERE organization_id = %s
        """, (org_id,))
        identity_count = cur.fetchone()[0]
        cur.close()

        if fc_count > 0:
            return {
                'signal_number': 8,
                'name': 'Federated Credential Presence',
                'status': 'PASS',
                'detail': f'{fc_count} federated credentials across {identity_count} identities',
                'rows_checked': fc_count,
            }
        return {
            'signal_number': 8,
            'name': 'Federated Credential Presence',
            'status': 'WARN',
            'detail': 'Zero federated credentials found — none discovered or not applicable',
            'rows_checked': 0,
        }

    def _check_9_secret_cert_expiry(self, org_id: int) -> dict:
        """Secret / Certificate Expiry"""
        if not self._table_exists('identity_credentials'):
            # Fall back to credential_expiration on identities
            cur = self._cur()
            cur.execute("""
                SELECT COUNT(*) FROM identities
                WHERE organization_id = %s
                  AND identity_category IN ('service_principal', 'application')
                  AND credential_expiration IS NOT NULL
            """, (org_id,))
            count = cur.fetchone()[0]
            cur.close()

            if count > 0:
                return {
                    'signal_number': 9,
                    'name': 'Secret / Certificate Expiry',
                    'status': 'PASS',
                    'detail': f'{count} SPNs have credential_expiration on identities table',
                    'rows_checked': count,
                }
            return {
                'signal_number': 9,
                'name': 'Secret / Certificate Expiry',
                'status': 'WARN',
                'detail': 'identity_credentials table not found; no credential_expiration data on identities',
                'rows_checked': 0,
            }

        cur = self._cur()
        cur.execute("""
            SELECT COUNT(*) FROM identity_credentials
            WHERE organization_id = %s
              AND expires_at IS NOT NULL
        """, (org_id,))
        with_expiry = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM identity_credentials
            WHERE organization_id = %s
        """, (org_id,))
        total = cur.fetchone()[0]
        cur.close()

        if total == 0:
            return {
                'signal_number': 9,
                'name': 'Secret / Certificate Expiry',
                'status': 'WARN',
                'detail': 'No identity_credentials rows for this org',
                'rows_checked': 0,
            }
        return {
            'signal_number': 9,
            'name': 'Secret / Certificate Expiry',
            'status': 'PASS' if with_expiry > 0 else 'WARN',
            'detail': f'{with_expiry}/{total} credentials have expires_at populated',
            'rows_checked': total,
        }

    def _check_10_dormancy(self, org_id: int) -> dict:
        """Dormancy Flag"""
        cur = self._cur()
        # Check if activity_status is used to flag dormancy
        cur.execute("""
            SELECT id, display_name, enabled, last_sign_in, activity_status
            FROM identities
            WHERE organization_id = %s
              AND identity_category IN ('user', 'guest')
            ORDER BY random()
            LIMIT 5
        """, (org_id,))
        samples = cur.fetchall()
        cur.close()

        if not samples:
            return {
                'signal_number': 10,
                'name': 'Dormancy Flag',
                'status': 'WARN',
                'detail': 'No human identities to spot-check',
                'rows_checked': 0,
            }

        mismatches = []
        now = datetime.now(timezone.utc)
        for row in samples:
            db_id, name, enabled, last_signin, activity_status = row
            # Dormancy logic: enabled=true, last_sign_in older than 90 days
            is_dormant_computed = False
            if enabled and last_signin:
                days_since = (now - last_signin).days
                if days_since > 90:
                    is_dormant_computed = True
            elif enabled and last_signin is None:
                is_dormant_computed = True  # never signed in

            db_says_dormant = activity_status in ('dormant', 'stale', 'never_used')

            if is_dormant_computed != db_says_dormant:
                mismatches.append(
                    f'{name}: computed={is_dormant_computed}, '
                    f'activity_status={activity_status}'
                )

        if mismatches:
            return {
                'signal_number': 10,
                'name': 'Dormancy Flag',
                'status': 'WARN',
                'detail': f'{len(mismatches)}/5 spot-check mismatches: {"; ".join(mismatches[:3])}',
                'rows_checked': len(samples),
            }
        return {
            'signal_number': 10,
            'name': 'Dormancy Flag',
            'status': 'PASS',
            'detail': f'5 random human identities spot-checked — dormancy logic consistent',
            'rows_checked': len(samples),
        }

    def _check_11_orphan(self, org_id: int) -> dict:
        """Orphan Flag"""
        cur = self._cur()
        cur.execute("""
            SELECT i.id, i.display_name, i.enabled, i.last_sign_in,
                   i.owner_count, i.owner_status
            FROM identities i
            WHERE i.organization_id = %s
              AND i.identity_category IN ('service_principal', 'application')
            ORDER BY random()
            LIMIT 5
        """, (org_id,))
        samples = cur.fetchall()

        if not samples:
            cur.close()
            return {
                'signal_number': 11,
                'name': 'Orphan Flag',
                'status': 'WARN',
                'detail': 'No SPN identities to spot-check',
                'rows_checked': 0,
            }

        mismatches = []
        for row in samples:
            db_id, name, enabled, last_signin, owner_count, owner_status = row
            # Count active role assignments
            cur.execute("""
                SELECT COUNT(*) FROM role_assignments
                WHERE identity_db_id = %s
            """, (db_id,))
            role_count = cur.fetchone()[0]

            # Orphan logic: disabled + has roles + no owner + stale/no sign-in
            is_orphan_computed = (
                not enabled
                and role_count > 0
                and (owner_count is None or owner_count == 0)
            )

            db_says_orphan = owner_status in ('orphaned', 'unowned')

            if is_orphan_computed != db_says_orphan:
                mismatches.append(
                    f'{name}: computed={is_orphan_computed}, '
                    f'owner_status={owner_status}'
                )
        cur.close()

        if mismatches:
            return {
                'signal_number': 11,
                'name': 'Orphan Flag',
                'status': 'WARN',
                'detail': f'{len(mismatches)}/5 spot-check mismatches: {"; ".join(mismatches[:3])}',
                'rows_checked': len(samples),
            }
        return {
            'signal_number': 11,
            'name': 'Orphan Flag',
            'status': 'PASS',
            'detail': '5 random SPNs spot-checked — orphan logic consistent',
            'rows_checked': len(samples),
        }

    def _check_12_blast_radius(self, org_id: int) -> dict:
        """Blast Radius Depth"""
        cur = self._cur()
        cur.execute("""
            SELECT COUNT(*) FROM graph_edges
            WHERE organization_id = %s
        """, (org_id,))
        edge_count = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM graph_nodes
            WHERE organization_id = %s
        """, (org_id,))
        node_count = cur.fetchone()[0]
        cur.close()

        if edge_count == 0:
            return {
                'signal_number': 12,
                'name': 'Blast Radius Depth',
                'status': 'WARN',
                'detail': f'graph_edges empty for org — run discovery ({node_count} nodes exist)',
                'rows_checked': 0,
            }
        return {
            'signal_number': 12,
            'name': 'Blast Radius Depth',
            'status': 'PASS',
            'detail': f'{node_count} graph nodes, {edge_count} graph edges for org',
            'rows_checked': edge_count,
        }
