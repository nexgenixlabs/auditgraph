"""
Identity Correlation Engine (ICE) — links regular ↔ privileged accounts.

Many orgs create two accounts per employee: a regular account (bhupathi@company.com)
and a privileged account (ep.bhupathi@company.com). This engine detects those pairs
and links them to a single human identity for orphaned-account detection.
"""
from difflib import SequenceMatcher
from psycopg2.extras import RealDictCursor


DEFAULT_CONFIG = {
    'ice_enabled': 'true',
    'ice_privileged_prefixes': 'ep.,adm-,adm.,a-,admin-,admin.,priv-,priv.,sa_,pa-,pa.',
    'ice_privileged_suffixes': '-admin,.admin,-priv,.priv,-elevated,.elevated',
    'ice_display_name_similarity_threshold': '0.80',
    'ice_creation_window_hours': '48',
}


class IdentityCorrelator:
    """Correlates regular ↔ privileged user accounts."""

    def __init__(self, db):
        self.db = db

    def correlate(self, run_id):
        """Main entry: load config, fetch users, run matching, return summary."""
        config = self._load_config()
        if config.get('ice_enabled', 'true') != 'true':
            return {'status': 'disabled', 'humans_created': 0, 'links_created': 0}

        tenant_id = self.db._tenant_id
        if not tenant_id:
            return {'status': 'skipped', 'reason': 'no_tenant'}

        regular, privileged = self._fetch_users(run_id)
        if not regular and not privileged:
            return {'status': 'no_users', 'humans_created': 0, 'links_created': 0}

        total_humans = 0
        total_links = 0

        # Method 1: Naming convention (highest signal)
        h, l = self._match_by_naming_convention(tenant_id, regular, privileged, config)
        total_humans += h
        total_links += l

        # Method 2: Employee ID (rare but very high confidence)
        h, l = self._match_by_employee_id(tenant_id, regular, privileged, config)
        total_humans += h
        total_links += l

        # Method 3: Display name fuzzy match
        h, l = self._match_by_display_name(tenant_id, regular, privileged, config)
        total_humans += h
        total_links += l

        return {
            'status': 'completed',
            'humans_created': total_humans,
            'links_created': total_links,
            'regular_count': len(regular),
            'privileged_count': len(privileged),
        }

    def _load_config(self):
        """Load ICE settings from DB, falling back to defaults."""
        config = dict(DEFAULT_CONFIG)
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        try:
            cursor.execute(
                "SELECT key, value FROM settings WHERE key LIKE 'ice_%%'")
            for row in cursor.fetchall():
                config[row['key']] = row['value']
        except Exception:
            pass
        finally:
            cursor.close()
        return config

    def _fetch_users(self, run_id):
        """Fetch human_user identities from the latest run, split by category."""
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        try:
            cursor.execute("""
                SELECT id, identity_id, display_name, object_id, upn,
                       employee_id_entra, department, manager_id, manager_upn,
                       job_title, account_category, enabled, created_datetime,
                       last_sign_in
                FROM identities
                WHERE discovery_run_id = %s
                  AND identity_category IN ('human_user', 'guest')
                  AND deleted_at IS NULL
            """, (run_id,))
            users = [dict(r) for r in cursor.fetchall()]
        finally:
            cursor.close()

        regular = [u for u in users if u.get('account_category') == 'regular']
        privileged = [u for u in users if u.get('account_category') == 'privileged']
        return regular, privileged

    def _match_by_naming_convention(self, tenant_id, regular, privileged, config):
        """Strip prefix/suffix from privileged UPN, match against regular UPNs."""
        prefixes = [p.strip() for p in config.get('ice_privileged_prefixes', '').split(',') if p.strip()]
        suffixes = [s.strip() for s in config.get('ice_privileged_suffixes', '').split(',') if s.strip()]

        # Build lookup: local_part → regular user
        regular_map = {}
        for u in regular:
            upn = (u.get('upn') or '').lower()
            if '@' in upn:
                local = upn.split('@')[0]
                regular_map[local] = u

        humans_created = 0
        links_created = 0

        for priv in privileged:
            if self._already_linked(priv.get('object_id')):
                continue
            priv_upn = (priv.get('upn') or '').lower()
            if '@' not in priv_upn:
                continue
            priv_local = priv_upn.split('@')[0]
            priv_domain = priv_upn.split('@')[1]

            # Try stripping each prefix/suffix
            stripped = None
            for prefix in prefixes:
                if priv_local.startswith(prefix):
                    stripped = priv_local[len(prefix):]
                    break
            if not stripped:
                for suffix in suffixes:
                    if priv_local.endswith(suffix):
                        stripped = priv_local[:-len(suffix)]
                        break
            if not stripped:
                continue

            # Look for exact match
            match = regular_map.get(stripped)
            if not match:
                # Try with dots replaced by nothing, etc.
                alt = stripped.replace('.', '')
                for key, val in regular_map.items():
                    if key.replace('.', '') == alt:
                        match = val
                        break

            if match:
                confidence = 95.0 if regular_map.get(stripped) else 85.0
                h, l = self._create_link_pair(
                    tenant_id, match, priv, 'naming_convention', confidence)
                humans_created += h
                links_created += l

        return humans_created, links_created

    def _match_by_employee_id(self, tenant_id, regular, privileged, config):
        """Match by shared employeeId (rare but high confidence)."""
        eid_map = {}
        for u in regular:
            eid = u.get('employee_id_entra')
            if eid:
                eid_map[eid] = u

        humans_created = 0
        links_created = 0

        for priv in privileged:
            if self._already_linked(priv.get('object_id')):
                continue
            eid = priv.get('employee_id_entra')
            if eid and eid in eid_map:
                match = eid_map[eid]
                h, l = self._create_link_pair(
                    tenant_id, match, priv, 'employee_id', 95.0)
                humans_created += h
                links_created += l

        return humans_created, links_created

    def _match_by_display_name(self, tenant_id, regular, privileged, config):
        """Fuzzy match on display names after stripping admin prefixes."""
        threshold = float(config.get('ice_display_name_similarity_threshold', '0.80'))
        admin_prefixes = ['admin - ', 'ep - ', 'priv - ', 'adm - ', 'admin-', 'ep-', 'priv-']

        def normalize_name(name):
            if not name:
                return ''
            n = name.lower().strip()
            for ap in admin_prefixes:
                if n.startswith(ap):
                    n = n[len(ap):]
                    break
            return n

        regular_names = [(normalize_name(u.get('display_name')), u) for u in regular]
        humans_created = 0
        links_created = 0

        for priv in privileged:
            if self._already_linked(priv.get('object_id')):
                continue
            priv_name = normalize_name(priv.get('display_name'))
            if not priv_name:
                continue

            best_ratio = 0
            best_match = None
            for reg_name, reg_user in regular_names:
                if not reg_name:
                    continue
                ratio = SequenceMatcher(None, priv_name, reg_name).ratio()
                if ratio > best_ratio:
                    best_ratio = ratio
                    best_match = reg_user

            if best_ratio >= threshold and best_match:
                # Only link if not already linked by a higher-confidence method
                if not self._already_linked(best_match.get('object_id')):
                    h, l = self._create_link_pair(
                        tenant_id, best_match, priv, 'display_name', 80.0)
                    humans_created += h
                    links_created += l

        return humans_created, links_created

    def _create_link_pair(self, tenant_id, regular_user, priv_user, method, confidence):
        """Create a human identity and link both accounts to it."""
        # Derive display name from the regular account
        display_name = regular_user.get('display_name', 'Unknown')
        human_id = self.db.save_human_identity(
            tenant_id=tenant_id,
            display_name=display_name,
            employee_id=regular_user.get('employee_id_entra'),
            department=regular_user.get('department'),
            manager_id=regular_user.get('manager_id'),
        )
        if not human_id:
            return 0, 0

        humans_created = 1
        links_created = 0

        # Link regular account
        link_id = self.db.save_identity_link(
            tenant_id=tenant_id,
            human_identity_id=human_id,
            identity_db_id=regular_user['id'],
            account_type='regular',
            account_upn=regular_user.get('upn'),
            account_object_id=regular_user.get('object_id'),
            account_enabled=regular_user.get('enabled', True),
            link_method=method,
            link_confidence=confidence,
        )
        if link_id:
            links_created += 1

        # Link privileged account
        link_id = self.db.save_identity_link(
            tenant_id=tenant_id,
            human_identity_id=human_id,
            identity_db_id=priv_user['id'],
            account_type='privileged',
            account_upn=priv_user.get('upn'),
            account_object_id=priv_user.get('object_id'),
            account_enabled=priv_user.get('enabled', True),
            link_method=method,
            link_confidence=confidence,
        )
        if link_id:
            links_created += 1

        return humans_created, links_created

    def _already_linked(self, object_id):
        """Check if an account is already linked."""
        if not object_id:
            return False
        cursor = self.db.conn.cursor()
        try:
            cursor.execute(
                "SELECT 1 FROM identity_links WHERE account_object_id = %s LIMIT 1",
                (object_id,))
            return cursor.fetchone() is not None
        except Exception:
            return False
        finally:
            cursor.close()
