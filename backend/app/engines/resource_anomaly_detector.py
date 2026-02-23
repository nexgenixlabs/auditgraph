"""
Resource Anomaly Detection Engine (Phase 89)

Detects security anomalies in Azure Storage Accounts and Key Vaults by
comparing discovery runs. Every anomaly includes explainable AI fields:
trigger, baseline, deviation, confidence, impact, recommended_action.

Anomaly Types:
    - resource_score_spike: Risk score jumps >threshold pts between runs
    - config_drift_critical: Dangerous config change (public blob, TLS downgrade, etc.)
    - shadow_infrastructure: New resource with no diagnostic logging
    - expiry_cascade: N+ secrets/keys/certs expiring in window
    - privilege_creep: Privileged identity count grows >threshold%
    - network_exposure_change: Firewall opened or network rules removed

Usage:
    detector = ResourceAnomalyDetector(db)
    anomalies = detector.analyze(current_run_id, previous_run_id, settings)
"""
import json
import logging
from typing import Dict, List, Optional
from psycopg2.extras import RealDictCursor

from app.database import Database

logger = logging.getLogger(__name__)


class ResourceAnomalyDetector:
    """Detect security anomalies in Azure resources."""

    def __init__(self, db: Database):
        self.db = db

    def analyze(self, current_run_id: int, previous_run_id: int,
                settings: Optional[Dict] = None) -> List[Dict]:
        """
        Run all resource anomaly detectors and return combined results.

        Args:
            current_run_id: Latest completed discovery run
            previous_run_id: Previous discovery run for comparison
            settings: Configurable thresholds

        Returns:
            List of anomaly dicts ready for save_anomalies()
        """
        settings = settings or {}
        anomalies = []

        detectors = [
            ('resource_score_spike', self._detect_score_spike),
            ('config_drift_critical', self._detect_config_drift),
            ('shadow_infrastructure', self._detect_shadow_infra),
            ('expiry_cascade', self._detect_expiry_cascade),
            ('privilege_creep', self._detect_privilege_creep),
            ('network_exposure_change', self._detect_network_change),
        ]

        for name, detector in detectors:
            try:
                if name == 'shadow_infrastructure':
                    results = detector(current_run_id, previous_run_id)
                elif name == 'expiry_cascade':
                    results = detector(current_run_id, settings)
                else:
                    results = detector(current_run_id, previous_run_id, settings)
                anomalies.extend(results)
                if results:
                    logger.info(f"  Resource anomaly '{name}': {len(results)} findings")
            except Exception as e:
                logger.error(f"  Resource anomaly detector '{name}' failed: {e}")

        return anomalies

    # ── Data Helpers ──────────────────────────────────────────

    def _get_run_resources(self, run_id: int, table: str) -> Dict[str, Dict]:
        """Get resources for a run from a specific table, keyed by resource_id."""
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            SELECT * FROM {table}
            WHERE discovery_run_id = %s
        """, (run_id,))
        rows = cursor.fetchall()
        cursor.close()
        result = {}
        for row in rows:
            r = dict(row)
            for jf in ('risk_components', 'critical_overrides', 'tags', 'network_rules',
                        'access_policies', 'secrets_detail', 'keys_detail', 'certs_detail',
                        'logging_destinations', 'encryption_details', 'risk_reasons'):
                if jf in r and isinstance(r[jf], str):
                    try:
                        r[jf] = json.loads(r[jf])
                    except Exception:
                        pass
            result[r['resource_id']] = r
        return result

    def _get_all_resources(self, run_id: int) -> Dict[str, Dict]:
        """Get all resources (storage + key vaults) for a run."""
        resources = {}
        for table, rtype in [('azure_storage_accounts', 'storage_account'),
                              ('azure_key_vaults', 'key_vault')]:
            for rid, r in self._get_run_resources(run_id, table).items():
                r['resource_type'] = rtype
                resources[rid] = r
        return resources

    def _get_risk_history_depth(self, resource_id: str) -> int:
        """Count how many risk history entries exist for a resource."""
        cursor = self.db.conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM resource_risk_history
            WHERE resource_id = %s
        """, (resource_id,))
        count = cursor.fetchone()[0]
        cursor.close()
        return count

    # ── Anomaly Detectors ────────────────────────────────────

    def _detect_score_spike(self, current_run_id: int,
                            previous_run_id: int,
                            settings: Dict) -> List[Dict]:
        """Detect resources with dramatic risk score increases."""
        threshold = int(settings.get('resource_anomaly_score_spike_threshold', 30))
        anomalies = []

        curr = self._get_all_resources(current_run_id)
        prev = self._get_all_resources(previous_run_id)

        for rid, curr_res in curr.items():
            prev_res = prev.get(rid)
            if not prev_res:
                continue

            old_score = prev_res.get('risk_score', 0) or 0
            new_score = curr_res.get('risk_score', 0) or 0
            delta = new_score - old_score

            if delta >= threshold:
                history_depth = self._get_risk_history_depth(rid)
                confidence = min(history_depth * 30, 95)
                severity = 'critical' if delta >= 50 else 'high'

                anomalies.append({
                    'anomaly_type': 'resource_score_spike',
                    'severity': severity,
                    'identity_id': None,
                    'identity_name': None,
                    'title': f"Risk spike: {curr_res.get('name', rid)}",
                    'description': (
                        f"Risk score jumped from {old_score} to {new_score} (+{delta}) "
                        f"for {curr_res.get('resource_type', 'resource')} '{curr_res.get('name', '')}'."
                    ),
                    'details': {
                        'resource_id': rid,
                        'resource_name': curr_res.get('name', ''),
                        'resource_type': curr_res.get('resource_type', ''),
                        'trigger': f'Score increase of {delta} points exceeds threshold of {threshold}',
                        'baseline': old_score,
                        'deviation': delta,
                        'confidence': confidence,
                        'impact': f"Resource risk elevated from {prev_res.get('risk_level', 'unknown')} to {curr_res.get('risk_level', 'unknown')}",
                        'recommended_action': 'Review recent configuration changes and remediate risk drivers',
                        'old_score': old_score,
                        'new_score': new_score,
                        'old_level': prev_res.get('risk_level', 'info'),
                        'new_level': curr_res.get('risk_level', 'info'),
                    },
                })

        return anomalies

    def _detect_config_drift(self, current_run_id: int,
                             previous_run_id: int,
                             settings: Dict) -> List[Dict]:
        """Detect critical configuration changes between runs."""
        anomalies = []

        # Storage accounts
        curr_sa = self._get_run_resources(current_run_id, 'azure_storage_accounts')
        prev_sa = self._get_run_resources(previous_run_id, 'azure_storage_accounts')

        CRITICAL_CHECKS_SA = [
            ('public_blob_access', False, True, 'Public blob access enabled',
             'Public blob access exposes data to the internet',
             'Disable public blob access immediately'),
            ('shared_key_access', False, True, 'Shared key access re-enabled',
             'Shared key access bypasses Azure AD authentication',
             'Disable shared key access and use Azure AD only'),
            ('https_only', True, False, 'HTTPS enforcement disabled',
             'HTTP traffic allows credential interception',
             'Re-enable HTTPS-only traffic'),
        ]

        for rid, curr_res in curr_sa.items():
            prev_res = prev_sa.get(rid)
            if not prev_res:
                continue

            for field, safe_val, danger_val, title_suffix, impact, action in CRITICAL_CHECKS_SA:
                old_val = prev_res.get(field)
                new_val = curr_res.get(field)
                if old_val == safe_val and new_val == danger_val:
                    anomalies.append({
                        'anomaly_type': 'config_drift_critical',
                        'severity': 'critical',
                        'identity_id': None,
                        'identity_name': None,
                        'title': f"Config drift: {curr_res.get('name', '')} — {title_suffix}",
                        'description': f"{title_suffix} on storage account '{curr_res.get('name', '')}'.",
                        'details': {
                            'resource_id': rid,
                            'resource_name': curr_res.get('name', ''),
                            'resource_type': 'storage_account',
                            'trigger': f'{field} changed from {safe_val} to {danger_val}',
                            'baseline': str(safe_val),
                            'deviation': str(danger_val),
                            'confidence': 100,
                            'impact': impact,
                            'recommended_action': action,
                            'field': field,
                            'old_value': safe_val,
                            'new_value': danger_val,
                        },
                    })

            # TLS downgrade
            old_tls = prev_res.get('minimum_tls_version', 'TLS1_2')
            new_tls = curr_res.get('minimum_tls_version', 'TLS1_2')
            tls_order = {'TLS1_0': 0, 'TLS1_1': 1, 'TLS1_2': 2, 'TLS1_3': 3}
            if tls_order.get(new_tls, 2) < tls_order.get(old_tls, 2):
                anomalies.append({
                    'anomaly_type': 'config_drift_critical',
                    'severity': 'high',
                    'identity_id': None,
                    'identity_name': None,
                    'title': f"TLS downgrade: {curr_res.get('name', '')}",
                    'description': f"TLS version downgraded from {old_tls} to {new_tls}.",
                    'details': {
                        'resource_id': rid,
                        'resource_name': curr_res.get('name', ''),
                        'resource_type': 'storage_account',
                        'trigger': f'TLS downgraded from {old_tls} to {new_tls}',
                        'baseline': old_tls,
                        'deviation': new_tls,
                        'confidence': 100,
                        'impact': 'Weaker TLS allows protocol downgrade attacks',
                        'recommended_action': f'Restore minimum TLS version to {old_tls} or higher',
                    },
                })

        # Key vaults
        curr_kv = self._get_run_resources(current_run_id, 'azure_key_vaults')
        prev_kv = self._get_run_resources(previous_run_id, 'azure_key_vaults')

        CRITICAL_CHECKS_KV = [
            ('soft_delete_enabled', True, False, 'Soft delete disabled',
             'Secrets can be permanently deleted without recovery',
             'Re-enable soft delete on this key vault'),
            ('purge_protection', True, False, 'Purge protection disabled',
             'Soft-deleted secrets can be purged before retention expires',
             'Re-enable purge protection'),
        ]

        for rid, curr_res in curr_kv.items():
            prev_res = prev_kv.get(rid)
            if not prev_res:
                continue

            for field, safe_val, danger_val, title_suffix, impact, action in CRITICAL_CHECKS_KV:
                old_val = prev_res.get(field)
                new_val = curr_res.get(field)
                if old_val == safe_val and new_val == danger_val:
                    anomalies.append({
                        'anomaly_type': 'config_drift_critical',
                        'severity': 'critical',
                        'identity_id': None,
                        'identity_name': None,
                        'title': f"Config drift: {curr_res.get('name', '')} — {title_suffix}",
                        'description': f"{title_suffix} on key vault '{curr_res.get('name', '')}'.",
                        'details': {
                            'resource_id': rid,
                            'resource_name': curr_res.get('name', ''),
                            'resource_type': 'key_vault',
                            'trigger': f'{field} changed from {safe_val} to {danger_val}',
                            'baseline': str(safe_val),
                            'deviation': str(danger_val),
                            'confidence': 100,
                            'impact': impact,
                            'recommended_action': action,
                            'field': field,
                            'old_value': safe_val,
                            'new_value': danger_val,
                        },
                    })

        return anomalies

    def _detect_shadow_infra(self, current_run_id: int,
                             previous_run_id: int) -> List[Dict]:
        """Detect new resources that lack diagnostic logging (shadow infrastructure)."""
        anomalies = []

        curr_sa = self._get_run_resources(current_run_id, 'azure_storage_accounts')
        prev_sa = self._get_run_resources(previous_run_id, 'azure_storage_accounts')

        for rid, curr_res in curr_sa.items():
            if rid in prev_sa:
                continue  # Not new
            if not curr_res.get('diagnostic_logging_enabled'):
                anomalies.append({
                    'anomaly_type': 'shadow_infrastructure',
                    'severity': 'high',
                    'identity_id': None,
                    'identity_name': None,
                    'title': f"Shadow infra: {curr_res.get('name', '')} (no logging)",
                    'description': (
                        f"New storage account '{curr_res.get('name', '')}' discovered "
                        f"without diagnostic logging enabled."
                    ),
                    'details': {
                        'resource_id': rid,
                        'resource_name': curr_res.get('name', ''),
                        'resource_type': 'storage_account',
                        'trigger': 'New resource without diagnostic logging',
                        'baseline': 'Expected: diagnostic logging enabled',
                        'deviation': 'Logging disabled or not configured',
                        'confidence': 90,
                        'impact': 'All data access is unauditable — potential exfiltration cannot be detected',
                        'recommended_action': 'Enable diagnostic settings (StorageRead/Write/Delete) to Log Analytics',
                        'subscription': curr_res.get('subscription_name', ''),
                        'resource_group': curr_res.get('resource_group', ''),
                    },
                })

        # New key vaults (no diagnostic equivalent, but flag if public)
        curr_kv = self._get_run_resources(current_run_id, 'azure_key_vaults')
        prev_kv = self._get_run_resources(previous_run_id, 'azure_key_vaults')

        for rid, curr_res in curr_kv.items():
            if rid in prev_kv:
                continue
            pub = str(curr_res.get('public_network_access', 'Enabled'))
            net = str(curr_res.get('default_network_action', 'Allow'))
            if pub != 'Disabled' and 'Allow' in net:
                anomalies.append({
                    'anomaly_type': 'shadow_infrastructure',
                    'severity': 'high',
                    'identity_id': None,
                    'identity_name': None,
                    'title': f"Shadow infra: {curr_res.get('name', '')} (public vault)",
                    'description': (
                        f"New key vault '{curr_res.get('name', '')}' discovered "
                        f"with public network access and no firewall."
                    ),
                    'details': {
                        'resource_id': rid,
                        'resource_name': curr_res.get('name', ''),
                        'resource_type': 'key_vault',
                        'trigger': 'New key vault with public access and no network restrictions',
                        'baseline': 'Expected: private endpoint or firewall rules',
                        'deviation': 'Public access with Allow-all firewall',
                        'confidence': 90,
                        'impact': 'Secrets accessible from any network — increases attack surface',
                        'recommended_action': 'Configure private endpoints or IP/VNet firewall rules',
                        'subscription': curr_res.get('subscription_name', ''),
                        'resource_group': curr_res.get('resource_group', ''),
                    },
                })

        return anomalies

    def _detect_expiry_cascade(self, current_run_id: int,
                               settings: Dict) -> List[Dict]:
        """Detect key vaults with multiple items expiring in a short window."""
        window_days = int(settings.get('resource_anomaly_expiry_window_days', 7))
        threshold = int(settings.get('resource_anomaly_expiry_threshold', 3))
        anomalies = []

        curr_kv = self._get_run_resources(current_run_id, 'azure_key_vaults')

        for rid, kv in curr_kv.items():
            expiring = (kv.get('secrets_expiring_soon', 0) or 0) + \
                       (kv.get('keys_expiring_soon', 0) or 0) + \
                       (kv.get('certs_expiring_soon', 0) or 0)

            if expiring >= threshold:
                severity = 'critical' if expiring >= threshold * 2 else 'high'
                anomalies.append({
                    'anomaly_type': 'expiry_cascade',
                    'severity': severity,
                    'identity_id': None,
                    'identity_name': None,
                    'title': f"Expiry cascade: {kv.get('name', '')} ({expiring} items)",
                    'description': (
                        f"Key vault '{kv.get('name', '')}' has {expiring} items "
                        f"expiring within 30 days (threshold: {threshold})."
                    ),
                    'details': {
                        'resource_id': rid,
                        'resource_name': kv.get('name', ''),
                        'resource_type': 'key_vault',
                        'trigger': f'{expiring} items expiring soon (threshold: {threshold})',
                        'baseline': f'Expected fewer than {threshold} concurrent expirations',
                        'deviation': f'{expiring} items expiring in window',
                        'confidence': 85,
                        'impact': 'Mass credential rotation needed — service disruption risk',
                        'recommended_action': 'Stagger secret/key/cert rotation schedules and renew immediately',
                        'secrets_expiring': kv.get('secrets_expiring_soon', 0),
                        'keys_expiring': kv.get('keys_expiring_soon', 0),
                        'certs_expiring': kv.get('certs_expiring_soon', 0),
                    },
                })

        return anomalies

    def _detect_privilege_creep(self, current_run_id: int,
                                previous_run_id: int,
                                settings: Dict) -> List[Dict]:
        """Detect resources where privileged identity count grew significantly."""
        pct_threshold = int(settings.get('resource_anomaly_privilege_creep_threshold', 50))
        anomalies = []

        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)

        # Get current and previous privilege counts from risk history
        for run_id, label in [(current_run_id, 'current'), (previous_run_id, 'previous')]:
            pass  # We'll query both in one go

        cursor.execute("""
            SELECT resource_id, resource_type, privileged_identity_count, discovery_run_id
            FROM resource_risk_history
            WHERE discovery_run_id IN (%s, %s)
        """, (current_run_id, previous_run_id))
        rows = cursor.fetchall()
        cursor.close()

        by_resource = {}
        for r in rows:
            rid = r['resource_id']
            by_resource.setdefault(rid, {})
            if r['discovery_run_id'] == current_run_id:
                by_resource[rid]['current'] = r
            else:
                by_resource[rid]['previous'] = r

        for rid, data in by_resource.items():
            curr_data = data.get('current')
            prev_data = data.get('previous')
            if not curr_data or not prev_data:
                continue

            old_count = prev_data.get('privileged_identity_count', 0) or 0
            new_count = curr_data.get('privileged_identity_count', 0) or 0
            abs_delta = new_count - old_count

            if old_count == 0:
                if new_count >= 3:
                    pct_change = 100
                else:
                    continue
            else:
                pct_change = round((abs_delta / old_count) * 100)

            if pct_change >= pct_threshold or abs_delta >= 3:
                history_depth = self._get_risk_history_depth(rid)
                confidence = min(history_depth * 25, 90)
                severity = 'high' if abs_delta >= 5 or pct_change >= 100 else 'medium'

                anomalies.append({
                    'anomaly_type': 'privilege_creep',
                    'severity': severity,
                    'identity_id': None,
                    'identity_name': None,
                    'title': f"Privilege creep: {rid.split('/')[-1]} (+{abs_delta} identities)",
                    'description': (
                        f"Privileged identity count for '{rid.split('/')[-1]}' grew from "
                        f"{old_count} to {new_count} (+{pct_change}%)."
                    ),
                    'details': {
                        'resource_id': rid,
                        'resource_name': rid.split('/')[-1],
                        'resource_type': curr_data.get('resource_type', ''),
                        'trigger': f'Privileged identity count increased by {pct_change}% (+{abs_delta})',
                        'baseline': old_count,
                        'deviation': abs_delta,
                        'confidence': confidence,
                        'impact': 'Expanded blast radius increases compromise impact',
                        'recommended_action': 'Review recent RBAC assignments and remove unnecessary privileges',
                        'old_count': old_count,
                        'new_count': new_count,
                        'pct_change': pct_change,
                    },
                })

        return anomalies

    def _detect_network_change(self, current_run_id: int,
                               previous_run_id: int,
                               settings: Dict) -> List[Dict]:
        """Detect resources where network exposure increased (firewall opened, rules removed)."""
        anomalies = []

        # Storage accounts
        curr_sa = self._get_run_resources(current_run_id, 'azure_storage_accounts')
        prev_sa = self._get_run_resources(previous_run_id, 'azure_storage_accounts')

        for rid, curr_res in curr_sa.items():
            prev_res = prev_sa.get(rid)
            if not prev_res:
                continue

            old_action = str(prev_res.get('default_network_action', 'Allow'))
            new_action = str(curr_res.get('default_network_action', 'Allow'))

            if 'Deny' in old_action and 'Allow' in new_action:
                anomalies.append({
                    'anomaly_type': 'network_exposure_change',
                    'severity': 'critical',
                    'identity_id': None,
                    'identity_name': None,
                    'title': f"Firewall opened: {curr_res.get('name', '')}",
                    'description': (
                        f"Storage account '{curr_res.get('name', '')}' firewall changed "
                        f"from Deny to Allow — all network access now permitted."
                    ),
                    'details': {
                        'resource_id': rid,
                        'resource_name': curr_res.get('name', ''),
                        'resource_type': 'storage_account',
                        'trigger': 'Network default action changed from Deny to Allow',
                        'baseline': 'Deny (restricted)',
                        'deviation': 'Allow (open)',
                        'confidence': 100,
                        'impact': 'Resource exposed to all networks — data exfiltration risk',
                        'recommended_action': 'Restore firewall to Deny and whitelist required IPs/VNets',
                    },
                })

            # IP/VNet rules removed
            old_ip = prev_res.get('ip_rules_count', 0) or 0
            new_ip = curr_res.get('ip_rules_count', 0) or 0
            old_vnet = prev_res.get('vnet_rules_count', 0) or 0
            new_vnet = curr_res.get('vnet_rules_count', 0) or 0

            if (old_ip + old_vnet) > 0 and (new_ip + new_vnet) == 0 and 'Deny' in new_action:
                anomalies.append({
                    'anomaly_type': 'network_exposure_change',
                    'severity': 'high',
                    'identity_id': None,
                    'identity_name': None,
                    'title': f"Network rules removed: {curr_res.get('name', '')}",
                    'description': (
                        f"All IP/VNet rules removed from '{curr_res.get('name', '')}' "
                        f"({old_ip} IP + {old_vnet} VNet rules → 0)."
                    ),
                    'details': {
                        'resource_id': rid,
                        'resource_name': curr_res.get('name', ''),
                        'resource_type': 'storage_account',
                        'trigger': f'All {old_ip + old_vnet} network rules removed',
                        'baseline': f'{old_ip} IP rules + {old_vnet} VNet rules',
                        'deviation': '0 rules remaining',
                        'confidence': 100,
                        'impact': 'No whitelisted networks — may block legitimate access',
                        'recommended_action': 'Re-add required IP/VNet rules or configure private endpoints',
                    },
                })

        # Key vaults
        curr_kv = self._get_run_resources(current_run_id, 'azure_key_vaults')
        prev_kv = self._get_run_resources(previous_run_id, 'azure_key_vaults')

        for rid, curr_res in curr_kv.items():
            prev_res = prev_kv.get(rid)
            if not prev_res:
                continue

            old_pub = str(prev_res.get('public_network_access', 'Enabled'))
            new_pub = str(curr_res.get('public_network_access', 'Enabled'))
            old_action = str(prev_res.get('default_network_action', 'Allow'))
            new_action = str(curr_res.get('default_network_action', 'Allow'))

            # Public access re-enabled
            if old_pub == 'Disabled' and new_pub != 'Disabled':
                anomalies.append({
                    'anomaly_type': 'network_exposure_change',
                    'severity': 'critical',
                    'identity_id': None,
                    'identity_name': None,
                    'title': f"Public access enabled: {curr_res.get('name', '')}",
                    'description': (
                        f"Key vault '{curr_res.get('name', '')}' public network access "
                        f"changed from Disabled to {new_pub}."
                    ),
                    'details': {
                        'resource_id': rid,
                        'resource_name': curr_res.get('name', ''),
                        'resource_type': 'key_vault',
                        'trigger': f'public_network_access changed from Disabled to {new_pub}',
                        'baseline': 'Disabled (private only)',
                        'deviation': f'{new_pub} (network exposed)',
                        'confidence': 100,
                        'impact': 'Secrets exposed to public networks — credential theft risk',
                        'recommended_action': 'Disable public network access and use private endpoints',
                    },
                })

            # Firewall opened
            if 'Deny' in old_action and 'Allow' in new_action:
                anomalies.append({
                    'anomaly_type': 'network_exposure_change',
                    'severity': 'critical',
                    'identity_id': None,
                    'identity_name': None,
                    'title': f"Firewall opened: {curr_res.get('name', '')}",
                    'description': (
                        f"Key vault '{curr_res.get('name', '')}' firewall changed "
                        f"from Deny to Allow."
                    ),
                    'details': {
                        'resource_id': rid,
                        'resource_name': curr_res.get('name', ''),
                        'resource_type': 'key_vault',
                        'trigger': 'Network default action changed from Deny to Allow',
                        'baseline': 'Deny (restricted)',
                        'deviation': 'Allow (open)',
                        'confidence': 100,
                        'impact': 'Vault accessible from all networks',
                        'recommended_action': 'Restore firewall to Deny and whitelist required networks',
                    },
                })

        return anomalies
