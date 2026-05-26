"""
Resource Scope Extractor — Extract discovered resources from RBAC scopes.

Parses ARM resource IDs from role_assignments.scope to build a canonical
resource inventory without additional Azure API calls. Every resource that
any identity has RBAC access to becomes a discovered_resources row.

Also merges resources from azure_storage_accounts / azure_key_vaults tables
when they have been populated by dedicated discovery.

Provider-to-type normalization map:
  Microsoft.Storage/storageAccounts → storage_account
  Microsoft.KeyVault/vaults → key_vault
  Microsoft.Sql/servers → sql_server
  etc.

High-value classification:
  Key Vaults, SQL databases, Cognitive Services, ML workspaces,
  Synapse, Data Factory, Automation Accounts, Container clusters.
"""

import logging
import re
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════
# ARM Scope Parsing
# ═══════════════════════════════════════════════════════════════════

# Pattern: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}[/child...]
_ARM_RESOURCE_RE = re.compile(
    r'^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/([^/]+/[^/]+)/([^/]+)',
    re.IGNORECASE,
)

_ARM_SUBSCRIPTION_RE = re.compile(
    r'^/subscriptions/([^/]+)$', re.IGNORECASE,
)

_ARM_RG_RE = re.compile(
    r'^/subscriptions/([^/]+)/resourceGroups/([^/]+)$', re.IGNORECASE,
)


def parse_arm_scope(scope: str) -> Optional[Dict]:
    """Parse a full ARM resource ID into components.

    Returns dict with:
        subscription_id, resource_group, provider_type, resource_name, resource_id
    or None if not a resource-level scope.
    """
    if not scope:
        return None

    m = _ARM_RESOURCE_RE.match(scope)
    if m:
        return {
            'subscription_id': m.group(1).lower(),
            'resource_group': m.group(2),
            'provider_type': m.group(3),
            'resource_name': m.group(4),
            'resource_id': scope.lower(),
        }
    return None


# ═══════════════════════════════════════════════════════════════════
# Provider → Normalized Type Map
# ═══════════════════════════════════════════════════════════════════

# Maps ARM provider/type (case-insensitive) → canonical resource_type
PROVIDER_TYPE_MAP: Dict[str, str] = {
    # Tier 1: High-priority
    'microsoft.storage/storageaccounts': 'storage_account',
    'microsoft.keyvault/vaults': 'key_vault',
    'microsoft.sql/servers': 'sql_server',
    'microsoft.sql/managedinstances': 'sql_managed_instance',
    'microsoft.documentdb/databaseaccounts': 'cosmos_db',
    'microsoft.servicebus/namespaces': 'service_bus',
    'microsoft.eventhub/namespaces': 'event_hub',
    'microsoft.web/sites': 'app_service',
    'microsoft.web/serverfarms': 'app_service_plan',
    'microsoft.containerservice/managedclusters': 'aks_cluster',
    'microsoft.app/containerapps': 'container_app',
    'microsoft.compute/virtualmachines': 'virtual_machine',
    'microsoft.compute/virtualmachinescalesets': 'vmss',

    # Tier 2: Medium-priority
    'microsoft.automation/automationaccounts': 'automation_account',
    'microsoft.logic/workflows': 'logic_app',
    'microsoft.logic/integrationaccounts': 'logic_app_integration',
    'microsoft.apimanagement/service': 'api_management',
    'microsoft.databricks/workspaces': 'databricks_workspace',
    'microsoft.synapse/workspaces': 'synapse_workspace',
    'microsoft.machinelearningservices/workspaces': 'ml_workspace',
    'microsoft.cognitiveservices/accounts': 'cognitive_services',
    'microsoft.datafactory/factories': 'data_factory',

    # Tier 3: Supporting infrastructure
    'microsoft.network/virtualnetworks': 'virtual_network',
    'microsoft.network/networkinterfaces': 'network_interface',
    'microsoft.network/dnszones': 'dns_zone',
    'microsoft.cdn/profiles': 'cdn_profile',
    'microsoft.operationalinsights/workspaces': 'log_analytics',
    'microsoft.insights/components': 'app_insights',
    'microsoft.purview/accounts': 'purview',
    'microsoft.search/searchservices': 'search_service',
    'microsoft.desktopvirtualization/applicationgroups': 'avd_app_group',
    'microsoft.compute/disks': 'managed_disk',
    'microsoft.databasewatcher/watchers': 'database_watcher',
    'microsoft.videoindexer/accounts': 'video_indexer',
    'microsoft.apicenter/services': 'api_center',
}

# ═══════════════════════════════════════════════════════════════════
# High-Value Target Classification
# ═══════════════════════════════════════════════════════════════════

# resource_type → (is_high_value, reason)
HIGH_VALUE_TYPES: Dict[str, str] = {
    'key_vault': 'Stores secrets, keys, and certificates',
    'sql_server': 'Database server — may contain sensitive data',
    'sql_managed_instance': 'Managed SQL instance — may contain sensitive data',
    'cosmos_db': 'NoSQL database — may contain application data',
    'cognitive_services': 'AI/ML service with API keys and model access',
    'ml_workspace': 'Machine Learning workspace with training data/models',
    'synapse_workspace': 'Analytics workspace with data lake access',
    'data_factory': 'Data pipeline orchestration — can access multiple data stores',
    'automation_account': 'Can execute scripts with managed identity privileges',
    'aks_cluster': 'Container orchestrator — hosts workloads with elevated access',
    'databricks_workspace': 'Analytics/ML environment with data access',
    'storage_account': 'May contain sensitive blobs/files/queues',
    'purview': 'Data governance — catalogs all organizational data assets',
}


def classify_resource(resource_type: str) -> Tuple[bool, Optional[str]]:
    """Classify a resource as high-value or not.

    Returns (is_high_value, reason_or_None).
    """
    reason = HIGH_VALUE_TYPES.get(resource_type)
    return (reason is not None, reason)


# ═══════════════════════════════════════════════════════════════════
# Main Extraction Engine
# ═══════════════════════════════════════════════════════════════════

class ResourceScopeExtractor:
    """Extract and normalize discovered resources from RBAC scope data.

    Processes role_assignments.scope for a given discovery run, builds a
    canonical resource inventory, and merges with existing resource tables.
    """

    def __init__(self, db):
        self.db = db

    def extract_and_persist(self, run_id: int, organization_id: int) -> Dict:
        """Extract resources from scopes and persist to discovered_resources.

        Args:
            run_id: Discovery run ID
            organization_id: Tenant org ID

        Returns:
            dict with extraction stats
        """
        from psycopg2.extras import RealDictCursor
        from app.constants.roles import PRIVILEGED_RBAC_ROLES

        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)

        # ── Step 1: Load all resource-level role assignments for this run ──
        cursor.execute("""
            SELECT ra.scope, ra.role_name, ra.identity_db_id
            FROM role_assignments ra
            JOIN identities i ON i.id = ra.identity_db_id
            WHERE i.discovery_run_id = %s
              AND ra.scope_type = 'resource'
              AND ra.scope IS NOT NULL
              AND ra.scope != ''
        """, (run_id,))
        role_rows = cursor.fetchall()

        # ── Step 2: Parse scopes into resources ──
        # resource_id_lower → resource dict
        resources: Dict[str, Dict] = {}
        # Track identity exposure per resource
        resource_identities: Dict[str, Set[int]] = {}
        resource_priv_identities: Dict[str, Set[int]] = {}

        for row in role_rows:
            parsed = parse_arm_scope(row['scope'])
            if not parsed:
                continue

            rid = parsed['resource_id']  # already lowercased
            provider_lower = parsed['provider_type'].lower()
            resource_type = PROVIDER_TYPE_MAP.get(provider_lower, 'other')

            if rid not in resources:
                is_hv, hv_reason = classify_resource(resource_type)
                resources[rid] = {
                    'resource_id': rid,
                    'resource_name': parsed['resource_name'],
                    'resource_type': resource_type,
                    'provider_type': parsed['provider_type'],
                    'subscription_id': parsed['subscription_id'],
                    'resource_group': parsed['resource_group'],
                    'is_high_value': is_hv,
                    'high_value_reason': hv_reason,
                    'data_classification': None,
                    'risk_level': None,
                    'discovery_source': 'rbac_scope',
                }

            # Track identity counts
            idb_id = row['identity_db_id']
            resource_identities.setdefault(rid, set()).add(idb_id)
            if row['role_name'] in PRIVILEGED_RBAC_ROLES:
                resource_priv_identities.setdefault(rid, set()).add(idb_id)

        # ── Step 3: Merge with azure_storage_accounts / azure_key_vaults ──
        # These may have richer metadata (data_classification, risk_level)
        for table, rtype in [('azure_storage_accounts', 'storage_account'),
                             ('azure_key_vaults', 'key_vault')]:
            try:
                cursor.execute(f"""
                    SELECT resource_id, name, subscription_id, resource_group,
                           data_classification, risk_level
                    FROM {table}
                    WHERE discovery_run_id = %s
                """, (run_id,))
                for row in cursor.fetchall():
                    rid = (row['resource_id'] or '').lower()
                    if not rid:
                        continue
                    if rid in resources:
                        # Enrich existing entry
                        if row.get('data_classification'):
                            resources[rid]['data_classification'] = row['data_classification']
                        if row.get('risk_level'):
                            resources[rid]['risk_level'] = row['risk_level']
                        resources[rid]['discovery_source'] = f'{rtype}_discovery'
                    else:
                        # Add resource from dedicated table
                        is_hv, hv_reason = classify_resource(rtype)
                        resources[rid] = {
                            'resource_id': rid,
                            'resource_name': row.get('name'),
                            'resource_type': rtype,
                            'provider_type': f'Microsoft.{"Storage/storageAccounts" if rtype == "storage_account" else "KeyVault/vaults"}',
                            'subscription_id': (row.get('subscription_id') or '').lower(),
                            'resource_group': row.get('resource_group'),
                            'is_high_value': is_hv,
                            'high_value_reason': hv_reason,
                            'data_classification': row.get('data_classification'),
                            'risk_level': row.get('risk_level'),
                            'discovery_source': f'{rtype}_discovery',
                        }
            except Exception as e:
                logger.debug("Resource merge from %s failed: %s", table, e)
                try:
                    self.db.conn.rollback()
                except Exception:
                    pass

        # ── Step 4: Persist to discovered_resources ──
        inserted = 0
        for rid, res in resources.items():
            identity_count = len(resource_identities.get(rid, set()))
            priv_count = len(resource_priv_identities.get(rid, set()))
            try:
                cursor.execute("""
                    INSERT INTO discovered_resources (
                        organization_id, resource_id, resource_name,
                        resource_type, provider_type,
                        subscription_id, resource_group,
                        is_high_value, high_value_reason,
                        data_classification, risk_level,
                        identity_count, privileged_identity_count,
                        discovery_source, discovery_run_id
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (organization_id, resource_id, discovery_run_id)
                    DO UPDATE SET
                        resource_name = COALESCE(discovered_resources.resource_name, EXCLUDED.resource_name),
                        resource_type = CASE
                            WHEN discovered_resources.resource_type = 'other' THEN EXCLUDED.resource_type
                            ELSE discovered_resources.resource_type
                        END,
                        is_high_value = EXCLUDED.is_high_value OR discovered_resources.is_high_value,
                        high_value_reason = COALESCE(EXCLUDED.high_value_reason, discovered_resources.high_value_reason),
                        data_classification = COALESCE(EXCLUDED.data_classification, discovered_resources.data_classification),
                        risk_level = COALESCE(EXCLUDED.risk_level, discovered_resources.risk_level),
                        identity_count = EXCLUDED.identity_count,
                        privileged_identity_count = EXCLUDED.privileged_identity_count,
                        discovery_source = CASE
                            WHEN discovered_resources.discovery_source LIKE '%inventory%' THEN 'rbac_scope+inventory'
                            ELSE EXCLUDED.discovery_source
                        END
                """, (
                    organization_id, rid, res['resource_name'],
                    res['resource_type'], res['provider_type'],
                    res['subscription_id'], res['resource_group'],
                    res['is_high_value'], res['high_value_reason'],
                    res['data_classification'], res['risk_level'],
                    identity_count, priv_count,
                    res['discovery_source'], run_id,
                ))
                inserted += 1
            except Exception as e:
                logger.debug("discovered_resources upsert error: %s", e)
                try:
                    self.db.conn.rollback()
                except Exception:
                    pass

        self.db._commit()
        cursor.close()

        # Stats
        type_counts = {}
        hv_count = 0
        for r in resources.values():
            rt = r['resource_type']
            type_counts[rt] = type_counts.get(rt, 0) + 1
            if r['is_high_value']:
                hv_count += 1

        stats = {
            'total_resources': len(resources),
            'inserted': inserted,
            'high_value_count': hv_count,
            'by_type': type_counts,
            'subscriptions': len(set(r['subscription_id'] for r in resources.values() if r.get('subscription_id'))),
            'resource_groups': len(set(r['resource_group'] for r in resources.values() if r.get('resource_group'))),
        }
        logger.info(
            "Resource scope extraction: %d resources (%d high-value) "
            "from %d RBAC scopes (org=%s, run=%s)",
            stats['total_resources'], hv_count, len(role_rows),
            organization_id, run_id,
        )
        return stats
