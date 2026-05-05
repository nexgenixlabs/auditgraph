"""
Resource Inventory Collector — Azure Resource Graph enumeration.

Queries Azure Resource Graph to build an authoritative resource inventory
for all subscriptions accessible via a cloud connection's credentials.
Merges with existing scope-extracted resources (deduplication by resource_id)
and enriches metadata (location, tags, sku, kind, managed_by).

Pipeline placement:
  _run_connection_discovery → ... → _run_resource_inventory → _run_resource_scope_extraction → _run_reachability

Zero-conflict merge strategy:
  - If resource already exists from rbac_scope extraction → enrich metadata
  - If resource is new from inventory → insert with discovery_source='resource_inventory'
  - Dedup key: (organization_id, resource_id, discovery_run_id)
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Azure Resource Graph KQL — enumerate all resources with metadata
_RESOURCE_INVENTORY_KQL = """
Resources
| project id, name, type, resourceGroup, location,
          tags, sku, kind, managedBy, subscriptionId,
          tenantId
| order by type asc, name asc
"""

# Maximum results per Resource Graph query page
_PAGE_SIZE = 1000

# Safety cap — don't enumerate more than this per org
_MAX_RESOURCES = 50000


class ResourceInventoryCollector:
    """Collect full Azure resource inventory via Resource Graph.

    Uses the same ClientSecretCredential as the main discovery engine.
    Produces rows for `discovered_resources` table with enriched metadata.
    """

    def __init__(self, credential, subscription_ids: List[str], db, org_id: int):
        """
        Args:
            credential: azure.identity.ClientSecretCredential instance
            subscription_ids: List of subscription IDs to enumerate
            db: Database instance (with org context)
            org_id: Organization ID
        """
        self.credential = credential
        self.subscription_ids = subscription_ids
        self.db = db
        self.org_id = org_id

    def collect_and_persist(self, run_id: int) -> Dict:
        """Enumerate resources via Resource Graph and persist to discovered_resources.

        Args:
            run_id: Discovery run ID

        Returns:
            dict with collection stats
        """
        try:
            from azure.mgmt.resourcegraph import ResourceGraphClient
            from azure.mgmt.resourcegraph.models import (
                QueryRequest,
                QueryRequestOptions,
                ResultFormat,
            )
        except ImportError:
            logger.warning("azure-mgmt-resourcegraph not installed — skipping inventory collection")
            return {'total_resources': 0, 'error': 'sdk_not_installed'}

        if not self.subscription_ids:
            logger.info("No subscriptions available for resource inventory (org=%s)", self.org_id)
            return {'total_resources': 0, 'skipped': 'no_subscriptions'}

        # Create Resource Graph client
        try:
            rg_client = ResourceGraphClient(
                self.credential,
                connection_timeout=15,
                read_timeout=60,
            )
        except Exception as e:
            logger.error("Failed to create ResourceGraphClient: %s", e)
            return {'total_resources': 0, 'error': str(e)[:200]}

        # Execute paginated KQL query
        all_resources = []
        skip_token = None
        page_count = 0

        while True:
            try:
                options = QueryRequestOptions(
                    result_format=ResultFormat.OBJECT_ARRAY,
                    top=_PAGE_SIZE,
                    skip_token=skip_token,
                )
                request = QueryRequest(
                    subscriptions=self.subscription_ids,
                    query=_RESOURCE_INVENTORY_KQL,
                    options=options,
                )
                response = rg_client.resources(request)

                # Extract data rows
                rows = []
                if hasattr(response, 'data') and response.data:
                    rows = response.data
                elif hasattr(response, 'result_truncated'):
                    # Fallback for different SDK versions
                    rows = getattr(response, 'data', []) or []

                all_resources.extend(rows)
                page_count += 1

                # Check for pagination
                skip_token = getattr(response, 'skip_token', None)
                if not skip_token or len(all_resources) >= _MAX_RESOURCES:
                    break

            except Exception as e:
                logger.warning(
                    "Resource Graph query page %d failed (org=%s): %s",
                    page_count + 1, self.org_id, str(e)[:200]
                )
                break

        if not all_resources:
            logger.info("Resource Graph returned 0 resources (org=%s, subs=%d)",
                       self.org_id, len(self.subscription_ids))
            return {'total_resources': 0, 'pages': page_count}

        # Persist to discovered_resources with metadata enrichment
        stats = self._persist_resources(run_id, all_resources)
        stats['pages'] = page_count

        logger.info(
            "Resource inventory collection: %d resources enumerated, %d persisted "
            "(org=%s, run=%s, subs=%d, pages=%d)",
            len(all_resources), stats.get('persisted', 0),
            self.org_id, run_id, len(self.subscription_ids), page_count,
        )
        return stats

    def _persist_resources(self, run_id: int, raw_resources: List[Dict]) -> Dict:
        """Parse and upsert Resource Graph results into discovered_resources."""
        from psycopg2.extras import RealDictCursor, Json
        from app.engines.resource_scope_extractor import (
            PROVIDER_TYPE_MAP, classify_resource,
        )

        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)

        persisted = 0
        enriched = 0
        skipped = 0
        type_counts: Dict[str, int] = {}
        hv_count = 0

        for raw in raw_resources:
            try:
                resource_id = (raw.get('id') or '').lower()
                if not resource_id:
                    skipped += 1
                    continue

                # Normalize provider type
                raw_type = (raw.get('type') or '').lower()
                resource_type = PROVIDER_TYPE_MAP.get(raw_type, 'other')
                is_hv, hv_reason = classify_resource(resource_type)

                # Extract metadata
                resource_name = raw.get('name')
                resource_group = raw.get('resourceGroup')
                subscription_id = (raw.get('subscriptionId') or '').lower()
                location = raw.get('location')
                tags = raw.get('tags') or {}
                sku_raw = raw.get('sku')
                sku = None
                if isinstance(sku_raw, dict):
                    sku = sku_raw.get('name') or sku_raw.get('tier')
                elif isinstance(sku_raw, str):
                    sku = sku_raw
                kind = raw.get('kind')
                managed_by = raw.get('managedBy')

                # Track stats
                type_counts[resource_type] = type_counts.get(resource_type, 0) + 1
                if is_hv:
                    hv_count += 1

                # Upsert with metadata enrichment
                cursor.execute("""
                    INSERT INTO discovered_resources (
                        organization_id, resource_id, resource_name,
                        resource_type, provider_type,
                        subscription_id, resource_group,
                        is_high_value, high_value_reason,
                        location, tags, sku, kind, managed_by,
                        discovery_source, discovery_run_id,
                        updated_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, NOW()
                    )
                    ON CONFLICT (organization_id, resource_id, discovery_run_id)
                    DO UPDATE SET
                        resource_name = COALESCE(EXCLUDED.resource_name, discovered_resources.resource_name),
                        resource_type = CASE
                            WHEN EXCLUDED.resource_type != 'other' THEN EXCLUDED.resource_type
                            ELSE discovered_resources.resource_type
                        END,
                        provider_type = COALESCE(EXCLUDED.provider_type, discovered_resources.provider_type),
                        is_high_value = EXCLUDED.is_high_value OR discovered_resources.is_high_value,
                        high_value_reason = COALESCE(EXCLUDED.high_value_reason, discovered_resources.high_value_reason),
                        location = COALESCE(EXCLUDED.location, discovered_resources.location),
                        tags = COALESCE(EXCLUDED.tags, discovered_resources.tags),
                        sku = COALESCE(EXCLUDED.sku, discovered_resources.sku),
                        kind = COALESCE(EXCLUDED.kind, discovered_resources.kind),
                        managed_by = COALESCE(EXCLUDED.managed_by, discovered_resources.managed_by),
                        discovery_source = CASE
                            WHEN discovered_resources.discovery_source = 'rbac_scope' THEN 'rbac_scope+inventory'
                            ELSE EXCLUDED.discovery_source
                        END,
                        updated_at = NOW()
                """, (
                    self.org_id, resource_id, resource_name,
                    resource_type, raw_type,
                    subscription_id, resource_group,
                    is_hv, hv_reason,
                    location, Json(tags) if tags else None, sku, kind, managed_by,
                    'resource_inventory', run_id,
                ))
                persisted += 1

            except Exception as e:
                skipped += 1
                logger.debug("Resource inventory upsert error: %s", e)
                try:
                    self.db.conn.rollback()
                except Exception:
                    pass

        # Commit batch
        try:
            self.db._commit()
        except Exception as e:
            logger.error("Resource inventory commit failed: %s", e)
            try:
                self.db.conn.rollback()
            except Exception:
                pass

        cursor.close()

        return {
            'total_resources': len(raw_resources),
            'persisted': persisted,
            'enriched': enriched,
            'skipped': skipped,
            'high_value_count': hv_count,
            'by_type': type_counts,
            'subscriptions': len(set(
                (r.get('subscriptionId') or '').lower()
                for r in raw_resources if r.get('subscriptionId')
            )),
        }
