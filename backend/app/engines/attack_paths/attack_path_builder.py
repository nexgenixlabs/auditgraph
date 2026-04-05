"""
Attack Path Builder — v1

Constructs identity→role→scope→blast-radius chains from existing
role_assignments + lineage_verdicts + keyvault_metadata tables.

No Azure API calls. Runs after discovery and scoring are complete.
"""
import logging

from app.engines.risk.agirs_engine import classify_role_privilege_tier
from app.engines.scoring.attack_path_scorer import score_attack_path

logger = logging.getLogger(__name__)


class AttackPathBuilder:
    """Builds v1 attack paths for all identities in a connection."""

    def build_paths_for_connection(self, connection_id, db) -> int:
        """Build attack paths for all identities in a connection.

        Called at end of discovery pipeline, after lineage verdicts
        and AGIRS scoring are complete.

        Returns count of paths created.
        """
        identities = db.get_identities_for_path_building(connection_id)
        paths_created = 0
        for identity in identities:
            paths = self._build_paths_for_identity(identity, connection_id, db)
            for path in paths:
                db.save_attack_path(path)
                paths_created += 1
        return paths_created

    def _build_paths_for_identity(self, identity, connection_id, db):
        """Build one attack path per unique (role_tier, scope_level) pair.

        An SPN with Owner at subscription AND Reader at a resource group
        produces 2 separate paths.
        """
        role_assignments = db.get_role_assignments_for_identity(identity['id'])
        if not role_assignments:
            return []

        # Group by (role_tier, scope_level)
        path_groups = {}
        for ra in role_assignments:
            tier = classify_role_privilege_tier(ra)
            scope_level = _parse_scope_level(ra.get('scope', ''))
            key = (tier, scope_level)
            if key not in path_groups:
                path_groups[key] = []
            path_groups[key].append(ra)

        paths = []
        for (tier, scope_level), ras in path_groups.items():
            # Key Vault items for KEY_VAULT tier
            kv_critical = 0
            kv_nodes = []
            if tier == 'KEY_VAULT':
                kv_items = db.get_keyvault_items_by_scope(ras[0].get('scope', ''))
                critical = [i for i in kv_items
                            if i.get('expiry_risk_tier') == 'CRITICAL']
                kv_critical = len(critical)
                kv_nodes = [
                    {
                        'type': 'keyvault_item',
                        'item_name': i.get('item_name'),
                        'item_type': i.get('item_type'),
                        'expiry_risk_tier': i.get('expiry_risk_tier'),
                        'days_until_expiry': i.get('days_until_expiry'),
                    }
                    for i in kv_items[:10]
                ]

            # Build path nodes array
            role_name = (ras[0].get('role_definition_name')
                         or ras[0].get('role_name', 'Unknown'))
            scope_value = ras[0].get('scope', '')

            path_nodes = [
                {
                    'type': 'identity',
                    'id': identity['id'],
                    'label': identity.get('display_name', ''),
                    'identity_type': identity.get('identity_type', ''),
                    'verdict': identity.get('verdict'),
                    'agirs_score': identity.get('agirs_score'),
                },
                {
                    'type': 'role',
                    'label': role_name,
                    'tier': tier,
                    'role_count': len(ras),
                },
                {
                    'type': 'scope',
                    'label': _format_scope_label(scope_value, scope_level),
                    'scope_level': scope_level,
                    'scope_value': scope_value,
                },
                {
                    'type': 'blast_boundary',
                    'label': _format_blast_label(scope_level),
                    'scope_level': scope_level,
                    'resource_count_inferred': True,
                },
            ]

            # Append KV nodes if present
            if kv_nodes:
                path_nodes.append({
                    'type': 'keyvault',
                    'vault_name': _extract_vault_name(scope_value),
                    'critical_items': kv_critical,
                    'items': kv_nodes,
                })

            # Score the path
            score_result = score_attack_path({
                'highest_scope_level': scope_level,
                'role_tier': tier,
                'identity_verdict': identity.get('verdict'),
                'keyvault_critical_items': kv_critical,
                'has_no_owner': identity.get('owner_count', 0) == 0,
            })

            paths.append({
                'connection_id': connection_id,
                'identity_id': identity['id'],
                'source_entity_id': identity.get('identity_id', str(identity['id'])),
                'path_nodes': path_nodes,
                'path_length': len(path_nodes),
                'highest_role': role_name,
                'highest_scope_level': scope_level,
                'path_risk_score': score_result['path_risk_score'],
                'path_risk_tier': score_result['path_risk_tier'],
                'has_keyvault_access': tier == 'KEY_VAULT',
                'has_subscription_scope': scope_level == 'subscription',
                'has_expired_credentials': identity.get(
                    'credentials_expired', False
                ),
                'has_no_owner': identity.get('owner_count', 0) == 0,
                'keyvault_critical_items': kv_critical,
                'identity_verdict': identity.get('verdict'),
                'identity_agirs_score': identity.get('agirs_score'),
            })

        return paths


# ── Scope parsing helpers ────────────────────────────────────────────


def _parse_scope_level(scope: str) -> str:
    """Derive scope level from an ARM scope string.

    /subscriptions/{id}                       → subscription
    /subscriptions/{id}/resourceGroups/{rg}    → resource_group
    deeper                                     → resource
    No /subscriptions/ prefix                  → directory
    """
    if not scope or '/subscriptions/' not in scope:
        return 'directory'
    parts = scope.strip('/').split('/')
    try:
        sub_idx = parts.index('subscriptions')
    except ValueError:
        return 'directory'
    depth = len(parts) - sub_idx
    if depth <= 2:
        return 'subscription'
    elif depth <= 4:
        return 'resource_group'
    return 'resource'


def _format_scope_label(scope: str, level: str) -> str:
    """Human-readable scope label."""
    if level == 'subscription':
        sub_id = scope.split('/subscriptions/')[-1].split('/')[0]
        return f'Subscription: {sub_id[:8]}...'
    elif level == 'resource_group':
        parts = scope.split('/resourceGroups/')
        if len(parts) > 1:
            rg = parts[-1].split('/')[0]
            return f'Resource Group: {rg}'
        return scope.split('/')[-1]
    elif level == 'resource':
        return scope.split('/')[-1]
    return 'Entra Directory'


def _format_blast_label(scope_level: str) -> str:
    """Human-readable blast boundary label."""
    labels = {
        'subscription': (
            'All resource groups and resources '
            'in this subscription'
        ),
        'resource_group': 'All resources in this resource group',
        'resource': 'This specific resource',
        'directory': 'All objects in Entra directory',
    }
    return labels.get(scope_level, 'Unknown blast boundary')


def _extract_vault_name(scope: str) -> str:
    """Extract Key Vault name from an ARM resource ID.

    /subscriptions/.../Microsoft.KeyVault/vaults/my-kv → my-kv
    """
    if '/vaults/' in scope:
        return scope.split('/vaults/')[-1].split('/')[0]
    return ''
