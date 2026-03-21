"""
Phase 8: Identity Graph Intelligence — BFS Attack Path Engine

Builds an in-memory directed graph from identity, role, and resource data,
then runs BFS traversal to discover privilege escalation paths.

Attack path types discovered:
  - PRIVILEGE_ESCALATION: low-priv identity → privileged role
  - KEYVAULT_SECRET_ACCESS: identity → KeyVault secret access
  - SPN_SECRET_EXPOSURE: identity → SPN with exposed/expired secrets
  - ROLE_CHAINING: identity → intermediate role → elevated privilege

Returns structured paths with risk scoring.
"""

import hashlib
import json
import logging
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Graph constants ───────────────────────────────────────────────────

# Node types
NODE_USER = 'User'
NODE_SERVICE_PRINCIPAL = 'ServicePrincipal'
NODE_MANAGED_IDENTITY = 'ManagedIdentity'
NODE_ROLE = 'Role'
NODE_RESOURCE = 'Resource'
NODE_SUBSCRIPTION = 'Subscription'
NODE_KEYVAULT = 'KeyVault'
# AWS node types
NODE_AWS_ACCOUNT = 'AWSAccount'
NODE_AWS_POLICY = 'AWSPolicy'
# GCP node types
NODE_GCP_PROJECT = 'GCPProject'

ALL_NODE_TYPES = (
    NODE_USER, NODE_SERVICE_PRINCIPAL, NODE_MANAGED_IDENTITY,
    NODE_ROLE, NODE_RESOURCE, NODE_SUBSCRIPTION, NODE_KEYVAULT,
    NODE_AWS_ACCOUNT, NODE_AWS_POLICY, NODE_GCP_PROJECT,
)

# Edge types
EDGE_ASSIGNED_ROLE = 'ASSIGNED_ROLE'
EDGE_HAS_PERMISSION = 'HAS_PERMISSION'
EDGE_CAN_ACCESS = 'CAN_ACCESS'
EDGE_HAS_SECRET = 'HAS_SECRET'
EDGE_CAN_ASSUME = 'CAN_ASSUME'
EDGE_OWNS_RESOURCE = 'OWNS_RESOURCE'
EDGE_CROSS_CLOUD = 'CROSS_CLOUD'

ALL_EDGE_TYPES = (
    EDGE_ASSIGNED_ROLE, EDGE_HAS_PERMISSION, EDGE_CAN_ACCESS,
    EDGE_HAS_SECRET, EDGE_CAN_ASSUME, EDGE_OWNS_RESOURCE,
    EDGE_CROSS_CLOUD,
)

# Privileged roles (targets for escalation) — multi-cloud
PRIVILEGED_ROLES = {
    # Azure
    'Global Administrator': 95,
    'Privileged Role Administrator': 90,
    'Owner': 85,
    'User Access Administrator': 80,
    'Application Administrator': 75,
    'Cloud Application Administrator': 70,
    'Contributor': 60,
    'Key Vault Administrator': 65,
    'Key Vault Secrets Officer': 60,
    # AWS managed policies (stored as role_name in role_assignments)
    'AdministratorAccess': 95,
    'IAMFullAccess': 90,
    'PowerUserAccess': 75,
    # AWS inline markers
    '[inline] AdminPolicy': 90,
    # GCP predefined roles
    'roles/owner': 95,
    'roles/editor': 70,
    'roles/iam.securityAdmin': 85,
    'roles/iam.serviceAccountAdmin': 80,
    'roles/iam.serviceAccountKeyAdmin': 80,
    'roles/resourcemanager.organizationAdmin': 90,
    'roles/resourcemanager.projectIamAdmin': 80,
    'roles/cloudkms.admin': 65,
    'roles/secretmanager.admin': 65,
}

# Low-privilege starting points — multi-cloud
LOW_PRIV_ROLES = {
    # Azure
    'Reader', 'Directory Readers', 'Security Reader',
    'Reports Reader', 'Message Center Reader',
    # AWS
    'SecurityAudit', 'ViewOnlyAccess', 'ReadOnlyAccess',
    # GCP
    'roles/viewer', 'roles/browser',
}

# Finding types
FINDING_PRIVILEGE_ESCALATION = 'PRIVILEGE_ESCALATION'
FINDING_KEYVAULT_SECRET_ACCESS = 'KEYVAULT_SECRET_ACCESS'
FINDING_SPN_SECRET_EXPOSURE = 'SPN_SECRET_EXPOSURE'
FINDING_ROLE_CHAINING = 'ROLE_CHAINING'
FINDING_CROSS_CLOUD_ESCALATION = 'CROSS_CLOUD_ESCALATION'
FINDING_AWS_TRUST_ABUSE = 'AWS_TRUST_ABUSE'
FINDING_GCP_SA_IMPERSONATION = 'GCP_SA_IMPERSONATION'

# Safety limits
MAX_BFS_DEPTH = 6
MAX_PATHS_PER_SOURCE = 10
MAX_TOTAL_PATHS = 3000


class GraphNode:
    """In-memory graph node."""
    __slots__ = ('id', 'node_type', 'name', 'risk_score', 'metadata')

    def __init__(self, node_id: str, node_type: str, name: str,
                 risk_score: int = 0, metadata: dict = None):
        self.id = node_id
        self.node_type = node_type
        self.name = name
        self.risk_score = risk_score
        self.metadata = metadata or {}


class GraphEdge:
    """In-memory graph edge."""
    __slots__ = ('source_id', 'target_id', 'edge_type', 'label', 'metadata')

    def __init__(self, source_id: str, target_id: str, edge_type: str,
                 label: str = '', metadata: dict = None):
        self.source_id = source_id
        self.target_id = target_id
        self.edge_type = edge_type
        self.label = label
        self.metadata = metadata or {}


class IdentityGraph:
    """In-memory directed graph for BFS traversal."""

    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.adjacency: Dict[str, List[Tuple[str, GraphEdge]]] = defaultdict(list)

    def add_node(self, node: GraphNode):
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge):
        self.adjacency[edge.source_id].append((edge.target_id, edge))

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self.nodes.get(node_id)

    def neighbors(self, node_id: str) -> List[Tuple[str, GraphEdge]]:
        return self.adjacency.get(node_id, [])

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return sum(len(v) for v in self.adjacency.values())

    def to_snapshot(self) -> dict:
        """Convert in-memory graph to serializable node/edge dicts for DB persistence.

        Maps internal node types to 5 canonical types:
          User/ServicePrincipal/ManagedIdentity → identity
          Role → role
          Resource/Subscription → resource
          KeyVault → secret
          (Credential nodes via HAS_SECRET edges → credential)

        Maps internal edge types to 4 canonical types:
          ASSIGNED_ROLE → identity_assigned_role
          CAN_ACCESS/HAS_PERMISSION → role_access_resource
          OWNS_RESOURCE/CAN_ASSUME → identity_owns_app
          HAS_SECRET → resource_contains_secret
        """
        NODE_TYPE_MAP = {
            NODE_USER: 'identity',
            NODE_SERVICE_PRINCIPAL: 'identity',
            NODE_MANAGED_IDENTITY: 'identity',
            NODE_ROLE: 'role',
            NODE_RESOURCE: 'resource',
            NODE_SUBSCRIPTION: 'resource',
            NODE_KEYVAULT: 'secret',
            NODE_AWS_ACCOUNT: 'resource',
            NODE_AWS_POLICY: 'role',
            NODE_GCP_PROJECT: 'resource',
        }
        EDGE_TYPE_MAP = {
            EDGE_ASSIGNED_ROLE: 'identity_assigned_role',
            EDGE_CAN_ACCESS: 'role_access_resource',
            EDGE_HAS_PERMISSION: 'role_access_resource',
            EDGE_OWNS_RESOURCE: 'identity_owns_app',
            EDGE_CAN_ASSUME: 'identity_owns_app',
            EDGE_HAS_SECRET: 'resource_contains_secret',
            EDGE_CROSS_CLOUD: 'role_access_resource',
        }

        nodes = []
        for node in self.nodes.values():
            canonical_type = NODE_TYPE_MAP.get(node.node_type, 'resource')
            nodes.append({
                'node_type': canonical_type,
                'external_id': node.id,
                'display_name': node.name,
                'metadata': {
                    'original_type': node.node_type,
                    'risk_score': node.risk_score,
                    **node.metadata,
                },
            })

        edges = []
        for source_id, neighbors in self.adjacency.items():
            src_node = self.nodes.get(source_id)
            if not src_node:
                continue
            src_canonical = NODE_TYPE_MAP.get(src_node.node_type, 'resource')
            for target_id, edge in neighbors:
                tgt_node = self.nodes.get(target_id)
                if not tgt_node:
                    continue
                tgt_canonical = NODE_TYPE_MAP.get(tgt_node.node_type, 'resource')
                canonical_edge = EDGE_TYPE_MAP.get(edge.edge_type, 'role_access_resource')
                edges.append({
                    'source_external_id': source_id,
                    'source_type': src_canonical,
                    'target_external_id': target_id,
                    'target_type': tgt_canonical,
                    'edge_type': canonical_edge,
                    'metadata': {
                        'original_edge_type': edge.edge_type,
                        'label': edge.label,
                        **edge.metadata,
                    },
                })

        return {'nodes': nodes, 'edges': edges}

    def copy(self) -> 'IdentityGraph':
        """Create a shallow copy of this graph for simulation purposes."""
        import copy as _copy
        g = IdentityGraph()
        g.nodes = dict(self.nodes)
        g.adjacency = defaultdict(list)
        for k, v in self.adjacency.items():
            g.adjacency[k] = list(v)
        return g


class GraphAttackEngine:
    """BFS-based attack path discovery engine.

    Builds an in-memory identity graph from DB data, then traverses it
    to find escalation paths from low-privilege identities to high-value targets.
    """

    def __init__(self, db):
        self.db = db
        self.graph = IdentityGraph()

    def analyze(self, org_id: int, run_id: int) -> dict:
        """Main entry: build graph, discover paths, compute risk scores, generate findings."""
        logger.info("GRAPH_ATTACK_START org_id=%d run_id=%d", org_id, run_id)

        # 1. Build in-memory graph
        self._build_graph(org_id, run_id)
        logger.info("GRAPH_BUILT org_id=%d nodes=%d edges=%d",
                    org_id, self.graph.node_count, self.graph.edge_count)

        if self.graph.node_count == 0:
            return {'paths': [], 'risk_scores': [], 'findings': [], 'stats': {}}

        # 2. Discover attack paths via BFS
        paths = self._discover_attack_paths()
        logger.info("GRAPH_PATHS_DISCOVERED org_id=%d paths=%d", org_id, len(paths))

        # 3. Compute per-identity risk scores
        risk_scores = self._compute_risk_scores(org_id, run_id, paths)

        # 4. Generate findings from paths
        findings = self._generate_findings(org_id, run_id, paths)

        stats = {
            'node_count': self.graph.node_count,
            'edge_count': self.graph.edge_count,
            'paths_discovered': len(paths),
            'findings_generated': len(findings),
            'identities_scored': len(risk_scores),
        }
        logger.info("GRAPH_ATTACK_COMPLETE org_id=%d stats=%s", org_id, json.dumps(stats))
        return {
            'paths': paths,
            'risk_scores': risk_scores,
            'findings': findings,
            'stats': stats,
        }

    # ── Graph construction ────────────────────────────────────────────

    def _build_graph(self, org_id: int, run_id: int):
        """Build in-memory graph from discovery data."""
        cursor = self.db.conn.cursor()

        # 1. Identity nodes (all clouds — identities table is cloud-agnostic)
        cursor.execute("""
            SELECT i.id, i.display_name, i.identity_category, i.risk_level, i.risk_score,
                   i.activity_status, i.object_id, COALESCE(i.cloud, 'azure') as cloud,
                   i.tags
            FROM identities i
            WHERE i.discovery_run_id = %s
        """, (run_id,))
        for row in cursor.fetchall():
            iid, name, cat, risk_lvl, risk_sc, activity, oid, cloud, tags = row
            ntype = self._category_to_node_type(cat)
            # Parse tags JSON
            identity_tags = {}
            if tags:
                if isinstance(tags, str):
                    try:
                        identity_tags = json.loads(tags)
                    except Exception:
                        pass
                elif isinstance(tags, dict):
                    identity_tags = tags
            self.graph.add_node(GraphNode(
                f'identity:{iid}', ntype, name or f'Identity-{iid}',
                risk_score=risk_sc or 0,
                metadata={'identity_id': iid, 'category': cat,
                          'risk_level': risk_lvl, 'activity': activity,
                          'object_id': oid, 'cloud': cloud, 'tags': identity_tags},
            ))

        # 2. Role assignments → Role nodes + ASSIGNED_ROLE edges
        cursor.execute("""
            SELECT ra.identity_db_id, ra.role_name, ra.scope, ra.scope_type, ra.risk_level
            FROM role_assignments ra
            JOIN identities i ON i.id = ra.identity_db_id
            WHERE i.discovery_run_id = %s
        """, (run_id,))
        seen_roles = set()
        for row in cursor.fetchall():
            iid, role_name, scope, scope_type, risk_lvl = row
            role_key = f'role:{role_name}'
            if role_key not in seen_roles:
                priv_score = PRIVILEGED_ROLES.get(role_name, 10)
                self.graph.add_node(GraphNode(
                    role_key, NODE_ROLE, role_name,
                    risk_score=priv_score,
                    metadata={'privileged': role_name in PRIVILEGED_ROLES},
                ))
                seen_roles.add(role_key)

            self.graph.add_edge(GraphEdge(
                f'identity:{iid}', role_key, EDGE_ASSIGNED_ROLE,
                label=role_name,
                metadata={'scope': scope, 'scope_type': scope_type, 'risk_level': risk_lvl},
            ))

            # Role → Subscription edge if subscription-scoped
            if scope and '/subscriptions/' in scope:
                sub_id = scope.split('/subscriptions/')[1].split('/')[0]
                sub_key = f'subscription:{sub_id}'
                if sub_key not in self.graph.nodes:
                    self.graph.add_node(GraphNode(
                        sub_key, NODE_SUBSCRIPTION, f'Sub-{sub_id[:8]}',
                        metadata={'subscription_id': sub_id},
                    ))
                self.graph.add_edge(GraphEdge(
                    role_key, sub_key, EDGE_CAN_ACCESS,
                    label=f'{role_name} on subscription',
                ))

        # 3. Entra role assignments
        cursor.execute("""
            SELECT era.identity_db_id, era.role_name, era.directory_scope, era.risk_level
            FROM entra_role_assignments era
            JOIN identities i ON i.id = era.identity_db_id
            WHERE i.discovery_run_id = %s
        """, (run_id,))
        for row in cursor.fetchall():
            iid, role_name, directory_scope, risk_lvl = row
            role_key = f'role:{role_name}'
            if role_key not in seen_roles:
                priv_score = PRIVILEGED_ROLES.get(role_name, 10)
                self.graph.add_node(GraphNode(
                    role_key, NODE_ROLE, role_name,
                    risk_score=priv_score,
                    metadata={'privileged': role_name in PRIVILEGED_ROLES, 'entra': True},
                ))
                seen_roles.add(role_key)
            self.graph.add_edge(GraphEdge(
                f'identity:{iid}', role_key, EDGE_ASSIGNED_ROLE,
                label=role_name,
                metadata={'entra': True, 'scope_label': directory_scope, 'risk_level': risk_lvl},
            ))

        # 4. Key Vaults → KEYVAULT nodes + CAN_ACCESS edges from identities with KV roles
        try:
            cursor.execute("""
                SELECT kv.id, kv.vault_name, kv.subscription_id, kv.risk_level
                FROM azure_key_vaults kv
                WHERE kv.discovery_run_id = %s
            """, (run_id,))
            for row in cursor.fetchall():
                kvid, name, sub_id, risk_lvl = row
                kv_key = f'keyvault:{kvid}'
                self.graph.add_node(GraphNode(
                    kv_key, NODE_KEYVAULT, name or f'KV-{kvid}',
                    metadata={'vault_id': kvid, 'subscription_id': sub_id,
                              'risk_level': risk_lvl},
                ))
                # Link KV roles to vault
                for kv_role in ('Key Vault Administrator', 'Key Vault Secrets Officer',
                                'Key Vault Secrets User', 'Key Vault Crypto Officer'):
                    kv_role_key = f'role:{kv_role}'
                    if kv_role_key in self.graph.nodes:
                        self.graph.add_edge(GraphEdge(
                            kv_role_key, kv_key, EDGE_HAS_SECRET,
                            label=f'{kv_role} → {name}',
                        ))
        except Exception:
            self.db.conn.rollback()  # reset transaction state

        # 5. Identity ownership (identity owns SPN) → CAN_ASSUME edges
        try:
            cursor.execute("""
                SELECT i.id AS owner_id, i2.id AS owned_id, i2.display_name
                FROM identities i
                JOIN app_registrations ar ON ar.discovery_run_id = %s
                JOIN identities i2 ON i2.discovery_run_id = %s
                    AND i2.identity_category = 'service_principal'
                    AND i2.app_id = ar.app_id
                WHERE i.discovery_run_id = %s
                  AND i.object_id = ANY(
                      SELECT jsonb_array_elements_text(ar.owner_ids)
                  )
            """, (run_id, run_id, run_id))
            for row in cursor.fetchall():
                owner_id, owned_id, owned_name = row
                self.graph.add_edge(GraphEdge(
                    f'identity:{owner_id}', f'identity:{owned_id}',
                    EDGE_CAN_ASSUME,
                    label=f'Owns SPN: {owned_name}',
                ))
        except Exception:
            self.db.conn.rollback()  # reset transaction state

        # 6. Credential exposure → HAS_SECRET edges
        try:
            cursor.execute("""
                SELECT i.id, i.display_name, i.credential_count, i.expired_credential_count
                FROM identities i
                WHERE i.discovery_run_id = %s
                  AND i.identity_category = 'service_principal'
                  AND (i.credential_count > 0 OR i.expired_credential_count > 0)
            """, (run_id,))
            for row in cursor.fetchall():
                iid, name, cred_count, expired_count = row
                secret_key = f'secret:{iid}'
                self.graph.add_node(GraphNode(
                    secret_key, NODE_RESOURCE, f'Secrets({name})',
                    risk_score=40 if (expired_count or 0) > 0 else 10,
                    metadata={'identity_id': iid, 'credential_count': cred_count,
                              'expired_count': expired_count},
                ))
                self.graph.add_edge(GraphEdge(
                    f'identity:{iid}', secret_key, EDGE_HAS_SECRET,
                    label=f'{cred_count} credentials' + (f' ({expired_count} expired)' if expired_count else ''),
                ))
        except Exception:
            self.db.conn.rollback()  # reset transaction state

        # 7. AWS cross-account trust → CAN_ASSUME edges
        #    AWS roles with cross-account or wildcard trust allow external assumption
        try:
            for nid, node in self.graph.nodes.items():
                if not nid.startswith('identity:'):
                    continue
                tags = node.metadata.get('tags', {})
                cloud = node.metadata.get('cloud')
                if cloud != 'aws':
                    continue
                cat = node.metadata.get('category', '')
                if cat not in ('iam_role', 'iam_service_linked_role'):
                    continue

                # Cross-account trust: any identity in another account can assume
                if tags.get('is_cross_account') or tags.get('is_wildcard_trust'):
                    for other_id, other_node in self.graph.nodes.items():
                        if not other_id.startswith('identity:'):
                            continue
                        if other_id == nid:
                            continue
                        other_cloud = other_node.metadata.get('cloud')
                        # Cross-cloud: Azure/GCP identity → AWS role via trust
                        if other_cloud != 'aws' or tags.get('is_cross_account'):
                            self.graph.add_edge(GraphEdge(
                                other_id, nid, EDGE_CAN_ASSUME,
                                label=f'Cross-{"cloud" if other_cloud != "aws" else "account"} trust: {node.name}',
                                metadata={'cross_cloud': other_cloud != 'aws',
                                          'source_cloud': other_cloud, 'target_cloud': 'aws'},
                            ))
                            # Limit fan-out per target role
                            break
        except Exception:
            pass

        # 8. GCP service account impersonation edges
        #    Identities with iam.serviceAccounts.actAs can impersonate SAs
        try:
            for nid, node in self.graph.nodes.items():
                if not nid.startswith('identity:'):
                    continue
                if node.metadata.get('cloud') != 'gcp':
                    continue
                cat = node.metadata.get('category', '')
                if cat != 'gcp_service_account':
                    continue
                # Check if any identity has actAs permission via a privileged role
                for other_id, other_node in self.graph.nodes.items():
                    if not other_id.startswith('identity:') or other_id == nid:
                        continue
                    # Check role edges from other_node
                    for target_id, edge in self.graph.neighbors(other_id):
                        target = self.graph.get_node(target_id)
                        if (target and target.node_type == NODE_ROLE
                                and target.name in ('roles/iam.serviceAccountAdmin',
                                                    'roles/iam.serviceAccountKeyAdmin',
                                                    'roles/owner', 'roles/editor')):
                            self.graph.add_edge(GraphEdge(
                                other_id, nid, EDGE_CAN_ASSUME,
                                label=f'Can impersonate SA: {node.name} via {target.name}',
                                metadata={'cross_cloud': other_node.metadata.get('cloud') != 'gcp',
                                          'source_cloud': other_node.metadata.get('cloud'),
                                          'target_cloud': 'gcp'},
                            ))
                            break  # One edge per pair
        except Exception:
            pass

        # 9. Cross-cloud secret exposure: Azure KV secrets containing AWS access keys
        #    If an Azure identity can access a KeyVault, and that vault could store
        #    AWS credentials, create a cross-cloud edge to AWS roles
        try:
            aws_identity_ids = [
                nid for nid, n in self.graph.nodes.items()
                if nid.startswith('identity:') and n.metadata.get('cloud') == 'aws'
                and n.metadata.get('category') in ('iam_user', 'iam_role')
            ]
            kv_ids = [nid for nid, n in self.graph.nodes.items()
                      if n.node_type == NODE_KEYVAULT]

            if aws_identity_ids and kv_ids:
                # For each KV, link it to one AWS identity (representing potential
                # stored AWS credentials)
                for kv_id in kv_ids:
                    if aws_identity_ids:
                        self.graph.add_edge(GraphEdge(
                            kv_id, aws_identity_ids[0], EDGE_CROSS_CLOUD,
                            label='Potential stored AWS credentials',
                            metadata={'cross_cloud': True, 'source_cloud': 'azure',
                                      'target_cloud': 'aws'},
                        ))
        except Exception:
            pass

        cursor.close()

    # ── BFS attack path discovery ─────────────────────────────────────

    def _discover_attack_paths(self) -> List[dict]:
        """Run BFS from each low-privilege identity to discover escalation paths."""
        paths = []

        # Find source identities (low privilege or no privileged roles)
        source_ids = []
        for nid, node in self.graph.nodes.items():
            if node.node_type in (NODE_USER, NODE_SERVICE_PRINCIPAL, NODE_MANAGED_IDENTITY):
                # Check if this identity has only low-priv or no privileged roles
                has_priv = False
                for target_id, edge in self.graph.neighbors(nid):
                    target = self.graph.get_node(target_id)
                    if target and target.node_type == NODE_ROLE and target.metadata.get('privileged'):
                        has_priv = True
                        break
                if not has_priv:
                    source_ids.append(nid)

        # Also include all identities for KeyVault and SPN exposure paths
        all_identity_ids = [
            nid for nid, n in self.graph.nodes.items()
            if n.node_type in (NODE_USER, NODE_SERVICE_PRINCIPAL, NODE_MANAGED_IDENTITY)
        ]

        # BFS: low-priv → privileged roles
        for src_id in source_ids:
            src_paths = self._bfs_to_targets(
                src_id, lambda n: n.node_type == NODE_ROLE and n.metadata.get('privileged'),
                FINDING_PRIVILEGE_ESCALATION,
            )
            paths.extend(src_paths)
            if len(paths) >= MAX_TOTAL_PATHS:
                break

        # BFS: any identity → KeyVault
        if len(paths) < MAX_TOTAL_PATHS:
            for src_id in all_identity_ids:
                kv_paths = self._bfs_to_targets(
                    src_id, lambda n: n.node_type == NODE_KEYVAULT,
                    FINDING_KEYVAULT_SECRET_ACCESS,
                )
                paths.extend(kv_paths)
                if len(paths) >= MAX_TOTAL_PATHS:
                    break

        # Direct: SPN secret exposure
        if len(paths) < MAX_TOTAL_PATHS:
            for nid, node in self.graph.nodes.items():
                if node.node_type == NODE_RESOURCE and node.metadata.get('expired_count', 0) > 0:
                    identity_id = node.metadata.get('identity_id')
                    if identity_id:
                        src_key = f'identity:{identity_id}'
                        src = self.graph.get_node(src_key)
                        if src:
                            paths.append({
                                'source_identity': src_key,
                                'source_name': src.name,
                                'source_type': src.node_type,
                                'target_privilege': node.name,
                                'target_type': NODE_RESOURCE,
                                'finding_type': FINDING_SPN_SECRET_EXPOSURE,
                                'attack_path_nodes': [
                                    {'id': src_key, 'type': src.node_type, 'name': src.name},
                                    {'id': nid, 'type': node.node_type, 'name': node.name},
                                ],
                                'attack_path_edges': [
                                    {'source': src_key, 'target': nid, 'type': EDGE_HAS_SECRET},
                                ],
                                'risk_score': min(100, 40 + node.metadata.get('expired_count', 0) * 10),
                                'severity': 'high',
                                'depth': 1,
                            })

        # BFS: role chaining (identity → role → another role via intermediate)
        if len(paths) < MAX_TOTAL_PATHS:
            for src_id in source_ids[:200]:  # Limit for performance
                chain_paths = self._bfs_to_targets(
                    src_id,
                    lambda n: n.node_type == NODE_ROLE and n.risk_score >= 60,
                    FINDING_ROLE_CHAINING,
                    min_depth=3,  # Must go through intermediate nodes
                )
                paths.extend(chain_paths)
                if len(paths) >= MAX_TOTAL_PATHS:
                    break

        # BFS: cross-cloud escalation (identity in one cloud → privilege in another)
        if len(paths) < MAX_TOTAL_PATHS:
            for src_id in all_identity_ids[:300]:
                src_node = self.graph.get_node(src_id)
                if not src_node:
                    continue
                src_cloud = src_node.metadata.get('cloud', 'azure')

                cross_paths = self._bfs_to_targets(
                    src_id,
                    lambda n, _src_cloud=src_cloud: (
                        n.node_type in (NODE_ROLE, NODE_SERVICE_PRINCIPAL)
                        and n.metadata.get('cloud', 'azure') != _src_cloud
                        and n.risk_score >= 60
                    ),
                    FINDING_CROSS_CLOUD_ESCALATION,
                    min_depth=2,
                )
                paths.extend(cross_paths)
                if len(paths) >= MAX_TOTAL_PATHS:
                    break

        # AWS trust abuse: wildcard/cross-account trust → privileged role
        if len(paths) < MAX_TOTAL_PATHS:
            aws_role_ids = [
                nid for nid, n in self.graph.nodes.items()
                if nid.startswith('identity:') and n.metadata.get('cloud') == 'aws'
                and n.metadata.get('category') in ('iam_role',)
                and (n.metadata.get('tags', {}).get('is_wildcard_trust')
                     or n.metadata.get('tags', {}).get('is_cross_account'))
            ]
            for role_id in aws_role_ids[:100]:
                role_node = self.graph.get_node(role_id)
                if not role_node:
                    continue
                # Check if this role has privileged policies
                for target_id, edge in self.graph.neighbors(role_id):
                    target = self.graph.get_node(target_id)
                    if target and target.node_type == NODE_ROLE and target.metadata.get('privileged'):
                        paths.append({
                            'source_identity': role_id,
                            'source_name': role_node.name,
                            'source_type': role_node.node_type,
                            'target_privilege': target.name,
                            'target_type': target.node_type,
                            'finding_type': FINDING_AWS_TRUST_ABUSE,
                            'attack_path_nodes': [
                                {'id': role_id, 'type': role_node.node_type, 'name': role_node.name,
                                 'cloud': 'aws'},
                                {'id': target_id, 'type': target.node_type, 'name': target.name,
                                 'cloud': 'aws'},
                            ],
                            'attack_path_edges': [
                                {'source': role_id, 'target': target_id,
                                 'type': EDGE_ASSIGNED_ROLE, 'label': edge.label},
                            ],
                            'risk_score': min(100, 50 + target.risk_score),
                            'severity': 'critical' if target.risk_score >= 80 else 'high',
                            'depth': 1,
                        })
                if len(paths) >= MAX_TOTAL_PATHS:
                    break

        return paths[:MAX_TOTAL_PATHS]

    def _bfs_to_targets(self, source_id: str, target_predicate,
                        finding_type: str, min_depth: int = 2) -> List[dict]:
        """BFS from source to nodes matching target_predicate.

        Returns list of attack path dicts.
        """
        source = self.graph.get_node(source_id)
        if not source:
            return []

        paths_found = []
        # BFS state: (current_node_id, path_nodes, path_edges, depth)
        queue = deque([(source_id, [{'id': source_id, 'type': source.node_type, 'name': source.name, 'cloud': source.metadata.get('cloud', 'azure')}], [], 0)])
        visited = {source_id}

        while queue and len(paths_found) < MAX_PATHS_PER_SOURCE:
            current_id, path_nodes, path_edges, depth = queue.popleft()

            if depth >= MAX_BFS_DEPTH:
                continue

            for neighbor_id, edge in self.graph.neighbors(current_id):
                if neighbor_id in visited:
                    continue

                neighbor = self.graph.get_node(neighbor_id)
                if not neighbor:
                    continue

                new_nodes = path_nodes + [{'id': neighbor_id, 'type': neighbor.node_type, 'name': neighbor.name, 'cloud': neighbor.metadata.get('cloud', 'azure')}]
                new_edges = path_edges + [{'source': current_id, 'target': neighbor_id, 'type': edge.edge_type, 'label': edge.label}]
                new_depth = depth + 1

                # Check if target reached
                if target_predicate(neighbor) and new_depth >= min_depth:
                    risk = self._compute_path_risk(new_nodes, new_edges)
                    severity = 'critical' if risk >= 80 else 'high' if risk >= 60 else 'medium'
                    paths_found.append({
                        'source_identity': source_id,
                        'source_name': source.name,
                        'source_type': source.node_type,
                        'target_privilege': neighbor.name,
                        'target_type': neighbor.node_type,
                        'finding_type': finding_type,
                        'attack_path_nodes': new_nodes,
                        'attack_path_edges': new_edges,
                        'risk_score': risk,
                        'severity': severity,
                        'depth': new_depth,
                    })
                    continue  # Don't continue past target

                visited.add(neighbor_id)
                queue.append((neighbor_id, new_nodes, new_edges, new_depth))

        return paths_found

    def _compute_path_risk(self, nodes: list, edges: list) -> int:
        """Compute risk score for an attack path."""
        score = 0
        for node_dict in nodes:
            node = self.graph.get_node(node_dict['id'])
            if node:
                score += node.risk_score * 0.3
        # Shorter paths = higher risk (more direct escalation)
        depth_factor = max(0.5, 1.0 - (len(nodes) - 2) * 0.1)
        score *= depth_factor
        # Privileged target boost
        target = self.graph.get_node(nodes[-1]['id']) if nodes else None
        if target and target.metadata.get('privileged'):
            score += PRIVILEGED_ROLES.get(target.name, 20)
        return max(0, min(100, int(score)))

    # ── Identity risk scoring ─────────────────────────────────────────

    def _compute_risk_scores(self, org_id: int, run_id: int,
                             paths: list) -> List[dict]:
        """Compute per-identity risk scores based on graph analysis."""
        identity_scores = {}

        # Base: collect all identity nodes
        for nid, node in self.graph.nodes.items():
            if node.node_type not in (NODE_USER, NODE_SERVICE_PRINCIPAL, NODE_MANAGED_IDENTITY):
                continue
            identity_id = node.metadata.get('identity_id')
            if not identity_id:
                continue

            # Factor 1: privileged role count
            priv_roles = 0
            owner_roles = 0
            total_roles = 0
            for target_id, edge in self.graph.neighbors(nid):
                target = self.graph.get_node(target_id)
                if target and target.node_type == NODE_ROLE:
                    total_roles += 1
                    if target.metadata.get('privileged'):
                        priv_roles += 1
                    if target.name == 'Owner':
                        owner_roles += 1

            # Factor 2: credential exposure
            cred_exposure = 0
            for target_id, edge in self.graph.neighbors(nid):
                if edge.edge_type == EDGE_HAS_SECRET:
                    target = self.graph.get_node(target_id)
                    if target and target.metadata.get('expired_count', 0) > 0:
                        cred_exposure += 20
                    else:
                        cred_exposure += 5

            # Factor 3: attack paths from this identity
            path_risk = 0
            path_count = 0
            for p in paths:
                if p['source_identity'] == nid:
                    path_count += 1
                    path_risk = max(path_risk, p['risk_score'])

            # Factor 4: secret age (from metadata)
            activity = node.metadata.get('activity', 'active')
            dormancy_penalty = 15 if activity in ('stale', 'inactive') else 0

            # Composite score
            score = min(100, (
                priv_roles * 15 +
                owner_roles * 10 +
                cred_exposure +
                path_risk * 0.3 +
                path_count * 5 +
                dormancy_penalty
            ))

            identity_scores[identity_id] = {
                'identity_id': identity_id,
                'identity_name': node.name,
                'identity_type': (node.node_type or 'service_principal').lower().strip(),
                'organization_id': org_id,
                'discovery_run_id': run_id,
                'risk_score': int(score),
                'factors': {
                    'privileged_roles': priv_roles,
                    'owner_roles': owner_roles,
                    'total_roles': total_roles,
                    'credential_exposure': cred_exposure,
                    'attack_paths': path_count,
                    'max_path_risk': path_risk,
                    'dormancy_penalty': dormancy_penalty,
                },
            }

        return list(identity_scores.values())

    # ── Finding generation ────────────────────────────────────────────

    def _generate_findings(self, org_id: int, run_id: int,
                           paths: list) -> List[dict]:
        """Generate attack path findings from discovered paths."""
        findings = []
        seen_fingerprints = set()

        for path in paths:
            # Fingerprint for deduplication
            fp_data = f"{path['source_identity']}:{path['finding_type']}:{path['target_privilege']}"
            fp = hashlib.sha256(fp_data.encode()).hexdigest()[:32]
            if fp in seen_fingerprints:
                continue
            seen_fingerprints.add(fp)

            source = self.graph.get_node(path['source_identity'])
            source_identity_id = source.metadata.get('identity_id') if source else None

            finding = {
                'organization_id': org_id,
                'identity_id': source_identity_id,
                'finding_type': path['finding_type'],
                'severity': path['severity'],
                'risk_score': path['risk_score'],
                'title': self._finding_title(path),
                'description': self._finding_description(path),
                'attack_path': {
                    'nodes': path['attack_path_nodes'],
                    'edges': path['attack_path_edges'],
                    'depth': path['depth'],
                },
                'remediation': self._finding_remediation(path),
                'discovery_run_id': run_id,
                'fingerprint': fp,
            }
            findings.append(finding)

        return findings

    def _finding_title(self, path: dict) -> str:
        titles = {
            FINDING_PRIVILEGE_ESCALATION: f"Privilege escalation path: {path['source_name']} → {path['target_privilege']}",
            FINDING_KEYVAULT_SECRET_ACCESS: f"KeyVault secret access: {path['source_name']} → {path['target_privilege']}",
            FINDING_SPN_SECRET_EXPOSURE: f"SPN secret exposure: {path['source_name']}",
            FINDING_ROLE_CHAINING: f"Role chaining: {path['source_name']} → {path['target_privilege']}",
            FINDING_CROSS_CLOUD_ESCALATION: f"Cross-cloud escalation: {path['source_name']} → {path['target_privilege']}",
            FINDING_AWS_TRUST_ABUSE: f"AWS trust abuse: {path['source_name']} → {path['target_privilege']}",
            FINDING_GCP_SA_IMPERSONATION: f"GCP SA impersonation: {path['source_name']} → {path['target_privilege']}",
        }
        return titles.get(path['finding_type'], f"Attack path: {path['source_name']}")

    def _finding_description(self, path: dict) -> str:
        depth = path.get('depth', len(path['attack_path_nodes']) - 1)
        descs = {
            FINDING_PRIVILEGE_ESCALATION: (
                f"Identity '{path['source_name']}' can escalate to '{path['target_privilege']}' "
                f"through a {depth}-step path. This grants elevated access that may not be intended."
            ),
            FINDING_KEYVAULT_SECRET_ACCESS: (
                f"Identity '{path['source_name']}' can reach KeyVault '{path['target_privilege']}' "
                f"through a {depth}-step path, potentially accessing stored secrets and certificates."
            ),
            FINDING_SPN_SECRET_EXPOSURE: (
                f"Service principal '{path['source_name']}' has exposed or expired credentials. "
                f"Expired secrets indicate poor credential hygiene and potential unauthorized access."
            ),
            FINDING_ROLE_CHAINING: (
                f"Identity '{path['source_name']}' can chain through intermediate roles to reach "
                f"'{path['target_privilege']}' in {depth} steps. This indirect path may bypass access controls."
            ),
            FINDING_CROSS_CLOUD_ESCALATION: (
                f"Identity '{path['source_name']}' can escalate privileges across cloud boundaries to reach "
                f"'{path['target_privilege']}' in {depth} steps. Cross-cloud paths are high-risk because they "
                f"span separate security domains."
            ),
            FINDING_AWS_TRUST_ABUSE: (
                f"AWS IAM role '{path['source_name']}' has a trust policy that allows external assumption, "
                f"leading to '{path['target_privilege']}'. Wildcard or cross-account trust enables lateral "
                f"movement from compromised accounts."
            ),
            FINDING_GCP_SA_IMPERSONATION: (
                f"Identity '{path['source_name']}' can impersonate GCP service account to reach "
                f"'{path['target_privilege']}'. Service account impersonation via actAs permission "
                f"bypasses normal access controls."
            ),
        }
        return descs.get(path['finding_type'], f"Attack path from {path['source_name']}")

    def _finding_remediation(self, path: dict) -> str:
        recs = {
            FINDING_PRIVILEGE_ESCALATION: "Remove unnecessary role assignments along the escalation path. Apply least-privilege by scoping roles to specific resources.",
            FINDING_KEYVAULT_SECRET_ACCESS: "Review KeyVault access policies. Remove unnecessary role assignments. Enable RBAC authorization mode on the vault.",
            FINDING_SPN_SECRET_EXPOSURE: "Rotate expired credentials immediately. Set up automated credential rotation. Consider using managed identities instead.",
            FINDING_ROLE_CHAINING: "Break the role chain by removing intermediate role assignments. Apply PIM for just-in-time access to privileged roles.",
            FINDING_CROSS_CLOUD_ESCALATION: "Eliminate cross-cloud privilege paths by removing stored credentials from accessible vaults. Use federated identity (OIDC) instead of static keys. Apply conditional access policies that restrict cross-cloud operations.",
            FINDING_AWS_TRUST_ABUSE: "Restrict the IAM role's trust policy to specific accounts and principals. Remove wildcard (*) trust. Add ExternalId conditions. Enable CloudTrail logging for AssumeRole events.",
            FINDING_GCP_SA_IMPERSONATION: "Remove iam.serviceAccounts.actAs permission from non-essential identities. Use Workload Identity Federation instead of service account keys. Apply VPC Service Controls.",
        }
        return recs.get(path['finding_type'], "Review and tighten access controls.")

    # ── Blast Radius & Escalation ─────────────────────────────────────

    def compute_blast_radius(self, identity_id: str) -> dict:
        """BFS from identity node through role→resource edges.

        Returns reachable resources, secrets, and a 0-100 blast radius score.
        Scoring: subscriptions×15 + resource_groups×5 + resources×2 + secrets×10, cap 100.
        """
        # Find identity node (try prefixed and raw)
        start_id = identity_id if identity_id in self.graph.nodes else f'identity:{identity_id}'
        source = self.graph.get_node(start_id)
        if not source:
            return {
                'identity_id': identity_id,
                'reachable_resources': [], 'reachable_secrets': [],
                'blast_radius_score': 0, 'subscription_count': 0,
                'resource_group_count': 0, 'resource_count': 0,
                'secret_count': 0, 'max_depth': 0,
            }

        visited = {start_id}
        queue = deque([(start_id, 0, None)])  # (node_id, depth, via_role)
        reachable_resources = []
        reachable_secrets = []
        subscriptions = set()
        resource_groups = set()
        max_depth = 0

        while queue:
            current_id, depth, via_role = queue.popleft()
            if depth > MAX_BFS_DEPTH:
                continue

            for neighbor_id, edge in self.graph.neighbors(current_id):
                if neighbor_id in visited:
                    continue
                visited.add(neighbor_id)
                neighbor = self.graph.get_node(neighbor_id)
                if not neighbor:
                    continue

                new_depth = depth + 1
                max_depth = max(max_depth, new_depth)
                current_via = via_role

                # Track via_role for resource attribution
                if neighbor.node_type == NODE_ROLE:
                    current_via = neighbor.name

                if neighbor.node_type in (NODE_RESOURCE, NODE_SUBSCRIPTION, NODE_AWS_ACCOUNT, NODE_GCP_PROJECT):
                    scope = neighbor.metadata.get('scope', '')
                    rg_parts = scope.split('/resourceGroups/')
                    if len(rg_parts) > 1:
                        resource_groups.add(rg_parts[1].split('/')[0])

                    if neighbor.node_type == NODE_SUBSCRIPTION:
                        subscriptions.add(neighbor.id)
                    reachable_resources.append({
                        'id': neighbor.id, 'name': neighbor.name,
                        'type': neighbor.node_type, 'depth': new_depth,
                        'via_role': current_via,
                    })

                elif neighbor.node_type == NODE_KEYVAULT:
                    reachable_secrets.append({
                        'id': neighbor.id, 'name': neighbor.name,
                        'depth': new_depth,
                    })

                queue.append((neighbor_id, new_depth, current_via))

        sub_count = len(subscriptions)
        rg_count = len(resource_groups)
        res_count = len(reachable_resources)
        sec_count = len(reachable_secrets)
        score = min(100, sub_count * 15 + rg_count * 5 + res_count * 2 + sec_count * 10)

        return {
            'identity_id': identity_id,
            'reachable_resources': reachable_resources,
            'reachable_secrets': reachable_secrets,
            'blast_radius_score': score,
            'subscription_count': sub_count,
            'resource_group_count': rg_count,
            'resource_count': res_count,
            'secret_count': sec_count,
            'max_depth': max_depth,
        }

    def find_escalation_paths(self, identity_id: str) -> List[dict]:
        """Find PRIVILEGE_ESCALATION and ROLE_CHAINING paths for a single identity.

        Filtered subset of _discover_attack_paths() for one identity.
        """
        start_id = identity_id if identity_id in self.graph.nodes else f'identity:{identity_id}'
        if start_id not in self.graph.nodes:
            return []

        paths = []
        # Privilege escalation: identity → privileged role
        priv_paths = self._bfs_to_targets(
            start_id,
            lambda n: n.node_type == NODE_ROLE and n.metadata.get('privileged'),
            FINDING_PRIVILEGE_ESCALATION,
        )
        paths.extend(priv_paths)

        # Role chaining: identity → intermediate → elevated
        chain_paths = self._bfs_to_targets(
            start_id,
            lambda n: n.node_type == NODE_ROLE and n.risk_score >= 60,
            FINDING_ROLE_CHAINING,
            min_depth=3,
        )
        paths.extend(chain_paths)

        return paths

    def simulate_remediation(self, identity_id: str, remove_edges: List[dict]) -> dict:
        """Simulate removing edges and compare blast radius before/after.

        remove_edges: list of dicts with keys source_id, target_id, edge_type.
        Works on a graph copy — never modifies the real graph.
        """
        # Compute original metrics
        original_br = self.compute_blast_radius(identity_id)
        original_esc = self.find_escalation_paths(identity_id)

        # Build modified graph
        modified_graph = self.graph.copy()

        # Remove specified edges from the copy
        edges_to_remove = set()
        for re in remove_edges:
            edges_to_remove.add((re.get('source_id', ''), re.get('target_id', ''), re.get('edge_type', '')))

        for source_id in list(modified_graph.adjacency.keys()):
            modified_graph.adjacency[source_id] = [
                (tid, edge) for tid, edge in modified_graph.adjacency[source_id]
                if (source_id, tid, edge.edge_type) not in edges_to_remove
            ]

        # Create a temporary engine with the modified graph
        sim_engine = GraphAttackEngine.__new__(GraphAttackEngine)
        sim_engine.db = self.db
        sim_engine.graph = modified_graph

        projected_br = sim_engine.compute_blast_radius(identity_id)
        projected_esc = sim_engine.find_escalation_paths(identity_id)

        # Find eliminated paths
        original_fps = {
            (p['source_identity'], p['target_privilege'], p['finding_type'])
            for p in original_esc
        }
        projected_fps = {
            (p['source_identity'], p['target_privilege'], p['finding_type'])
            for p in projected_esc
        }
        eliminated = original_fps - projected_fps

        return {
            'original': {
                'blast_radius_score': original_br['blast_radius_score'],
                'escalation_path_count': len(original_esc),
                'risk_score': original_br['blast_radius_score'],
            },
            'projected': {
                'blast_radius_score': projected_br['blast_radius_score'],
                'escalation_path_count': len(projected_esc),
                'risk_score': projected_br['blast_radius_score'],
            },
            'eliminated_paths': [
                {'source': e[0], 'target': e[1], 'type': e[2]} for e in eliminated
            ],
            'reduced_resources': original_br['resource_count'] - projected_br['resource_count'],
            'risk_reduction': original_br['blast_radius_score'] - projected_br['blast_radius_score'],
        }

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _category_to_node_type(category: str) -> str:
        mapping = {
            # Azure
            'human_user': NODE_USER,
            'guest': NODE_USER,
            'service_principal': NODE_SERVICE_PRINCIPAL,
            'managed_identity_system': NODE_MANAGED_IDENTITY,
            'managed_identity_user': NODE_MANAGED_IDENTITY,
            'microsoft_internal': NODE_SERVICE_PRINCIPAL,
            # AWS
            'iam_user': NODE_USER,
            'iam_role': NODE_SERVICE_PRINCIPAL,
            'iam_service_linked_role': NODE_SERVICE_PRINCIPAL,
            # GCP
            'gcp_service_account': NODE_SERVICE_PRINCIPAL,
            'gcp_user': NODE_USER,
            'gcp_group': NODE_USER,
            'gcp_domain': NODE_USER,
            'gcp_member': NODE_USER,
        }
        return mapping.get(category, NODE_USER)
