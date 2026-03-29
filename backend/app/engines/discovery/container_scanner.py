"""
Container Identity Plane Scanner — AKS Workload Identity + ACR

Discovers AKS clusters, federated identity credentials (workload identity),
ACR registries, and optionally K8s RBAC bindings (Layer 2, opt-in).

Features:
    - Resource Graph API bulk query for AKS clusters + ACR registries
    - Federated credential discovery via Graph API
    - Wildcard / overly-broad subject detection → FEDERATED_MISCONFIGURED verdict
    - ACR admin account → synthetic identity flagging
    - Layer 2 K8s RBAC scanning (opt-in per cluster, requires kubeconfig)
    - AKS system MSI → identity linking

Dependencies:
    - azure-mgmt-resourcegraph: Resource Graph bulk queries
    - azure-mgmt-containerservice: AKS management API
    - azure-mgmt-containerregistry: ACR management API
    - msgraph-sdk or requests: Graph API for federated credentials
"""

import logging
import re
from typing import Dict, List, Optional, Set

from app.constants import ContainerResourceType, FederatedIssuerType, Verdict, IdentityCategory, IdentityType

logger = logging.getLogger(__name__)

# Try optional imports with graceful fallback
try:
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest
except ImportError:
    ResourceGraphClient = None
    QueryRequest = None

try:
    from azure.mgmt.containerservice import ContainerServiceClient
except ImportError:
    ContainerServiceClient = None

try:
    from azure.mgmt.containerregistry import ContainerRegistryManagementClient
except ImportError:
    ContainerRegistryManagementClient = None


# ── Federated credential wildcard patterns ──

# AKS subject format: system:serviceaccount:{namespace}:{service_account}
_AKS_SUBJECT_RE = re.compile(
    r'^system:serviceaccount:(?P<ns>[^:]+):(?P<sa>[^:]+)$'
)

# GitHub subject format: repo:{org}/{repo}:{filter}
_GITHUB_SUBJECT_RE = re.compile(
    r'^repo:(?P<org>[^/]+)/(?P<repo>[^:]+):(?P<filter>.+)$'
)

# Overly-broad wildcard indicators
_WILDCARD_INDICATORS = {
    '*',           # literal asterisk
    'ref:refs/*',  # any Git ref
    'pull_request',  # any PR (usually too broad)
}


class ContainerScanner:
    """Scans Azure AKS clusters, federated credentials, and ACR registries."""

    def __init__(self, credential, db, subscriptions: list, organization_id: int):
        self.credential = credential
        self.db = db
        self.subscriptions = subscriptions
        self.organization_id = organization_id

    def scan(self, run_id: int) -> dict:
        """Main entry point. Returns summary stats."""
        stats = {
            'aks_clusters_found': 0,
            'federated_credentials': 0,
            'wildcard_credentials': 0,
            'federated_misconfigured': 0,
            'acr_registries': 0,
            'acr_admin_enabled': 0,
            'layer2_bindings': 0,
        }

        # 1. Discover AKS clusters via Resource Graph
        clusters = self._discover_aks_clusters()
        stats['aks_clusters_found'] = len(clusters)

        # 2. Save clusters to DB
        cluster_db_ids = {}  # azure_resource_id → db_id
        for cl in clusters:
            cl['organization_id'] = self.organization_id
            db_id = self.db.save_aks_cluster(run_id, cl)
            if db_id:
                cluster_db_ids[cl['azure_resource_id']] = db_id

        # 3. Discover federated credentials for identities in this run
        fed_stats = self._discover_federated_credentials(run_id, clusters, cluster_db_ids)
        stats['federated_credentials'] = fed_stats.get('total', 0)
        stats['wildcard_credentials'] = fed_stats.get('wildcards', 0)
        stats['federated_misconfigured'] = fed_stats.get('misconfigured', 0)

        # 4. Discover ACR registries
        acr_stats = self._discover_acr_registries(run_id)
        stats['acr_registries'] = acr_stats.get('total', 0)
        stats['acr_admin_enabled'] = acr_stats.get('admin_enabled', 0)

        # 5. Layer 2 K8s RBAC (opt-in per cluster)
        layer2_count = self._scan_layer2_rbac(run_id, clusters, cluster_db_ids)
        stats['layer2_bindings'] = layer2_count

        # 6. Link AKS system MSIs to identities
        self._link_aks_msi(run_id, clusters)

        logger.info(
            "ContainerScanner complete: %s AKS, %s fed creds (%s wildcard), "
            "%s ACR, %s layer2 bindings",
            stats['aks_clusters_found'], stats['federated_credentials'],
            stats['wildcard_credentials'], stats['acr_registries'],
            stats['layer2_bindings'],
        )
        return stats

    # ── Part 1: AKS Cluster Discovery ──

    def _discover_aks_clusters(self) -> list:
        """Query Azure Resource Graph for AKS clusters."""
        if ResourceGraphClient is None or QueryRequest is None:
            logger.warning("ContainerScanner: ResourceGraphClient not available")
            return []

        sub_ids = [s['id'] for s in self.subscriptions]
        if not sub_ids:
            return []

        try:
            rg_client = ResourceGraphClient(self.credential)
        except Exception as e:
            logger.error("ContainerScanner: ResourceGraphClient failed: %s", e)
            return []

        query = """
            Resources
            | where type =~ 'microsoft.containerservice/managedclusters'
            | project id, name, type, location, resourceGroup, subscriptionId,
                      identity, properties, sku, tags
            | order by name asc
        """

        all_clusters = []
        skip_token = None
        page = 0

        while True:
            try:
                request = QueryRequest(
                    subscriptions=sub_ids,
                    query=query,
                    options={'$top': 1000, '$skipToken': skip_token} if skip_token else {'$top': 1000},
                )
                response = rg_client.resources(request)
                rows = response.data if hasattr(response, 'data') else []

                for row in rows:
                    parsed = self._parse_aks_row(row)
                    if parsed:
                        all_clusters.append(parsed)

                skip_token = getattr(response, 'skip_token', None)
                page += 1
                if not skip_token or page >= 10:
                    break
            except Exception as e:
                logger.error("ContainerScanner: AKS query error (page %s): %s", page, e)
                break

        logger.info("ContainerScanner: discovered %s AKS clusters", len(all_clusters))
        return all_clusters

    def _parse_aks_row(self, row: dict) -> Optional[dict]:
        """Parse Resource Graph AKS row."""
        properties = row.get('properties') or {}
        identity = row.get('identity') or {}
        oidc = properties.get('oidcIssuerProfile') or {}
        agent_pools = properties.get('agentPoolProfiles') or []

        node_count = sum(p.get('count', 0) for p in agent_pools)

        system_msi_pid = None
        id_type = (identity.get('type') or '').lower()
        if 'systemassigned' in id_type:
            system_msi_pid = identity.get('principalId')

        resource_id = row.get('id') or ''
        rg = None
        if '/resourceGroups/' in resource_id:
            rg = resource_id.split('/resourceGroups/')[1].split('/')[0]

        wi_enabled = bool(
            oidc.get('enabled') or
            (properties.get('securityProfile') or {}).get('workloadIdentity', {}).get('enabled')
        )

        return {
            'cluster_name': row.get('name'),
            'resource_group': rg,
            'subscription_id': row.get('subscriptionId'),
            'azure_resource_id': resource_id,
            'location': row.get('location'),
            'kubernetes_version': properties.get('kubernetesVersion'),
            'node_count': node_count,
            'oidc_issuer_url': oidc.get('issuerURL'),
            'workload_identity_enabled': wi_enabled,
            'system_msi_principal_id': system_msi_pid,
            'network_profile': properties.get('networkProfile'),
            'tags': row.get('tags'),
        }

    # ── Part 2: Federated Credential Discovery ──

    def _discover_federated_credentials(self, run_id: int, clusters: list,
                                         cluster_db_ids: dict) -> dict:
        """Discover federated identity credentials for SPNs/UMIs in this run.

        Uses Graph API: GET /applications/{app_id}/federatedIdentityCredentials
        """
        stats = {'total': 0, 'wildcards': 0, 'misconfigured': 0}

        # Build OIDC issuer → cluster mapping
        issuer_to_cluster = {}
        for cl in clusters:
            issuer = cl.get('oidc_issuer_url')
            if issuer:
                issuer_to_cluster[issuer] = cl

        # Get SPNs with federated credentials from this run
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT i.id, i.identity_id, i.app_id, i.display_name, i.identity_category
                FROM identities i
                WHERE i.discovery_run_id = %s
                  AND i.identity_category IN (%s, %s)
                  AND i.app_id IS NOT NULL
            """, (run_id, IdentityCategory.SERVICE_PRINCIPAL, IdentityCategory.MANAGED_IDENTITY_USER))
            candidates = cursor.fetchall()
        finally:
            cursor.close()

        if not candidates:
            return stats

        # For each candidate, check federated credentials via existing credential data
        # (already discovered in main pipeline step 5)
        cursor = self.db.conn.cursor()
        try:
            for db_id, identity_id, app_id, display_name, category in candidates:
                # Check spn_credentials table for federated credentials
                cursor.execute("""
                    SELECT credential_id, description, end_date
                    FROM spn_credentials
                    WHERE identity_db_id = %s AND credential_type = 'federated'
                """, (db_id,))
                fed_creds = cursor.fetchall()

                if not fed_creds:
                    continue

                # Try to get federated credential details from Graph API
                try:
                    fed_details = self._fetch_federated_details(app_id)
                except Exception as e:
                    logger.debug("Fed cred detail fetch failed for %s: %s", app_id, e)
                    fed_details = []

                for fc in fed_details:
                    issuer = fc.get('issuer', '')
                    subject = fc.get('subject', '')
                    audiences = fc.get('audiences', [])
                    name = fc.get('name', '')

                    # Classify issuer type
                    issuer_type = self._classify_issuer(issuer, clusters)

                    # Parse subject for namespace/SA
                    namespace, service_account = None, None
                    m = _AKS_SUBJECT_RE.match(subject)
                    if m:
                        namespace = m.group('ns')
                        service_account = m.group('sa')

                    # Detect wildcard / overly-broad subject
                    is_wildcard, wildcard_reason = self._detect_wildcard(
                        issuer_type, subject, issuer, clusters
                    )

                    # Find matching cluster
                    cluster = issuer_to_cluster.get(issuer)
                    cluster_db_id = None
                    if cluster:
                        cluster_db_id = cluster_db_ids.get(cluster.get('azure_resource_id'))

                    self.db.save_aks_federated_credential(run_id, {
                        'identity_id': db_id,
                        'aks_cluster_id': cluster_db_id,
                        'credential_name': name,
                        'issuer_url': issuer,
                        'subject': subject,
                        'audiences': audiences,
                        'issuer_type': issuer_type,
                        'namespace': namespace,
                        'service_account': service_account,
                        'is_wildcard': is_wildcard,
                        'wildcard_reason': wildcard_reason,
                    })
                    stats['total'] += 1
                    if is_wildcard:
                        stats['wildcards'] += 1

                    # Fire FEDERATED_MISCONFIGURED verdict for wildcards
                    if is_wildcard:
                        try:
                            self.db.save_lineage_verdict(run_id, db_id, {
                                'verdict': Verdict.FEDERATED_MISCONFIGURED,
                                'confidence_score': 0.85,
                                'contributing_factors': {
                                    'reason': wildcard_reason,
                                    'issuer': issuer,
                                    'subject': subject,
                                    'identity_id': identity_id,
                                    'display_name': display_name,
                                },
                                'verdict_source': 'container_scanner',
                            })
                            stats['misconfigured'] += 1
                        except Exception as e:
                            logger.warning("FEDERATED_MISCONFIGURED verdict failed for %s: %s", db_id, e)
        finally:
            cursor.close()

        return stats

    def _fetch_federated_details(self, app_id: str) -> list:
        """Fetch federated identity credential details from Graph API."""
        import requests

        try:
            # Use the credential to get an access token for Graph API
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {'Authorization': f'Bearer {token.token}'}
            url = f'https://graph.microsoft.com/v1.0/applications(appId=\'{app_id}\')/federatedIdentityCredentials'
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                return resp.json().get('value', [])
        except Exception as e:
            logger.debug("Graph API fed cred fetch failed for %s: %s", app_id, e)
        return []

    def _classify_issuer(self, issuer: str, clusters: list) -> str:
        """Classify a federated credential issuer type."""
        if not issuer:
            return FederatedIssuerType.OTHER

        # Check if issuer matches an AKS cluster OIDC URL
        for cl in clusters:
            if cl.get('oidc_issuer_url') and issuer == cl['oidc_issuer_url']:
                return FederatedIssuerType.AKS

        # Check for GitHub Actions
        if 'token.actions.githubusercontent.com' in issuer:
            return FederatedIssuerType.GITHUB

        return FederatedIssuerType.OTHER

    def _detect_wildcard(self, issuer_type: str, subject: str,
                         issuer: str, clusters: list) -> tuple:
        """Detect overly-broad federated credential subjects.

        Returns (is_wildcard: bool, reason: str | None).
        """
        if not subject:
            return True, 'Empty subject — allows any principal from this issuer'

        # Check for literal wildcards
        for indicator in _WILDCARD_INDICATORS:
            if indicator in subject:
                return True, f'Subject contains wildcard pattern: {indicator}'

        if issuer_type == FederatedIssuerType.AKS:
            m = _AKS_SUBJECT_RE.match(subject)
            if not m:
                return True, f'AKS subject does not match expected format: {subject}'
            ns = m.group('ns')
            sa = m.group('sa')
            # Wildcard namespace or service account
            if ns == '*' or sa == '*':
                return True, f'AKS wildcard namespace/service account: {ns}:{sa}'
            # kube-system namespace is overly broad (system workloads)
            if ns == 'kube-system':
                return True, f'AKS subject uses kube-system namespace (system-wide access)'
            # Verify the issuer matches a known cluster
            matched = False
            for cl in clusters:
                if cl.get('oidc_issuer_url') and issuer == cl['oidc_issuer_url']:
                    matched = True
                    break
            if not matched:
                return True, 'AKS issuer does not match any discovered cluster OIDC URL'

        elif issuer_type == FederatedIssuerType.GITHUB:
            m = _GITHUB_SUBJECT_RE.match(subject)
            if not m:
                return True, f'GitHub subject does not match expected format: {subject}'
            filt = m.group('filter')
            # ref:refs/* or pull_request or environment:* are too broad
            if filt.startswith('ref:refs/*') or filt == 'pull_request':
                return True, f'GitHub subject filter too broad: {filt}'
            if '*' in filt:
                return True, f'GitHub subject contains wildcard: {filt}'

        return False, None

    # ── Part 3: ACR Registry Discovery ──

    def _discover_acr_registries(self, run_id: int) -> dict:
        """Discover Azure Container Registries."""
        stats = {'total': 0, 'admin_enabled': 0}

        if ResourceGraphClient is None or QueryRequest is None:
            return stats

        sub_ids = [s['id'] for s in self.subscriptions]
        if not sub_ids:
            return stats

        try:
            rg_client = ResourceGraphClient(self.credential)
        except Exception as e:
            logger.error("ContainerScanner: ACR ResourceGraphClient failed: %s", e)
            return stats

        query = """
            Resources
            | where type =~ 'microsoft.containerregistry/registries'
            | project id, name, type, location, resourceGroup, subscriptionId,
                      properties, sku, tags
            | order by name asc
        """

        try:
            request = QueryRequest(
                subscriptions=sub_ids,
                query=query,
                options={'$top': 1000},
            )
            response = rg_client.resources(request)
            rows = response.data if hasattr(response, 'data') else []

            for row in rows:
                props = row.get('properties') or {}
                sku = row.get('sku') or {}
                resource_id = row.get('id') or ''
                rg = None
                if '/resourceGroups/' in resource_id:
                    rg = resource_id.split('/resourceGroups/')[1].split('/')[0]

                admin_enabled = bool(props.get('adminUserEnabled'))
                public_access = (props.get('publicNetworkAccess') or '').lower() != 'disabled'

                db_id = self.db.save_acr_registry(run_id, {
                    'registry_name': row.get('name'),
                    'resource_group': rg,
                    'subscription_id': row.get('subscriptionId'),
                    'azure_resource_id': resource_id,
                    'location': row.get('location'),
                    'sku_name': sku.get('name'),
                    'login_server': props.get('loginServer'),
                    'admin_enabled': admin_enabled,
                    'public_network_access': public_access,
                    'encryption_enabled': bool((props.get('encryption') or {}).get('status') == 'enabled'),
                    'tags': row.get('tags'),
                })
                stats['total'] += 1
                if admin_enabled:
                    stats['admin_enabled'] += 1

                    # Create synthetic identity for ACR admin account
                    if db_id:
                        self._create_acr_admin_identity(run_id, row.get('name'), db_id)

        except Exception as e:
            logger.error("ContainerScanner: ACR query error: %s", e)

        logger.info("ContainerScanner: discovered %s ACR registries", stats['total'])
        return stats

    def _create_acr_admin_identity(self, run_id: int, registry_name: str, acr_db_id: int):
        """Create a synthetic identity for an ACR admin account.

        ACR admin is not a real Entra object but has pull/push access to all images.
        We create a synthetic identity entry to make it visible in the identity list.
        """
        cursor = self.db.conn.cursor()
        try:
            synthetic_id = f'acr-admin-{registry_name}'
            cursor.execute("""
                INSERT INTO identities (
                    discovery_run_id, identity_id, display_name,
                    identity_category, identity_type, risk_level,
                    associated_resource_id, associated_resource_type, associated_resource_name,
                    organization_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                RETURNING id
            """, (
                run_id, synthetic_id, f'ACR Admin: {registry_name}',
                IdentityCategory.SERVICE_PRINCIPAL, IdentityType.ACR_ADMIN_ACCOUNT, 'high',
                None, 'Microsoft.ContainerRegistry/registries', registry_name,
                self.organization_id,
            ))
            result = cursor.fetchone()
            if result:
                # Link back to ACR registry
                cursor.execute(
                    "UPDATE acr_registries SET admin_identity_id = %s WHERE id = %s",
                    (result[0], acr_db_id)
                )
            self.db._commit()
        except Exception as e:
            self.db._rollback()
            if self.organization_id:
                self.db.set_organization_context(self.organization_id)
            logger.debug("ACR admin identity creation failed for %s: %s", registry_name, e)
        finally:
            cursor.close()

    # ── Part 4: Layer 2 K8s RBAC Scanning ──

    def _scan_layer2_rbac(self, run_id: int, clusters: list, cluster_db_ids: dict) -> int:
        """Scan K8s RBAC bindings for clusters with layer2_scan_enabled.

        Layer 2 is opt-in per cluster. Requires kubeconfig or managed AKS
        credentials to connect to the K8s API server.
        """
        total_bindings = 0

        for cl in clusters:
            azure_rid = cl.get('azure_resource_id')
            cluster_db_id = cluster_db_ids.get(azure_rid)
            if not cluster_db_id:
                continue

            # Check if layer2 is enabled for this cluster
            if not cl.get('layer2_scan_enabled'):
                continue

            sub_id = cl.get('subscription_id')
            rg = cl.get('resource_group')
            cluster_name = cl.get('cluster_name')

            if not sub_id or not rg or not cluster_name:
                continue

            if ContainerServiceClient is None:
                logger.info("ContainerScanner: ContainerServiceClient not available for Layer 2")
                continue

            try:
                aks_client = ContainerServiceClient(self.credential, sub_id)
                # Get cluster credentials (admin kubeconfig)
                cred_result = aks_client.managed_clusters.list_cluster_user_credentials(
                    rg, cluster_name
                )
                kubeconfigs = cred_result.kubeconfigs or []
                if not kubeconfigs:
                    continue

                # Parse kubeconfig and connect to K8s API
                bindings = self._fetch_k8s_rbac_bindings(kubeconfigs[0])
                for binding in bindings:
                    binding['aks_cluster_id'] = cluster_db_id
                    self.db.save_aks_rbac_binding(run_id, binding)
                    total_bindings += 1

            except Exception as e:
                logger.warning("Layer 2 RBAC scan failed for %s: %s", cluster_name, e)

        return total_bindings

    def _fetch_k8s_rbac_bindings(self, kubeconfig_data) -> list:
        """Fetch RBAC bindings from K8s API using kubeconfig.

        Returns list of binding dicts ready for save_aks_rbac_binding().
        """
        bindings = []
        try:
            import base64
            import yaml
            from kubernetes import client as k8s_client, config as k8s_config

            # Decode kubeconfig
            kc_bytes = kubeconfig_data.value if hasattr(kubeconfig_data, 'value') else kubeconfig_data
            if isinstance(kc_bytes, bytes):
                kc_str = kc_bytes.decode('utf-8')
            else:
                kc_str = str(kc_bytes)

            kc_dict = yaml.safe_load(kc_str)
            k8s_config.load_kube_config_from_dict(kc_dict)
            rbac_api = k8s_client.RbacAuthorizationV1Api()

            # ClusterRoleBindings
            crbs = rbac_api.list_cluster_role_binding()
            for crb in crbs.items:
                for subj in (crb.subjects or []):
                    is_admin = (crb.role_ref.name == 'cluster-admin') if crb.role_ref else False
                    bindings.append({
                        'binding_type': 'ClusterRoleBinding',
                        'binding_name': crb.metadata.name,
                        'namespace': None,
                        'role_name': crb.role_ref.name if crb.role_ref else None,
                        'role_kind': crb.role_ref.kind if crb.role_ref else None,
                        'subject_kind': subj.kind,
                        'subject_name': subj.name,
                        'subject_namespace': subj.namespace,
                        'is_cluster_admin': is_admin,
                    })

            # RoleBindings (all namespaces)
            rbs = rbac_api.list_role_binding_for_all_namespaces()
            for rb in rbs.items:
                for subj in (rb.subjects or []):
                    bindings.append({
                        'binding_type': 'RoleBinding',
                        'binding_name': rb.metadata.name,
                        'namespace': rb.metadata.namespace,
                        'role_name': rb.role_ref.name if rb.role_ref else None,
                        'role_kind': rb.role_ref.kind if rb.role_ref else None,
                        'subject_kind': subj.kind,
                        'subject_name': subj.name,
                        'subject_namespace': subj.namespace,
                        'is_cluster_admin': False,
                    })

        except ImportError:
            logger.info("kubernetes client not installed — Layer 2 scan unavailable")
        except Exception as e:
            logger.warning("K8s RBAC fetch error: %s", e)

        return bindings

    # ── Part 5: AKS MSI Linking ──

    def _link_aks_msi(self, run_id: int, clusters: list):
        """Link AKS cluster system MSIs to identities table."""
        cursor = self.db.conn.cursor()
        try:
            for cl in clusters:
                pid = cl.get('system_msi_principal_id')
                if not pid:
                    continue

                cursor.execute("""
                    SELECT id FROM identities
                    WHERE identity_id = %s AND discovery_run_id = %s
                    LIMIT 1
                """, (pid, run_id))
                row = cursor.fetchone()
                if not row:
                    continue

                cursor.execute("""
                    UPDATE identities SET
                        associated_resource_id = %s,
                        associated_resource_type = %s,
                        associated_resource_name = %s
                    WHERE id = %s
                """, (
                    cl['azure_resource_id'],
                    'Microsoft.ContainerService/managedClusters',
                    cl['cluster_name'],
                    row[0],
                ))

            self.db._commit()
        except Exception as e:
            logger.warning("AKS MSI linking error: %s", e)
            self.db._rollback()
            if self.organization_id:
                self.db.set_organization_context(self.organization_id)
        finally:
            cursor.close()
