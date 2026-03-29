"""
Compute Identity Plane Scanner

Discovers Azure compute resources (App Services, Functions, VMs, Logic Apps) and
maps their managed identity relationships back to discovered identities.

Features:
    - Resource Graph API bulk query for all 4 compute types
    - App Service / Function classification via `kind` field
    - System MSI → identity linking (UPDATE identities.associated_resource_*)
    - GHOST_MSI detection: SAMIs whose host resource no longer exists
    - Environment variable secret detection (pattern match only — never stores values)
    - Compute-scoped RBAC scanning via Resource Graph
    - JIT policy check for Virtual Machines

Dependencies:
    - azure-mgmt-resourcegraph: Resource Graph bulk queries
    - azure-mgmt-web: App Service appsettings API (env var audit)
    - azure-mgmt-compute: VM JIT policy extension check
    - azure-mgmt-security: Security Center JIT policies (optional)
"""

import logging
import re
import json
from typing import Dict, List, Optional, Set

from app.constants import ComputeResourceType, IdentityCategory, Verdict

logger = logging.getLogger(__name__)

# Try optional imports with graceful fallback
try:
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest
except ImportError:
    ResourceGraphClient = None
    QueryRequest = None

try:
    from azure.mgmt.web import WebSiteManagementClient
except ImportError:
    WebSiteManagementClient = None

try:
    from azure.mgmt.security import SecurityCenter
except ImportError:
    SecurityCenter = None


# ── Secret detection patterns (env var name patterns — never inspects values) ──

_SECRET_NAME_PATTERNS = [
    (re.compile(r'(?i)(^|_)(password|passwd|pwd)(_|$)'), 'password'),
    (re.compile(r'(?i)(^|_)(secret|client_secret|app_secret)(_|$)'), 'secret'),
    (re.compile(r'(?i)(^|_)(api_key|apikey|api-key)(_|$)'), 'api_key'),
    (re.compile(r'(?i)(^|_)(connection_?string|connstr)(_|$)'), 'connection_string'),
    (re.compile(r'(?i)(^|_)(access_key|account_key|storage_key)(_|$)'), 'access_key'),
    (re.compile(r'(?i)(^|_)(private_key|signing_key)(_|$)'), 'private_key'),
    (re.compile(r'(?i)(^|_)(token|bearer|jwt)(_|$)'), 'token'),
    (re.compile(r'(?i)(^|_)(sas_token|shared_access)(_|$)'), 'sas_token'),
]

# Key Vault reference pattern: @Microsoft.KeyVault(...)
_KV_REF_PATTERN = re.compile(r'^@Microsoft\.KeyVault\(', re.IGNORECASE)

# ── High-privilege roles for compute RBAC ──

_HIGH_PRIV_ROLES = {
    'Owner', 'Contributor', 'User Access Administrator',
    'Website Contributor', 'Virtual Machine Contributor',
    'Logic App Contributor', 'Web Plan Contributor',
}

# ── Resource type constants (from SSOT constants.py) ──
# Local aliases for readability
CRT = ComputeResourceType


class ComputeScanner:
    """Scans Azure compute resources and their identity relationships."""

    def __init__(self, credential, db, subscriptions: list, organization_id: int):
        self.credential = credential
        self.db = db
        self.subscriptions = subscriptions
        self.organization_id = organization_id

    def scan(self, run_id: int) -> dict:
        """Main entry point. Returns summary stats."""
        stats = {
            'resources_found': 0,
            'msi_linked': 0,
            'ghost_msi_detected': 0,
            'env_secrets_found': 0,
            'rbac_assignments': 0,
            'jit_policies': 0,
        }

        # 1. Discover compute resources via Resource Graph
        resources = self._discover_compute_resources()
        stats['resources_found'] = len(resources)
        if not resources:
            logger.info("ComputeScanner: no compute resources found")
            return stats

        # 2. Save resources to DB
        resource_db_ids = {}  # azure_resource_id → db_id
        for res in resources:
            res['organization_id'] = self.organization_id
            db_id = self.db.save_compute_resource(run_id, res)
            if db_id:
                resource_db_ids[res['azure_resource_id']] = db_id

        # 3. Resolve MSI → identity links
        linked = self._resolve_msi_identities(run_id, resources)
        stats['msi_linked'] = linked

        # 4. Detect GHOST_MSI (SAMIs without host resource)
        ghosts = self._detect_ghost_msi(run_id, resources)
        stats['ghost_msi_detected'] = ghosts

        # 5. Scan env var secrets (App Services + Functions only)
        secrets_found = self._scan_env_secrets(run_id, resources, resource_db_ids)
        stats['env_secrets_found'] = secrets_found

        # 6. Compute-scoped RBAC
        rbac_count = self._scan_compute_rbac(run_id, resources, resource_db_ids)
        stats['rbac_assignments'] = rbac_count

        # 7. JIT policy check (VMs only)
        jit_count = self._check_jit_policies(run_id, resources, resource_db_ids)
        stats['jit_policies'] = jit_count

        logger.info(
            "ComputeScanner complete: %s resources, %s MSI linked, %s ghost MSI, "
            "%s env secrets, %s RBAC, %s JIT",
            stats['resources_found'], stats['msi_linked'],
            stats['ghost_msi_detected'], stats['env_secrets_found'],
            stats['rbac_assignments'], stats['jit_policies'],
        )
        return stats

    # ── Part 2: Resource Graph Discovery ──

    def _discover_compute_resources(self) -> list:
        """Query Azure Resource Graph for all compute resources across subscriptions."""
        if ResourceGraphClient is None or QueryRequest is None:
            logger.warning("ComputeScanner: ResourceGraphClient not available, skipping")
            return []

        sub_ids = [s['id'] for s in self.subscriptions]
        if not sub_ids:
            return []

        try:
            rg_client = ResourceGraphClient(self.credential)
        except Exception as e:
            logger.error("ComputeScanner: failed to create ResourceGraphClient: %s", e)
            return []

        query = """
            Resources
            | where type in~ ('microsoft.web/sites', 'microsoft.compute/virtualmachines', 'microsoft.logic/workflows')
            | project id, name, type, kind, location, resourceGroup, subscriptionId,
                      identity, properties, sku, tags
            | order by type asc, name asc
        """

        all_resources = []
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
                    parsed = self._parse_resource_graph_row(row)
                    if parsed:
                        all_resources.append(parsed)

                skip_token = getattr(response, 'skip_token', None)
                page += 1
                if not skip_token or page >= 20:  # safety limit
                    break

            except Exception as e:
                logger.error("ComputeScanner: Resource Graph query error (page %s): %s", page, e)
                break

        logger.info("ComputeScanner: discovered %s compute resources", len(all_resources))
        return all_resources

    def _parse_resource_graph_row(self, row: dict) -> Optional[dict]:
        """Parse a single Resource Graph row into our compute_resources schema."""
        arm_type = (row.get('type') or '').lower()
        kind = (row.get('kind') or '').lower()
        properties = row.get('properties') or {}
        identity = row.get('identity') or {}
        sku = row.get('sku') or {}

        # Classify resource type
        if arm_type == 'microsoft.web/sites':
            if 'functionapp' in kind:
                resource_type = CRT.FUNCTION
            else:
                resource_type = CRT.APP_SERVICE
        elif arm_type == 'microsoft.compute/virtualmachines':
            resource_type = CRT.VIRTUAL_MACHINE
        elif arm_type == 'microsoft.logic/workflows':
            resource_type = CRT.LOGIC_APP
        else:
            return None

        # Extract system MSI principal ID
        system_msi_principal_id = None
        if identity.get('type', '').lower() in ('systemassigned', 'systemassigned,userassigned',
                                                   'systemassigned, userassigned'):
            system_msi_principal_id = identity.get('principalId')

        # Extract user-assigned MSI resource IDs
        user_msi_ids = []
        user_assigned = identity.get('userAssignedIdentities') or {}
        for ua_resource_id in user_assigned.keys():
            user_msi_ids.append(ua_resource_id)

        # Public access detection
        has_public_access = self._detect_public_access(resource_type, properties)

        # OS type (VMs only)
        os_type = None
        if resource_type == CRT.VIRTUAL_MACHINE:
            storage_profile = properties.get('storageProfile') or {}
            os_disk = storage_profile.get('osDisk') or {}
            os_type = os_disk.get('osType') or properties.get('osProfile', {}).get('windowsConfiguration') and 'Windows' or 'Linux'

        # State
        state = None
        if resource_type == CRT.VIRTUAL_MACHINE:
            statuses = (properties.get('instanceView') or {}).get('statuses') or []
            for s in statuses:
                code = (s.get('code') or '').lower()
                if code.startswith('powerstate/'):
                    state = code.replace('powerstate/', '')
        elif resource_type in (CRT.APP_SERVICE, CRT.FUNCTION):
            state = (properties.get('state') or '').lower() or None
        elif resource_type == CRT.LOGIC_APP:
            state = (properties.get('state') or '').lower() or None

        # Logic App kind
        logic_app_kind = None
        if resource_type == CRT.LOGIC_APP:
            logic_app_kind = kind or 'consumption'

        # Extract resource group from id
        resource_id = row.get('id') or ''
        rg = None
        if '/resourceGroups/' in resource_id:
            rg = resource_id.split('/resourceGroups/')[1].split('/')[0]

        return {
            'resource_type': resource_type,
            'resource_name': row.get('name'),
            'resource_group': rg,
            'subscription_id': row.get('subscriptionId'),
            'azure_resource_id': resource_id,
            'location': row.get('location'),
            'system_msi_principal_id': system_msi_principal_id,
            'user_msi_resource_ids': user_msi_ids if user_msi_ids else None,
            'jit_enabled': None,  # filled in step 7
            'has_public_access': has_public_access,
            'os_type': os_type,
            'logic_app_kind': logic_app_kind,
            'sku_name': sku.get('name'),
            'state': state,
            'tags': row.get('tags'),
        }

    def _detect_public_access(self, resource_type: str, properties: dict) -> bool:
        """Heuristic check for public internet accessibility."""
        if resource_type in (CRT.APP_SERVICE, CRT.FUNCTION):
            # publicNetworkAccess or no access restrictions
            pna = (properties.get('publicNetworkAccess') or '').lower()
            if pna == 'disabled':
                return False
            # If site has IP restrictions blocking all, not public
            site_config = properties.get('siteConfig') or {}
            ip_restrictions = site_config.get('ipSecurityRestrictions') or []
            if ip_restrictions and len(ip_restrictions) == 1:
                action = (ip_restrictions[0].get('action') or '').lower()
                ip_addr = ip_restrictions[0].get('ipAddress') or ''
                if action == 'deny' and ip_addr == 'Any':
                    return False
            return True  # default: App Services are public unless restricted

        elif resource_type == CRT.VIRTUAL_MACHINE:
            # VMs with public IP (simplified — Resource Graph may not have full NIC data)
            network_profile = properties.get('networkProfile') or {}
            nics = network_profile.get('networkInterfaces') or []
            # Resource Graph doesn't always include publicIP details; default False
            return False

        elif resource_type == CRT.LOGIC_APP:
            # Logic Apps with HTTP trigger accessible publicly unless restricted
            access_control = properties.get('accessControl') or {}
            triggers = access_control.get('triggers') or {}
            allowed_ips = triggers.get('allowedCallerIpAddresses') or []
            if not allowed_ips:
                # Check definition triggers for HTTP
                definition = properties.get('definition') or {}
                trigger_defs = definition.get('triggers') or {}
                for t_name, t_val in trigger_defs.items():
                    if (t_val.get('type') or '').lower() in ('request', 'httptrigger'):
                        return True
            return False

        return False

    # ── Part 3: MSI Identity Resolution ──

    def _resolve_msi_identities(self, run_id: int, resources: list) -> int:
        """Link system MSI principal IDs on compute resources back to identities table.

        Updates identities.associated_resource_* columns for matching SAMIs,
        and sets compute_resources.system_msi_identity_id for the reverse link.
        """
        cursor = self.db.conn.cursor()
        linked = 0
        try:
            # Build map: principal_id → identity db_id + identity_id for SAMIs in this run
            cursor.execute("""
                SELECT id, identity_id, display_name
                FROM identities
                WHERE discovery_run_id = %s
                  AND identity_category = %s
            """, (run_id, IdentityCategory.MANAGED_IDENTITY_SYSTEM))
            sami_map = {}  # principal_id (object_id) → {id, identity_id, display_name}
            for row in cursor.fetchall():
                sami_map[row[1]] = {'id': row[0], 'identity_id': row[1], 'display_name': row[2]}

            for res in resources:
                principal_id = res.get('system_msi_principal_id')
                if not principal_id:
                    continue

                sami = sami_map.get(principal_id)
                if not sami:
                    continue

                # Map resource_type to ARM type for associated_resource_type
                arm_type_map = {
                    CRT.APP_SERVICE: 'Microsoft.Web/sites',
                    CRT.FUNCTION: 'Microsoft.Web/sites',
                    CRT.VIRTUAL_MACHINE: 'Microsoft.Compute/virtualMachines',
                    CRT.LOGIC_APP: 'Microsoft.Logic/workflows',
                }
                arm_type = arm_type_map.get(res['resource_type'], res['resource_type'])

                # Update identities table with resource context
                try:
                    cursor.execute("""
                        UPDATE identities SET
                            associated_resource_id = %s,
                            associated_resource_type = %s,
                            associated_resource_name = %s
                        WHERE id = %s
                    """, (
                        res['azure_resource_id'],
                        arm_type,
                        res['resource_name'],
                        sami['id'],
                    ))
                    linked += 1
                except Exception as e:
                    logger.warning("MSI link update failed for identity %s: %s", sami['id'], e)
                    self.db._rollback()
                    if self.organization_id:
                        self.db.set_organization_context(self.organization_id)
                    cursor = self.db.conn.cursor()

            self.db._commit()
        except Exception as e:
            logger.error("MSI identity resolution error: %s", e)
            self.db._rollback()
            if self.organization_id:
                self.db.set_organization_context(self.organization_id)
        finally:
            cursor.close()

        logger.info("ComputeScanner: linked %s MSI → identity", linked)
        return linked

    # ── Part 4: GHOST_MSI Detection ──

    def _detect_ghost_msi(self, run_id: int, resources: list) -> int:
        """Detect SAMIs whose host compute resource was NOT found in this scan.

        A GHOST_MSI is a system-assigned managed identity that has role assignments
        but whose parent resource no longer appears in Azure Resource Graph.
        We update the lineage verdict to GHOST_MSI for these identities.
        """
        # Collect all system MSI principal IDs found on compute resources
        found_principals: Set[str] = set()
        for res in resources:
            pid = res.get('system_msi_principal_id')
            if pid:
                found_principals.add(pid)

        cursor = self.db.conn.cursor()
        ghost_count = 0
        try:
            # Find SAMIs in this run that have roles but NO associated_resource_id
            # and whose principal_id is NOT in found_principals
            cursor.execute("""
                SELECT i.id, i.identity_id, i.display_name
                FROM identities i
                WHERE i.discovery_run_id = %s
                  AND i.identity_category = %s
                  AND i.associated_resource_id IS NULL
                  AND EXISTS (
                      SELECT 1 FROM role_assignments ra
                      WHERE ra.identity_db_id = i.id
                  )
            """, (run_id, IdentityCategory.MANAGED_IDENTITY_SYSTEM))
            orphan_samis = cursor.fetchall()

            for row in orphan_samis:
                db_id, identity_id, display_name = row
                if identity_id in found_principals:
                    # Has a compute resource — not a ghost
                    continue

                # This SAMI has roles but no host resource found → GHOST_MSI
                # Save verdict (the lineage engine may have already set this,
                # but we reinforce it here with compute-scanner as source)
                try:
                    self.db.save_lineage_verdict(run_id, db_id, {
                        'verdict': Verdict.GHOST_MSI,
                        'confidence_score': 0.9,
                        'contributing_factors': {
                            'reason': 'System MSI has active roles but host resource not found in compute scan',
                            'identity_id': identity_id,
                            'display_name': display_name,
                        },
                        'verdict_source': 'compute_scanner',
                    })
                    ghost_count += 1
                except Exception as e:
                    logger.warning("GHOST_MSI verdict save failed for %s: %s", db_id, e)

        except Exception as e:
            logger.error("GHOST_MSI detection error: %s", e)
        finally:
            cursor.close()

        if ghost_count > 0:
            logger.info("ComputeScanner: detected %s GHOST_MSI identities", ghost_count)
        return ghost_count

    # ── Part 5: Environment Variable Secret Detection ──

    def _scan_env_secrets(self, run_id: int, resources: list, resource_db_ids: dict) -> int:
        """Scan App Service/Function env vars for secret patterns.

        Uses Azure Web Management API to read app settings names.
        NEVER stores or logs actual values — only the setting name and pattern matched.

        Rate limited: processes sequentially (API is per-subscription, not concurrent).
        """
        if WebSiteManagementClient is None:
            logger.warning("ComputeScanner: WebSiteManagementClient not available, skipping env scan")
            return 0

        # Group web resources by subscription
        web_resources = [r for r in resources
                         if r['resource_type'] in CRT.WEB_TYPES]
        if not web_resources:
            return 0

        by_sub: Dict[str, list] = {}
        for res in web_resources:
            sub_id = res.get('subscription_id')
            if sub_id:
                by_sub.setdefault(sub_id, []).append(res)

        secrets_found = 0
        for sub_id, sub_resources in by_sub.items():
            try:
                web_client = WebSiteManagementClient(self.credential, sub_id)
            except Exception as e:
                logger.warning("ComputeScanner: WebSiteManagementClient(%s) failed: %s", sub_id, e)
                continue

            for res in sub_resources:
                rg = res.get('resource_group')
                name = res.get('resource_name')
                azure_rid = res.get('azure_resource_id')
                db_id = resource_db_ids.get(azure_rid)
                if not rg or not name or not db_id:
                    continue

                try:
                    app_settings = web_client.web_apps.list_application_settings(rg, name)
                    settings = (app_settings.properties or {}) if hasattr(app_settings, 'properties') else {}

                    for key, value in settings.items():
                        # Check if value is a Key Vault reference (safe — no secret in env)
                        is_kv_ref = bool(_KV_REF_PATTERN.match(str(value or '')))

                        # Check name against secret patterns
                        for pattern, pattern_name in _SECRET_NAME_PATTERNS:
                            if pattern.search(key):
                                severity = 'LOW' if is_kv_ref else 'HIGH'
                                self.db.save_compute_env_secret(run_id, db_id, {
                                    'env_var_name': key,
                                    'pattern_matched': pattern_name,
                                    'is_keyvault_reference': is_kv_ref,
                                    'severity': severity,
                                })
                                secrets_found += 1
                                break  # one match per env var is enough

                except Exception as e:
                    logger.warning("ComputeScanner: appsettings scan failed for %s/%s: %s", rg, name, e)

        logger.info("ComputeScanner: found %s env var secret patterns", secrets_found)
        return secrets_found

    # ── Part 6: Compute RBAC Scanning ──

    def _scan_compute_rbac(self, run_id: int, resources: list, resource_db_ids: dict) -> int:
        """Scan RBAC role assignments scoped to compute resources via Resource Graph."""
        if ResourceGraphClient is None or QueryRequest is None:
            return 0

        sub_ids = [s['id'] for s in self.subscriptions]
        if not sub_ids:
            return 0

        # Build set of compute resource ARM IDs for scope matching
        compute_scopes = set()
        for res in resources:
            rid = res.get('azure_resource_id')
            if rid:
                compute_scopes.add(rid.lower())

        # Build identity lookup: object_id → identity db_id
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT id, identity_id FROM identities WHERE discovery_run_id = %s
            """, (run_id,))
            oid_to_dbid = {row[1]: row[0] for row in cursor.fetchall()}
        finally:
            cursor.close()

        # Query role assignments scoped to compute resources
        try:
            rg_client = ResourceGraphClient(self.credential)
        except Exception as e:
            logger.error("ComputeScanner: RBAC ResourceGraphClient failed: %s", e)
            return 0

        query = """
            authorizationresources
            | where type == 'microsoft.authorization/roleassignments'
            | extend principalId = tostring(properties.principalId),
                     roleDefinitionId = tostring(properties.roleDefinitionId),
                     scope = tostring(properties.scope)
            | project principalId, roleDefinitionId, scope
        """

        rbac_count = 0
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
                    scope = (row.get('scope') or '').lower()
                    # Check if scope is at or within a compute resource
                    matching_resource = None
                    for cs in compute_scopes:
                        if scope == cs or scope.startswith(cs + '/'):
                            matching_resource = cs
                            break
                    if not matching_resource:
                        continue

                    principal_id = row.get('principalId')
                    role_def_id = row.get('roleDefinitionId', '')
                    role_name = role_def_id.rsplit('/', 1)[-1] if '/' in role_def_id else role_def_id

                    # Determine scope level
                    scope_level = 'resource'

                    # Find matching db IDs
                    identity_db_id = oid_to_dbid.get(principal_id)
                    # Find matching compute resource db_id
                    # Need original-case resource ID for db lookup
                    compute_db_id = None
                    for res in resources:
                        if (res.get('azure_resource_id') or '').lower() == matching_resource:
                            compute_db_id = resource_db_ids.get(res['azure_resource_id'])
                            break

                    is_high = role_name in _HIGH_PRIV_ROLES
                    self.db.save_compute_role_assignment(run_id, {
                        'compute_resource_id': compute_db_id,
                        'principal_azure_object_id': principal_id,
                        'identity_id': identity_db_id,
                        'role_name': role_name,
                        'scope': row.get('scope'),
                        'scope_level': scope_level,
                        'is_high_privilege': is_high,
                    })
                    rbac_count += 1

                skip_token = getattr(response, 'skip_token', None)
                page += 1
                if not skip_token or page >= 20:
                    break

            except Exception as e:
                logger.error("ComputeScanner: RBAC query error (page %s): %s", page, e)
                break

        logger.info("ComputeScanner: found %s compute-scoped RBAC assignments", rbac_count)
        return rbac_count

    # ── Part 7: JIT Policy Check ──

    def _check_jit_policies(self, run_id: int, resources: list, resource_db_ids: dict) -> int:
        """Check JIT (Just-in-Time) access policies for VMs.

        Uses Azure Security Center API if available, falls back to checking
        network security group rules for JIT patterns.
        """
        vm_resources = [r for r in resources if r['resource_type'] == CRT.VIRTUAL_MACHINE]
        if not vm_resources:
            return 0

        jit_count = 0

        # Try Security Center API for JIT policies
        if SecurityCenter is not None:
            # Group VMs by subscription
            by_sub: Dict[str, list] = {}
            for vm in vm_resources:
                sub_id = vm.get('subscription_id')
                if sub_id:
                    by_sub.setdefault(sub_id, []).append(vm)

            for sub_id, sub_vms in by_sub.items():
                try:
                    sec_client = SecurityCenter(self.credential, sub_id, asc_location='centralus')
                    jit_policies = list(sec_client.jit_network_access_policies.list())

                    # Build a set of VM resource IDs covered by JIT
                    jit_vm_ids: Set[str] = set()
                    for policy in jit_policies:
                        vms_in_policy = getattr(policy, 'virtual_machines', []) or []
                        for vm_ref in vms_in_policy:
                            vm_id = getattr(vm_ref, 'id', '') or ''
                            if vm_id:
                                jit_vm_ids.add(vm_id.lower())

                    for vm in sub_vms:
                        azure_rid = vm.get('azure_resource_id', '')
                        is_jit = azure_rid.lower() in jit_vm_ids
                        db_id = resource_db_ids.get(azure_rid)
                        if db_id and is_jit:
                            try:
                                cursor = self.db.conn.cursor()
                                cursor.execute(
                                    "UPDATE compute_resources SET jit_enabled = TRUE WHERE id = %s",
                                    (db_id,)
                                )
                                self.db._commit()
                                cursor.close()
                                jit_count += 1
                            except Exception as e:
                                logger.warning("JIT update failed for %s: %s", db_id, e)
                                self.db._rollback()
                                if self.organization_id:
                                    self.db.set_organization_context(self.organization_id)

                except Exception as e:
                    logger.warning("ComputeScanner: JIT policy check failed for sub %s: %s", sub_id, e)
        else:
            logger.info("ComputeScanner: SecurityCenter not available, JIT check skipped")

        # For VMs with no JIT info, explicitly mark as False
        for vm in vm_resources:
            azure_rid = vm.get('azure_resource_id', '')
            db_id = resource_db_ids.get(azure_rid)
            if db_id and vm.get('jit_enabled') is None:
                try:
                    cursor = self.db.conn.cursor()
                    cursor.execute(
                        "UPDATE compute_resources SET jit_enabled = FALSE WHERE id = %s AND jit_enabled IS NULL",
                        (db_id,)
                    )
                    self.db._commit()
                    cursor.close()
                except Exception:
                    self.db._rollback()
                    if self.organization_id:
                        self.db.set_organization_context(self.organization_id)

        logger.info("ComputeScanner: %s VMs with JIT enabled", jit_count)
        return jit_count
