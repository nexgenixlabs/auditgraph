"""
Data Plane Identity Scanner — Azure Database Servers

Discovers Azure SQL, PostgreSQL, MySQL, and CosmosDB servers and maps their
AAD admin identity relationships back to discovered identities.

Features:
    - Resource Graph API bulk query for all 4 database types
    - AAD-only authentication status detection
    - Mixed auth (password + AAD) flagging
    - Firewall rule collection with open-firewall detection
    - AAD admin identity resolution
    - CosmosDB local auth and public access detection

Dependencies:
    - azure-mgmt-resourcegraph: Resource Graph bulk queries
    - azure-mgmt-resource: ARM REST calls for auth config and firewall rules
"""

import logging
from typing import Dict, List, Optional

from app.constants import DatabaseServerType

logger = logging.getLogger(__name__)

# Try optional imports with graceful fallback
try:
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest
except ImportError:
    ResourceGraphClient = None
    QueryRequest = None

try:
    from azure.mgmt.resource import ResourceManagementClient
except ImportError:
    ResourceManagementClient = None

DST = DatabaseServerType


class DatabaseScanner:
    """Scans Azure database servers and their identity/auth relationships."""

    def __init__(self, credential, db, subscriptions: list, organization_id: int):
        self.credential = credential
        self.db = db
        self.subscriptions = subscriptions
        self.organization_id = organization_id

    def scan(self, run_id: int) -> dict:
        """Main entry point. Returns summary stats."""
        stats = {
            'servers_found': 0,
            'mixed_auth_count': 0,
            'open_firewall_count': 0,
            'aad_admins_resolved': 0,
            'firewall_rules': 0,
        }

        if not ResourceGraphClient or not QueryRequest:
            logger.warning("DatabaseScanner: azure-mgmt-resourcegraph not available, skipping")
            return stats

        sub_ids = [s['id'] for s in self.subscriptions if s.get('id')]
        if not sub_ids:
            logger.info("DatabaseScanner: no subscriptions, skipping")
            return stats

        try:
            rg_client = ResourceGraphClient(self.credential)
        except Exception as e:
            logger.error("DatabaseScanner: failed to create ResourceGraphClient: %s", e)
            return stats

        # Step 1: Discover Azure SQL Servers
        sql_servers = self._discover_sql_servers(rg_client, sub_ids, run_id)
        stats['servers_found'] += len(sql_servers)

        # Step 2: Discover PostgreSQL Flexible Servers
        pg_servers = self._discover_pg_servers(rg_client, sub_ids, run_id)
        stats['servers_found'] += len(pg_servers)

        # Step 3: Discover MySQL Flexible Servers
        mysql_servers = self._discover_mysql_servers(rg_client, sub_ids, run_id)
        stats['servers_found'] += len(mysql_servers)

        # Step 4: Discover CosmosDB Accounts
        cosmos_servers = self._discover_cosmos_accounts(rg_client, sub_ids, run_id)
        stats['servers_found'] += len(cosmos_servers)

        all_servers = sql_servers + pg_servers + mysql_servers + cosmos_servers

        # Step 5: Fetch auth config and firewall rules (ARM calls)
        for srv in all_servers:
            db_id = srv.get('_db_id')
            if not db_id:
                continue

            # Auth config ARM call
            self._fetch_auth_config(srv, run_id, db_id)

            # Firewall rules
            fw_count = self._fetch_firewall_rules(srv, run_id, db_id)
            stats['firewall_rules'] += fw_count

            # Update has_open_firewall on server record
            if srv.get('_has_open_firewall'):
                stats['open_firewall_count'] += 1

            if srv.get('mixed_auth_enabled'):
                stats['mixed_auth_count'] += 1

            # AAD admin discovery
            self._fetch_aad_admin(srv, run_id, db_id)

        # Step 6: Resolve AAD admin identity IDs
        self.db.resolve_database_aad_admins(run_id)

        # Count resolved admins
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM database_aad_admins
                WHERE discovery_run_id = %s AND identity_id IS NOT NULL
            """, (run_id,))
            stats['aad_admins_resolved'] = cursor.fetchone()[0] or 0
            cursor.close()
        except Exception:
            pass

        logger.info(
            "DatabaseScanner: %d servers (%d mixed auth, %d open firewall, %d admins resolved)",
            stats['servers_found'], stats['mixed_auth_count'],
            stats['open_firewall_count'], stats['aad_admins_resolved'],
        )
        return stats

    # ------------------------------------------------------------------
    # Resource Graph discovery methods
    # ------------------------------------------------------------------

    def _run_resource_graph(self, rg_client, sub_ids: list, query: str) -> list:
        """Execute a Resource Graph query and return rows."""
        try:
            request = QueryRequest(
                subscriptions=sub_ids,
                query=query,
            )
            response = rg_client.resources(request)
            return response.data if hasattr(response, 'data') else []
        except Exception as e:
            logger.warning("DatabaseScanner: Resource Graph query failed: %s", e)
            return []

    def _discover_sql_servers(self, rg_client, sub_ids: list, run_id: int) -> list:
        """Discover Azure SQL Servers via Resource Graph."""
        query = """
            resources
            | where type == 'microsoft.sql/servers'
            | extend publicAccess = tostring(properties.publicNetworkAccess)
            | extend minTlsVersion = tostring(properties.minimalTlsVersion)
            | project id, name, resourceGroup, subscriptionId, location,
              publicAccess, minTlsVersion, tags
        """
        rows = self._run_resource_graph(rg_client, sub_ids, query)
        servers = []
        for row in rows:
            srv = self._parse_sql_row(row)
            db_id = self.db.save_database_server(run_id, srv)
            srv['_db_id'] = db_id
            servers.append(srv)
        return servers

    def _parse_sql_row(self, row: dict) -> dict:
        """Parse a Resource Graph Azure SQL row."""
        return {
            'server_type': DST.AZURE_SQL,
            'server_name': row.get('name', ''),
            'resource_group': row.get('resourceGroup', ''),
            'subscription_id': row.get('subscriptionId', ''),
            'azure_resource_id': row.get('id', ''),
            'location': row.get('location', ''),
            'public_network_access': row.get('publicAccess'),
            'tls_version': row.get('minTlsVersion'),
            # Auth config will be filled by ARM call
            'mixed_auth_enabled': None,
            'aad_only_auth_enforced': None,
        }

    def _discover_pg_servers(self, rg_client, sub_ids: list, run_id: int) -> list:
        """Discover PostgreSQL Flexible Servers via Resource Graph."""
        query = """
            resources
            | where type == 'microsoft.dbforpostgresql/flexibleservers'
            | extend aadAuthEnabled = tostring(properties.authConfig.activeDirectoryAuth)
            | extend passwordAuthEnabled = tostring(properties.authConfig.passwordAuth)
            | project id, name, resourceGroup, subscriptionId, location,
              aadAuthEnabled, passwordAuthEnabled, tags
        """
        rows = self._run_resource_graph(rg_client, sub_ids, query)
        servers = []
        for row in rows:
            srv = self._parse_pg_row(row)
            db_id = self.db.save_database_server(run_id, srv)
            srv['_db_id'] = db_id
            servers.append(srv)
        return servers

    def _parse_pg_row(self, row: dict) -> dict:
        """Parse PostgreSQL Flexible Server row and determine auth config."""
        aad = (row.get('aadAuthEnabled') or '').lower()
        pwd = (row.get('passwordAuthEnabled') or '').lower()

        if aad == 'enabled' and pwd == 'disabled':
            mixed_auth = False
            aad_only = True
        elif aad == 'enabled' and pwd == 'enabled':
            mixed_auth = True
            aad_only = False
        else:
            mixed_auth = True
            aad_only = False

        return {
            'server_type': DST.POSTGRESQL,
            'server_name': row.get('name', ''),
            'resource_group': row.get('resourceGroup', ''),
            'subscription_id': row.get('subscriptionId', ''),
            'azure_resource_id': row.get('id', ''),
            'location': row.get('location', ''),
            'mixed_auth_enabled': mixed_auth,
            'aad_only_auth_enforced': aad_only,
        }

    def _discover_mysql_servers(self, rg_client, sub_ids: list, run_id: int) -> list:
        """Discover MySQL Flexible Servers via Resource Graph."""
        query = """
            resources
            | where type == 'microsoft.dbformysql/flexibleservers'
            | extend aadAuthEnabled = tostring(properties.authConfig.activeDirectoryAuth)
            | extend passwordAuthEnabled = tostring(properties.authConfig.localAuthEnabled)
            | project id, name, resourceGroup, subscriptionId, location,
              aadAuthEnabled, passwordAuthEnabled, tags
        """
        rows = self._run_resource_graph(rg_client, sub_ids, query)
        servers = []
        for row in rows:
            srv = self._parse_mysql_row(row)
            db_id = self.db.save_database_server(run_id, srv)
            srv['_db_id'] = db_id
            servers.append(srv)
        return servers

    def _parse_mysql_row(self, row: dict) -> dict:
        """Parse MySQL Flexible Server row — same auth mapping as PostgreSQL."""
        aad = (row.get('aadAuthEnabled') or '').lower()
        pwd = (row.get('passwordAuthEnabled') or '').lower()

        if aad == 'enabled' and pwd == 'disabled':
            mixed_auth = False
            aad_only = True
        elif aad == 'enabled' and pwd == 'enabled':
            mixed_auth = True
            aad_only = False
        else:
            mixed_auth = True
            aad_only = False

        return {
            'server_type': DST.MYSQL,
            'server_name': row.get('name', ''),
            'resource_group': row.get('resourceGroup', ''),
            'subscription_id': row.get('subscriptionId', ''),
            'azure_resource_id': row.get('id', ''),
            'location': row.get('location', ''),
            'mixed_auth_enabled': mixed_auth,
            'aad_only_auth_enforced': aad_only,
        }

    def _discover_cosmos_accounts(self, rg_client, sub_ids: list, run_id: int) -> list:
        """Discover CosmosDB accounts via Resource Graph."""
        query = """
            resources
            | where type == 'microsoft.documentdb/databaseaccounts'
            | extend disableLocalAuth = tobool(properties.disableLocalAuth)
            | extend publicAccess = tostring(properties.publicNetworkAccess)
            | extend ipRules = properties.ipRules
            | project id, name, resourceGroup, subscriptionId, location,
              disableLocalAuth, publicAccess, ipRules, tags
        """
        rows = self._run_resource_graph(rg_client, sub_ids, query)
        servers = []
        for row in rows:
            srv = self._parse_cosmos_row(row)
            db_id = self.db.save_database_server(run_id, srv)
            srv['_db_id'] = db_id
            servers.append(srv)
        return servers

    def _parse_cosmos_row(self, row: dict) -> dict:
        """Parse CosmosDB account row."""
        disable_local = row.get('disableLocalAuth', False)
        public_access = (row.get('publicAccess') or '').lower()
        ip_rules = row.get('ipRules') or []

        # CosmosDB: public access + no IP rules = open firewall equivalent
        has_open = (public_access == 'enabled' and len(ip_rules) == 0)

        return {
            'server_type': DST.COSMOSDB,
            'server_name': row.get('name', ''),
            'resource_group': row.get('resourceGroup', ''),
            'subscription_id': row.get('subscriptionId', ''),
            'azure_resource_id': row.get('id', ''),
            'location': row.get('location', ''),
            'local_auth_disabled': disable_local is True,
            'mixed_auth_enabled': disable_local is not True,
            'aad_only_auth_enforced': disable_local is True,
            'public_network_access': row.get('publicAccess'),
            'has_open_firewall': has_open,
            '_has_open_firewall': has_open,
        }

    # ------------------------------------------------------------------
    # ARM calls for auth config, firewall rules, AAD admin
    # ------------------------------------------------------------------

    def _arm_get(self, resource_id: str, sub_path: str, api_version: str) -> Optional[dict]:
        """Make an ARM GET call. Returns parsed JSON or None on failure."""
        try:
            from azure.mgmt.resource import ResourceManagementClient
            # Use generic REST call via credential
            import requests
            from azure.identity import DefaultAzureCredential
            token = self.credential.get_token("https://management.azure.com/.default")
            url = f"https://management.azure.com{resource_id}/{sub_path}?api-version={api_version}"
            resp = requests.get(url, headers={'Authorization': f'Bearer {token.token}'}, timeout=30)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code in (403, 404):
                logger.debug("DatabaseScanner ARM %d for %s/%s", resp.status_code, resource_id, sub_path)
                return None
            else:
                logger.warning("DatabaseScanner ARM %d for %s/%s", resp.status_code, resource_id, sub_path)
                return None
        except Exception as e:
            logger.debug("DatabaseScanner ARM call failed: %s", e)
            return None

    def _fetch_auth_config(self, srv: dict, run_id: int, db_id: int):
        """Fetch AAD-only auth status for Azure SQL servers via ARM."""
        if srv['server_type'] != DST.AZURE_SQL:
            return  # PG/MySQL auth config comes from Resource Graph, Cosmos from properties

        resource_id = srv.get('azure_resource_id')
        if not resource_id:
            return

        result = self._arm_get(
            resource_id,
            'azureADOnlyAuthentications/Default',
            '2021-11-01',
        )
        if result:
            props = result.get('properties', {})
            aad_only = props.get('azureADOnlyAuthentication', False)
            srv['aad_only_auth_enforced'] = aad_only
            srv['mixed_auth_enabled'] = not aad_only

            # Update server record
            try:
                cursor = self.db.conn.cursor()
                cursor.execute("""
                    UPDATE database_servers
                    SET mixed_auth_enabled = %s, aad_only_auth_enforced = %s
                    WHERE id = %s
                """, (not aad_only, aad_only, db_id))
                self.db._commit()
                cursor.close()
            except Exception:
                self.db._rollback()
                if self.organization_id:
                    self.db.set_organization_context(self.organization_id)

    def _fetch_firewall_rules(self, srv: dict, run_id: int, db_id: int) -> int:
        """Fetch firewall rules for a database server via ARM."""
        resource_id = srv.get('azure_resource_id')
        if not resource_id:
            return 0

        # Determine the firewall rules sub-path
        stype = srv['server_type']
        if stype == DST.AZURE_SQL:
            sub_path = 'firewallRules'
            api_version = '2021-11-01'
        elif stype == DST.POSTGRESQL:
            sub_path = 'firewallRules'
            api_version = '2022-12-01'
        elif stype == DST.MYSQL:
            sub_path = 'firewallRules'
            api_version = '2021-12-01-preview'
        else:
            # CosmosDB doesn't have traditional firewall rules
            return 0

        result = self._arm_get(resource_id, sub_path, api_version)
        if not result:
            return 0

        rules = result.get('value', [])
        has_open = False

        for rule in rules:
            props = rule.get('properties', {})
            start_ip = props.get('startIpAddress', '')
            end_ip = props.get('endIpAddress', '')
            rule_name = rule.get('name', '')

            is_allow_all = (start_ip == '0.0.0.0')
            is_azure_svc = (
                rule_name == 'AllowAllWindowsAzureIps'
                or (start_ip == '0.0.0.0' and end_ip == '0.0.0.0')
            )

            if is_allow_all:
                has_open = True

            self.db.save_database_firewall_rule(run_id, db_id, {
                'rule_name': rule_name,
                'start_ip': start_ip,
                'end_ip': end_ip,
                'is_allow_all': is_allow_all,
                'is_azure_services': is_azure_svc,
            })

        # Update has_open_firewall on server
        srv['_has_open_firewall'] = has_open
        if has_open:
            srv['has_open_firewall'] = True
        try:
            cursor = self.db.conn.cursor()
            cursor.execute(
                "UPDATE database_servers SET has_open_firewall = %s WHERE id = %s",
                (has_open, db_id),
            )
            self.db._commit()
            cursor.close()
        except Exception:
            self.db._rollback()
            if self.organization_id:
                self.db.set_organization_context(self.organization_id)

        return len(rules)

    def _fetch_aad_admin(self, srv: dict, run_id: int, db_id: int):
        """Fetch AAD admin for a database server via ARM."""
        resource_id = srv.get('azure_resource_id')
        if not resource_id:
            return

        stype = srv['server_type']
        if stype == DST.AZURE_SQL:
            result = self._arm_get(resource_id, 'administrators', '2022-02-01-preview')
            if not result:
                return
            for admin in result.get('value', []):
                props = admin.get('properties', {})
                if props.get('administratorType') == 'ActiveDirectory':
                    self.db.save_database_aad_admin(run_id, db_id, {
                        'principal_id': props.get('sid'),
                        'principal_type': props.get('principalType', 'Unknown'),
                        'admin_login': props.get('login'),
                    })
        elif stype in (DST.POSTGRESQL, DST.MYSQL):
            # PG/MySQL AAD admins come from administrators sub-resource
            api_version = '2022-12-01' if stype == DST.POSTGRESQL else '2021-12-01-preview'
            result = self._arm_get(resource_id, 'administrators', api_version)
            if not result:
                return
            for admin in result.get('value', []):
                props = admin.get('properties', {})
                self.db.save_database_aad_admin(run_id, db_id, {
                    'principal_id': props.get('objectId') or props.get('sid'),
                    'principal_type': props.get('principalType', 'Unknown'),
                    'admin_login': props.get('login') or props.get('principalName'),
                })
        # CosmosDB does not have AAD admin concept
