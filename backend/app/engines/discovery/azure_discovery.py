"""
Azure Discovery Engine

This module contains the AzureDiscoveryEngine class that orchestrates the complete
discovery process for Azure cloud identities. It connects to Microsoft Graph API
and Azure Resource Manager to discover and analyze identities and their permissions.

Discovery Process (executed in order):
    1. Create discovery run record in database
    2. Discover Azure RBAC role assignments (via Azure CLI)
    3. Discover Entra ID directory roles (via Graph API)
    4. Discover Service Principals with pagination (via Graph API)
    5. Discover SPN credentials (secrets, certificates, federated)
    6. Discover Microsoft Graph API permissions
    7. Discover custom application role assignments
    8. Discover users who have Azure RBAC or Entra roles
    9. Calculate risk levels based on permissions and activity
    10. Check credential expiration status
    11. Check last activity/sign-in status
    12. Save all data to PostgreSQL database
    13. Complete discovery run with summary statistics

Key Features:
    - Async/await pattern for efficient API calls
    - Pagination support for large directories (999 items per page)
    - Microsoft system SPN filtering (custom SPNs start with 'spn-')
    - Risk calculation combining Azure RBAC and Entra roles
    - Credential expiration tracking
    - Activity status detection

Identity Types Discovered:
    - Service Principals (application identities)
    - Users (with Azure RBAC or Entra role assignments)
    - Managed Identities (system and user-assigned)

Risk Level Calculation:
    - CRITICAL: Owner/Contributor on subscription, Global Admin, etc.
    - HIGH: Security Admin, User Access Administrator
    - MEDIUM: Reader roles, custom roles without activity
    - LOW/INFO: Properly scoped, active identities

Usage:
    engine = AzureDiscoveryEngine(azure_directory_id, client_id, client_secret)
    result = engine.run_discovery()

Dependencies:
    - azure-identity: Azure authentication
    - msgraph-sdk: Microsoft Graph API client
    - azure-mgmt-authorization: RBAC role assignment discovery (SDK-based, no CLI)
    - azure-mgmt-resource: Subscription discovery
"""
import os
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set

logger = logging.getLogger(__name__)

# Suppress noisy Azure SDK HTTP-level logging.  Each ARM/Graph request
# logs full request + response at INFO → thousands of lines for large
# tenants.  WARNING level still surfaces auth failures and throttling.
logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.WARNING)
logging.getLogger('azure.identity').setLevel(logging.WARNING)
logging.getLogger('azure.mgmt.authorization').setLevel(logging.WARNING)
logging.getLogger('azure.mgmt.resource').setLevel(logging.WARNING)

import asyncio
import aiohttp

from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient

# ── Graph API timeout constants ──────────────────────────────────────
# Prevents hung network calls from blocking the discovery thread forever.
# total=60s  — absolute max per HTTP request (connect + transfer)
# connect=10s — TCP handshake timeout
# sock_read=30s — max silence between bytes from the server
GRAPH_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=60, connect=10, sock_read=30)

# Timeout for individual Graph SDK (Kiota) calls, in seconds.
GRAPH_SDK_TIMEOUT = 30

# Timeout kwargs for synchronous ARM management clients (SubscriptionClient,
# AuthorizationManagementClient, ResourceGraphClient, KeyVaultManagementClient).
# Azure SDK defaults are 300s each — far too long for a single API call.
ARM_TIMEOUT_KWARGS = {'connection_timeout': 10, 'read_timeout': 30}
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resource import SubscriptionClient
try:
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest
except ImportError:
    ResourceGraphClient = None
    QueryRequest = None
from app.database import Database
from app.constants import Verdict, IdentityCategory
from app.constants.agirs import WORKLOAD_CONFIDENCE_DEFAULT, WORKLOAD_CONFIDENCE_THRESHOLD
from .models import DiscoveryResult
import json

# Well-known dangerous MS Graph Application permission GUIDs
HIGH_RISK_PERMISSION_GUIDS = {
    '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8': 'RoleManagement.ReadWrite.Directory',
    '19dbc75e-c2e2-444c-a770-ec596d67a115': 'Directory.ReadWrite.All',
    'e2a3a72e-5f79-4c64-b005-482f1d733b6b': 'Mail.ReadWrite',
    '75359482-378d-4052-8f01-80520e7db3cd': 'Files.ReadWrite.All',
    '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9': 'Application.ReadWrite.All',
    '741f803b-c850-494e-b5df-cde7c675a1ca': 'User.ReadWrite.All',
    '62a82d76-70ea-41e2-9197-370581804d09': 'Group.ReadWrite.All',
    '06b708a9-e830-4db3-a914-8e69da51d44f': 'AppRoleAssignment.ReadWrite.All',
    '01d4f32e-3f2d-4d15-9825-dc7784652969': 'RoleManagement.Read.Directory',
    '7ab1d382-f21e-4acd-a863-ba3e13f7da61': 'Directory.Read.All',
}

# Microsoft Graph service principal resource ID (for requiredResourceAccess matching)
MS_GRAPH_RESOURCE_ID = '00000003-0000-0000-c000-000000000000'

# Confirmed workload types — hard evidence of active management (module-level)
_CONFIRMED_WORKLOAD_TYPES: frozenset[str] = frozenset({
    'audit_connector', 'cicd_pipeline', 'monitoring_agent',
    'data_pipeline', 'container_workload', 'storage_workload',
    'lab_workload',
})

# ── AG-148: Federated Identity Credential Issuer Type Mapping ─────────
# Maps known issuer URL patterns to issuer_type labels.
# Order matters: first match wins.
FEDERATED_ISSUER_MAP = [
    ('token.actions.githubusercontent.com', 'github_actions'),
    ('app.terraform.io', 'terraform_cloud'),
    ('vstoken.dev.azure.com', 'azure_devops'),
    ('accounts.google.com', 'google_workload'),
    ('sts.windows.net', 'azure_managed_identity'),
    ('login.microsoftonline.com', 'azure_managed_identity'),
]

def _classify_issuer_type(issuer: str) -> str:
    """Classify a federated credential issuer URL into a known type."""
    issuer_lower = (issuer or '').lower()
    for pattern, issuer_type in FEDERATED_ISSUER_MAP:
        if pattern in issuer_lower:
            return issuer_type
    return 'external_oidc'

# ── Access Tier Classification Constants ─────────────────────────────
# Control-plane role keywords (case-insensitive substring)
_CONTROL_PLANE_KEYWORDS = frozenset({'owner', 'contributor', 'administrator', 'manager', 'operator'})

# Data-plane-only roles (exact match, lowered)
_DATA_PLANE_ROLES = frozenset({
    'storage file data smb share reader',
    'storage file data smb share contributor',
    'storage file data smb share elevated contributor',
    'storage file data privileged contributor',
    'storage file data privileged reader',
    'storage blob data reader',
    'storage blob data contributor',
    'storage blob data owner',
    'storage queue data reader',
    'storage queue data contributor',
    'storage queue data message sender',
    'storage queue data message processor',
    'storage table data reader',
    'storage table data contributor',
    'key vault secrets user',
    'key vault certificates user',
    'key vault crypto user',
    'key vault reader',
    'virtual machine user login',
    'desktop virtualization user',
    'desktop virtualization session host operator',
})

# Scope types that indicate broad visibility → always control_plane
_CONTROL_PLANE_SCOPES = frozenset({'subscription', 'management_group'})

# PHI/PII indicators in resource/group names → upgrade to control_plane
_SENSITIVE_DATA_INDICATORS = frozenset({'phi', 'pii', 'hipaa', 'health', 'patient', 'ssn', 'confidential'})


def load_tenant_lab_patterns(db, tenant_id) -> tuple:
    """Load lab name patterns: tenant settings > platform_settings > empty tuple.

    Never raises — returns () if config is missing so discovery continues.
    """
    try:
        # Priority 1: per-tenant setting  (settings table, org-scoped)
        val = db.get_setting('lab_name_patterns', organization_id=tenant_id)
        if val:
            import json as _json
            parsed = _json.loads(val)
            if isinstance(parsed, list) and parsed:
                return tuple(parsed)

        # Priority 2: platform-wide default  (platform_settings table)
        cursor = db.conn.cursor()
        cursor.execute(
            "SELECT value FROM platform_settings WHERE key = 'lab_name_patterns'"
        )
        row = cursor.fetchone()
        cursor.close()
        if row and row[0]:
            import json as _json
            parsed = _json.loads(row[0])
            if isinstance(parsed, list) and parsed:
                return tuple(parsed)
    except Exception:
        pass  # fail open — never block discovery over config lookup failure
    return ()

class ScanTimeoutError(Exception):
    """Raised when a scan exceeds its time budget."""
    pass


MAX_SCAN_MINUTES = 45


class AzureDiscoveryEngine:
    """
    Orchestrates Azure identity discovery across Microsoft Graph and Azure RM.

    This engine connects to Azure using service principal credentials and discovers
    all identities (SPNs, users, managed identities), their role assignments,
    credentials, and permissions. It calculates risk levels and stores everything
    in PostgreSQL for dashboard display.

    Attributes:
        azure_directory_id: Azure AD / Entra directory ID
        client_id: Service principal application ID for authentication
        client_secret: Service principal secret for authentication
        db: Database instance for storing discovery results
        graph_client: Microsoft Graph SDK client
        subscription_id: Target Azure subscription ID
        subscription_name: Human-readable subscription name
    """

    def __init__(self, azure_directory_id: str, client_id: str, client_secret: str,
                 db_org_id=None, cloud_connection_id: int = None):
        """
        Initialize the discovery engine with Azure credentials.

        Args:
            azure_directory_id: Azure AD / Entra directory ID
            client_id: Service principal application ID
            client_secret: Service principal client secret
            db_org_id: AuditGraph organization ID (integer) for RLS context
            cloud_connection_id: ID from cloud_connections table (for multi-connection support)
        """
        if cloud_connection_id is None:
            raise ValueError("cloud_connection_id is required for discovery")
        if db_org_id is None:
            raise ValueError("db_org_id is required for discovery")

        self.azure_directory_id = azure_directory_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.db_org_id = db_org_id
        self.cloud_connection_id = cloud_connection_id
        logger.info(
            "AzureDiscovery initialized: org_id=%s connection_id=%s tenant=%s",
            self.db_org_id, self.cloud_connection_id, self.azure_directory_id
        )
        self.db = Database(organization_id=db_org_id)

        # Concurrency control: max 20 concurrent Graph API calls
        self._graph_semaphore = asyncio.Semaphore(20)
        # Time budget tracking (set at scan start)
        self._scan_start_time: float | None = None

        self.credential = ClientSecretCredential(
            tenant_id=azure_directory_id,
            client_id=client_id,
            client_secret=client_secret,
            connection_timeout=10,
            read_timeout=30,
        )
        # AG-116: zero after SDK credential init — prevent memory retention
        self.client_secret = None
        client_secret = None

        self.graph_client = GraphServiceClient(
            credentials=self.credential,
            scopes=['https://graph.microsoft.com/.default']
        )

        # Auto-discover all accessible subscriptions, partitioned by tenant
        all_subs = self._discover_subscriptions()
        native_subs = [s for s in all_subs if s.get('tenant_id') == self.azure_directory_id]
        self.foreign_subscriptions = [s for s in all_subs if s.get('tenant_id') != self.azure_directory_id]
        if self.foreign_subscriptions:
            logger.info("Found %s subscription(s) from other tenants", len(self.foreign_subscriptions))

        # Filter to only ACTIVATED (monitored) subscriptions — the user chose which
        # subscriptions to scan in the UI.  If no cloud_subscriptions rows exist yet
        # (very first connection), eagerly sync ALL discovered subscriptions to
        # cloud_subscriptions so the UI can display them, then auto-activate the
        # first one so the scan doesn't iterate all N subscriptions (which can
        # take 76+ min for tenants with 10+ idle subs).
        monitored_ids = self._get_monitored_subscription_ids()
        if monitored_ids is not None:
            before = len(native_subs)
            self.subscriptions = [s for s in native_subs if s['id'] in monitored_ids]
            skipped = before - len(self.subscriptions)
            if skipped:
                logger.info("Filtered to %s activated subscription(s), skipping %s inactive", len(self.subscriptions), skipped)
        else:
            # First scan — eagerly sync subscriptions to registry + auto-activate first
            logger.info("First scan: syncing %s discovered subscription(s) to registry", len(native_subs))
            first_activated = None
            for idx, sub in enumerate(native_subs):
                try:
                    cursor = self.db.conn.cursor()
                    # Auto-activate the first subscription so the initial scan is fast
                    is_first = (idx == 0)
                    cursor.execute("""
                        INSERT INTO cloud_subscriptions
                            (organization_id, cloud, account_id, account_name, status,
                             cloud_connection_id, monitored)
                        VALUES (%s, 'azure', %s, %s, %s, %s, %s)
                        ON CONFLICT (cloud_connection_id, account_id) DO NOTHING
                    """, (
                        db_org_id, sub['id'], sub['name'],
                        'active' if is_first else 'discovered',
                        self.cloud_connection_id,
                        is_first,
                    ))
                    self.db._commit()
                    cursor.close()
                    if is_first:
                        first_activated = sub
                except Exception as e:
                    logger.warning("Early subscription sync failed for %s: %s", sub['name'], e)
                    try:
                        self.db._rollback()
                    except Exception:
                        pass
            if first_activated:
                self.subscriptions = [first_activated]
                logger.info("Auto-activated first subscription: %s (%s)",
                            first_activated['name'], first_activated['id'][:8])
            else:
                self.subscriptions = native_subs

        sub_names = [f"{s['name']} ({s['id'][:8]}...)" for s in self.subscriptions]
        logger.info("Discovery Engine initialized for %s subscription(s): %s", len(self.subscriptions), ', '.join(sub_names) or 'none')

        # Cache resource SPN appRoles to avoid repeated API calls
        # Key: resource_spn_id, Value: dict mapping appRoleId -> role value
        self._resource_spn_cache: Dict[str, Dict[str, str]] = {}

        # ── Pipeline health metrics counters ──
        # Populated during discovery for pipeline_stage_metrics collection.
        self._entra_roles_fetched: int = 0
        self._entra_roles_matched: int = 0
        self._entra_roles_saved: int = 0
        self._entra_roles_failed: int = 0
        self._role_assignments_fetched: int = 0
        self._role_assignments_saved: int = 0
        self._credentials_fetched: int = 0
        self._credentials_saved: int = 0
        self._app_registrations_fetched: int = 0
        self._app_registrations_saved: int = 0
        self._all_principal_count: int = 0

    def _check_time_budget(self, phase_name: str) -> bool:
        """Check if the scan has exceeded its time budget.
        Returns True if budget exceeded (caller should skip remaining phases).
        """
        if self._scan_start_time is None:
            return False
        import time
        elapsed_minutes = (time.monotonic() - self._scan_start_time) / 60
        if elapsed_minutes > MAX_SCAN_MINUTES:
            logger.error(
                "[scan] TIME BUDGET EXCEEDED at phase '%s' after %.1fmin — "
                "skipping remaining discovery phases org=%s",
                phase_name, elapsed_minutes, self.db_org_id
            )
            return True
        return False

    def _update_job_progress(self, stage, progress, discovery_run_id=None):
        """Report progress to snapshot_jobs with per-stage timing.

        Tracks stage_timings JSONB: {stage: {started: epoch, elapsed: secs}}
        and computes estimated_remaining_seconds from progress rate.
        Non-fatal on failure.
        """
        import time as _t
        job_id = getattr(self, 'snapshot_job_id', None)
        if not job_id:
            return

        # Track per-stage timing in memory
        now = _t.monotonic()
        if not hasattr(self, '_stage_timings'):
            self._stage_timings = {}
            self._stage_start_wall = {}
        prev_stage = getattr(self, '_current_stage', None)
        if prev_stage and prev_stage != stage and prev_stage in self._stage_timings:
            # Close previous stage
            self._stage_timings[prev_stage]['elapsed'] = round(
                now - self._stage_timings[prev_stage]['_mono_start'], 1
            )
        if stage not in self._stage_timings:
            self._stage_timings[stage] = {
                'started': _t.time(),
                '_mono_start': now,
                'elapsed': 0,
            }
        self._current_stage = stage

        # Build serializable timings dict (strip internal _mono_start)
        timings_json = {
            k: {'started': round(v['started'], 1), 'elapsed': round(v.get('elapsed', now - v['_mono_start']), 1)}
            for k, v in self._stage_timings.items()
        }

        # ETA: estimated remaining seconds from progress rate
        scan_start = self._scan_start_time or now
        elapsed_total = max(now - scan_start, 1)
        eta = None
        if progress > 5:
            rate = progress / elapsed_total  # % per second
            remaining_pct = 100 - progress
            eta = max(0, int(remaining_pct / rate))

        try:
            cursor = self.db.conn.cursor()
            try:
                import json as _json
                if discovery_run_id is not None:
                    cursor.execute("""
                        UPDATE snapshot_jobs
                        SET stage = %s, progress = %s, discovery_run_id = %s,
                            last_heartbeat_at = NOW(),
                            duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at))::integer,
                            stage_timings = %s,
                            estimated_remaining_seconds = %s
                        WHERE id = %s AND status = 'running'
                    """, (stage, progress, discovery_run_id,
                          _json.dumps(timings_json), eta, job_id))
                else:
                    cursor.execute("""
                        UPDATE snapshot_jobs
                        SET stage = %s, progress = %s, last_heartbeat_at = NOW(),
                            duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at))::integer,
                            stage_timings = %s,
                            estimated_remaining_seconds = %s
                        WHERE id = %s AND status = 'running'
                    """, (stage, progress, _json.dumps(timings_json), eta, job_id))
                self.db._force_commit()  # Always commit progress updates (even in batch mode)
            except Exception as e:
                logger.warning("Job progress update failed: %s", e)
                try:
                    self.db._rollback()
                except Exception:
                    pass
            finally:
                cursor.close()
        except Exception as e:
            logger.warning("Job progress update failed (outer): %s", e)

    def _update_job_metrics(self, identities=0, resources=0, subscriptions=0):
        """Update discovered counts on snapshot job. Non-fatal on failure.

        Inline UPDATE instead of delegating to db.update_snapshot_job_metrics()
        which does its own _commit() that would conflict with caller's
        transaction management.
        """
        job_id = getattr(self, 'snapshot_job_id', None)
        if not job_id:
            return
        try:
            cursor = self.db.conn.cursor()
            try:
                cursor.execute("""
                    UPDATE snapshot_jobs
                    SET identities_discovered = %s,
                        resources_discovered = %s,
                        subscriptions_discovered = %s,
                        duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at))::integer
                    WHERE id = %s
                """, (identities, resources, subscriptions, job_id))
                self.db._commit()
            except Exception as e:
                logger.warning("Job metrics update failed: %s", e)
                try:
                    self.db._rollback()
                except Exception:
                    pass
            finally:
                cursor.close()
        except Exception:
            pass

    def _get_monitored_subscription_ids(self) -> Optional[Set[str]]:
        """Query cloud_subscriptions for activated (monitored=true) subscription IDs.

        Returns:
            Set of subscription IDs that are monitored, or None if no
            cloud_subscriptions rows exist yet for this connection (first run).
        """
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                SELECT account_id, monitored FROM cloud_subscriptions
                WHERE cloud_connection_id = %s AND deleted = false
            """, (self.cloud_connection_id,))
            rows = cursor.fetchall()
            cursor.close()
            if not rows:
                return None  # no rows yet — first connection, scan all
            monitored = set()
            for r in rows:
                aid = r[0] if not isinstance(r, dict) else r.get('account_id')
                mon = r[1] if not isinstance(r, dict) else r.get('monitored')
                if mon:
                    monitored.add(aid)
            return monitored
        except Exception as e:
            logger.warning("Failed to query monitored subscriptions: %s", e)
            return None  # fail-open: scan all

    def _discover_subscriptions(self) -> List[Dict[str, str]]:
        """Auto-discover all Azure subscriptions accessible to the service principal.

        IMPORTANT: Never falls back to env vars in multi-org mode — each organization's
        SPN must have RBAC access to their own subscriptions.

        Each subscription's tenant_id is preserved exactly as reported by Azure.
        Subscriptions with a different tenant_id than the source connection are
        classified as cross-tenant and routed to their own cloud_connection.
        """
        try:
            sub_client = SubscriptionClient(self.credential, **ARM_TIMEOUT_KWARGS)
            subs = []
            for sub in sub_client.subscriptions.list():
                if sub.state and sub.state.lower() in ('enabled', 'warned'):
                    sub_tenant = sub.tenant_id
                    # Only fall back to source tenant if Azure SDK truly returned None
                    # (very rare — most subscriptions report tenant_id)
                    if not sub_tenant:
                        sub_tenant = self.azure_directory_id
                    elif sub_tenant != self.azure_directory_id:
                        logger.info("Detected cross-tenant subscription: %s (%s...) -> tenant %s...", sub.display_name, sub.subscription_id[:8], sub_tenant[:8])
                    subs.append({
                        'id': sub.subscription_id,
                        'name': sub.display_name or sub.subscription_id,
                        'tenant_id': sub_tenant,
                    })
            if not subs:
                logger.warning("No Azure subscriptions found -- SPN needs Reader RBAC on at least one subscription")
            return subs
        except Exception as e:
            logger.warning("Subscription discovery failed: %s", e)
            return []

    def run_discovery(self) -> DiscoveryResult:
        """
        Execute the full discovery process synchronously.

        This is the main entry point that wraps the async discovery
        in asyncio.run() for synchronous calling contexts (like the scheduler).

        Creates a fresh event loop for the current thread if one doesn't exist,
        which is required for Python 3.10+ where daemon threads do not
        auto-create an event loop.

        Returns:
            DiscoveryResult or None on completion
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError("closed")
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        try:
            return loop.run_until_complete(self._async_run_discovery())
        finally:
            try:
                loop.close()
            except Exception:
                pass

    async def _async_run_discovery(self) -> DiscoveryResult:
        import time as _time
        self._scan_start_time = _time.monotonic()

        sub_summary = ", ".join(f"{s['name']} ({s['id'][:8]}...)" for s in self.subscriptions) or "No subscriptions"
        logger.info("=" * 60)
        logger.info("AuditGraph Discovery Engine")
        logger.info("=" * 60)
        logger.info("Subscriptions: %s", sub_summary)
        logger.info("Started: %s UTC", datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
        
        # Create discovery run using Database class method
        logger.info("Creating discovery run...")
        # Store all subscription IDs as comma-separated for the run record
        all_sub_ids = ",".join(s['id'] for s in self.subscriptions) if self.subscriptions else os.getenv('AZURE_SUBSCRIPTION_ID', '')
        all_sub_names = ", ".join(s['name'] for s in self.subscriptions) if self.subscriptions else os.getenv('AZURE_SUBSCRIPTION_NAME', 'Unknown')
        run_id = self.db.create_discovery_run(all_sub_ids, all_sub_names,
                                               cloud_connection_id=self.cloud_connection_id)
        logger.info("Discovery run created (ID: %s)", run_id)
        self._update_job_progress('initializing', 5, discovery_run_id=run_id)
        self._update_job_metrics(subscriptions=len(self.subscriptions))

        # Capture scanner's own public IP (assigned to discovery SPN in IP enrichment)
        self._scanner_ip = None
        try:
            import aiohttp as _aio
            async with _aio.ClientSession(timeout=_aio.ClientTimeout(total=5)) as _ip_session:
                async with _ip_session.get(
                    'https://api.ipify.org?format=json',
                    timeout=_aio.ClientTimeout(total=5)
                ) as _ip_resp:
                    if _ip_resp.status == 200:
                        _ip_data = await _ip_resp.json()
                        self._scanner_ip = _ip_data.get('ip')
                        logger.info("Scanner public IP: %s", self._scanner_ip)
        except Exception as e:
            logger.debug("Could not detect scanner public IP: %s", e)

        # Step 1: Get role assignments FIRST
        logger.info("Discovering Role Assignments...")
        self._update_job_progress('discovering_roles', 10)
        role_assignments = self._discover_role_assignments()
        logger.info("Found %s role assignments", len(role_assignments))

        # Step 1.5: Enrich Key Vault metadata from role assignment scopes
        try:
            self._enrich_keyvault_metadata(role_assignments)
        except Exception as e:
            logger.warning("Key Vault metadata enrichment error: %s", e)
            self.db._rollback()

        # Step 2: Extract principal IDs that have roles
        principal_ids_with_roles = set(ra['principal_id'] for ra in role_assignments)
        logger.info("Found %s unique principals with roles", len(principal_ids_with_roles))

        # Step 2.5: Discover Entra ID directory roles
        logger.info("Discovering Entra ID Directory Roles...")
        self._update_job_progress('discovering_roles', 18)
        entra_roles = await self._discover_entra_roles()

        # Merge principal IDs from both Azure RBAC and Entra roles
        entra_principal_ids = set(er['principal_id'] for er in entra_roles)
        all_principal_ids = principal_ids_with_roles.union(entra_principal_ids)
        logger.info("Total unique principals (RBAC + Entra): %s", len(all_principal_ids))

        # ── Scan component status tracking ──
        scan_component_status = {
            "service_principals": "pending",
            "users": "pending",
            "groups": "pending",
            "memberships": "pending",
            "roles": "success",  # already completed above
        }
        # Defaults — used if timeout fires before a phase runs
        service_principals = []
        users = []
        groups = []
        group_memberships = {}
        total_memberships = 0
        relevant_group_ids: Set[str] = set()
        two_tier_active = False
        control_count = 0
        data_count = 0
        self._data_plane_findings = []
        _scan_timed_out = False

        def _mark_remaining_timeout():
            """Mark all pending components as timeout."""
            nonlocal _scan_timed_out
            _scan_timed_out = True
            for k, v in scan_component_status.items():
                if v == "pending":
                    scan_component_status[k] = "timeout"

        # Step 3: Discover Service Principals
        logger.info("Discovering Service Principals...")
        self._update_job_progress('discovering_identities', 25)
        service_principals = await self._discover_service_principals()
        scan_component_status["service_principals"] = "success"
        logger.info("Found %s service principals", len(service_principals))

        # Step 3.1: Link SPNs to parent App Registrations (lineage)
        app_reg_map = await self._fetch_app_registration_map()
        self._enrich_spns_with_app_registrations(service_principals, app_reg_map)

        # Steps 3.5–3.12: Parallel Graph API discovery
        # Credentials must finish first (federated enrichment depends on it),
        # then remaining steps run concurrently via asyncio.gather().
        logger.info("[parallel-discovery] Starting parallel SPN enrichment (7 concurrent tasks, owned_objects deferred)...")
        import time as _perf_time
        _parallel_start = _perf_time.monotonic()

        # Steps 3.5–3.11: ALL run concurrently (credentials moved into gather)
        # Federated enrichment (step 3.55) runs after gather since it depends on credentials.
        # NOTE: _discover_owned_objects (step 3.12) deferred to background post-scan job.
        async def _timed(name, coro):
            t0 = _perf_time.monotonic()
            result = await coro
            elapsed = round(_perf_time.monotonic() - t0, 1)
            logger.info("[parallel-discovery] %s finished in %.1fs", name, elapsed)
            return result

        (
            credentials_map,
            permissions_map,
            app_roles_map,
            ownership_map,
            pim_map,
            ca_policies,
            _audit_prov_result,
        ) = await asyncio.gather(
            _timed("credentials", self._discover_credentials(service_principals)),      # 3.5
            _timed("permissions", self._discover_permissions(service_principals)),       # 3.6
            _timed("app_roles", self._discover_app_roles(service_principals)),           # 3.7
            _timed("ownership", self._discover_ownership(service_principals)),           # 3.8
            _timed("pim", self._discover_pim_assignments()),                             # 3.9
            _timed("conditional_access", self._discover_conditional_access()),           # 3.10
            _timed("audit_provenance", self._discover_audit_provenance(service_principals)),  # 3.11
        )
        self._update_job_progress('discovering_identities', 35)
        _parallel_elapsed = round(_perf_time.monotonic() - _parallel_start, 1)
        logger.info(
            "[parallel-discovery] SPN enrichment complete in %.1fs (7 tasks) org=%s",
            _parallel_elapsed, self.db_org_id,
        )

        # Step 3.55: Enrich SPNs with federated credential classification (depends on credentials_map)
        fed_count = 0
        for sp in service_principals:
            creds = credentials_map.get(sp.get('identity_id'), [])
            fed_creds = [c for c in creds if c.get('credential_type') == 'federated']
            if fed_creds:
                best = fed_creds[0]
                sp['federated_workload_type'] = best.get('federated_workload_type')
                sp['federated_workload_name'] = best.get('federated_workload_name')
                fed_count += 1
        if fed_count:
            logger.info("Federated credential classification: %s SPNs enriched", fed_count)

        if self._check_time_budget("service_principals"):
            _mark_remaining_timeout()

        # Step 4: Discover Entra Groups (moved before users for AG-75 inclusion criteria)
        if not _scan_timed_out:
            logger.info("Discovering Entra Groups...")
            self._update_job_progress('discovering_groups', 38)
            try:
                groups = await self._discover_groups()
                scan_component_status["groups"] = "success"
            except Exception as e:
                logger.error("[scan] groups FAILED org=%s error=%s", self.db_org_id, e, exc_info=True)
                scan_component_status["groups"] = "failed"
                groups = []
            logger.info("Found %s security groups", len(groups))
            if self._check_time_budget("groups"):
                _mark_remaining_timeout()

        # Step 4b: Discover Group Memberships (two-tier with pre-flight)
        # Tier 1: Groups with RBAC or Entra roles → full Graph API expansion
        # Tier 2: Remaining groups → populated by identity-centric memberOf (Step 5c)
        # Pre-flight: test memberOf permission before committing to two-tier.
        #             If memberOf returns 403 → fall back to expanding ALL groups.
        if not _scan_timed_out:
            try:
                group_id_set_all = {g['group_id'] for g in groups}

                # Compute relevant (role-bearing) group IDs
                relevant_group_ids = set()
                for ra in role_assignments:
                    pid = ra.get('principal_id')
                    if pid and pid in group_id_set_all:
                        relevant_group_ids.add(pid)
                for er in entra_roles:
                    pid = er.get('principal_id')
                    if pid and pid in group_id_set_all:
                        relevant_group_ids.add(pid)

                # Pre-flight: test memberOf permission
                memberof_ok = await self._check_memberof_permission()
                two_tier_active = memberof_ok

                if memberof_ok:
                    logger.info(
                        "[two-tier] memberOf pre-flight PASSED. "
                        "%d/%d groups have roles → Tier 1 expansion. "
                        "%d groups → Tier 2 (memberOf in Step 5c). org=%s",
                        len(relevant_group_ids), len(groups),
                        len(groups) - len(relevant_group_ids), self.db_org_id,
                    )
                    group_memberships = await self._discover_group_memberships(
                        groups, relevant_group_ids=relevant_group_ids,
                    )
                else:
                    logger.info(
                        "[two-tier] memberOf pre-flight FAILED (403). "
                        "Falling back to full expansion of all %d groups. org=%s",
                        len(groups), self.db_org_id,
                    )
                    group_memberships = await self._discover_group_memberships(
                        groups,
                    )
                self._update_job_progress('discovering_groups', 40)
                total_memberships = sum(len(v) for v in group_memberships.values())
                scan_component_status["memberships"] = "success"
            except Exception as e:
                logger.error("[scan] memberships FAILED org=%s error=%s", self.db_org_id, e, exc_info=True)
                scan_component_status["memberships"] = "failed"

        # Step 4c: Collect relevant principal IDs (AG-75 inclusion criteria)
        all_principal_ids = self._collect_relevant_principal_ids(
            role_assignments, entra_roles, pim_map,
            groups, group_memberships, ownership_map, ca_policies,
            service_principals
        )

        # Step 4d: Pure access-based filter for user discovery.
        # Include a principal if and only if it has an access path to Azure
        # or Entra — directly or via a security group.
        #
        # PATH 1 — Direct RBAC on monitored subscriptions
        # PATH 2 — Direct Entra directory role
        # PATH 3 — Member of a security group with RBAC on monitored subs
        # PATH 4 — Member of a security group with an Entra directory role
        #
        # No name patterns. No type assumptions. Access paths only.
        # _collect_relevant_principal_ids() still builds full access_paths
        # for all 6 sources (PIM, ownership, CA) — used for graph and risk
        # scoring on any identity that qualifies via the 4 paths above.

        group_id_set_for_filter = {g['group_id'] for g in groups}
        access_qualified_ids = set()   # non-group principals with direct roles
        privileged_group_ids = set()   # groups that hold roles

        # Scan RBAC role assignments (already scoped to monitored subscriptions)
        for ra in role_assignments:
            pid = ra.get('principal_id')
            if pid:
                if pid in group_id_set_for_filter:
                    privileged_group_ids.add(pid)
                else:
                    access_qualified_ids.add(pid)

        # Scan Entra directory role assignments
        for er in entra_roles:
            pid = er.get('principal_id')
            if pid:
                if pid in group_id_set_for_filter:
                    privileged_group_ids.add(pid)
                else:
                    access_qualified_ids.add(pid)

        # Expand members of privileged groups.
        # _discover_group_memberships() already resolves nested groups
        # (MAX_DEPTH=3), so nested members appear with is_nested=True.
        # We include ALL member types from privileged groups — the
        # intersection with all_principal_ids below ensures only
        # validated principals pass through.
        for gid in privileged_group_ids:
            for member in group_memberships.get(gid, []):
                mid = member.get('member_object_id')
                mtype = member.get('member_type', '')
                if mid and mtype != 'group':
                    access_qualified_ids.add(mid)

        # Intersect with all_principal_ids (defensive — ensures every ID
        # was validated by _collect_relevant_principal_ids and has
        # access_paths populated).
        user_principal_ids = all_principal_ids & access_qualified_ids
        # Pipeline health: record total principal count for metrics
        self._all_principal_count = len(user_principal_ids)

        direct_rbac_count = sum(
            1 for pid in user_principal_ids
            if (getattr(self, '_principal_access_paths', {}).get(pid, {}).get('direct_rbac'))
        )
        direct_entra_count = sum(
            1 for pid in user_principal_ids
            if (getattr(self, '_principal_access_paths', {}).get(pid, {}).get('direct_entra'))
        )
        via_group_count = sum(
            1 for pid in user_principal_ids
            if (getattr(self, '_principal_access_paths', {}).get(pid, {}).get('group_membership'))
        )
        logger.info(
            "[access-filter] Qualified principals: %d "
            "(direct_rbac=%d, direct_entra=%d, via_group=%d) "
            "from %d total candidates, %d privileged groups expanded",
            len(user_principal_ids),
            direct_rbac_count, direct_entra_count, via_group_count,
            len(all_principal_ids), len(privileged_group_ids),
        )

        # Step 5: Discover users (scoped to access-qualified principals)
        if not _scan_timed_out:
            logger.info("Discovering Users...")
            try:
                users = await self._discover_users(user_principal_ids)
                scan_component_status["users"] = "success"
            except Exception as e:
                logger.error(
                    "[scan] users FAILED org=%s error=%s",
                    self.db_org_id, e, exc_info=True
                )
                scan_component_status["users"] = "failed"
                users = []
            logger.info(
                "Found %s users (from %s access-qualified principals, %s total candidates)",
                len(users), len(user_principal_ids), len(all_principal_ids),
            )

            # Sanity check: if we had principals to find but got 0 users
            if len(user_principal_ids) > 10 and len(users) == 0:
                logger.error(
                    "[scan] ANOMALY: %s access-qualified principals but 0 users "
                    "for org=%s tenant=%s. Check throttling/permissions/pagination.",
                    len(user_principal_ids), self.db_org_id, self.azure_directory_id
                )

            # Post-discovery validation: remove any human_user whose
            # access_paths contain zero RBAC, Entra, or group-inherited
            # access.  This is a safety net for edge cases the pre-filter
            # might miss (e.g. stale group data, race conditions).
            pre_validation = len(users)
            validated_users = []
            for u in users:
                ap = u.get('access_paths') or {}
                has_rbac = bool(ap.get('direct_rbac'))
                has_entra = bool(ap.get('direct_entra'))
                has_group = any(
                    gm.get('role', '') != ''
                    for gm in (ap.get('group_membership') or [])
                )
                if has_rbac or has_entra or has_group:
                    validated_users.append(u)
            removed = pre_validation - len(validated_users)
            if removed > 0:
                logger.warning(
                    "[access-filter] Post-validation removed %d human_user(s) "
                    "with no RBAC/Entra/group access (org=%s)",
                    removed, self.db_org_id,
                )
            users = validated_users

            # Step 4e: Access tier classification for human users
            for u in users:
                u['access_tier'] = self._classify_access_tier(u, role_assignments, entra_roles, group_memberships)

            control_count = sum(1 for u in users if u.get('access_tier') == 'control_plane')
            data_count = sum(1 for u in users if u.get('access_tier') == 'data_plane')
            logger.info(
                "Access tier: %d control_plane, %d data_plane (of %d humans) org=%s",
                control_count, data_count, len(users), self.db_org_id,
            )

            # Step 4f: Generate BROAD_DATA_PLANE_ACCESS findings for large groups
            data_plane_findings = []
            group_lookup = {g['group_id']: g for g in groups}

            group_dp_stats = {}  # group_id → {name, roles, scopes, member_count}
            for ra in role_assignments:
                pid = ra.get('principal_id')
                if pid and pid in group_lookup:
                    role_lower = (ra.get('role_name') or '').lower()
                    if role_lower in _DATA_PLANE_ROLES:
                        if pid not in group_dp_stats:
                            grp = group_lookup[pid]
                            group_dp_stats[pid] = {
                                'name': grp.get('display_name', ''),
                                'roles': set(), 'scopes': set(),
                                'member_count': grp.get('member_count', 0),
                            }
                        group_dp_stats[pid]['roles'].add(ra.get('role_name', ''))
                        rn = ra.get('resource_name') or ra.get('scope', '').rsplit('/', 1)[-1]
                        group_dp_stats[pid]['scopes'].add(rn)

            for gid, st in group_dp_stats.items():
                if st['member_count'] >= 100:
                    roles_str = ', '.join(sorted(st['roles']))
                    resources_str = ', '.join(sorted(list(st['scopes'])[:3]))
                    data_plane_findings.append({
                        'entity_type': 'security_group',
                        'entity_id': gid,
                        'finding_type': 'BROAD_DATA_PLANE_ACCESS',
                        'severity': 'medium',
                        'risk_score': min(st['member_count'] // 10, 100),
                        'title': f"Group '{st['name']}' grants {roles_str} to {st['member_count']} users",
                        'description': (
                            f"{st['member_count']} users have {roles_str} access to "
                            f"{resources_str} via group membership. Review if all members "
                            f"require this access."
                        ),
                        'recommended_fix': "Audit group membership and remove users who no longer need access.",
                        'metadata': {
                            'group_name': st['name'], 'group_id': gid,
                            'member_count': st['member_count'],
                            'roles': list(st['roles']), 'resources': list(st['scopes']),
                        },
                        'finding_fingerprint': f"broad_data_plane_{gid}",
                    })

            self._data_plane_findings = data_plane_findings
            if data_plane_findings:
                logger.info("Generated %d BROAD_DATA_PLANE_ACCESS findings org=%s",
                            len(data_plane_findings), self.db_org_id)

            self._update_job_progress('discovering_identities', 42)
            if self._check_time_budget("users"):
                _mark_remaining_timeout()

        # Step 5.5: Discover Managed Identities
        logger.info("Discovering Managed Identities...")
        managed_identities = []
        logger.info("Found %s user-assigned managed identities", len(managed_identities))

        all_identities = service_principals + users + managed_identities

        # Step 5c: Identity-centric memberOf enrichment (Tier 2 gap-fill)
        # Only needed when two-tier is active — Tier 2 groups have no memberships
        # from Step 4b and need identity-centric memberOf to populate them.
        # When two_tier_active=False, all groups were fully expanded in Step 4b.
        if not _scan_timed_out and two_tier_active:
            # Pre-flight: verify memberOf permission before calling per-identity
            memberof_5c_ok = await self._check_memberof_permission()
            if memberof_5c_ok:
                try:
                    tier2_count = len(groups) - len(relevant_group_ids)
                    logger.info(
                        "[Step 5c] Running identity-centric memberOf enrichment "
                        "for %d Tier 2 groups (%d identities). org=%s",
                        tier2_count, len(all_identities), self.db_org_id,
                    )
                    group_memberships = await self._discover_identity_group_memberships(
                        all_identities, groups, group_memberships
                    )
                    total_memberships = sum(len(v) for v in group_memberships.values())
                except Exception as e:
                    logger.error("[Step 5c] identity memberOf enrichment FAILED org=%s error=%s",
                                self.db_org_id, e, exc_info=True)
            else:
                logger.warning(
                    "[Step 5c] memberOf pre-flight FAILED (403) — skipping "
                    "identity-centric enrichment. Groups tab will show Tier 1 "
                    "data only (%d role-bearing groups). org=%s",
                    len(relevant_group_ids), self.db_org_id,
                )
        elif not _scan_timed_out and not two_tier_active:
            logger.info(
                "[Step 5c] SKIPPED — two-tier inactive, all %d groups "
                "already expanded in Step 4b. org=%s",
                len(groups), self.db_org_id,
            )

        groups_with_members = sum(1 for v in group_memberships.values() if v)
        logger.info("After memberOf enrichment: %s groups with members, %s total memberships",
                    groups_with_members, total_memberships)

        # Membership validation
        if len(groups) > 0 and total_memberships == 0:
            logger.warning(
                "[scan] ANOMALY: %s groups discovered but 0 memberships "
                "org=%s — group member API may have failed or groups are empty",
                len(groups), self.db_org_id
            )
            if scan_component_status["memberships"] == "success":
                scan_component_status["memberships"] = "empty"

        # Step 5d: Compute member/nested counts (rbac_roles populated at save time
        # from the canonical role_assignments list to avoid JSONB drift — FIX A)
        from app.constants.roles import RBACRole
        PRIVILEGED_ROLES = {
            RBACRole.OWNER, RBACRole.CONTRIBUTOR, RBACRole.USER_ACCESS_ADMIN,
            RBACRole.RBAC_ADMIN,
            RBACRole.KEY_VAULT_ADMIN, RBACRole.STORAGE_ACCOUNT_CONTRIBUTOR,
        }
        # Build group_id→roles index from the canonical ARM role_assignments list
        group_id_set = {g['group_id'] for g in groups}
        group_role_index: Dict[str, list] = {}
        for ra in role_assignments:
            pid = ra.get('principal_id')
            if pid in group_id_set:
                group_role_index.setdefault(pid, []).append(ra)

        for group in groups:
            grp_roles = group_role_index.get(group['group_id'], [])
            group['rbac_roles'] = [
                {'role_name': r['role_name'], 'scope': r.get('scope', ''), 'scope_type': r.get('scope_type', '')}
                for r in grp_roles
            ]
            group['is_privileged'] = any(r['role_name'] in PRIVILEGED_ROLES for r in grp_roles)
            members_list = group_memberships.get(group['group_id'], [])
            group['member_count'] = len([m for m in members_list if m['depth'] == 0])
            group['nested_group_count'] = len([m for m in members_list if m['member_type'] == 'group' and m['depth'] == 0])
        logger.info("Privileged groups: %s", sum(1 for g in groups if g['is_privileged']))

        # Step 5e: Collect MFA/SSPR registration data (bulk, then per-user fallback)
        if not _scan_timed_out:
            mfa_map = {}
            try:
                mfa_map = await self._collect_mfa_registration()
            except Exception as e:
                logger.warning("[MFA] Bulk collection failed: %s. org=%s", e, self.db_org_id)

            if mfa_map:
                mfa_applied = 0
                for identity in all_identities:
                    oid = identity.get('object_id')
                    if oid and oid in mfa_map:
                        reg = mfa_map[oid]
                        if reg.get('mfa_registered') is not None:
                            identity['ca_mfa_enforced'] = reg['mfa_registered']
                            identity['mfa_status'] = 'enrolled' if reg['mfa_registered'] else 'not_enrolled'
                            methods = []
                            if reg.get('mfa_registered'):
                                methods.append('mfa')
                            if reg.get('sspr_registered'):
                                methods.append('sspr')
                            if methods:
                                identity['mfa_methods'] = methods
                            mfa_applied += 1
                logger.info(
                    "[MFA] Applied bulk registration data to %s/%s identities. org=%s",
                    mfa_applied, len(all_identities), self.db_org_id,
                )
            else:
                # AG-161: Fallback — per-user /authentication/methods (no Reports.Read.All needed)
                logger.info("[MFA] Bulk endpoint empty — falling back to per-user auth methods. org=%s", self.db_org_id)
                human_ids = [i for i in all_identities if i.get('identity_category') in ('human_user', 'guest')]
                try:
                    per_user_map = await self._collect_mfa_auth_methods(human_ids)
                    if per_user_map:
                        mfa_applied = 0
                        for identity in all_identities:
                            oid = identity.get('object_id')
                            if oid and oid in per_user_map:
                                info = per_user_map[oid]
                                identity['mfa_status'] = info['mfa_status']
                                identity['ca_mfa_enforced'] = info['mfa_status'] == 'enrolled'
                                identity['mfa_methods'] = info.get('mfa_methods', [])
                                mfa_applied += 1
                        logger.info(
                            "[MFA-methods] Applied per-user MFA data to %s/%s identities. org=%s",
                            mfa_applied, len(all_identities), self.db_org_id,
                        )
                    else:
                        logger.warning(
                            "[MFA] Both bulk and per-user collection returned empty. "
                            "MFA will show as Unknown. org=%s", self.db_org_id,
                        )
                    # Set unknown for humans not covered by either collection path
                    _unknown_set = 0
                    for identity in all_identities:
                        if identity.get('identity_category') in ('human_user', 'guest') and not identity.get('mfa_status'):
                            identity['mfa_status'] = 'unknown'
                            _unknown_set += 1
                    if _unknown_set:
                        logger.info("[MFA] Set mfa_status='unknown' for %s humans without MFA data. org=%s", _unknown_set, self.db_org_id)
                except Exception as e:
                    logger.warning("[MFA] Per-user fallback failed: %s. org=%s", e, self.db_org_id)

        # Step 6: Calculate risks (enhanced points-based scoring)
        logger.info("Calculating Risk Levels...")
        self._update_job_progress('analyzing_risk', 48)
        identities_with_risks = self._calculate_risks(
            all_identities, role_assignments, entra_roles,
            permissions_map, app_roles_map, credentials_map
        )

        # Step 7: Check credentials
        logger.info("Checking Credential Expiration...")
        self._update_job_progress('analyzing_risk', 52)
        identities_with_creds = self._check_credentials(identities_with_risks, credentials_map)

        # Attach role_assignments to each identity dict for the activity waterfall
        _ra_by_pid = {}
        for ra in role_assignments:
            _ra_by_pid.setdefault(ra['principal_id'], []).append(ra)
        for identity in identities_with_creds:
            pid = identity.get('object_id') or identity.get('principal_id')
            if pid and pid in _ra_by_pid:
                identity['role_assignments'] = _ra_by_pid[pid]

        # Step 8: Check activity
        logger.info("Checking Last Activity...")
        self._update_job_progress('analyzing_risk', 56)
        final_identities = self._check_activity(identities_with_creds)

        # Step 8.01: Telemetry coverage classification
        final_identities = self._compute_telemetry_coverage(final_identities)

        # Step 8.05: IP enrichment deferred to background thread (post-scan)
        # Was 121s (65% of scan time) for 305 identities with 0.3% hit rate.
        # Data not displayed in UI or used in risk scoring — safe to defer.
        self._update_job_progress('analyzing_risk', 57)
        logger.info("IP enrichment deferred to background (post-scan)")

        # Step 8.1: Sign-in intelligence deferred to background thread (post-scan)
        # Was ~205s (sequential, 150ms rate limit × ~1018 SPNs).
        # Data only used in lineage narrative — not in risk scoring or identity list.
        logger.info("Sign-in intelligence deferred to background (post-scan)")

        # Step 8.5: Infer workload type from role topology
        logger.info("Inferring workload types from role topology...")
        # Load lab patterns once per discovery run (not per identity)
        lab_patterns = load_tenant_lab_patterns(self.db, self.db_org_id)
        inferred_count = 0
        for identity in final_identities:
            if identity.get('identity_category') in ('service_principal', 'managed_identity_user', 'managed_identity_system'):
                result = self._infer_workload_from_roles(identity, lab_patterns=lab_patterns)
                existing_flags = identity.get('workload_risk_flags') or []
                new_flags = result.get('workload_risk_flags') or []
                result['workload_risk_flags'] = list(
                    dict.fromkeys(existing_flags + new_flags)
                )
                identity.update(result)
                if result['workload_type'] != 'unknown':
                    inferred_count += 1
        logger.info("Workload inference: %s/%s SPNs classified", inferred_count,
                     sum(1 for i in final_identities if i.get('identity_category') in ('service_principal', 'managed_identity_user', 'managed_identity_system')))

        # Step 8.75: Assemble lineage verdicts
        # Lineage engine unified under Python to ensure consistency.
        # These verdicts are the SINGLE SOURCE OF TRUTH for GET /api/spn/<id>/lineage.
        verdict_count = 0
        for identity in final_identities:
            if identity.get('identity_category') in (
                'service_principal', 'managed_identity_user', 'managed_identity_system'
            ):
                verdict = self._assemble_lineage_verdict(identity)
                identity.update(verdict)
                verdict_count += 1
        logger.info("Lineage verdicts assembled: %s identities", verdict_count)

        # Step 9: Save to database using Database class methods
        logger.info("Saving identities to database...")
        self._update_job_progress('saving_identities', 60)
        saved_count = self._save_identities(run_id, final_identities, role_assignments, credentials_map, permissions_map, app_roles_map, ownership_map, pim_map, ca_policies)
        logger.info("Saved %s identities", saved_count)
        self._identities_saved_count = saved_count
        self._update_job_metrics(identities=saved_count, subscriptions=len(self.subscriptions))

        # Step 9.1: Save Entra Groups
        logger.info("Saving Entra groups...")
        try:
            self._save_entra_groups(run_id, groups, group_memberships)
        except Exception as e:
            logger.error("Error saving Entra groups: %s", e)
            try:
                self.db._rollback()
            except Exception:
                pass

        # Step 9.2: Expand group-held roles to individual members in role_assignments
        try:
            self._expand_group_roles_to_members(run_id, role_assignments, groups, group_memberships)
        except Exception as e:
            logger.error("Error expanding group roles to members: %s", e)
            try:
                self.db._rollback()
            except Exception:
                pass

        # Step 9.5: Populate normalized lineage tables
        # (identity_orphan_classifications, identity_lineage_scores, lineage_verdicts)
        self._populate_lineage_tables(run_id, final_identities)

        # Step 9.6: Save data-plane group findings
        if self._data_plane_findings:
            try:
                self.db.save_security_findings(run_id, self._data_plane_findings)
            except Exception as e:
                logger.warning("Failed to save data-plane findings: %s", e)
                try:
                    self.db._rollback()
                except Exception:
                    pass

        self._update_job_progress('discovering_resources', 68)

        # Step 9.7: ARM Activity Log collection (no P2 required)
        # Fetches recent ARM management events per subscription, matches to
        # known identities, stores top 3 per identity in identity_arm_connections,
        # and backfills role_assignments.last_used_at.
        try:
            self._collect_arm_activity(run_id, final_identities)
        except Exception as e:
            logger.warning("ARM activity collection error: %s", e)
            try:
                self.db._rollback()
            except Exception:
                pass

        # Step 9a: P2 Telemetry Ingestion FIRST (if enabled)
        # MUST run before exposure scoring so fresh sign-in data is available
        p2_enabled = False
        try:
            p2_enabled = self.db.get_setting('p2_telemetry_enabled', 'false', organization_id=self.db_org_id) == 'true'
            logger.debug("P2 telemetry enabled=%s for org_id=%s", p2_enabled, self.db_org_id)
            if p2_enabled:
                logger.info("Ingesting P2 sign-in telemetry...")
                from app.engines.telemetry.p2_ingestion import P2TelemetryService
                telemetry = P2TelemetryService(self.credential, self.db)
                telemetry.ingest_signin_logs(run_id, self.db_org_id)
                telemetry.ingest_user_signin_logs(run_id, self.db_org_id)
                telemetry.compute_activity_stats(run_id, self.db_org_id)
                telemetry.backfill_last_sign_in(run_id)
                logger.info("P2 telemetry ingested -- activity stats ready for scoring")
        except Exception as e:
            logger.warning("P2 telemetry ingestion error: %s", e)
            self.db._rollback()

        # Step 9a-ii: Compute Workload Identity Exposure Scores (uses P2 data)
        logger.info("Computing workload identity exposure scores...")
        try:
            self._compute_workload_exposure(run_id)
        except Exception as e:
            logger.error("Workload exposure computation error: %s", e)
            self.db._rollback()

        # Step 9a-iii: Behavioral anomaly detection (after scoring)
        try:
            if p2_enabled:
                from app.engines.telemetry.behavioral_engine import BehavioralAnomalyEngine
                anomaly_engine = BehavioralAnomalyEngine(self.db)
                anomaly_engine.detect_anomalies(run_id, self.db._organization_id)
        except Exception as e:
            logger.warning("Behavioral anomaly detection error: %s", e)
            self.db._rollback()

        # Step 9b: Discover App Registrations
        org_id_val = getattr(self, '_organization_id', None) or self.db_org_id
        self._update_job_progress('discovering_apps', 80)
        logger.info("Discovering App Registrations...")
        try:
            from psycopg2.extras import RealDictCursor as RDC
            spn_cursor = self.db.conn.cursor(cursor_factory=RDC)
            spn_cursor.execute("""
                SELECT id, app_id, last_sign_in, activity_status
                FROM identities
                WHERE discovery_run_id = %s AND identity_category = 'service_principal'
            """, (run_id,))
            spn_app_id_map = {}
            for row in spn_cursor.fetchall():
                if row.get('app_id'):
                    spn_app_id_map[row['app_id']] = {
                        'id': row['id'],
                        'last_sign_in': row['last_sign_in'].isoformat() if row.get('last_sign_in') else None,
                        'activity_status': row.get('activity_status'),
                    }
            spn_cursor.close()

            app_regs = await self._discover_app_registrations(spn_app_id_map)
            for ar in app_regs:
                ar['organization_id'] = org_id_val
                self.db.save_app_registration(run_id, ar)
            logger.info("Saved %s app registrations", len(app_regs))
        except Exception as e:
            logger.error("App registration discovery error: %s", e, exc_info=True)
            self.db._rollback()

        # Step 9b.5: AG-148 — Discover Federated Identity Credentials
        try:
            await self._discover_federated_credentials(run_id, app_regs if 'app_regs' in dir() else [], spn_app_id_map if 'spn_app_id_map' in dir() else {})
        except Exception as e:
            logger.warning("Federated credential discovery error: %s", e)
            try:
                self.db._rollback()
            except Exception:
                pass

        # Step 9c: ARM Resource Graph — find resources referencing SPN appIds
        self._update_job_progress('scanning_resources', 90)
        try:
            arm_map = self._fetch_arm_resource_associations(service_principals)
            if arm_map:
                # Resolve identity_db_ids for SPNs that got ARM bindings
                from psycopg2.extras import RealDictCursor as RDC2
                arm_cursor = self.db.conn.cursor(cursor_factory=RDC2)
                arm_app_ids = list(arm_map.keys())
                arm_cursor.execute("""
                    SELECT id, app_id FROM identities
                    WHERE discovery_run_id = %s AND app_id = ANY(%s)
                """, (run_id, arm_app_ids))
                app_id_to_db_id = {row['app_id']: row['id'] for row in arm_cursor.fetchall()}
                arm_cursor.close()

                binding_saved = 0
                for app_id, bindings in arm_map.items():
                    db_id = app_id_to_db_id.get(app_id)
                    if not db_id:
                        continue
                    for binding in bindings:
                        try:
                            self.db.save_lineage_binding(db_id, self.cloud_connection_id, binding)
                            binding_saved += 1
                        except Exception as be:
                            logger.warning("save_lineage_binding failed: %s", be)
                            self.db._rollback()

                if binding_saved:
                    logger.info("ARM Resource Graph: saved %s bindings", binding_saved)
                    # Update workload_origin for SPNs with ARM bindings that lack a better origin
                    for app_id, bindings in arm_map.items():
                        db_id = app_id_to_db_id.get(app_id)
                        if not db_id or not bindings:
                            continue
                        best = max(bindings, key=lambda b: b.get('confidence_score', 0))
                        try:
                            upd_cursor = self.db.conn.cursor()
                            upd_cursor.execute("""
                                UPDATE identities
                                SET workload_origin = %s,
                                    workload_origin_source = 'arm_resource_graph'
                                WHERE id = %s
                                  AND (workload_origin IS NULL OR workload_origin = 'Unknown')
                            """, (
                                f"{best['resource_type']}: {best['resource_name']}",
                                db_id,
                            ))
                            upd_cursor.close()
                            self.db._commit()
                        except Exception:
                            self.db._rollback()
        except Exception as e:
            logger.warning("ARM Resource Graph scan error: %s", e)
            self.db._rollback()

        # Step 9e: Managed Identity lineage — map resources → managed identity → SPN
        self._update_job_progress('scanning_managed_identities', 90)
        try:
            mi_map = self._fetch_managed_identity_associations(final_identities)
            if mi_map:
                from psycopg2.extras import RealDictCursor as RDC3
                mi_cursor = self.db.conn.cursor(cursor_factory=RDC3)
                mi_oids = list(mi_map.keys())
                mi_cursor.execute("""
                    SELECT id, object_id FROM identities
                    WHERE discovery_run_id = %s AND object_id = ANY(%s)
                """, (run_id, mi_oids))
                oid_to_db_id = {row['object_id']: row['id'] for row in mi_cursor.fetchall()}
                mi_cursor.close()

                mi_saved = 0
                for oid, bindings in mi_map.items():
                    db_id = oid_to_db_id.get(oid)
                    if not db_id:
                        continue
                    for binding in bindings:
                        try:
                            self.db.save_lineage_binding(db_id, self.cloud_connection_id, binding)
                            mi_saved += 1
                        except Exception as be:
                            logger.warning("save MI lineage binding failed: %s", be)
                            self.db._rollback()

                if mi_saved:
                    logger.info("Managed identity lineage: saved %s bindings", mi_saved)
                    # Update workload_origin for MIs with resource bindings
                    for oid, bindings in mi_map.items():
                        db_id = oid_to_db_id.get(oid)
                        if not db_id or not bindings:
                            continue
                        best = max(bindings, key=lambda b: b.get('confidence_score', 0))
                        try:
                            upd_cursor = self.db.conn.cursor()
                            upd_cursor.execute("""
                                UPDATE identities
                                SET workload_origin = %s,
                                    workload_origin_source = 'managed_identity_binding'
                                WHERE id = %s
                                  AND (workload_origin IS NULL OR workload_origin = 'Unknown')
                            """, (
                                f"{best['resource_type']}: {best['resource_name']}",
                                db_id,
                            ))
                            upd_cursor.close()
                            self.db._commit()
                        except Exception:
                            self.db._rollback()
        except Exception as e:
            logger.warning("Managed identity lineage scan error: %s", e)
            self.db._rollback()

        # Step 9f: Upgrade verdict_confidence for identities with ARM/MI bindings
        # The verdict was assembled at Step 8.75 before ARM data existed.
        # Now that bindings are saved, promote confidence to 'high' for any
        # identity that has at least one binding in identity_lineage_bindings.
        try:
            upd_cursor = self.db.conn.cursor()
            upd_cursor.execute("""
                UPDATE identities i
                SET verdict_confidence = 'high'
                FROM (
                    SELECT DISTINCT spn_id
                    FROM identity_lineage_bindings
                    WHERE spn_id IN (
                        SELECT id FROM identities WHERE discovery_run_id = %s
                    )
                ) lb
                WHERE i.id = lb.spn_id
                  AND i.verdict_confidence IS DISTINCT FROM 'high'
            """, (run_id,))
            upgraded = upd_cursor.rowcount
            upd_cursor.close()
            self.db._commit()
            if upgraded:
                logger.info("Confidence upgrade: %s identities promoted to 'high' (ARM/MI binding)", upgraded)
        except Exception as e:
            logger.warning("Confidence upgrade failed: %s", e)
            self.db._rollback()

        # Step 9g: Dependency impact analysis
        # Compute what breaks if each identity is deleted, based on ARM/MI bindings.
        try:
            from psycopg2.extras import RealDictCursor as RDC_dep
            dep_cursor = self.db.conn.cursor(cursor_factory=RDC_dep)
            dep_cursor.execute("""
                SELECT i.id, i.identity_id,
                       COALESCE(json_agg(json_build_object(
                           'resource_type', lb.resource_type,
                           'resource_name', lb.resource_name,
                           'resource_group', lb.resource_group,
                           'binding_method', lb.binding_method
                       )) FILTER (WHERE lb.id IS NOT NULL), '[]') AS bindings
                FROM identities i
                LEFT JOIN identity_lineage_bindings lb ON lb.spn_id = i.id
                WHERE i.discovery_run_id = %s
                GROUP BY i.id, i.identity_id
                HAVING COUNT(lb.id) > 0
            """, (run_id,))
            identities_with_bindings = dep_cursor.fetchall()

            # Build a map of identity_id → role_assignments for impact computation
            role_map = {}
            for ra in role_assignments:
                iid = ra.get('identity_id')
                if iid:
                    role_map.setdefault(iid, []).append(ra)

            dep_updated = 0
            for row in identities_with_bindings:
                db_id = row['id']
                iid = row['identity_id']
                bindings_list = row['bindings'] if isinstance(row['bindings'], list) else []
                roles_for_identity = role_map.get(iid, [])

                impact = self._compute_dependency_impact(bindings_list, roles_for_identity)

                dep_cursor.execute("""
                    UPDATE identities
                    SET dependency_impact = %s,
                        dependency_impact_resources = %s
                    WHERE id = %s
                """, (
                    impact['dependency_impact'],
                    json.dumps(impact['dependency_impact_resources']),
                    db_id,
                ))
                dep_updated += 1

            dep_cursor.close()
            self.db._commit()
            if dep_updated:
                logger.info("Dependency impact: computed for %s identities", dep_updated)
        except Exception as e:
            logger.warning("Dependency impact analysis failed: %s", e)
            self.db._rollback()

        # Step 10: Evaluate scan integrity and complete discovery run
        self._update_job_progress('finalizing', 92)
        logger.info("Completing discovery run...")

        # Determine final scan status from component results
        CRITICAL_COMPONENTS = {"users", "groups", "memberships"}

        failed = [k for k, v in scan_component_status.items() if v == "failed"]
        critical_failed = [k for k in failed if k in CRITICAL_COMPONENTS]

        if critical_failed:
            final_scan_status = "failed"
            logger.error(
                "[scan] FAILED org=%s critical components failed: %s",
                self.db_org_id, critical_failed
            )
        elif failed:
            final_scan_status = "partial"
        else:
            final_scan_status = "completed"

        # Anomaly guard: SPNs present but 0 users → force failed
        spns_count = len(service_principals)
        users_count = len(users)
        if spns_count > 10 and users_count == 0 and final_scan_status != "failed":
            final_scan_status = "failed"
            logger.error(
                "[scan] INTEGRITY ANOMALY: %s SPNs but 0 users — "
                "marking scan FAILED org=%s",
                spns_count, self.db_org_id
            )

        # Regression guard: check previous run for relevant_group/human count drops.
        # Uses relevant_group_count (groups with roles) for the group regression
        # check — total_group_count includes informational groups that don't
        # affect access and shouldn't trigger false regression alarms.
        # When the previous run lacks relevant_group_count (pre-optimization),
        # the group check is skipped to avoid false alarms during the transition.
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                SELECT total_identities,
                       (metadata->>'relevant_group_count')::int,
                       COALESCE((metadata->>'human_identity_count')::int, 0)
                FROM discovery_runs
                WHERE organization_id = %s AND status = 'completed'
                  AND id < %s AND total_identities > 0
                ORDER BY id DESC LIMIT 1
            """, (self.db_org_id, run_id))
            prev = cursor.fetchone()
            cursor.close()

            if prev:
                prev_relevant_groups = prev[1]  # None if pre-optimization run
                prev_humans = prev[2]
                curr_relevant_groups = len(relevant_group_ids)
                curr_humans = len(users)

                # Only check group regression if previous run tracked relevant_group_count.
                # Pre-optimization runs stored group_count (total) which is much larger
                # than relevant_group_count and would cause false regression alarms.
                if prev_relevant_groups is not None and prev_relevant_groups > 20 and curr_relevant_groups < prev_relevant_groups * 0.5:
                    final_scan_status = "failed"
                    logger.error(
                        "[scan] REGRESSION: relevant groups dropped >50%% (%d -> %d) — "
                        "marking scan FAILED org=%s",
                        prev_relevant_groups, curr_relevant_groups, self.db_org_id
                    )

                if prev_humans > 10 and curr_humans < prev_humans * 0.5 and final_scan_status != "failed":
                    final_scan_status = "failed"
                    logger.error(
                        "[scan] REGRESSION: humans dropped >50%% (%d -> %d) — "
                        "marking scan FAILED org=%s",
                        prev_humans, curr_humans, self.db_org_id
                    )
        except Exception as e:
            logger.warning("[scan] Regression guard check failed: %s", e)
            try:
                self.db.conn.rollback()
            except Exception:
                pass

        try:
            critical_count = sum(1 for i in final_identities if i['risk_level'] == 'critical')
            high_count = sum(1 for i in final_identities if i['risk_level'] == 'high')
            medium_count = sum(1 for i in final_identities if i['risk_level'] == 'medium')
            low_count = sum(1 for i in final_identities if i['risk_level'] == 'low')

            # Write metadata BEFORE complete_discovery_run() — that method
            # sets snapshot_hash which triggers the immutability guard and
            # would block any subsequent UPDATE on this row.
            _relevant_count = len(relevant_group_ids)
            _expansion_count = _relevant_count if two_tier_active else len(groups)
            tracking_metadata = json.dumps({
                'component_status': scan_component_status,
                'group_count': len(groups),
                'relevant_group_count': _relevant_count,
                'total_group_count': len(groups),
                'member_expansion_count': _expansion_count,
                'two_tier_mode': two_tier_active,
                'membership_count': total_memberships,
                'human_identity_count': len(users),
                'control_plane_count': control_count,
                'data_plane_count': data_count,
            })
            cursor = self.db.conn.cursor()
            cursor.execute("""
                UPDATE discovery_runs
                SET metadata = COALESCE(metadata, '{}')::jsonb || %s::jsonb
                WHERE id = %s
            """, (tracking_metadata, run_id))
            cursor.close()
            self.db._commit()

            self.db.complete_discovery_run(
                run_id, len(final_identities),
                critical_count, high_count, medium_count, low_count
            )

            # complete_discovery_run sets status='completed'; override if
            # scan_component_status dictates a different final status.
            if final_scan_status != "completed":
                cursor = self.db.conn.cursor()
                cursor.execute(
                    "UPDATE discovery_runs SET status = %s WHERE id = %s",
                    (final_scan_status, run_id)
                )
                cursor.close()
                self.db._commit()

            logger.info("Discovery run completed with status=%s", final_scan_status)
        except Exception as e:
            logger.error("complete_discovery_run error: %s", e)
            self.db._rollback()
            # Try a simpler completion
            try:
                _rel_count = len(relevant_group_ids)
                _exp_count = _rel_count if two_tier_active else len(groups)
                tracking_metadata = json.dumps({
                    'component_status': scan_component_status,
                    'group_count': len(groups),
                    'relevant_group_count': _rel_count,
                    'total_group_count': len(groups),
                    'member_expansion_count': _exp_count,
                    'two_tier_mode': two_tier_active,
                    'membership_count': total_memberships,
                    'human_identity_count': len(users),
                })
                cursor = self.db.conn.cursor()
                cursor.execute(
                    "UPDATE discovery_runs SET status=%s, completed_at=NOW(), total_identities=%s, metadata=COALESCE(metadata,'{}')::jsonb || %s::jsonb WHERE id=%s",
                    (final_scan_status, len(final_identities), tracking_metadata, run_id)
                )
                cursor.close()
                self.db._commit()
                logger.info("Discovery run completed (fallback) status=%s", final_scan_status)
            except Exception as e2:
                logger.error("Fallback completion also failed: %s", e2)
                self.db._rollback()

        # Phase 3 graph writer — populate graph_nodes + graph_edges for
        # the blast-radius / attack-path traversal engine.  Gated by
        # USE_BLAST_RADIUS so it can be toggled without redeploying.
        # Failure here must NEVER abort the discovery run.
        try:
            from app.config.feature_flags import FeatureFlags
            if FeatureFlags.USE_BLAST_RADIUS:
                from app.services.phase3_graph_writer import Phase3GraphWriter
                gw = Phase3GraphWriter(self.db_org_id, self.cloud_connection_id, self.db)
                gw_summary = gw.write_from_discovery(
                    final_identities,
                    permissions_map=permissions_map,
                )
                logger.info(
                    "Phase 3 graph: nodes=%d edges=%d invalidated=%d",
                    gw_summary.get("nodes_upserted", 0),
                    gw_summary.get("edges_upserted", 0),
                    gw_summary.get("edges_invalidated", 0),
                )
        except Exception as e:
            logger.warning("Phase 3 graph writer warning (non-fatal): %s", e)

        # Phase 3 skeleton writer — populate builder input tables
        # (identity_role_assignments, identity_activity, identity_privilege_summary,
        # identity_list) so B02/B05/B07 builders return real data.
        # Always runs (not feature-gated) — these tables are the foundation
        # for the list endpoint and all builder state.
        try:
            from app.services.phase3_skeleton_writer import Phase3SkeletonWriter
            sw = Phase3SkeletonWriter(self.db_org_id, self.cloud_connection_id, self.db)
            sw_summary = sw.write_from_discovery(
                final_identities,
                discovery_run_id=run_id,
            )
            logger.info(
                "Phase 3 skeleton: roles=%d activity=%d privilege=%d list=%d",
                sw_summary.get("identity_role_assignments", 0),
                sw_summary.get("identity_activity", 0),
                sw_summary.get("identity_privilege_summary", 0),
                sw_summary.get("identity_list", 0),
            )
        except Exception as e:
            logger.warning("Phase 3 skeleton writer warning (non-fatal): %s", e)

        # Sync discovered subscriptions into cloud_subscriptions registry
        try:
            for sub in self.subscriptions:
                cursor = self.db.conn.cursor()
                run_org_id = self.db_org_id
                if not self.cloud_connection_id:
                    logger.warning("Skipping subscription sync -- cloud_connection_id is required (NOT NULL)")
                    break
                cursor.execute("""
                    INSERT INTO cloud_subscriptions (organization_id, cloud, account_id, account_name, status, cloud_connection_id)
                    VALUES (%s, 'azure', %s, %s, 'discovered', %s)
                    ON CONFLICT (cloud_connection_id, account_id) DO UPDATE
                    SET account_name = EXCLUDED.account_name
                """, (run_org_id, sub['id'], sub['name'], self.cloud_connection_id))
                self.db.safe_commit()
                cursor.close()
            logger.info("Synced %s subscription(s) to registry", len(self.subscriptions))
        except Exception as e:
            logger.warning("Subscription sync warning: %s", e)
            self.db._rollback()

        # Sync foreign-tenant subscriptions to their own connections
        if self.foreign_subscriptions:
            try:
                run_org_id = self.db_org_id
                # Look up source connection label for provenance tracking
                source_label = None
                try:
                    source_conn = self.db.get_cloud_connection_by_id(self.cloud_connection_id)
                    if source_conn:
                        source_label = source_conn.get('label')
                except Exception:
                    pass
                # Group foreign subs by tenant to batch-create connections
                foreign_by_tenant: Dict[str, list] = {}
                for sub in self.foreign_subscriptions:
                    foreign_by_tenant.setdefault(sub['tenant_id'], []).append(sub)
                for foreign_tenant, tenant_subs in foreign_by_tenant.items():
                    logger.info("Creating cloud connection for cross-tenant %s... (%s sub(s))", foreign_tenant[:8], len(tenant_subs))
                    foreign_conn = self.db.find_or_create_cloud_connection(
                        run_org_id, foreign_tenant,
                        label=f'Azure Tenant {foreign_tenant[:8]}...',
                        source_azure_directory_id=self.azure_directory_id,
                        source_connection_label=source_label)
                    for sub in tenant_subs:
                        cursor = self.db.conn.cursor()
                        cursor.execute("""
                            INSERT INTO cloud_subscriptions (organization_id, cloud, account_id, account_name,
                                                              status, cloud_connection_id)
                            VALUES (%s, 'azure', %s, %s, 'discovered', %s)
                            ON CONFLICT (cloud_connection_id, account_id) DO UPDATE
                            SET account_name = EXCLUDED.account_name
                        """, (run_org_id, sub['id'], sub['name'], foreign_conn['id']))
                        self.db.safe_commit()
                        cursor.close()
                logger.info("Synced %s foreign-tenant subscription(s) across %s tenant(s)", len(self.foreign_subscriptions), len(foreign_by_tenant))
            except Exception as e:
                logger.warning("Foreign subscription sync warning: %s", e)
                self.db._rollback()

        # Seed auto identity groups for this organization (Phase 38 + RLS fix)
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("SELECT organization_id FROM discovery_runs WHERE id = %s", (run_id,))
            row = cursor.fetchone()
            cursor.close()
            if row and row[0]:
                self.db.seed_auto_groups_for_organization(row[0])
                logger.info("Auto identity groups seeded for organization %s", row[0])
        except Exception as e:
            logger.warning("Auto groups seed warning: %s", e)
            self.db._rollback()

        # ── Structured scan summary log ──
        import time as _time_final
        scan_duration = (_time_final.monotonic() - self._scan_start_time) / 60 if self._scan_start_time else 0
        logger.info(
            "[SCAN COMPLETE] org=%s run=%s status=%s duration=%.1fmin "
            "users=%s spns=%s groups=%s memberships=%s "
            "components=%s",
            self.db_org_id, run_id, final_scan_status,
            scan_duration,
            users_count, spns_count, len(groups),
            total_memberships,
            json.dumps(scan_component_status)
        )

        return None
    
    # Safety limit: max pages for Graph API pagination to prevent infinite loops
    _MAX_GRAPH_PAGES = 50  # 50 pages × 999 per page = ~50,000 entities

    async def _discover_service_principals(self) -> List[Dict[str, Any]]:
        """Discover ALL service principals via direct HTTP with pagination.

        Uses a direct GET to /v1.0/servicePrincipals with $select for full
        field coverage and @odata.nextLink pagination so every SPN in the
        tenant is returned — regardless of whether it has role assignments.
        """
        import aiohttp

        try:
            identities = []
            skipped_microsoft_count = 0
            # skipped_sami_count removed — SAMIs are now included for lineage mapping

            # Get bearer token from the same credential used by the SDK
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}

            select_fields = ','.join([
                'id', 'appId', 'displayName', 'accountEnabled', 'createdDateTime',
                'servicePrincipalType', 'alternativeNames', 'appOwnerOrganizationId',
                'publisherName', 'signInActivity',
                'servicePrincipalNames', 'tags', 'passwordCredentials', 'keyCredentials',
            ])
            url = (
                f"https://graph.microsoft.com/v1.0/servicePrincipals"
                f"?$select={select_fields}&$top=999"
            )

            MAX_PAGE_RETRIES = 5

            async with aiohttp.ClientSession(timeout=GRAPH_HTTP_TIMEOUT) as session:
                page = 0
                sign_in_available = True
                while url:
                    page += 1
                    data = None

                    for attempt in range(MAX_PAGE_RETRIES):
                        async with self._graph_semaphore:
                            async with session.get(url, headers=headers) as resp:
                                if resp.status == 200:
                                    data = await resp.json()
                                    break
                                elif resp.status == 429:
                                    retry_after = int(resp.headers.get('Retry-After', '10'))
                                    retry_after = min(retry_after, 60)
                                    logger.warning(
                                        "[_discover_service_principals] 429 on page %s, Retry-After=%ss (attempt %s/%s)",
                                        page, retry_after, attempt + 1, MAX_PAGE_RETRIES
                                    )
                                    await asyncio.sleep(retry_after)
                                    continue
                                elif resp.status == 503:
                                    wait = 5 * (attempt + 1)
                                    logger.warning(
                                        "[_discover_service_principals] 503 on page %s — waiting %ss (attempt %s/%s)",
                                        page, wait, attempt + 1, MAX_PAGE_RETRIES
                                    )
                                    await asyncio.sleep(wait)
                                    continue
                                else:
                                    body = await resp.text()
                                    # If signInActivity fails (403 / needs P2), retry page 1 without it
                                    if page == 1 and ('signInActivity' in body or resp.status == 403):
                                        logger.warning("SP signInActivity requires Entra ID P2 — retrying without it")
                                        self._persist_permission(
                                            'p2_signin_activity', 'denied',
                                            error_detail='Entra ID P2 license required for signInActivity field',
                                            impact_description='Interactive/non-interactive sign-in timestamps '
                                                              'unavailable. Activity inference will rely on '
                                                              'ARM Activity Logs and heuristics.')
                                        sign_in_available = False
                                        select_no_sia = select_fields.replace(',signInActivity', '')
                                        url = (
                                            f"https://graph.microsoft.com/v1.0/servicePrincipals"
                                            f"?$select={select_no_sia}&$top=999"
                                        )
                                        page = 0
                                        data = None
                                        break
                                    logger.error(
                                        "[_discover_service_principals] FAILED status=%s body=%s",
                                        resp.status, body[:500]
                                    )
                                    raise Exception(
                                        f"Graph API /servicePrincipals failed on page {page}: "
                                        f"status={resp.status} body={body[:300]}"
                                    )
                    else:
                        # All retries exhausted
                        raise Exception(
                            f"Graph API /servicePrincipals failed after {MAX_PAGE_RETRIES} retries on page {page} "
                            f"(collected {len(identities)} SPNs so far)"
                        )

                    if data is None:
                        # signInActivity retry — loop back with new URL
                        continue

                    for sp in data.get('value', []):
                        # --- Parse fields from JSON dict ---
                        sp_id = sp.get('id')
                        app_id = sp.get('appId')
                        display_name = sp.get('displayName')

                        if len(identities) < 10:
                            logger.info("SP: %s (%s)", display_name, sp_id)

                        created = sp.get('createdDateTime')

                        # Determine identity type
                        sp_type_raw = sp.get('servicePrincipalType') or ''
                        identity_type = 'managed_identity' if sp_type_raw == 'ManagedIdentity' else 'service_principal'

                        # Extract sign-in activity (requires Entra ID P2)
                        last_sign_in = None
                        sia = sp.get('signInActivity')
                        if sia:
                            last_sign_in = (
                                sia.get('lastSignInDateTime')
                                or sia.get('lastNonInteractiveSignInDateTime')
                            )
                        # Store raw signInActivity for pattern classification later
                        _signin_raw = {}
                        if sia:
                            _signin_raw = {
                                'lastSignInDateTime': sia.get('lastSignInDateTime'),
                                'lastDelegatedSignInDateTime': sia.get('lastDelegatedClientSignInDateTime'),
                                'lastNonInteractiveSignInDateTime': sia.get('lastNonInteractiveSignInDateTime'),
                            }

                        owner_org = sp.get('appOwnerOrganizationId')
                        owner_org_str = str(owner_org) if owner_org else None

                        identity_dict = {
                            'identity_id': app_id or sp_id,
                            'object_id': sp_id,
                            'app_id': app_id,
                            'display_name': display_name,
                            'identity_type': identity_type,
                            'enabled': sp.get('accountEnabled', True),
                            'created_datetime': created,
                            'last_sign_in': last_sign_in,
                            'service_principal_type': sp_type_raw or None,
                            'app_owner_organization_id': owner_org_str,
                            'app_owner_org_id': owner_org_str,
                            'publisher_name': sp.get('publisherName'),
                            'service_principal_names': sp.get('servicePrincipalNames', []),
                            'tags': sp.get('tags', []),
                            'password_credentials': sp.get('passwordCredentials', []),
                            'key_credentials': sp.get('keyCredentials', []),
                            # Multi-cloud normalized fields
                            'cloud': 'azure',
                            'azure_directory_id': self.azure_directory_id,
                            'source': 'entra',
                            'permission_plane': 'entra_id',
                            # Flag the discovery connector's own SPN
                            'is_discovery_connector': bool(app_id and app_id == self.client_id),
                            # Observed usage: connector SPN is always in use during discovery
                            'observed_last_used': datetime.utcnow().isoformat() if (app_id and app_id == self.client_id) else None,
                            '_signin_activity_raw': _signin_raw,
                        }

                        # ──── STRICT DISCOVERY POLICY ────
                        sp_type_norm = sp_type_raw.strip().lower()

                        if sp_type_norm == "managedidentity":
                            alt_names = sp.get('alternativeNames') or []
                            alt_join = " ".join(str(a) for a in alt_names).lower()
                            is_uami = "userassignedidentities" in alt_join

                            if is_uami:
                                identity_dict["identity_category"] = "managed_identity_user"
                                identity_dict["identity_type"] = "managed_identity_user"
                            else:
                                # System-assigned managed identities — included for lineage mapping
                                identity_dict["identity_category"] = "managed_identity_system"
                                identity_dict["identity_type"] = "managed_identity_system"

                                # Parse ARM resource ID from alternativeNames for SAMI→Resource cross-link
                                for alt in alt_names:
                                    alt_str = str(alt)
                                    if alt_str.startswith('/subscriptions/'):
                                        self._parse_sami_resource(identity_dict, alt_str)
                                        break

                            identity_dict["alternative_names"] = alt_names
                            identity_dict["is_microsoft_system"] = False
                            identities.append(identity_dict)

                        elif self._is_microsoft_system_app(identity_dict):
                            identity_dict["identity_category"] = "service_principal"
                            identity_dict["identity_type"] = "service_principal"
                            identity_dict["is_microsoft_system"] = True
                            identities.append(identity_dict)
                            skipped_microsoft_count += 1

                        else:
                            identity_dict["identity_category"] = "service_principal"
                            identity_dict["identity_type"] = "service_principal"
                            identity_dict["is_microsoft_system"] = False
                            identities.append(identity_dict)

                    page_count = len(data.get('value', []))
                    logger.info(
                        "[_discover_service_principals] org=%s page=%s spns_this_page=%s total_so_far=%s",
                        self.db_org_id, page, page_count, len(identities)
                    )

                    # Follow pagination (with safety limit)
                    url = data.get('@odata.nextLink')
                    if page >= self._MAX_GRAPH_PAGES:
                        logger.warning("SP pagination hit safety limit (%d pages, %d SPNs) — stopping",
                                       page, len(identities))
                        break

            sami_count = sum(1 for i in identities if i.get('identity_category') == 'managed_identity_system')
            uami_count = sum(1 for i in identities if i.get('identity_category') == 'managed_identity_user')
            if skipped_microsoft_count > 0 or sami_count > 0 or uami_count > 0:
                logger.info("Flagged: %s Microsoft system apps, %s system-assigned MIs, %s user-assigned MIs",
                            skipped_microsoft_count, sami_count, uami_count)
                logger.info("Total: %s identities (%s customer, %s Microsoft)", len(identities), len(identities) - skipped_microsoft_count, skipped_microsoft_count)

            logger.info("Discovered %s service principals across %s page(s) (signInActivity=%s)",
                        len(identities), page, sign_in_available)
            if sign_in_available:
                self._persist_permission('p2_signin_activity', 'granted')
            # Persist P2 license availability on the cloud connection
            try:
                cur = self.db.conn.cursor()
                cur.execute(
                    "UPDATE cloud_connections SET has_p2_license = %s WHERE id = %s",
                    (sign_in_available, self.cloud_connection_id)
                )
                self.db.conn.commit()
                cur.close()
                logger.info("Persisted has_p2_license=%s for connection %s", sign_in_available, self.cloud_connection_id)
            except Exception as e:
                logger.warning("Failed to persist has_p2_license: %s", e)
            return identities
        except Exception as e:
            logger.error("[_discover_service_principals] FAILED org=%s error=%s", self.db_org_id, e)
            raise

    @staticmethod
    def _parse_sami_resource(identity_dict: dict, arm_resource_id: str):
        """Parse an ARM resource ID from SAMI alternativeNames into associated_resource_* fields.

        Expected format: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
        Handles nested types like Microsoft.Sql/servers/databases.
        """
        import re
        parts = arm_resource_id.split('/')
        # Minimum: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
        # That's at least 9 parts: ['', 'subscriptions', sub, 'resourceGroups', rg, 'providers', provider, type, name]
        if len(parts) < 9:
            return

        sub_id = parts[2] if len(parts) > 2 else None
        rg = parts[4] if len(parts) > 4 and parts[3].lower() == 'resourcegroups' else None

        # Extract provider/type/name — everything after 'providers/'
        try:
            prov_idx = next(i for i, p in enumerate(parts) if p.lower() == 'providers')
            provider_parts = parts[prov_idx + 1:]  # e.g. ['Microsoft.Compute', 'virtualMachines', 'myVM']
            if len(provider_parts) >= 2:
                # provider_parts[0] = namespace (Microsoft.Compute)
                # provider_parts[1] = type (virtualMachines)
                # provider_parts[2] = name (myVM)
                # For nested: Microsoft.Sql/servers/myServer/databases/myDB
                resource_type = f"{provider_parts[0]}/{provider_parts[1]}"
                resource_name = provider_parts[2] if len(provider_parts) > 2 else provider_parts[1]
            else:
                return
        except StopIteration:
            return

        identity_dict['associated_resource_id'] = arm_resource_id
        identity_dict['associated_resource_type'] = resource_type
        identity_dict['associated_resource_name'] = resource_name
        identity_dict['associated_resource_group'] = rg
        identity_dict['associated_subscription_id'] = sub_id

    async def _fetch_app_registration_map(self) -> Dict[str, Dict[str, Any]]:
        """Fetch all App Registrations and return a lookup keyed by appId.

        This is a lightweight call used to link SPNs to their parent App
        Registration.  The full _discover_app_registrations() method runs
        later for deep analysis.

        Returns:
            { appId: { object_id, display_name, app_owner_organization_id,
                       publisher_domain, sign_in_audience,
                       owner_display_name, owner_id } }
        """
        import aiohttp

        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}

            select_fields = 'id,appId,displayName,appOwnerOrganizationId,publisherDomain,signInAudience,identifierUris,notes,description,web,requiredResourceAccess'
            url: str | None = (
                f"https://graph.microsoft.com/v1.0/applications"
                f"?$select={select_fields}&$top=999"
            )

            lookup: Dict[str, Dict[str, Any]] = {}
            page = 0

            async with aiohttp.ClientSession(timeout=GRAPH_HTTP_TIMEOUT) as session:
                while url:
                    page += 1
                    async with session.get(url, headers=headers) as resp:
                        if resp.status != 200:
                            body = await resp.text()
                            logger.error("Graph API error %s on applications page %s: %s",
                                         resp.status, page, body[:500])
                            break
                        data = await resp.json()

                    for app in data.get('value', []):
                        app_id = app.get('appId')
                        if app_id:
                            lookup[app_id] = {
                                'object_id': app.get('id'),
                                'display_name': app.get('displayName'),
                                'app_owner_organization_id': app.get('appOwnerOrganizationId'),
                                'publisher_domain': app.get('publisherDomain'),
                                'sign_in_audience': app.get('signInAudience'),
                                'owner_display_name': None,
                                'owner_id': None,
                                # Metadata fields for signal extraction
                                'identifierUris': app.get('identifierUris'),
                                'notes': app.get('notes'),
                                'description': app.get('description'),
                                'web': app.get('web'),
                                'replyUrls': app.get('replyUrls'),
                                'requiredResourceAccess': app.get('requiredResourceAccess'),
                            }

                    url = data.get('@odata.nextLink')

                logger.info("Fetched %s app registrations across %s page(s)", len(lookup), page)

                # Fetch first owner for each app registration
                owner_fetched = 0
                for app_info in lookup.values():
                    obj_id = app_info.get('object_id')
                    if not obj_id:
                        continue
                    try:
                        owner_url = (
                            f"https://graph.microsoft.com/v1.0/applications/{obj_id}"
                            f"/owners?$select=id,displayName,userPrincipalName&$top=1"
                        )
                        async with session.get(owner_url, headers=headers) as resp:
                            if resp.status == 200:
                                owner_data = await resp.json()
                                owners = owner_data.get('value', [])
                                if owners:
                                    first = owners[0]
                                    app_info['owner_display_name'] = (
                                        first.get('displayName') or first.get('userPrincipalName')
                                    )
                                    app_info['owner_id'] = first.get('id')
                                    owner_fetched += 1
                    except Exception:
                        pass  # Non-fatal — owner lookup is best-effort

            logger.info("Fetched %s app registrations for lineage lookup (%s pages, %s with owners)",
                        len(lookup), page, owner_fetched)
            return lookup
        except Exception as e:
            logger.error("Error fetching app registration map: %s", e)
            return {}

    def _enrich_spns_with_app_registrations(
        self,
        service_principals: List[Dict[str, Any]],
        app_reg_map: Dict[str, Dict[str, Any]],
    ) -> None:
        """Annotate each SPN identity dict with its parent App Registration.

        For SPNs whose appId matches an app registration, sets lineage fields
        directly on the identity dict (mutates in place).
        """
        linked = 0
        external = 0

        for sp in service_principals:
            app_id = sp.get('app_id')

            if not app_id:
                continue

            app_reg = app_reg_map.get(app_id)
            if app_reg:
                sp['app_registration_object_id'] = app_reg['object_id']
                sp['app_registration_name'] = app_reg['display_name']
                sp['app_reg_publisher_domain'] = app_reg.get('publisher_domain')
                sp['app_reg_sign_in_audience'] = app_reg.get('sign_in_audience')
                sp['app_reg_owner_display_name'] = app_reg.get('owner_display_name')
                sp['app_reg_owner_id'] = app_reg.get('owner_id')

                owner_org = app_reg.get('app_owner_organization_id')
                is_ext = bool(owner_org and str(owner_org).lower() != self.azure_directory_id.lower())
                sp['is_external_app'] = is_ext

                # Extract metadata signals from app registration
                tenant_domain = app_reg.get('publisher_domain') or ''
                app_signals = self._extract_app_reg_signals(app_reg, tenant_domain)
                sp.update(app_signals)

                # Upgrade workload_type from metadata if still unknown
                current_wt = sp.get('workload_type') or 'unknown'
                if current_wt in ('unknown', 'unassigned') and app_signals.get('app_reg_likely_service'):
                    SERVICE_TYPE_MAP = {
                        'app_service': 'web_workload',
                        'container_app': 'container_workload',
                        'static_web_app': 'web_workload',
                        'custom_domain': 'web_workload',
                    }
                    mapped_type = SERVICE_TYPE_MAP.get(app_signals['app_reg_likely_service_type'])
                    if mapped_type:
                        sp['workload_type'] = mapped_type
                        sp['workload_confidence'] = max(sp.get('workload_confidence', 0), 20)
                        sp['role_pattern_matched'] = (
                            sp.get('role_pattern_matched') or
                            f"replyUrl: {app_signals['app_reg_likely_service']}"
                        )

                linked += 1
                if is_ext:
                    external += 1

        logger.info("SPN→App Registration lineage: %s/%s linked (%s external)",
                     linked, len(service_principals), external)

    # ── App Registration Signal Extraction ──────────────────────────

    # Well-known Microsoft resource app IDs
    KNOWN_APIS = {
        '00000003-0000-0000-c000-000000000000': 'microsoft_graph',
        '797f4846-ba00-4fd7-ba43-dac1f8f63013': 'azure_service_management',
        'e406a681-f3d4-42a8-90b6-c2b029497af1': 'azure_storage',
        'cfa8b339-82a2-471a-a3c9-0fc0be7a4093': 'azure_key_vault',
        '00000002-0000-0000-c000-000000000000': 'azure_ad_graph_legacy',
        '00000007-0000-0000-c000-000000000000': 'dynamics_crm',
        '00000003-0000-0ff1-ce00-000000000000': 'sharepoint_online',
        '00000002-0000-0ff1-ce00-000000000000': 'exchange_online',
        '00000009-0000-0000-c000-000000000000': 'power_bi',
        '0000000a-0000-0000-c000-000000000000': 'intune',
        'c5393580-f805-4401-95e8-94b7a6ef2fc2': 'office_365_management',
        'ca7f3f0b-7d91-482c-8e09-c5d840d0eac5': 'log_analytics',
        '022907d3-0f1b-48f7-badc-1ba6abab6d66': 'azure_sql',
    }

    # Map frozensets of API usage → workload type labels
    API_USAGE_WORKLOAD_MAP = {
        frozenset({'microsoft_graph'}): 'directory_management',
        frozenset({'microsoft_graph', 'azure_service_management'}): 'cloud_management',
        frozenset({'azure_storage'}): 'data_pipeline',
        frozenset({'azure_storage', 'azure_key_vault'}): 'secure_data_pipeline',
        frozenset({'azure_key_vault'}): 'secrets_management',
        frozenset({'sharepoint_online'}): 'sharepoint_integration',
        frozenset({'exchange_online'}): 'mail_integration',
        frozenset({'dynamics_crm'}): 'crm_integration',
        frozenset({'power_bi'}): 'analytics',
        frozenset({'intune'}): 'device_management',
        frozenset({'log_analytics'}): 'monitoring',
        frozenset({'azure_sql'}): 'database_workload',
        frozenset({'microsoft_graph', 'sharepoint_online'}): 'collaboration_platform',
        frozenset({'microsoft_graph', 'exchange_online'}): 'mail_automation',
    }

    def _extract_app_reg_signals(self, app: dict, tenant_domain: str) -> dict:
        """Extract deployment and provenance signals from App Registration metadata.

        Parses replyUrls, identifierUris, notes, description,
        requiredResourceAccess to infer what Azure service backs the app.

        Args:
            app: Raw app registration dict from Graph API lookup.
            tenant_domain: Tenant's primary domain for filtering.

        Returns:
            Dict of signal fields to merge onto the identity dict.
        """
        from urllib.parse import urlparse

        signals: dict = {}

        # --- replyUrls: extract hostnames, find Azure service references ---
        reply_urls = (
            app.get('replyUrls') or
            (app.get('web') or {}).get('redirectUris') or
            []
        )
        public_hostnames: list = []
        likely_service = None
        likely_service_type = None

        for url in reply_urls:
            if not url or not url.startswith('http'):
                continue
            hostname = urlparse(url).hostname or ''
            if 'localhost' in hostname or '127.0.0.1' in hostname:
                continue
            public_hostnames.append(hostname)
            if '.azurewebsites.net' in hostname:
                likely_service = hostname.split('.azurewebsites.net')[0]
                likely_service_type = 'app_service'
            elif '.azurecontainerapps.io' in hostname:
                likely_service = hostname.split('.')[0]
                likely_service_type = 'container_app'
            elif '.azurestaticapps.net' in hostname:
                likely_service = hostname.split('.')[0]
                likely_service_type = 'static_web_app'
            elif '.onmicrosoft.com' not in hostname and (not tenant_domain or tenant_domain not in hostname):
                likely_service = hostname
                likely_service_type = 'custom_domain'

        signals['app_reg_reply_url_hostnames'] = public_hostnames or None
        signals['app_reg_likely_service'] = likely_service
        signals['app_reg_likely_service_type'] = likely_service_type

        # --- identifierUris: logical namespace of the app ---
        identifier_uris = app.get('identifierUris') or []
        signals['app_reg_identifier_uris'] = identifier_uris or None

        # --- notes + description: free text provenance ---
        notes = ' '.join(filter(None, [
            app.get('notes'), app.get('description')
        ])).strip()
        signals['app_reg_notes'] = notes or None

        # --- signInAudience (already stored separately, included for completeness) ---
        signals['app_reg_sign_in_audience'] = app.get('sign_in_audience') or app.get('signInAudience')

        # --- requiredResourceAccess: which APIs this app calls ---
        api_accesses: list = []
        required_permission_ids: list = []
        high_risk_manifest_perms: list = []
        for rra in (app.get('requiredResourceAccess') or []):
            resource_id = rra.get('resourceAppId', '')
            api_name = self.KNOWN_APIS.get(resource_id, f'unknown_{resource_id[:8]}')
            api_accesses.append(api_name)
            for ra in (rra.get('resourceAccess') or []):
                perm_id = ra.get('id', '')
                perm_type = ra.get('type', '')  # 'Role' (Application) or 'Scope' (Delegated)
                entry = {
                    'resource_app_id': resource_id,
                    'resource_api_name': api_name,
                    'permission_id': perm_id,
                    'type': perm_type,
                }
                required_permission_ids.append(entry)
                # Cross-ref with HIGH_RISK_PERMISSION_GUIDS
                if perm_id in HIGH_RISK_PERMISSION_GUIDS:
                    high_risk_manifest_perms.append({
                        **entry,
                        'permission_name': HIGH_RISK_PERMISSION_GUIDS[perm_id],
                    })
        signals['app_reg_required_apis'] = api_accesses or None
        signals['app_reg_required_permission_ids'] = required_permission_ids or None
        signals['app_reg_high_risk_manifest_perms'] = high_risk_manifest_perms or None

        return signals

    # ── Sign-in Activity Pattern Classification ─────────────────────

    def _classify_signin_pattern(self, signin_data: dict) -> dict:
        """Classify the sign-in pattern of an identity from its signInActivity data.

        Patterns:
            never_used               — no sign-in timestamps at all
            machine_only             — only non-interactive sign-ins
            human_delegated_only     — only delegated (interactive) sign-ins
            hybrid_concurrent        — both types within 7 days of each other
            hybrid_delegated_recent  — both types, delegated more recent
            hybrid_noninteractive_recent — both types, non-interactive more recent

        Returns dict with:
            signin_pattern, last_delegated_signin, last_noninteractive_signin,
            days_since_last_signin, signin_risk_flags
        """
        from datetime import datetime, timezone

        def parse_dt(s):
            if not s:
                return None
            s = s.replace('Z', '+00:00')
            try:
                return datetime.fromisoformat(s)
            except (ValueError, TypeError):
                return None

        last_del = signin_data.get('lastDelegatedSignInDateTime')
        last_nonint = signin_data.get('lastNonInteractiveSignInDateTime')
        last_any = signin_data.get('lastSignInDateTime')

        has_del = last_del is not None
        has_nonint = last_nonint is not None

        if not has_del and not has_nonint:
            pattern = 'never_used'
        elif has_nonint and not has_del:
            pattern = 'machine_only'
        elif has_del and not has_nonint:
            pattern = 'human_delegated_only'
        else:
            del_dt = parse_dt(last_del)
            nonint_dt = parse_dt(last_nonint)
            if del_dt and nonint_dt:
                gap_days = abs((del_dt - nonint_dt).days)
                if gap_days <= 7:
                    pattern = 'hybrid_concurrent'
                elif del_dt > nonint_dt:
                    pattern = 'hybrid_delegated_recent'
                else:
                    pattern = 'hybrid_noninteractive_recent'
            else:
                pattern = 'machine_only' if has_nonint else 'human_delegated_only'

        # Real last-seen = most recent of all three
        candidates = [parse_dt(d) for d in [last_del, last_nonint, last_any] if d]
        candidates = [c for c in candidates if c is not None]
        last_seen_dt = max(candidates) if candidates else None

        now = datetime.now(timezone.utc)
        days_dormant = None
        if last_seen_dt:
            if last_seen_dt.tzinfo is None:
                last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
            days_dormant = (now - last_seen_dt).days

        # Build risk flags for this signal
        signin_risk_flags = []
        if pattern == 'hybrid_concurrent':
            signin_risk_flags.append('shared_human_machine_identity')
        if pattern == 'human_delegated_only':
            signin_risk_flags.append('unexpected_interactive_usage')
        if days_dormant is not None and days_dormant > 365:
            signin_risk_flags.append('stale_over_1_year')
        elif days_dormant is not None and days_dormant > 90:
            signin_risk_flags.append('dormant_over_90_days')
        if last_seen_dt is None:
            signin_risk_flags.append('never_authenticated')

        return {
            'signin_pattern': pattern,
            'last_delegated_signin': last_del,
            'last_noninteractive_signin': last_nonint,
            'days_since_last_signin': days_dormant,
            'signin_risk_flags': signin_risk_flags,
        }

    # ── Workload Topology Inference ─────────────────────────────────

    # Pattern rules ordered by specificity (first match wins).
    # When both role_keywords AND scope_keywords are non-empty, BOTH must match.
    # When only one is non-empty, that one alone is sufficient.
    WORKLOAD_PATTERNS = [
        # Rule 1 — Audit connector (our own SPN, highest priority)
        {
            'type': 'audit_connector',
            'confidence': 95,
            'role_keywords': [],
            'scope_keywords': [],
            'risk_flags': [],
            'requires_connector_flag': True,
        },
        # Rule 2 — Container / AKS workload
        {
            'type': 'container_workload',
            'confidence': 85,
            'role_keywords': ['azure kubernetes', 'aks'],
            'scope_keywords': ['microsoft.containerservice', 'managedclusters'],
            'risk_flags': ['cluster_admin_possible', 'pod_escape_risk'],
        },
        # Rule 3 — Monitoring / observability agent (before cicd to avoid 'contributor' overlap)
        {
            'type': 'monitoring_agent',
            'confidence': 80,
            'role_keywords': ['monitoring', 'log analytics', 'diagnostics', 'metrics'],
            'scope_keywords': ['microsoft.insights', 'microsoft.operationalinsights'],
            'risk_flags': ['telemetry_access', 'log_exfiltration_risk'],
        },
        # Rule 4 — Data pipeline / analytics (before cicd to avoid 'contributor' overlap)
        {
            'type': 'data_pipeline',
            'confidence': 80,
            'role_keywords': ['data factory', 'storage blob data', 'synapse', 'databricks'],
            'scope_keywords': ['microsoft.datafactory', 'microsoft.synapse', 'microsoft.databricks', 'microsoft.storage'],
            'risk_flags': ['data_exfiltration_risk', 'cross_storage_access'],
        },
        # Rule 5 — Admin / privileged identity (role-only, no scope needed)
        {
            'type': 'admin_identity',
            'confidence': 90,
            'role_keywords': ['owner', 'user access administrator', 'global administrator', 'privileged role'],
            'scope_keywords': [],
            'risk_flags': ['full_control', 'privilege_escalation_risk', 'blast_radius_high'],
        },
        # Rule 6 — CI/CD pipeline (requires deployment scope to avoid false positives)
        {
            'type': 'cicd_pipeline',
            'confidence': 80,
            'role_keywords': ['contributor'],
            'scope_keywords': ['microsoft.web', 'microsoft.containerregistry', 'microsoft.app'],
            'risk_flags': ['deploy_access', 'supply_chain_risk'],
        },
        # Rule 7 — Storage workload
        {
            'type': 'storage_workload',
            'confidence': 75,
            'role_keywords': ['storage', 'blob', 'queue', 'table', 'file'],
            'scope_keywords': ['microsoft.storage'],
            'risk_flags': ['data_access', 'storage_key_risk'],
        },
        # Rule 8 — Configuration reader (read-only, fallback)
        {
            'type': 'config_reader',
            'confidence': 75,
            'role_keywords': ['reader'],
            'scope_keywords': [],
            'risk_flags': ['recon_capability'],
            'exclude_roles': ['owner', 'contributor', 'admin', 'write', 'delete'],
        },
    ]

    def _infer_workload_from_roles(self, identity: Dict[str, Any],
                                       lab_patterns: tuple = ()) -> Dict[str, Any]:
        """Infer workload type from an identity's RBAC + Entra role assignments.

        Matching logic:
        - When both role_keywords and scope_keywords are configured, BOTH must match.
        - When only role_keywords is configured, role match alone is sufficient.
        - When only scope_keywords is configured, scope match alone is sufficient.
        - Confidence is boosted +10 when both match (capped at 100).

        Returns dict with:
            workload_type: str         — one of the 9 types (or 'unknown')
            workload_confidence: int   — 0-100
            role_pattern_matched: str  — pattern name that matched
            workload_risk_flags: list  — risk flags from the matched pattern
        """
        roles = identity.get('roles', [])
        entra_roles = identity.get('entra_roles', [])
        is_connector = identity.get('is_discovery_connector', False)

        # Collect lowercase role names and scopes for matching
        role_names_lower = [r.get('role_name', '').lower() for r in roles]
        scopes_lower = [r.get('scope', '').lower() for r in roles]
        entra_names_lower = [r.get('role_name', '').lower() for r in entra_roles]
        all_role_names = role_names_lower + entra_names_lower
        all_scopes_joined = ' '.join(scopes_lower)

        for pattern in self.WORKLOAD_PATTERNS:
            # Connector flag gate — skip or auto-match
            if pattern.get('requires_connector_flag'):
                if is_connector:
                    return {
                        'workload_type': pattern['type'],
                        'workload_confidence': pattern['confidence'],
                        'role_pattern_matched': pattern['type'],
                        'workload_risk_flags': pattern.get('risk_flags', []),
                    }
                continue

            # Check exclusion list (e.g., config_reader excludes Owner/Contributor)
            exclude = pattern.get('exclude_roles', [])
            if exclude and any(
                any(ex in rn for ex in exclude) for rn in all_role_names
            ):
                continue

            has_role_kw = bool(pattern['role_keywords'])
            has_scope_kw = bool(pattern['scope_keywords'])

            # Match: at least one role keyword matches a role name
            role_kw_match = any(
                any(kw in rn for kw in pattern['role_keywords'])
                for rn in all_role_names
            ) if has_role_kw else False

            # Match: at least one scope keyword appears in any scope
            scope_kw_match = any(
                kw in all_scopes_joined for kw in pattern['scope_keywords']
            ) if has_scope_kw else False

            # Determine if pattern fires based on what's configured
            if has_role_kw and has_scope_kw:
                # Both configured → require BOTH to match
                if not (role_kw_match and scope_kw_match):
                    continue
                confidence = min(pattern['confidence'] + 10, 100)
            elif has_role_kw:
                if not role_kw_match:
                    continue
                confidence = pattern['confidence']
            elif has_scope_kw:
                if not scope_kw_match:
                    continue
                confidence = pattern['confidence']
            else:
                continue

            return {
                'workload_type': pattern['type'],
                'workload_confidence': confidence,
                'role_pattern_matched': pattern['type'],
                'workload_risk_flags': pattern.get('risk_flags', []),
            }

        # Fallback: name-based lab/test pattern detection
        display_name = (identity.get('display_name') or '').lower()
        if lab_patterns and any(p in display_name for p in lab_patterns):
            return {
                'workload_type': 'lab_workload',
                'workload_confidence': WORKLOAD_CONFIDENCE_DEFAULT,
                'role_pattern_matched': 'name_pattern_lab',
                'workload_risk_flags': ['lab_identity', 'review_cleanup'],
            }

        # Fallback: unknown workload
        return {
            'workload_type': 'unknown',
            'workload_confidence': 0,
            'role_pattern_matched': 'none',
            'workload_risk_flags': [],
        }

    def _expand_group_roles_to_members(self, run_id: int, role_assignments: dict,
                                         groups: list, group_memberships: dict):
        """Expand group-held RBAC roles to individual members in role_assignments table.

        For each group that holds RBAC roles, creates role_assignment rows for each
        member identity with principal_type='group' (or 'group_nested' for nested members).
        Uses NOT EXISTS to avoid duplicating direct assignments.
        """
        # Ensure group columns exist
        self.db._ensure_role_assignment_group_cols()

        # Idempotent: skip if group rows already exist for this run
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT COUNT(*) FROM role_assignments ra
                JOIN identities i ON i.id = ra.identity_db_id
                WHERE i.discovery_run_id = %s AND ra.principal_type != 'direct'
            """, (run_id,))
            existing = cursor.fetchone()[0]
            if existing > 0:
                logger.info("Group role expansion: %s rows already exist for run %s, skipping", existing, run_id)
                cursor.close()
                return
        finally:
            cursor.close()

        # Build group_name_map: group_id → display_name
        group_name_map = {
            (g.get('group_id') or g.get('id')): g.get('display_name', '')
            for g in groups if g.get('group_id') or g.get('id')
        }

        # Build group_role_index: group_id → list of role dicts
        group_role_index = {}
        for group in groups:
            gid = group.get('group_id') or group.get('id')
            if not gid:
                continue
            rbac_roles = group.get('rbac_roles') or []
            if isinstance(rbac_roles, str):
                import json as _json
                try:
                    rbac_roles = _json.loads(rbac_roles)
                except Exception:
                    rbac_roles = []
            if rbac_roles:
                group_role_index[gid] = rbac_roles

        if not group_role_index:
            logger.info("Group role expansion: no groups with RBAC roles found")
            return

        # Build oid_to_dbid map: object_id → identity db id
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("SELECT id, identity_id FROM identities WHERE discovery_run_id = %s", (run_id,))
            oid_to_dbid = {row[1]: row[0] for row in cursor.fetchall()}
        finally:
            cursor.close()

        expanded_count = 0
        for group_id, roles in group_role_index.items():
            members = group_memberships.get(group_id, [])
            for member in members:
                member_oid = member.get('member_object_id') or member.get('id')
                if not member_oid:
                    continue
                db_id = oid_to_dbid.get(member_oid)
                if not db_id:
                    continue

                depth = member.get('depth', 0)
                is_nested = member.get('is_nested', False) or depth > 0
                ptype = 'group_nested' if is_nested else 'group'

                for role in roles:
                    role_name = role.get('role_name', '')
                    scope = role.get('scope', '')
                    if not role_name or not scope:
                        continue

                    # Dedup: skip if this identity already has a direct assignment with same role+scope
                    cursor = self.db.conn.cursor()
                    try:
                        cursor.execute("""
                            SELECT 1 FROM role_assignments
                            WHERE identity_db_id = %s AND role_name = %s AND scope = %s
                            LIMIT 1
                        """, (db_id, role_name, scope))
                        if cursor.fetchone():
                            continue
                    finally:
                        cursor.close()

                    self.db.save_role_assignment(db_id, {
                        'role_name': role_name,
                        'scope': scope,
                        'scope_type': role.get('scope_type', 'subscription'),
                        'principal_id': member_oid,
                        'role_type': 'azure',
                        'principal_type': ptype,
                        'group_principal_azure_object_id': group_id,
                        'group_display_name': group_name_map.get(group_id, ''),
                    })
                    expanded_count += 1

        logger.info("Group role expansion: %s inherited role rows created for run %s", expanded_count, run_id)

    def _populate_lineage_tables(self, run_id: int, identities: list):
        """Populate normalized lineage tables from verdict data on identities.

        Writes to identity_orphan_classifications and identity_lineage_scores
        for NHI identities that have verdict data and a saved DB id.
        """
        oc_count = 0
        ls_count = 0
        try:
            cursor = self.db.conn.cursor()
            for identity in identities:
                db_id = identity.get('_db_id')
                if not db_id:
                    continue
                if identity.get('identity_category') not in (
                    'service_principal', 'managed_identity_user', 'managed_identity_system'
                ):
                    continue

                # --- identity_orphan_classifications ---
                rec_action = (identity.get('recommended_action') or '').upper()
                if rec_action:
                    _VERDICT_TO_ORPHAN = {
                        Verdict.ORPHANED: 'SAFE_TO_RETIRE',
                        Verdict.UNUSED: 'SAFE_TO_RETIRE',
                        Verdict.GHOST_MSI: 'SAFE_TO_RETIRE',
                        Verdict.AT_RISK: 'CAUTION',
                        Verdict.STALE: 'CAUTION',
                        Verdict.NEEDS_REVIEW: 'UNKNOWN',
                        Verdict.HEALTHY: 'NOT_ORPHANED',
                        Verdict.FEDERATED_MISCONFIGURED: 'CAUTION',
                    }
                    oc_status = _VERDICT_TO_ORPHAN.get(rec_action, 'UNKNOWN')
                    oc_reasons = identity.get('verdict_risk_summary')
                    all_roles = (identity.get('roles') or []) + (identity.get('entra_roles') or [])
                    _READ_ONLY = {'reader', 'viewer'}
                    active_rc = sum(
                        1 for r in all_roles
                        if not any(ro in (r.get('role_name') or r.get('role_definition_name') or '').lower()
                                   for ro in _READ_ONLY)
                    )
                    if oc_status == 'SAFE_TO_RETIRE' and active_rc > 0:
                        oc_status = 'CAUTION'
                    try:
                        cursor.execute("""
                            INSERT INTO identity_orphan_classifications
                                (spn_id, connection_id, orphan_status, orphan_reasons,
                                 active_role_count, recommended_action, classified_at)
                            VALUES (%s, %s, %s, %s, %s, %s, NOW())
                            ON CONFLICT (spn_id) DO UPDATE SET
                                orphan_status = EXCLUDED.orphan_status,
                                orphan_reasons = EXCLUDED.orphan_reasons,
                                active_role_count = EXCLUDED.active_role_count,
                                recommended_action = EXCLUDED.recommended_action,
                                classified_at = NOW()
                        """, (
                            db_id,
                            self.cloud_connection_id,
                            oc_status,
                            json.dumps(oc_reasons) if oc_reasons else None,
                            active_rc,
                            identity.get('verdict_action_text'),
                        ))
                        oc_count += 1
                    except Exception as e:
                        logger.warning("orphan_classification insert failed for id=%s: %s", db_id, e)
                        try:
                            self.db._rollback()
                            cursor = self.db.conn.cursor()
                        except Exception:
                            pass

                # --- identity_lineage_scores ---
                v_score = identity.get('verdict_score')
                if v_score is not None:
                    try:
                        cursor.execute("""
                            INSERT INTO identity_lineage_scores
                                (spn_id, lineage_score, scored_at)
                            VALUES (%s, %s, NOW())
                            ON CONFLICT (spn_id) DO UPDATE SET
                                lineage_score = EXCLUDED.lineage_score,
                                scored_at = NOW()
                        """, (db_id, max(0, min(100, v_score))))
                        ls_count += 1
                    except Exception as e:
                        logger.warning("lineage_score insert failed for id=%s: %s", db_id, e)
                        try:
                            self.db._rollback()
                            cursor = self.db.conn.cursor()
                        except Exception:
                            pass

                # --- lineage_verdicts (historical tracking) ---
                rec_action = (identity.get('recommended_action') or '').upper()
                if rec_action and db_id:
                    prev_verdict = None
                    try:
                        cursor.execute("""
                            SELECT lv.verdict FROM lineage_verdicts lv
                            WHERE lv.identity_id = %s AND lv.discovery_run_id != %s
                            ORDER BY lv.scored_at DESC LIMIT 1
                        """, (db_id, run_id))
                        prev_row = cursor.fetchone()
                        if prev_row:
                            prev_verdict = prev_row[0]
                    except Exception:
                        pass

                    verdict_changed = prev_verdict is not None and prev_verdict != rec_action
                    self.db.save_lineage_verdict(run_id, db_id, {
                        'verdict': rec_action,
                        'confidence_score': (identity.get('verdict_score') or 0) / 100.0,
                        'contributing_factors': identity.get('verdict_signals'),
                        'previous_verdict': prev_verdict,
                        'verdict_changed': verdict_changed,
                        'verdict_source': 'lineage_engine',
                    })

            self.db._commit()
            cursor.close()
            logger.info("Lineage tables populated: %s orphan_classifications, %s lineage_scores",
                         oc_count, ls_count)
        except Exception as e:
            logger.warning("Lineage table population failed: %s", e)
            try:
                self.db._rollback()
            except Exception:
                pass

    def _assemble_lineage_verdict(self, identity: Dict[str, Any]) -> Dict[str, Any]:
        """Assemble a lineage verdict from all signal sources for a workload identity.

        Score (0-100) is additive for UI display.
        Confidence ('high'|'medium'|'low') uses a signal-priority model:
            high  — ARM/MI binding exists, OR federated credential, OR discovery connector
            medium — role pattern matched with high workload_confidence (>=60)
            low   — everything else

        Returns dict with 8 keys:
            verdict_confidence: 'high' | 'medium' | 'low'
            verdict_score: int (0-100)
            workload_origin: str — human-readable origin description
            workload_origin_source: str — which signal determined the origin
            recommended_action: str — one of ORPHANED/AT_RISK/STALE/UNUSED/NEEDS_REVIEW/HEALTHY
            verdict_action_text: str — human-readable recommendation
            verdict_signals: list[dict] — individual signal contributions
            verdict_risk_summary: list[str] — human-readable risk flag strings
        """
        signals = []
        score = 0

        # ── Signal 1: Role topology ──────────────────────────────────
        # active_role_count excludes read-only roles (Reader/Viewer) for scoring,
        # but has_roles includes ALL roles — Reader on a Key Vault is still real access.
        all_roles = (identity.get('roles') or []) + (identity.get('entra_roles') or [])
        _READ_ONLY = {'reader', 'viewer'}
        active_role_count = sum(
            1 for r in all_roles
            if not any(ro in (r.get('role_name') or r.get('role_definition_name') or '').lower() for ro in _READ_ONLY)
        )
        has_roles = len(all_roles) > 0
        workload_type = identity.get('workload_type') or 'unknown'
        workload_conf = identity.get('workload_confidence') or 0

        if workload_type != 'unknown' and workload_conf >= WORKLOAD_CONFIDENCE_THRESHOLD:
            signals.append({'source': 'role_topology', 'weight': 30,
                            'detail': f'Classified as {workload_type} (conf {workload_conf}%)'})
            score += 30
        elif workload_type != 'unknown':
            signals.append({'source': 'role_topology', 'weight': 15,
                            'detail': f'Classified as {workload_type} (conf {workload_conf}%)'})
            score += 15
        elif has_roles:
            signals.append({'source': 'role_topology', 'weight': 10,
                            'detail': f'Has roles but unclassified workload type'})
            score += 10

        # ── Signal 2: App registration metadata ──────────────────────
        has_app_reg = bool(identity.get('app_registration_object_id'))
        app_reg_owner = identity.get('app_reg_owner_display_name')
        likely_service = identity.get('app_reg_likely_service')
        reply_urls = identity.get('app_reg_reply_url_hostnames') or []
        is_external = identity.get('is_external_app', False)

        if has_app_reg:
            if app_reg_owner:
                signals.append({'source': 'app_reg_owner', 'weight': 15,
                                'detail': f'Owner: {app_reg_owner}'})
                score += 15
            else:
                signals.append({'source': 'app_reg_owner', 'weight': 0,
                                'detail': 'No owner assigned (ownerless)'})

            if likely_service:
                signals.append({'source': 'app_reg_metadata', 'weight': 20,
                                'detail': f'Likely service: {likely_service}'})
                score += 20
            elif reply_urls:
                signals.append({'source': 'app_reg_reply_urls', 'weight': 10,
                                'detail': f'Reply URLs: {", ".join(reply_urls[:3])}'})
                score += 10

            if is_external:
                signals.append({'source': 'app_reg_external', 'weight': 5,
                                'detail': 'External (multi-tenant) application'})
                score += 5

        # ── Signal 3: Sign-in activity ───────────────────────────────
        signin_pattern = identity.get('signin_pattern')
        days_since = identity.get('days_since_last_signin')
        last_sign_in = identity.get('last_sign_in')

        if signin_pattern and signin_pattern not in ('unknown', 'none', 'never_used'):
            signals.append({'source': 'signin_pattern', 'weight': 20,
                            'detail': f'Sign-in pattern: {signin_pattern}'})
            score += 20
        elif signin_pattern == 'never_used':
            # Never authenticated — negative signal toward orphan/review
            signals.append({'source': 'signin_pattern', 'weight': -10,
                            'detail': 'Never authenticated (no sign-in history)'})
            score = max(0, score - 10)
        elif last_sign_in:
            signals.append({'source': 'signin_last_seen', 'weight': 10,
                            'detail': f'Last sign-in recorded (days ago: {days_since})'})
            score += 10

        # ── Observed usage: MAX(observed_last_used, Azure sign-in) ──
        # AuditGraph records observed_last_used during discovery for connector SPNs.
        # effective_last_used = MAX(observed, Azure sign-in) with source attribution.
        observed_last_used = identity.get('observed_last_used')
        last_ni = identity.get('last_noninteractive_signin')
        effective_last_used = None
        effective_last_used_source = None

        # Parse dates for comparison
        def _parse_ts(v):
            if not v:
                return None
            if isinstance(v, datetime):
                return v
            try:
                return datetime.fromisoformat(str(v).replace('Z', '+00:00').replace('+00:00', ''))
            except (ValueError, TypeError):
                return None

        obs_dt = _parse_ts(observed_last_used)
        ni_dt = _parse_ts(last_ni)
        signin_dt = _parse_ts(last_sign_in)

        # Pick the most recent timestamp
        candidates = [
            (obs_dt, 'auditgraph'),
            (ni_dt, 'azure_signin'),
            (signin_dt, 'azure_signin'),
        ]
        for dt, src in candidates:
            if dt and (effective_last_used is None or dt > effective_last_used):
                effective_last_used = dt
                effective_last_used_source = src

        # Override days_since if observed_last_used is more recent
        if obs_dt and effective_last_used_source == 'auditgraph':
            days_since = (datetime.utcnow() - obs_dt).days

        # ── Signal 4: Federated credential ────────────────────────────
        fed_wt = identity.get('federated_workload_type')
        fed_wn = identity.get('federated_workload_name') or ''
        # AG-148: Also check has_federated_credentials (Graph API confirmed)
        has_fed_creds = identity.get('has_federated_credentials', False)
        fed_issuer_types = identity.get('federated_issuer_types') or []
        if isinstance(fed_issuer_types, str):
            try:
                fed_issuer_types = json.loads(fed_issuer_types)
            except Exception:
                fed_issuer_types = []

        if fed_wt:
            signals.append({'source': 'federated_credential', 'weight': 35,
                            'detail': f'Federated credential: {fed_wt} ({fed_wn})'})
            score += 35
        elif has_fed_creds:
            # Graph API confirmed federated credentials exist (AG-148)
            issuer_label = ', '.join(t.replace('_', ' ').title() for t in fed_issuer_types[:3]) or 'External OIDC'
            signals.append({'source': 'federated_credential', 'weight': 35,
                            'detail': f'Federated credential confirmed: {issuer_label}'})
            score += 35

        # ── Federated usage inference ─────────────────────────────────
        # Federated identities (GitHub OIDC, AKS, Terraform) don't generate
        # Azure sign-in logs. If effective_last_used is still NULL but a
        # federated credential exists, infer usage from created_datetime.
        if fed_wt and effective_last_used is None:
            created_raw = identity.get('created_datetime')
            created_dt = _parse_ts(created_raw)
            if created_dt:
                effective_last_used = created_dt
                effective_last_used_source = 'inferred_federated'
                # Update days_since so downstream logic treats this as active
                days_since = (datetime.utcnow() - created_dt).days

        # ── Signal 5: Discovery connector flag ───────────────────────
        is_connector = identity.get('is_discovery_connector', False)
        if is_connector:
            signals.append({'source': 'discovery_connector', 'weight': 30,
                            'detail': 'This is the AuditGraph discovery connector'})
            score += 30

        # ── Signal 6: ARM / managed identity binding ─────────────────
        # Set by Step 9d/9e after save; absent at Step 8.75 (first pass).
        has_arm_binding = bool(identity.get('arm_binding_count'))
        if has_arm_binding:
            arm_count = identity['arm_binding_count']
            signals.append({'source': 'arm_resource_binding', 'weight': 30,
                            'detail': f'ARM resource association: {arm_count} resource(s)'})
            score += 30

        # ── Signal 7: Heuristic workload detection ─────────────────
        # Runs ONLY when ARM, MI, and federated signals are absent.
        # Detects GitHub Actions (client secret), Terraform, automation scripts.
        heuristic = None
        if not has_arm_binding and not fed_wt and not is_connector:
            heuristic = self._detect_workload_from_patterns(identity)
            if heuristic:
                h_weight = 20 if heuristic['confidence'] == 'medium' else 10
                signals.append({
                    'source': 'heuristic_detection', 'weight': h_weight,
                    'detail': heuristic['reason'],
                })
                score += h_weight

        # ── Signal 8: API Usage Pattern (M1) ────────────────────────
        api_usage = identity.get('api_usage_pattern')
        if api_usage and api_usage != 'none':
            signals.append({'source': 'api_usage_pattern', 'weight': 15,
                            'detail': f'API usage pattern: {api_usage}'})
            score += 15

        # ── Signal 9: Audit Provenance (M3) ─────────────────────────
        audit_created_by = identity.get('audit_created_by')
        if audit_created_by:
            audit_method = identity.get('audit_creation_method', 'unknown')
            signals.append({'source': 'audit_provenance', 'weight': 20,
                            'detail': f'Created by {audit_created_by} via {audit_method}'})
            score += 20

        # ── Signal 10: Owned Objects (M5) ────────────────────────────
        is_platform = identity.get('is_platform_spn', False)
        owned_count = identity.get('owned_object_count', 0)
        if is_platform:
            signals.append({'source': 'platform_spn', 'weight': 25,
                            'detail': f'Platform SPN: owns/created multiple applications'})
            score += 25
        elif owned_count > 0:
            signals.append({'source': 'owned_objects', 'weight': 10,
                            'detail': f'Owns {owned_count} object(s) in directory'})
            score += 10

        # ── Signal 11: Tier-aware inactivity ─────────────────────────
        # Compute the highest privilege tier across all role assignments
        # to generate tier-specific inactivity signals.
        from app.engines.risk.agirs_engine import classify_role_privilege_tier
        _TIER_RANK = {'KEY_VAULT': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        role_tiers = [classify_role_privilege_tier(r) for r in all_roles] if all_roles else []
        highest_tier = max(role_tiers, key=lambda t: _TIER_RANK.get(t, 0), default='LOW')
        is_high_kv = highest_tier in ('HIGH', 'KEY_VAULT')
        is_medium = highest_tier == 'MEDIUM'

        inactivity_signal = None
        if is_high_kv and (signin_pattern == 'never_used' or (days_since is None and not last_sign_in)):
            inactivity_signal = 'high_privilege_never_used'
            signals.append({'source': 'inactivity_tier', 'weight': -15,
                            'detail': f'{highest_tier} privilege identity never authenticated'})
            score = max(0, score - 15)
        elif is_high_kv and days_since is not None and days_since > 90:
            inactivity_signal = 'high_privilege_long_inactive'
            signals.append({'source': 'inactivity_tier', 'weight': -12,
                            'detail': f'{highest_tier} privilege identity inactive for {days_since} days'})
            score = max(0, score - 12)
        elif is_high_kv and days_since is not None and 31 <= days_since <= 90:
            inactivity_signal = 'high_privilege_short_inactive'
            signals.append({'source': 'inactivity_tier', 'weight': -5,
                            'detail': f'{highest_tier} privilege identity inactive for {days_since} days'})
            score = max(0, score - 5)
        elif is_medium and days_since is not None and days_since > 31:
            inactivity_signal = 'medium_privilege_inactive'
            signals.append({'source': 'inactivity_tier', 'weight': -3,
                            'detail': f'MEDIUM privilege identity inactive for {days_since} days'})
            score = max(0, score - 3)

        # ── Signal 12: Key Vault item expiry ─────────────────────────
        kv_critical_count = 0
        kv_warning_count = 0
        kv_critical_names = []
        if highest_tier == 'KEY_VAULT' and hasattr(self, 'db') and self.db:
            # Collect unique vault scopes from KV-scoped roles
            kv_scopes = set()
            for r in all_roles:
                scope_val = r.get('scope') or r.get('directory_scope') or ''
                if 'Microsoft.KeyVault/vaults' in scope_val:
                    # Extract vault-level scope (strip sub-paths like /keys/mykey)
                    parts = scope_val.split('/providers/Microsoft.KeyVault/vaults/')
                    if len(parts) == 2:
                        vault_path = parts[1].split('/')[0]
                        kv_scopes.add(parts[0] + '/providers/Microsoft.KeyVault/vaults/' + vault_path)

            for kv_scope in kv_scopes:
                try:
                    kv_items = self.db.get_keyvault_items_by_scope(kv_scope)
                    for item in kv_items:
                        tier = item.get('expiry_risk_tier', '')
                        if tier == 'CRITICAL':
                            kv_critical_count += 1
                            kv_critical_names.append(item.get('item_name', '?'))
                        elif tier == 'WARNING':
                            kv_warning_count += 1
                except Exception:
                    pass  # keyvault_metadata table may not exist

        if kv_critical_count > 0:
            signals.append({'source': 'keyvault_expiry_critical', 'weight': -15,
                            'detail': f'{kv_critical_count} vault item(s) expiring within 14 days: {", ".join(kv_critical_names[:5])}'})
            score = max(0, score - 15)
        if kv_warning_count > 0:
            signals.append({'source': 'keyvault_expiry_warning', 'weight': -8,
                            'detail': f'{kv_warning_count} vault item(s) expiring within 30 days'})
            score = max(0, score - 8)

        # ── Clamp score ──────────────────────────────────────────────
        score = max(0, min(100, score))

        # ── Confidence: signal-priority model ────────────────────────
        # Confidence is determined by the HIGHEST-PRIORITY signal present,
        # NOT by summing weights.  This prevents misleading "high" when
        # many weak signals accumulate.
        if is_connector:
            confidence = 'high'
        elif has_arm_binding:
            confidence = 'high'
        elif fed_wt or has_fed_creds:
            confidence = 'high'
        elif heuristic and heuristic['confidence'] == 'medium':
            confidence = 'medium'
        elif audit_created_by:
            confidence = 'medium'
        elif workload_type != 'unknown' and workload_conf >= WORKLOAD_CONFIDENCE_THRESHOLD:
            confidence = 'medium'
        else:
            confidence = 'low'

        # ── Determine origin ─────────────────────────────────────────
        # Priority: connector > app_reg_metadata > reply_url > federated >
        #           heuristic (NEW) > role_inference > app_reg_name
        # RULE: Never leave origin as "Unknown" if ANY signal exists.
        origin = 'Unknown'
        origin_source = 'none'

        if is_connector:
            origin = 'AuditGraph Discovery Connector'
            origin_source = 'discovery_connector'
        elif likely_service:
            origin = likely_service
            origin_source = 'app_reg_metadata'
        elif reply_urls:
            origin = f'Service at {reply_urls[0]}'
            origin_source = 'reply_url'
        elif fed_wt:
            origin = f'{fed_wt.replace("_", " ").title()}: {fed_wn}'
            origin_source = 'federated_credential'
        elif heuristic:
            # P4: Heuristic detection (GitHub, Terraform, automation)
            origin = heuristic['origin']
            origin_source = heuristic['origin_source']
        elif audit_created_by and identity.get('audit_creation_method') not in ('unknown', None):
            method = identity.get('audit_creation_method', 'unknown')
            origin = f'Created by {audit_created_by} via {method}'
            origin_source = 'audit_provenance'
        elif workload_type != 'unknown':
            origin = f'{workload_type.replace("_", " ").title()} (inferred from roles)'
            origin_source = 'role_inference'
        elif has_app_reg and identity.get('app_registration_name'):
            origin = identity['app_registration_name']
            origin_source = 'app_reg_name'

        # Last resort: if still Unknown but we have ANY evidence, use it
        if origin == 'Unknown':
            if signin_pattern and signin_pattern not in ('unknown', 'none', 'never_used'):
                origin = f'{signin_pattern.replace("_", " ").title()} workload'
                origin_source = 'signin_pattern_fallback'
            elif has_roles and has_app_reg:
                origin = identity.get('app_registration_name') or identity.get('display_name', 'Unknown')
                origin_source = 'display_name_fallback'

        # ── Recommended action ───────────────────────────────────────
        risk_flags = identity.get('workload_risk_flags') or []
        risk_summary = list(risk_flags)  # copy

        # Dependency impact: resources that depend on this identity.
        # INVARIANT: UNUSED verdict must NEVER coexist with dependency entries.
        dep_impact = identity.get('dependency_impact_resources') or []
        if isinstance(dep_impact, str):
            try:
                dep_impact = json.loads(dep_impact)
            except Exception:
                dep_impact = []
        has_deps = isinstance(dep_impact, list) and len(dep_impact) > 0

        # never_used is a negative orphan signal — identity has never authenticated
        if signin_pattern == 'never_used':
            risk_summary.append('never_authenticated')

        # Confirmed signal = hard evidence that the identity is actively managed
        # or bound to infrastructure. These override ORPHANED verdict.
        # Workload classification with medium+ confidence counts as confirmed:
        # if the role-inference engine identified a known workload type,
        # that IS a confirmed signal (no P2 telemetry needed).
        has_workload_classification = (
            workload_type in _CONFIRMED_WORKLOAD_TYPES
            and workload_conf >= WORKLOAD_CONFIDENCE_THRESHOLD
        )
        has_confirmed_signal = (
            has_arm_binding
            or bool(fed_wt)
            or has_fed_creds  # AG-148: Graph API confirmed federated credentials
            or bool(app_reg_owner)
            or (signin_pattern and signin_pattern not in ('unknown', 'none', 'never_used'))
            or bool(last_sign_in)
            or has_workload_classification
        )

        # Strong signal = any lineage evidence (confirmed OR inferred).
        # Prevents NEEDS_REVIEW verdict but does NOT prevent ORPHANED.
        has_strong_signal = (
            has_confirmed_signal
            or bool(heuristic)
            or bool(likely_service)
            or bool(reply_urls)
            or (workload_type != 'unknown' and workload_conf >= WORKLOAD_CONFIDENCE_THRESHOLD)
            or bool(audit_created_by)
            or bool(is_platform)
            or (api_usage and api_usage != 'none')
        )

        # An identity active within the last 90 days must NEVER be ORPHANED.
        # It may be ungoverned (no owner) but it is not orphaned.
        _ninety_days_ago = datetime.utcnow() - timedelta(days=90)
        _recently_active = (
            (effective_last_used is not None and effective_last_used > _ninety_days_ago)
            or (last_sign_in is not None and _parse_ts(last_sign_in) is not None
                and _parse_ts(last_sign_in) > _ninety_days_ago)
        )

        if is_connector:
            action = 'HEALTHY'
            action_text = 'AuditGraph connector — no action required.'
        elif has_roles and not app_reg_owner and not last_sign_in and not has_confirmed_signal:
            if _recently_active:
                # Active (via non-interactive sign-in or observed usage) but no owner
                action = 'AT_RISK'
                action_text = 'Active identity with roles but no owner. Assign an owner to reduce governance risk.'
                risk_summary.append('Active but ungoverned — needs an owner')
            else:
                action = 'ORPHANED'
                action_text = 'Has active roles but no owner and no sign-in history. Assign an owner or disable.'
                risk_summary.append('Ownerless identity with active permissions')
        elif has_deps and not last_sign_in:
            # Priority: deps + no auth → AT_RISK (never UNUSED).
            # Deleting this identity could break dependent resources.
            action = 'AT_RISK'
            dep_count = len(dep_impact)
            action_text = (f'Never authenticated but {dep_count} resource(s) depend on this identity. '
                           f'Deletion could break dependent workloads.')
            risk_summary.append('Has dependents but never authenticated — deletion risk')
        elif (fed_wt or has_fed_creds) and not has_roles and not last_sign_in:
            # AG-148: Federated SPN — never classify as UNUSED even without roles/sign-in.
            # External pipelines depend on this identity.
            action = 'FEDERATED_UNVERIFIED'
            action_text = ('External pipeline dependency detected via federated credentials. '
                           'Review federated credentials before any action.')
            risk_summary.append('Federated pipeline dependency — deletion risk HIGH')
        elif not has_roles and not last_sign_in and not has_deps:
            action = 'UNUSED'
            action_text = 'No roles, no sign-in activity, and no dependents detected. Consider removing.'
            risk_summary.append('No permissions or activity detected')
        elif identity.get('identity_category') == IdentityCategory.MANAGED_IDENTITY_SYSTEM \
             and identity.get('associated_resource_id') is None and has_roles:
            action = Verdict.GHOST_MSI
            action_text = 'System-assigned MI with no host resource. The resource may have been deleted.'
            risk_summary.append('Ghost MSI — host resource missing')
        elif 'shared_identity' in risk_flags or 'shared_credential' in risk_flags:
            action = 'AT_RISK'
            action_text = 'Shared identity or credential detected. Review access and rotate credentials.'
            risk_summary.append('Shared identity/credential risk')
        elif inactivity_signal in ('high_privilege_never_used', 'high_privilege_long_inactive') and has_roles:
            action = 'AT_RISK'
            if inactivity_signal == 'high_privilege_never_used':
                action_text = f'{highest_tier} privilege identity — no authentication observed. Review necessity or disable.'
                risk_summary.append(f'{highest_tier} privilege — no authentication observed')
            else:
                action_text = f'{highest_tier} privilege identity inactive for {days_since} days. Rotate credentials or disable.'
                risk_summary.append(f'{highest_tier} privilege inactive {days_since}d')
        elif days_since is not None and days_since > 365 and has_roles:
            action = 'STALE'
            action_text = f'Last sign-in was {days_since} days ago but still has active roles. Review necessity.'
            risk_summary.append(f'Stale: no sign-in for {days_since} days')
        elif inactivity_signal in ('high_privilege_short_inactive', 'medium_privilege_inactive') and has_roles:
            action = 'STALE'
            action_text = f'{highest_tier} privilege identity inactive for {days_since} days. Monitor for further inactivity.'
            risk_summary.append(f'{highest_tier} privilege inactive {days_since}d')
        elif has_strong_signal:
            action = 'HEALTHY'
            if score >= 60:
                action_text = 'Well-understood identity with strong lineage signals.'
            else:
                action_text = 'Identity has supporting lineage evidence. No immediate action needed.'
        elif has_roles:
            # Defensive: roles present but no strong signal and not caught above.
            action = 'NEEDS_REVIEW'
            action_text = 'Identity has roles but no lineage signals. Manual review recommended.'
            risk_summary.append('No lineage signals — manual review needed')
        else:
            action = 'NEEDS_REVIEW'
            action_text = 'No lineage signals found. Periodic review recommended.'

        # ── AG-148: Federated verdict override ───────────────────────
        # If federated credentials confirmed AND identity has activity → ACTIVE_FEDERATED.
        # Suppresses any delete/disable recommendation.
        if (fed_wt or has_fed_creds) and action in ('HEALTHY', 'STALE', 'AT_RISK'):
            if last_sign_in or _recently_active or has_arm_binding:
                action = 'ACTIVE_FEDERATED'
                issuer_label = (fed_wt or (fed_issuer_types[0] if fed_issuer_types else 'external_oidc')).replace('_', ' ').title()
                action_text = (f'Active federated identity ({issuer_label}). '
                               f'External pipeline dependency — review federated credentials before any action.')
            elif action in ('STALE', 'AT_RISK') and not last_sign_in:
                # No activity but has federated creds — don't delete
                action = 'FEDERATED_UNVERIFIED'
                action_text = ('External pipeline dependency detected via federated credentials. '
                               'Review federated credentials before any action.')
                risk_summary.append('Federated pipeline dependency — deletion risk HIGH')

        # ── Human-readable lineage_signals ────────────────────────────
        # Structured signals for executive-readable lineage panel.
        # Type: ARM | FEDERATED | ROLE | SIGNIN | OWNER
        lineage_signals = []

        # ARM signal
        if has_arm_binding:
            arm_count = identity.get('arm_binding_count', 0)
            dep_res = identity.get('dependency_impact_resources') or []
            if isinstance(dep_res, str):
                try:
                    import json as _json
                    dep_res = _json.loads(dep_res)
                except Exception:
                    dep_res = []
            if dep_res and isinstance(dep_res, list) and len(dep_res) > 0:
                top = dep_res[0]
                rtype = top.get('resource_type', 'resource')
                rname = top.get('resource_name', 'unknown')
                loc = top.get('region') or top.get('location', '')
                loc_str = f' ({loc})' if loc else ''
                lineage_signals.append({
                    'type': 'ARM', 'label': 'Static',
                    'value': f"clientId found in {rtype} '{rname}'{loc_str}",
                    'confidence': 'high',
                })
            else:
                lineage_signals.append({
                    'type': 'ARM', 'label': 'Static',
                    'value': f'Bound to {arm_count} ARM resource(s)',
                    'confidence': 'high',
                })

        # Federated signal
        if fed_wt:
            if fed_wt == 'github_actions':
                fed_value = f"GitHub Actions \u2192 {fed_wn}" if fed_wn else 'GitHub Actions (OIDC)'
            elif fed_wt == 'aks':
                fed_value = f"AKS \u2192 {fed_wn}" if fed_wn else 'AKS Workload Identity'
            else:
                fed_value = f"{fed_wt.replace('_', ' ').title()} \u2192 {fed_wn}" if fed_wn else fed_wt.replace('_', ' ').title()
            lineage_signals.append({
                'type': 'FEDERATED', 'label': 'Federated',
                'value': fed_value,
                'confidence': 'high',
            })

        # Heuristic signal (GitHub, Terraform, automation)
        if heuristic:
            lineage_signals.append({
                'type': 'HEURISTIC', 'label': 'Inferred',
                'value': heuristic['reason'],
                'confidence': heuristic['confidence'],
            })

        # Sign-in signal
        last_ni = identity.get('last_noninteractive_signin')
        if last_ni or last_sign_in:
            if days_since is not None and days_since >= 0:
                if days_since == 0:
                    signin_value = 'Last non-interactive sign-in today'
                elif days_since <= 30:
                    signin_value = f'Last non-interactive sign-in {days_since} days ago'
                elif days_since <= 365:
                    months = days_since // 30
                    signin_value = f'Last non-interactive sign-in {months} month{"s" if months != 1 else ""} ago'
                else:
                    months = days_since // 30
                    signin_value = f'Last non-interactive sign-in {months} months ago'
            else:
                signin_value = 'Sign-in activity recorded'
            lineage_signals.append({
                'type': 'SIGNIN', 'label': 'Sign-in',
                'value': signin_value,
                'confidence': 'high' if days_since is not None and days_since <= 90 else 'medium',
            })

        # Owner signal
        if has_app_reg:
            if app_reg_owner:
                lineage_signals.append({
                    'type': 'OWNER', 'label': 'Owner',
                    'value': app_reg_owner,
                    'confidence': 'medium',
                })
            else:
                lineage_signals.append({
                    'type': 'OWNER', 'label': 'Owner',
                    'value': 'No owner assigned',
                    'confidence': 'high',
                })

        # Observed usage signal
        if obs_dt:
            obs_days = (datetime.utcnow() - obs_dt).days
            if is_connector:
                obs_label = 'Actively used by AuditGraph'
            elif obs_days == 0:
                obs_label = 'Observed in use today (via AuditGraph)'
            else:
                obs_label = f'Observed in use {obs_days} day{"s" if obs_days != 1 else ""} ago (via AuditGraph)'
            lineage_signals.append({
                'type': 'OBSERVED', 'label': 'Observed',
                'value': obs_label,
                'confidence': 'high',
            })

        # Inferred usage signal (federated identities with no sign-in data)
        if effective_last_used_source == 'inferred_federated' and fed_wt:
            fed_label_map = {
                'github_actions': 'GitHub Actions (OIDC)',
                'aks': 'AKS Workload Identity',
                'terraform': 'Terraform Cloud',
            }
            inferred_label = fed_label_map.get(fed_wt, fed_wt.replace('_', ' ').title())
            lineage_signals.append({
                'type': 'INFERRED', 'label': 'Usage',
                'value': f'Likely used via {inferred_label}',
                'confidence': 'medium',
            })

        # API usage pattern signal (M1)
        if api_usage and api_usage != 'none':
            lineage_signals.append({
                'type': 'API', 'label': 'APIs',
                'value': f'Usage pattern: {api_usage.replace("_", " ").title()}',
                'confidence': 'medium',
            })

        # Provenance signal (M3)
        if audit_created_by:
            method = identity.get('audit_creation_method', 'unknown')
            lineage_signals.append({
                'type': 'PROVENANCE', 'label': 'Created By',
                'value': f'{audit_created_by} ({method})',
                'confidence': 'medium',
            })

        # Platform SPN signal (M5)
        if is_platform:
            evidence = identity.get('platform_spn_evidence') or {}
            lineage_signals.append({
                'type': 'PLATFORM', 'label': 'Platform',
                'value': f'Owns {evidence.get("owned_app_count", 0)} apps, created {evidence.get("created_app_count", 0)} apps',
                'confidence': 'high',
            })

        # Key Vault expiry signal
        if kv_critical_count > 0:
            lineage_signals.append({
                'type': 'ALERT', 'label': 'KV Expiry',
                'value': f'{kv_critical_count} vault item(s) expiring within 14 days: {", ".join(kv_critical_names[:5])}',
                'confidence': 'high',
            })
            risk_summary.append(f'{kv_critical_count} vault item(s) critically expiring')
        if kv_warning_count > 0:
            lineage_signals.append({
                'type': 'ALERT', 'label': 'KV Expiry',
                'value': f'{kv_warning_count} vault item(s) expiring within 30 days',
                'confidence': 'medium',
            })

        # Inactivity tier signal
        if inactivity_signal:
            _inactivity_labels = {
                'high_privilege_never_used': f'{highest_tier} privilege — no authentication observed',
                'high_privilege_long_inactive': f'{highest_tier} privilege — inactive {days_since}d',
                'high_privilege_short_inactive': f'{highest_tier} privilege — inactive {days_since}d',
                'medium_privilege_inactive': f'MEDIUM privilege — inactive {days_since}d',
            }
            lineage_signals.append({
                'type': 'INACTIVITY', 'label': 'Inactivity',
                'value': _inactivity_labels.get(inactivity_signal, inactivity_signal),
                'confidence': 'high' if 'never' in inactivity_signal else 'medium',
            })

        # High sign-in failure alert (M4)
        fail_count = identity.get('signin_failure_count_30d', 0)
        if fail_count and fail_count >= 10:
            lineage_signals.append({
                'type': 'ALERT', 'label': 'Sign-in Failures',
                'value': f'{fail_count} failed sign-ins in last 30 days',
                'confidence': 'high',
            })

        # ── Lineage narrative ──────────────────────────────────────────
        # Human-readable paragraph summarizing all evidence and risk.
        narrative_parts = []
        display = identity.get('display_name', 'This identity')
        cat = identity.get('identity_category', 'identity')
        cat_label = {
            'service_principal': 'Service Principal',
            'managed_identity_system': 'System Managed Identity',
            'managed_identity_user': 'User Managed Identity',
            'human_user': 'User',
            'guest': 'Guest User',
        }.get(cat, 'Identity')

        # Where it runs
        if is_connector:
            narrative_parts.append(f"{cat_label} '{display}' is the AuditGraph Discovery Connector.")
        elif fed_wt:
            fed_label = fed_value  # reuse from above
            narrative_parts.append(f"{cat_label} '{display}' is federated to {fed_label}.")
        elif has_arm_binding and lineage_signals and lineage_signals[0]['type'] == 'ARM':
            narrative_parts.append(f"{cat_label} '{display}' is {lineage_signals[0]['value']}.")
        elif heuristic:
            narrative_parts.append(f"{cat_label} '{display}' is likely used for {heuristic['origin'].lower()}.")
        elif origin != 'Unknown':
            narrative_parts.append(f"{cat_label} '{display}' is used by {origin}.")
        else:
            narrative_parts.append(f"{cat_label} '{display}' has no confirmed workload binding.")

        # What it accesses
        if has_roles:
            if workload_type != 'unknown':
                narrative_parts.append(
                    f'It has {active_role_count} active role{"s" if active_role_count != 1 else ""} '
                    f'classified as {workload_type.replace("_", " ")}.'
                )
            else:
                narrative_parts.append(
                    f'It has {active_role_count} active role{"s" if active_role_count != 1 else ""} '
                    f'but the workload type is unclassified.'
                )

        # Activity (with observed usage source attribution)
        source_tag = ''
        if effective_last_used_source == 'auditgraph':
            source_tag = ' (observed by AuditGraph)'
        elif effective_last_used_source == 'inferred_federated':
            source_tag = ' (inferred from federated credential)'
        if is_connector:
            narrative_parts.append('It is actively used during every discovery scan.')
        elif effective_last_used_source == 'inferred_federated':
            narrative_parts.append(f'Azure does not record sign-in logs for federated identities, but it is likely active{source_tag}.')
        elif days_since is not None and days_since > 365:
            narrative_parts.append(f'It has not been used for {days_since // 30} months.')
        elif days_since is not None and days_since > 90:
            narrative_parts.append(f'It has not been used for {days_since} days.')
        elif days_since is not None and days_since >= 0:
            narrative_parts.append(f'It was last active {days_since} day{"s" if days_since != 1 else ""} ago{source_tag}.')
        elif not last_sign_in and not last_ni and not obs_dt:
            narrative_parts.append('No sign-in activity has ever been recorded.')

        # Provenance (M3)
        if audit_created_by:
            method = identity.get('audit_creation_method', 'unknown')
            narrative_parts.append(f'It was created by {audit_created_by} via {method}.')

        # Resources accessed (M4)
        signin_resources = identity.get('signin_resources_accessed')
        if signin_resources and isinstance(signin_resources, list):
            top_res = [r.get('name', '?') for r in signin_resources[:3]]
            narrative_parts.append(f'It accesses {", ".join(top_res)}.')

        # Sign-in failure warning (M4)
        if fail_count and fail_count >= 10:
            narrative_parts.append(f'Warning: {fail_count} sign-in failures in the last 30 days.')

        # Owner risk
        if has_app_reg and not app_reg_owner:
            narrative_parts.append('No owner is assigned to the app registration.')
        elif 'shared_identity' in risk_flags:
            narrative_parts.append('This identity may be shared across multiple teams or services.')

        # Conclusion
        if action == 'ORPHANED':
            narrative_parts.append('This identity is likely orphaned and still has access to live resources.')
        elif action == 'STALE':
            narrative_parts.append('This identity is stale and should be reviewed for decommissioning.')
        elif action == 'UNUSED':
            narrative_parts.append('This identity appears unused and can likely be removed.')
        elif action == 'AT_RISK':
            narrative_parts.append('This identity poses elevated risk and requires immediate review.')
        elif action == 'NEEDS_REVIEW':
            narrative_parts.append('Insufficient evidence to determine safety. Manual review recommended.')
        elif action == 'HEALTHY':
            narrative_parts.append('This identity appears healthy with sufficient lineage evidence.')

        lineage_narrative = ' '.join(narrative_parts)

        # Debug logging for lineage signals (helps demo validation)
        iid = identity.get('identity_id', '?')
        logger.debug(
            "DETECTION [%s] ARM=%d MI=0 FED=%s HEURISTIC=%s SIGNIN=%s "
            "score=%d conf=%s action=%s origin=%s origin_src=%s signals=%d strong=%s",
            iid,
            identity.get('arm_binding_count', 0),
            fed_wt or 'none',
            heuristic['workload_type'] if heuristic else 'none',
            signin_pattern or 'none',
            score, confidence, action, origin, origin_source,
            len(signals),
            has_strong_signal,
        )

        return {
            'verdict_confidence': confidence,
            'verdict_score': score,
            'workload_origin': origin,
            'workload_origin_source': origin_source,
            'recommended_action': action,
            'verdict_action_text': action_text,
            'verdict_signals': signals,
            'verdict_risk_summary': risk_summary,
            'lineage_signals': lineage_signals,
            'lineage_narrative': lineage_narrative,
            'effective_last_used': effective_last_used.isoformat() if effective_last_used else None,
            'effective_last_used_source': effective_last_used_source,
        }

    # ── Module 5: Owned Objects Scanner ─────────────────────────────────

    async def _discover_owned_objects(self, service_principals: list):
        """Discover owned and created objects per SPN via Graph API.

        Calls GET /v1.0/servicePrincipals/{id}/ownedObjects and /createdObjects.
        Skips Microsoft system SPNs. Detects platform SPNs (owns >=2 apps OR created >=3 apps).
        Sets owned_objects, created_objects, owned_object_count, created_object_count,
        is_platform_spn, platform_spn_evidence on each identity dict.
        """
        import os
        if os.environ.get('DISABLE_OWNED_OBJECTS', 'false').lower() == 'true':
            logger.info("[owned_objects] SKIPPED via env flag")
            return

        import aiohttp
        import asyncio as _asyncio

        token = self.credential.get_token("https://graph.microsoft.com/.default")
        headers = {"Authorization": f"Bearer {token.token}"}

        enriched = 0
        platform_count = 0

        async with aiohttp.ClientSession(timeout=GRAPH_HTTP_TIMEOUT) as session:
            for sp in service_principals:
                if sp.get('is_microsoft_system'):
                    continue
                obj_id = sp.get('object_id')
                if not obj_id:
                    continue

                owned = []
                created = []

                # Fetch ownedObjects
                try:
                    url = (
                        f"https://graph.microsoft.com/v1.0/servicePrincipals/{obj_id}"
                        f"/ownedObjects?$select=id,displayName&$top=999"
                    )
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for obj in data.get('value', []):
                                owned.append({
                                    'id': obj.get('id'),
                                    'display_name': obj.get('displayName'),
                                    'odata_type': obj.get('@odata.type', ''),
                                })
                        elif resp.status == 403:
                            logger.debug("ownedObjects 403 for %s — skipping", obj_id)
                except Exception as e:
                    logger.debug("ownedObjects error for %s: %s", obj_id, e)

                await _asyncio.sleep(0.15)  # Rate limit 150ms

                # Fetch createdObjects
                try:
                    url = (
                        f"https://graph.microsoft.com/v1.0/servicePrincipals/{obj_id}"
                        f"/createdObjects?$select=id,displayName&$top=999"
                    )
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for obj in data.get('value', []):
                                created.append({
                                    'id': obj.get('id'),
                                    'display_name': obj.get('displayName'),
                                    'odata_type': obj.get('@odata.type', ''),
                                })
                        elif resp.status == 403:
                            logger.debug("createdObjects 403 for %s — skipping", obj_id)
                except Exception as e:
                    logger.debug("createdObjects error for %s: %s", obj_id, e)

                await _asyncio.sleep(0.15)

                # Set on identity dict
                sp['owned_objects'] = owned or None
                sp['created_objects'] = created or None
                sp['owned_object_count'] = len(owned)
                sp['created_object_count'] = len(created)

                # Detect platform SPNs
                owned_apps = sum(1 for o in owned if 'application' in (o.get('odata_type') or '').lower())
                created_apps = sum(1 for c in created if 'application' in (c.get('odata_type') or '').lower())
                is_platform = owned_apps >= 2 or created_apps >= 3
                sp['is_platform_spn'] = is_platform
                if is_platform:
                    sp['platform_spn_evidence'] = {
                        'owned_app_count': owned_apps,
                        'created_app_count': created_apps,
                        'owned_total': len(owned),
                        'created_total': len(created),
                    }
                    platform_count += 1
                else:
                    sp['platform_spn_evidence'] = None

                if owned or created:
                    enriched += 1

        logger.info("Owned objects: %s SPNs enriched, %s platform SPNs detected", enriched, platform_count)

    # ── Module 5b: Background Owned Objects Enrichment ────────────────

    @classmethod
    async def enrich_owned_objects_background(
        cls,
        azure_directory_id: str,
        client_id: str,
        client_secret: str,
        db_org_id: int,
        run_id: int,
    ):
        """Background job: enrich SPNs with owned/created objects data.

        Runs AFTER scan completes. Queries SPN object_ids from the DB,
        calls Graph API in parallel (semaphore-throttled), then batch-updates
        the identities table with owned_objects, is_platform_spn, etc.
        """
        import aiohttp
        import asyncio as _asyncio
        import time as _bg_time
        from azure.identity import ClientSecretCredential
        from app.database import Database

        _start = _bg_time.monotonic()
        logger.info("[owned_objects_bg] START org=%s run=%s", db_org_id, run_id)

        # Get credential token
        credential = ClientSecretCredential(
            tenant_id=azure_directory_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        client_secret = None  # AG-116: zero after SDK init
        token = credential.get_token("https://graph.microsoft.com/.default")
        headers = {"Authorization": f"Bearer {token.token}"}

        # Fetch SPN object_ids from the latest run (non-Microsoft only)
        db = Database()
        try:
            cursor = db.conn.cursor()
            cursor.execute("""
                SELECT id, identity_id
                FROM identities
                WHERE discovery_run_id = %s
                  AND identity_category = 'service_principal'
                  AND COALESCE(is_microsoft_system, false) = false
                  AND identity_id IS NOT NULL
            """, (run_id,))
            spn_rows = cursor.fetchall()
            cursor.close()
        except Exception as e:
            logger.error("[owned_objects_bg] DB query failed: %s", e)
            db.close()
            return
        finally:
            try:
                db.conn.rollback()
            except Exception:
                pass

        if not spn_rows:
            logger.info("[owned_objects_bg] No SPNs found for run=%s", run_id)
            db.close()
            return

        logger.info("[owned_objects_bg] Processing %d SPNs org=%s", len(spn_rows), db_org_id)

        # Parallel enrichment with semaphore throttling
        sem = _asyncio.Semaphore(25)
        enriched = 0
        platform_count = 0
        updates = []  # (db_id, owned_objects, created_objects, owned_count, created_count, is_platform, platform_evidence)

        async def _enrich_one(session, db_id, obj_id):
            nonlocal enriched, platform_count
            async with sem:
                owned = []
                created = []

                # Fetch ownedObjects
                try:
                    url = (
                        f"https://graph.microsoft.com/v1.0/servicePrincipals/{obj_id}"
                        f"/ownedObjects?$select=id,displayName&$top=999"
                    )
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for obj in data.get('value', []):
                                owned.append({
                                    'id': obj.get('id'),
                                    'display_name': obj.get('displayName'),
                                    'odata_type': obj.get('@odata.type', ''),
                                })
                except Exception:
                    pass

                # Fetch createdObjects
                try:
                    url = (
                        f"https://graph.microsoft.com/v1.0/servicePrincipals/{obj_id}"
                        f"/createdObjects?$select=id,displayName&$top=999"
                    )
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for obj in data.get('value', []):
                                created.append({
                                    'id': obj.get('id'),
                                    'display_name': obj.get('displayName'),
                                    'odata_type': obj.get('@odata.type', ''),
                                })
                except Exception:
                    pass

                # Detect platform SPNs
                owned_apps = sum(1 for o in owned if 'application' in (o.get('odata_type') or '').lower())
                created_apps = sum(1 for c in created if 'application' in (c.get('odata_type') or '').lower())
                is_platform = owned_apps >= 2 or created_apps >= 3
                platform_evidence = None
                if is_platform:
                    platform_evidence = {
                        'owned_app_count': owned_apps,
                        'created_app_count': created_apps,
                        'owned_total': len(owned),
                        'created_total': len(created),
                    }
                    platform_count += 1

                if owned or created:
                    enriched += 1

                updates.append((
                    db_id,
                    owned or None,
                    created or None,
                    len(owned),
                    len(created),
                    is_platform,
                    platform_evidence,
                ))

        async with aiohttp.ClientSession(timeout=GRAPH_HTTP_TIMEOUT) as session:
            tasks = [_enrich_one(session, row[0], row[1]) for row in spn_rows]
            await _asyncio.gather(*tasks, return_exceptions=True)

        # Batch update identities table
        import json
        update_count = 0
        try:
            cursor = db.conn.cursor()
            for (db_id, owned, created, owned_cnt, created_cnt, is_plat, plat_ev) in updates:
                try:
                    cursor.execute("""
                        UPDATE identities SET
                            owned_objects = %s,
                            created_objects = %s,
                            owned_object_count = %s,
                            created_object_count = %s,
                            is_platform_spn = %s,
                            platform_spn_evidence = %s
                        WHERE id = %s
                    """, (
                        json.dumps(owned) if owned else None,
                        json.dumps(created) if created else None,
                        owned_cnt,
                        created_cnt,
                        is_plat,
                        json.dumps(plat_ev) if plat_ev else None,
                        db_id,
                    ))
                    update_count += 1
                except Exception as e:
                    logger.debug("[owned_objects_bg] Update failed for id=%s: %s", db_id, e)
                    try:
                        db.conn.rollback()
                    except Exception:
                        pass
            db.conn.commit()
            cursor.close()
        except Exception as e:
            logger.error("[owned_objects_bg] Batch update failed: %s", e)
            try:
                db.conn.rollback()
            except Exception:
                pass

        db.close()
        _elapsed = round(_bg_time.monotonic() - _start, 1)
        logger.info(
            "[owned_objects_bg] DONE in %.1fs: %d/%d SPNs enriched, %d platform SPNs, %d DB updates org=%s",
            _elapsed, enriched, len(spn_rows), platform_count, update_count, db_org_id,
        )

    # ── Module 3: AAD Audit Log Provenance ────────────────────────────

    @staticmethod
    def _classify_creation_method(initiated_by: dict) -> str:
        """Classify the creation method from an audit log's initiatedBy field.

        Returns one of: 'portal', 'terraform', 'cli_powershell', 'programmatic',
        'user_initiated', 'unknown'.
        """
        if not initiated_by:
            return 'unknown'
        app = initiated_by.get('app') or {}
        user = initiated_by.get('user') or {}
        app_name = (app.get('displayName') or '').lower()
        user_agent = (app.get('servicePrincipalName') or '').lower()

        if 'azure portal' in app_name or 'portal' in app_name:
            return 'portal'
        if 'terraform' in app_name or 'terraform' in user_agent:
            return 'terraform'
        if any(kw in app_name for kw in ('powershell', 'az cli', 'azure cli', 'azcli')):
            return 'cli_powershell'
        if app.get('appId') or app.get('displayName'):
            return 'programmatic'
        if user.get('userPrincipalName') or user.get('displayName'):
            return 'user_initiated'
        return 'unknown'

    async def _discover_audit_provenance(self, service_principals: list):
        """Discover AAD audit log provenance for service principals.

        Calls directoryAudits to find:
        - Creation event (who created this SPN and how)
        - Recent modifications in the last 90 days

        Bails on 403 (AuditLog.Read.All not granted).
        Skips Microsoft system SPNs.
        Time-boxed to MAX_PHASE_SECONDS (default 180s) and capped at
        MAX_SPNS_PROCESSED (default 500) to prevent scan stalls.
        """
        import os
        if os.environ.get('DISABLE_AUDIT_PROVENANCE', 'false').lower() == 'true':
            logger.info("[audit_provenance] SKIPPED via env flag")
            return

        import aiohttp
        import asyncio as _asyncio
        import time as _time
        from urllib.parse import quote

        phase_start = _time.monotonic()
        MAX_PHASE_SECONDS = int(os.environ.get('AUDIT_PROVENANCE_MAX_SECONDS', '180'))
        MAX_SPNS_PROCESSED = int(os.environ.get('AUDIT_PROVENANCE_MAX_SPNS', '500'))

        token = self.credential.get_token("https://graph.microsoft.com/.default")
        headers = {"Authorization": f"Bearer {token.token}"}

        enriched = 0
        processed = 0
        skipped_ms = 0
        skipped_no_id = 0
        ninety_days_ago = (datetime.utcnow() - timedelta(days=90)).strftime('%Y-%m-%dT00:00:00Z')

        async with aiohttp.ClientSession(timeout=GRAPH_HTTP_TIMEOUT) as session:
            for sp in service_principals:
                processed += 1

                if processed % 50 == 0:
                    elapsed = _time.monotonic() - phase_start
                    logger.info(
                        "[audit_provenance] progress: processed=%d enriched=%d elapsed=%.1fs",
                        processed, enriched, elapsed
                    )

                elapsed = _time.monotonic() - phase_start
                if elapsed > MAX_PHASE_SECONDS:
                    logger.warning(
                        "[audit_provenance] TIME BUDGET EXCEEDED at %.1fs — "
                        "enriched %d/%d SPNs, skipping remainder",
                        elapsed, enriched, processed
                    )
                    break
                if processed >= MAX_SPNS_PROCESSED:
                    logger.warning(
                        "[audit_provenance] SPN CAP REACHED (%d) — "
                        "enriched %d SPNs, skipping remainder",
                        MAX_SPNS_PROCESSED, enriched
                    )
                    break

                if sp.get('is_microsoft_system'):
                    skipped_ms += 1
                    continue
                obj_id = sp.get('object_id')
                if not obj_id:
                    skipped_no_id += 1
                    continue

                # Fetch creation event
                created_by = None
                creation_method = 'unknown'
                creation_date = None
                try:
                    filter_str = (
                        f"targetResources/any(t: t/id eq '{obj_id}') "
                        f"and activityDisplayName eq 'Add service principal'"
                    )
                    url = (
                        f"https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
                        f"?$filter={quote(filter_str)}&$top=1&$orderby=activityDateTime asc"
                    )
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 403:
                            logger.info("Audit provenance: AuditLog.Read.All not granted — skipping module")
                            self._persist_permission(
                                'directory_audit_log', 'denied',
                                error_detail='AuditLog.Read.All Graph API permission not granted',
                                impact_description='Identity creation provenance, modification history, '
                                                  'and Entra role exercise evidence unavailable.')
                            return  # Bail entirely
                        if resp.status == 200:
                            self._persist_permission('directory_audit_log', 'granted')
                            data = await resp.json()
                            events = data.get('value', [])
                            if events:
                                event = events[0]
                                initiated = event.get('initiatedBy', {})
                                user_info = initiated.get('user') or {}
                                app_info = initiated.get('app') or {}
                                created_by = (
                                    user_info.get('userPrincipalName')
                                    or user_info.get('displayName')
                                    or app_info.get('displayName')
                                    or 'Unknown'
                                )
                                creation_method = self._classify_creation_method(initiated)
                                creation_date = event.get('activityDateTime')
                except Exception as e:
                    logger.debug("Audit creation lookup error for %s: %s", obj_id, e)

                await _asyncio.sleep(0.15)

                # Fetch recent modifications (last 90 days)
                recent_mods = []
                mod_count = 0
                try:
                    filter_str = (
                        f"targetResources/any(t: t/id eq '{obj_id}') "
                        f"and activityDateTime ge {ninety_days_ago}"
                    )
                    url = (
                        f"https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
                        f"?$filter={quote(filter_str)}&$top=999&$orderby=activityDateTime desc"
                    )
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            events = data.get('value', [])
                            mod_count = len(events)
                            for event in events:
                                initiated = event.get('initiatedBy', {})
                                user_info = initiated.get('user') or {}
                                app_info = initiated.get('app') or {}
                                recent_mods.append({
                                    'activity': event.get('activityDisplayName'),
                                    'date': event.get('activityDateTime'),
                                    'actor': (
                                        user_info.get('userPrincipalName')
                                        or app_info.get('displayName')
                                        or 'Unknown'
                                    ),
                                    'method': self._classify_creation_method(initiated),
                                })
                except Exception as e:
                    logger.debug("Audit recent mods error for %s: %s", obj_id, e)

                await _asyncio.sleep(0.15)

                # Set on identity dict
                sp['audit_created_by'] = created_by
                sp['audit_creation_method'] = creation_method
                sp['audit_creation_date'] = creation_date
                sp['audit_recent_modifications'] = recent_mods or None
                sp['audit_modification_count_90d'] = mod_count
                if created_by:
                    enriched += 1

        elapsed = _time.monotonic() - phase_start
        logger.info(
            "[audit_provenance] COMPLETE: processed=%d enriched=%d "
            "skipped_ms=%d skipped_no_id=%d elapsed=%.1fs",
            processed, enriched, skipped_ms, skipped_no_id, elapsed
        )

    # ── Module 4: AAD Sign-in Intelligence ────────────────────────────

    @staticmethod
    def _classify_ip(ip_str: str) -> str:
        """Classify an IP address into category.

        Returns one of: 'internal_rfc1918', 'azure_datacenter', 'external', 'unknown'.
        """
        import ipaddress as _ipa
        if not ip_str:
            return 'unknown'
        try:
            addr = _ipa.ip_address(ip_str)
            if addr.is_private:
                return 'internal_rfc1918'
            # Azure DC heuristic: common first octets for Azure public IPs
            first_octet = int(ip_str.split('.')[0]) if '.' in ip_str else 0
            if first_octet in (13, 20, 40, 52, 104):
                return 'azure_datacenter'
            return 'external'
        except (ValueError, TypeError):
            return 'unknown'

    @staticmethod
    def _process_signin_intelligence(identity: dict, sign_ins: list):
        """Process sign-in events and set intelligence fields on identity dict.

        Extracts IPs, resources, locations, client apps, failure/success counts.
        """
        ips = {}
        resources = {}
        locations = {}
        client_apps = {}
        failures = 0
        successes = 0

        for si in sign_ins:
            # IP
            ip = si.get('ipAddress')
            if ip:
                if ip not in ips:
                    ips[ip] = {
                        'ip': ip,
                        'classification': AzureDiscoveryEngine._classify_ip(ip),
                        'count': 0,
                    }
                ips[ip]['count'] += 1

            # Resource
            res = si.get('resourceDisplayName')
            if res:
                if res not in resources:
                    resources[res] = {'name': res, 'count': 0}
                resources[res]['count'] += 1

            # Location
            loc = si.get('location') or {}
            city = loc.get('city') or ''
            country = loc.get('countryOrRegion') or ''
            loc_key = f"{city},{country}" if city or country else ''
            if loc_key:
                if loc_key not in locations:
                    locations[loc_key] = {'city': city, 'country': country, 'count': 0}
                locations[loc_key]['count'] += 1

            # Client app
            client = si.get('clientAppUsed') or ''
            if client:
                if client not in client_apps:
                    client_apps[client] = {'app': client, 'count': 0}
                client_apps[client]['count'] += 1

            # Status
            status = si.get('status') or {}
            error_code = status.get('errorCode', 0)
            if error_code and error_code != 0:
                failures += 1
            else:
                successes += 1

        identity['signin_ips'] = list(ips.values()) or None
        identity['signin_resources_accessed'] = list(resources.values()) or None
        identity['signin_locations'] = list(locations.values()) or None
        identity['signin_client_apps'] = list(client_apps.values()) or None
        identity['signin_failure_count_30d'] = failures
        identity['signin_success_count_30d'] = successes
        identity['signin_total_events_30d'] = len(sign_ins)

    async def _discover_signin_intelligence(self, identities: list):
        """Discover sign-in intelligence for workload identities via Graph API.

        Calls GET /v1.0/auditLogs/signIns with servicePrincipalId filter.
        6-hour cache via setting key. Rate limit 150ms. Bails on 403.
        """
        import os
        if os.environ.get('DISABLE_SIGNIN_INTELLIGENCE', 'false').lower() == 'true':
            logger.info("[signin_intelligence] SKIPPED via env flag")
            return

        import aiohttp
        import asyncio as _asyncio
        from urllib.parse import quote

        # 6-hour cache check
        cache_key = f'signin_intelligence_last_run_{self.cloud_connection_id}'
        try:
            last_run = self.db.get_setting(cache_key, None, organization_id=self.db._organization_id)
            if last_run:
                last_dt = datetime.fromisoformat(last_run.replace('Z', '+00:00').replace('+00:00', ''))
                if (datetime.utcnow() - last_dt).total_seconds() < 6 * 3600:
                    logger.info("Sign-in intelligence: cached (last run %s) — skipping", last_run)
                    return
        except Exception:
            pass

        token = self.credential.get_token("https://graph.microsoft.com/.default")
        headers = {"Authorization": f"Bearer {token.token}"}
        thirty_days_ago = (datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%dT00:00:00Z')
        select_fields = 'createdDateTime,resourceDisplayName,ipAddress,location,clientAppUsed,status,servicePrincipalId'

        enriched = 0
        batch_count = 0

        async with aiohttp.ClientSession(timeout=GRAPH_HTTP_TIMEOUT) as session:
            for identity in identities:
                if identity.get('identity_category') not in ('service_principal', 'managed_identity_user', 'managed_identity_system'):
                    continue
                if identity.get('is_microsoft_system'):
                    continue
                obj_id = identity.get('object_id')
                if not obj_id:
                    continue

                try:
                    filter_str = (
                        f"servicePrincipalId eq '{obj_id}' "
                        f"and createdDateTime ge {thirty_days_ago}"
                    )
                    url = (
                        f"https://graph.microsoft.com/v1.0/auditLogs/signIns"
                        f"?$filter={quote(filter_str)}&$top=999"
                        f"&$orderby=createdDateTime desc&$select={select_fields}"
                    )
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 403:
                            logger.info("Sign-in intelligence: 403 — signIns API not available, skipping module")
                            return  # Bail entirely
                        if resp.status == 200:
                            data = await resp.json()
                            sign_ins = data.get('value', [])
                            if sign_ins:
                                self._process_signin_intelligence(identity, sign_ins)
                                enriched += 1
                except Exception as e:
                    logger.debug("Sign-in intelligence error for %s: %s", obj_id, e)

                await _asyncio.sleep(0.15)
                batch_count += 1
                if batch_count % 100 == 0:
                    logger.info("Sign-in intelligence: processed %s identities...", batch_count)

        # Update cache timestamp
        try:
            self.db.save_setting(cache_key, datetime.utcnow().isoformat(), organization_id=self.db._organization_id)
        except Exception:
            pass

        logger.info("Sign-in intelligence: %s identities enriched out of %s processed", enriched, batch_count)

    # ── Heuristic workload detection ──────────────────────────────────
    # Detects workloads when federated identity and ARM bindings are absent.
    # Catches: GitHub Actions with client secrets, Terraform SPNs, automation scripts.

    # Patterns for heuristic matching (compiled once at class level)
    _GITHUB_NAME_PATTERNS = {'github', 'gh-', 'actions', 'ghactions', 'github-actions'}
    _TERRAFORM_NAME_PATTERNS = {'terraform', 'tf-', 'iac', 'infra-pipeline', 'pulumi', 'bicep'}
    _TERRAFORM_ROLES = {'owner', 'contributor', 'user access administrator'}

    @staticmethod
    def _detect_workload_from_patterns(identity: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect workload type from naming conventions, roles, and sign-in patterns.

        Called when ARM, MI, and federated signals are absent.
        Returns dict with workload_type, confidence, reason, origin, origin_source
        or None if no pattern matched.
        """
        display_name = (identity.get('display_name') or '').lower()
        app_reg_notes = (identity.get('app_reg_notes') or '').lower()
        app_reg_name = (identity.get('app_registration_name') or '').lower()
        signin_pattern = identity.get('signin_pattern') or ''
        all_roles = (identity.get('roles') or []) + (identity.get('entra_roles') or [])
        _READ_ONLY = {'reader', 'viewer'}
        has_roles = any(
            not any(ro in (r.get('role_name') or r.get('role_definition_name') or '').lower() for ro in _READ_ONLY)
            for r in all_roles
        ) if all_roles else False
        workload_type = identity.get('workload_type') or 'unknown'

        # Collect role names for Terraform detection
        role_names_lower = set()
        risk_flags = identity.get('workload_risk_flags') or []
        # role_pattern_matched stores the matched pattern name
        role_pattern = (identity.get('role_pattern_matched') or '').lower()

        # ── Rule 1: GitHub Actions heuristic ─────────────────────────
        name_matches_github = any(
            p in display_name or p in app_reg_name
            for p in AzureDiscoveryEngine._GITHUB_NAME_PATTERNS
        )
        notes_match_github = 'github' in app_reg_notes

        if name_matches_github or notes_match_github:
            return {
                'workload_type': 'github_actions_inferred',
                'confidence': 'medium',
                'reason': 'Likely GitHub Actions pipeline (name/notes pattern match, no federated credential)',
                'origin': f'GitHub Actions (inferred from {"name" if name_matches_github else "notes"})',
                'origin_source': 'heuristic_github',
            }

        # ── Rule 2: Terraform / IaC heuristic ────────────────────────
        name_matches_terraform = any(
            p in display_name or p in app_reg_name
            for p in AzureDiscoveryEngine._TERRAFORM_NAME_PATTERNS
        )
        # Check if workload has elevated roles typical of IaC
        has_iac_roles = (
            workload_type == 'admin_identity'
            or 'admin' in role_pattern
            or any(p in display_name for p in ('contributor', 'deploy'))
        )

        if name_matches_terraform or (has_iac_roles and any(
            p in display_name for p in ('deploy', 'pipeline', 'infra', 'provision')
        )):
            return {
                'workload_type': 'terraform_pipeline',
                'confidence': 'medium',
                'reason': 'Infrastructure pipeline identity (IaC naming pattern + elevated roles)',
                'origin': f'Terraform / IaC pipeline (inferred from {"name" if name_matches_terraform else "roles + naming"})',
                'origin_source': 'heuristic_terraform',
            }

        # ── Rule 3: Automation / Script heuristic ────────────────────
        is_machine_only = signin_pattern in ('machine_only',)
        if is_machine_only and has_roles:
            # Generic automation: machine-only sign-in with roles but no binding
            return {
                'workload_type': 'automation_script',
                'confidence': 'low',
                'reason': 'Automation script identity (machine-only sign-in, roles present, no ARM/federated binding)',
                'origin': 'Automation script (inferred from machine-only sign-in pattern)',
                'origin_source': 'heuristic_automation',
            }

        return None

    # ── Resource types that cause HIGH impact if their SPN is deleted ──
    _HIGH_IMPACT_RESOURCE_TYPES = {
        'appservice', 'functionapp', 'containerapp', 'managedclusters',
        'virtualmachines', 'logicapp', 'sites', 'kubernetes',
        'containerapps', 'aks',
    }
    _MEDIUM_IMPACT_RESOURCE_TYPES = {
        'storageaccounts', 'keyvaults', 'sqldatabases', 'sqlservers',
        'cosmosdb', 'servicebus', 'eventhubs', 'redis',
    }
    _READER_ONLY_ROLES = {
        'reader', 'monitoring reader', 'log analytics reader',
        'security reader', 'cost management reader',
    }

    def _compute_dependency_impact(
        self,
        bindings: list,
        role_assignments: list,
    ) -> Dict[str, Any]:
        """Compute dependency impact — what breaks if this SPN is deleted.

        Args:
            bindings: list of ARM/MI resource binding dicts from Steps 9d/9e
            role_assignments: list of role assignment dicts for this identity

        Returns:
            dict with:
                dependency_impact: 'high' | 'medium' | 'low' | 'none_detected'
                dependency_impact_resources: list of affected resource dicts
                deletion_impact_statement: human-readable impact summary
        """
        if not bindings:
            # Check if identity has write/contribute roles (implicit impact)
            role_names = [r.get('role_name', '').lower() for r in (role_assignments or [])]
            has_write_roles = any(
                rn and rn not in self._READER_ONLY_ROLES
                for rn in role_names
            )
            if has_write_roles:
                return {
                    'dependency_impact': 'none_detected',
                    'dependency_impact_resources': [],
                    'deletion_impact_statement': (
                        'No direct resource bindings found, but this identity has '
                        'write/contribute roles. Deletion may break undiscovered workloads.'
                    ),
                }
            return {
                'dependency_impact': 'none_detected',
                'dependency_impact_resources': [],
                'deletion_impact_statement': 'No resource bindings or write roles detected.',
            }

        # Classify each bound resource
        impact_resources = []
        max_impact = 'low'

        for b in bindings:
            rt_raw = (b.get('resource_type') or '').lower().replace(' ', '')
            resource_name = b.get('resource_name', '')
            resource_group = b.get('resource_group', '')
            binding_method = b.get('binding_method', '')

            # Determine resource-level impact
            if any(ht in rt_raw for ht in self._HIGH_IMPACT_RESOURCE_TYPES):
                res_impact = 'high'
            elif any(mt in rt_raw for mt in self._MEDIUM_IMPACT_RESOURCE_TYPES):
                res_impact = 'medium'
            else:
                res_impact = 'low'

            impact_resources.append({
                'resource_name': resource_name,
                'resource_type': b.get('resource_type', ''),
                'resource_group': resource_group,
                'impact_level': res_impact,
                'binding_method': binding_method,
            })

            # Track highest impact
            if res_impact == 'high':
                max_impact = 'high'
            elif res_impact == 'medium' and max_impact != 'high':
                max_impact = 'medium'

        # Check if identity only has Reader roles (downgrade to low)
        role_names = [r.get('role_name', '').lower() for r in (role_assignments or [])]
        only_reader = all(
            rn in self._READER_ONLY_ROLES
            for rn in role_names
            if rn
        ) if role_names else False

        if only_reader and max_impact != 'high':
            max_impact = 'low'

        # Build human-readable deletion impact statement
        high_res = [r for r in impact_resources if r['impact_level'] == 'high']
        med_res = [r for r in impact_resources if r['impact_level'] == 'medium']

        lines = []
        if high_res:
            lines.append('CRITICAL resources that will break:')
            for r in high_res[:5]:
                lines.append(f'  - {r["resource_name"]} ({r["resource_type"]})')
        if med_res:
            lines.append('Resources that may be affected:')
            for r in med_res[:5]:
                lines.append(f'  - {r["resource_name"]} ({r["resource_type"]})')
        remaining = len(impact_resources) - len(high_res[:5]) - len(med_res[:5])
        if remaining > 0:
            lines.append(f'  + {remaining} more resource(s)')

        statement = '\n'.join(lines) if lines else (
            f'{len(impact_resources)} resource(s) bound, all low-impact.'
        )

        return {
            'dependency_impact': max_impact,
            'dependency_impact_resources': impact_resources,
            'deletion_impact_statement': statement,
        }

    @staticmethod
    def _classify_federated_credential(issuer: str, subject: str) -> Dict[str, str]:
        """Classify a federated credential into a workload type and name.

        Returns dict with:
            federated_workload_type: 'github_actions' | 'aks_workload' | 'external_federation'
            federated_workload_name: extracted repo/namespace or issuer host
        """
        issuer = issuer or ''
        subject = subject or ''

        # GitHub Actions OIDC
        if 'token.actions.githubusercontent.com' in issuer:
            # subject format: repo:org/repo:ref:refs/heads/main  OR  repo:org/repo:environment:prod
            name = subject
            if subject.startswith('repo:'):
                # Extract "org/repo" portion
                parts = subject[5:]  # strip "repo:"
                colon_idx = parts.find(':')
                if colon_idx > 0:
                    name = parts[:colon_idx]
                else:
                    name = parts
            return {
                'federated_workload_type': 'github_actions',
                'federated_workload_name': name,
            }

        # AKS / Kubernetes OIDC
        if 'kubernetes' in issuer.lower() or 'system:serviceaccount:' in subject:
            # subject format: system:serviceaccount:namespace:sa-name
            name = subject
            if 'system:serviceaccount:' in subject:
                sa_parts = subject.split('system:serviceaccount:')[-1]
                # sa_parts is "namespace:sa-name"
                name = sa_parts.replace(':', '/')
            return {
                'federated_workload_type': 'aks_workload',
                'federated_workload_name': name,
            }

        # External / unknown federation
        host = issuer.replace('https://', '').replace('http://', '').split('/')[0]
        return {
            'federated_workload_type': 'external_federation',
            'federated_workload_name': host or subject or 'unknown',
        }

    # ── ARM Resource Graph KQL templates ────────────────────────────
    # Each tuple: (resource_type_label, KQL template with {app_ids} placeholder,
    #              binding_method, confidence_score)
    _ARM_KQL_QUERIES = [
        (
            'AppService',
            """
            Resources
            | where type =~ "microsoft.web/sites"
            | where kind !contains "functionapp"
            | mv-expand setting = properties.siteConfig.appSettings
            | where setting.value in~ ({app_ids})
            | project id, name, resourceGroup, location,
                      settingKey = setting.name, matchedValue = tostring(setting.value)
            """,
            'HardcodedClientId',
            90,
        ),
        (
            'FunctionApp',
            """
            Resources
            | where type =~ "microsoft.web/sites"
            | where kind contains "functionapp"
            | mv-expand setting = properties.siteConfig.appSettings
            | where setting.value in~ ({app_ids})
            | project id, name, resourceGroup, location,
                      settingKey = setting.name, matchedValue = tostring(setting.value)
            """,
            'HardcodedClientId',
            90,
        ),
        (
            'ContainerApp',
            """
            Resources
            | where type =~ "microsoft.app/containerapps"
            | mv-expand container = properties.template.containers
            | mv-expand env = container.env
            | where env.value in~ ({app_ids})
            | project id, name, resourceGroup, location,
                      envKey = env.name, matchedValue = tostring(env.value)
            """,
            'HardcodedClientId',
            85,
        ),
        (
            'LogicApp',
            """
            Resources
            | where type =~ "microsoft.logic/workflows"
            | where properties.parameters has_any ({app_ids})
            | project id, name, resourceGroup, location
            """,
            'HardcodedClientId',
            70,
        ),
    ]

    # Maximum appIds per Resource Graph query batch
    _ARM_BATCH_SIZE = 50

    def _fetch_arm_resource_associations(
        self, service_principals: List[Dict]
    ) -> Dict[str, List[Dict]]:
        """Scan Azure Resource Graph for resources referencing SPN appIds.

        Runs 4 KQL queries per batch against Resource Graph, batching
        appIds into groups of 50 to stay within query-size limits.

        Args:
            service_principals: list of identity dicts (must have 'app_id')

        Returns:
            dict mapping app_id -> list of ResourceBinding dicts matching the
            WorkloadAssociationsPanel frontend shape.
        """
        if ResourceGraphClient is None:
            logger.warning("azure-mgmt-resourcegraph not installed — skipping ARM scan")
            return {}

        # Collect non-empty app_ids
        app_id_set: Dict[str, str] = {}  # app_id -> identity_id
        for sp in service_principals:
            aid = sp.get('app_id')
            iid = sp.get('identity_id')
            if aid and iid and sp.get('identity_category') in (
                'service_principal', 'managed_identity_user', 'managed_identity_system'
            ):
                app_id_set[aid] = iid

        if not app_id_set:
            return {}

        sub_ids = [s['id'] for s in self.subscriptions]
        if not sub_ids:
            logger.info("ARM scan skipped — no subscriptions available")
            return {}

        rg_client = ResourceGraphClient(self.credential, **ARM_TIMEOUT_KWARGS)

        # Batch app_ids
        all_app_ids = list(app_id_set.keys())
        result_map: Dict[str, List[Dict]] = {}

        for batch_start in range(0, len(all_app_ids), self._ARM_BATCH_SIZE):
            batch = all_app_ids[batch_start:batch_start + self._ARM_BATCH_SIZE]
            # Build KQL-safe comma-separated quoted list
            kql_list = ", ".join(f"'{aid}'" for aid in batch)

            for res_type, kql_template, binding_method, confidence in self._ARM_KQL_QUERIES:
                kql = kql_template.replace('{app_ids}', kql_list)
                try:
                    request = QueryRequest(
                        subscriptions=sub_ids,
                        query=kql,
                    )
                    response = rg_client.resources(request)
                    rows = response.data if hasattr(response, 'data') else []
                    if not rows:
                        continue

                    for row in rows:
                        # Determine which app_id matched
                        matched_value = (row.get('matchedValue') or '').strip()
                        if not matched_value:
                            # LogicApp query doesn't project matchedValue — match any in batch
                            for aid in batch:
                                if aid not in result_map:
                                    result_map[aid] = []
                                result_map[aid].append({
                                    'resource_id': row.get('id', ''),
                                    'resource_type': res_type,
                                    'resource_name': row.get('name', ''),
                                    'resource_group': row.get('resourceGroup', ''),
                                    'region': row.get('location', ''),
                                    'binding_method': binding_method,
                                    'confidence_score': max(confidence - 20, 50),
                                    'binding_evidence': {'parameterSearch': True},
                                    'subscription_id': '',
                                    'last_verified_at': None,
                                })
                            continue

                        # Exact match — find which batch app_id
                        matched_aid = None
                        for aid in batch:
                            if aid.lower() == matched_value.lower():
                                matched_aid = aid
                                break
                        if not matched_aid:
                            continue

                        if matched_aid not in result_map:
                            result_map[matched_aid] = []

                        evidence: Dict[str, Any] = {'matchedValue': matched_value}
                        if row.get('settingKey'):
                            evidence['settingKey'] = row['settingKey']
                        if row.get('envKey'):
                            evidence['envKey'] = row['envKey']

                        # Extract subscription_id from ARM resource id
                        rid = row.get('id', '')
                        import re as _re
                        sub_match = _re.search(r'/subscriptions/([^/]+)', rid, _re.IGNORECASE)
                        sub_id = sub_match.group(1) if sub_match else ''

                        result_map[matched_aid].append({
                            'resource_id': rid,
                            'resource_type': res_type,
                            'resource_name': row.get('name', ''),
                            'resource_group': row.get('resourceGroup', ''),
                            'region': row.get('location', ''),
                            'binding_method': binding_method,
                            'confidence_score': confidence,
                            'binding_evidence': evidence,
                            'subscription_id': sub_id,
                            'last_verified_at': None,
                        })

                except Exception as e:
                    logger.warning("ARM Resource Graph query failed for %s: %s", res_type, e)
                    continue

        total_bindings = sum(len(v) for v in result_map.values())
        if total_bindings:
            logger.info("ARM Resource Graph: found %s bindings across %s SPNs",
                        total_bindings, len(result_map))
        return result_map

    # KQL for managed identity association scan
    _MI_KQL = """
        Resources
        | where isnotempty(identity)
        | project id, name, type, resourceGroup, location,
                  identityType = tostring(identity.type),
                  systemPrincipalId = tostring(identity.principalId),
                  userAssigned = identity.userAssignedIdentities
    """

    def _fetch_managed_identity_associations(
        self, all_identities: List[Dict]
    ) -> Dict[str, List[Dict]]:
        """Scan Azure Resource Graph for resources with managed identity blocks.

        Queries all resources that have an `identity` property, then maps:
          - identity.principalId  → system-assigned MI (match via object_id)
          - identity.userAssignedIdentities keys → user-assigned MI ARM resource IDs
            (match via alternativeNames on the SPN)

        Args:
            all_identities: list of identity dicts (from discovery)

        Returns:
            dict mapping object_id -> list of ResourceBinding dicts
        """
        if ResourceGraphClient is None:
            logger.warning("azure-mgmt-resourcegraph not installed — skipping MI scan")
            return {}

        sub_ids = [s['id'] for s in self.subscriptions]
        if not sub_ids:
            return {}

        # Build lookup maps for matching
        # 1. object_id → identity_id (for system-assigned: principalId == object_id)
        oid_to_iid: Dict[str, str] = {}
        # 2. ARM resource ID (lowercase) → object_id (for user-assigned)
        uami_arm_to_oid: Dict[str, str] = {}

        for identity in all_identities:
            cat = identity.get('identity_category', '')
            oid = identity.get('object_id')
            if not oid:
                continue

            if cat in ('managed_identity_system', 'managed_identity_user', 'service_principal'):
                oid_to_iid[oid] = identity.get('identity_id', oid)

            # User-assigned MIs have ARM resource IDs in alternativeNames
            if cat == 'managed_identity_user':
                for alt in (identity.get('alternative_names') or []):
                    alt_str = str(alt).strip()
                    if '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/' in alt_str:
                        uami_arm_to_oid[alt_str.lower()] = oid

        if not oid_to_iid and not uami_arm_to_oid:
            return {}

        rg_client = ResourceGraphClient(self.credential, **ARM_TIMEOUT_KWARGS)
        result_map: Dict[str, List[Dict]] = {}

        try:
            request = QueryRequest(
                subscriptions=sub_ids,
                query=self._MI_KQL,
            )
            response = rg_client.resources(request)
            rows = response.data if hasattr(response, 'data') else []
        except Exception as e:
            logger.warning("Managed identity Resource Graph query failed: %s", e)
            return {}

        if not rows:
            return {}

        import re as _re

        for row in rows:
            resource_id = row.get('id', '')
            resource_name = row.get('name', '')
            resource_type_raw = row.get('type', '')
            resource_group = row.get('resourceGroup', '')
            region = row.get('location', '')
            sub_match = _re.search(r'/subscriptions/([^/]+)', resource_id, _re.IGNORECASE)
            sub_id = sub_match.group(1) if sub_match else ''

            # Normalize resource type: microsoft.web/sites → WebApp
            rtype_short = resource_type_raw.split('/')[-1] if '/' in resource_type_raw else resource_type_raw

            # ── System-assigned MI ──
            sys_pid = (row.get('systemPrincipalId') or '').strip()
            if sys_pid and sys_pid in oid_to_iid:
                if sys_pid not in result_map:
                    result_map[sys_pid] = []
                result_map[sys_pid].append({
                    'resource_id': resource_id,
                    'resource_type': rtype_short,
                    'resource_name': resource_name,
                    'resource_group': resource_group,
                    'region': region,
                    'binding_method': 'ManagedIdentitySystemAssigned',
                    'confidence_score': 95,
                    'binding_evidence': {
                        'principalId': sys_pid,
                        'identityType': row.get('identityType', ''),
                        'association_type': 'managed_identity',
                        'match_type': 'managed_identity_binding',
                    },
                    'subscription_id': sub_id,
                    'last_verified_at': None,
                })

            # ── User-assigned MIs ──
            user_assigned = row.get('userAssigned')
            if isinstance(user_assigned, dict):
                for uami_arm_id, uami_props in user_assigned.items():
                    uami_key = uami_arm_id.strip().lower()
                    matched_oid = uami_arm_to_oid.get(uami_key)
                    if not matched_oid:
                        # Try matching by principalId inside the value
                        if isinstance(uami_props, dict):
                            pid = (uami_props.get('principalId') or '').strip()
                            if pid and pid in oid_to_iid:
                                matched_oid = pid
                    if not matched_oid:
                        continue

                    if matched_oid not in result_map:
                        result_map[matched_oid] = []
                    result_map[matched_oid].append({
                        'resource_id': resource_id,
                        'resource_type': rtype_short,
                        'resource_name': resource_name,
                        'resource_group': resource_group,
                        'region': region,
                        'binding_method': 'ManagedIdentityUserAssigned',
                        'confidence_score': 95,
                        'binding_evidence': {
                            'userAssignedArmId': uami_arm_id,
                            'principalId': uami_props.get('principalId', '') if isinstance(uami_props, dict) else '',
                            'association_type': 'managed_identity',
                            'match_type': 'managed_identity_binding',
                        },
                        'subscription_id': sub_id,
                        'last_verified_at': None,
                    })

        total = sum(len(v) for v in result_map.values())
        sys_count = sum(
            1 for bindings in result_map.values()
            for b in bindings if b['binding_method'] == 'ManagedIdentitySystemAssigned'
        )
        uami_count = total - sys_count
        if total:
            logger.info("Managed identity associations: %s bindings (%s system-assigned, %s user-assigned) across %s identities",
                        total, sys_count, uami_count, len(result_map))
        return result_map

    async def _discover_credentials(self, service_principals: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Discover credentials (secrets, certificates, federated) for service principals

        Returns:
            Dictionary mapping identity_id to list of credentials
        """
        # AG-74 Phase 1: Skip Microsoft system SPNs — credentials are Microsoft-managed
        customer_sps = [sp for sp in service_principals if not sp.get('is_microsoft_system')]
        logger.info("[_discover_credentials] processing %s/%s customer SPNs (skipping %s MS system)",
                    len(customer_sps), len(service_principals),
                    len(service_principals) - len(customer_sps))
        service_principals = customer_sps

        credentials_map = {}

        logger.info("Discovering SPN Credentials...")
        
        for sp in service_principals:
            try:
                # Get full service principal details including credentials
                sp_response = await asyncio.wait_for(self.graph_client.service_principals.by_service_principal_id(sp['object_id']).get(), timeout=GRAPH_SDK_TIMEOUT)
                
                credentials = []
                
                # Process password credentials (secrets)
                if hasattr(sp_response, 'password_credentials') and sp_response.password_credentials:
                    for pwd_cred in sp_response.password_credentials:
                        credentials.append({
                            'credential_type': 'secret',
                            'key_id': str(pwd_cred.key_id) if pwd_cred.key_id else None,
                            'display_name': pwd_cred.display_name if hasattr(pwd_cred, 'display_name') else None,
                            'start_datetime': pwd_cred.start_date_time.isoformat() if hasattr(pwd_cred, 'start_date_time') and pwd_cred.start_date_time else None,
                            'end_datetime': pwd_cred.end_date_time.isoformat() if hasattr(pwd_cred, 'end_date_time') and pwd_cred.end_date_time else None,
                        })
                
                # Process key credentials (certificates)
                if hasattr(sp_response, 'key_credentials') and sp_response.key_credentials:
                    for key_cred in sp_response.key_credentials:
                        credentials.append({
                            'credential_type': 'certificate',
                            'key_id': str(key_cred.key_id) if key_cred.key_id else None,
                            'display_name': key_cred.display_name if hasattr(key_cred, 'display_name') else None,
                            'start_datetime': key_cred.start_date_time.isoformat() if hasattr(key_cred, 'start_date_time') and key_cred.start_date_time else None,
                            'end_datetime': key_cred.end_date_time.isoformat() if hasattr(key_cred, 'end_date_time') and key_cred.end_date_time else None,
                            'thumbprint': key_cred.custom_key_identifier.decode('utf-8') if hasattr(key_cred, 'custom_key_identifier') and key_cred.custom_key_identifier else None,
                        })
                
                # Process federated credentials
                if hasattr(sp_response, 'federated_identity_credentials') and sp_response.federated_identity_credentials:
                    for fed_cred in sp_response.federated_identity_credentials:
                        issuer = fed_cred.issuer if hasattr(fed_cred, 'issuer') else None
                        subject = fed_cred.subject if hasattr(fed_cred, 'subject') else None
                        classification = self._classify_federated_credential(issuer, subject)
                        cred_dict = {
                            'credential_type': 'federated',
                            'key_id': fed_cred.id if hasattr(fed_cred, 'id') else str(hash(fed_cred.subject)),
                            'display_name': fed_cred.name if hasattr(fed_cred, 'name') else None,
                            'start_datetime': None,
                            'end_datetime': None,  # Federated credentials don't expire
                            'issuer': issuer,
                            'subject': subject,
                        }
                        cred_dict.update(classification)
                        credentials.append(cred_dict)
                
                if credentials:
                    credentials_map[sp['identity_id']] = credentials
                    if len(credentials_map) <= 5:  # Show first 5
                        logger.info("%s: %s credential(s)", sp['display_name'], len(credentials))
            
            except Exception as e:
                # Don't fail entire discovery if one SPN fails
                if len(credentials_map) == 0:  # Only show first error
                    logger.warning("Error getting credentials for %s: %s", sp['display_name'], e)
                continue
        
        logger.info("Found credentials for %s SPNs", len(credentials_map))
        return credentials_map


    async def _resolve_app_role_name(self, resource_spn_id: str, app_role_id: str) -> tuple:
        """
        Resolve appRoleId to (permission_name, resource_display_name) using cache.
        Returns ('', '') if unresolvable.
        """
        resource_spn_id = str(resource_spn_id)
        app_role_id = str(app_role_id)

        if resource_spn_id not in self._resource_spn_cache:
            try:
                resource_sp = await asyncio.wait_for(self.graph_client.service_principals.by_service_principal_id(
                    resource_spn_id
                ).get(), timeout=GRAPH_SDK_TIMEOUT)
                roles_lookup = {}
                if hasattr(resource_sp, 'app_roles') and resource_sp.app_roles:
                    for role in resource_sp.app_roles:
                        roles_lookup[str(role.id)] = role.value or ''
                self._resource_spn_cache[resource_spn_id] = {
                    'roles': roles_lookup,
                    'display_name': resource_sp.display_name if resource_sp.display_name else 'Unknown',
                }
            except Exception as e:
                logger.debug("Could not fetch resource SPN %s: %s", resource_spn_id, e)
                self._resource_spn_cache[resource_spn_id] = {'roles': {}, 'display_name': 'Unknown'}

        cached = self._resource_spn_cache[resource_spn_id]
        perm_name = cached['roles'].get(app_role_id, '')
        return perm_name, cached['display_name']

    async def _discover_permissions(self, service_principals: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Discover Graph API permissions for service principals.

        Collects both:
          - Application permissions (appRoleAssignments) — what the SPN can do as itself
          - Delegated permissions (oauth2PermissionGrants) — what users consented to

        Returns:
            Dictionary mapping identity_id to list of permissions
        """
        # AG-74 Phase 1: Skip Microsoft system SPNs — permissions are Microsoft-managed
        customer_sps = [sp for sp in service_principals if not sp.get('is_microsoft_system')]
        logger.info("[_discover_permissions] processing %s/%s customer SPNs (skipping %s MS system)",
                    len(customer_sps), len(service_principals),
                    len(service_principals) - len(customer_sps))
        service_principals = customer_sps

        permissions_map: Dict[str, List[Dict]] = {}
        app_perm_total = 0
        delegated_perm_total = 0
        error_count = 0

        logger.info("Discovering API Permissions...")

        for sp in service_principals:
            sp_object_id = sp.get('object_id')
            sp_identity_id = sp.get('identity_id')
            if not sp_object_id:
                continue

            permissions: List[Dict] = []

            # ── Application permissions (appRoleAssignments) ──
            try:
                assignments = await asyncio.wait_for(self.graph_client.service_principals.by_service_principal_id(
                    sp_object_id
                ).app_role_assignments.get(), timeout=GRAPH_SDK_TIMEOUT)

                if assignments and assignments.value:
                    for assignment in assignments.value:
                        resource_id = str(assignment.resource_id) if assignment.resource_id else ''
                        app_role_id = str(assignment.app_role_id) if assignment.app_role_id else ''

                        perm_name, resource_name = await self._resolve_app_role_name(resource_id, app_role_id)
                        if perm_name:
                            permissions.append({
                                'name': perm_name,
                                'description': f"{resource_name}: {perm_name}",
                                'resource_name': resource_name,
                                'permission_type': 'Application',
                                'permission_id': app_role_id,
                                'consent_type': 'Admin',
                            })
                            app_perm_total += 1
            except Exception as e:
                logger.warning("appRoleAssignments failed for %s (%s): %s",
                               sp.get('display_name', '?'), sp_object_id, e)
                error_count += 1

            # ── Delegated permissions (oauth2PermissionGrants) ──
            try:
                from msgraph.generated.oauth2_permission_grants.oauth2_permission_grants_request_builder import Oauth2PermissionGrantsRequestBuilder
                from kiota_abstractions.base_request_configuration import RequestConfiguration

                query = Oauth2PermissionGrantsRequestBuilder.Oauth2PermissionGrantsRequestBuilderGetQueryParameters(
                    filter=f"clientId eq '{sp_object_id}'",
                )
                config = RequestConfiguration(query_parameters=query)
                grants = await asyncio.wait_for(self.graph_client.oauth2_permission_grants.get(request_configuration=config), timeout=GRAPH_SDK_TIMEOUT)

                if grants and grants.value:
                    for grant in grants.value:
                        # Resolve resource SPN to get actual resource name
                        resource_spn_id = str(grant.resource_id) if grant.resource_id else ''
                        resource_name = 'Microsoft Graph'
                        resource_app_id = ''
                        if resource_spn_id and resource_spn_id in self._resource_spn_cache:
                            cached = self._resource_spn_cache[resource_spn_id]
                            resource_name = cached.get('display_name', 'Microsoft Graph')
                            resource_app_id = cached.get('app_id', '')
                        elif resource_spn_id:
                            try:
                                res_sp = await asyncio.wait_for(self.graph_client.service_principals.by_service_principal_id(
                                    resource_spn_id
                                ).get(), timeout=GRAPH_SDK_TIMEOUT)
                                if res_sp:
                                    resource_name = res_sp.display_name or 'Microsoft Graph'
                                    resource_app_id = str(res_sp.app_id) if res_sp.app_id else ''
                                    self._resource_spn_cache[resource_spn_id] = {
                                        'display_name': resource_name,
                                        'app_id': resource_app_id,
                                        'roles': {},
                                    }
                            except Exception:
                                pass
                        scope_str = grant.scope or ''
                        for perm_name in scope_str.split():
                            perm_name = perm_name.strip()
                            if perm_name:
                                permissions.append({
                                    'name': perm_name,
                                    'description': perm_name,
                                    'resource_name': resource_name,
                                    'resource_app_id': resource_app_id,
                                    'permission_type': 'Delegated',
                                    'consent_type': grant.consent_type or 'Unknown',
                                })
                                delegated_perm_total += 1
            except Exception as e:
                logger.warning("oauth2PermissionGrants failed for %s (%s): %s",
                               sp.get('display_name', '?'), sp_object_id, e)
                error_count += 1

            if permissions:
                permissions_map[sp_identity_id] = permissions
                if len(permissions_map) <= 5:  # Show first 5
                    logger.info("%s: %s permission(s)", sp['display_name'], len(permissions))

        # ── M1: Compute api_usage_pattern per SPN from distinct resource APIs ──
        for sp in service_principals:
            sp_identity_id = sp.get('identity_id')
            perms = permissions_map.get(sp_identity_id, [])
            if not perms:
                continue
            # Collect distinct resource API names
            resource_apis = set()
            for p in perms:
                rname = p.get('resource_name', '')
                # Map display name back to KNOWN_APIS key
                for api_id, api_label in self.KNOWN_APIS.items():
                    if api_label.replace('_', ' ') in rname.lower() or rname.lower().replace(' ', '_') == api_label:
                        resource_apis.add(api_label)
                        break
                else:
                    # Try resource_app_id directly
                    rap_id = p.get('resource_app_id', '')
                    if rap_id in self.KNOWN_APIS:
                        resource_apis.add(self.KNOWN_APIS[rap_id])
                    elif 'graph' in rname.lower():
                        resource_apis.add('microsoft_graph')
            api_list = sorted(resource_apis)
            sp['oauth2_resource_apis'] = api_list or None
            # Match against API_USAGE_WORKLOAD_MAP
            pattern = 'none'
            frozen = frozenset(resource_apis)
            if frozen in self.API_USAGE_WORKLOAD_MAP:
                pattern = self.API_USAGE_WORKLOAD_MAP[frozen]
            elif resource_apis:
                # Try subset matching — find the best match
                best_match = None
                best_size = 0
                for key_set, label in self.API_USAGE_WORKLOAD_MAP.items():
                    if key_set.issubset(frozen) and len(key_set) > best_size:
                        best_match = label
                        best_size = len(key_set)
                pattern = best_match or f'multi_api_{len(resource_apis)}'
            sp['api_usage_pattern'] = pattern

        logger.info("Permissions: %s application + %s delegated across %s SPNs%s",
                     app_perm_total, delegated_perm_total, len(permissions_map),
                     " (%s errors)" % error_count if error_count else "")
        return permissions_map

    async def _discover_app_roles(self, service_principals: list) -> dict:
        """
        Discover custom application role assignments for service principals.
        Returns assignments to custom apps (NOT Microsoft Graph).

        Similar to _discover_permissions but filters OUT Microsoft Graph.

        Args:
            service_principals: List of service principal dicts

        Returns:
            Dict mapping identity_id to list of app role assignments
        """
        # AG-74 Phase 1: Skip Microsoft system SPNs — app roles are Microsoft-managed
        customer_sps = [sp for sp in service_principals if not sp.get('is_microsoft_system')]
        logger.info("[_discover_app_roles] processing %s/%s customer SPNs (skipping %s MS system)",
                    len(customer_sps), len(service_principals),
                    len(service_principals) - len(customer_sps))
        service_principals = customer_sps

        logger.info("Discovering Custom App Roles...")
        app_roles_map = {}
        found_count = 0
        
        for sp in service_principals:
            identity_id = sp.get('id')
            if not identity_id:
                continue
            
            try:
                # Fetch app role assignments (same endpoint as permissions)
                response = await asyncio.wait_for(self.graph_client.service_principals.by_service_principal_id(
                    identity_id
                ).app_role_assignments.get(), timeout=GRAPH_SDK_TIMEOUT)
                
                assignments = response.value if response and response.value else []
                
                # Filter OUT Microsoft Graph (we store those separately)
                custom_app_roles = [
                    {
                        'app_role_id': assignment.app_role_id,
                        'resource_id': assignment.resource_id,
                        'resource_display_name': assignment.resource_display_name,
                        'principal_display_name': assignment.principal_display_name,
                        'created_date_time': assignment.created_date_time.isoformat() if assignment.created_date_time else None,
                    }
                    for assignment in assignments
                    if assignment.resource_display_name and assignment.resource_display_name.lower() != 'microsoft graph'
                ]
                
                if custom_app_roles:
                    app_roles_map[identity_id] = custom_app_roles
                    found_count += 1
                    logger.info("%s: %s app role(s)", sp.get('displayName', 'Unknown'), len(custom_app_roles))
                
            except Exception as e:
                # Silently skip if no permissions or access denied
                continue
        
        if found_count > 0:
            logger.info("Fetched app roles for %s service principals", found_count)
        else:
            logger.info("No custom app role assignments found")
        
        return app_roles_map

    async def _discover_ownership(self, service_principals: list) -> dict:
        """
        Discover owners for service principals via their application registration.

        Each SPN may have an associated application registration with owners.
        Owners are typically the humans who created or manage the application.

        Microsoft Graph API: GET /applications/{app-id}/owners

        Returns:
            Dict mapping identity_id -> list of owner dicts
        """
        # AG-74 Phase 1: Skip Microsoft system SPNs — ownership is Microsoft-managed
        customer_sps = [sp for sp in service_principals if not sp.get('is_microsoft_system')]
        logger.info("[_discover_ownership] processing %s/%s customer SPNs (skipping %s MS system)",
                    len(customer_sps), len(service_principals),
                    len(service_principals) - len(customer_sps))
        service_principals = customer_sps

        logger.info("Discovering Application Owners...")
        ownership_map = {}
        found_count = 0
        error_count = 0

        for sp in service_principals:
            identity_id = sp.get('identity_id')
            app_id = sp.get('app_id')

            # Skip if no app_id (e.g., managed identities don't have app registrations)
            if not app_id:
                continue

            # Skip Microsoft internal apps
            if sp.get('is_microsoft_system'):
                continue

            try:
                # Get the application by appId, then get its owners
                # First, find the application object ID from the appId
                from msgraph.generated.applications.applications_request_builder import ApplicationsRequestBuilder
                from kiota_abstractions.base_request_configuration import RequestConfiguration

                query_params = ApplicationsRequestBuilder.ApplicationsRequestBuilderGetQueryParameters(
                    filter=f"appId eq '{app_id}'",
                    select=['id', 'displayName']
                )
                request_config = RequestConfiguration(query_parameters=query_params)

                apps = await asyncio.wait_for(self.graph_client.applications.get(request_configuration=request_config), timeout=GRAPH_SDK_TIMEOUT)

                if apps and apps.value and len(apps.value) > 0:
                    app_object_id = apps.value[0].id

                    # Now get the owners
                    owners_response = await asyncio.wait_for(self.graph_client.applications.by_application_id(app_object_id).owners.get(), timeout=GRAPH_SDK_TIMEOUT)

                    if owners_response and owners_response.value:
                        owners = []
                        is_first = True
                        for owner in owners_response.value:
                            owner_data = {
                                'owner_object_id': owner.id,
                                'owner_display_name': getattr(owner, 'display_name', None),
                                'owner_upn': getattr(owner, 'user_principal_name', None) or getattr(owner, 'mail', None),
                                'owner_type': 'user' if hasattr(owner, 'user_principal_name') else 'servicePrincipal',
                                'is_primary_owner': is_first,
                                'ownership_type': 'application',
                            }
                            owners.append(owner_data)
                            is_first = False

                        if owners:
                            ownership_map[identity_id] = owners
                            found_count += 1

                            if found_count <= 5:
                                logger.info("%s: %s owner(s)", sp.get('display_name', 'Unknown'), len(owners))

            except Exception as e:
                error_count += 1
                if error_count <= 3:
                    logger.warning("Could not get owners for %s: %s", sp.get('display_name', 'Unknown'), str(e)[:50])

        if found_count > 0:
            logger.info("Found owners for %s applications", found_count)
        else:
            logger.info("No application owners found")

        if error_count > 3:
            logger.warning("%s errors occurred (showing first 3)", error_count)

        return ownership_map

    async def _discover_pim_assignments(self) -> dict:
        """
        Discover PIM eligible role assignments and active activations.

        Uses Microsoft Graph API:
        - roleEligibilityScheduleInstances — eligible roles
        - roleAssignmentScheduleInstances — active activations (filter: Activated)
        - roleAssignmentScheduleRequests — history with justification/ticket

        Requires Azure AD P2 license. Handle 403 gracefully.

        Returns:
            Dict mapping object_id -> { 'eligible': [...], 'activations': [...] }
        """
        logger.info("Discovering PIM Assignments...")
        pim_map = {}  # keyed by principal object_id

        # Cache role definitions to avoid redundant API calls
        role_def_cache = {}

        async def _get_role_name(role_definition_id: str) -> str:
            if role_definition_id in role_def_cache:
                return role_def_cache[role_definition_id]
            try:
                role_def = await asyncio.wait_for(self.graph_client.role_management.directory.role_definitions.by_unified_role_definition_id(role_definition_id).get(), timeout=GRAPH_SDK_TIMEOUT)
                name = role_def.display_name if role_def else "Unknown Role"
            except Exception:
                name = "Unknown Role"
            role_def_cache[role_definition_id] = name
            return name

        # --- Eligible assignments ---
        eligible_count = 0
        try:
            eligible_response = await asyncio.wait_for(self.graph_client.role_management.directory.role_eligibility_schedule_instances.get(), timeout=GRAPH_SDK_TIMEOUT)
            if eligible_response and eligible_response.value:
                for item in eligible_response.value:
                    principal_id = item.principal_id
                    role_def_id = item.role_definition_id
                    role_name = await _get_role_name(role_def_id)

                    if principal_id not in pim_map:
                        pim_map[principal_id] = {'eligible': [], 'activations': []}

                    is_permanent = item.end_date_time is None
                    pim_map[principal_id]['eligible'].append({
                        'role_name': role_name,
                        'role_definition_id': role_def_id,
                        'directory_scope': getattr(item, 'directory_scope_id', '/') or '/',
                        'assignment_type': 'permanent_eligible' if is_permanent else 'time_bound_eligible',
                        'start_datetime': item.start_date_time.isoformat() if item.start_date_time else None,
                        'end_datetime': item.end_date_time.isoformat() if item.end_date_time else None,
                        'member_type': getattr(item, 'member_type', None),
                    })
                    eligible_count += 1

            logger.info("Found %s PIM eligible assignments", eligible_count)

        except Exception as e:
            err_str = str(e)
            if '403' in err_str or 'Forbidden' in err_str or 'Authorization' in err_str:
                logger.info("PIM eligible assignments: requires Azure AD P2 license (403)")
            else:
                logger.warning("PIM eligible assignments error: %s", err_str[:80])

        # --- Active activations ---
        activation_count = 0
        try:
            activations_response = await asyncio.wait_for(self.graph_client.role_management.directory.role_assignment_schedule_instances.get(), timeout=GRAPH_SDK_TIMEOUT)
            if activations_response and activations_response.value:
                for item in activations_response.value:
                    # Only track activated (JIT) assignments, skip permanently assigned
                    assignment_type = getattr(item, 'assignment_type', None)
                    if assignment_type and assignment_type.lower() == 'assigned':
                        continue

                    principal_id = item.principal_id
                    role_def_id = item.role_definition_id
                    role_name = await _get_role_name(role_def_id)

                    if principal_id not in pim_map:
                        pim_map[principal_id] = {'eligible': [], 'activations': []}

                    pim_map[principal_id]['activations'].append({
                        'role_name': role_name,
                        'role_definition_id': role_def_id,
                        'directory_scope': getattr(item, 'directory_scope_id', '/') or '/',
                        'status': 'Active',
                        'activation_start': item.start_date_time.isoformat() if item.start_date_time else None,
                        'activation_end': item.end_date_time.isoformat() if item.end_date_time else None,
                    })
                    activation_count += 1

            logger.info("Found %s active PIM activations", activation_count)

        except Exception as e:
            err_str = str(e)
            if '403' in err_str or 'Forbidden' in err_str or 'Authorization' in err_str:
                logger.info("PIM activations: requires Azure AD P2 license (403)")
            else:
                logger.warning("PIM activations error: %s", err_str[:80])

        # --- Activation history (requests with justification/ticket) ---
        try:
            from kiota_abstractions.base_request_configuration import RequestConfiguration

            requests_response = await asyncio.wait_for(self.graph_client.role_management.directory.role_assignment_schedule_requests.get(), timeout=GRAPH_SDK_TIMEOUT)
            if requests_response and requests_response.value:
                for item in requests_response.value:
                    principal_id = item.principal_id
                    if principal_id not in pim_map:
                        continue  # only enrich identities we already know about

                    # Find matching activation and enrich with justification/ticket
                    role_def_id = item.role_definition_id
                    justification = getattr(item, 'justification', None)
                    ticket_info = getattr(item, 'ticket_info', None)
                    ticket_number = getattr(ticket_info, 'ticket_number', None) if ticket_info else None
                    ticket_system = getattr(ticket_info, 'ticket_system', None) if ticket_info else None
                    is_approval_required = False
                    created_dt = getattr(item, 'created_date_time', None)

                    for act in pim_map[principal_id]['activations']:
                        if act['role_definition_id'] == role_def_id and not act.get('justification'):
                            act['justification'] = justification
                            act['ticket_number'] = ticket_number
                            act['ticket_system'] = ticket_system
                            act['is_approval_required'] = is_approval_required
                            act['created_datetime'] = created_dt.isoformat() if created_dt else None
                            break

        except Exception as e:
            err_str = str(e)
            if '403' not in err_str and 'Forbidden' not in err_str:
                logger.warning("PIM request history error: %s", err_str[:80])

        if pim_map:
            logger.info("PIM data found for %s principals", len(pim_map))
        else:
            logger.info("No PIM data found (Azure AD P2 required)")

        return pim_map

    async def _collect_mfa_registration(self) -> dict:
        """Collect per-user MFA/SSPR registration status via Graph API.

        Uses the beta credentialUserRegistrationDetails report endpoint
        (one bulk call for all users in the tenant).

        Requires: Reports.Read.All permission.
        Returns: dict mapping user object_id -> {mfa_registered, sspr_registered}
        """
        logger.info("Collecting MFA/SSPR registration data...")
        mfa_map: dict[str, dict] = {}

        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}

            url: str | None = (
                "https://graph.microsoft.com/beta"
                "/reports/credentialUserRegistrationDetails?$top=999"
            )

            async with aiohttp.ClientSession(timeout=GRAPH_HTTP_TIMEOUT) as session:
                page = 0
                while url:
                    page += 1
                    async with self._graph_semaphore:
                        async with session.get(url, headers=headers) as resp:
                            if resp.status == 403:
                                logger.warning(
                                    "[MFA] 403 Forbidden — Reports.Read.All "
                                    "permission likely missing. MFA data will "
                                    "be NULL (unknown). org=%s",
                                    self.db_org_id,
                                )
                                return mfa_map
                            if resp.status == 404:
                                logger.warning(
                                    "[MFA] 404 — credentialUserRegistrationDetails "
                                    "endpoint not available. org=%s",
                                    self.db_org_id,
                                )
                                return mfa_map
                            if resp.status != 200:
                                body = await resp.text()
                                logger.warning(
                                    "[MFA] HTTP %s on page %s — %s. org=%s",
                                    resp.status, page, body[:200], self.db_org_id,
                                )
                                return mfa_map
                            data = await resp.json()

                    for entry in data.get('value', []):
                        uid = entry.get('id')
                        if uid:
                            mfa_map[uid] = {
                                'mfa_registered': entry.get('isMfaRegistered'),
                                'sspr_registered': entry.get('isSsprRegistered'),
                            }

                    url = data.get('@odata.nextLink')

            logger.info(
                "[MFA] Collected registration data for %s users. org=%s",
                len(mfa_map), self.db_org_id,
            )
        except Exception as e:
            logger.warning(
                "[MFA] Collection failed: %s. MFA data will be NULL. org=%s",
                e, self.db_org_id,
            )

        return mfa_map

    # ── AG-161: Per-user authentication methods (fallback for MFA status) ──

    # Method types that count as genuine MFA factors
    MFA_FACTOR_TYPES = {
        'microsoftAuthenticatorAuthenticationMethod',
        'phoneAuthenticationMethod',
        'fido2AuthenticationMethod',
        'windowsHelloForBusinessAuthenticationMethod',
        'softwareOathAuthenticationMethod',
        'temporaryAccessPassAuthenticationMethod',
    }
    # Non-MFA types (password, email used for SSPR only)
    NON_MFA_TYPES = {
        'passwordAuthenticationMethod',
        'emailAuthenticationMethod',
    }

    async def _collect_mfa_auth_methods(self, human_identities: list) -> dict:
        """Collect per-user MFA enrollment via /users/{id}/authentication/methods.

        Requires: UserAuthenticationMethod.Read.All (Application).
        No P2 dependency. Falls back from the bulk credentialUserRegistrationDetails
        endpoint which requires Reports.Read.All.

        Uses concurrent requests (bounded by _graph_semaphore) to cover
        large tenants within the time budget.

        Returns: dict mapping object_id -> {mfa_status, mfa_methods}
        """
        import time as _time
        phase_start = _time.monotonic()
        TIME_BUDGET = 600  # seconds — enough for ~1000+ users with concurrency

        mfa_result: dict[str, dict] = {}
        if not human_identities:
            return mfa_result

        # Only process human identities with an object_id
        targets = [(h.get('object_id'), h.get('display_name', ''))
                    for h in human_identities if h.get('object_id')]
        if not targets:
            return mfa_result

        logger.info(
            "[MFA-methods] Collecting authentication methods for %s humans (concurrent). org=%s",
            len(targets), self.db_org_id,
        )

        # Shared mutable state for the permission-check sentinel
        _permission_ok = True

        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}

            _diag = {'throttled': 0, 'not_found': 0, 'timeout': 0, 'other_err': 0, 'budget_skip': 0}

            async def _fetch_one(session, oid):
                nonlocal _permission_ok
                if not _permission_ok:
                    return None
                if _time.monotonic() - phase_start > TIME_BUDGET:
                    _diag['budget_skip'] += 1
                    return None

                url = f"https://graph.microsoft.com/v1.0/users/{oid}/authentication/methods"
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        async with self._graph_semaphore:
                            if not _permission_ok:
                                return None
                            async with session.get(url, headers=headers) as resp:
                                if resp.status in (401, 403):
                                    _permission_ok = False
                                    logger.warning(
                                        "[MFA-methods] %s — "
                                        "UserAuthenticationMethod.Read.All likely missing. org=%s",
                                        resp.status, self.db_org_id,
                                    )
                                    return None
                                if resp.status == 404:
                                    _diag['not_found'] += 1
                                    return None
                                if resp.status == 429:
                                    _diag['throttled'] += 1
                                    retry_after = int(resp.headers.get('Retry-After', 2))
                                    await asyncio.sleep(min(retry_after, 10))
                                    continue  # retry
                                if resp.status != 200:
                                    _diag['other_err'] += 1
                                    return None

                                data = await resp.json()
                                methods_raw = data.get('value', [])

                                method_types = []
                                has_mfa_factor = False
                                for m in methods_raw:
                                    odata_type = m.get('@odata.type', '')
                                    suffix = odata_type.rsplit('.', 1)[-1] if '.' in odata_type else odata_type
                                    method_types.append(suffix)
                                    if suffix in self.MFA_FACTOR_TYPES:
                                        has_mfa_factor = True

                                return (oid, {
                                    'mfa_status': 'enrolled' if has_mfa_factor else 'not_enrolled',
                                    'mfa_methods': method_types,
                                })
                    except asyncio.TimeoutError:
                        _diag['timeout'] += 1
                        if attempt < max_retries - 1:
                            await asyncio.sleep(1)
                            continue
                        return None
                    except Exception as e:
                        logger.debug("[MFA-methods] Error for %s: %s", oid, str(e)[:100])
                        return None
                return None  # all retries exhausted

            # Fire all requests concurrently; semaphore bounds in-flight count
            async with aiohttp.ClientSession(timeout=GRAPH_HTTP_TIMEOUT) as session:
                tasks = [_fetch_one(session, oid) for oid, _ in targets]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, tuple) and r is not None:
                        mfa_result[r[0]] = r[1]

            logger.info(
                "[MFA-methods] Collected auth methods for %s/%s humans. "
                "throttled=%s not_found=%s timeout=%s other=%s budget_skip=%s org=%s",
                len(mfa_result), len(targets),
                _diag['throttled'], _diag['not_found'], _diag['timeout'],
                _diag['other_err'], _diag['budget_skip'], self.db_org_id,
            )
        except Exception as e:
            logger.warning(
                "[MFA-methods] Collection failed: %s. org=%s",
                e, self.db_org_id,
            )

        return mfa_result

    async def _discover_conditional_access(self) -> list:
        """
        Discover Conditional Access policies via Microsoft Graph API.

        Uses: graph_client.identity.conditional_access.policies.get()
        Requires: Policy.Read.All permission. Handle 403 gracefully.

        Returns:
            List of parsed CA policy dicts
        """
        logger.info("Discovering Conditional Access Policies...")
        policies = []

        try:
            ca_response = await asyncio.wait_for(self.graph_client.identity.conditional_access.policies.get(), timeout=GRAPH_SDK_TIMEOUT)
            if ca_response and ca_response.value:
                for policy in ca_response.value:
                    state = getattr(policy, 'state', None)
                    if state and hasattr(state, 'value'):
                        state = state.value
                    state = str(state or 'unknown').lower()

                    # Parse conditions
                    conditions = getattr(policy, 'conditions', None)
                    users_cond = getattr(conditions, 'users', None) if conditions else None
                    apps_cond = getattr(conditions, 'applications', None) if conditions else None
                    client_app_types = getattr(conditions, 'client_app_types', []) if conditions else []
                    if client_app_types and hasattr(client_app_types[0], 'value'):
                        client_app_types = [str(c.value) for c in client_app_types]
                    else:
                        client_app_types = [str(c) for c in (client_app_types or [])]

                    include_users = []
                    exclude_users = []
                    targets_all_users = False
                    has_exclusions = False

                    if users_cond:
                        inc = getattr(users_cond, 'include_users', []) or []
                        exc = getattr(users_cond, 'exclude_users', []) or []
                        include_users = [str(u) for u in inc]
                        exclude_users = [str(u) for u in exc]
                        targets_all_users = 'All' in include_users
                        has_exclusions = len(exclude_users) > 0

                    include_applications = []
                    if apps_cond:
                        inc_apps = getattr(apps_cond, 'include_applications', []) or []
                        include_applications = [str(a) for a in inc_apps]

                    # Parse grant controls
                    grant = getattr(policy, 'grant_controls', None)
                    requires_mfa = False
                    grant_dict = {}
                    if grant:
                        built_in = getattr(grant, 'built_in_controls', []) or []
                        if built_in and hasattr(built_in[0], 'value'):
                            built_in = [str(c.value) for c in built_in]
                        else:
                            built_in = [str(c) for c in built_in]
                        requires_mfa = 'mfa' in [b.lower() for b in built_in]
                        grant_dict = {'built_in_controls': built_in}

                    # Legacy auth detection
                    allows_legacy_auth = 'exchangeActiveSync' in client_app_types or 'other' in client_app_types

                    modified = getattr(policy, 'modified_date_time', None)

                    policies.append({
                        'policy_id': policy.id,
                        'display_name': policy.display_name or 'Unnamed',
                        'state': state,
                        'include_users': include_users,
                        'exclude_users': exclude_users,
                        'include_applications': include_applications,
                        'client_app_types': client_app_types,
                        'grant_controls': grant_dict,
                        'session_controls': {},
                        'requires_mfa': requires_mfa,
                        'targets_all_users': targets_all_users,
                        'has_exclusions': has_exclusions,
                        'allows_legacy_auth': allows_legacy_auth,
                        'modified_datetime': modified.isoformat() if modified else None,
                    })

            logger.info("Found %s Conditional Access policies", len(policies))
            enabled = sum(1 for p in policies if p['state'] == 'enabled')
            mfa = sum(1 for p in policies if p['requires_mfa'] and p['state'] == 'enabled')
            logger.info("Enabled: %s, MFA-enforcing: %s", enabled, mfa)

        except Exception as e:
            err_str = str(e)
            if '403' in err_str or 'Forbidden' in err_str or 'Authorization' in err_str:
                logger.info("Conditional Access: requires Policy.Read.All permission (403)")
                self._persist_permission(
                    'conditional_access', 'denied',
                    error_detail='Policy.Read.All permission not granted',
                    impact_description='Conditional Access policy coverage and MFA enforcement '
                                      'data unavailable.')
            else:
                logger.warning("Conditional Access error: %s", err_str[:80])

        if policies:
            self._persist_permission('conditional_access', 'granted')
        return policies

    def _compute_ca_coverage(self, ca_policies: list, identities: list) -> dict:
        """
        Compute per-identity CA coverage using a simplified heuristic.

        If any enabled policy targets 'All' users and the identity is not excluded -> covered.

        Returns:
            Dict mapping object_id -> coverage dict
        """
        coverage_map = {}

        # Build set of exclude user IDs from all-users policies
        all_user_policies = [p for p in ca_policies if p.get('targets_all_users') and p.get('state') == 'enabled']
        mfa_all_user_policies = [p for p in all_user_policies if p.get('requires_mfa')]

        # Build global exclude set
        global_excludes = set()
        for p in all_user_policies:
            for uid in p.get('exclude_users', []):
                global_excludes.add(uid)

        for identity in identities:
            object_id = identity.get('object_id')
            if not object_id:
                continue

            is_excluded = object_id in global_excludes
            applicable = len(all_user_policies)
            excluded_from = sum(1 for p in all_user_policies if object_id in p.get('exclude_users', []))

            if applicable == 0:
                coverage_status = 'no_coverage'
                mfa_enforced = False
            elif is_excluded:
                coverage_status = 'excluded'
                mfa_enforced = False
            else:
                mfa_enforced = len(mfa_all_user_policies) > 0 and not is_excluded
                coverage_status = 'covered'

            risk_flags = []
            if is_excluded and applicable > 0:
                risk_flags.append('excluded_from_ca_policy')
            if not mfa_enforced and applicable > 0:
                risk_flags.append('no_mfa_enforced')

            coverage_map[object_id] = {
                'coverage_status': coverage_status,
                'mfa_enforced': mfa_enforced,
                'applicable_policy_count': applicable,
                'excluded_from_count': excluded_from,
                'risk_flags': risk_flags,
            }

        return coverage_map

    async def _discover_managed_identities(self) -> List[Dict]:
        """
        Discover user-assigned managed identities from Azure subscription.
        These appear as service principals in Entra ID with servicePrincipalType = 'ManagedIdentity'.
        
        Note: System-assigned managed identities are tied to specific Azure resources
        and are filtered out by _is_microsoft_system_app() since they're auto-managed.
        
        Returns:
            List of managed identity dicts (already in service_principals, this is supplementary)
        """
        managed_identities = []
        
        try:
            # Managed identities are actually already in the service principals list!
            # They have servicePrincipalType = 'ManagedIdentity' for user-assigned
            # We don't need a separate call - they're included in _discover_service_principals
            
            # This method exists for potential future enhancement (e.g., fetching from ARM API)
            # For now, managed identities are already discovered as service principals
            pass
            
        except Exception as e:
            logger.warning("Could not discover managed identities: %s", e)
        
        return managed_identities

    # ── AG-75: Identity Inclusion Criteria ─────────────────────────────
    def _collect_relevant_principal_ids(
        self,
        role_assignments: List[Dict],
        entra_roles: List[Dict],
        pim_map: Dict[str, Dict],
        groups: List[Dict],
        group_memberships: Dict[str, List[Dict]],
        ownership_map: Dict[str, List[Dict]],
        ca_policies: List[Dict],
        service_principals: List[Dict],
    ) -> Set[str]:
        """Compute the canonical set of principal IDs with actionable access.

        Returns a Set[str] of Azure AD object IDs satisfying inclusion criteria.
        Also populates self._principal_access_paths: Dict[str, Dict] with
        per-principal access_paths JSONB for persistence.
        """
        access_paths: Dict[str, Dict] = {}

        def _ensure(pid: str):
            if pid not in access_paths:
                access_paths[pid] = {
                    'direct_rbac': [],
                    'direct_entra': [],
                    'group_membership': [],
                    'pim_eligible': [],
                    'ca_targeted': [],
                    'spn_ownership': [],
                }

        # 1. Direct RBAC principals
        for ra in role_assignments:
            pid = ra.get('principal_id')
            if pid:
                _ensure(pid)
                access_paths[pid]['direct_rbac'].append({
                    'role': ra.get('role_name', ''),
                    'scope': ra.get('scope', ''),
                })

        # 2. Direct Entra role principals
        for er in entra_roles:
            pid = er.get('principal_id')
            if pid:
                _ensure(pid)
                access_paths[pid]['direct_entra'].append({
                    'role': er.get('role_name', ''),
                })

        # 3. PIM-eligible principals
        for pid, pim_data in pim_map.items():
            eligible = pim_data.get('eligible', [])
            if eligible:
                _ensure(pid)
                for e in eligible:
                    access_paths[pid]['pim_eligible'].append({
                        'role': e.get('role_name', ''),
                        'scope': e.get('directory_scope', '/'),
                    })

        # 4. Group members from role-bearing groups
        # IMPORTANT: Only expand groups that have RBAC or Entra directory roles.
        # PIM eligibility alone does NOT make a group "role-bearing" for member
        # expansion — PIM tracks individual principal eligibility, not inherited
        # group access.  Using set(access_paths.keys()) would include PIM-only
        # groups, pulling in all their members with empty inherited roles.
        group_id_set = {g['group_id'] for g in groups}
        group_name_map = {g['group_id']: g.get('display_name', '') for g in groups}

        # Build role_bearing_group_ids strictly from RBAC + Entra sources
        role_bearing_group_ids = set()
        group_roles_index: Dict[str, List[str]] = {}
        for ra in role_assignments:
            pid = ra.get('principal_id')
            if pid and pid in group_id_set:
                role_bearing_group_ids.add(pid)
                group_roles_index.setdefault(pid, []).append(ra.get('role_name', ''))
        for er in entra_roles:
            pid = er.get('principal_id')
            if pid and pid in group_id_set:
                role_bearing_group_ids.add(pid)
                group_roles_index.setdefault(pid, []).append(er.get('role_name', ''))

        expanded_from_groups = 0
        for gid in role_bearing_group_ids:
            members = group_memberships.get(gid, [])
            g_name = group_name_map.get(gid, gid)
            g_roles = group_roles_index.get(gid, [])
            for member in members:
                mid = member.get('member_object_id')
                if mid and member.get('member_type') != 'group':
                    _ensure(mid)
                    access_paths[mid]['group_membership'].append({
                        'group_id': gid,
                        'group_name': g_name,
                        'role': ', '.join(g_roles) if g_roles else '',
                    })
                    expanded_from_groups += 1

        # 5. SPN owners (user type only)
        spn_lookup = {sp.get('identity_id'): sp for sp in service_principals}
        owner_count = 0
        for spn_identity_id, owners in ownership_map.items():
            sp = spn_lookup.get(spn_identity_id)
            spn_obj_id = sp.get('object_id', '') if sp else ''
            spn_name = sp.get('display_name', '') if sp else ''
            for owner in owners:
                if owner.get('owner_type') == 'user':
                    oid = owner.get('owner_object_id')
                    if oid:
                        _ensure(oid)
                        access_paths[oid]['spn_ownership'].append({
                            'spn_id': spn_obj_id,
                            'spn_name': spn_name,
                        })
                        owner_count += 1

        # 6. CA policy targets (named users, not 'All')
        ca_count = 0
        for policy in ca_policies:
            include_users = policy.get('include_users', [])
            p_name = policy.get('display_name', '')
            p_id = policy.get('policy_id', '')
            for uid in include_users:
                if uid and uid != 'All':
                    _ensure(uid)
                    access_paths[uid]['ca_targeted'].append({
                        'policy_id': p_id,
                        'policy_name': p_name,
                    })
                    ca_count += 1

        self._principal_access_paths = access_paths
        result_set = set(access_paths.keys())

        logger.info(
            "[_collect_relevant_principal_ids] %d unique principals "
            "(RBAC=%d Entra=%d PIM=%d group_expanded=%d SPN_owners=%d CA=%d)",
            len(result_set),
            len({ra['principal_id'] for ra in role_assignments if ra.get('principal_id')}),
            len({er['principal_id'] for er in entra_roles if er.get('principal_id')}),
            len({pid for pid, d in pim_map.items() if d.get('eligible')}),
            expanded_from_groups,
            owner_count,
            ca_count,
        )

        return result_set

    async def _discover_users(self, principal_ids: Set[str]) -> List[Dict[str, Any]]:
        """Discover users scoped to the AG-75 inclusion criteria principal set.

        Only users whose Azure AD object ID is in principal_ids are returned.
        Pages through all tenant users but filters client-side, with early
        termination when all principals have been found.
        """
        import aiohttp

        if not principal_ids:
            logger.info("[_discover_users] No relevant principals — skipping user discovery")
            return []

        logger.info("[_discover_users] org=%s tenant=%s starting (target=%d principals)",
                    self.db_org_id, self.azure_directory_id, len(principal_ids))

        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}

            select_fields = ','.join([
                'id', 'displayName', 'userPrincipalName', 'accountEnabled',
                'createdDateTime', 'userType', 'employeeId', 'department', 'jobTitle',
                'signInActivity', 'onPremisesSyncEnabled', 'mail', 'assignedLicenses',
            ])
            url: str | None = (
                f"https://graph.microsoft.com/v1.0/users"
                f"?$select={select_fields}&$top=999"
            )

            all_users: list[dict] = []
            page = 0
            sign_in_available = True

            MAX_PAGE_RETRIES = 5

            async with aiohttp.ClientSession(timeout=GRAPH_HTTP_TIMEOUT) as session:
                while url:
                    page += 1
                    data = None

                    for attempt in range(MAX_PAGE_RETRIES):
                        async with self._graph_semaphore:
                            async with session.get(url, headers=headers) as resp:
                                if resp.status == 200:
                                    data = await resp.json()
                                    break
                                elif resp.status == 429:
                                    retry_after = int(resp.headers.get('Retry-After', '10'))
                                    retry_after = min(retry_after, 60)
                                    logger.warning(
                                        "[_discover_users] 429 throttled on page %s — waiting %ss (attempt %s/%s)",
                                        page, retry_after, attempt + 1, MAX_PAGE_RETRIES
                                    )
                                    await asyncio.sleep(retry_after)
                                    continue
                                elif resp.status == 503:
                                    wait = 5 * (attempt + 1)
                                    logger.warning(
                                        "[_discover_users] 503 on page %s — waiting %ss (attempt %s/%s)",
                                        page, wait, attempt + 1, MAX_PAGE_RETRIES
                                    )
                                    await asyncio.sleep(wait)
                                    continue
                                else:
                                    body = await resp.text()
                                    # If signInActivity fails (403 / needs P2), retry page 1 without it
                                    if page == 1 and ('signInActivity' in body or resp.status == 403):
                                        logger.warning("[_discover_users] signInActivity requires Entra ID P2 — retrying without it")
                                        sign_in_available = False
                                        select_no_sia = select_fields.replace(',signInActivity', '')
                                        url = (
                                            f"https://graph.microsoft.com/v1.0/users"
                                            f"?$select={select_no_sia}&$top=999"
                                        )
                                        page = 0  # reset so retry starts as page 1
                                        data = None
                                        break
                                    logger.error("[_discover_users] FAILED status=%s body=%s",
                                                 resp.status, body[:500])
                                    raise Exception(
                                        f"Graph API /users failed on page {page}: status={resp.status} body={body[:300]}"
                                    )
                    else:
                        # All retries exhausted
                        raise Exception(
                            f"Graph API /users failed after {MAX_PAGE_RETRIES} retries on page {page} "
                            f"(collected {len(all_users)} users so far)"
                        )

                    if data is None:
                        # signInActivity retry — loop back with new URL
                        continue

                    page_users = data.get('value', [])
                    matched = [u for u in page_users if u.get('id') in principal_ids]
                    all_users.extend(matched)

                    logger.info(
                        "[_discover_users] org=%s page=%s scanned=%s matched=%s found_so_far=%s/%s",
                        self.db_org_id, page, len(page_users), len(matched),
                        len(all_users), len(principal_ids)
                    )

                    # Early termination: found all principals
                    if len(all_users) >= len(principal_ids):
                        logger.info(
                            "[_discover_users] All %d relevant principals found — "
                            "stopping pagination early at page %d",
                            len(all_users), page
                        )
                        break

                    url = data.get('@odata.nextLink')
                    if page >= self._MAX_GRAPH_PAGES:
                        logger.warning("User pagination hit safety limit (%d pages, %d users) — stopping",
                                       page, len(all_users))
                        break

            logger.info("Fetched %s users across %s page(s) (signInActivity=%s)", len(all_users), page, sign_in_available)

            # ── Beta endpoint fallback for signInActivity ─────────────
            # If v1.0 stripped signInActivity (no P2 on v1.0), try beta endpoint
            # which may expose signInActivity on some tenants.
            if not sign_in_available and all_users:
                logger.info("[_discover_users] Attempting beta endpoint for signInActivity (%d users)", len(all_users))
                beta_enriched = 0
                try:
                    # Batch fetch via beta with signInActivity in $select
                    beta_select = ','.join(['id', 'signInActivity'])
                    beta_url: str | None = (
                        f"https://graph.microsoft.com/beta/users"
                        f"?$select={beta_select}&$top=999"
                    )
                    user_ids_needed = {u['id'] for u in all_users}
                    sia_map: dict[str, dict] = {}
                    beta_page = 0

                    async with aiohttp.ClientSession(timeout=GRAPH_HTTP_TIMEOUT) as beta_session:
                        while beta_url and beta_page < 10:
                            beta_page += 1
                            async with self._graph_semaphore:
                                async with beta_session.get(beta_url, headers=headers) as bresp:
                                    if bresp.status != 200:
                                        body = await bresp.text()
                                        if 'signInActivity' in body or bresp.status == 403:
                                            logger.info("[_discover_users] Beta endpoint also lacks signInActivity — giving up")
                                        else:
                                            logger.debug("[_discover_users] Beta /users error: %s %s", bresp.status, body[:200])
                                        break
                                    bdata = await bresp.json()

                            for bu in bdata.get('value', []):
                                uid = bu.get('id')
                                if uid in user_ids_needed and bu.get('signInActivity'):
                                    sia_map[uid] = bu['signInActivity']

                            # If we've gathered enough, stop
                            if len(sia_map) >= len(user_ids_needed):
                                break
                            beta_url = bdata.get('@odata.nextLink')

                    # Merge signInActivity back into all_users
                    if sia_map:
                        sign_in_available = True
                        for u in all_users:
                            uid = u.get('id')
                            if uid in sia_map:
                                u['signInActivity'] = sia_map[uid]
                                beta_enriched += 1
                        logger.info("[_discover_users] Beta enriched %d/%d users with signInActivity",
                                    beta_enriched, len(all_users))
                except Exception as e:
                    logger.warning("[_discover_users] Beta signInActivity fallback failed: %s", e)

            # Persist P2 license availability on the cloud connection (only upgrade, never downgrade)
            if sign_in_available:
                try:
                    cur = self.db.conn.cursor()
                    cur.execute(
                        "UPDATE cloud_connections SET has_p2_license = %s WHERE id = %s",
                        (True, self.cloud_connection_id)
                    )
                    self.db.conn.commit()
                    cur.close()
                    logger.info("Persisted has_p2_license=True for connection %s (users)", self.cloud_connection_id)
                except Exception as e:
                    logger.warning("Failed to persist has_p2_license (users): %s", e)

            # Fetch manager info for included users — parallel with Semaphore(20)
            manager_map: dict[str, dict] = {}
            mgr_sem = asyncio.Semaphore(20)
            mgr_lock = asyncio.Lock()
            mgr_t0 = __import__('time').time()

            async def _fetch_manager(uid: str):
                async with mgr_sem:
                    try:
                        mgr = await asyncio.wait_for(
                            self.graph_client.users.by_user_id(uid).manager.get(),
                            timeout=GRAPH_SDK_TIMEOUT
                        )
                        if mgr:
                            entry = {
                                'manager_id': getattr(mgr, 'id', None),
                                'manager_upn': getattr(mgr, 'user_principal_name', None),
                            }
                            async with mgr_lock:
                                manager_map[uid] = entry
                    except Exception:
                        pass

            mgr_tasks = [
                _fetch_manager(u['id'])
                for u in all_users
                if u.get('id') and u['id'] in principal_ids
            ]
            if mgr_tasks:
                await asyncio.gather(*mgr_tasks)
            mgr_elapsed = __import__('time').time() - mgr_t0
            logger.info(
                "[_discover_users] Manager fetch: %d users in %.1fs (parallel sem=20)",
                len(mgr_tasks), mgr_elapsed
            )

            ice_config = self._load_ice_config()

            identities = []
            for u in all_users:
                uid = u.get('id')
                display_name = u.get('displayName')
                upn = u.get('userPrincipalName')

                if len(identities) < 10:
                    logger.info("User: %s (%s)", display_name, upn)

                created = u.get('createdDateTime')

                user_type = u.get('userType') or ''
                user_type_lower = user_type.lower()
                is_guest = user_type_lower in ('guest', 'externalmember')

                last_sign_in = None
                sia = u.get('signInActivity')
                if sia:
                    last_sign_in = (
                        sia.get('lastSignInDateTime')
                        or sia.get('lastNonInteractiveSignInDateTime')
                    )
                # Store raw signInActivity for pattern classification
                _signin_raw = {}
                if sia:
                    _signin_raw = {
                        'lastSignInDateTime': sia.get('lastSignInDateTime'),
                        'lastDelegatedSignInDateTime': sia.get('lastDelegatedClientSignInDateTime'),
                        'lastNonInteractiveSignInDateTime': sia.get('lastNonInteractiveSignInDateTime'),
                    }

                mgr_info = manager_map.get(uid, {})

                # Build a lightweight mock for _classify_account_category
                class _UserProxy:
                    user_principal_name = upn
                user_proxy = _UserProxy()

                _user_category = 'guest' if is_guest else 'human_user'
                identities.append({
                    'identity_id': uid,
                    'object_id': uid,
                    'app_id': None,
                    'display_name': display_name,
                    'user_principal_name': upn,
                    'identity_type': _user_category,
                    'identity_category': _user_category,
                    'enabled': u.get('accountEnabled', True),
                    'created_datetime': created,
                    'last_sign_in': last_sign_in,
                    'last_signin_datetime': sia.get('lastSignInDateTime') if sia else None,
                    'last_noninteractive_signin_datetime': sia.get('lastNonInteractiveSignInDateTime') if sia else None,
                    'on_premises_sync_enabled': u.get('onPremisesSyncEnabled'),
                    'mail': u.get('mail'),
                    'assigned_licenses': u.get('assignedLicenses', []),
                    # Multi-cloud normalized fields
                    'cloud': 'azure',
                    'azure_directory_id': self.azure_directory_id,
                    'source': 'entra',
                    'permission_plane': 'entra_id',
                    'is_federated': is_guest,
                    # ICE fields
                    'upn': upn,
                    'employee_id_entra': u.get('employeeId'),
                    'department': u.get('department'),
                    'job_title': u.get('jobTitle'),
                    'manager_id': mgr_info.get('manager_id'),
                    'manager_upn': mgr_info.get('manager_upn'),
                    'account_category': self._classify_account_category(user_proxy, ice_config),
                    '_signin_activity_raw': _signin_raw,
                    'access_paths': getattr(self, '_principal_access_paths', {}).get(uid, {}),
                })

            guests = sum(1 for i in identities if i['identity_category'] == 'guest')
            humans = sum(1 for i in identities if i['identity_category'] == 'human_user')
            logger.info("[_discover_users] Complete: org=%s total=%s human_user=%s guest=%s",
                        self.db_org_id, len(identities), humans, guests)
            return identities
        except Exception as e:
            logger.error(
                "[_discover_users] FATAL: user fetch failed org=%s tenant=%s error=%s",
                self.db_org_id, self.azure_directory_id, e,
                exc_info=True
            )
            raise  # Let the caller decide — do NOT return empty list silently
    
    _ice_config_cache = None

    def _load_ice_config(self) -> dict:
        """Load ICE configuration from settings table, with caching."""
        if self._ice_config_cache is not None:
            return self._ice_config_cache
        defaults = {
            'ice_privileged_prefixes': 'ep.,adm-,adm.,a-,admin-,admin.,priv-,priv.,sa_,pa-,pa.',
            'ice_privileged_suffixes': '-admin,.admin,-priv,.priv,-elevated,.elevated',
        }
        try:
            from app.database import Database
            # AG-94: Use org-scoped connection instead of admin to prevent cross-tenant settings leak
            db = Database(organization_id=self.db_org_id)
            try:
                from psycopg2.extras import RealDictCursor
                cursor = db.conn.cursor(cursor_factory=RealDictCursor)
                cursor.execute("SELECT key, value FROM settings WHERE key IN ('ice_privileged_prefixes', 'ice_privileged_suffixes') AND organization_id = %s", (self.db_org_id,))
                rows = cursor.fetchall()
                cursor.close()
                for row in rows:
                    defaults[row['key']] = row['value']
            finally:
                db.close()
        except Exception:
            pass
        self._ice_config_cache = defaults
        return defaults

    def _classify_account_category(self, user, ice_config: dict) -> str:
        """Classify a user account as regular, privileged, or service_account."""
        upn = getattr(user, 'user_principal_name', '') or ''
        local_part = upn.split('@')[0].lower() if '@' in upn else upn.lower()
        if not local_part:
            return 'unknown'

        prefixes = [p.strip() for p in ice_config.get('ice_privileged_prefixes', '').split(',') if p.strip()]
        suffixes = [s.strip() for s in ice_config.get('ice_privileged_suffixes', '').split(',') if s.strip()]

        for prefix in prefixes:
            if local_part.startswith(prefix):
                return 'privileged'
        for suffix in suffixes:
            if local_part.endswith(suffix):
                return 'privileged'

        # Service accounts detected by naming pattern
        svc_patterns = ['svc-', 'svc.', 'service-', 'service.', 'bot-', 'noreply']
        for sp in svc_patterns:
            if local_part.startswith(sp):
                return 'service_account'

        return 'regular'

    def _classify_access_tier(self, identity, role_assignments, entra_roles, group_memberships):
        """Return 'control_plane' or 'data_plane' for a human identity.

        control_plane if ANY qualifying role is:
        - Any Entra directory role
        - Role name contains a control-plane keyword
        - Scope is subscription or management_group
        - Resource-group scope with non-data-plane role
        - Data-plane role on a sensitive resource (PHI/PII in scope or group name)

        data_plane if ALL roles are data-plane-only at resource scope.
        """
        ap = identity.get('access_paths') or {}
        identity_id = identity.get('identity_id', '')

        # Entra directory role → always control_plane
        if ap.get('direct_entra'):
            return 'control_plane'

        # Check group names for sensitive data indicators
        for gm in (ap.get('group_membership') or []):
            gname = (gm.get('group_name') or '').lower()
            for ind in _SENSITIVE_DATA_INDICATORS:
                if ind in gname:
                    return 'control_plane'

        # Build all role tuples: (role_name_lower, scope_type, scope_lower)
        role_tuples = []

        # Direct RBAC
        for ra in role_assignments:
            if ra.get('principal_id') == identity_id:
                role_tuples.append((
                    (ra.get('role_name') or '').lower(),
                    (ra.get('scope_type') or '').lower(),
                    (ra.get('scope') or '').lower(),
                ))

        # Group-inherited from access_paths
        for gm in (ap.get('group_membership') or []):
            roles_str = gm.get('role', '')
            if roles_str:
                for rn in roles_str.split(', '):
                    role_tuples.append((
                        rn.strip().lower(),
                        (gm.get('scope_type') or 'resource').lower(),
                        (gm.get('scope') or '').lower(),
                    ))

        if not role_tuples:
            return 'data_plane'

        for role_lower, scope_type, scope in role_tuples:
            # Control-plane keyword in role name
            if any(kw in role_lower for kw in _CONTROL_PLANE_KEYWORDS):
                return 'control_plane'
            # Broad scope
            if scope_type in _CONTROL_PLANE_SCOPES:
                return 'control_plane'
            # Resource-group scope with non-data-plane role
            if scope_type == 'resource_group' and role_lower not in _DATA_PLANE_ROLES:
                return 'control_plane'
            # Sensitive data in scope path
            for ind in _SENSITIVE_DATA_INDICATORS:
                if ind in scope:
                    return 'control_plane'

        return 'data_plane'

    def _discover_role_assignments(self) -> List[Dict[str, Any]]:
        """Discover RBAC role assignments across ALL accessible subscriptions using Azure SDK.

        Each subscription has a 20-minute timeout — if exceeded, that subscription is
        skipped and discovery continues with the remaining subscriptions.

        Performance: Role definitions are pre-fetched with a single LIST call per
        subscription (instead of one GET per role assignment).  The resulting map is
        keyed by the short UUID at the tail of the full ARM role-definition ID so
        that scope-path variations all resolve to the same entry.  The map is also
        carried across subscriptions — built-in role UUIDs are identical across
        subscriptions, so later subscriptions get near-100% cache hits with zero
        API calls for role definitions.
        """
        from datetime import datetime, timezone
        import time as _time

        role_assignments = []
        printed = 0
        SUB_TIMEOUT_SECONDS = 20 * 60  # 20-minute per-subscription timeout

        # Cache: short role-definition UUID → role_name (shared across subscriptions)
        # Keyed by the last path segment of role_definition_id to avoid
        # scope-path mismatches (the same role UUID appears with different
        # subscription/management-group prefixes).
        role_def_cache: Dict[str, str] = {}
        cache_hits = 0
        api_calls = 0

        for sub_idx, sub in enumerate(self.subscriptions):
            sub_id = sub['id']
            sub_name = sub['name']
            sub_start = _time.monotonic()
            sub_count = 0
            logger.info("Subscription [%d/%d]: %s (%s...)", sub_idx + 1, len(self.subscriptions), sub_name, sub_id[:8])

            try:
                auth_client = AuthorizationManagementClient(self.credential, sub_id, **ARM_TIMEOUT_KWARGS)

                # Pre-fetch ALL role definitions for this subscription in ONE call.
                # Built-in + custom roles are returned (~70-150 entries).
                # On the 2nd+ subscription most UUIDs are already cached, so this
                # call only adds net-new custom roles.
                pre_fetch_count = 0
                try:
                    for rd in auth_client.role_definitions.list(
                        scope=f'/subscriptions/{sub_id}'
                    ):
                        short_id = rd.id.rsplit('/', 1)[-1] if rd.id else ''
                        if short_id and short_id not in role_def_cache:
                            role_def_cache[short_id] = rd.role_name or rd.display_name or short_id
                            pre_fetch_count += 1
                    api_calls += 1
                    logger.info("  Pre-fetched %d new role definitions (cache total: %d)",
                                pre_fetch_count, len(role_def_cache))
                except Exception as e:
                    logger.warning("  Could not pre-fetch role definitions for %s: %s", sub_name, e)

                sub_timed_out = False

                for assignment in auth_client.role_assignments.list_for_subscription():
                    # Per-subscription timeout check
                    if _time.monotonic() - sub_start > SUB_TIMEOUT_SECONDS:
                        logger.warning(
                            "⏰ Subscription %s exceeded 20-minute timeout after %d role assignments — skipping remainder",
                            sub_name, sub_count
                        )
                        sub_timed_out = True
                        break

                    principal_id = assignment.principal_id
                    if not principal_id:
                        continue

                    scope = assignment.scope or ''
                    role_def_id = assignment.role_definition_id or ''

                    # Resolve role name from cache using the short UUID
                    short_id = role_def_id.rsplit('/', 1)[-1] if role_def_id else ''
                    if short_id and short_id in role_def_cache:
                        role_name = role_def_cache[short_id]
                        cache_hits += 1
                    else:
                        # Fallback: use the short UUID as the display name
                        role_name = short_id or 'Unknown'

                    scope_type = 'subscription'
                    scope_lower = scope.lower()
                    if '/providers/' in scope_lower and '/resourcegroups/' in scope_lower:
                        scope_type = 'resource'
                    elif '/resourcegroups/' in scope_lower:
                        scope_type = 'resource_group'

                    created_on = None
                    days_since_assigned = None
                    if hasattr(assignment, 'created_on') and assignment.created_on:
                        created_on = assignment.created_on.isoformat()
                        try:
                            days_since_assigned = (datetime.now(timezone.utc) - assignment.created_on).days
                        except Exception:
                            pass

                    risk_level, why_critical = self._calculate_role_risk(role_name, scope_type)
                    resource_type, resource_name = self._parse_scope(scope)

                    if printed < 15:
                        logger.info("%s -> %s", role_name, scope.split('/')[-1][:30] if scope else 'root')
                        printed += 1
                    elif printed == 15:
                        logger.info("... (listing remaining silently)")
                        printed += 1

                    sub_count += 1
                    role_assignments.append({
                        'principal_id': principal_id,
                        'assignment_id': assignment.id,
                        'role_name': role_name,
                        'scope': scope,
                        'scope_type': scope_type,
                        'created_on': created_on,
                        'scope_exists': True,
                        'usage_status': 'unknown',
                        'days_since_assigned': days_since_assigned,
                        'redundant_with': None,
                        'role_type': 'azure',
                        'risk_level': risk_level,
                        'why_critical': why_critical,
                        'resource_type': resource_type,
                        'resource_name': resource_name,
                        'subscription_id': sub_id,
                        'subscription_name': sub_name,
                    })

                elapsed = _time.monotonic() - sub_start
                if sub_timed_out:
                    logger.warning("Subscription %s: %d roles discovered in %.1fs (TIMED OUT)", sub_name, sub_count, elapsed)
                else:
                    logger.info("Subscription %s: %d roles discovered in %.1fs", sub_name, sub_count, elapsed)

            except Exception as e:
                logger.warning("Error discovering roles for subscription %s: %s", sub_name, e)
                continue

        logger.info(
            "Total: %s role assignments across %s subscription(s) "
            "(role_def_cache: %d unique defs, %d cache hits, %d LIST calls)",
            len(role_assignments), len(self.subscriptions),
            len(role_def_cache), cache_hits, api_calls
        )
        return role_assignments

    # Exact-match role risk map: role_name_lower → { scope_type → (risk_level, description) }
    # Roles not in this map fall through to suffix-based defaults.
    _ROLE_RISK_EXACT = {
        'owner': {
            'subscription': ('critical', 'Owner on Subscription: Full control including IAM - violates SOC2 least privilege, PCI-DSS 7.1, HIPAA §164.312(a)(1) access controls'),
            'resource_group': ('high', 'Owner on Resource Group: Full control over all resources - review for SOC2 least privilege, consider scope reduction'),
            '_default': ('medium', 'Owner on resource: Full control - verify business justification per SOC2 access review requirements'),
        },
        'user access administrator': {
            '_default': ('critical', 'User Access Administrator: Can grant any role - privilege escalation risk, violates SOC2 separation of duties, PCI-DSS 7.1'),
        },
        'contributor': {
            'subscription': ('high', 'Contributor on Subscription: Can create/modify/delete all resources - violates SOC2 least privilege, PCI-DSS 7.2 access restrictions'),
            'resource_group': ('medium', 'Contributor on Resource Group: Broad modification access - review for SOC2 least privilege compliance'),
            '_default': ('low', 'Contributor on resource: Scoped access - verify business justification'),
        },
        # Scoped contributor roles — exact matches prevent inheriting full Contributor blast radius
        'log analytics contributor': {
            '_default': ('low', 'Log Analytics Contributor: Can manage Log Analytics workspaces and solutions'),
        },
        'storage blob data contributor': {
            '_default': ('medium', 'Storage Blob Data Contributor: Can read/write/delete blob containers and data'),
        },
        'storage blob data owner': {
            '_default': ('medium', 'Storage Blob Data Owner: Full control over blob storage data including RBAC'),
        },
        'monitoring contributor': {
            '_default': ('low', 'Monitoring Contributor: Can manage monitoring settings and alerts'),
        },
        'network contributor': {
            '_default': ('medium', 'Network Contributor: Can modify network security - SOC2 network security controls, review firewall/NSG changes'),
        },
        'sql db contributor': {
            '_default': ('medium', 'SQL DB Contributor: Can manage SQL databases but not access data directly'),
        },
        'sql server contributor': {
            '_default': ('medium', 'SQL Server Contributor: Can manage SQL servers and databases'),
        },
        'cosmos db account reader role': {
            '_default': ('low', 'Cosmos DB Account Reader: Read-only access to Cosmos DB metadata'),
        },
        'documentdb account contributor': {
            '_default': ('medium', 'DocumentDB Account Contributor: Can manage Cosmos DB accounts'),
        },
        'backup contributor': {
            '_default': ('low', 'Backup Contributor: Can manage backup services and items'),
        },
        'site recovery contributor': {
            '_default': ('low', 'Site Recovery Contributor: Can manage Azure Site Recovery operations'),
        },
        'virtual machine contributor': {
            '_default': ('medium', 'Virtual Machine Contributor: Can manage VMs but not access or networking - SOC2 system access controls'),
        },
        'web plan contributor': {
            '_default': ('low', 'Web Plan Contributor: Can manage App Service plans'),
        },
        'website contributor': {
            '_default': ('medium', 'Website Contributor: Can manage App Service web apps'),
        },
        'key vault administrator': {
            '_default': ('high', 'Key Vault Administrator: Full access to secrets/keys/certificates - HIPAA encryption controls, PCI-DSS 3.5 key management'),
        },
        'key vault secrets officer': {
            '_default': ('high', 'Key Vault Secrets Officer: Can manage all secret operations - HIPAA encryption controls'),
        },
        'key vault crypto officer': {
            '_default': ('high', 'Key Vault Crypto Officer: Can manage all key operations - PCI-DSS 3.5 key management'),
        },
        'key vault certificates officer': {
            '_default': ('medium', 'Key Vault Certificates Officer: Can manage certificate operations'),
        },
        'key vault reader': {
            '_default': ('low', 'Key Vault Reader: Read-only access to Key Vault metadata'),
        },
        'key vault secrets user': {
            '_default': ('medium', 'Key Vault Secrets User: Can read secret contents'),
        },
        'key vault crypto user': {
            '_default': ('medium', 'Key Vault Crypto User: Can perform cryptographic operations'),
        },
        'data factory contributor': {
            '_default': ('medium', 'Data Factory Contributor: Can manage Data Factory pipelines and datasets'),
        },
        'logic app contributor': {
            '_default': ('low', 'Logic App Contributor: Can manage Logic Apps'),
        },
        'automation contributor': {
            '_default': ('medium', 'Automation Contributor: Can manage Automation runbooks and schedules'),
        },
    }

    def _calculate_role_risk(self, role_name: str, scope_type: str) -> tuple:
        """Calculate risk level and explanation for a role assignment with compliance context.

        Uses exact-match lookup first, then suffix-based defaults for unknown roles.
        """
        role_lower = role_name.lower().strip()

        # 1. Exact match against the role risk map
        if role_lower in self._ROLE_RISK_EXACT:
            scope_map = self._ROLE_RISK_EXACT[role_lower]
            return scope_map.get(scope_type, scope_map['_default'])

        # 2. Suffix-based defaults for unrecognized roles
        if role_lower.endswith('contributor'):
            return ('low', f'{role_name}: Scoped contributor access - review blast radius')
        if role_lower.endswith('owner'):
            return ('medium', f'{role_name}: Owner-level access on scoped resource - verify business justification')
        if role_lower.endswith('administrator') or role_lower.endswith('admin'):
            return ('medium', f'{role_name}: Administrative access - review scope and privileges')
        if role_lower.endswith('operator'):
            return ('low', f'{role_name}: Operator access - limited to operational actions')
        if role_lower.endswith('reader') or role_lower.endswith('read'):
            return ('low', 'Read-only access: Limited risk but review for data sensitivity per SOC2 access monitoring')

        return ('info', None)

    def _parse_scope(self, scope: str) -> tuple:
        """Extract resource type and name from ARM scope"""
        if not scope:
            return (None, None)

        parts = scope.split('/')

        # Subscription level
        if '/resourceGroups/' not in scope:
            return ('subscription', parts[-1] if len(parts) > 2 else None)

        # Resource group level
        if scope.count('/') <= 4:
            rg_idx = parts.index('resourceGroups') if 'resourceGroups' in parts else -1
            if rg_idx >= 0 and rg_idx + 1 < len(parts):
                return ('resourceGroup', parts[rg_idx + 1])

        # Resource level - get provider and type
        if '/providers/' in scope:
            try:
                provider_idx = parts.index('providers')
                if provider_idx + 2 < len(parts):
                    resource_type = parts[provider_idx + 1] + '/' + parts[provider_idx + 2]
                    resource_name = parts[-1]
                    return (resource_type, resource_name)
            except Exception:
                pass

        return (None, parts[-1] if parts else None)

    def _calculate_entra_role_risk(self, role_name: str) -> tuple:
        """Calculate risk level and explanation for an Entra directory role with compliance context"""
        role_lower = role_name.lower()

        # Critical Entra roles
        if 'global administrator' in role_lower:
            return ('critical', 'Global Administrator: Full tenant control - violates SOC2 least privilege, HIPAA §164.312 access controls, PCI-DSS 7.1 need-to-know')

        if 'privileged role administrator' in role_lower:
            return ('critical', 'Privileged Role Admin: Can assign any role - privilege escalation, violates SOC2 separation of duties, PCI-DSS 7.1')

        if 'privileged authentication administrator' in role_lower:
            return ('critical', 'Privileged Auth Admin: Can reset MFA for all users - account takeover risk, HIPAA §164.312(d) authentication controls')

        # High risk roles
        if 'application administrator' in role_lower or 'cloud application administrator' in role_lower:
            return ('high', 'Application Admin: Can manage all apps/SPNs - potential data access via app credentials, HIPAA BAA concerns')

        if 'user administrator' in role_lower:
            return ('high', 'User Administrator: Can create users/reset passwords - SOC2 access control risk, PCI-DSS 8.1 user ID management')

        if 'security administrator' in role_lower:
            return ('high', 'Security Administrator: Can modify security policies - SOC2 change management, affects HIPAA/PCI security controls')

        if 'exchange administrator' in role_lower:
            return ('high', 'Exchange Administrator: Full mailbox access - HIPAA ePHI exposure via email, SOC2 confidentiality controls')

        if 'sharepoint administrator' in role_lower:
            return ('high', 'SharePoint Administrator: Full document access - PII/PHI exposure risk, GDPR Art. 32 data protection')

        if 'intune administrator' in role_lower:
            return ('high', 'Intune Administrator: Device management - can access/wipe devices, SOC2 endpoint security controls')

        if 'conditional access administrator' in role_lower:
            return ('high', 'Conditional Access Admin: Can bypass MFA policies - authentication security risk, HIPAA §164.312(d)')

        if 'billing administrator' in role_lower:
            return ('high', 'Billing Administrator: Access to payment/financial data - PCI-DSS cardholder data exposure risk')

        if 'compliance administrator' in role_lower:
            return ('high', 'Compliance Administrator: Can modify compliance settings - SOC2/HIPAA audit control risk')

        # Medium risk roles
        if 'helpdesk administrator' in role_lower or 'password administrator' in role_lower:
            return ('medium', 'Helpdesk/Password Admin: Can reset non-admin passwords - social engineering risk, SOC2 access controls')

        if 'groups administrator' in role_lower:
            return ('medium', 'Groups Administrator: Can modify security groups - affects access controls, SOC2 group management')

        if 'teams administrator' in role_lower:
            return ('medium', 'Teams Administrator: Access to all Teams data - potential PII/confidential data exposure')

        if 'authentication administrator' in role_lower:
            return ('medium', 'Authentication Admin: Can reset MFA for non-admins - account security risk, HIPAA §164.312(d)')

        if 'license administrator' in role_lower:
            return ('medium', 'License Administrator: Can manage licenses - no direct data access but operational impact')

        # Low risk roles
        if 'reader' in role_lower:
            return ('low', 'Directory Reader: Read-only access - limited risk but review for SOC2 access monitoring')

        if 'reports reader' in role_lower or 'usage summary reports reader' in role_lower:
            return ('low', 'Reports Reader: Can view usage reports - minimal risk, audit trail access')

        if 'message center reader' in role_lower:
            return ('low', 'Message Center Reader: Can view service messages - informational access only')

        return ('info', None)
    
    # ─── Group Scanner (Phase 2A) ──────────────────────────────────────

    async def _discover_groups(self) -> List[Dict[str, Any]]:
        """Discover Entra ID security groups via Graph API with pagination."""
        import aiohttp

        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}

            select_fields = ','.join([
                'id', 'displayName', 'description', 'mailEnabled',
                'securityEnabled', 'groupTypes', 'membershipRule',
                'isAssignableToRole', 'createdDateTime',
            ])
            url: str | None = (
                f"https://graph.microsoft.com/v1.0/groups"
                f"?$select={select_fields}&$top=999"
            )

            all_groups: list[dict] = []
            page = 0
            first_error_logged = False

            MAX_PAGE_RETRIES = 5

            async with aiohttp.ClientSession(timeout=GRAPH_HTTP_TIMEOUT) as session:
                while url:
                    page += 1
                    data = None

                    for attempt in range(MAX_PAGE_RETRIES):
                        async with self._graph_semaphore:
                            async with session.get(url, headers=headers) as resp:
                                if resp.status == 200:
                                    data = await resp.json()
                                    break
                                elif resp.status == 429:
                                    retry_after = int(resp.headers.get('Retry-After', '10'))
                                    retry_after = min(retry_after, 60)
                                    logger.warning(
                                        "[_discover_groups] 429 throttled on page %s — waiting %ss (attempt %s/%s)",
                                        page, retry_after, attempt + 1, MAX_PAGE_RETRIES
                                    )
                                    await asyncio.sleep(retry_after)
                                    continue
                                elif resp.status == 503:
                                    wait = 5 * (attempt + 1)
                                    logger.warning(
                                        "[_discover_groups] 503 on page %s — waiting %ss (attempt %s/%s)",
                                        page, wait, attempt + 1, MAX_PAGE_RETRIES
                                    )
                                    await asyncio.sleep(wait)
                                    continue
                                else:
                                    body = await resp.text()
                                    logger.error("Graph API error %s on groups page %s: %s", resp.status, page, body[:500])
                                break

                    if data is None:
                        break

                    logger.info(
                        "[_discover_groups] org=%s page=%s groups_this_page=%s total_so_far=%s",
                        self.db_org_id, page, len(data.get('value', [])), len(all_groups) + len([
                            g for g in data.get('value', []) if g.get('securityEnabled', False)
                        ])
                    )

                    for g in data.get('value', []):
                        try:
                            security_enabled = g.get('securityEnabled', False)
                            # Skip pure mail/M365 groups that aren't security-enabled
                            if not security_enabled:
                                continue

                            group_types = g.get('groupTypes') or []
                            # Determine membership type
                            membership_type = None
                            if 'DynamicMembership' in group_types:
                                membership_type = 'dynamic'
                            elif g.get('membershipRule'):
                                membership_type = 'dynamic'
                            else:
                                membership_type = 'assigned'

                            all_groups.append({
                                'group_id': g.get('id'),
                                'display_name': g.get('displayName'),
                                'description': g.get('description'),
                                'mail_enabled': g.get('mailEnabled', False),
                                'security_enabled': True,
                                'group_types': group_types,
                                'membership_type': membership_type,
                                'is_role_assignable': g.get('isAssignableToRole', False),
                                'created_datetime': g.get('createdDateTime'),
                                'is_privileged': False,
                                'member_count': 0,
                                'nested_group_count': 0,
                                'rbac_roles': [],
                            })
                        except Exception as e:
                            if not first_error_logged:
                                logger.warning("Error parsing group %s: %s", g.get('id'), e)
                                first_error_logged = True

                    url = data.get('@odata.nextLink')
                    if page >= self._MAX_GRAPH_PAGES:
                        logger.warning("Group pagination hit safety limit (%d pages, %d groups) — stopping",
                                       page, len(all_groups))
                        break

            logger.info("Fetched %s security groups across %s page(s)", len(all_groups), page)
            return all_groups

        except Exception as e:
            logger.error("Group discovery failed: %s", e)
            return []

    async def _discover_group_memberships(
        self, groups: List[Dict[str, Any]],
        relevant_group_ids: Optional[Set[str]] = None,
    ) -> Dict[str, List[Dict]]:
        """Discover group memberships with nested resolution up to 3 levels.

        Two-tier optimization (when relevant_group_ids is provided):
          Tier 1 (relevant_group_ids): Groups with Azure RBAC or Entra roles.
                  Full Graph API member expansion via /groups/{id}/members.
          Tier 2 (remaining groups): Skipped here. Memberships are populated
                  by identity-centric memberOf enrichment (Step 5c).

        When relevant_group_ids is None, expands ALL groups (fallback mode
        used when memberOf pre-flight fails).

        Returns dict mapping group_id → list of member dicts.
        """
        import aiohttp
        import asyncio as _asyncio

        MAX_DEPTH = 3
        memberships: Dict[str, List[Dict]] = {}

        if not groups:
            return memberships

        # Determine which groups to expand via Graph API
        if relevant_group_ids is not None:
            expand_groups = [g for g in groups if g.get('group_id') in relevant_group_ids]
            skipped = len(groups) - len(expand_groups)
            logger.info(
                "[memberships] Tier 1: %d groups for Graph API expansion, "
                "Tier 2: %d groups deferred to memberOf (Step 5c)",
                len(expand_groups), skipped,
            )
        else:
            expand_groups = groups
            logger.info("[memberships] Full expansion: %d groups", len(expand_groups))

        if not expand_groups:
            logger.info("[memberships] 0 groups to expand — returning empty")
            return memberships

        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}
            first_error_logged = False

            async with aiohttp.ClientSession(timeout=GRAPH_HTTP_TIMEOUT) as session:

                async def _fetch_members(group_id: str, depth: int, visited: set) -> List[Dict]:
                    """Recursively fetch members, resolving nested groups."""
                    nonlocal first_error_logged
                    if depth > MAX_DEPTH or group_id in visited:
                        return []
                    visited.add(group_id)

                    members: list[dict] = []
                    url: str | None = (
                        f"https://graph.microsoft.com/v1.0/groups/{group_id}/members"
                        f"?$select=id,displayName&$top=999"
                    )

                    while url:
                        try:
                            async with session.get(url, headers=headers) as resp:
                                if resp.status == 403:
                                    if not first_error_logged:
                                        logger.error(
                                            "GROUP MEMBERSHIP FETCH FAILED: 403 Forbidden. "
                                            "The AuditGraph service principal is missing "
                                            "GroupMember.Read.All or Directory.Read.All permission. "
                                            "Grant this permission in Azure Portal → App Registrations → "
                                            "API Permissions, then re-run discovery."
                                        )
                                        first_error_logged = True
                                    break
                                if resp.status != 200:
                                    logger.warning("[memberships] group %s returned status %s — skipping", group_id, resp.status)
                                    break
                                data = await resp.json()

                            for m in data.get('value', []):
                                odata_type = m.get('@odata.type', '')
                                member_id = m.get('id')
                                if not member_id:
                                    continue

                                if '#microsoft.graph.user' in odata_type:
                                    member_type = 'user'
                                elif '#microsoft.graph.servicePrincipal' in odata_type:
                                    member_type = 'servicePrincipal'
                                elif '#microsoft.graph.group' in odata_type:
                                    member_type = 'group'
                                else:
                                    member_type = 'other'

                                members.append({
                                    'member_object_id': member_id,
                                    'member_type': member_type,
                                    'member_display_name': m.get('displayName'),
                                    'is_nested': depth > 0,
                                    'depth': depth,
                                })

                                # Recursively resolve nested groups
                                if member_type == 'group' and depth < MAX_DEPTH:
                                    nested = await _fetch_members(member_id, depth + 1, visited)
                                    members.extend(nested)

                            url = data.get('@odata.nextLink')
                        except Exception as e:
                            if not first_error_logged:
                                logger.warning("Error fetching members for group %s: %s", group_id, e)
                                first_error_logged = True
                            break

                    return members

                # Fetch memberships in parallel with concurrency limiter
                sem = _asyncio.Semaphore(20)

                async def _fetch_group(group):
                    gid = group.get('group_id')
                    if not gid:
                        return (None, [])
                    async with sem:
                        visited: set = set()
                        members = await _fetch_members(gid, 0, visited)
                        return (gid, members)

                tasks = [_fetch_group(g) for g in expand_groups]
                results = await _asyncio.gather(*tasks, return_exceptions=True)

                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        logger.warning("Group membership task %s failed: %s", i, result)
                        continue
                    gid, members = result
                    if gid:
                        memberships[gid] = members

                    if (i + 1) % 50 == 0:
                        logger.info("Group membership progress: %s/%s groups", i + 1, len(expand_groups))

            return memberships

        except Exception as e:
            logger.error("Group membership discovery failed: %s", e)
            return memberships

    async def _check_memberof_permission(self) -> bool:
        """Pre-flight check: test if the service principal can call memberOf.

        Calls GET /users?$top=1 to get a test user, then tries
        GET /users/{id}/memberOf?$top=1. Returns True if 200, False if 403.
        On any error (network, token, no users), returns False (safe fallback).
        """
        import aiohttp

        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}
        except Exception as e:
            logger.warning("memberOf pre-flight: token error: %s", e)
            return False

        try:
            async with aiohttp.ClientSession(timeout=GRAPH_HTTP_TIMEOUT) as session:
                # Get one user to test with
                async with session.get(
                    "https://graph.microsoft.com/v1.0/users?$top=1&$select=id",
                    headers=headers,
                ) as resp:
                    if resp.status != 200:
                        logger.warning("memberOf pre-flight: /users returned %s", resp.status)
                        return False
                    data = await resp.json()
                    users = data.get('value', [])
                    if not users:
                        logger.warning("memberOf pre-flight: no users found in tenant")
                        return False
                    test_uid = users[0]['id']

                # Test memberOf on that user
                async with session.get(
                    f"https://graph.microsoft.com/v1.0/users/{test_uid}/memberOf?$top=1",
                    headers=headers,
                ) as resp:
                    if resp.status == 403:
                        logger.warning(
                            "memberOf pre-flight: 403 on /users/%s/memberOf — "
                            "GroupMember.Read.All or Directory.Read.All may be missing",
                            test_uid,
                        )
                        return False
                    if resp.status == 200:
                        logger.info("memberOf pre-flight: PASSED (200 OK)")
                        return True
                    logger.warning("memberOf pre-flight: unexpected status %s", resp.status)
                    return False
        except Exception as e:
            logger.warning("memberOf pre-flight: request error: %s", e)
            return False

    async def _discover_identity_group_memberships(
        self, identities: List[Dict], groups: List[Dict],
        existing_memberships: Dict[str, List[Dict]]
    ) -> Dict[str, List[Dict]]:
        """Identity-centric group membership discovery via memberOf endpoint.

        For each identity, calls:
          - GET /users/{object_id}/memberOf          (human_user, guest)
          - GET /servicePrincipals/{object_id}/memberOf  (service_principal, managed_identity_*)

        Works with Directory.Read.All, GroupMember.Read.All, or Group.Read.All.
        Enriches group-centric results with identity-centric data (Tier 2 groups).
        Uses Semaphore(20) for parallel API calls.

        403 handling: per-identity skip with one retry. A 403 on one identity
        does NOT abort the entire step — only that identity is skipped.

        Returns updated memberships dict: group_id -> list of member dicts.
        Merges with existing_memberships (deduplicates by member_object_id per group).
        """
        import aiohttp
        import time as _time

        _phase_start = _time.monotonic()

        # Build lookup structures from discovered groups
        group_id_set = {g.get('group_id') or g.get('id') for g in groups if g.get('group_id') or g.get('id')}

        memberships: Dict[str, List[Dict]] = {gid: list(members) for gid, members in existing_memberships.items()}
        # Track existing members per group for dedup
        existing_members: Dict[str, set] = {
            gid: {m.get('member_object_id') for m in members}
            for gid, members in memberships.items()
        }

        if not groups or not identities:
            return memberships

        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}
        except Exception as e:
            logger.error("Failed to get token for memberOf discovery: %s", e)
            return memberships

        total_added = 0
        skipped_403 = 0
        skipped_other = 0
        groups_touched = set()
        # Note: @odata.type is always returned automatically — including it in
        # $select causes a 400 "not valid in $select" on the memberOf endpoint.
        select_fields = "id,displayName,securityEnabled,groupTypes,isAssignableToRole,mailEnabled"
        _lock = asyncio.Lock()
        sem = asyncio.Semaphore(20)
        _first_error_logged = False

        async def _fetch_memberof(session, identity):
            nonlocal total_added, skipped_403, skipped_other, _first_error_logged

            oid = identity.get('object_id') or identity.get('id')
            if not oid:
                return

            cat = identity.get('identity_category', '')
            if cat in ('human_user', 'guest'):
                endpoint = f"https://graph.microsoft.com/v1.0/users/{oid}/memberOf"
            elif cat in ('service_principal', 'managed_identity_system', 'managed_identity_user'):
                endpoint = f"https://graph.microsoft.com/v1.0/servicePrincipals/{oid}/memberOf"
            else:
                return

            async with sem:
                url: Optional[str] = f"{endpoint}?$select={select_fields}&$top=999"
                local_results = []
                retried_403 = False

                while url:
                    try:
                        async with session.get(url, headers=headers) as resp:
                            if resp.status == 403:
                                if not retried_403:
                                    retried_403 = True
                                    await asyncio.sleep(1)
                                    continue
                                async with _lock:
                                    skipped_403 += 1
                                    if skipped_403 <= 3:
                                        logger.warning(
                                            "memberOf 403 for %s (%s) — skipping this identity",
                                            oid, identity.get('display_name', '?'),
                                        )
                                return
                            if resp.status == 404:
                                return
                            if resp.status == 429:
                                retry_after = int(resp.headers.get('Retry-After', 5))
                                await asyncio.sleep(min(retry_after, 15))
                                continue
                            if resp.status != 200:
                                async with _lock:
                                    skipped_other += 1
                                    if not _first_error_logged:
                                        _first_error_logged = True
                                        logger.warning(
                                            "memberOf: unexpected status %s for %s — skipping",
                                            resp.status, oid,
                                        )
                                return
                            data = await resp.json()
                    except Exception as e:
                        logger.debug("memberOf request error for %s: %s", oid, e)
                        return

                    display_name = identity.get('display_name', '')
                    for obj in data.get('value', []):
                        odata_type = obj.get('@odata.type', '')
                        if '#microsoft.graph.group' not in odata_type:
                            continue
                        if not obj.get('securityEnabled', False):
                            continue

                        grp_id = obj.get('id')
                        if not grp_id or grp_id not in group_id_set:
                            continue

                        if cat in ('human_user', 'guest'):
                            member_type = 'user'
                        else:
                            member_type = 'servicePrincipal'

                        local_results.append((grp_id, {
                            'member_object_id': oid,
                            'member_type': member_type,
                            'member_display_name': display_name,
                            'is_nested': False,
                            'depth': 0,
                        }))

                    url = data.get('@odata.nextLink')

                # Merge results under lock
                if local_results:
                    async with _lock:
                        for grp_id, member in local_results:
                            if grp_id not in existing_members:
                                existing_members[grp_id] = set()
                            if member['member_object_id'] in existing_members[grp_id]:
                                _diag_deduped += 1
                                continue
                            if grp_id not in memberships:
                                memberships[grp_id] = []
                            memberships[grp_id].append(member)
                            existing_members[grp_id].add(member['member_object_id'])
                            total_added += 1
                            groups_touched.add(grp_id)

        async with aiohttp.ClientSession(timeout=GRAPH_HTTP_TIMEOUT) as session:
            tasks = [_fetch_memberof(session, identity) for identity in identities]
            await asyncio.gather(*tasks, return_exceptions=True)

        _elapsed = round(_time.monotonic() - _phase_start, 1)
        if skipped_403 > 0:
            logger.warning(
                "Identity-centric memberOf: %d identities skipped due to 403 "
                "(out of %d total). Groups tab may have partial data for those identities.",
                skipped_403, len(identities),
            )
        logger.info(
            "Identity-centric memberOf: discovered %s new memberships across %s groups "
            "(%d identities in %.1fs, skipped_403=%d)",
            total_added, len(groups_touched), len(identities), _elapsed, skipped_403,
        )
        logger.info(
            "[memberOf-diag] no_oid=%d no_category=%d api_ok=%d "
            "status_404=%d status_other=%d request_error=%d "
            "total_objects=%d not_group=%d not_security=%d not_in_set=%d "
            "deduped=%d added=%d group_id_set_size=%d existing_groups=%d",
            _diag_no_oid, _diag_no_category, _diag_api_ok,
            _diag_status_404, _diag_status_other, _diag_request_error,
            _diag_total_objects, _diag_not_group, _diag_not_security,
            _diag_not_in_set, _diag_deduped, total_added,
            len(group_id_set), len(existing_memberships),
        )
        return memberships

    def _save_entra_groups(self, run_id: int, groups: List[Dict], group_memberships: Dict[str, List[Dict]]):
        """Save discovered groups and their memberships to the database."""
        saved = 0
        membership_saved = 0
        membership_failed = 0
        total_membership_attempted = 0
        for group in groups:
            try:
                group_db_id = self.db.save_entra_group(run_id, group)
                if not group_db_id:
                    continue
                saved += 1

                # Save memberships for this group
                members = group_memberships.get(group.get('group_id', ''), [])
                for member in members:
                    total_membership_attempted += 1
                    try:
                        self.db.save_entra_group_membership(group_db_id, member, run_id)
                        membership_saved += 1
                    except Exception as e:
                        membership_failed += 1
                        logger.warning(
                            "Save membership error for group_db_id=%s member=%s: %s",
                            group_db_id, member.get('member_object_id', '?'), e,
                        )
                        try:
                            self.db._rollback()
                        except Exception:
                            pass
            except Exception as e:
                logger.error("Save group error for %s: %s", group.get('display_name'), e)
                try:
                    self.db._rollback()
                except Exception:
                    pass

        logger.info(
            "Saved %s/%s Entra groups | memberships: %s saved, %s failed out of %s attempted",
            saved, len(groups), membership_saved, membership_failed, total_membership_attempted,
        )

    def _enrich_keyvault_metadata(self, role_assignments: List[Dict]) -> None:
        """Fetch key/secret/certificate metadata for vaults found in role assignment scopes.

        Uses the ARM management plane (KeyVaultManagementClient) to enumerate
        vault items. Never reads secret values — management plane only returns
        names, attributes, and expiry dates.
        """
        # Extract unique vault ARM resource IDs from role assignment scopes
        vault_scopes: Set[str] = set()
        for ra in role_assignments:
            scope = ra.get('scope', '')
            if 'Microsoft.KeyVault/vaults/' in scope:
                parts = scope.split('/')
                try:
                    kv_idx = parts.index('vaults')
                    vault_id = '/'.join(parts[:kv_idx + 2])
                    vault_scopes.add(vault_id)
                except ValueError:
                    continue

        if not vault_scopes:
            return

        logger.info("Key Vault metadata: found %s vault(s) in role scopes", len(vault_scopes))

        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient
        except ImportError:
            logger.warning("azure-mgmt-keyvault not installed — skipping KV metadata enrichment")
            return

        from datetime import timezone
        now_utc = datetime.now(timezone.utc)
        total_items = 0

        for vault_resource_id in vault_scopes:
            # Parse subscription_id from resource ID
            # Format: /subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{name}
            rid_parts = vault_resource_id.split('/')
            try:
                sub_idx = rid_parts.index('subscriptions')
                sub_id = rid_parts[sub_idx + 1]
            except (ValueError, IndexError):
                continue

            vault_name = rid_parts[-1]

            try:
                kv_mgmt = KeyVaultManagementClient(self.credential, sub_id, **ARM_TIMEOUT_KWARGS)
            except Exception as e:
                logger.warning("KV mgmt client error for sub %s: %s", sub_id[:8], e)
                continue

            # Fetch vault properties to get the vault URI
            try:
                rg_idx = rid_parts.index('resourceGroups')
                rg_name = rid_parts[rg_idx + 1]
                vault_info = kv_mgmt.vaults.get(rg_name, vault_name)
            except Exception as e:
                logger.warning("Could not fetch vault %s: %s", vault_name, e)
                continue

            vault_uri = getattr(vault_info.properties, 'vault_uri', '') or ''

            # Use data-plane SDK to list items (requires vault URI)
            for item_type_plural, item_type_singular in [
                ('keys', 'key'), ('secrets', 'secret'), ('certificates', 'certificate')
            ]:
                try:
                    if item_type_singular == 'key':
                        from azure.keyvault.keys import KeyClient
                        client = KeyClient(vault_url=vault_uri, credential=self.credential)
                        items = client.list_properties_of_keys()
                    elif item_type_singular == 'secret':
                        from azure.keyvault.secrets import SecretClient
                        client = SecretClient(vault_url=vault_uri, credential=self.credential)
                        items = client.list_properties_of_secrets()
                    else:
                        from azure.keyvault.certificates import CertificateClient
                        client = CertificateClient(vault_url=vault_uri, credential=self.credential)
                        items = client.list_properties_of_certificates()

                    for item in items:
                        expires_on = getattr(item, 'expires_on', None)
                        created_on = getattr(item, 'created_on', None)
                        updated_on = getattr(item, 'updated_on', None)
                        enabled = getattr(item, 'enabled', True)
                        name = getattr(item, 'name', '') or ''

                        days_until_expiry = None
                        expiry_risk_tier = 'NONE'
                        if expires_on:
                            # Ensure timezone-aware comparison
                            if expires_on.tzinfo is None:
                                expires_on = expires_on.replace(tzinfo=timezone.utc)
                            delta = (expires_on - now_utc).days
                            days_until_expiry = delta
                            if delta <= 14:
                                expiry_risk_tier = 'CRITICAL'
                            elif delta <= 30:
                                expiry_risk_tier = 'WARNING'
                            elif delta <= 90:
                                expiry_risk_tier = 'INFO'
                            else:
                                expiry_risk_tier = 'HEALTHY'

                        self.db.save_keyvault_metadata_item({
                            'connection_id': self.cloud_connection_id,
                            'vault_name': vault_name,
                            'vault_resource_id': vault_resource_id,
                            'item_type': item_type_singular,
                            'item_name': name,
                            'enabled': enabled if enabled is not None else True,
                            'expires_on': expires_on,
                            'created_on': created_on,
                            'last_updated': updated_on,
                            'days_until_expiry': days_until_expiry,
                            'expiry_risk_tier': expiry_risk_tier,
                        })
                        total_items += 1

                except Exception as e:
                    logger.warning("KV %s/%s enumeration error: %s", vault_name, item_type_plural, e)
                    self.db._rollback()

        if total_items:
            logger.info("Key Vault metadata: saved %s items across %s vault(s)", total_items, len(vault_scopes))

    async def _discover_entra_roles(self) -> List[Dict[str, Any]]:
        """Discover Entra ID directory role assignments for given principals.

        Role definition names are cached to avoid N+1 API calls — Entra
        tenants typically have ~60-80 built-in role definitions reused across
        many assignments.
        """
        MAX_ATTEMPTS = 3
        role_assignments_response = None

        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                logger.info("Discovering Entra ID Directory Roles (attempt %s/%s)...", attempt, MAX_ATTEMPTS)
                role_assignments_response = await asyncio.wait_for(
                    self.graph_client.role_management.directory.role_assignments.get(),
                    timeout=GRAPH_SDK_TIMEOUT,
                )
                break  # success
            except Exception as e:
                logger.warning(
                    "Entra role assignment fetch attempt %s/%s failed: %s",
                    attempt, MAX_ATTEMPTS, e, exc_info=True,
                )
                if attempt < MAX_ATTEMPTS:
                    await asyncio.sleep(2 ** attempt)  # exponential backoff: 2s, 4s
                else:
                    logger.error("Entra role discovery failed after %s attempts — returning empty", MAX_ATTEMPTS)
                    return []

        entra_roles = []
        entra_role_def_cache: Dict[str, str] = {}

        try:
            # Collect all assignments with pagination (Graph API default page = 100)
            all_assignments = []
            if role_assignments_response and role_assignments_response.value:
                all_assignments.extend(role_assignments_response.value)

            next_link = getattr(role_assignments_response, 'odata_next_link', None) if role_assignments_response else None
            while next_link:
                try:
                    role_assignments_response = await asyncio.wait_for(
                        self.graph_client.role_management.directory.role_assignments.with_url(next_link).get(),
                        timeout=GRAPH_SDK_TIMEOUT,
                    )
                    if role_assignments_response and role_assignments_response.value:
                        all_assignments.extend(role_assignments_response.value)
                    next_link = getattr(role_assignments_response, 'odata_next_link', None) if role_assignments_response else None
                except Exception as e:
                    logger.warning("Entra role pagination failed at page — returning partial results: %s", e)
                    break

            if all_assignments:
                for assignment in all_assignments:
                    rd_id = assignment.role_definition_id
                    if rd_id in entra_role_def_cache:
                        role_name = entra_role_def_cache[rd_id]
                    else:
                        # Get role definition to get role name
                        try:
                            role_def = await asyncio.wait_for(self.graph_client.role_management.directory.role_definitions.by_unified_role_definition_id(rd_id).get(), timeout=GRAPH_SDK_TIMEOUT)
                            role_name = role_def.display_name if role_def else "Unknown Role"
                        except Exception:
                            role_name = "Unknown Role"
                        entra_role_def_cache[rd_id] = role_name

                    # Calculate Entra role risk level
                    risk_level, why_critical = self._calculate_entra_role_risk(role_name)

                    entra_roles.append({
                        'principal_id': assignment.principal_id,
                        'role_name': role_name,
                        'role_definition_id': rd_id,
                        'directory_scope': assignment.directory_scope_id or '/',
                        # Usage intelligence fields
                        'usage_status': 'unknown',
                        'assigned_on': None,  # Entra doesn't expose this easily
                        'days_since_assigned': None,
                        'redundant_with': None,
                        'role_type': 'entra',
                        'risk_level': risk_level,
                        'why_critical': why_critical,
                    })

                    if len(entra_roles) <= 10:
                        logger.info("Entra role: %s", role_name)

            if len(entra_roles) == 0:
                logger.warning("Entra role discovery returned ZERO assignments — verify RoleManagement.Read.Directory permission")
                self._persist_permission(
                    'entra_role_management', 'denied',
                    error_detail='Zero role assignments returned — RoleManagement.Read.Directory likely missing',
                    impact_description='Entra directory roles (Global Administrator, Security Admin, etc.) '
                                      'will not appear in identity privilege assessment.')
            else:
                self._persist_permission('entra_role_management', 'granted')

            logger.info("Found %s Entra ID role assignments (%d unique role defs cached)",
                        len(entra_roles), len(entra_role_def_cache))
            # Pipeline health: record fetched count
            self._entra_roles_fetched = len(entra_roles)
            return entra_roles

        except Exception as e:
            logger.error("Error processing Entra role assignments: %s", e, exc_info=True)
            return entra_roles  # return whatever we got so far


    def discover_cognitive_services_and_deployments(self, run_id: int) -> dict:
        """Phase 2.1: discover Cognitive Services / Azure OpenAI accounts and
        their model deployments (gpt-4, gpt-4o, embeddings, etc.).

        Architecture-only — reads the management plane, no logs/telemetry
        required. Answers "which model is this AI agent using?" by linking an
        agent's RBAC scope to the deployments hosted on the account.

        Persists to azure_cognitive_services_accounts + azure_ai_model_deployments.
        Returns {accounts, deployments} counts.
        """
        try:
            from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
        except ImportError:
            logger.warning("azure-mgmt-cognitiveservices not installed — skipping AI model discovery")
            return {'accounts': 0, 'deployments': 0}

        accounts_persisted = 0
        deployments_persisted = 0
        conn = self.db.conn
        cur = conn.cursor()

        for sub in getattr(self, 'subscriptions', []) or []:
            sub_id = sub.get('subscription_id') or sub.get('id')
            sub_name = sub.get('display_name') or sub.get('name') or ''
            if not sub_id:
                continue
            try:
                cs_client = CognitiveServicesManagementClient(self.credential, sub_id, **ARM_TIMEOUT_KWARGS)
            except Exception as e:
                logger.warning("CognitiveServices client error for sub %s: %s", str(sub_id)[:8], e)
                continue

            try:
                accounts = list(cs_client.accounts.list())
            except Exception as e:
                logger.warning("Could not list Cognitive Services accounts in sub %s: %s", str(sub_id)[:8], e)
                continue

            for acct in accounts:
                try:
                    rid = acct.id or ''
                    rid_parts = rid.split('/')
                    rg = ''
                    try:
                        rg = rid_parts[rid_parts.index('resourceGroups') + 1]
                    except (ValueError, IndexError):
                        pass
                    props = getattr(acct, 'properties', None)
                    network_acls = getattr(props, 'network_acls', None) if props else None
                    pe = getattr(props, 'private_endpoint_connections', None) if props else None
                    cur.execute("""
                        INSERT INTO azure_cognitive_services_accounts
                            (discovery_run_id, organization_id, resource_id, name, kind, sku,
                             location, resource_group, subscription_id, subscription_name,
                             public_network_access, network_acls_default_action,
                             private_endpoint_count, custom_subdomain, endpoint_url)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (organization_id, resource_id, discovery_run_id) DO NOTHING
                    """, (
                        run_id, self.db_org_id, rid, acct.name,
                        getattr(acct, 'kind', None),
                        getattr(getattr(acct, 'sku', None), 'name', None),
                        getattr(acct, 'location', None),
                        rg, sub_id, sub_name,
                        getattr(props, 'public_network_access', None) if props else None,
                        getattr(network_acls, 'default_action', None) if network_acls else None,
                        len(pe) if pe else 0,
                        getattr(props, 'custom_sub_domain_name', None) if props else None,
                        (getattr(props, 'endpoint', None) if props else None),
                    ))
                    accounts_persisted += 1

                    # List deployments (the actual models)
                    try:
                        deployments = list(cs_client.deployments.list(rg, acct.name))
                    except Exception as e:
                        logger.debug("No deployments for %s: %s", acct.name, e)
                        deployments = []
                    for dep in deployments:
                        dprops = getattr(dep, 'properties', None)
                        model = getattr(dprops, 'model', None) if dprops else None
                        dsku = getattr(dep, 'sku', None)
                        cur.execute("""
                            INSERT INTO azure_ai_model_deployments
                                (discovery_run_id, organization_id, account_resource_id, account_name,
                                 deployment_name, model_name, model_version, model_format,
                                 sku_name, sku_capacity, provisioning_state, rai_policy_name)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                            ON CONFLICT (organization_id, account_resource_id, deployment_name, discovery_run_id) DO NOTHING
                        """, (
                            run_id, self.db_org_id, rid, acct.name,
                            dep.name,
                            getattr(model, 'name', None) if model else (dep.name or 'unknown'),
                            getattr(model, 'version', None) if model else None,
                            getattr(model, 'format', None) if model else None,
                            getattr(dsku, 'name', None) if dsku else None,
                            getattr(dsku, 'capacity', None) if dsku else None,
                            getattr(dprops, 'provisioning_state', None) if dprops else None,
                            getattr(dprops, 'rai_policy_name', None) if dprops else None,
                        ))
                        deployments_persisted += 1
                except Exception as e:
                    logger.warning("Error persisting CS account %s: %s", getattr(acct, 'name', '?'), e)
                    continue

        conn.commit()
        cur.close()
        logger.info("AI model discovery: %d accounts, %d deployments (run %s)",
                    accounts_persisted, deployments_persisted, run_id)
        return {'accounts': accounts_persisted, 'deployments': deployments_persisted}


    def _is_microsoft_system_app(self, identity: Dict) -> bool:
        """
        Determine if a service principal is a Microsoft first-party app.
        Uses multiple detection methods for comprehensive coverage.

        Detection methods (in order):
        1. appOwnerOrganizationId = Microsoft's tenant ID (most reliable)
        2. publisherName contains Microsoft patterns
        3. appId in known Microsoft first-party app list
        4. Display name matches Microsoft patterns (fallback for legacy apps)

        NOTE: Managed Identities (both SAMI and UAMI) are NOT filtered here.
        They are customer-owned Azure resources and should be tracked.

        Args:
            identity: Service principal dict from Microsoft Graph

        Returns:
            True if Microsoft first-party app, False if customer-owned
        """
        # Never flag the discovery connector SPN as Microsoft
        if identity.get('is_discovery_connector'):
            return False

        # Skip managed identities - they are customer-owned, not Microsoft apps
        sp_type = (identity.get('service_principal_type') or identity.get('servicePrincipalType') or '').lower()
        if sp_type == 'managedidentity':
            return False

        # All known Microsoft tenant IDs — SPNs owned by any of these are first-party
        MICROSOFT_TENANT_IDS = {
            'f8cdef31-a31e-4b4a-93e4-5f571e91255a',  # Microsoft Services
            '72f988bf-86f1-41af-91ab-2d7cd011db47',  # Microsoft Corp
            '33e01921-4d64-4f8c-a055-5bdaffd5e33d',  # Microsoft MSIT
            '47df5bb7-e6bc-4256-afb0-dd8c8e3c1ce8',  # Microsoft Partner Network
        }

        # Check 1: Microsoft-owned tenant (most reliable check)
        # NOTE: MS Graph SDK returns UUID objects, must convert to str for comparison
        app_owner_org = identity.get('app_owner_organization_id') or identity.get('appOwnerOrganizationId')
        app_owner_org_str = str(app_owner_org).lower() if app_owner_org else None
        if app_owner_org_str in MICROSOFT_TENANT_IDS:
            return True
        # If app_owner_organization_id is set and is NOT Microsoft, it's customer-owned
        if app_owner_org_str and app_owner_org_str not in MICROSOFT_TENANT_IDS:
            return False

        # Check 2: Publisher name indicates Microsoft
        publisher = (identity.get('publisher_name') or identity.get('publisherName') or '').lower()
        if publisher:
            microsoft_publishers = [
                'microsoft services',
                'microsoft corporation',
                'microsoft azure',
            ]
            if any(mp in publisher for mp in microsoft_publishers):
                return True

        # Check 3: Known Microsoft first-party app IDs
        MICROSOFT_FIRST_PARTY_APP_IDS = {
            '00000001-0000-0000-c000-000000000000',  # Azure ESTS
            '00000002-0000-0000-c000-000000000000',  # Azure AD Graph (legacy)
            '00000003-0000-0000-c000-000000000000',  # Microsoft Graph
            '00000004-0000-0000-c000-000000000000',  # Windows Azure Security Token Service
            '00000005-0000-0000-c000-000000000000',  # Office 365 Management APIs
            '00000006-0000-0ff1-ce00-000000000000',  # Microsoft Office 365 Portal
            '00000007-0000-0000-c000-000000000000',  # Azure Key Vault
            '00000007-0000-0ff1-ce00-000000000000',  # Microsoft Office 365
            '00000009-0000-0000-c000-000000000000',  # Microsoft Power BI
            '0000000a-0000-0000-c000-000000000000',  # Microsoft Intune
            '0000000c-0000-0000-c000-000000000000',  # Microsoft App Access Panel
            '00000012-0000-0000-c000-000000000000',  # Microsoft Rights Management Services
            '797f4846-ba00-4fd7-ba43-dac1f8f63013',  # Azure Service Management
            'c44b4083-3bb0-49c1-b47d-974e53cbdf3c',  # Azure Portal
            '00000002-0000-0ff1-ce00-000000000000',  # Office 365 Exchange Online
            '00000003-0000-0ff1-ce00-000000000000',  # Office 365 SharePoint Online
        }

        app_id = identity.get('app_id') or identity.get('appId')
        if app_id and app_id in MICROSOFT_FIRST_PARTY_APP_IDS:
            return True

        # Check 4: Display name pattern matching (catches most Microsoft apps)
        display_name = (identity.get('display_name') or identity.get('displayName') or '').lower()

        # Customer apps typically have custom naming patterns
        # Check for customer naming conventions FIRST (whitelist approach)
        customer_prefixes = ['spn-', 'app-', 'svc-', 'sa-', 'func-', 'aks-', 'webapp-', 'mi-']
        for prefix in customer_prefixes:
            if display_name.startswith(prefix):
                return False  # Definitely customer-owned

        # Known third-party apps (not Microsoft, not customer)
        third_party_apps = ['apple internet accounts']
        if display_name in third_party_apps:
            return False  # Track as customer (3rd party integration)

        # Microsoft app patterns - comprehensive list
        microsoft_keywords = [
            # Core Microsoft brands
            'microsoft', 'azure', 'office', 'o365', 'm365', 'sharepoint', 'onedrive',
            'teams', 'outlook', 'exchange', 'dynamics', 'powerbi', 'power bi',
            'powerapps', 'power apps', 'powerautomate', 'intune', 'defender',
            'sentinel', 'purview', 'entra', 'windows', 'xbox', 'skype', 'yammer',
            'viva', 'bing', 'cortana', 'onenote', 'planner', 'visio', 'project',

            # Azure/AD specific
            'aad', 'activedirectory', 'active directory', 'azuread', 'graph',
            'arm', 'subscription', 'resourcemanager', 'keyvault', 'storageaccount',

            # Services patterns
            'substrate', 'demeter', 'kaizala', 'whiteboard', 'sway', 'bookings',
            'stream', 'forms', 'lists', 'todo', 'clipchamp', 'loop', 'mesh',
            'copilot', 'ic3', 'pim', 'mip', 'aip', 'rms', 'dlp',

            # Infrastructure
            'provisioning', 'configuration', 'licensing', 'compliance', 'policy',
            'migration', 'sync', 'registration', 'protection', 'discovery',
            'connector', 'gateway', 'portal', 'admin', 'management',
            'shell', 'wcss', 'shredding', 'mro', 'oms',

            # Service types
            'tenant', 'directory', 'identity', 'authentication', 'authorization',
            'token', 'certificate', 'credential', 'secret',

            # Communication
            'conferencing', 'calling', 'pstn', 'meeting', 'attendant', 'bot',
            'notification', 'push', 'signal', 'channel',

            # Data/Analytics
            'reporting', 'analytics', 'telemetry', 'insights', 'diagnostic',

            # Security
            'security', 'safelinks', 'encryption', 'privacy', 'audit',
            'ediscovery', 'retention', 'archiv',

            # Other Microsoft services
            'ocaas', 'mcapi', 'smit', 'cap ', 'ids-', 'ppe-',
            'signup', 'client interaction', 'experience management',
            'worker service', 'lifecycle', 'profile', 'people',
            'approval', 'request', 'support', 'help',
            'common data service', 'dataverse', 'cds',
            'customer service', 'sales', 'marketing',
            'portfolios', 'projectwork', 'weve', 'weveengine',
            'windowsupdate', 'update service',
            'virtual visits', 'billing rp', 'aci', 'spauthevent',
            'customer experience', 'experience platform',

            # Azure resource services
            'acr', 'container registry', 'asm', 'app service',
            'cdn', 'frontdoor', 'traffic manager', 'load balancer',
            'logic app', 'function app', 'devops',
            'cosmos', 'sql server', 'sql database',
            'redis', 'signalr', 'event hub', 'event grid',
            'iot', 'data factory', 'data lake', 'databricks',
            'cognitive', 'bot framework', 'qna',
            'cloud shell', 'advisor', 'cost management',
            'monitor', 'log analytics', 'application insights',
            'backup', 'recovery', 'site recovery',
            'batch', 'hpc', 'machine learning',

            # Generic Microsoft service patterns
            'service', 'processor', 'handler', 'proxy', 'agent',
            'scheduler', 'deployer', 'cab', 'capacity', ' rp',
        ]

        # Check if display name contains any Microsoft keyword
        for keyword in microsoft_keywords:
            if keyword in display_name:
                return True

        # Heuristic: SPNs without owner org that have UUID-prefixed names
        # are Microsoft auto-generated service principals
        if not app_owner_org:
            import re
            if re.match(r'^[0-9a-f]{8}-', display_name):
                return True

        # Default: Assume customer-owned if no Microsoft patterns found
        return False

    def _calculate_role_usage_status(
        self,
        identity: Dict,
        roles: List[Dict],
        entra_roles: List[Dict]
    ) -> tuple:
        """
        Calculate usage status for each role based on inference.

        Usage Status Logic:
        - orphaned: Role scope points to deleted resource (scope_exists=False)
        - definitely_unused: Identity disabled OR credentials expired OR never signed in
        - likely_unused: No sign-in in 90+ days AND role assigned 90+ days ago
        - possibly_overprivileged: Has broader role that makes this one redundant
        - assumed_active: Recent sign-in, recent role assignment

        Returns:
            (updated_roles, updated_entra_roles) with usage_status populated
        """
        # Get identity status indicators
        is_disabled = not identity.get('enabled', True)
        last_sign_in = identity.get('last_sign_in')
        last_activity = identity.get('last_activity_date')
        credential_status = identity.get('credential_status', '')

        # Best available activity proxy: prefer P2 sign-in, fall back to
        # discovery-level last_activity_date (e.g. observed_last_used).
        best_activity = last_sign_in or last_activity

        # Calculate days since activity
        days_since_signin = None
        if best_activity:
            try:
                from datetime import datetime, timezone
                if isinstance(best_activity, str):
                    signin_dt = datetime.fromisoformat(best_activity.replace('Z', '+00:00'))
                else:
                    signin_dt = best_activity
                days_since_signin = (datetime.now(timezone.utc) - signin_dt).days
            except Exception:
                pass

        has_expired_creds = credential_status and 'expired' in credential_status.lower()
        never_signed_in = best_activity is None

        # Check for redundant roles (Owner makes Contributor redundant, etc.)
        role_hierarchy = {
            'owner': ['contributor', 'reader'],
            'contributor': ['reader'],
            'user access administrator': [],
            'global administrator': ['privileged role administrator', 'user administrator', 'application administrator'],
            'privileged role administrator': ['application administrator', 'user administrator'],
        }

        # Get all role names for this identity
        azure_role_names = [r['role_name'].lower() for r in roles]
        entra_role_names = [r['role_name'].lower() for r in entra_roles]
        all_role_names = azure_role_names + entra_role_names

        # Set last_used_at from best available activity proxy
        for role in roles:
            role['last_used_at'] = best_activity
        for role in entra_roles:
            role['last_used_at'] = best_activity

        # Update Azure RBAC roles
        for role in roles:
            role_name_lower = role['role_name'].lower()
            days_assigned = role.get('days_since_assigned')

            # Check for orphaned (scope doesn't exist)
            if not role.get('scope_exists', True):
                role['usage_status'] = 'orphaned'
                continue

            # Check if identity is definitely unused
            if is_disabled:
                role['usage_status'] = 'definitely_unused'
                role['why_critical'] = (role.get('why_critical') or '') + ' Identity is disabled.'
                continue

            if has_expired_creds:
                role['usage_status'] = 'definitely_unused'
                role['why_critical'] = (role.get('why_critical') or '') + ' Credentials are expired.'
                continue

            if never_signed_in:
                role['usage_status'] = 'definitely_unused'
                role['why_critical'] = (role.get('why_critical') or '') + ' Identity has never signed in.'
                continue

            # Check for likely unused (dormant)
            if days_since_signin and days_since_signin > 90 and days_assigned and days_assigned > 90:
                role['usage_status'] = 'likely_unused'
                continue

            # Check for redundant roles
            for broader_role, lesser_roles in role_hierarchy.items():
                if broader_role in all_role_names and role_name_lower in lesser_roles:
                    # Check if same scope (for Azure RBAC)
                    broader_assignments = [r for r in roles if broader_role in r['role_name'].lower()]
                    for broader in broader_assignments:
                        if role.get('scope', '').startswith(broader.get('scope', 'xxx')):
                            role['usage_status'] = 'possibly_overprivileged'
                            role['redundant_with'] = broader['role_name']
                            break
                    if role.get('usage_status') == 'possibly_overprivileged':
                        break

            # Default: assumed active
            if role.get('usage_status', 'unknown') == 'unknown':
                if days_since_signin and days_since_signin < 30:
                    role['usage_status'] = 'assumed_active'
                elif days_assigned and days_assigned < 30:
                    role['usage_status'] = 'assumed_active'
                else:
                    role['usage_status'] = 'unknown'

        # Update Entra roles similarly
        for role in entra_roles:
            role_name_lower = role['role_name'].lower()
            days_assigned = role.get('days_since_assigned')

            if is_disabled:
                role['usage_status'] = 'definitely_unused'
                continue

            if has_expired_creds:
                role['usage_status'] = 'definitely_unused'
                continue

            if never_signed_in:
                role['usage_status'] = 'definitely_unused'
                continue

            if days_since_signin and days_since_signin > 90:
                role['usage_status'] = 'likely_unused'
                continue

            # Check for redundant Entra roles
            for broader_role, lesser_roles in role_hierarchy.items():
                if broader_role in entra_role_names and role_name_lower in lesser_roles:
                    role['usage_status'] = 'possibly_overprivileged'
                    role['redundant_with'] = broader_role.title()
                    break

            if role.get('usage_status', 'unknown') == 'unknown':
                if days_since_signin and days_since_signin < 30:
                    role['usage_status'] = 'assumed_active'
                else:
                    role['usage_status'] = 'unknown'

        # Normalize usage_status to standard values for UI display
        _STATUS_MAP = {
            'assumed_active': 'active',
            'definitely_unused': 'never_used',
            'likely_unused': 'dormant',
            'possibly_overprivileged': 'stale',
            'orphaned': 'dormant',
        }
        for role in roles + entra_roles:
            old = role.get('usage_status', 'unknown')
            if old in _STATUS_MAP:
                role['usage_status'] = _STATUS_MAP[old]
            elif old not in ('active', 'stale', 'dormant', 'never_used', 'unknown'):
                # Compute from last_sign_in if still unknown
                if days_since_signin is not None:
                    if days_since_signin <= 30:
                        role['usage_status'] = 'active'
                    elif days_since_signin <= 90:
                        role['usage_status'] = 'stale'
                    else:
                        role['usage_status'] = 'dormant'
                elif never_signed_in:
                    role['usage_status'] = 'never_used'

        return (roles, entra_roles)

    def _calculate_risks(
        self,
        identities: List[Dict],
        role_assignments: List[Dict],
        entra_roles: List[Dict] = [],
        permissions_map: Dict[str, List[Dict]] = None,
        app_roles_map: Dict[str, List[Dict]] = None,
        credentials_map: Dict[str, List[Dict]] = None
    ) -> List[Dict]:
        """
        V2 structured risk calculation. Produces both risk_reasons (backward compat)
        and risk_factors JSONB (structured factor cards).

        V2 Risk Levels:
        - 900+ = CRITICAL
        - 500-899 = HIGH
        - 200-499 = MEDIUM
        - 1-199 = LOW
        - 0 = INFO
        """
        from app.engines.risk_catalog import make_factor, score_to_level_v2

        permissions_map = permissions_map or {}
        app_roles_map = app_roles_map or {}
        credentials_map = credentials_map or {}

        # Process ALL identities - don't filter any out
        for identity in identities:
            if identity.get('identity_type') in ('human_user', 'guest'):
                if not identity.get('identity_category'):
                    identity['identity_category'] = 'human_user'
                identity['is_microsoft_system'] = False

        # Calculate risks for all identities
        for identity in identities:
            identity_id = identity.get('identity_id')
            object_id = identity.get('object_id')

            # Gather all data for this identity
            identity_roles = [ra for ra in role_assignments if ra['principal_id'] == object_id]
            identity_entra_roles = [er for er in entra_roles if er['principal_id'] == object_id]
            identity_permissions = permissions_map.get(identity_id, [])
            identity_app_roles = app_roles_map.get(identity_id, [])
            identity_credentials = credentials_map.get(identity_id, [])

            # Initialize V2 scoring
            risk_factors = []

            # ============================================================
            # 1. Entra ID Directory Roles (highest privilege)
            # ============================================================
            for entra_role in identity_entra_roles:
                role_name_lower = entra_role['role_name'].lower()
                if 'global administrator' in role_name_lower:
                    risk_factors.append(make_factor("TENANT_ADMIN_ROLE", f"entra_role:{entra_role['role_name']}"))
                elif 'privileged role administrator' in role_name_lower:
                    risk_factors.append(make_factor("PRIV_ROLE_ADMIN", f"entra_role:{entra_role['role_name']}"))
                elif 'application administrator' in role_name_lower or 'cloud application administrator' in role_name_lower:
                    risk_factors.append(make_factor("APP_ADMIN_ROLE", f"entra_role:{entra_role['role_name']}"))
                elif 'user administrator' in role_name_lower:
                    risk_factors.append(make_factor("USER_ADMIN_ROLE", f"entra_role:{entra_role['role_name']}"))
                elif 'security administrator' in role_name_lower:
                    risk_factors.append(make_factor("SECURITY_ADMIN_ROLE", f"entra_role:{entra_role['role_name']}"))
                elif 'exchange administrator' in role_name_lower:
                    risk_factors.append(make_factor("EXCHANGE_ADMIN_ROLE", f"entra_role:{entra_role['role_name']}"))
                elif 'sharepoint administrator' in role_name_lower:
                    risk_factors.append(make_factor("SHAREPOINT_ADMIN_ROLE", f"entra_role:{entra_role['role_name']}"))

            # ============================================================
            # 2. Azure RBAC Roles
            # ============================================================
            # V2 exact-match map for RBAC role → risk factor code
            _V2_RBAC_FACTOR = {
                'owner': lambda st: "SUBSCRIPTION_OWNER" if st == 'subscription' else "RG_OWNER" if st == 'resource_group' else "RESOURCE_OWNER",
                'contributor': lambda st: "SUBSCRIPTION_CONTRIBUTOR" if st == 'subscription' else "RG_CONTRIBUTOR" if st == 'resource_group' else "SCOPED_CONTRIBUTOR",
                'user access administrator': lambda _: "UAA_ROLE",
                'key vault administrator': lambda _: "KEYVAULT_FULL_ACCESS",
                'key vault secrets officer': lambda _: "KEYVAULT_FULL_ACCESS",
                'key vault crypto officer': lambda _: "KEYVAULT_FULL_ACCESS",
                'storage blob data contributor': lambda _: "SCOPED_DATA_CONTRIBUTOR",
                'storage blob data owner': lambda _: "SCOPED_DATA_CONTRIBUTOR",
                'network contributor': lambda _: "NETWORK_CONTRIBUTOR",
                'virtual machine contributor': lambda _: "VM_CONTRIBUTOR",
                'sql db contributor': lambda _: "DB_CONTRIBUTOR",
                'sql server contributor': lambda _: "DB_CONTRIBUTOR",
                'documentdb account contributor': lambda _: "DB_CONTRIBUTOR",
            }

            for role in identity_roles:
                role_name_lower = role['role_name'].lower().strip()
                scope_type = role['scope_type']
                source_label = f"rbac:{role['role_name']}@{scope_type}"

                if role_name_lower in _V2_RBAC_FACTOR:
                    factor_code = _V2_RBAC_FACTOR[role_name_lower](scope_type)
                    risk_factors.append(make_factor(factor_code, source_label))
                elif role_name_lower.endswith('contributor'):
                    risk_factors.append(make_factor("SCOPED_CONTRIBUTOR", source_label))
                elif role_name_lower.endswith('owner'):
                    risk_factors.append(make_factor("RESOURCE_OWNER", source_label))

            # ============================================================
            # 3. API Permissions (Graph API)
            # ============================================================
            write_permissions = []
            read_all_permissions = []

            for perm in identity_permissions:
                perm_name = (perm.get('permission_name') or '').lower()
                if '.write' in perm_name or '.readwrite' in perm_name:
                    write_permissions.append(perm.get('permission_name'))
                elif '.read.all' in perm_name or 'readall' in perm_name:
                    read_all_permissions.append(perm.get('permission_name'))

            if write_permissions:
                risk_factors.append(make_factor("DIRECTORY_RW_API", f"{len(write_permissions)} write perm(s): {', '.join(write_permissions[:3])}"))

            if read_all_permissions and not write_permissions:
                risk_factors.append(make_factor("DIRECTORY_READ_ALL_API", f"{len(read_all_permissions)} read-all perm(s)"))

            # ============================================================
            # 4. Orphaned Permissions
            # ============================================================
            has_roles = len(identity_roles) > 0 or len(identity_entra_roles) > 0
            has_permissions = len(identity_permissions) > 0

            if not has_roles and has_permissions:
                risk_factors.append(make_factor("ORPHANED_PERMISSIONS", f"{len(identity_permissions)} API perms without role justification"))

            # ============================================================
            # 5. App Roles
            # ============================================================
            admin_app_roles = []
            for app_role in identity_app_roles:
                role_value = (app_role.get('app_role_value') or app_role.get('resource_display_name') or '').lower()
                if any(keyword in role_value for keyword in ['admin', 'owner', 'full', 'write', 'manage']):
                    admin_app_roles.append(app_role)

            if admin_app_roles:
                risk_factors.append(make_factor("ADMIN_APP_ROLES", f"{len(admin_app_roles)} admin app role(s)"))
            elif identity_app_roles:
                risk_factors.append(make_factor("STANDARD_APP_ROLES", f"{len(identity_app_roles)} app role(s)"))

            # ============================================================
            # 6. Credential Status
            # ============================================================
            has_expired = False
            has_expiring_soon = False
            active_cred_count = 0
            for cred in identity_credentials:
                end_date = cred.get('end_datetime')
                if end_date:
                    from datetime import datetime, timezone
                    try:
                        if isinstance(end_date, str):
                            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                        else:
                            end_dt = end_date
                        now = datetime.now(timezone.utc)
                        if end_dt < now:
                            has_expired = True
                        else:
                            active_cred_count += 1
                            if (end_dt - now).days < 30:
                                has_expiring_soon = True
                    except Exception:
                        active_cred_count += 1

            if has_expired:
                risk_factors.append(make_factor("SECRET_EXPIRED", "Unrotated expired credential(s)"))
            elif has_expiring_soon:
                risk_factors.append(make_factor("SECRET_EXPIRING_SOON", "Credential(s) expiring within 30 days"))

            if active_cred_count > 1:
                risk_factors.append(make_factor("MULTIPLE_ACTIVE_SECRETS", f"{active_cred_count} active credentials"))

            # ============================================================
            # 7. Orphaned identity
            # ============================================================
            if not has_roles and not has_permissions and not identity_app_roles:
                if identity.get('identity_type') not in ('human_user', 'guest'):
                    risk_factors.append(make_factor("ORPHANED_IDENTITY", "No role assignments"))

            # ============================================================
            # 8. Ghost identity — CIS v8 Control 5.3 / MITRE T1078.001
            # ============================================================
            if not identity.get('enabled', True) and has_roles:
                risk_factors.append(make_factor("GHOST_ACCESS",
                    f"Disabled identity with {len(identity_roles) + len(identity_entra_roles)} active role assignment(s)"))

            # ============================================================
            # Sum V2 score and derive level
            # ============================================================
            risk_score = sum(f['points'] for f in risk_factors)
            risk_level = score_to_level_v2(risk_score)

            # Backward-compat: derive risk_reasons from factors
            risk_reasons = [f"{f['description']} (+{f['points']})" for f in risk_factors]
            if not risk_reasons:
                risk_reasons = ['No elevated privileges detected']

            # ============================================================
            # Apply custom risk rules (post-scoring adjustment)
            # ============================================================
            try:
                custom_rules = self._get_custom_rules()
                if custom_rules:
                    from app.engines.risk_rules import RiskRuleEngine
                    engine = RiskRuleEngine()
                    rule_identity = {
                        **identity,
                        'risk_score': risk_score,
                        'role_count': len(identity_roles) + len(identity_entra_roles),
                        'api_permission_count': len(identity_permissions),
                        'app_role_count': len(identity_app_roles),
                        'roles': identity_roles,
                        'entra_roles': identity_entra_roles,
                        '_permissions': identity_permissions,
                        '_credentials': identity_credentials,
                    }
                    adj, extra_reasons, forced = engine.evaluate_rules(rule_identity, custom_rules)
                    if forced:
                        risk_level = forced
                        risk_reasons.extend(extra_reasons)
                    elif adj != 0:
                        risk_score += adj
                        risk_reasons.extend(extra_reasons)
                        risk_level = score_to_level_v2(risk_score)
            except Exception as e:
                logger.warning("Custom risk rules error: %s", e)

            # Calculate role usage status (inference-based)
            identity_roles, identity_entra_roles = self._calculate_role_usage_status(
                identity, identity_roles, identity_entra_roles
            )

            # Store results
            identity['risk_level'] = risk_level
            identity['risk_score'] = risk_score
            identity['risk_reasons'] = risk_reasons
            identity['risk_factors'] = risk_factors
            identity['roles'] = identity_roles
            identity['entra_roles'] = identity_entra_roles
            identity['role_count'] = len(identity_roles) + len(identity_entra_roles)
            identity['api_permission_count'] = len(identity_permissions)
            identity['app_role_count'] = len(identity_app_roles)

            # Print high-risk identities
            if risk_level in ['critical', 'high']:
                logger.info("%s: %s (%s pts)", identity['display_name'], risk_level.upper(), risk_score)
                for factor in risk_factors[:3]:
                    logger.info("  %s: +%s (%s)", factor['code'], factor['points'], factor['severity'])

        # Summary
        critical_count = sum(1 for i in identities if i.get('risk_level') == 'critical')
        high_count = sum(1 for i in identities if i.get('risk_level') == 'high')

        logger.info("Risk Summary (V2 scale):")
        logger.info("Total: %s customer-owned identities", len(identities))
        logger.info("Critical: %s  High: %s", critical_count, high_count)

        return identities

    def _get_custom_rules(self):
        """Fetch enabled custom risk rules (cached per discovery run)."""
        if not hasattr(self, '_cached_custom_rules'):
            try:
                self._cached_custom_rules = self.db.get_enabled_risk_rules()
            except Exception:
                self._cached_custom_rules = []
        return self._cached_custom_rules

    def _check_credentials(self, identities: List[Dict], credentials_map: Dict[str, List[Dict]] = None) -> List[Dict]:
        from datetime import datetime, timezone
        credentials_map = credentials_map or {}
        now = datetime.now(timezone.utc)
        expired_count = 0
        expiring_count = 0

        logger.info("Checking %s identities for credential expiration...", len(identities))
        for identity in identities:
            creds = credentials_map.get(identity.get('identity_id'), [])
            # Find earliest non-federated expiry
            expiries = []
            for c in creds:
                if c.get('credential_type') == 'federated':
                    continue
                end = c.get('end_datetime')
                if end:
                    if isinstance(end, str):
                        try:
                            end = datetime.fromisoformat(end.replace('Z', '+00:00'))
                        except (ValueError, TypeError):
                            continue
                    expiries.append(end)

            if expiries:
                earliest = min(expiries)
                identity['credential_expiration'] = earliest.isoformat()
                identity['secret_expiry_earliest'] = earliest.isoformat()
                if earliest < now:
                    identity['credential_status'] = 'Expired'
                    identity['secret_expiry_status'] = 'expired'
                    expired_count += 1
                elif earliest < now + __import__('datetime').timedelta(days=30):
                    identity['credential_status'] = 'Expiring Soon'
                    identity['secret_expiry_status'] = 'expiring_soon'
                    expiring_count += 1
                elif earliest < now + __import__('datetime').timedelta(days=90):
                    identity['credential_status'] = 'Valid'
                    identity['secret_expiry_status'] = 'expiring_90d'
                else:
                    identity['credential_status'] = 'Valid'
                    identity['secret_expiry_status'] = 'valid'
            elif creds:
                # Has credentials but none with expiry (federated-only or no-expiry)
                identity['credential_status'] = 'Valid'
                identity['credential_expiration'] = None
                identity['secret_expiry_earliest'] = None
                identity['secret_expiry_status'] = 'no_secret'
            else:
                identity['credential_status'] = None
                identity['credential_expiration'] = None
                identity['secret_expiry_earliest'] = None
                identity['secret_expiry_status'] = 'no_secret'

        logger.info("Credential check: %s expired, %s expiring soon, %s total with creds",
                     expired_count, expiring_count, len(credentials_map))
        return identities
    
    def _check_activity(self, identities: List[Dict]) -> List[Dict]:
        """
        Calculate activity status based on sign-in data.

        Activity Status:
        - active: Signed in within last 30 days
        - inactive: Signed in 30-90 days ago
        - stale: Signed in 90+ days ago
        - never_used: Never signed in
        - unknown: No sign-in data available
        """
        from datetime import datetime, timezone

        logger.info("Checking %s identities...", len(identities))

        active_count = 0
        inactive_count = 0
        stale_count = 0
        never_used_count = 0
        unknown_count = 0

        for identity in identities:
            # ── DISABLED ACCOUNT GATE (P0 trust rule) ────────────────────
            # A disabled Azure AD account CANNOT perform interactive sign-ins.
            # Any activity signal is either pre-disable history, ARM noise,
            # or group-level misattribution. Disabled = Inactive. No exceptions.
            if not identity.get('enabled', True):
                identity['activity_status'] = 'inactive'
                inactive_count += 1
                continue

            last_sign_in = identity.get('last_sign_in')
            observed = identity.get('observed_last_used')

            if last_sign_in:
                try:
                    if isinstance(last_sign_in, str):
                        signin_dt = datetime.fromisoformat(last_sign_in.replace('Z', '+00:00'))
                    else:
                        signin_dt = last_sign_in
                        if signin_dt.tzinfo is None:
                            signin_dt = signin_dt.replace(tzinfo=timezone.utc)

                    days_since = (datetime.now(timezone.utc) - signin_dt).days

                    if days_since <= 30:
                        identity['activity_status'] = 'active'
                        active_count += 1
                    elif days_since <= 90:
                        identity['activity_status'] = 'inactive'
                        inactive_count += 1
                    else:
                        identity['activity_status'] = 'stale'
                        stale_count += 1
                except Exception:
                    identity['activity_status'] = 'unknown'
                    unknown_count += 1
            elif observed:
                # AuditGraph-observed activity (connector SPN authenticates
                # during scan). Classify by age of observation.
                try:
                    if isinstance(observed, str):
                        obs_dt = datetime.fromisoformat(str(observed).replace('Z', '+00:00'))
                        if obs_dt.tzinfo is None:
                            obs_dt = obs_dt.replace(tzinfo=timezone.utc)
                    else:
                        obs_dt = observed
                        if obs_dt.tzinfo is None:
                            obs_dt = obs_dt.replace(tzinfo=timezone.utc)
                    days_since = (datetime.now(timezone.utc) - obs_dt).days
                    if days_since <= 30:
                        identity['activity_status'] = 'active'
                        active_count += 1
                    elif days_since <= 90:
                        identity['activity_status'] = 'inactive'
                        inactive_count += 1
                    else:
                        identity['activity_status'] = 'stale'
                        stale_count += 1
                except Exception:
                    identity['activity_status'] = 'unknown'
                    unknown_count += 1
            else:
                # No sign-in data — use multi-signal behavioral intelligence
                # to avoid false never_used classification.
                created = identity.get('created_datetime')
                days_old = None
                if created:
                    try:
                        created_dt = datetime.fromisoformat(str(created).replace('Z', '+00:00')) if isinstance(created, str) else created
                        days_old = (datetime.now(timezone.utc) - created_dt).days
                    except Exception:
                        pass

                if days_old is not None and days_old < 7:
                    # Recently created — too early to classify
                    identity['activity_status'] = 'recently_created'
                    unknown_count += 1

                # Signal 1: Federated credential = OIDC/workload identity (authenticates without sign-in logs)
                elif identity.get('federated_workload_type') or identity.get('is_federated'):
                    identity['activity_status'] = 'likely_active'
                    active_count += 1

                # Signal 2: Privileged accounts (T0/T1) should never be classified never_used
                # without explicit decommission evidence — they require manual review
                elif identity.get('privilege_tier') in ('T0', 'T1', 0, 1):
                    identity['activity_status'] = 'likely_active'
                    active_count += 1

                # Signal 3: Has active credentials (secrets/certs) = likely in use
                elif (identity.get('credential_count') or 0) > 0 and identity.get('credential_risk') != 'expired':
                    identity['activity_status'] = 'likely_active'
                    active_count += 1

                # Signal 4: Recent ARM role assignments (< 90 days) = operational identity
                elif self._has_recent_role_assignment(identity, max_days=90):
                    identity['activity_status'] = 'likely_active'
                    active_count += 1

                else:
                    identity['activity_status'] = 'never_used'
                    never_used_count += 1

            # ── Sign-in pattern classification (Prompt 4) ──────────────
            signin_raw = identity.get('_signin_activity_raw', {})
            signin_result = self._classify_signin_pattern(signin_raw)
            identity['signin_pattern'] = signin_result['signin_pattern']
            identity['last_delegated_signin'] = signin_result['last_delegated_signin']
            identity['last_noninteractive_signin'] = signin_result['last_noninteractive_signin']
            identity['days_since_last_signin'] = signin_result['days_since_last_signin']
            # Merge signin risk flags into existing workload_risk_flags
            existing_flags = identity.get('workload_risk_flags') or []
            new_flags = signin_result['signin_risk_flags']
            identity['workload_risk_flags'] = list(dict.fromkeys(existing_flags + new_flags))

            # ── Canonical last_activity waterfall (SSOT) ──────────────
            try:
                self._compute_last_activity(identity)
            except Exception as exc:
                logger.warning("_compute_last_activity failed for %s: %s",
                               identity.get('display_name', '?'), exc)

        logger.info("Activity Summary:")
        if active_count > 0:
            logger.info("Active (30 days): %s", active_count)
        if inactive_count > 0:
            logger.info("Inactive (30-90 days): %s", inactive_count)
        if stale_count > 0:
            logger.info("Stale (90+ days): %s", stale_count)
        if never_used_count > 0:
            logger.info("Never used: %s", never_used_count)
        if unknown_count > 0:
            logger.info("Unknown: %s", unknown_count)

        return identities

    @staticmethod
    def _has_recent_role_assignment(identity: Dict, max_days: int = 90) -> bool:
        """Check if identity has ARM role assignments created within max_days."""
        from datetime import datetime, timezone
        roles = identity.get('role_assignments') or []
        now = datetime.now(timezone.utc)
        for ra in roles:
            created = ra.get('created_on')
            if not created:
                continue
            try:
                if isinstance(created, str):
                    created = datetime.fromisoformat(created.replace('Z', '+00:00'))
                if hasattr(created, 'timestamp'):
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    if (now - created).days <= max_days:
                        return True
            except Exception:
                continue
        return False

    @staticmethod
    def _compute_last_activity(identity: Dict):
        """Compute canonical last_activity_date/source/confidence via priority waterfall.

        Priority (highest first):
        1. signInActivity.lastSignInDateTime → graph_signin / high
        2. lastNonInteractiveSignInDateTime → entra_noninteractive / high
        3. observed_last_used (AuditGraph scan — currently only set for the
           discovery connector SPN, which authenticated to Azure to run us) →
           auditgraph_scan / high
        4. Most recent role_assignments[].created_on → role_assignment / medium
        5. credential_expiration (non-expired = implies rotation) → credential_rotation / medium
        6. federated_credential_created / created_datetime for federated → federated_credential / medium
        7. created_datetime → created_date / low
        8. null → null / none

        Note: workload_signin_events (signal 0) is applied at API query time,
        not here — it lives in a separate table.
        """
        from datetime import datetime, timezone

        # ── DISABLED ACCOUNT GUARD (defense-in-depth, AG-145) ──────────
        # Disabled accounts must never have activity attributed.
        # Primary gate is in _check_activity (continue), but this guards
        # against future calling-code changes.
        if not identity.get('enabled', True):
            identity['last_activity_date'] = None
            identity['last_activity_source'] = None
            identity['last_activity_confidence'] = 'none'
            return

        def _parse(v):
            if not v:
                return None
            if hasattr(v, 'timestamp'):
                # Normalize naive datetimes to UTC to prevent
                # "offset-naive vs offset-aware" comparison errors.
                if v.tzinfo is None:
                    v = v.replace(tzinfo=timezone.utc)
                return v
            try:
                dt = datetime.fromisoformat(str(v).replace('Z', '+00:00'))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except (ValueError, TypeError):
                return None

        best_date = None
        source = None
        confidence = 'none'

        # Signal 1: Graph signInActivity (interactive sign-in)
        last_si = _parse(identity.get('last_sign_in'))
        if last_si:
            best_date = last_si
            source = 'graph_signin'
            confidence = 'high'

        # Signal 2: Non-interactive sign-in
        last_ni = _parse(identity.get('last_noninteractive_signin'))
        if last_ni and (best_date is None or last_ni > best_date):
            best_date = last_ni
            source = 'entra_noninteractive'
            confidence = 'high'

        # Signal 3: AuditGraph scan activity (observed_last_used)
        # We set this for the connector SPN at discovery time — it proves the
        # SPN successfully authenticated to Azure within the last few minutes.
        obs = _parse(identity.get('observed_last_used'))
        if obs and (best_date is None or obs > best_date):
            best_date = obs
            source = 'auditgraph_scan'
            confidence = 'high'

        # Signal 3: Most recent role assignment created_on
        role_assignments = identity.get('role_assignments') or []
        for ra in role_assignments:
            ra_dt = _parse(ra.get('created_on'))
            if ra_dt and (best_date is None or ra_dt > best_date):
                best_date = ra_dt
                source = 'role_assignment'
                confidence = 'medium'

        # Signal 4: Credential expiration (non-expired implies rotation activity)
        cred_exp = _parse(identity.get('credential_expiration'))
        if cred_exp and cred_exp > datetime.now(timezone.utc):
            # Non-expired credential — use as activity signal only if nothing better
            if best_date is None:
                best_date = cred_exp
                source = 'credential_rotation'
                confidence = 'medium'

        # Signal 5: Federated credential
        if identity.get('federated_workload_type') or identity.get('is_federated'):
            created = _parse(identity.get('created_datetime'))
            if created and best_date is None:
                best_date = created
                source = 'federated_credential'
                confidence = 'medium'

        # Signal 6: created_datetime as last resort
        if best_date is None:
            created = _parse(identity.get('created_datetime'))
            if created:
                best_date = created
                source = 'created_date'
                confidence = 'low'

        identity['last_activity_date'] = best_date.isoformat() if best_date else None
        identity['last_activity_source'] = source
        identity['last_activity_confidence'] = confidence

    def _compute_telemetry_coverage(self, identities: List[Dict]) -> List[Dict]:
        """Classify telemetry coverage for each identity based on connector permissions.

        Coverage levels:
        - full: All relevant telemetry sources available for this identity type.
        - partial: Some telemetry sources available but not all.
        - blind: No meaningful telemetry sources available (only metadata).

        Classification rules by identity_category:
        - human_user/guest: Needs p2_signin_activity OR arm_activity_log for full.
        - service_principal: Needs arm_activity_log for full. p2_signin alone = partial.
        - managed_identity_*: Needs arm_activity_log for full (sign-in logs don't cover MI).

        This method reads the connector_permissions table once (batch) and applies
        the coverage classification to all identities in the list.
        """
        # Fetch permission statuses for this connection
        perm_status = {}  # permission_name → status
        if self.cloud_connection_id:
            try:
                rows = self.db.get_connector_permissions(
                    self.db_org_id, connection_id=self.cloud_connection_id)
                for row in rows:
                    # Single connection: (permission_name, status, tested_at, error_detail, impact)
                    perm_status[row[0]] = row[1]
            except Exception as e:
                logger.debug("Could not fetch connector permissions for coverage: %s", e)
                try:
                    self.db._rollback()
                except Exception:
                    pass

        has_arm = perm_status.get('arm_activity_log') == 'granted'
        has_p2 = perm_status.get('p2_signin_activity') == 'granted'
        has_audit = perm_status.get('directory_audit_log') == 'granted'

        for identity in identities:
            category = (identity.get('identity_category') or '').lower()

            if category in ('human_user', 'guest'):
                # Humans need sign-in telemetry (P2) or ARM activity
                if has_p2 and has_arm:
                    identity['telemetry_coverage'] = 'full'
                elif has_p2 or has_arm:
                    identity['telemetry_coverage'] = 'partial'
                else:
                    identity['telemetry_coverage'] = 'blind'

            elif category in ('managed_identity_system', 'managed_identity_user'):
                # Managed identities: ARM is the only meaningful signal
                # (sign-in logs don't cover MI; P2 doesn't help)
                if has_arm:
                    identity['telemetry_coverage'] = 'full'
                elif has_audit:
                    identity['telemetry_coverage'] = 'partial'
                else:
                    identity['telemetry_coverage'] = 'blind'

            elif category == 'service_principal':
                # SPNs: ARM + P2 = full, either alone = partial
                if has_arm and has_p2:
                    identity['telemetry_coverage'] = 'full'
                elif has_arm or has_p2:
                    identity['telemetry_coverage'] = 'partial'
                else:
                    identity['telemetry_coverage'] = 'blind'

            else:
                # microsoft_internal or unknown — best-effort
                if has_arm or has_p2:
                    identity['telemetry_coverage'] = 'partial'
                else:
                    identity['telemetry_coverage'] = 'blind'

        return identities

    async def _validate_arm_activity_log_permission(self) -> bool:
        """Verify ARM Activity Log read permission exists before bulk fetch.

        Tests a single $top=1 call against the first subscription.
        Logs clear guidance if permission is missing (403).
        Persists result to connector_permissions table.
        Returns True if ARM Activity Log is accessible.
        """
        import aiohttp

        sub_ids = [s['id'] for s in self.subscriptions]
        if not sub_ids:
            self._persist_permission('arm_activity_log', 'not_tested',
                                     error_detail='No subscriptions available')
            return False

        try:
            arm_token = self.credential.get_token("https://management.azure.com/.default")
            arm_headers = {"Authorization": f"Bearer {arm_token.token}"}
        except Exception as e:
            logger.warning("ARM token acquisition failed — cannot validate Activity Log permission: %s", e)
            self._persist_permission('arm_activity_log', 'denied',
                                     error_detail=f'Token acquisition failed: {str(e)[:200]}')
            return False

        test_sub = sub_ids[0]

        try:
            from urllib.parse import quote
            # ARM Activity Log requires $filter with eventTimestamp
            cutoff = (datetime.utcnow() - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
            filter_str = f"eventTimestamp ge '{cutoff}'"
            async with aiohttp.ClientSession(timeout=GRAPH_HTTP_TIMEOUT) as session:
                url = (
                    f"https://management.azure.com"
                    f"/subscriptions/{test_sub}"
                    f"/providers/microsoft.insights"
                    f"/eventtypes/management/values"
                    f"?api-version=2015-04-01"
                    f"&$filter={quote(filter_str)}"
                    f"&$top=1"
                )
                async with session.get(url, headers=arm_headers) as resp:
                    if resp.status == 200:
                        logger.info("ARM Activity Log permission verified for subscription %s", test_sub[:8])
                        self._persist_permission('arm_activity_log', 'granted')
                        return True
                    elif resp.status == 403:
                        logger.warning(
                            "ARM Activity Log PERMISSION MISSING for subscription %s. "
                            "Last IP column will show '—'. "
                            "Fix: assign 'Monitoring Reader' role to AuditGraph service principal "
                            "on subscription %s. No P2 license required.",
                            test_sub, test_sub
                        )
                        self._persist_permission(
                            'arm_activity_log', 'denied',
                            error_detail='HTTP 403 — Monitoring Reader role not assigned',
                            impact_description='Identity activity evidence and role last-used '
                                              'timestamps unavailable. Identities will show as '
                                              'telemetry-blind for activity.')
                        return False
                    else:
                        body = await resp.text()
                        logger.warning("ARM Activity Log validation returned HTTP %s for %s: %s", resp.status, test_sub[:8], body[:500])
                        self._persist_permission('arm_activity_log', 'denied',
                                                 error_detail=f'HTTP {resp.status}: {body[:200]}')
                        return False
        except Exception as e:
            logger.warning("ARM Activity Log validation failed: %s", e)
            self._persist_permission('arm_activity_log', 'denied',
                                     error_detail=f'Validation error: {str(e)[:200]}')
            return False

    def _persist_permission(self, permission_name: str, status: str,
                            error_detail: str = None, impact_description: str = None):
        """Persist a connector permission check result to the database."""
        if not self.cloud_connection_id:
            return
        try:
            self.db.save_connector_permission(
                connection_id=self.cloud_connection_id,
                org_id=self.db_org_id,
                permission_name=permission_name,
                status=status,
                error_detail=error_detail,
                impact_description=impact_description,
            )
        except Exception as e:
            logger.debug("Failed to persist permission check for %s: %s", permission_name, e)
            try:
                self.db._rollback()
            except Exception:
                pass

    # Noisy Azure platform operations that add no security signal
    _ARM_SKIP_OPERATION_PREFIXES = (
        'Microsoft.Resources/deployments/',
        'Microsoft.Resources/tags/',
        'Microsoft.Resources/subscriptions/read',
        'Microsoft.Resources/checkResourceName',
        'Microsoft.Authorization/policies/',
        'Microsoft.Authorization/policyAssignments/',
        'Microsoft.Authorization/roleAssignments/read',
        'Microsoft.Authorization/permissions/read',
        'Microsoft.Advisor/',
        'Microsoft.Security/assessments/',
        'Microsoft.Security/subAssessments/',
        'Microsoft.Security/autoProvisioningSettings/',
        'Microsoft.Insights/diagnosticSettings/',
        'Microsoft.Insights/autoscalesettings/',
        'Microsoft.Insights/metrics/',
        'Microsoft.Insights/logs/',
        'Microsoft.Compute/restorePointCollections/',
        'Microsoft.AlertsManagement/',
        'Microsoft.PolicyInsights/',
        'Microsoft.CostManagement/',
        'Microsoft.Billing/',
    )

    # Operations ending with these suffixes NEVER count as meaningful role exercise.
    # Read/list operations prove network reachability but not privilege usage.
    _ARM_NOISE_SUFFIXES = (
        '/read',
        '/listKeys',
        '/listkeys',
        '/list',
    )

    def _collect_arm_activity(self, run_id: int, identities: list) -> None:
        """Collect ARM management activity events per subscription (no P2 required).

        For each subscription:
        1. Fetches recent management events from ARM Activity Log API
        2. Matches events to known identity principal IDs
        3. Stores top events in identity_arm_connections table
        4. Updates role_assignments.last_used_at from matched events

        Uses ARM Reader token (same as role assignment reads).
        Rate limit: ~12,000 requests/hour. One request per subscription.
        """
        import time as _time
        from urllib.parse import quote

        phase_start = _time.monotonic()
        sub_ids = [s['id'] for s in self.subscriptions]
        if not sub_ids:
            logger.debug("[arm_activity] No subscriptions — skipping")
            return

        # Build caller → identity_db_id lookup
        # ARM Activity Log caller field values:
        #   - Human users: UPN (email)
        #   - Service principals: app_id (client_id / application_id)
        #   - Claims OID fallback: object_id
        # AG-145: Exclude disabled identities — they cannot perform actions.
        cursor = self.db.conn.cursor()
        cursor.execute(
            "SELECT id, object_id, principal_id, identity_id, display_name, upn, enabled, app_id "
            "FROM identities WHERE discovery_run_id = %s",
            (run_id,)
        )
        pid_map = {}  # caller string → identity_db_id
        disabled_skipped = 0
        for row in cursor.fetchall():
            db_id, obj_id, principal_id, identity_id, display_name, upn, enabled, app_id = row
            # ── AG-145 Rule 1: Disabled identities must never receive ARM attribution
            if enabled is False:
                disabled_skipped += 1
                continue
            if obj_id:
                pid_map[obj_id] = db_id
            if principal_id and principal_id != obj_id:
                pid_map[principal_id] = db_id
            # AG-147: ARM caller for SPNs is app_id (client_id), NOT object_id.
            # Terraform, Azure DevOps, and other SPN-authenticated tools use
            # the application (client) ID as the ARM caller value.
            if app_id and app_id != obj_id:
                pid_map[app_id] = db_id
            # For human users, ARM uses UPN as caller (looks like email)
            if identity_id and '@' in str(identity_id):
                pid_map[identity_id] = db_id
                pid_map[str(identity_id).lower()] = db_id
            # UPN column (most reliable for human user ARM matching)
            if upn and '@' in str(upn):
                pid_map[upn] = db_id
                pid_map[str(upn).lower()] = db_id
            # AG-145 Rule 2: display_name removed from pid_map — unreliable,
            # causes cross-identity misattribution when multiple identities
            # share similar display names containing '@'.
        cursor.close()
        if disabled_skipped:
            logger.info("[arm_activity] Excluded %d disabled identities from caller map", disabled_skipped)
        logger.info("[arm_activity] Starting for org=%s, run=%s: %d caller_map entries, %d subscriptions",
                     self.db_org_id, run_id, len(pid_map), len(sub_ids))

        if not pid_map:
            logger.debug("[arm_activity] No identities with principal IDs — skipping")
            return

        # Get ARM token
        try:
            arm_token = self.credential.get_token("https://management.azure.com/.default")
        except Exception as e:
            logger.warning("[arm_activity] ARM token acquisition failed: %s", e)
            return

        import requests
        session = requests.Session()
        session.headers.update({
            "Authorization": f"Bearer {arm_token.token}",
            "Content-Type": "application/json",
        })

        # AG-147: Configurable lookback window. End is always scan-time (utcnow).
        import os as _os
        arm_lookback_days = int(_os.environ.get('ARM_ACTIVITY_LOOKBACK_DAYS', '90'))
        cutoff = (datetime.utcnow() - timedelta(days=arm_lookback_days)).strftime('%Y-%m-%dT%H:%M:%SZ')
        all_events = []  # list of dicts for identity_arm_connections
        role_updates = {}  # (principal_id, resource_id) → best event per scope

        for sub_id in sub_ids:
            elapsed = _time.monotonic() - phase_start
            if elapsed > 180:  # 3 minute budget
                logger.warning("[arm_activity] Time budget exceeded at %.1fs — processed %d/%d subs",
                               elapsed, sub_ids.index(sub_id), len(sub_ids))
                break

            filter_str = f"eventTimestamp ge '{cutoff}'"
            url = (
                f"https://management.azure.com"
                f"/subscriptions/{sub_id}"
                f"/providers/microsoft.insights"
                f"/eventtypes/management/values"
                f"?api-version=2015-04-01"
                f"&$filter={quote(filter_str)}"
                f"&$top=500"
            )

            try:
                resp = session.get(url, timeout=30)
                if resp.status_code == 403:
                    logger.debug("[arm_activity] Permission denied for sub %s -- skipping", sub_id[:8])
                    continue
                if resp.status_code != 200:
                    logger.debug("[arm_activity] HTTP %s for sub %s: %s",
                                resp.status_code, sub_id[:8], resp.text[:300])
                    continue
                data = resp.json()
            except Exception as e:
                logger.warning("[arm_activity] Request failed for sub %s: %s", sub_id[:8], e)
                continue

            events = data.get('value', [])
            raw_event_count = len(events)
            logger.info("[arm_activity] Sub %s: %d raw events before filtering",
                        sub_id[:8], raw_event_count)

            # Per-identity event counters to limit to 5 per identity per subscription
            identity_event_counts = {}
            noise_skipped = 0
            matched_count = 0
            unmatched_callers = []

            for evt in events:
                # ── 1. Extract claims (may be str in some API versions) ──
                claims = evt.get('claims') or {}
                if isinstance(claims, str):
                    try:
                        claims = json.loads(claims)
                    except Exception:
                        claims = {}

                # ── 2. Extract IP FIRST — claims.ipaddr has real human IPs ──
                ip_addr = None
                if isinstance(claims, dict):
                    ip_addr = claims.get('ipaddr')
                if not ip_addr:
                    ip_addr = evt.get('callerIpAddress')

                # ── 3. Extract operation name ──
                op_name_raw = evt.get('operationName', {})
                if isinstance(op_name_raw, dict):
                    op_name = op_name_raw.get('localizedValue') or op_name_raw.get('value', '')
                else:
                    op_name = str(op_name_raw)

                # ── 4. Operation noise filter (skip platform ops + read/list) ──
                if any(op_name.startswith(pfx) for pfx in self._ARM_SKIP_OPERATION_PREFIXES):
                    noise_skipped += 1
                    continue
                # Read/list operations never prove privilege exercise
                op_lower = op_name.lower()
                if any(op_lower.endswith(sfx) for sfx in self._ARM_NOISE_SUFFIXES):
                    noise_skipped += 1
                    continue

                # ── 5. Extract caller + OID from claims ──
                caller = evt.get('caller', '')
                oid_from_claims = ''
                if isinstance(claims, dict):
                    oid_from_claims = (
                        claims.get('oid')
                        or claims.get('http://schemas.microsoft.com/identity/claims/objectidentifier')
                        or ''
                    )

                # Skip only if BOTH caller AND ip are empty (pure system noise)
                if not caller and not ip_addr:
                    continue

                # ── 6. Caller matching: direct → lowercase → claims.oid ──
                identity_db_id = (
                    pid_map.get(caller)
                    or (pid_map.get(caller.lower()) if caller else None)
                    or (pid_map.get(oid_from_claims) if oid_from_claims else None)
                )
                if not identity_db_id:
                    if len(unmatched_callers) < 10:
                        unmatched_callers.append(caller or oid_from_claims or '(empty)')
                    continue

                matched_count += 1

                # Limit events per identity
                count = identity_event_counts.get(identity_db_id, 0)
                if count >= 5:
                    continue
                identity_event_counts[identity_db_id] = count + 1

                status_raw = evt.get('status', {})
                if isinstance(status_raw, dict):
                    status_val = status_raw.get('localizedValue') or status_raw.get('value', '')
                else:
                    status_val = str(status_raw)

                # Only successful operations count as meaningful role exercise
                if status_val and status_val.lower() not in ('succeeded', 'accepted', 'started', 'success', ''):
                    noise_skipped += 1
                    continue

                resource_id = evt.get('resourceId', '')
                resource_type_raw = evt.get('resourceType', {})
                if isinstance(resource_type_raw, dict):
                    resource_type = resource_type_raw.get('value', '')
                else:
                    resource_type = str(resource_type_raw) if resource_type_raw else ''

                event_ts = evt.get('eventTimestamp')

                all_events.append({
                    'identity_db_id': identity_db_id,
                    'principal_id': caller,
                    'event_timestamp': event_ts,
                    'caller_ip_address': ip_addr,
                    'operation_name': op_name,
                    'resource_id': resource_id,
                    'resource_type': resource_type,
                    'subscription_id': sub_id,
                    'status': status_val,
                })

                # Track best (most recent) event per (principal, resource_id) for scope-aware role updates
                key = (caller, resource_id or sub_id)
                if key not in role_updates or event_ts > role_updates[key]['last_used_at']:
                    role_updates[key] = {
                        'principal_id': caller,
                        'subscription_id': sub_id,
                        'resource_id': resource_id or f'/subscriptions/{sub_id}',
                        'last_used_at': event_ts,
                        'last_used_operation': op_name,
                    }

            # ── Diagnostic logging per subscription ──
            logger.info("[arm_activity] Sub %s: %d after noise filter (%d skipped), %d matched to %d identities",
                        sub_id[:8], raw_event_count - noise_skipped, noise_skipped,
                        matched_count, len(identity_event_counts))
            if matched_count == 0 and raw_event_count > 0:
                logger.warning("[arm_activity] Sub %s: 0 matches — sample unmatched callers: %s",
                               sub_id[:8], unmatched_callers[:5])
                logger.warning("[arm_activity] Sub %s: sample caller_map keys: %s",
                               sub_id[:8], list(pid_map.keys())[:10])

        # Batch-insert into identity_arm_connections
        if all_events:
            try:
                inserted = self.db.save_arm_connections_batch(
                    self.db_org_id, run_id, all_events
                )
                logger.info("[arm_activity] Stored %d ARM connection events for %d identities",
                            inserted, len({e['identity_db_id'] for e in all_events}))
            except Exception as e:
                logger.warning("[arm_activity] Failed to save ARM connections: %s", e)
                try:
                    self.db._rollback()
                except Exception:
                    pass

        # Update role_assignments.last_used_at from ARM events
        if role_updates:
            try:
                updated = self.db.update_role_last_used_from_arm(
                    self.db_org_id, list(role_updates.values())
                )
                logger.info("[arm_activity] Updated last_used_at on %d role assignments", updated)
            except Exception as e:
                logger.warning("[arm_activity] Failed to update role last_used_at: %s", e)
                try:
                    self.db._rollback()
                except Exception:
                    pass

        # Update identities.last_observed_ip from ARM events (most recent per identity WITH IP)
        best_per_identity_ip = {}
        for evt in all_events:
            iid = evt['identity_db_id']
            if evt.get('caller_ip_address') and (
                iid not in best_per_identity_ip or evt['event_timestamp'] > best_per_identity_ip[iid]['event_timestamp']
            ):
                best_per_identity_ip[iid] = evt

        # AG-147: Most recent ARM event per identity (regardless of IP) for last_activity_date
        best_per_identity_all = {}
        for evt in all_events:
            iid = evt['identity_db_id']
            if iid not in best_per_identity_all or evt['event_timestamp'] > best_per_identity_all[iid]['event_timestamp']:
                best_per_identity_all[iid] = evt

        cursor = self.db.conn.cursor()

        # IP enrichment (only events with caller_ip_address)
        if best_per_identity_ip:
            for iid, evt in best_per_identity_ip.items():
                try:
                    cursor.execute("""
                        UPDATE identities SET
                            last_observed_ip = %s,
                            last_observed_ip_source = 'arm_activity_log',
                            last_observed_ip_date = %s,
                            last_observed_operation = %s
                        WHERE id = %s AND (last_observed_ip IS NULL OR last_observed_ip_date < %s)
                    """, (
                        evt['caller_ip_address'],
                        evt['event_timestamp'],
                        evt['operation_name'],
                        iid,
                        evt['event_timestamp'],
                    ))
                except Exception as e:
                    logger.debug("[arm_activity] IP update failed for id=%s: %s", iid, e)
                    try:
                        self.db.conn.rollback()
                    except Exception:
                        pass

        # Commit IP updates before starting activity updates
        try:
            self.db._commit()
        except Exception:
            pass

        # ── AG-147 Fix 3: ARM activity → last_activity_date waterfall ──
        # ARM events prove actual API calls (high confidence). Update
        # last_activity_date if the ARM event is more recent than whatever
        # the initial waterfall computed. Uses ALL events (not just those with IPs).
        if best_per_identity_all:
            arm_activity_updated = 0
            for iid, evt in best_per_identity_all.items():
                try:
                    cursor.execute("""
                        UPDATE identities SET
                            last_activity_date = %s,
                            last_activity_source = 'arm_activity_log',
                            last_activity_confidence = 'high'
                        WHERE id = %s
                          AND (last_activity_date IS NULL OR last_activity_date < %s::timestamptz)
                    """, (
                        evt['event_timestamp'],
                        iid,
                        evt['event_timestamp'],
                    ))
                    if cursor.rowcount > 0:
                        arm_activity_updated += 1
                except Exception as e:
                    logger.debug("[arm_activity] last_activity_date update failed for id=%s: %s", iid, e)
                    try:
                        self.db.conn.rollback()
                    except Exception:
                        pass
            logger.info("[arm_activity] Updated last_activity_date on %d/%d identities from ARM events",
                        arm_activity_updated, len(best_per_identity_all))

        try:
            self.db._commit()
        except Exception:
            pass
        cursor.close()

        elapsed = _time.monotonic() - phase_start
        logger.info("[arm_activity] COMPLETE: %d events, %d role updates, %.1fs",
                    len(all_events), len(role_updates), elapsed)

    async def _fetch_last_observed_ips(self, identities: List[Dict]) -> None:
        """Fetch last observed IP from ARM Activity Log for all identities.

        ARM Activity Log is free (no P2 license required), 90-day retention.
        Falls back to directory audit log for identities with no ARM activity.
        Runs as a batch enrichment pass after _check_activity().
        """
        import os
        if os.environ.get('DISABLE_IP_ENRICHMENT', 'false').lower() == 'true':
            logger.info("[ip_enrichment] SKIPPED via env flag")
            return

        import aiohttp
        import asyncio as _asyncio
        import time as _time
        from urllib.parse import quote

        phase_start = _time.monotonic()
        MAX_PHASE_SECONDS = int(os.environ.get('IP_ENRICHMENT_MAX_SECONDS', '120'))
        MAX_IDENTITIES_PROCESSED = int(os.environ.get('IP_ENRICHMENT_MAX_IDENTITIES', '300'))
        processed = 0
        enriched = 0
        skipped_ms = 0
        skipped_no_id = 0

        sub_ids = [s['id'] for s in self.subscriptions]
        if not sub_ids:
            logger.debug("No subscriptions — skipping ARM activity IP enrichment")
            return

        # AG-147: Use same configurable lookback as _collect_arm_activity
        arm_lookback_days = int(os.environ.get('ARM_ACTIVITY_LOOKBACK_DAYS', '90'))
        cutoff = (datetime.utcnow() - timedelta(days=arm_lookback_days)).strftime('%Y-%m-%dT%H:%M:%SZ')

        # Get ARM token for Activity Log API
        try:
            arm_token = self.credential.get_token("https://management.azure.com/.default")
            arm_headers = {"Authorization": f"Bearer {arm_token.token}"}
        except Exception as e:
            logger.debug("ARM token acquisition failed — skipping IP enrichment: %s", e)
            return

        # Get Graph token for directory audit fallback
        try:
            graph_token = self.credential.get_token("https://graph.microsoft.com/.default")
            graph_headers = {"Authorization": f"Bearer {graph_token.token}"}
        except Exception as e:
            logger.debug("Graph token acquisition failed for audit fallback: %s", e)
            graph_headers = None

        scanner_client_id = getattr(self, 'client_id', None)
        scanner_ip = getattr(self, '_scanner_ip', None)

        # ── Helper: try ARM Activity Log across subscriptions ──
        async def _try_arm(session, identity, principal_id):
            for sub_id in sub_ids:
                try:
                    filter_str = (
                        f"eventTimestamp ge '{cutoff}'"
                        f" and caller eq '{principal_id}'"
                    )
                    url = (
                        f"https://management.azure.com"
                        f"/subscriptions/{sub_id}"
                        f"/providers/microsoft.insights"
                        f"/eventtypes/management/values"
                        f"?api-version=2015-04-01"
                        f"&$filter={quote(filter_str)}"
                        f"&$select=caller,callerIpAddress,eventTimestamp,operationName"
                        f"&$top=1"
                        f"&$orderby=eventTimestamp desc"
                    )
                    async with session.get(url, headers=arm_headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            events = data.get('value', [])
                            if events and events[0].get('callerIpAddress'):
                                event = events[0]
                                op_name = event.get('operationName')
                                if isinstance(op_name, dict):
                                    op_name = op_name.get('localizedValue') or op_name.get('value')
                                identity['last_observed_ip'] = event['callerIpAddress']
                                identity['last_observed_ip_source'] = 'arm_activity_log'
                                identity['last_observed_ip_date'] = event.get('eventTimestamp')
                                identity['last_observed_operation'] = op_name
                                return True
                except Exception as e:
                    status_code = getattr(e, 'status', None) or getattr(getattr(e, 'response', None), 'status', None)
                    if status_code == 403:
                        logger.warning("ARM Activity Log: PERMISSION DENIED for subscription %s. Identity: %s", sub_id, principal_id)
                    elif status_code == 429:
                        logger.warning("ARM Activity Log: RATE LIMITED for %s in %s.", principal_id, sub_id)
                    elif status_code == 404:
                        logger.warning("ARM Activity Log: NOT FOUND for subscription %s.", sub_id)
                    else:
                        logger.warning("ARM Activity Log: fetch failed for %s in %s. Error: %s", principal_id, sub_id, e)
                await _asyncio.sleep(0.05)
            return False

        # ── Helper: try Graph directory audit log (has IP, no P2 needed) ──
        # Directory audit retention: 30 days for free/P1, 30 days for P2
        # Graph API rejects activityDateTime older than retention window
        audit_cutoff = (datetime.utcnow() - timedelta(days=29)).strftime('%Y-%m-%dT%H:%M:%SZ')

        async def _try_directory_audit(session, identity, principal_id):
            if not graph_headers:
                return False
            app_id = identity.get('app_id')
            try:
                if app_id:
                    filter_clause = f"initiatedBy/app/appId eq '{app_id}'"
                else:
                    filter_clause = f"initiatedBy/user/id eq '{principal_id}'"
                full_filter = f"{filter_clause} and activityDateTime ge {audit_cutoff}"
                audit_url = (
                    f"https://graph.microsoft.com/v1.0"
                    f"/auditLogs/directoryAudits"
                    f"?$filter={quote(full_filter)}"
                    f"&$top=1"
                    f"&$orderby=activityDateTime desc"
                    f"&$select=activityDateTime,initiatedBy,operationType"
                )
                for attempt in range(3):
                    async with session.get(audit_url, headers=graph_headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            audits = data.get('value', [])
                            if audits:
                                initiated_by = audits[0].get('initiatedBy', {})
                                ip = (
                                    initiated_by.get('user', {}).get('ipAddress')
                                    or initiated_by.get('app', {}).get('ipAddress')
                                )
                                if ip:
                                    identity['last_observed_ip'] = ip
                                    identity['last_observed_ip_source'] = 'directory_audit_log'
                                    identity['last_observed_ip_date'] = audits[0].get('activityDateTime')
                                    identity['last_observed_operation'] = audits[0].get('operationType')
                                    return True
                            return False
                        elif resp.status == 429:
                            # Rate limited — exponential backoff
                            retry_after = int(resp.headers.get('Retry-After', 2 ** (attempt + 1)))
                            await _asyncio.sleep(min(retry_after, 10))
                            continue
                        elif resp.status == 403:
                            logger.warning("Directory audit: PERMISSION DENIED (AuditLog.Read.All required)")
                            return False
                        else:
                            return False
            except Exception as e:
                logger.warning("Directory audit log query failed for %s: %s", principal_id, e)
            await _asyncio.sleep(0.1)
            return False

        # ── Main enrichment loop ──
        IP_ENRICHMENT_TIMEOUT = aiohttp.ClientTimeout(total=10, connect=5)
        async with aiohttp.ClientSession(timeout=IP_ENRICHMENT_TIMEOUT) as session:
            for identity in identities:
                processed += 1

                # Progress log every 50 identities
                if processed % 50 == 0:
                    elapsed = _time.monotonic() - phase_start
                    logger.info(
                        "[ip_enrichment] progress: processed=%d enriched=%d elapsed=%.1fs",
                        processed, enriched, elapsed
                    )

                # Phase budget check
                elapsed = _time.monotonic() - phase_start
                if elapsed > MAX_PHASE_SECONDS:
                    logger.warning(
                        "[ip_enrichment] TIME BUDGET EXCEEDED at %.1fs — "
                        "enriched %d/%d identities, skipping remainder",
                        elapsed, enriched, processed
                    )
                    break
                if processed >= MAX_IDENTITIES_PROCESSED:
                    logger.warning(
                        "[ip_enrichment] IDENTITY CAP REACHED (%d) — "
                        "enriched %d identities, skipping remainder",
                        MAX_IDENTITIES_PROCESSED, enriched
                    )
                    break

                if identity.get('is_microsoft_system'):
                    skipped_ms += 1
                    continue
                principal_id = identity.get('object_id') or identity.get('principal_id')
                if not principal_id:
                    skipped_no_id += 1
                    continue

                # Scanner self-IP: assign to the discovery SPN (we know our own IP)
                if scanner_client_id and scanner_ip and identity.get('app_id') == scanner_client_id:
                    identity['last_observed_ip'] = scanner_ip
                    identity['last_observed_ip_source'] = 'scanner_self'
                    identity['last_observed_ip_date'] = datetime.utcnow().isoformat() + 'Z'
                    identity['last_observed_operation'] = 'AuditGraph discovery scan'
                    enriched += 1
                    continue

                is_human = identity.get('identity_category') in ('human_user', 'guest')

                if is_human:
                    # Humans: directory audit first (portal/directory ops include IP)
                    if await _try_directory_audit(session, identity, principal_id):
                        enriched += 1
                        continue
                    # Fallback: ARM Activity Log (if they did write operations)
                    if await _try_arm(session, identity, principal_id):
                        enriched += 1
                        continue
                else:
                    # SPNs/managed identities: ARM Activity Log first (write operations)
                    if await _try_arm(session, identity, principal_id):
                        enriched += 1
                        continue
                    # Fallback: directory audit log
                    if await _try_directory_audit(session, identity, principal_id):
                        enriched += 1
                        continue

        elapsed = _time.monotonic() - phase_start
        logger.info(
            "[ip_enrichment] COMPLETE: processed=%d enriched=%d "
            "skipped_ms=%d skipped_no_id=%d elapsed=%.1fs",
            processed, enriched, skipped_ms, skipped_no_id, elapsed
        )

    # ── Background IP Enrichment (post-scan) ─────────────────────────────

    @classmethod
    async def enrich_ips_background(
        cls,
        azure_directory_id: str,
        client_id: str,
        client_secret: str,
        db_org_id: int,
        run_id: int,
        subscription_ids: list = None,
    ):
        """Background job: enrich identities with last observed IP from ARM Activity Log.

        Runs AFTER scan completes. Queries identity object_ids from the DB,
        calls ARM Activity Log + Directory Audit Log APIs in parallel (semaphore-throttled),
        then batch-updates the identities table with IP fields.
        """
        import aiohttp
        import asyncio as _asyncio
        import time as _bg_time
        import json
        import os
        from azure.identity import ClientSecretCredential
        from app.database import Database

        if os.environ.get('DISABLE_IP_ENRICHMENT', 'false').lower() == 'true':
            logger.info("[ip_enrichment_bg] SKIPPED via env flag")
            return

        _start = _bg_time.monotonic()
        logger.info("[ip_enrichment_bg] START org=%s run=%s", db_org_id, run_id)

        # Get credential
        credential = ClientSecretCredential(
            tenant_id=azure_directory_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        client_secret = None  # AG-116: zero after SDK init

        # Get ARM token
        try:
            arm_token = credential.get_token("https://management.azure.com/.default")
            arm_headers = {"Authorization": f"Bearer {arm_token.token}"}
        except Exception as e:
            logger.warning("[ip_enrichment_bg] ARM token failed: %s", e)
            return

        # Get Graph token for directory audit fallback
        try:
            graph_token = credential.get_token("https://graph.microsoft.com/.default")
            graph_headers = {"Authorization": f"Bearer {graph_token.token}"}
        except Exception as e:
            logger.warning("[ip_enrichment_bg] Graph token failed (audit fallback unavailable): %s", e)
            graph_headers = None

        # Fetch identities from the latest run (non-Microsoft only)
        db = Database()
        try:
            cursor = db.conn.cursor()
            cursor.execute("""
                SELECT id, identity_id, identity_category, app_id
                FROM identities
                WHERE discovery_run_id = %s
                  AND COALESCE(is_microsoft_system, false) = false
                  AND identity_id IS NOT NULL
            """, (run_id,))
            rows = cursor.fetchall()
            cursor.close()
        except Exception as e:
            logger.error("[ip_enrichment_bg] DB query failed: %s", e)
            db.close()
            return
        finally:
            try:
                db.conn.rollback()
            except Exception:
                pass

        if not rows:
            logger.info("[ip_enrichment_bg] No identities found for run=%s", run_id)
            db.close()
            return

        # Get subscription IDs for ARM Activity Log queries
        if not subscription_ids:
            try:
                cursor = db.conn.cursor()
                cursor.execute("""
                    SELECT DISTINCT subscription_id FROM identity_subscription_access
                    WHERE discovery_run_id = %s AND subscription_id IS NOT NULL
                    LIMIT 20
                """, (run_id,))
                subscription_ids = [r[0] for r in cursor.fetchall()]
                cursor.close()
            except Exception:
                subscription_ids = []
            finally:
                try:
                    db.conn.rollback()
                except Exception:
                    pass

        if not subscription_ids:
            logger.warning("[ip_enrichment_bg] No subscriptions found — skipping ARM queries")

        logger.info("[ip_enrichment_bg] Processing %d identities, %d subscriptions, org=%s",
                    len(rows), len(subscription_ids), db_org_id)

        from datetime import datetime, timedelta
        from urllib.parse import quote
        import os as _os

        # AG-147: Use same configurable lookback as _collect_arm_activity
        arm_lookback_days = int(_os.environ.get('ARM_ACTIVITY_LOOKBACK_DAYS', '90'))
        cutoff = (datetime.utcnow() - timedelta(days=arm_lookback_days)).strftime('%Y-%m-%dT%H:%M:%SZ')
        audit_cutoff = (datetime.utcnow() - timedelta(days=29)).strftime('%Y-%m-%dT%H:%M:%SZ')

        sem = _asyncio.Semaphore(20)
        enriched = 0
        updates = []  # (db_id, ip, source, date, operation)

        async def _try_arm_bg(session, principal_id):
            """Try ARM Activity Log across subscriptions."""
            for sub_id in subscription_ids:
                try:
                    filter_str = (
                        f"eventTimestamp ge '{cutoff}'"
                        f" and caller eq '{principal_id}'"
                    )
                    url = (
                        f"https://management.azure.com"
                        f"/subscriptions/{sub_id}"
                        f"/providers/microsoft.insights"
                        f"/eventtypes/management/values"
                        f"?api-version=2015-04-01"
                        f"&$filter={quote(filter_str)}"
                        f"&$select=caller,callerIpAddress,eventTimestamp,operationName"
                        f"&$top=1"
                        f"&$orderby=eventTimestamp desc"
                    )
                    async with session.get(url, headers=arm_headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            events = data.get('value', [])
                            if events and events[0].get('callerIpAddress'):
                                event = events[0]
                                op_name = event.get('operationName')
                                if isinstance(op_name, dict):
                                    op_name = op_name.get('localizedValue') or op_name.get('value')
                                return (event['callerIpAddress'], 'arm_activity_log',
                                        event.get('eventTimestamp'), op_name)
                except Exception:
                    pass
                await _asyncio.sleep(0.02)
            return None

        async def _try_audit_bg(session, principal_id, app_id, is_human):
            """Try Graph directory audit log."""
            if not graph_headers:
                return None
            try:
                if not is_human and app_id:
                    filter_clause = f"initiatedBy/app/appId eq '{app_id}'"
                else:
                    filter_clause = f"initiatedBy/user/id eq '{principal_id}'"
                full_filter = f"{filter_clause} and activityDateTime ge {audit_cutoff}"
                audit_url = (
                    f"https://graph.microsoft.com/v1.0"
                    f"/auditLogs/directoryAudits"
                    f"?$filter={quote(full_filter)}"
                    f"&$top=1"
                    f"&$orderby=activityDateTime desc"
                    f"&$select=activityDateTime,initiatedBy,operationType"
                )
                for attempt in range(2):
                    async with session.get(audit_url, headers=graph_headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            audits = data.get('value', [])
                            if audits:
                                initiated_by = audits[0].get('initiatedBy', {})
                                ip = (
                                    initiated_by.get('user', {}).get('ipAddress')
                                    or initiated_by.get('app', {}).get('ipAddress')
                                )
                                if ip:
                                    return (ip, 'directory_audit_log',
                                            audits[0].get('activityDateTime'),
                                            audits[0].get('operationType'))
                            return None
                        elif resp.status == 429:
                            retry_after = int(resp.headers.get('Retry-After', 2 ** (attempt + 1)))
                            await _asyncio.sleep(min(retry_after, 10))
                            continue
                        else:
                            return None
            except Exception:
                pass
            return None

        async def _enrich_one(session, db_id, principal_id, category, app_id):
            nonlocal enriched
            async with sem:
                is_human = category in ('human_user', 'guest')
                result = None

                if is_human:
                    result = await _try_audit_bg(session, principal_id, app_id, True)
                    if not result and subscription_ids:
                        result = await _try_arm_bg(session, principal_id)
                else:
                    if subscription_ids:
                        result = await _try_arm_bg(session, principal_id)
                    if not result:
                        result = await _try_audit_bg(session, principal_id, app_id, False)

                if result:
                    updates.append((db_id, result[0], result[1], result[2], result[3]))
                    enriched += 1

        IP_TIMEOUT = aiohttp.ClientTimeout(total=10, connect=5)
        async with aiohttp.ClientSession(timeout=IP_TIMEOUT) as session:
            tasks = [
                _enrich_one(session, row[0], row[1], row[2], row[3])
                for row in rows
            ]
            await _asyncio.gather(*tasks, return_exceptions=True)

        # Batch update identities table
        update_count = 0
        try:
            cursor = db.conn.cursor()
            for (db_id, ip, source, ip_date, operation) in updates:
                try:
                    cursor.execute("""
                        UPDATE identities SET
                            last_observed_ip = %s,
                            last_observed_ip_source = %s,
                            last_observed_ip_date = %s,
                            last_observed_operation = %s
                        WHERE id = %s
                    """, (ip, source, ip_date, operation, db_id))
                    update_count += 1
                except Exception as e:
                    logger.debug("[ip_enrichment_bg] Update failed for id=%s: %s", db_id, e)
                    try:
                        db.conn.rollback()
                    except Exception:
                        pass
            db.conn.commit()
            cursor.close()
        except Exception as e:
            logger.error("[ip_enrichment_bg] Batch update failed: %s", e)
            try:
                db.conn.rollback()
            except Exception:
                pass

        db.close()
        _elapsed = round(_bg_time.monotonic() - _start, 1)
        logger.info(
            "[ip_enrichment_bg] DONE in %.1fs: %d/%d identities enriched, %d DB updates org=%s",
            _elapsed, enriched, len(rows), update_count, db_org_id,
        )

    # ── Background Sign-in Intelligence (post-scan) ────────────────────

    @classmethod
    async def enrich_signin_intelligence_background(
        cls,
        azure_directory_id: str,
        client_id: str,
        client_secret: str,
        db_org_id: int,
        run_id: int,
        cloud_connection_id: int = None,
    ):
        """Background job: enrich SPN identities with sign-in intelligence from Graph API.

        Runs AFTER scan completes. Queries SPN object_ids from the DB,
        calls Graph auditLogs/signIns in parallel (semaphore-throttled),
        then batch-updates the identities table with signin fields.
        """
        import aiohttp
        import asyncio as _asyncio
        import time as _bg_time
        import json
        import os
        from azure.identity import ClientSecretCredential
        from app.database import Database
        from urllib.parse import quote

        if os.environ.get('DISABLE_SIGNIN_INTELLIGENCE', 'false').lower() == 'true':
            logger.info("[signin_intel_bg] SKIPPED via env flag")
            return

        # 6-hour cache check
        if cloud_connection_id:
            db_check = Database()
            try:
                cache_key = f'signin_intelligence_last_run_{cloud_connection_id}'
                last_run = db_check.get_setting(cache_key, None, organization_id=db_org_id)
                if last_run:
                    from datetime import datetime
                    last_dt = datetime.fromisoformat(last_run.replace('Z', '+00:00').replace('+00:00', ''))
                    if (datetime.utcnow() - last_dt).total_seconds() < 6 * 3600:
                        logger.info("[signin_intel_bg] cached (last run %s) — skipping", last_run)
                        db_check.close()
                        return
            except Exception:
                pass
            finally:
                db_check.close()

        _start = _bg_time.monotonic()
        logger.info("[signin_intel_bg] START org=%s run=%s", db_org_id, run_id)

        credential = ClientSecretCredential(
            tenant_id=azure_directory_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        client_secret = None  # AG-116: zero after SDK init

        try:
            graph_token = credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {graph_token.token}"}
        except Exception as e:
            logger.warning("[signin_intel_bg] Graph token failed: %s", e)
            return

        # Fetch SPN identities from the latest run
        db = Database()
        try:
            cursor = db.conn.cursor()
            cursor.execute("""
                SELECT id, identity_id, object_id
                FROM identities
                WHERE discovery_run_id = %s
                  AND identity_category IN ('service_principal', 'managed_identity_user', 'managed_identity_system')
                  AND COALESCE(is_microsoft_system, false) = false
                  AND identity_id IS NOT NULL
            """, (run_id,))
            rows = cursor.fetchall()
            cursor.close()
        except Exception as e:
            logger.error("[signin_intel_bg] DB query failed: %s", e)
            db.close()
            return
        finally:
            try:
                db.conn.rollback()
            except Exception:
                pass

        if not rows:
            logger.info("[signin_intel_bg] No SPN identities for run=%s", run_id)
            db.close()
            return

        logger.info("[signin_intel_bg] Processing %d SPNs org=%s", len(rows), db_org_id)

        from datetime import datetime, timedelta
        thirty_days_ago = (datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%dT00:00:00Z')
        select_fields = 'createdDateTime,resourceDisplayName,ipAddress,location,clientAppUsed,status,servicePrincipalId'

        sem = _asyncio.Semaphore(20)
        enriched = 0
        updates = []  # (db_id, signin_ips, signin_resources, signin_locations, signin_client_apps, fail, success, total)

        async def _fetch_signins(session, db_id, obj_id):
            nonlocal enriched
            async with sem:
                try:
                    filter_str = (
                        f"servicePrincipalId eq '{obj_id}' "
                        f"and createdDateTime ge {thirty_days_ago}"
                    )
                    url = (
                        f"https://graph.microsoft.com/v1.0/auditLogs/signIns"
                        f"?$filter={quote(filter_str)}&$top=999"
                        f"&$orderby=createdDateTime desc&$select={select_fields}"
                    )
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 403:
                            return  # signIns API not available
                        if resp.status == 429:
                            retry_after = int(resp.headers.get('Retry-After', '5'))
                            await _asyncio.sleep(min(retry_after, 30))
                            return
                        if resp.status != 200:
                            return
                        data = await resp.json()
                        sign_ins = data.get('value', [])
                        if not sign_ins:
                            return

                    # Process sign-in data
                    ips, resources, locations, client_apps = {}, {}, {}, {}
                    failures, successes = 0, 0
                    for si in sign_ins:
                        ip = si.get('ipAddress')
                        if ip:
                            if ip not in ips:
                                ips[ip] = {'ip': ip, 'classification': cls._classify_ip(ip), 'count': 0}
                            ips[ip]['count'] += 1
                        res = si.get('resourceDisplayName')
                        if res:
                            if res not in resources:
                                resources[res] = {'name': res, 'count': 0}
                            resources[res]['count'] += 1
                        loc = si.get('location') or {}
                        city = loc.get('city') or ''
                        country = loc.get('countryOrRegion') or ''
                        loc_key = f"{city},{country}" if city or country else ''
                        if loc_key:
                            if loc_key not in locations:
                                locations[loc_key] = {'city': city, 'country': country, 'count': 0}
                            locations[loc_key]['count'] += 1
                        client = si.get('clientAppUsed') or ''
                        if client:
                            if client not in client_apps:
                                client_apps[client] = {'app': client, 'count': 0}
                            client_apps[client]['count'] += 1
                        status = si.get('status') or {}
                        error_code = status.get('errorCode', 0)
                        if error_code and error_code != 0:
                            failures += 1
                        else:
                            successes += 1

                    updates.append((
                        db_id,
                        json.dumps(list(ips.values())) if ips else None,
                        json.dumps(list(resources.values())) if resources else None,
                        json.dumps(list(locations.values())) if locations else None,
                        json.dumps(list(client_apps.values())) if client_apps else None,
                        failures, successes, len(sign_ins),
                    ))
                    enriched += 1
                except Exception as e:
                    logger.debug("[signin_intel_bg] Error for %s: %s", obj_id, e)

        SIGNIN_TIMEOUT = aiohttp.ClientTimeout(total=15, connect=5)
        async with aiohttp.ClientSession(timeout=SIGNIN_TIMEOUT) as session:
            tasks = [_fetch_signins(session, row[0], row[2]) for row in rows]
            await _asyncio.gather(*tasks, return_exceptions=True)

        # Batch update identities table
        update_count = 0
        try:
            cursor = db.conn.cursor()
            for (db_id, s_ips, s_res, s_loc, s_apps, fail, succ, total) in updates:
                try:
                    cursor.execute("""
                        UPDATE identities SET
                            signin_ips = %s,
                            signin_resources_accessed = %s,
                            signin_locations = %s,
                            signin_client_apps = %s,
                            signin_failure_count_30d = %s,
                            signin_success_count_30d = %s,
                            signin_total_events_30d = %s
                        WHERE id = %s
                    """, (s_ips, s_res, s_loc, s_apps, fail, succ, total, db_id))
                    update_count += 1
                except Exception as e:
                    logger.debug("[signin_intel_bg] Update failed for id=%s: %s", db_id, e)
                    try:
                        db.conn.rollback()
                    except Exception:
                        pass
            db.conn.commit()
            cursor.close()
        except Exception as e:
            logger.error("[signin_intel_bg] Batch update failed: %s", e)
            try:
                db.conn.rollback()
            except Exception:
                pass

        # Update cache timestamp
        if cloud_connection_id:
            try:
                cache_key = f'signin_intelligence_last_run_{cloud_connection_id}'
                db_cache = Database()
                try:
                    cur = db_cache.conn.cursor()
                    cur.execute("""
                        INSERT INTO settings (key, value, organization_id)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (key, organization_id) DO UPDATE SET value = EXCLUDED.value
                    """, (cache_key, datetime.utcnow().isoformat(), db_org_id))
                    db_cache.conn.commit()
                    cur.close()
                finally:
                    db_cache.close()
            except Exception:
                pass

        db.close()
        _elapsed = round(_bg_time.monotonic() - _start, 1)
        logger.info(
            "[signin_intel_bg] DONE in %.1fs: %d/%d SPNs enriched, %d DB updates org=%s",
            _elapsed, enriched, len(rows), update_count, db_org_id,
        )

    def _save_identities(self, run_id: int, identities: List[Dict], all_role_assignments: List[Dict], credentials_map: Dict[str, List[Dict]] = None, permissions_map: Dict[str, List[Dict]] = None, app_roles_map: Dict[str, List[Dict]] = None, ownership_map: Dict[str, List[Dict]] = None, pim_map: Dict[str, Dict] = None, ca_policies: List[Dict] = None) -> int:
        """Save all identities to database (customer-owned only, Microsoft system apps excluded at discovery)"""
        saved_count = 0

        # Phase 23: Enforce identity count limit based on organization plan
        # trial and pro: no identity limit (None). free: capped at max_identities.
        if self.db_org_id:
            try:
                from app.api.handlers import TIER_LIMITS
                cursor = self.db.conn.cursor()
                cursor.execute("SELECT plan FROM organizations WHERE id = %s", (self.db_org_id,))
                row = cursor.fetchone()
                cursor.close()
                if row:
                    plan = row[0] or 'free'
                    limits = TIER_LIMITS.get(plan, TIER_LIMITS['free'])
                    max_ids = limits.get('max_identities')
                    if max_ids is not None and len(identities) > max_ids:
                        # Prioritize humans/guests (security-critical), then by risk score.
                        # This prevents machine identities from consuming all cap slots.
                        _CAT_PRIORITY = {'human_user': 3, 'guest': 2}
                        identities.sort(
                            key=lambda x: (
                                _CAT_PRIORITY.get(x.get('identity_category', ''), 0),
                                x.get('risk_score', 0),
                            ),
                            reverse=True,
                        )
                        _humans = sum(1 for i in identities[:max_ids] if i.get('identity_category') in ('human_user', 'guest'))
                        logger.warning(
                            "Organization %s (%s plan): truncating %s identities to %s "
                            "(humans/guests kept: %s, sorted by category+risk)",
                            self.db_org_id, plan, len(identities), max_ids, _humans,
                        )
                        identities = identities[:max_ids]
                    else:
                        logger.info("Organization %s (%s plan): %s identities, limit=%s — no truncation",
                                    self.db_org_id, plan, len(identities), max_ids or 'unlimited')
            except Exception as e:
                logger.error("Entitlement check failed, proceeding without limit: %s", e)

        # Ensure clean transaction state before identity save loop.
        # Prior operations (job progress/metrics) may have left a poisoned
        # transaction; rollback clears it so the first identity isn't lost.
        try:
            self.db._rollback()
        except Exception:
            pass

        import time as _save_time
        _save_start = _save_time.monotonic()

        # Pre-fetch created_datetime from previous runs in one query (batch lookup)
        _prev_dates = {}
        _ids_needing_dates = [
            i.get('identity_id') for i in identities
            if not i.get('created_datetime') and not any(
                r.get('created_on') for r in i.get('roles', []) if r.get('created_on')
            )
        ]
        if _ids_needing_dates:
            try:
                from psycopg2.extras import execute_values as _exec_vals
                _date_cursor = self.db.conn.cursor()
                _date_cursor.execute("""
                    SELECT DISTINCT ON (i.identity_id)
                        i.identity_id, i.created_datetime
                    FROM identities i
                    JOIN discovery_runs dr ON dr.id = i.discovery_run_id
                    WHERE i.identity_id = ANY(%s)
                    AND i.created_datetime IS NOT NULL
                    AND dr.cloud_connection_id = %s
                    ORDER BY i.identity_id, i.discovery_run_id DESC
                """, (_ids_needing_dates, self.cloud_connection_id))
                for row in _date_cursor.fetchall():
                    _prev_dates[row[0]] = row[1]
                _date_cursor.close()
            except Exception as e:
                logger.warning("Batch date prefetch failed (non-blocking): %s", e)
                try:
                    self.db._rollback()
                except Exception:
                    pass

        for idx, identity in enumerate(identities):

            # Set source for multi-cloud
            identity['source'] = 'azure'
            if not identity.get('permission_plane'):
                identity['permission_plane'] = 'entra_id'

            # For SPNs without created_datetime, calculate from roles or previous runs
            if not identity.get('created_datetime'):
                # Try role assignment dates first
                role_dates = [r.get('created_on') for r in identity.get('roles', []) if r.get('created_on')]
                if role_dates:
                    identity['created_datetime'] = min(role_dates)
                elif identity.get('identity_id') in _prev_dates:
                    identity['created_datetime'] = _prev_dates[identity['identity_id']]
                else:
                    from datetime import datetime
                    identity['created_datetime'] = datetime.utcnow().isoformat()

            # ── AG-78: Compute privilege_tier from roles before persist ──
            if 'privilege_tier' not in identity:
                _roles = list(identity.get('roles', [])) + list(identity.get('entra_roles', []))
                _pt = 3
                _T0_ENTRA = {'global administrator', 'privileged role administrator',
                             'privileged authentication administrator', 'security operator',
                             'application administrator', 'cloud application administrator',
                             'hybrid identity administrator', 'domain name administrator',
                             'external identity provider administrator'}
                _T0_ARM = {'owner', 'user access administrator'}
                _T1_ENTRA = {'user administrator', 'exchange administrator',
                             'sharepoint administrator', 'teams administrator',
                             'intune administrator', 'conditional access administrator',
                             'authentication administrator', 'groups administrator',
                             'license administrator', 'password administrator',
                             'security administrator', 'compliance administrator',
                             'billing administrator', 'helpdesk administrator'}
                _T1_ARM = {'owner', 'contributor', 'user access administrator'}
                for r in _roles:
                    rn = (r.get('role_name') or '').lower()
                    rt = (r.get('role_type') or '').lower()
                    if rt == 'entra' and rn in _T0_ENTRA:
                        _pt = 0; break
                    st = (r.get('scope_type') or '').lower()
                    if rt == 'azure' and rn in _T0_ARM and st in ('subscription', 'tenant', ''):
                        _pt = 0; break
                if _pt > 0:
                    for r in _roles:
                        rn = (r.get('role_name') or '').lower()
                        rt = (r.get('role_type') or '').lower()
                        if rt == 'entra' and rn in _T1_ENTRA:
                            _pt = 1; break
                        if rt == 'azure' and rn in _T1_ARM:
                            _pt = 1; break
                if _pt > 1:
                    for r in _roles:
                        if (r.get('role_type') or '').lower() in ('entra', 'azure'):
                            _pt = 2; break
                identity['privilege_tier'] = f'T{_pt}'

            # ── Signal 11: Flag Microsoft first-party SPNs ──
            if 'is_microsoft_first_party' not in identity:
                from app.constants.identity_status import (
                    MICROSOFT_FIRST_PARTY_OWNER_IDS,
                    MICROSOFT_FIRST_PARTY_NAME_PREFIXES,
                )
                _owner_org = identity.get('app_owner_org_id') or ''
                _dname = identity.get('display_name') or ''
                identity['is_microsoft_first_party'] = (
                    _owner_org in MICROSOFT_FIRST_PARTY_OWNER_IDS
                    or any(_dname.startswith(p) for p in MICROSOFT_FIRST_PARTY_NAME_PREFIXES)
                )

            try:
                identity_db_id = self.db.save_identity(run_id, identity)
                identity['_db_id'] = identity_db_id
            except Exception as e:
                logger.error("save_identity FAILED for %s: %s", identity.get('display_name'), e)
                self.db._rollback()
                continue

            # Save resource→identity link for SAMIs with associated_resource_id
            if identity.get('associated_resource_id') and identity_db_id:
                try:
                    self.db.save_resource_identity_link(run_id, {
                        'resource_id': identity['associated_resource_id'],
                        'resource_type': identity.get('associated_resource_type', ''),
                        'resource_name': identity.get('associated_resource_name', ''),
                        'resource_group': identity.get('associated_resource_group'),
                        'subscription_id': identity.get('associated_subscription_id'),
                        'identity_db_id': identity_db_id,
                        'identity_id': identity.get('identity_id', ''),
                        'identity_display_name': identity.get('display_name', ''),
                        'link_type': 'system_assigned',
                    })
                except Exception as e:
                    logger.warning("save_resource_identity_link failed for %s: %s", identity.get('display_name'), e)

            # Save all per-identity metadata (roles, subs, entra, creds, permissions, PIM, etc.)
            # AG-151 FIX: Each section isolated so a failure in one doesn't skip the rest.
            try:
                # Save role assignments for this identity
                identity_roles = identity.get('roles', [])
                self._role_assignments_fetched += len(identity_roles)
                for role in identity_roles:
                    self.db.save_role_assignment(identity_db_id, role)
                    self._role_assignments_saved += 1
            except Exception as e:
                logger.error("save_role_assignments FAILED for %s: %s", identity.get('display_name'), e)
                try:
                    self.db._rollback()
                except Exception:
                    pass

            try:
                # Save identity ↔ subscription access (multi-subscription junction table)
                identity_roles = identity.get('roles', [])
                seen_sub_roles = set()
                for role in identity_roles:
                    sub_id_from_role = role.get('subscription_id')
                    if sub_id_from_role:
                        key = (sub_id_from_role, role.get('role_name', ''), role.get('scope', ''))
                        if key not in seen_sub_roles:
                            seen_sub_roles.add(key)
                            self.db.save_identity_subscription_access(
                                identity_db_id,
                                identity.get('identity_id', ''),
                                role,
                                sub_id_from_role,
                                role.get('subscription_name', ''),
                                run_id,
                            )
                # Compute primary subscription + additional count
                if seen_sub_roles:
                    self.db.update_identity_subscription_summary(identity_db_id)
            except Exception as e:
                logger.error("save_subscription_access FAILED for %s: %s", identity.get('display_name'), e)
                try:
                    self.db._rollback()
                except Exception:
                    pass

            # Save Entra ID role assignments for this identity (per-role resilience)
            identity_entra_roles = identity.get('entra_roles', [])
            _entra_saved = 0
            _entra_consecutive_failures = 0
            for entra_role in identity_entra_roles:
                try:
                    self.db.save_entra_role_assignment(identity_db_id, entra_role)
                    _entra_saved += 1
                    _entra_consecutive_failures = 0
                except Exception as _er:
                    _entra_consecutive_failures += 1
                    logger.warning(
                        "save_entra_role_assignment failed for %s role=%s: %s",
                        identity.get('display_name'), entra_role.get('role_name'), _er,
                    )
                    try:
                        self.db._rollback()
                    except Exception:
                        pass
                    if _entra_consecutive_failures >= 3 and _entra_saved == 0:
                        logger.error(
                            "Entra role save SYSTEMIC FAILURE — %d consecutive failures, "
                            "0 successes. Aborting Entra saves for %s.",
                            _entra_consecutive_failures, identity.get('display_name'),
                        )
                        break
            # Pipeline health: accumulate per-identity save metrics
            self._entra_roles_matched += len(identity_entra_roles)
            self._entra_roles_saved += _entra_saved
            self._entra_roles_failed += (len(identity_entra_roles) - _entra_saved)
            if identity_entra_roles and _entra_saved < len(identity_entra_roles):
                logger.warning(
                    "Entra role save partial: %d/%d saved for %s",
                    _entra_saved, len(identity_entra_roles), identity.get('display_name'),
                )

            try:
                # Save credentials for this identity (SPNs only)
                if credentials_map and identity.get('identity_id') in credentials_map:
                    credentials = credentials_map[identity.get('identity_id')]
                    self._credentials_fetched += len(credentials)
                    for credential in credentials:
                        self.db.save_credential(identity_db_id, credential)
                        self._credentials_saved += 1
                        # Also populate identity_credentials inventory
                        # (skip 'federated' — tracked in federated_credentials table)
                        _ic_type = credential.get('credential_type', '')
                        if _ic_type in ('secret', 'certificate', 'key', 'password', 'token'):
                            try:
                                self.db.save_identity_credential(
                                    org_id=self.db_org_id,
                                    connection_id=self.cloud_connection_id,
                                    identity_id=identity.get('identity_id', ''),
                                    credential_type=_ic_type,
                                    created_at=credential.get('start_datetime'),
                                    expires_at=credential.get('end_datetime'),
                                    metadata={
                                        'key_id': credential.get('key_id'),
                                        'display_name': credential.get('display_name'),
                                    },
                                )
                            except Exception as _ic_err:
                                logger.debug("save_identity_credential skipped: %s", _ic_err)
                                try:
                                    self.db._rollback()
                                except Exception:
                                    pass
                    self.db.update_identity_credential_summary(identity_db_id)
            except Exception as e:
                logger.error("save_credentials FAILED for %s: %s", identity.get('display_name'), e)
                try:
                    self.db._rollback()
                except Exception:
                    pass

            try:
                # Save API permissions for this identity (SPNs only)
                if permissions_map and identity.get('identity_id') in permissions_map:
                    permissions = permissions_map[identity.get('identity_id')]
                    self.db.store_graph_permissions(identity_db_id, permissions)

                # Save custom app roles for this identity (SPNs only)
                if app_roles_map and identity.get('identity_id') in app_roles_map:
                    app_roles = app_roles_map[identity.get('identity_id')]
                    self.db.store_app_roles(identity_db_id, app_roles)
            except Exception as e:
                logger.error("save_permissions_app_roles FAILED for %s: %s", identity.get('display_name'), e)
                try:
                    self.db._rollback()
                except Exception:
                    pass

            try:
                # Save ownership for this identity (SPNs only) — separate try to avoid
                # being blocked by permissions/app_roles ON CONFLICT failures
                if ownership_map and identity.get('identity_id') in ownership_map:
                    owners = ownership_map[identity.get('identity_id')]
                    self.db.store_ownership(identity_db_id, owners)
            except Exception as e:
                logger.error("save_ownership FAILED for %s: %s", identity.get('display_name'), e)
                try:
                    self.db._rollback()
                except Exception:
                    pass

            try:
                # Save PIM data for this identity (keyed by object_id)
                object_id = identity.get('object_id')
                if pim_map and object_id and object_id in pim_map:
                    pim_data = pim_map[object_id]
                    for eligible in pim_data.get('eligible', []):
                        self.db.save_pim_eligible(identity_db_id, eligible)
                    for activation in pim_data.get('activations', []):
                        self.db.save_pim_activation(identity_db_id, activation)
                    self.db.update_identity_pim_summary(identity_db_id)
            except Exception as e:
                logger.error("save_pim FAILED for %s: %s", identity.get('display_name'), e)
                try:
                    self.db._rollback()
                except Exception:
                    pass

            saved_count += 1

        # Explicit commit after all identities saved
        try:
            self.db.conn.commit()
        except Exception:
            pass
        _save_elapsed = round(_save_time.monotonic() - _save_start, 1)
        logger.info(
            "Identity write complete: org=%s run=%s total=%s elapsed=%.1fs",
            self.db_org_id, run_id, saved_count, _save_elapsed,
        )

        # ── Post-save: recompute activity_status from actual DB values ──
        # Fixes Signal 10 drift: ensures activity_status matches the
        # authoritative last_sign_in / enabled columns after upsert.
        # Preserves multi-signal intelligence (likely_active, recently_created)
        # for identities that have no sign-in data.
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                UPDATE identities
                SET activity_status = CASE
                    WHEN enabled = FALSE THEN 'inactive'
                    WHEN last_sign_in IS NOT NULL
                         AND last_sign_in >= NOW() - INTERVAL '30 days'
                        THEN 'active'
                    WHEN last_sign_in IS NOT NULL
                         AND last_sign_in >= NOW() - INTERVAL '90 days'
                        THEN 'inactive'
                    WHEN last_sign_in IS NOT NULL
                        THEN 'stale'
                    WHEN last_sign_in IS NULL
                         AND activity_status NOT IN ('likely_active', 'recently_created')
                        THEN 'never_used'
                    ELSE activity_status
                END
                WHERE discovery_run_id = %s
            """, (run_id,))
            recomputed = cursor.rowcount
            self.db._commit()
            cursor.close()
            logger.info(
                "activity_status recomputed: org=%s run=%s rows=%s",
                self.db_org_id, run_id, recomputed,
            )
        except Exception as e:
            logger.warning("activity_status recompute failed: org=%s error=%s", self.db_org_id, e)
            try:
                self.db._rollback()
            except Exception:
                pass

        # ── Post-save: backfill is_microsoft_first_party for existing rows ──
        # Catches rows saved before the flag was added or identities that
        # didn't pass through the inline check above.
        try:
            from app.constants.identity_status import (
                MICROSOFT_FIRST_PARTY_OWNER_IDS,
                MICROSOFT_FIRST_PARTY_NAME_PREFIXES,
            )
            cursor = self.db.conn.cursor()
            cursor.execute("""
                UPDATE identities
                SET is_microsoft_first_party = TRUE
                WHERE discovery_run_id = %s
                  AND COALESCE(is_microsoft_first_party, FALSE) = FALSE
                  AND (
                      app_owner_org_id = ANY(%s)
                      OR display_name LIKE 'Microsoft %%'
                      OR display_name LIKE 'Agent (%%'
                      OR display_name LIKE 'Windows %%'
                  )
            """, (run_id, list(MICROSOFT_FIRST_PARTY_OWNER_IDS)))
            ms_fp_count = cursor.rowcount
            self.db._commit()
            cursor.close()
            if ms_fp_count:
                logger.info(
                    "is_microsoft_first_party backfill: org=%s run=%s rows=%s",
                    self.db_org_id, run_id, ms_fp_count,
                )
        except Exception as e:
            logger.warning("is_microsoft_first_party backfill failed: org=%s error=%s", self.db_org_id, e)
            try:
                self.db._rollback()
            except Exception:
                pass

        # ── Bulk reconciliation: backfill identity_list for any missed dual-writes ──
        try:
            logger.info("Reconciling identity_list: org=%s run=%s", self.db_org_id, run_id)
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT INTO identity_list (
                    organization_id, identity_id, global_identity_id,
                    display_name, identity_type, cloud_provider,
                    is_microsoft_system, governance, lifecycle_state,
                    privilege_level, risk_label, risk_score, last_seen,
                    identity_class
                )
                SELECT
                    %s,
                    i.identity_id,
                    md5(concat(%s, '|', i.identity_id))::uuid,
                    i.display_name,
                    CASE
                        WHEN i.identity_category = 'guest' THEN 'guest'
                        WHEN i.identity_category = 'human_user' THEN 'human_user'
                        WHEN i.identity_category IN ('managed_identity_system','managed_identity_user') THEN i.identity_category
                        ELSE 'service_principal'
                    END,
                    COALESCE(i.cloud, 'azure'),
                    COALESCE(i.is_microsoft_system, false),
                    CASE WHEN i.owner_count > 0 THEN 'Governed' ELSE 'Orphaned' END,
                    COALESCE(i.lifecycle_state, 'Active'),
                    'standard',
                    COALESCE(i.risk_level, 'low'),
                    COALESCE(i.risk_score, 0),
                    NOW(),
                    CASE
                        WHEN i.identity_category IN ('guest','guest_user','b2b_user') OR i.is_federated THEN 'EXTERNAL'
                        WHEN i.identity_category IN ('human_user','user','member') THEN 'HUMAN'
                        ELSE 'WORKLOAD'
                    END
                FROM identities i
                WHERE i.discovery_run_id = %s
                ON CONFLICT (organization_id, identity_id) DO UPDATE SET
                    display_name     = EXCLUDED.display_name,
                    identity_type    = EXCLUDED.identity_type,
                    is_microsoft_system = EXCLUDED.is_microsoft_system,
                    identity_class   = EXCLUDED.identity_class,
                    governance       = EXCLUDED.governance,
                    risk_label       = EXCLUDED.risk_label,
                    risk_score       = EXCLUDED.risk_score,
                    last_seen        = NOW()
            """, (self.db_org_id, str(self.db_org_id), run_id))
            il_count = cursor.rowcount
            self.db._commit()
            cursor.close()
            logger.info("identity_list reconciled: org=%s upserted=%s", self.db_org_id, il_count)
        except Exception as e:
            logger.error("identity_list reconciliation FAILED: org=%s error=%s", self.db_org_id, e)
            try:
                self.db._rollback()
            except Exception:
                pass

        # Save CA policies and compute coverage after all identities are saved
        try:
            if ca_policies:
                logger.info("Saving %s CA policies and computing coverage...", len(ca_policies))
                for policy in ca_policies:
                    self.db.save_ca_policy(run_id, policy)

                # Compute per-identity coverage
                ca_coverage_map = self._compute_ca_coverage(ca_policies, identities)
                if ca_coverage_map:
                    # Need to re-resolve identity_db_ids for coverage
                    cursor = self.db.conn.cursor()
                    cursor.execute(
                        "SELECT id, object_id FROM identities WHERE discovery_run_id = %s AND object_id IS NOT NULL",
                        (run_id,),
                    )
                    id_map = {row[1]: row[0] for row in cursor.fetchall()}
                    cursor.close()

                    for object_id, coverage in ca_coverage_map.items():
                        db_id = id_map.get(object_id)
                        if db_id:
                            self.db.save_ca_identity_coverage(db_id, coverage)

                    covered = sum(1 for c in ca_coverage_map.values() if c['coverage_status'] == 'covered')
                    logger.info("CA coverage computed: %s/%s identities covered", covered, len(ca_coverage_map))
        except Exception as e:
            logger.warning("CA policy save/coverage error: %s", e)
            self.db._rollback()

        # Post-discovery sweep: catch any Microsoft SPNs that slipped through detection
        try:
            self.db.sweep_microsoft_flag(run_id)
        except Exception as e:
            logger.warning("Microsoft flag sweep error: %s", e)
            self.db._rollback()

        return saved_count

    def _compute_workload_exposure(self, run_id):
        """Batch-compute exposure scores for all workload identities (SPNs, MIs, App Regs)."""
        from app.engines.risk.spn_risk_engine import WorkloadExposureEngine
        from psycopg2.extras import RealDictCursor as RDC

        engine = WorkloadExposureEngine()
        cursor = self.db.conn.cursor(cursor_factory=RDC)

        # ── Part 1: SPN + Managed Identity scoring ──────────────────
        cursor.execute("""
            SELECT i.id, i.identity_id, i.object_id, i.display_name, i.identity_category,
                   i.risk_level, i.risk_score, i.activity_status, i.last_sign_in,
                   i.created_datetime, i.service_principal_type, i.credential_risk,
                   i.ca_coverage_status, i.enabled, ar.sign_in_audience
            FROM identities i
            LEFT JOIN app_registrations ar
              ON ar.linked_spn_id = i.id AND ar.discovery_run_id = i.discovery_run_id
            WHERE i.discovery_run_id = %s
              AND i.identity_category IN ('service_principal', 'managed_identity_system', 'managed_identity_user')
              AND NOT COALESCE(i.is_microsoft_system, false)
        """, (run_id,))
        spn_rows = cursor.fetchall()

        roles_map = {}
        entra_map = {}
        creds_map = {}
        perms_map = {}
        owners_map = {}
        pim_map = {}

        if spn_rows:
            db_ids = [row['id'] for row in spn_rows]
            ph = ','.join(['%s'] * len(db_ids))

            # Batch-fetch roles
            cursor.execute(f"SELECT identity_db_id, role_name, scope_type, scope, created_on FROM role_assignments WHERE identity_db_id IN ({ph})", db_ids)
            for r in cursor.fetchall():
                roles_map.setdefault(r['identity_db_id'], []).append(dict(r))

            # Batch-fetch entra roles
            cursor.execute(f"SELECT identity_db_id, role_name, risk_level FROM entra_role_assignments WHERE identity_db_id IN ({ph})", db_ids)
            for r in cursor.fetchall():
                entra_map.setdefault(r['identity_db_id'], []).append(dict(r))

            # Batch-fetch credentials
            cursor.execute(f"SELECT identity_db_id, credential_type, start_datetime, end_datetime, display_name, key_id FROM credentials WHERE identity_db_id IN ({ph})", db_ids)
            for r in cursor.fetchall():
                creds_map.setdefault(r['identity_db_id'], []).append(dict(r))

            # Batch-fetch permissions
            cursor.execute(f"SELECT identity_db_id, permission_name, risk_level FROM graph_api_permissions WHERE identity_db_id IN ({ph})", db_ids)
            for r in cursor.fetchall():
                perms_map.setdefault(r['identity_db_id'], []).append(dict(r))

            # Batch-fetch owners
            cursor.execute(f"SELECT identity_db_id, owner_display_name, owner_upn FROM sp_ownership WHERE identity_db_id IN ({ph})", db_ids)
            for r in cursor.fetchall():
                owners_map.setdefault(r['identity_db_id'], []).append(dict(r))

            # Batch-fetch PIM data
            try:
                cursor.execute("SAVEPOINT pim_fetch")
                cursor.execute(f"SELECT identity_db_id, role_name, start_datetime FROM pim_eligible_assignments WHERE identity_db_id IN ({ph})", db_ids)
                for r in cursor.fetchall():
                    pim_map.setdefault(r['identity_db_id'], {'eligible': [], 'activations': []})
                    pim_map[r['identity_db_id']]['eligible'].append(dict(r))
                cursor.execute(f"SELECT identity_db_id, role_name, start_datetime FROM pim_activations WHERE identity_db_id IN ({ph})", db_ids)
                for r in cursor.fetchall():
                    pim_map.setdefault(r['identity_db_id'], {'eligible': [], 'activations': []})
                    pim_map[r['identity_db_id']]['activations'].append(dict(r))
                cursor.execute("RELEASE SAVEPOINT pim_fetch")
            except Exception:
                cursor.execute("ROLLBACK TO SAVEPOINT pim_fetch")

            # Batch-fetch P2 activity stats (if available)
            p2_stats_map = {}
            try:
                cursor.execute("SAVEPOINT p2_fetch")
                cursor.execute(f"""
                    SELECT identity_db_id, total_sign_ins, successful_sign_ins,
                           failed_sign_ins, unique_resources, unique_ips,
                           unique_locations, peak_hour, off_hours_pct,
                           avg_daily_sign_ins, risk_sign_ins, ca_failures
                    FROM workload_activity_stats
                    WHERE identity_db_id IN ({ph})
                    ORDER BY period_end DESC
                """, db_ids)
                for r in cursor.fetchall():
                    dbid = r['identity_db_id']
                    if dbid not in p2_stats_map:
                        p2_stats_map[dbid] = dict(r)
                cursor.execute("RELEASE SAVEPOINT p2_fetch")
            except Exception:
                cursor.execute("ROLLBACK TO SAVEPOINT p2_fetch")

        scored = 0
        critical_count = 0
        for row in (spn_rows or []):
            db_id = row['id']
            identity_data = dict(row)
            cat = (identity_data.get('identity_category') or '').lower()
            result = engine.compute_exposure(
                identity_data,
                roles_map.get(db_id, []),
                entra_map.get(db_id, []),
                creds_map.get(db_id, []),
                perms_map.get(db_id, []),
                owners_map.get(db_id, []),
                pim_map.get(db_id, {}),
                identity_type=cat,
                p2_stats=p2_stats_map.get(db_id),
            )
            self.db.save_spn_exposure(db_id, result, result.get('findings', []), run_id)
            scored += 1
            if result['scores']['total'] >= 80:
                critical_count += 1

        logger.info("Computed exposure for %s SPNs/MIs (%s critical)", scored, critical_count)

        # ── Part 2: App Registration scoring ─────────────────────────
        try:
            cursor.execute("SAVEPOINT appreg_fetch")
            cursor.execute("""
                SELECT id, app_id, display_name, sign_in_audience, owner_count,
                       owners, has_service_principal, linked_spn_id,
                       spn_last_sign_in, spn_activity_status, created_datetime,
                       high_risk_permissions, required_permissions,
                       application_permission_count, credential_details,
                       has_expired_credential, has_expiring_soon,
                       has_localhost_redirect, has_http_redirect
                FROM app_registrations
                WHERE discovery_run_id = %s
            """, (run_id,))
            app_reg_rows = cursor.fetchall()
            cursor.execute("RELEASE SAVEPOINT appreg_fetch")
        except Exception:
            cursor.execute("ROLLBACK TO SAVEPOINT appreg_fetch")
            app_reg_rows = []

        if app_reg_rows:
            # Build linked SPN lookup maps
            linked_spn_ids = set()
            for ar in app_reg_rows:
                if ar.get('linked_spn_id'):
                    linked_spn_ids.add(ar['linked_spn_id'])

            linked_roles_map = {}
            linked_entra_map = {}
            if linked_spn_ids:
                lph = ','.join(['%s'] * len(linked_spn_ids))
                lids = list(linked_spn_ids)
                cursor.execute(f"SELECT identity_db_id, role_name, scope_type, scope, created_on FROM role_assignments WHERE identity_db_id IN ({lph})", lids)
                for r in cursor.fetchall():
                    linked_roles_map.setdefault(r['identity_db_id'], []).append(dict(r))
                cursor.execute(f"SELECT identity_db_id, role_name, risk_level FROM entra_role_assignments WHERE identity_db_id IN ({lph})", lids)
                for r in cursor.fetchall():
                    linked_entra_map.setdefault(r['identity_db_id'], []).append(dict(r))

            ar_scored = 0
            ar_critical = 0
            for ar in app_reg_rows:
                ar_data = dict(ar)
                spn_id = ar_data.get('linked_spn_id')
                result = engine.compute_app_reg_exposure(
                    ar_data,
                    linked_spn_roles=linked_roles_map.get(spn_id, []) if spn_id else [],
                    linked_spn_entra_roles=linked_entra_map.get(spn_id, []) if spn_id else [],
                )
                self.db.save_app_reg_exposure(ar_data['id'], result, result.get('findings', []), run_id)
                ar_scored += 1
                if result['scores']['total'] >= 80:
                    ar_critical += 1

            logger.info("Computed exposure for %s App Registrations (%s critical)", ar_scored, ar_critical)

        cursor.close()

    def _create_result(self, identities: List[Dict], role_assignments: List[Dict], run_id: int) -> DiscoveryResult:
        service_principals = [i for i in identities if i['identity_type'] == 'service_principal']
        users = [i for i in identities if i['identity_type'] in ('human_user', 'guest')]
        managed_identities = [i for i in identities if i['identity_type'] == 'managed_identity']
        
        critical_count = sum(1 for i in identities if i['risk_level'] == 'critical')
        high_count = sum(1 for i in identities if i['risk_level'] == 'high')
        medium_count = sum(1 for i in identities if i['risk_level'] == 'medium')
        
        logger.info("Discovery Summary: Total Identities: %s (Service Principals: %s, Users: %s, Managed Identities: %s)",
                     len(identities), len(service_principals), len(users), len(managed_identities))
        logger.info("Risk Assessment: Critical: %s, High: %s, Medium: %s",
                     critical_count, high_count, medium_count)
        
        return DiscoveryResult(
            run_id=run_id,
            total_identities=len(identities),
            service_principals_count=len(service_principals),
            users_count=len(users),
            managed_identities_count=len(managed_identities),
            actionable_count=len(identities),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            identities=identities,
            role_assignments=role_assignments
        )
    
    # ──────────────────────────────────────────────────────────
    # App Registration Discovery (Phase 74)
    # ──────────────────────────────────────────────────────────

    async def _discover_app_registrations(self, spn_app_id_map: Dict[str, Dict]) -> List[Dict[str, Any]]:
        """Discover Entra ID App Registrations via Graph API."""
        try:
            results = []
            from msgraph.generated.applications.applications_request_builder import ApplicationsRequestBuilder
            from kiota_abstractions.base_request_configuration import RequestConfiguration

            query_params = ApplicationsRequestBuilder.ApplicationsRequestBuilderGetQueryParameters(
                top=999,
                select=['id', 'appId', 'displayName', 'createdDateTime',
                        'signInAudience', 'publisherDomain',
                        'appOwnerOrganizationId', 'requiredResourceAccess',
                        'passwordCredentials', 'keyCredentials',
                        'web']
            )
            request_config = RequestConfiguration(query_parameters=query_params)

            apps = await asyncio.wait_for(self.graph_client.applications.get(request_configuration=request_config), timeout=GRAPH_SDK_TIMEOUT)
            all_apps = []
            if apps and apps.value:
                all_apps.extend(apps.value)

            # Pagination
            next_link = getattr(apps, 'odata_next_link', None) if apps else None
            while next_link:
                try:
                    from msgraph.generated.applications.applications_request_builder import ApplicationsRequestBuilder as AB2
                    apps = await asyncio.wait_for(self.graph_client.applications.with_url(next_link).get(), timeout=GRAPH_SDK_TIMEOUT)
                    if apps and apps.value:
                        all_apps.extend(apps.value)
                    next_link = getattr(apps, 'odata_next_link', None) if apps else None
                except Exception:
                    break

            logger.info("Found %s app registrations", len(all_apps))

            now = datetime.utcnow()

            for app in all_apps:
                app_id = getattr(app, 'app_id', None) or ''
                object_id = getattr(app, 'id', None) or ''
                display_name = getattr(app, 'display_name', None) or 'Unknown'

                # Created
                created = None
                if hasattr(app, 'created_date_time') and app.created_date_time:
                    created = app.created_date_time.isoformat()

                # Sign-in audience
                audience = getattr(app, 'sign_in_audience', None) or ''
                publisher_domain = getattr(app, 'publisher_domain', None) or ''
                owner_org_id = getattr(app, 'app_owner_organization_id', None) or ''

                # Third-party check
                is_third_party = bool(owner_org_id and owner_org_id != self.azure_directory_id)

                # ── Permissions ──
                app_perm_count = 0
                delegated_perm_count = 0
                high_risk_list = []
                raw_perms = []

                rra = getattr(app, 'required_resource_access', None) or []
                for resource_access in rra:
                    resource_app_id = getattr(resource_access, 'resource_app_id', '') or ''
                    entries = getattr(resource_access, 'resource_access', None) or []
                    perm_list = []
                    for entry in entries:
                        perm_id = getattr(entry, 'id', '') or ''
                        perm_type = getattr(entry, 'type', '') or ''
                        perm_list.append({'id': str(perm_id), 'type': perm_type})
                        if perm_type == 'Role':
                            app_perm_count += 1
                            guid_str = str(perm_id)
                            if guid_str in HIGH_RISK_PERMISSION_GUIDS:
                                high_risk_list.append(HIGH_RISK_PERMISSION_GUIDS[guid_str])
                        elif perm_type == 'Scope':
                            delegated_perm_count += 1
                    raw_perms.append({
                        'resource_app_id': resource_app_id,
                        'permissions': perm_list,
                    })

                total_perms = app_perm_count + delegated_perm_count

                # ── Credentials ──
                secrets = getattr(app, 'password_credentials', None) or []
                certs = getattr(app, 'key_credentials', None) or []
                secret_count = len(secrets)
                cert_count = len(certs)
                cred_details = []
                next_expiry = None
                has_expired = False
                has_expiring_soon = False

                for cred in list(secrets) + list(certs):
                    cred_type = 'secret' if cred in secrets else 'certificate'
                    end_dt = getattr(cred, 'end_date_time', None)
                    start_dt = getattr(cred, 'start_date_time', None)
                    key_id = str(getattr(cred, 'key_id', '') or '')
                    cred_name = getattr(cred, 'display_name', None) or ''
                    end_iso = end_dt.isoformat() if end_dt else None
                    start_iso = start_dt.isoformat() if start_dt else None
                    cred_details.append({
                        'type': cred_type,
                        'key_id': key_id,
                        'display_name': cred_name,
                        'start': start_iso,
                        'end': end_iso,
                    })
                    if end_dt:
                        if end_dt.replace(tzinfo=None) < now:
                            has_expired = True
                        else:
                            days_left = (end_dt.replace(tzinfo=None) - now).days
                            if days_left <= 30:
                                has_expiring_soon = True
                            if next_expiry is None or end_dt < next_expiry:
                                next_expiry = end_dt

                next_expiry_iso = next_expiry.isoformat() if next_expiry else None

                # ── Redirect URIs ──
                web = getattr(app, 'web', None)
                redirect_uris_raw = []
                if web:
                    redirect_uris_raw = list(getattr(web, 'redirect_uris', None) or [])

                redirect_uri_count = len(redirect_uris_raw)
                has_localhost = any('localhost' in uri.lower() or '127.0.0.1' in uri for uri in redirect_uris_raw)
                has_http = any(uri.lower().startswith('http://') and 'localhost' not in uri.lower() and '127.0.0.1' not in uri for uri in redirect_uris_raw)

                # ── Owners ──
                owners_list = []
                try:
                    owners_resp = await asyncio.wait_for(self.graph_client.applications.by_application_id(object_id).owners.get(), timeout=GRAPH_SDK_TIMEOUT)
                    if owners_resp and owners_resp.value:
                        for o in owners_resp.value:
                            owners_list.append({
                                'object_id': getattr(o, 'id', '') or '',
                                'display_name': getattr(o, 'display_name', '') or '',
                                'upn': getattr(o, 'user_principal_name', '') or '',
                                'type': getattr(o, 'odata_type', '') or '',
                            })
                except Exception:
                    pass

                owner_count = len(owners_list)
                primary_owner = owners_list[0]['display_name'] if owners_list else None

                # ── SPN cross-link ──
                spn_info = spn_app_id_map.get(app_id, {})
                has_spn = bool(spn_info)
                linked_spn_id = spn_info.get('id')
                spn_last_sign_in = spn_info.get('last_sign_in')
                spn_activity = spn_info.get('activity_status')

                # ── Risk scoring ──
                risk_score, risk_reasons = self._compute_app_registration_risk(
                    owner_count=owner_count,
                    audience=audience,
                    app_perm_count=app_perm_count,
                    high_risk_list=high_risk_list,
                    has_expired=has_expired,
                    has_expiring_soon=has_expiring_soon,
                    is_third_party=is_third_party,
                    has_localhost=has_localhost,
                    has_http=has_http,
                    has_spn=has_spn,
                    spn_activity=spn_activity,
                )
                if risk_score >= 80:
                    risk_level = 'critical'
                elif risk_score >= 50:
                    risk_level = 'high'
                elif risk_score >= 25:
                    risk_level = 'medium'
                elif risk_score > 0:
                    risk_level = 'low'
                else:
                    risk_level = 'info'

                results.append({
                    'app_object_id': object_id,
                    'app_id': app_id,
                    'display_name': display_name,
                    'created_datetime': created,
                    'sign_in_audience': audience,
                    'publisher_domain': publisher_domain,
                    'app_owner_organization_id': owner_org_id,
                    'is_third_party': is_third_party,
                    'required_permissions': raw_perms,
                    'permission_count': total_perms,
                    'application_permission_count': app_perm_count,
                    'delegated_permission_count': delegated_perm_count,
                    'high_risk_permissions': high_risk_list,
                    'secret_count': secret_count,
                    'certificate_count': cert_count,
                    'credential_details': cred_details,
                    'next_expiry': next_expiry_iso,
                    'has_expired_credential': has_expired,
                    'has_expiring_soon': has_expiring_soon,
                    'owner_count': owner_count,
                    'owners': owners_list,
                    'primary_owner': primary_owner,
                    'has_service_principal': has_spn,
                    'linked_spn_id': linked_spn_id,
                    'spn_last_sign_in': spn_last_sign_in,
                    'spn_activity_status': spn_activity,
                    'redirect_uris': redirect_uris_raw,
                    'redirect_uri_count': redirect_uri_count,
                    'has_localhost_redirect': has_localhost,
                    'has_http_redirect': has_http,
                    'risk_level': risk_level,
                    'risk_score': risk_score,
                    'risk_reasons': risk_reasons,
                })

            return results
        except Exception as e:
            logger.error("App registration discovery failed: %s", e, exc_info=True)
            return []

    async def _discover_federated_credentials(self, run_id: int, app_regs: list, spn_app_id_map: dict) -> None:
        """AG-148: Discover federated identity credentials from application objects.

        Calls GET /applications/{object_id}/federatedIdentityCredentials for each
        app registration that has a linked SPN. Stores results in federated_credentials
        table and updates has_federated_credentials on the identity.

        Handles 403/404 gracefully — logs and skips without failing the run.
        """
        import time as _time
        phase_start = _time.monotonic()
        org_id = getattr(self, '_organization_id', None) or self.db_org_id

        if not app_regs:
            logger.debug("[federated_creds] No app registrations — skipping")
            return

        fetched = 0
        stored = 0
        errors = 0
        identities_updated = set()

        for ar in app_regs:
            app_object_id = ar.get('app_object_id')
            app_id = ar.get('app_id')
            linked_spn_db_id = None

            # Only fetch for apps that have a linked SPN
            spn_info = spn_app_id_map.get(app_id)
            if not spn_info:
                continue
            linked_spn_db_id = spn_info.get('id')
            if not linked_spn_db_id:
                continue

            # Time budget: 60s
            if _time.monotonic() - phase_start > 60:
                logger.warning("[federated_creds] Time budget exceeded — stopping")
                break

            try:
                fed_resp = await asyncio.wait_for(
                    self.graph_client.applications.by_application_id(app_object_id)
                    .federated_identity_credentials.get(),
                    timeout=GRAPH_SDK_TIMEOUT
                )
                if not fed_resp or not fed_resp.value:
                    continue

                fetched += 1
                issuer_types_for_identity = set()

                for fc in fed_resp.value:
                    cred_id = getattr(fc, 'id', '') or ''
                    name = getattr(fc, 'name', None) or ''
                    issuer = getattr(fc, 'issuer', '') or ''
                    subject = getattr(fc, 'subject', '') or ''
                    audiences = getattr(fc, 'audiences', None) or []
                    description = getattr(fc, 'description', None) or ''

                    issuer_type = _classify_issuer_type(issuer)
                    issuer_types_for_identity.add(issuer_type)

                    # Store in federated_credentials table
                    try:
                        cursor = self.db.conn.cursor()
                        cursor.execute("""
                            INSERT INTO federated_credentials
                            (organization_id, identity_db_id, identity_id, discovery_run_id,
                             credential_id, name, issuer, subject, audiences, issuer_type, description)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (organization_id, identity_id, credential_id, discovery_run_id)
                            DO UPDATE SET
                                name = EXCLUDED.name,
                                issuer = EXCLUDED.issuer,
                                subject = EXCLUDED.subject,
                                audiences = EXCLUDED.audiences,
                                issuer_type = EXCLUDED.issuer_type,
                                description = EXCLUDED.description,
                                discovered_at = NOW()
                        """, (
                            org_id, linked_spn_db_id, app_id, run_id,
                            cred_id, name, issuer, subject,
                            json.dumps(audiences) if audiences else '[]',
                            issuer_type, description,
                        ))
                        cursor.close()
                        stored += 1
                    except Exception as e:
                        logger.debug("[federated_creds] Insert failed for %s: %s", app_id, e)
                        try:
                            self.db.conn.rollback()
                        except Exception:
                            pass

                # Update the SPN identity record
                fed_count = len(fed_resp.value)
                if issuer_types_for_identity:
                    try:
                        cursor = self.db.conn.cursor()
                        cursor.execute("""
                            UPDATE identities SET
                                has_federated_credentials = TRUE,
                                federated_issuer_types = %s,
                                federated_cred_count = %s,
                                recommended_action = 'review_federated_dependencies'
                            WHERE id = %s
                        """, (
                            json.dumps(sorted(issuer_types_for_identity)),
                            fed_count,
                            linked_spn_db_id,
                        ))
                        cursor.close()
                        identities_updated.add(linked_spn_db_id)
                    except Exception as e:
                        logger.debug("[federated_creds] Identity update failed: %s", e)
                        try:
                            self.db.conn.rollback()
                        except Exception:
                            pass

            except Exception as e:
                err_str = str(e)
                # 403/404 are expected — skip gracefully
                if '403' in err_str or '404' in err_str or 'Forbidden' in err_str or 'NotFound' in err_str:
                    continue
                errors += 1
                if errors <= 3:
                    logger.debug("[federated_creds] Error for app %s: %s", app_object_id, e)
                continue

        # Commit all changes
        try:
            self.db._commit()
        except Exception:
            pass

        # AG-148: Fix verdict for identities that now have federated credentials.
        # The lineage verdict was computed before federated discovery, so identities
        # classified as UNUSED/ORPHANED need correction.
        if identities_updated:
            verdict_fixed = 0
            try:
                cursor = self.db.conn.cursor()
                for iid in identities_updated:
                    # Check current verdict — only fix UNUSED/ORPHANED/NEEDS_REVIEW
                    cursor.execute("""
                        SELECT recommended_action, last_activity_source
                        FROM identities WHERE id = %s
                    """, (iid,))
                    row = cursor.fetchone()
                    if not row:
                        continue
                    current_action, activity_src = row
                    if current_action in ('UNUSED', 'ORPHANED', 'NEEDS_REVIEW', 'STALE', 'AT_RISK',
                                          'FEDERATED_UNVERIFIED', 'ACTIVE_FEDERATED'):
                        new_action = 'review_federated_dependencies'
                        if activity_src and activity_src not in ('created_date', 'none', None):
                            new_text = ('Active federated identity. External pipeline dependency — '
                                        'review federated credentials before any action.')
                        else:
                            new_text = ('External pipeline dependency detected via federated credentials. '
                                        'Review federated credentials before any action.')
                        cursor.execute("""
                            UPDATE identities SET
                                recommended_action = %s,
                                verdict_action_text = %s,
                                verdict_confidence = 'high'
                            WHERE id = %s
                        """, (new_action, new_text, iid))
                        verdict_fixed += 1
                cursor.close()
                self.db._commit()
                if verdict_fixed:
                    logger.info("[federated_creds] Fixed verdicts for %d identities", verdict_fixed)
            except Exception as e:
                logger.debug("[federated_creds] Verdict fix error: %s", e)
                try:
                    self.db.conn.rollback()
                except Exception:
                    pass

        elapsed = _time.monotonic() - phase_start
        logger.info(
            "[federated_creds] Complete: %d apps with creds, %d credentials stored, "
            "%d identities updated, %d errors, %.1fs",
            fetched, stored, len(identities_updated), errors, elapsed
        )

    def _compute_app_registration_risk(self, owner_count, audience, app_perm_count,
                                        high_risk_list, has_expired, has_expiring_soon,
                                        is_third_party, has_localhost, has_http,
                                        has_spn, spn_activity):
        """Compute risk score for an app registration."""
        score = 0
        reasons = []

        if owner_count == 0:
            score += 40
            reasons.append('No owner — no accountability')
        if audience in ('AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount') and app_perm_count > 0:
            score += 30
            reasons.append(f'Multi-tenant with {app_perm_count} Application permissions')
        if has_expired:
            score += 25
            reasons.append('Has expired credentials')
        if app_perm_count > 5:
            score += 20
            reasons.append(f'{app_perm_count} Application-level permissions (excessive)')
        if is_third_party:
            score += 15
            reasons.append('Third-party publisher')
        if has_localhost:
            score += 15
            reasons.append('Localhost redirect URI (dev/test artifact)')
        if has_http:
            score += 15
            reasons.append('Non-HTTPS redirect URI')
        if has_spn and spn_activity in ('stale', 'never_used', 'inactive'):
            score += 10
            reasons.append(f'SPN is {spn_activity} — app may be abandoned')
        if len(high_risk_list) > 3:
            score += 10
            reasons.append(f'{len(high_risk_list)} high-risk permissions')
        if has_expiring_soon:
            score += 10
            reasons.append('Credentials expiring within 30 days')

        return score, reasons

    def _save_results_to_json(self, result: DiscoveryResult):
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"discovery_results_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump({
                'run_id': result.run_id,
                'timestamp': timestamp,
                'total_identities': result.total_identities,
                'service_principals': result.service_principals_count,
                'users': result.users_count,
                'managed_identities': result.managed_identities_count,
                'critical_risks': result.critical_count,
                'high_risks': result.high_count,
                'medium_risks': result.medium_count,
            }, f, indent=2, default=str)
        logger.info("Results saved to: %s", filename)


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    
    engine = AzureDiscoveryEngine(
        azure_directory_id=os.getenv('AZURE_TENANT_ID'),
        client_id=os.getenv('AZURE_CLIENT_ID'),
        client_secret=os.getenv('AZURE_CLIENT_SECRET')
    )
    
    result = engine.run_discovery()