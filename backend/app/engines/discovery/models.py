"""
Data Models for Azure Identity Discovery

This module defines the core data structures used throughout the AuditGraph
discovery and analysis pipeline. It includes dataclasses for identities,
role assignments, and discovery results, as well as enums for type safety.

Key Models:
    - Identity: Represents a discovered Azure identity (SPN, user, managed identity)
    - RoleAssignment: Represents an Azure RBAC role assignment
    - DiscoveryResult: Container for all discovery run results and statistics
    - IdentityType: Enum of identity types (service_principal, user, etc.)
    - RiskLevel: Enum of risk levels (critical, high, medium, low, info)

Microsoft System SPN Detection:
    The module includes logic to detect and filter Microsoft first-party
    service principals (like Microsoft Graph, Office 365) which are
    system-managed and should not be flagged as security risks.

    Detection is based on:
    - Known Microsoft app IDs (e.g., 00000003-0000-0000-c000-000000000000)
    - Display name patterns (starting with Microsoft, Azure, Office, etc.)

Risk Calculation:
    The Identity.calculate_risk() method evaluates:
    - Privilege level (Owner, Contributor, User Access Administrator)
    - Scope breadth (subscription vs resource group vs resource)
    - Credential expiration status
    - Activity status (orphaned identities with no assignments)
    - Microsoft system SPN status (not flagged as risks)
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict
from enum import Enum


# Microsoft System SPN Detection - Known first-party application IDs
MICROSOFT_SYSTEM_APPS = {
    # Common Microsoft first-party app IDs
    '00000003-0000-0000-c000-000000000000',  # Microsoft Graph
    '00000002-0000-0000-c000-000000000000',  # Azure AD Graph (deprecated)
    '797f4846-ba00-4fd7-ba43-dac1f8f63013',  # Windows Azure Service Management
    '00000007-0000-0000-c000-000000000000',  # Azure Key Vault
    '0000000c-0000-0000-c000-000000000000',  # Microsoft App Access Panel
}

MICROSOFT_DISPLAY_NAME_PATTERNS = [
    'Microsoft',
    'Office 365',
    'Office365',
    'Office',
    'Windows',
    'Azure',
    'Skype',
    'SharePoint',
    'Teams',
    'Exchange',
    'Dynamics',
    'Power',
    'Intune',
    'Substrate',
    'Conferencing',
    'Sway',
    'Bing',
    'Cortana',
    'Viva',
    'M365',
    'O365',
    'o365',
    'AAD',
    'MS',  # Matches MS-PIM, MS Teams, etc
    'Device Registration',
    'Messaging Bot',
    'Media Analysis',
    'Customer Experience',
    'Customer Service',
    'Signup',
    'OneProfile',
    'SubscriptionRP',
    'Common Data Service',
    'Portfolios',
    'ProductsLifecycle',
    'CAP',
    'CAB',
    'OMS',
    'OCaaS',
    'MCAPI',
    'Safelinks',
    'IC3',
    'IDS-PROD',
    'Graph Connector',
    'SPAuthEvent',
    'Request Approvals',
    'Policy Administration',
    'Narada',
    'WeveEngine',
    'Dataverse',
    'Billing RP',
    'IAM',
    'CloudLicensing',
    'IPSubstrate',
    'aciapi',
    'ESTS',
    'CompliancePolicy',
    'Configuration Manager',
    'ProjectWorkManagement',
    'PushChannel',
    'WindowsUpdate',
    'TenantSearchProcessors',
    'DeploymentScheduler',
    'Connectors',
    'Virtual Visits',
    'Conference Auto Attendant',
    'PPE-',
    'Privacy Management',
    'People Profile',
    'Group Configuration',
    'SalesInsights',
    'Meeting Migration',
]


def is_microsoft_system_spn(identity) -> bool:
    """
    Detect if an identity is a Microsoft system service principal
    
    Returns True if:
    - App ID is a known Microsoft first-party app
    - Display name starts with Microsoft/Office/Azure/etc
    """
    # Check if app_id matches known Microsoft apps
    if identity.app_id and identity.app_id in MICROSOFT_SYSTEM_APPS:
        return True
    
    # Check if display name indicates Microsoft service
    if identity.display_name:
        for pattern in MICROSOFT_DISPLAY_NAME_PATTERNS:
            if identity.display_name.startswith(pattern):
                return True
    
    return False


# ====================================================================
# Phase 78: Cloud-Agnostic Adapter Models
# ====================================================================

@dataclass
class CloudCredential:
    """Normalized credential across cloud providers."""
    provider: str  # azure, aws, gcp
    credential_type: str  # secret, certificate, access_key, service_account_key
    display_name: str = ''
    expiry: Optional[datetime] = None
    status: str = 'unknown'  # active, expired, expiring_soon, unknown
    created_at: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            'provider': self.provider,
            'credential_type': self.credential_type,
            'display_name': self.display_name,
            'expiry': self.expiry.isoformat() if self.expiry else None,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


@dataclass
class CloudRole:
    """Normalized role assignment across cloud providers."""
    provider: str  # azure, aws, gcp
    role_name: str
    scope: str = ''
    is_privileged: bool = False
    source: str = ''  # direct, inherited, group

    def to_dict(self) -> Dict:
        return {
            'provider': self.provider,
            'role_name': self.role_name,
            'scope': self.scope,
            'is_privileged': self.is_privileged,
            'source': self.source,
        }


@dataclass
class CloudIdentity:
    """Normalized identity across cloud providers."""
    provider: str  # azure, aws, gcp
    identity_type: str  # service_principal, iam_user, iam_role, service_account, etc.
    display_name: str
    external_id: str = ''  # provider-specific ID (object_id, ARN, email)
    risk_score: int = 0
    risk_level: str = 'info'
    credentials: List['CloudCredential'] = field(default_factory=list)
    roles: List['CloudRole'] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'provider': self.provider,
            'identity_type': self.identity_type,
            'display_name': self.display_name,
            'external_id': self.external_id,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'credentials': [c.to_dict() for c in self.credentials],
            'roles': [r.to_dict() for r in self.roles],
            'metadata': self.metadata,
        }


class IdentityType(Enum):
    """Types of identities in Azure"""
    SERVICE_PRINCIPAL = "service_principal"
    MANAGED_IDENTITY_SYSTEM = "managed_identity_system"
    MANAGED_IDENTITY_USER = "managed_identity_user"
    USER = "user"
    GROUP = "group"


class IdentityCategory(Enum):
    """Canonical identity categories used by the UI and database"""
    # Azure
    SERVICE_PRINCIPAL = "service_principal"
    MANAGED_IDENTITY_SYSTEM = "managed_identity_system"
    MANAGED_IDENTITY_USER = "managed_identity_user"
    HUMAN_USER = "human_user"
    GUEST = "guest"
    MICROSOFT_INTERNAL = "microsoft_internal"
    # AWS
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    IAM_SERVICE_LINKED_ROLE = "iam_service_linked_role"
    # GCP
    GCP_SERVICE_ACCOUNT = "gcp_service_account"
    GCP_USER = "gcp_user"
    GCP_GROUP = "gcp_group"
    GCP_DOMAIN = "gcp_domain"
    GCP_MEMBER = "gcp_member"
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    """Risk levels for identities"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


@dataclass
class RoleAssignment:
    """Represents an Azure RBAC role assignment"""
    role_name: str
    scope: str
    scope_type: str  # subscription, resource_group, resource
    principal_id: str
    principal_type: str
    assignment_id: str
    created_on: Optional[datetime] = None


@dataclass
class Identity:
    """Represents a discovered Azure identity"""
    id: str
    display_name: str
    identity_type: IdentityType
    app_id: Optional[str] = None
    object_id: Optional[str] = None
    created_datetime: Optional[datetime] = None
    
    # Role assignments
    role_assignments: List[RoleAssignment] = field(default_factory=list)
    
    # Risk assessment
    risk_level: RiskLevel = RiskLevel.INFO
    risk_reasons: List[str] = field(default_factory=list)
    
    # Additional metadata
    enabled: bool = True
    tags: Dict[str, str] = field(default_factory=dict)
    is_microsoft_system: bool = False  # NEW: Track if it's a Microsoft SPN
    
    # For service principals
    credential_expiration: Optional[datetime] = None
    credential_status: str = "unknown"  # unknown, good, warning, critical, expired
    last_sign_in: Optional[datetime] = None
    activity_status: str = "unknown"  # unknown, active, inactive, stale, never_used
    
    # For managed identities
    associated_resource_id: Optional[str] = None
    
    def add_role_assignment(self, role: RoleAssignment):
        """Add a role assignment to this identity"""
        self.role_assignments.append(role)
    
    def calculate_risk(self):
        """Calculate risk level based on permissions and status"""
        self.risk_reasons = []
        
        # Detect if this is a Microsoft system SPN
        if self.identity_type == IdentityType.SERVICE_PRINCIPAL:
            self.is_microsoft_system = is_microsoft_system_spn(self)
        
        # Check for overprivileged roles
        dangerous_roles = ['Owner', 'Contributor', 'User Access Administrator']
        
        for assignment in self.role_assignments:
            if assignment.role_name in dangerous_roles:
                if assignment.scope_type == 'subscription':
                    self.risk_level = RiskLevel.CRITICAL
                    self.risk_reasons.append(
                        f"{assignment.role_name} on subscription level"
                    )
                elif assignment.role_name == 'Owner':
                    self.risk_level = RiskLevel.HIGH
                    self.risk_reasons.append(
                        f"Owner role on {assignment.scope_type}"
                    )
        
        # Check for expired credentials
        if self.credential_status == 'expired':
            if self.risk_level == RiskLevel.INFO:
                self.risk_level = RiskLevel.MEDIUM
            self.risk_reasons.append("Has expired credentials")
        
        # Check for orphaned identities (no role assignments)
        # SMART FILTERING: Only flag custom SPNs as orphaned, not Microsoft system SPNs
        if len(self.role_assignments) == 0:
            # Only flag as risk if it's NOT a Microsoft system SPN
            if not self.is_microsoft_system:
                if self.risk_level == RiskLevel.INFO:
                    self.risk_level = RiskLevel.MEDIUM
                self.risk_reasons.append("No role assignments (orphaned custom identity)")
            # If it IS a Microsoft system SPN, keep it as INFO (not a risk)
        
        # Check for orphaned managed identities (no resource)
        if (self.identity_type in [IdentityType.MANAGED_IDENTITY_SYSTEM, 
                                    IdentityType.MANAGED_IDENTITY_USER] and 
            not self.associated_resource_id):
            if self.risk_level == RiskLevel.INFO:
                self.risk_level = RiskLevel.HIGH
            self.risk_reasons.append("Managed identity not attached to any resource")
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'display_name': self.display_name,
            'identity_type': self.identity_type.value,
            'app_id': self.app_id,
            'object_id': self.object_id,
            'created_datetime': self.created_datetime.isoformat() if self.created_datetime else None,
            'role_assignments': [
                {
                    'role_name': ra.role_name,
                    'scope': ra.scope,
                    'scope_type': ra.scope_type
                }
                for ra in self.role_assignments
            ],
            'risk_level': self.risk_level.value,
            'risk_reasons': self.risk_reasons,
            'enabled': self.enabled,
            'credential_status': self.credential_status,
            'associated_resource_id': self.associated_resource_id,
            'is_microsoft_system': self.is_microsoft_system  # NEW
        }


@dataclass
class DiscoveryResult:
    """Results from a discovery run"""
    subscription_id: str
    subscription_name: str
    discovered_at: datetime
    identities: List[Identity] = field(default_factory=list)
    
    # Statistics
    total_identities: int = 0
    service_principals: int = 0
    managed_identities: int = 0
    critical_risks: int = 0
    high_risks: int = 0
    medium_risks: int = 0
    microsoft_system_spns: int = 0  # NEW: Track Microsoft system SPNs
    custom_spns: int = 0  # NEW: Track custom SPNs
    
    def add_identity(self, identity: Identity):
        """Add an identity to the results"""
        self.identities.append(identity)
        self.total_identities += 1
        
        if identity.identity_type == IdentityType.SERVICE_PRINCIPAL:
            self.service_principals += 1
            # Track Microsoft vs custom SPNs
            if identity.is_microsoft_system:
                self.microsoft_system_spns += 1
            else:
                self.custom_spns += 1
        elif identity.identity_type in [IdentityType.MANAGED_IDENTITY_SYSTEM, 
                                        IdentityType.MANAGED_IDENTITY_USER]:
            self.managed_identities += 1
        
        if identity.risk_level == RiskLevel.CRITICAL:
            self.critical_risks += 1
        elif identity.risk_level == RiskLevel.HIGH:
            self.high_risks += 1
        elif identity.risk_level == RiskLevel.MEDIUM:
            self.medium_risks += 1
    
    def get_summary(self) -> Dict:
        """Get summary statistics"""
        return {
            'subscription_id': self.subscription_id,
            'subscription_name': self.subscription_name,
            'discovered_at': self.discovered_at.isoformat(),
            'statistics': {
                'total_identities': self.total_identities,
                'service_principals': self.service_principals,
                'managed_identities': self.managed_identities,
                'microsoft_system_spns': self.microsoft_system_spns,
                'custom_spns': self.custom_spns,
                'critical_risks': self.critical_risks,
                'high_risks': self.high_risks,
                'medium_risks': self.medium_risks
            }
        }
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            **self.get_summary(),
            'identities': [identity.to_dict() for identity in self.identities]
        }