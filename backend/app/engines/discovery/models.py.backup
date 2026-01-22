"""
Data models for discovered Azure identities
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict
from enum import Enum


class IdentityType(Enum):
    """Types of identities in Azure"""
    SERVICE_PRINCIPAL = "service_principal"
    MANAGED_IDENTITY_SYSTEM = "managed_identity_system"
    MANAGED_IDENTITY_USER = "managed_identity_user"
    USER = "user"
    GROUP = "group"


class RiskLevel(Enum):
    """Risk levels for identities"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RoleAssignment:
    """Represents an Azure RBAC role assignment"""
    role_name: str
    scope: str
    scope_type: str
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
    role_assignments: List[RoleAssignment] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.INFO
    risk_reasons: List[str] = field(default_factory=list)
    enabled: bool = True
    tags: Dict[str, str] = field(default_factory=dict)
    credential_expires: Optional[datetime] = None
    has_expired_credentials: bool = False
    associated_resource_id: Optional[str] = None
    
    def add_role_assignment(self, role: RoleAssignment):
        """Add a role assignment to this identity"""
        self.role_assignments.append(role)
    
    def calculate_risk(self):
        """Calculate risk level based on permissions and status"""
        self.risk_reasons = []
        dangerous_roles = ['Owner', 'Contributor', 'User Access Administrator']
        
        for assignment in self.role_assignments:
            if assignment.role_name in dangerous_roles:
                if assignment.scope_type == 'subscription':
                    self.risk_level = RiskLevel.CRITICAL
                    self.risk_reasons.append(f"{assignment.role_name} on subscription level")
                elif assignment.role_name == 'Owner':
                    self.risk_level = RiskLevel.HIGH
                    self.risk_reasons.append(f"Owner role on {assignment.scope_type}")
        
        if self.has_expired_credentials:
            if self.risk_level == RiskLevel.INFO:
                self.risk_level = RiskLevel.MEDIUM
            self.risk_reasons.append("Has expired credentials")
        
        if len(self.role_assignments) == 0:
            if self.risk_level == RiskLevel.INFO:
                self.risk_level = RiskLevel.MEDIUM
            self.risk_reasons.append("No role assignments (orphaned)")
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'display_name': self.display_name,
            'identity_type': self.identity_type.value,
            'app_id': self.app_id,
            'object_id': self.object_id,
            'role_assignments': [
                {'role_name': ra.role_name, 'scope': ra.scope, 'scope_type': ra.scope_type}
                for ra in self.role_assignments
            ],
            'risk_level': self.risk_level.value,
            'risk_reasons': self.risk_reasons,
        }


@dataclass
class DiscoveryResult:
    """Results from a discovery run"""
    subscription_id: str
    subscription_name: str
    discovered_at: datetime
    identities: List[Identity] = field(default_factory=list)
    total_identities: int = 0
    service_principals: int = 0
    managed_identities: int = 0
    critical_risks: int = 0
    high_risks: int = 0
    medium_risks: int = 0
    
    def add_identity(self, identity: Identity):
        """Add an identity to the results"""
        self.identities.append(identity)
        self.total_identities += 1
        
        if identity.identity_type == IdentityType.SERVICE_PRINCIPAL:
            self.service_principals += 1
        elif identity.identity_type in [IdentityType.MANAGED_IDENTITY_SYSTEM, IdentityType.MANAGED_IDENTITY_USER]:
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
