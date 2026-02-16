"""
Role Mining & Optimization Engine v2

Provides:
  - Capability mapping: Azure RBAC / Entra roles → capability tags
  - Toxic Combination detection: risk-based rules, scope overlap, single-identity
  - Evidence + Confidence model for unused classification
  - Improved bundle mining: pairs + larger sets with risk tags
  - Redundancy detection with scope-aware logic
  - Blast radius scoring with scope/prod/sensitivity modifiers
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
import hashlib
import json


# ─────────────────────────────────────────────────────────────
# § 1  CAPABILITY TAGS
# ─────────────────────────────────────────────────────────────

class Cap(str, Enum):
    """Capability tags that abstract individual role permissions."""
    IAM_WRITE = "IAM_WRITE"
    SECRETS_READ = "SECRETS_READ"
    SECRETS_WRITE = "SECRETS_WRITE"
    COMPUTE_MODIFY = "COMPUTE_MODIFY"
    DATA_READ = "DATA_READ"
    DATA_WRITE = "DATA_WRITE"
    NETWORK_MODIFY = "NETWORK_MODIFY"
    APP_CRED_WRITE = "APP_CRED_WRITE"
    POLICY_WRITE = "POLICY_WRITE"
    LOG_READ = "LOG_READ"
    USER_ADMIN = "USER_ADMIN"
    GROUP_ADMIN = "GROUP_ADMIN"


# Azure RBAC role → capabilities
AZURE_ROLE_CAPS: Dict[str, Set[Cap]] = {
    "owner": {Cap.IAM_WRITE, Cap.COMPUTE_MODIFY, Cap.DATA_READ, Cap.DATA_WRITE,
              Cap.NETWORK_MODIFY, Cap.SECRETS_READ, Cap.SECRETS_WRITE, Cap.POLICY_WRITE},
    "contributor": {Cap.COMPUTE_MODIFY, Cap.DATA_READ, Cap.DATA_WRITE,
                    Cap.NETWORK_MODIFY, Cap.SECRETS_READ, Cap.SECRETS_WRITE},
    "reader": {Cap.DATA_READ, Cap.LOG_READ},
    "user access administrator": {Cap.IAM_WRITE},
    "key vault administrator": {Cap.SECRETS_READ, Cap.SECRETS_WRITE},
    "key vault secrets officer": {Cap.SECRETS_READ, Cap.SECRETS_WRITE},
    "key vault secrets user": {Cap.SECRETS_READ},
    "key vault reader": {Cap.SECRETS_READ},
    "key vault crypto officer": {Cap.SECRETS_READ, Cap.SECRETS_WRITE},
    "storage blob data owner": {Cap.DATA_READ, Cap.DATA_WRITE, Cap.IAM_WRITE},
    "storage blob data contributor": {Cap.DATA_READ, Cap.DATA_WRITE},
    "storage blob data reader": {Cap.DATA_READ},
    "virtual machine contributor": {Cap.COMPUTE_MODIFY},
    "virtual machine administrator login": {Cap.COMPUTE_MODIFY},
    "network contributor": {Cap.NETWORK_MODIFY},
    "security admin": {Cap.POLICY_WRITE, Cap.LOG_READ},
    "security reader": {Cap.LOG_READ},
    "monitoring contributor": {Cap.LOG_READ},
    "managed identity operator": {Cap.IAM_WRITE, Cap.COMPUTE_MODIFY},
    "managed identity contributor": {Cap.IAM_WRITE},
    "logic app contributor": {Cap.COMPUTE_MODIFY},
    "automation contributor": {Cap.COMPUTE_MODIFY},
    "data factory contributor": {Cap.COMPUTE_MODIFY, Cap.DATA_READ, Cap.DATA_WRITE},
    "sql db contributor": {Cap.DATA_READ, Cap.DATA_WRITE},
    "sql server contributor": {Cap.DATA_READ, Cap.DATA_WRITE, Cap.NETWORK_MODIFY},
    "cosmos db account reader role": {Cap.DATA_READ},
    "documentdb account contributor": {Cap.DATA_READ, Cap.DATA_WRITE},
}

# Entra directory role → capabilities
ENTRA_ROLE_CAPS: Dict[str, Set[Cap]] = {
    "global administrator": {Cap.IAM_WRITE, Cap.USER_ADMIN, Cap.GROUP_ADMIN,
                             Cap.APP_CRED_WRITE, Cap.POLICY_WRITE, Cap.SECRETS_WRITE,
                             Cap.SECRETS_READ},
    "privileged role administrator": {Cap.IAM_WRITE, Cap.POLICY_WRITE},
    "application administrator": {Cap.APP_CRED_WRITE, Cap.SECRETS_WRITE},
    "cloud application administrator": {Cap.APP_CRED_WRITE, Cap.SECRETS_WRITE},
    "user administrator": {Cap.USER_ADMIN, Cap.GROUP_ADMIN},
    "groups administrator": {Cap.GROUP_ADMIN},
    "exchange administrator": {Cap.DATA_READ, Cap.DATA_WRITE, Cap.POLICY_WRITE},
    "security administrator": {Cap.POLICY_WRITE, Cap.LOG_READ},
    "security reader": {Cap.LOG_READ},
    "conditional access administrator": {Cap.POLICY_WRITE},
    "authentication administrator": {Cap.USER_ADMIN},
    "password administrator": {Cap.USER_ADMIN},
    "billing administrator": set(),
    "directory readers": {Cap.LOG_READ},
    "helpdesk administrator": {Cap.USER_ADMIN},
    "intune administrator": {Cap.COMPUTE_MODIFY, Cap.POLICY_WRITE},
    "sharepoint administrator": {Cap.DATA_READ, Cap.DATA_WRITE},
}


def caps_for_role(role_name: str, source: str) -> Set[Cap]:
    """Return capability set for a given role name and source."""
    key = role_name.lower().strip()
    if source == "entra":
        return ENTRA_ROLE_CAPS.get(key, set())
    return AZURE_ROLE_CAPS.get(key, set())


# ─────────────────────────────────────────────────────────────
# § 2  DATA MODELS
# ─────────────────────────────────────────────────────────────

@dataclass
class NormalizedRole:
    """Unified role assignment from any source."""
    identity_db_id: int
    identity_id: str
    identity_name: str
    identity_category: str
    source: str              # "azure" or "entra"
    role_name: str
    role_type: str           # "rbac", "entra", "custom"
    assignment_method: str   # "direct", "group", "inherited", "pim_eligible", "pim_active"
    scope_type: str          # "tenant", "subscription", "resource_group", "resource"
    scope_id: str
    scope_name: str
    assigned_at: Optional[datetime] = None
    days_since_assigned: Optional[int] = None
    capabilities: Set[Cap] = field(default_factory=set)
    usage_status: str = "unknown"
    redundant_with: Optional[str] = None
    risk_level: str = "unknown"
    why_critical: Optional[str] = None
    scope_exists: bool = True
    enabled: bool = True
    last_sign_in: Optional[datetime] = None

    def __post_init__(self):
        if not self.capabilities:
            self.capabilities = caps_for_role(self.role_name, self.source)


@dataclass
class Evidence:
    """Evidence for an unused / toxic finding."""
    last_activity_time: Optional[str] = None
    last_activity_source: Optional[str] = None
    evidence_count: int = 0
    window_days: int = 90
    confidence: str = "LOW"    # HIGH / MED / LOW
    detail: str = ""
    additional_sources: List[Dict] = field(default_factory=list)


@dataclass
class ToxicFinding:
    """A single toxic combination finding."""
    finding_id: str
    identity_id: str
    identity_name: str
    identity_category: str
    rule_id: str
    title: str
    category: str              # "privilege_escalation", "lateral_movement", "data_exfil", "god_mode"
    risk_score: int
    risk_level: str
    matched_roles: List[str]
    matched_capabilities: List[str]
    scope: str
    scope_type: str
    reasoning: str
    recommendation: str
    assignment_methods: List[str] = field(default_factory=list)
    blast_radius: str = "unknown"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BundleResult:
    """A common role bundle across identities."""
    roles: List[str]
    sources: List[str]
    identity_count: int
    identities: List[str]     # identity names
    capabilities: List[str]
    risk_tags: List[str]
    risk_level: str


@dataclass
class UnusedFinding:
    """Enhanced unused finding with evidence."""
    identity_id: str
    identity_name: str
    identity_category: str
    role_name: str
    source: str
    finding_type: str          # definitely_unused, likely_unused, potentially_unused
    risk_level: str
    scope: Optional[str]
    scope_type: str
    days_since_assigned: Optional[int]
    assignment_method: str
    recommendation: str
    evidence: Evidence
    blast_radius: str = "low"

    def to_dict(self) -> dict:
        d = asdict(self)
        d['evidence'] = asdict(self.evidence)
        return d


# ─────────────────────────────────────────────────────────────
# § 3  SCOPE OVERLAP LOGIC
# ─────────────────────────────────────────────────────────────

SCOPE_ORDER = {"tenant": 0, "management_group": 1, "subscription": 2,
               "resource_group": 3, "resource": 4}


def scopes_overlap(a_type: str, a_id: str, b_type: str, b_id: str) -> bool:
    """Return True if scope A and scope B overlap (same or one contains the other)."""
    a_ord = SCOPE_ORDER.get(a_type, 99)
    b_ord = SCOPE_ORDER.get(b_type, 99)

    # Tenant scope overlaps everything
    if a_type == "tenant" or b_type == "tenant":
        return True
    if a_id == b_id:
        return True

    # Broader scope contains narrower if narrower starts with broader path
    a_path = (a_id or "").lower().rstrip("/")
    b_path = (b_id or "").lower().rstrip("/")
    if a_ord < b_ord and b_path.startswith(a_path + "/"):
        return True
    if b_ord < a_ord and a_path.startswith(b_path + "/"):
        return True
    return False


def scope_label(scope_id: str, scope_type: str) -> str:
    """Short human-readable scope label."""
    if scope_type == "tenant" or scope_id in ("/", ""):
        return "Tenant-wide"
    parts = (scope_id or "").split("/")
    if scope_type == "subscription" and len(parts) >= 3:
        return f"Sub: ...{parts[2][-8:]}"
    if scope_type == "resource_group" and len(parts) >= 5:
        return f"RG: {parts[4]}"
    if len(parts) > 2:
        return f".../{parts[-1]}"
    return scope_id or "/"


# ─────────────────────────────────────────────────────────────
# § 4  BLAST RADIUS SCORING
# ─────────────────────────────────────────────────────────────

def blast_radius(scope_type: str, scope_id: str, role_name: str,
                 caps: Set[Cap], assignment_method: str = "direct") -> Tuple[str, int]:
    """
    Compute blast radius label + modifier.
    Bigger scope + more dangerous capabilities = higher blast.
    PIM-eligible roles get a discount (require activation to exercise).
    Returns: (label, modifier_points)
    """
    scope_pts = {"tenant": 40, "management_group": 35, "subscription": 25,
                 "resource_group": 10, "resource": 0}.get(scope_type, 0)

    danger_caps = {Cap.IAM_WRITE, Cap.SECRETS_WRITE, Cap.POLICY_WRITE,
                   Cap.APP_CRED_WRITE, Cap.USER_ADMIN}
    cap_pts = len(caps & danger_caps) * 8

    # Prod hint: scope names containing "prod" get a boost
    prod_boost = 10 if "prod" in (scope_id or "").lower() else 0

    # PIM-eligible roles require activation — lower immediate risk
    pim_discount = 15 if assignment_method in ("pim_eligible", "pim_eligible_group") else 0

    total = max(0, scope_pts + cap_pts + prod_boost - pim_discount)
    if total >= 50:
        return "critical", total
    if total >= 30:
        return "high", total
    if total >= 15:
        return "medium", total
    return "low", total


# ─────────────────────────────────────────────────────────────
# § 5  TOXIC COMBINATION ENGINE
# ─────────────────────────────────────────────────────────────

@dataclass
class ToxicRule:
    """Declarative toxic combination rule."""
    rule_id: str
    title: str
    category: str
    base_score: int
    base_level: str
    required_source: Optional[str]   # "azure", "entra", None=any
    # At least one of role_match / cap_match must be met
    role_match: Optional[List[Set[str]]]     # list of role-name sets (all must match)
    cap_match: Optional[List[Set[Cap]]]      # list of cap sets (all must match)
    reasoning: str
    recommendation: str


TOXIC_RULES: List[ToxicRule] = [
    ToxicRule(
        rule_id="TC-AZ-001",
        title="Owner + User Access Administrator",
        category="god_mode",
        base_score=95, base_level="critical",
        required_source=None,
        role_match=[{"owner"}, {"user access administrator"}],
        cap_match=None,
        reasoning="Owner provides full resource control; User Access Administrator can assign any role to anyone. Together they grant unconstrained tenant control — an attacker can give themselves any role and modify any resource.",
        recommendation="Remove User Access Administrator if Owner is required. If IAM delegation is needed, scope User Access Administrator to a single resource group and move Owner to PIM eligible-only.",
    ),
    ToxicRule(
        rule_id="TC-AZ-002",
        title="Contributor + IAM Write capability",
        category="privilege_escalation",
        base_score=90, base_level="critical",
        required_source=None,
        role_match=[{"contributor"}],
        cap_match=[{Cap.IAM_WRITE}],
        reasoning="Contributor can modify all resources but normally cannot grant roles. When combined with any IAM write capability, the identity can self-escalate by granting itself Owner or broader permissions.",
        recommendation="Remove the IAM write role. If the identity needs Contributor, ensure no co-assigned role grants roleAssignments/write. Consider a custom role with explicit denies.",
    ),
    ToxicRule(
        rule_id="TC-EN-001",
        title="Global Administrator + Privileged Role Administrator",
        category="god_mode",
        base_score=95, base_level="critical",
        required_source="entra",
        role_match=[{"global administrator"}, {"privileged role administrator"}],
        cap_match=None,
        reasoning="Global Admin already has full directory control. Privileged Role Admin adds the ability to re-assign any role — this means the identity can persist its own elevation and grant Global Admin to other identities, defeating PIM controls.",
        recommendation="Remove Privileged Role Administrator. If PIM administration is needed, use a dedicated break-glass identity with conditional access restrictions.",
    ),
    ToxicRule(
        rule_id="TC-EN-002",
        title="Global Administrator + Application Administrator",
        category="privilege_escalation",
        base_score=85, base_level="critical",
        required_source="entra",
        role_match=[{"global administrator"}, {"application administrator"}],
        cap_match=None,
        reasoning="Application Administrator can create app registrations and add credentials. Combined with Global Admin, an attacker can create a backdoor service principal with admin consent, establishing persistent access that survives password resets.",
        recommendation="Remove Application Administrator. Use Cloud Application Administrator for limited app management, or restrict via PIM with approval workflow.",
    ),
    ToxicRule(
        rule_id="TC-AZ-003",
        title="Compute Modify + Secrets Read",
        category="data_exfil",
        base_score=70, base_level="high",
        required_source=None,
        role_match=None,
        cap_match=[{Cap.COMPUTE_MODIFY}, {Cap.SECRETS_READ}],
        reasoning="Compute modify allows deploying/modifying VMs and functions; secrets read allows accessing Key Vault secrets and storage keys. An attacker can deploy malicious code that reads secrets and exfiltrates them.",
        recommendation="Separate compute management from secrets access. Use managed identities for applications needing secrets, with scoped Key Vault access policies.",
    ),
    ToxicRule(
        rule_id="TC-AZ-004",
        title="Data Read/Write + Secrets Read",
        category="data_exfil",
        base_score=65, base_level="high",
        required_source=None,
        role_match=None,
        cap_match=[{Cap.DATA_READ, Cap.SECRETS_READ}],
        reasoning="Data read/write access combined with secrets access creates a direct data exfiltration path. The identity can read storage account keys from Key Vault and use them to download all blob data.",
        recommendation="Remove the secrets read role if data access is the primary need. Use managed identity + RBAC for data access without needing Key Vault secrets.",
    ),
    ToxicRule(
        rule_id="TC-AZ-006",
        title="Network Modify + Compute Modify",
        category="lateral_movement",
        base_score=60, base_level="high",
        required_source=None,
        role_match=None,
        cap_match=[{Cap.NETWORK_MODIFY}, {Cap.COMPUTE_MODIFY}],
        reasoning="Network modify allows changing NSGs, route tables, and VPN gateways; compute modify allows deploying VMs. Together they enable an attacker to punch holes in network isolation and deploy rogue workloads in any subnet.",
        recommendation="Separate network administration from compute management into distinct identities. Use network contributor for network-only operations.",
    ),
    ToxicRule(
        rule_id="TC-AZ-007",
        title="Managed Identity Operator + Compute Modify",
        category="privilege_escalation",
        base_score=65, base_level="high",
        required_source=None,
        role_match=None,
        cap_match=[{Cap.IAM_WRITE, Cap.COMPUTE_MODIFY}],
        reasoning="Managed Identity Operator can assign managed identities to VMs; compute modify allows creating VMs. An attacker can create a VM, assign a privileged managed identity, and impersonate it from the VM's metadata endpoint.",
        recommendation="Remove Managed Identity Operator. If identity assignment is needed, scope it to a specific managed identity and restrict VM creation to approved images.",
    ),
]


class ToxicComboEngine:
    """Evaluate toxic combination rules against an identity's roles."""

    def __init__(self, window_days: int = 90):
        self.window_days = window_days

    def evaluate_identity(self, identity_roles: List[NormalizedRole]) -> List[ToxicFinding]:
        """Evaluate all toxic rules against a single identity's roles."""
        if not identity_roles:
            return []

        findings: List[ToxicFinding] = []
        first = identity_roles[0]
        identity_id = first.identity_id
        identity_name = first.identity_name
        identity_category = first.identity_category

        # Separate by source for source-specific rules
        azure_roles = [r for r in identity_roles if r.source == "azure"]
        entra_roles = [r for r in identity_roles if r.source == "entra"]

        for rule in TOXIC_RULES:
            matched = self._evaluate_rule(rule, identity_roles, azure_roles, entra_roles)
            if matched:
                matched_role_objs, scope_info = matched
                matched_role_names = [r.role_name for r in matched_role_objs]
                all_caps = set()
                for r in matched_role_objs:
                    all_caps |= r.capabilities
                methods = list(set(r.assignment_method for r in matched_role_objs))

                # Blast radius from broadest matching scope
                br_label, br_pts = "low", 0
                for r in matched_role_objs:
                    lbl, pts = blast_radius(r.scope_type, r.scope_id, r.role_name, r.capabilities,
                                            assignment_method=r.assignment_method)
                    if pts > br_pts:
                        br_label, br_pts = lbl, pts

                # Score = base + blast modifier
                final_score = min(100, rule.base_score + (br_pts // 5))
                final_level = rule.base_level
                if final_score >= 90:
                    final_level = "critical"
                elif final_score >= 70:
                    final_level = "high"

                fid = hashlib.md5(
                    f"{identity_id}:{rule.rule_id}:{','.join(sorted(matched_role_names))}".encode()
                ).hexdigest()[:12]

                findings.append(ToxicFinding(
                    finding_id=f"TF-{fid}",
                    identity_id=identity_id,
                    identity_name=identity_name,
                    identity_category=identity_category,
                    rule_id=rule.rule_id,
                    title=rule.title,
                    category=rule.category,
                    risk_score=final_score,
                    risk_level=final_level,
                    matched_roles=matched_role_names,
                    matched_capabilities=[c.value for c in all_caps],
                    scope=scope_info,
                    scope_type=matched_role_objs[0].scope_type,
                    reasoning=rule.reasoning,
                    recommendation=rule.recommendation,
                    assignment_methods=methods,
                    blast_radius=br_label,
                ))

        return findings

    def _evaluate_rule(self, rule: ToxicRule,
                       all_roles: List[NormalizedRole],
                       azure_roles: List[NormalizedRole],
                       entra_roles: List[NormalizedRole],
                       ) -> Optional[Tuple[List[NormalizedRole], str]]:
        """Check if a rule matches. Returns matched role objects + scope string, or None."""
        pool = all_roles
        if rule.required_source == "azure":
            pool = azure_roles
        elif rule.required_source == "entra":
            pool = entra_roles

        if not pool:
            return None

        # Role-name based matching
        if rule.role_match:
            matched_roles = []
            for required_set in rule.role_match:
                found = None
                for r in pool:
                    if r.role_name.lower().strip() in required_set:
                        found = r
                        break
                if not found:
                    return None
                matched_roles.append(found)

            # If rule ALSO requires cap_match, verify those too (AND logic)
            if rule.cap_match:
                already_matched_names = {r.role_name.lower() for r in matched_roles}
                remaining_pool = [r for r in pool if r.role_name.lower() not in already_matched_names]
                for required_caps in rule.cap_match:
                    found = None
                    for r in remaining_pool:
                        if required_caps <= r.capabilities:
                            found = r
                            break
                    if not found:
                        return None
                    matched_roles.append(found)

            # Check scope overlap for Azure RBAC pairs
            if len(matched_roles) >= 2 and any(r.source == "azure" for r in matched_roles):
                a, b = matched_roles[0], matched_roles[1]
                if not scopes_overlap(a.scope_type, a.scope_id, b.scope_type, b.scope_id):
                    return None

            scope_str = " + ".join(scope_label(r.scope_id, r.scope_type) for r in matched_roles)
            return matched_roles, scope_str

        # Capability-based matching (role_match is None, use cap_match)
        if rule.cap_match:
            # Each cap set must be covered by at least one role
            matched_roles = []
            for required_caps in rule.cap_match:
                found = None
                for r in pool:
                    if required_caps <= r.capabilities:
                        found = r
                        break
                if not found:
                    # Try combining across roles
                    combined = set()
                    combo = []
                    for r in pool:
                        overlap = required_caps & r.capabilities
                        if overlap:
                            combined |= overlap
                            combo.append(r)
                        if required_caps <= combined:
                            found = combo[0]  # representative
                            break
                    if not found:
                        return None
                matched_roles.append(found)

            # Deduplicate
            seen_ids = set()
            unique = []
            for r in matched_roles:
                key = (r.role_name, r.scope_id, r.source)
                if key not in seen_ids:
                    seen_ids.add(key)
                    unique.append(r)
            matched_roles = unique if len(unique) >= 2 else matched_roles

            # Must have at least 2 distinct roles for a "combination"
            role_names = set(r.role_name.lower() for r in matched_roles)
            if len(role_names) < 2:
                # Single role having both caps is not a toxic *combo*
                return None

            scope_str = " + ".join(scope_label(r.scope_id, r.scope_type) for r in matched_roles)
            return matched_roles, scope_str

        return None

    def evaluate_all(self, roles_by_identity: Dict[str, List[NormalizedRole]]) -> List[ToxicFinding]:
        """Evaluate all identities, return all toxic findings."""
        all_findings = []
        for ident_id, roles in roles_by_identity.items():
            all_findings.extend(self.evaluate_identity(roles))
        return all_findings


# ─────────────────────────────────────────────────────────────
# § 6  EVIDENCE & CONFIDENCE MODEL
# ─────────────────────────────────────────────────────────────

def compute_evidence(role: NormalizedRole, window_days: int = 90,
                     pim_activations: Optional[List[Dict]] = None) -> Evidence:
    """Build evidence + confidence for an unused role finding."""
    ev = Evidence(window_days=window_days)

    if not role.enabled:
        ev.confidence = "HIGH"
        ev.detail = "Identity is disabled — role cannot be exercised"
        ev.evidence_count = 1
        return ev

    if role.usage_status == "definitely_unused":
        ev.confidence = "HIGH"
        ev.detail = "Identity has never signed in or credentials are expired"
        ev.evidence_count = 1
        return ev

    # Check PIM activations — proves role was actually exercised
    if pim_activations:
        for act in pim_activations:
            ev.additional_sources.append({
                "source": "pim_activation",
                "time": act.get("activation_start"),
                "status": act.get("status", ""),
                "detail": f"PIM activation: {act.get('status', 'unknown')}",
            })
        ev.evidence_count += len(pim_activations)

        # Most recent activation
        latest = pim_activations[0]  # already sorted DESC
        latest_time = latest.get("activation_start")
        if latest_time and isinstance(latest_time, datetime):
            days_ago = (datetime.utcnow() - latest_time.replace(tzinfo=None)).days
            if days_ago <= window_days:
                ev.confidence = "HIGH"
                ev.last_activity_time = latest_time.isoformat()
                ev.last_activity_source = "pim_activation"
                ev.detail = f"PIM role activated {days_ago} days ago — role is USED"
                return ev

    if role.last_sign_in:
        ev.last_activity_time = role.last_sign_in.isoformat() if hasattr(role.last_sign_in, 'isoformat') else str(role.last_sign_in)
        ev.last_activity_source = "sign_in_logs"
        ev.evidence_count += 1

        if isinstance(role.last_sign_in, datetime):
            days_since = (datetime.utcnow() - role.last_sign_in.replace(tzinfo=None)).days
        else:
            days_since = 999

        if days_since > window_days:
            ev.confidence = "MED"
            ev.detail = f"No sign-in activity in {days_since} days (window: {window_days}d)"
        else:
            ev.confidence = "LOW"
            ev.detail = f"Last sign-in {days_since} days ago — may still be active"
        return ev

    # No sign-in data at all
    ev.confidence = "LOW"
    ev.detail = "No sign-in data available — cannot confirm unused"
    return ev


# ─────────────────────────────────────────────────────────────
# § 7  BUNDLE MINING
# ─────────────────────────────────────────────────────────────

RISK_CAP_COMBOS = {
    frozenset({Cap.SECRETS_READ, Cap.COMPUTE_MODIFY}): "Secrets + Compute (exfil risk)",
    frozenset({Cap.IAM_WRITE, Cap.COMPUTE_MODIFY}): "IAM + Compute (escalation risk)",
    frozenset({Cap.IAM_WRITE, Cap.SECRETS_WRITE}): "IAM + Secrets Write (persistence risk)",
    frozenset({Cap.DATA_WRITE, Cap.SECRETS_READ}): "Data Write + Secrets (exfil risk)",
    frozenset({Cap.NETWORK_MODIFY, Cap.COMPUTE_MODIFY}): "Network + Compute (lateral movement risk)",
    frozenset({Cap.APP_CRED_WRITE, Cap.IAM_WRITE}): "App Cred + IAM (backdoor risk)",
}


def mine_bundles(roles_by_identity: Dict[str, List[NormalizedRole]],
                 min_count: int = 2, max_bundle_size: int = 6) -> List[BundleResult]:
    """Mine common role bundles (pairs + larger sets) across identities."""
    # Step 1: Build identity → role-set mapping
    identity_role_sets: Dict[str, Set[str]] = {}
    identity_names: Dict[str, str] = {}
    role_sources: Dict[str, str] = {}

    for ident_id, roles in roles_by_identity.items():
        rset = set()
        for r in roles:
            key = f"{r.role_name}|{r.source}"
            rset.add(key)
            role_sources[key] = r.source
            identity_names[ident_id] = r.identity_name
        identity_role_sets[ident_id] = rset

    results: List[BundleResult] = []

    # Step 2: Pair mining (fast — O(n*r^2))
    pair_counts: Dict[Tuple[str, str], List[str]] = {}
    for ident_id, rset in identity_role_sets.items():
        sorted_roles = sorted(rset)
        for i in range(len(sorted_roles)):
            for j in range(i + 1, len(sorted_roles)):
                pair = (sorted_roles[i], sorted_roles[j])
                pair_counts.setdefault(pair, []).append(ident_id)

    for (ra, rb), idents in sorted(pair_counts.items(), key=lambda x: -len(x[1])):
        if len(idents) < min_count:
            continue
        role_a_name, role_a_src = ra.split("|", 1)
        role_b_name, role_b_src = rb.split("|", 1)
        caps_a = caps_for_role(role_a_name, role_a_src)
        caps_b = caps_for_role(role_b_name, role_b_src)
        combined_caps = caps_a | caps_b

        risk_tags = []
        for combo, tag in RISK_CAP_COMBOS.items():
            if combo <= combined_caps:
                risk_tags.append(tag)

        risk_level = "critical" if len(risk_tags) >= 2 else ("high" if risk_tags else "low")

        results.append(BundleResult(
            roles=[role_a_name, role_b_name],
            sources=[role_a_src, role_b_src],
            identity_count=len(idents),
            identities=[identity_names.get(i, i) for i in idents[:10]],
            capabilities=[c.value for c in combined_caps],
            risk_tags=risk_tags,
            risk_level=risk_level,
        ))

        if len(results) >= 20:
            break

    # Step 3: Larger bundle mining (size 3-6, simple frequency)
    if len(identity_role_sets) >= 3:
        for size in range(3, min(max_bundle_size + 1, 5)):
            bundle_counts: Dict[Tuple, List[str]] = {}
            for ident_id, rset in identity_role_sets.items():
                if len(rset) < size:
                    continue
                sorted_roles = sorted(rset)
                # Only try the most common subsets — use the existing pair info
                # Simple approach: for each identity, record its full role set
                key = tuple(sorted_roles[:size])
                bundle_counts.setdefault(key, []).append(ident_id)

            for bundle, idents in sorted(bundle_counts.items(), key=lambda x: -len(x[1])):
                if len(idents) < min_count:
                    continue
                role_names = []
                sources = []
                combined_caps: Set[Cap] = set()
                for rkey in bundle:
                    name, src = rkey.split("|", 1)
                    role_names.append(name)
                    sources.append(src)
                    combined_caps |= caps_for_role(name, src)

                risk_tags = []
                for combo, tag in RISK_CAP_COMBOS.items():
                    if combo <= combined_caps:
                        risk_tags.append(tag)

                risk_level = "critical" if len(risk_tags) >= 2 else ("high" if risk_tags else "low")
                results.append(BundleResult(
                    roles=role_names,
                    sources=sources,
                    identity_count=len(idents),
                    identities=[identity_names.get(i, i) for i in idents[:10]],
                    capabilities=[c.value for c in combined_caps],
                    risk_tags=risk_tags,
                    risk_level=risk_level,
                ))
                if len(results) >= 30:
                    break

    return results


# ─────────────────────────────────────────────────────────────
# § 8  REDUNDANCY DETECTION (scope-aware)
# ─────────────────────────────────────────────────────────────

# Broader → narrower containment map
ROLE_CONTAINS: Dict[str, Set[str]] = {
    "owner": {"contributor", "reader"},
    "contributor": {"reader"},
    "storage blob data owner": {"storage blob data contributor", "storage blob data reader"},
    "storage blob data contributor": {"storage blob data reader"},
    "key vault administrator": {"key vault secrets officer", "key vault secrets user", "key vault reader", "key vault crypto officer"},
    "key vault secrets officer": {"key vault secrets user", "key vault reader"},
    "key vault crypto officer": {"key vault reader"},
    "global administrator": {"privileged role administrator", "user administrator",
                             "application administrator", "cloud application administrator",
                             "groups administrator", "security administrator",
                             "exchange administrator", "helpdesk administrator"},
    "privileged role administrator": {"application administrator", "cloud application administrator"},
    "user administrator": {"helpdesk administrator", "password administrator"},
}


def detect_redundant(identity_roles: List[NormalizedRole]) -> List[Tuple[NormalizedRole, str]]:
    """
    For a single identity, find roles that are redundant (subset of a broader role at same/broader scope).
    Returns list of (redundant_role, superseded_by_name).
    """
    redundant = []
    for narrow in identity_roles:
        narrow_key = narrow.role_name.lower().strip()
        for broad in identity_roles:
            if broad is narrow:
                continue
            broad_key = broad.role_name.lower().strip()
            contained = ROLE_CONTAINS.get(broad_key, set())
            if narrow_key in contained:
                # Check scope overlap — broad scope must contain narrow scope
                if scopes_overlap(broad.scope_type, broad.scope_id,
                                  narrow.scope_type, narrow.scope_id):
                    redundant.append((narrow, broad.role_name))
                    break
    return redundant


# ─────────────────────────────────────────────────────────────
# § 9  ORPHANED ROLES DETECTION
# ─────────────────────────────────────────────────────────────

def detect_orphaned(identity_roles: List[NormalizedRole],
                    identity_enabled: bool) -> List[NormalizedRole]:
    """Find orphaned roles: assigned to disabled identities or deleted scopes."""
    orphaned = []
    for r in identity_roles:
        if not r.scope_exists:
            orphaned.append(r)
        elif not identity_enabled:
            orphaned.append(r)
    return orphaned


# ─────────────────────────────────────────────────────────────
# § 10  MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────

class RoleMiningEngine:
    """Top-level orchestrator for Role Mining v2."""

    def __init__(self, db, window_days: int = 90):
        self.db = db
        self.window_days = window_days
        self.toxic_engine = ToxicComboEngine(window_days=window_days)

    def analyze(self) -> Dict:
        """Run the full role mining analysis. Returns structured result dict."""
        # 1. Load all roles from latest run
        roles_by_identity = self._load_all_roles()
        # Store run_id for evidence loading
        self._run_id = getattr(self, '_last_run_id', None)

        # 2. Toxic combinations
        toxic_findings = self.toxic_engine.evaluate_all(roles_by_identity)

        # 3. Unused findings with evidence
        unused_findings = self._analyze_unused(roles_by_identity)

        # 4. Redundancy
        redundant_findings = self._analyze_redundant(roles_by_identity)

        # 5. Orphaned
        orphaned_findings = self._analyze_orphaned(roles_by_identity)

        # 6. Bundles
        bundles = mine_bundles(roles_by_identity, min_count=2)

        # 7. Role frequency
        role_freq = self._role_frequency(roles_by_identity)

        # 8. Summary
        total_roles = sum(len(r) for r in roles_by_identity.values())
        summary = {
            "total_roles": total_roles,
            "total_identities": len(roles_by_identity),
            "unused": len(unused_findings),
            "redundant": len(redundant_findings),
            "orphaned": len(orphaned_findings),
            "toxic_combos": len(toxic_findings),
            "overprivileged": sum(1 for _, roles in roles_by_identity.items()
                                  for r in roles if r.risk_level in ("critical", "high")),
            "optimization_pct": min(100.0, round(
                (len(unused_findings) + len(redundant_findings) + len(orphaned_findings))
                / max(total_roles, 1) * 100, 1
            )),
        }

        return {
            "summary": summary,
            "toxic_combos": [f.to_dict() for f in toxic_findings],
            "unused_findings": [f.to_dict() for f in unused_findings],
            "redundant_findings": [self._redundant_to_dict(r, by) for r, by in redundant_findings],
            "orphaned_findings": [self._orphaned_to_dict(r) for r in orphaned_findings],
            "bundles": [self._bundle_to_dict(b) for b in bundles],
            "role_frequency": role_freq,
        }

    def _load_all_roles(self) -> Dict[str, List[NormalizedRole]]:
        """Load all Azure RBAC + Entra roles from latest run, grouped by identity."""
        cursor = self.db.conn.cursor()
        result: Dict[str, List[NormalizedRole]] = {}

        # Get latest run ID
        cursor.execute("""
            SELECT id FROM discovery_runs
            WHERE status = 'completed'
            ORDER BY id DESC LIMIT 1
        """)
        row = cursor.fetchone()
        if not row:
            cursor.close()
            return result
        run_id = row[0]
        self._last_run_id = run_id

        # Azure RBAC roles
        cursor.execute("""
            SELECT i.id, i.identity_id, i.display_name, i.identity_category,
                   i.enabled, i.last_sign_in,
                   r.role_name, r.scope, r.scope_type, r.created_on,
                   r.usage_status, r.redundant_with, r.risk_level, r.why_critical,
                   r.scope_exists, r.days_since_assigned
            FROM role_assignments r
            JOIN identities i ON i.id = r.identity_db_id
            WHERE i.discovery_run_id = %s
        """, (run_id,))

        for row in cursor.fetchall():
            db_id, ident_id, name, cat = row[0], row[1], row[2], row[3]
            enabled, last_sign = row[4], row[5]
            role_name, scope, scope_type = row[6], row[7], row[8]
            created_on = row[9]
            usage_status, redundant_with = row[10], row[11]
            risk_level, why_critical = row[12], row[13]
            scope_exists, days_since = row[14], row[15]

            nr = NormalizedRole(
                identity_db_id=db_id,
                identity_id=ident_id,
                identity_name=name or ident_id,
                identity_category=cat or "unknown",
                source="azure",
                role_name=role_name or "",
                role_type="rbac",
                assignment_method="direct",
                scope_type=scope_type or "subscription",
                scope_id=scope or "/",
                scope_name=scope_label(scope or "/", scope_type or "subscription"),
                assigned_at=created_on,
                days_since_assigned=days_since,
                usage_status=usage_status or "unknown",
                redundant_with=redundant_with,
                risk_level=risk_level or "unknown",
                why_critical=why_critical,
                scope_exists=scope_exists if scope_exists is not None else True,
                enabled=enabled if enabled is not None else True,
                last_sign_in=last_sign,
            )
            result.setdefault(ident_id, []).append(nr)

        # Entra roles
        cursor.execute("""
            SELECT i.id, i.identity_id, i.display_name, i.identity_category,
                   i.enabled, i.last_sign_in,
                   e.role_name, e.directory_scope, e.assigned_on,
                   e.usage_status, e.redundant_with, e.risk_level, e.why_critical,
                   e.days_since_assigned
            FROM entra_role_assignments e
            JOIN identities i ON i.id = e.identity_db_id
            WHERE i.discovery_run_id = %s
        """, (run_id,))

        for row in cursor.fetchall():
            db_id, ident_id, name, cat = row[0], row[1], row[2], row[3]
            enabled, last_sign = row[4], row[5]
            role_name, dir_scope, assigned_on = row[6], row[7], row[8]
            usage_status, redundant_with = row[9], row[10]
            risk_level, why_critical = row[11], row[12]
            days_since = row[13]

            nr = NormalizedRole(
                identity_db_id=db_id,
                identity_id=ident_id,
                identity_name=name or ident_id,
                identity_category=cat or "unknown",
                source="entra",
                role_name=role_name or "",
                role_type="entra",
                assignment_method="direct",
                scope_type="tenant",
                scope_id=dir_scope or "/",
                scope_name=scope_label(dir_scope or "/", "tenant"),
                assigned_at=assigned_on,
                days_since_assigned=days_since,
                usage_status=usage_status or "unknown",
                redundant_with=redundant_with,
                risk_level=risk_level or "unknown",
                why_critical=why_critical,
                scope_exists=True,
                enabled=enabled if enabled is not None else True,
                last_sign_in=last_sign,
            )
            result.setdefault(ident_id, []).append(nr)

        # Check PIM eligible assignments (with member_type for group distinction)
        cursor.execute("""
            SELECT p.identity_db_id, p.role_name, p.member_type
            FROM pim_eligible_assignments p
            JOIN identities i ON i.id = p.identity_db_id
            WHERE i.discovery_run_id = %s
        """, (run_id,))
        pim_eligible_map: Dict[int, Dict[str, str]] = {}
        for row in cursor.fetchall():
            db_id = row[0]
            role_lower = (row[1] or "").lower()
            member_type = row[2] or "Direct"
            pim_eligible_map.setdefault(db_id, {})[role_lower] = member_type

        # Check PIM active assignments
        cursor.execute("""
            SELECT p.identity_db_id, p.role_name
            FROM pim_activations p
            JOIN identities i ON i.id = p.identity_db_id
            WHERE i.discovery_run_id = %s
              AND (p.status = 'Active' OR (p.activation_end IS NOT NULL AND p.activation_end > NOW()))
        """, (run_id,))
        pim_active_map: Dict[int, Set[str]] = {}
        for row in cursor.fetchall():
            pim_active_map.setdefault(row[0], set()).add((row[1] or "").lower())

        # Tag assignment methods: pim_active > pim_eligible/pim_eligible_group > direct
        for ident_id, roles in result.items():
            for r in roles:
                role_lower = r.role_name.lower()
                db_id = r.identity_db_id
                if db_id in pim_active_map and role_lower in pim_active_map[db_id]:
                    r.assignment_method = "pim_active"
                elif db_id in pim_eligible_map and role_lower in pim_eligible_map.get(db_id, {}):
                    member_type = pim_eligible_map[db_id][role_lower]
                    r.assignment_method = "pim_eligible_group" if member_type == "Group" else "pim_eligible"
                # else: remains "direct" (default)

        cursor.close()
        return result

    def _load_evidence_data(self, run_id: Optional[int], window_days: int) -> Dict[Tuple[int, str], List[Dict]]:
        """Bulk-load PIM activations within window for all identities in the run."""
        result: Dict[Tuple[int, str], List[Dict]] = {}
        if not run_id:
            return result
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                SELECT pa.identity_db_id, pa.role_name, pa.activation_start, pa.status
                FROM pim_activations pa
                JOIN identities i ON i.id = pa.identity_db_id
                WHERE i.discovery_run_id = %s
                  AND pa.activation_start >= NOW() - INTERVAL '%s days'
                ORDER BY pa.activation_start DESC
            """, (run_id, window_days))
            for row in cursor.fetchall():
                db_id, role_name, activation_start, status = row
                key = (db_id, (role_name or "").lower())
                result.setdefault(key, []).append({
                    "activation_start": activation_start,
                    "status": status or "unknown",
                })
            cursor.close()
        except Exception:
            pass
        return result

    def _analyze_unused(self, roles_by_identity: Dict[str, List[NormalizedRole]]) -> List[UnusedFinding]:
        """Build unused findings with evidence/confidence."""
        # Load PIM evidence once
        pim_evidence = self._load_evidence_data(self._run_id, self.window_days)

        findings = []
        for ident_id, roles in roles_by_identity.items():
            for r in roles:
                if r.usage_status not in ("definitely_unused", "likely_unused"):
                    continue

                # Look up PIM activations for this role
                pim_key = (r.identity_db_id, r.role_name.lower())
                pim_acts = pim_evidence.get(pim_key)

                ev = compute_evidence(r, self.window_days, pim_activations=pim_acts)

                # If PIM activation proves the role is USED, skip this finding
                if ev.confidence == "HIGH" and ev.last_activity_source == "pim_activation":
                    continue

                # Map usage_status to finding_type with confidence guard
                if r.usage_status == "definitely_unused" and ev.confidence == "HIGH":
                    ftype = "definitely_unused"
                    rec = f'Remove "{r.role_name}" — confirmed unused'
                elif r.usage_status == "likely_unused" and ev.confidence in ("HIGH", "MED"):
                    ftype = "likely_unused"
                    rec = f'Review and likely remove "{r.role_name}" — appears unused ({ev.confidence} confidence)'
                else:
                    ftype = "potentially_unused"
                    rec = f'Potentially unused "{r.role_name}" — low confidence, verify with activity logs'

                br_label, _ = blast_radius(r.scope_type, r.scope_id, r.role_name, r.capabilities,
                                           assignment_method=r.assignment_method)

                findings.append(UnusedFinding(
                    identity_id=r.identity_id,
                    identity_name=r.identity_name,
                    identity_category=r.identity_category,
                    role_name=r.role_name,
                    source=r.source,
                    finding_type=ftype,
                    risk_level=r.risk_level,
                    scope=r.scope_id,
                    scope_type=r.scope_type,
                    days_since_assigned=r.days_since_assigned,
                    assignment_method=r.assignment_method,
                    recommendation=rec,
                    evidence=ev,
                    blast_radius=br_label,
                ))
        return findings

    def _analyze_redundant(self, roles_by_identity: Dict[str, List[NormalizedRole]]) -> List[Tuple[NormalizedRole, str]]:
        """Find redundant roles across all identities."""
        findings = []
        for ident_id, roles in roles_by_identity.items():
            redundants = detect_redundant(roles)
            findings.extend(redundants)
        return findings

    def _analyze_orphaned(self, roles_by_identity: Dict[str, List[NormalizedRole]]) -> List[NormalizedRole]:
        """Find orphaned roles across all identities."""
        findings = []
        for ident_id, roles in roles_by_identity.items():
            first = roles[0] if roles else None
            enabled = first.enabled if first else True
            orphaned = detect_orphaned(roles, enabled)
            findings.extend(orphaned)
        return findings

    def _role_frequency(self, roles_by_identity: Dict[str, List[NormalizedRole]]) -> List[Dict]:
        """Top roles by assignment count."""
        freq: Dict[Tuple[str, str], int] = {}
        for roles in roles_by_identity.values():
            for r in roles:
                key = (r.role_name, r.source)
                freq[key] = freq.get(key, 0) + 1

        sorted_freq = sorted(freq.items(), key=lambda x: -x[1])[:15]
        return [{"role_name": k[0], "source": k[1], "assignment_count": v}
                for k, v in sorted_freq]

    def _redundant_to_dict(self, role: NormalizedRole, superseded_by: str) -> Dict:
        br_label, _ = blast_radius(role.scope_type, role.scope_id, role.role_name, role.capabilities,
                                   assignment_method=role.assignment_method)
        return {
            "identity_id": role.identity_id,
            "identity_name": role.identity_name,
            "identity_category": role.identity_category,
            "role_name": role.role_name,
            "source": role.source,
            "scope": role.scope_id,
            "scope_type": role.scope_type,
            "superseded_by": superseded_by,
            "recommendation": f'Remove "{role.role_name}" — superseded by "{superseded_by}" at same/broader scope',
            "risk_level": role.risk_level,
            "blast_radius": br_label,
            "assignment_method": role.assignment_method,
        }

    def _orphaned_to_dict(self, role: NormalizedRole) -> Dict:
        if not role.scope_exists:
            reason = "Target resource no longer exists"
            rec = f'Remove "{role.role_name}" — target resource deleted'
        else:
            reason = "Identity is disabled"
            rec = f'Remove "{role.role_name}" — identity is disabled'
        return {
            "identity_id": role.identity_id,
            "identity_name": role.identity_name,
            "identity_category": role.identity_category,
            "role_name": role.role_name,
            "source": role.source,
            "scope": role.scope_id,
            "scope_type": role.scope_type,
            "reason": reason,
            "recommendation": rec,
            "risk_level": role.risk_level,
            "assignment_method": role.assignment_method,
        }

    def _bundle_to_dict(self, b: BundleResult) -> Dict:
        return {
            "roles": b.roles,
            "sources": b.sources,
            "identity_count": b.identity_count,
            "identities": b.identities,
            "capabilities": b.capabilities,
            "risk_tags": b.risk_tags,
            "risk_level": b.risk_level,
        }
