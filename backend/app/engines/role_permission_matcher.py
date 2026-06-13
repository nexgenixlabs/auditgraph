"""
AG-F (2026-05-30): Operation→role permission matcher.

Given an Azure ARM operation name (e.g. "Microsoft.KeyVault/vaults/secrets/get")
and a role name (e.g. "Key Vault Administrator"), determine whether that role
plausibly grants that operation. Used to correctly attribute ARM Activity Log
events to the *specific* roles that authorize them — instead of stamping the
same last_used_at on every role the principal holds at the matching scope.

Approach (pragmatic, no Azure API dependency):
 - Wildcard roles (Owner, Contributor, User Access Administrator) match
   anything within their authorization profile.
 - Service-scoped roles (e.g. "Key Vault Reader") match operations under the
   matching Microsoft.<Service>/* namespace only.
 - Read-only roles (any role whose name ends in "Reader") only match read /
   list / get operations.

This covers the ~95% of role-name patterns that exist in real tenants without
needing to ship the full Azure built-in role catalog (~400 entries × dozens
of action wildcards each). For unknown role names we fall back to the legacy
scope-only behavior (matches) so we never under-attribute.

When the Azure built-in role catalog ships as static JSON we can swap this
heuristic for the canonical lookup without touching callers.
"""
from __future__ import annotations
from typing import Optional


# AG-PILOT-RBAC-MOAT (2026-06-09): tighten wildcard set so daily-grant
# workflows can be attributed to UAA / RBAC Admin only, not to every
# privileged role. Customer-reported moat failure: a user who only ever
# grants access (User Access Admin work) had Contributor showing as
# "used" identically. Owner stays in wildcards because Owner truly
# authorizes any operation; UAA / RBAC Admin handled separately below.
_WILDCARD_ROLES = {
    'owner',
    'contributor',
}

# Roles that ONLY authorize role-assignment / authorization operations.
# Attributing daily Microsoft.Authorization/roleAssignments/write events
# to these (and NOT to Owner / Contributor) is the moat differentiator.
_AUTHORIZATION_ROLES = {
    'user access administrator',
    'role based access control administrator',
    'access review operator service role',
}
_AUTHORIZATION_OP_PREFIXES = (
    'microsoft.authorization/roleassignments/',
    'microsoft.authorization/roledefinitions/',
    'microsoft.authorization/roleeligibilityschedules/',
    'microsoft.authorization/roleassignmentschedules/',
    'microsoft.authorization/denyassignments/',
)

# Roles that authorize anything matching a specific service namespace.
# Key = lowercased substring that should appear in the role name.
# Value = list of Microsoft.<X>/ prefixes the role legitimately covers.
_SERVICE_PREFIX_ROLES: dict[str, tuple[str, ...]] = {
    'key vault':        ('microsoft.keyvault/',),
    'storage':          ('microsoft.storage/',),
    'sql':              ('microsoft.sql/', 'microsoft.dbforpostgresql/', 'microsoft.dbformysql/'),
    'cosmos':           ('microsoft.documentdb/',),
    'database':         ('microsoft.sql/', 'microsoft.dbforpostgresql/', 'microsoft.dbformysql/', 'microsoft.documentdb/'),
    'virtual machine':  ('microsoft.compute/',),
    'compute':          ('microsoft.compute/',),
    'desktop virtualization': ('microsoft.desktopvirtualization/',),
    'network':          ('microsoft.network/',),
    'dns':              ('microsoft.network/dnszones/', 'microsoft.network/privatednszones/'),
    'monitoring':       ('microsoft.insights/', 'microsoft.operationalinsights/'),
    'log analytics':    ('microsoft.operationalinsights/',),
    'application insights': ('microsoft.insights/',),
    'app service':      ('microsoft.web/',),
    'web':              ('microsoft.web/',),
    'function':         ('microsoft.web/sites/',),
    'event hub':        ('microsoft.eventhub/',),
    'service bus':      ('microsoft.servicebus/',),
    'kubernetes':       ('microsoft.containerservice/',),
    'container':        ('microsoft.containerservice/', 'microsoft.containerregistry/', 'microsoft.containerinstance/'),
    'cognitive':        ('microsoft.cognitiveservices/',),
    'machine learning': ('microsoft.machinelearningservices/',),
    'search':           ('microsoft.search/',),
    'cdn':              ('microsoft.cdn/',),
    'redis':            ('microsoft.cache/',),
    'app configuration': ('microsoft.appconfiguration/',),
    'managed identity': ('microsoft.managedidentity/',),
    'backup':           ('microsoft.recoveryservices/',),
    'recovery':         ('microsoft.recoveryservices/',),
    'security':         ('microsoft.security/',),
    'policy':           ('microsoft.authorization/policy',),
    'logic app':        ('microsoft.logic/',),
    'data factory':     ('microsoft.datafactory/',),
    'synapse':          ('microsoft.synapse/',),
    'event grid':       ('microsoft.eventgrid/',),
}

# Operation suffixes that count as read-only.
_READ_OP_SUFFIXES = ('/read', '/list', '/get', '/listkeys', '/listsas', '/getsecret', '/preview')


def _is_read_operation(operation: str) -> bool:
    op = operation.lower()
    if any(op.endswith(s) for s in _READ_OP_SUFFIXES):
        return True
    # "GET" verb in REST-style operationName values
    if '/get' in op or op.endswith('read'):
        return True
    return False


def role_matches_operation(role_name: Optional[str], operation: Optional[str]) -> bool:
    """Heuristic: does this role plausibly authorize this ARM operation?

    AG-PILOT-RBAC-MOAT (2026-06-09): tightened to default-False for
    unknown roles. Customer reported every role on a user showed the
    same last_used timestamp because one ARM event was stamping all
    of them. New semantics:

      - Owner / Contributor: match everything (true wildcards)
      - UAA / RBAC Admin: match ONLY Microsoft.Authorization/*
      - Reader (+ <service> Reader): match only read ops
      - Service-scoped roles: match only their service prefix
      - Unknown roles: don't gate — return False so we don't over-attribute

    The previous default-True meant a single Storage write event would
    stamp Owner + Contributor + Reader + 6 unrelated roles. Now each
    event attributes to the smallest matching set.
    """
    if not role_name or not operation:
        return False
    rn = role_name.lower()
    op = operation.lower()

    # 1. True wildcard roles (Owner / Contributor) match everything
    if rn in _WILDCARD_ROLES:
        return True

    # 2. Authorization-scoped roles: only Microsoft.Authorization/* operations
    if rn in _AUTHORIZATION_ROLES:
        return any(op.startswith(p) for p in _AUTHORIZATION_OP_PREFIXES)

    # 3. Read-only roles ("Reader" by itself or "<X> Reader") only match read ops
    if rn == 'reader' or rn.endswith(' reader'):
        if _is_read_operation(op):
            for keyword, prefixes in _SERVICE_PREFIX_ROLES.items():
                if keyword in rn:
                    return any(op.startswith(p) for p in prefixes)
            return True
        return False

    # 4. Service-scoped roles — match by service prefix
    for keyword, prefixes in _SERVICE_PREFIX_ROLES.items():
        if keyword in rn:
            return any(op.startswith(p) for p in prefixes)

    # 5. Unknown role pattern → don't over-attribute. Better to show
    #    "no telemetry" honestly than stamp every role with the same date.
    return False


# ─── Entra (Azure AD) directory role → audit-log category mapping ──────────
#
# AG-E Phase 2 (2026-06-01): Microsoft provides NO per-Entra-role exercise
# audit log. We infer role usage by attributing /auditLogs/directoryAudits
# events to whichever of an identity's standing roles could have authorized
# the operation. Categories sourced from Microsoft's privileged role docs
# (learn.microsoft.com/azure/active-directory/roles/permissions-reference).
#
# Conservative attribution: if multiple of an identity's roles could
# authorize the event, attribute to ALL of them. Better to over-attribute
# (looks "active") than under (looks "unused" → wrong audit verdict).
#
# Global Administrator is INTENTIONALLY MARKED AS '*' (matches everything)
# because that's true to its authorization profile. Downside: if a user
# holds GA + a lower role, the lower role also gets credit for any GA-
# eligible event. Net effect for the audit story: false-positive "active"
# is preferable to false-negative "unused" that could justify removing a
# role the user actually needs.

_ENTRA_ROLE_CATEGORY_MAP: dict[str, tuple[str, ...]] = {
    # Tier 0 — top privilege; matches every audit category
    'global administrator': ('*',),
    'company administrator': ('*',),  # legacy alias for Global Admin
    'privileged role administrator': ('RoleManagement', 'DirectoryManagement'),
    'privileged authentication administrator': ('UserManagement', 'AuthenticationMethod'),
    'partner tier2 support':  ('*',),

    # Tier 1 — broad-but-scoped
    'security administrator': ('RoleManagement', 'ConditionalAccess', 'PolicyManagement', 'DirectoryManagement'),
    'user administrator': ('UserManagement', 'GroupManagement', 'Invitations'),
    'application administrator': ('ApplicationManagement', 'ServicePrincipalManagement'),
    'cloud application administrator': ('ApplicationManagement', 'ServicePrincipalManagement'),
    'hybrid identity administrator': ('UserManagement', 'DirectoryManagement', 'AuthenticationMethod'),
    'authentication administrator': ('AuthenticationMethod', 'UserManagement'),
    'helpdesk administrator': ('UserManagement',),  # password reset
    'conditional access administrator': ('PolicyManagement', 'ConditionalAccess'),
    'compliance administrator': ('PolicyManagement', 'AuditLog'),
    'domain name administrator': ('Domain',),
    'external identity provider administrator': ('DirectoryManagement', 'AuthenticationMethod'),

    # Workload-specific admins
    'exchange administrator':   ('UserManagement', 'Exchange'),
    'sharepoint administrator': ('SharePoint',),
    'teams administrator':      ('Teams',),
    'intune administrator':     ('DeviceManagement',),
    'security operator':        ('AuditLog', 'PolicyManagement'),
    'security reader':          ('AuditLog',),
    'directory readers':        ('Directory',),  # read-only
    'global reader':            ('*',),  # all read; matches anything since we don't separate read vs write events
}


def entra_role_matches_audit_category(role_name: Optional[str], category: Optional[str]) -> bool:
    """Does this Entra role plausibly authorize an event in this audit category?

    role_name: e.g. 'Global Administrator', 'User Administrator'
    category:  e.g. 'UserManagement', 'RoleManagement', 'ApplicationManagement'

    Conservative: unknown role names default to True (don't under-attribute,
    same fallback rule as the ARM matcher). Wildcard ('*') in the map means
    the role's authorization scope covers every directoryAudits category.
    """
    if not role_name or not category:
        return True
    rn = role_name.lower().strip()
    cats = _ENTRA_ROLE_CATEGORY_MAP.get(rn)
    if cats is None:
        # Unknown role — fall back permissively
        return True
    if '*' in cats:
        return True
    return category in cats
