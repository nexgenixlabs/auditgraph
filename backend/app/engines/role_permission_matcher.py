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


# Roles that authorize EVERY operation at their scope (wildcards in their
# Azure RBAC role definition Actions array, e.g. "*", "*/read", etc.)
_WILDCARD_ROLES = {
    'owner',
    'contributor',
    'user access administrator',
    'role based access control administrator',
    'access review operator service role',
}

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

    Returns True if the role likely grants the operation, False if we can
    confidently say it doesn't. Unknown role names default to True (we
    fall back to scope-only semantics rather than risk under-attribution).
    """
    if not role_name or not operation:
        return True  # no info → don't gate
    rn = role_name.lower()
    op = operation.lower()

    # 1. Wildcard roles always match
    if rn in _WILDCARD_ROLES:
        return True

    # 2. Read-only roles ("Reader" by itself or "<X> Reader") only match read ops
    if rn == 'reader' or rn.endswith(' reader'):
        if _is_read_operation(op):
            # Still gate by service prefix if the reader name implies one
            for keyword, prefixes in _SERVICE_PREFIX_ROLES.items():
                if keyword in rn:
                    return any(op.startswith(p) for p in prefixes)
            return True
        return False

    # 3. Service-scoped roles — match by service prefix
    for keyword, prefixes in _SERVICE_PREFIX_ROLES.items():
        if keyword in rn:
            return any(op.startswith(p) for p in prefixes)

    # 4. Unknown role pattern → don't gate; fall back to scope-only behavior
    return True
