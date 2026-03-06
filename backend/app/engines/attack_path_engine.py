"""
Phase 3: Attack Path Analysis Engine

Tenant-wide batch analysis that performs graph traversal across all identities
to detect privilege escalation and sensitive data exposure paths.

Distinct from Phase 81 (per-identity on-demand attack paths in handlers.py):
- Runs as a scheduled batch job after security findings
- Persists results in attack_paths table
- Covers all identities in a discovery run
- Includes resource-to-sensitive-data exposure chains

Stability improvements:
- Deterministic SHA-256 fingerprinting for cross-snapshot deduplication
- Per-identity path cap (MAX_PATHS_PER_IDENTITY) to prevent runaway output
- Graph depth limit (MAX_GRAPH_DEPTH) on path_nodes length
"""

import hashlib
import json
import logging
from collections import defaultdict
from typing import Dict, List

logger = logging.getLogger(__name__)

# ── Safety limits ──────────────────────────────────────────────────────

MAX_GRAPH_DEPTH = 5           # Maximum nodes in a single path chain
MAX_PATHS_PER_IDENTITY = 10   # Stop emitting paths for an identity after this
MAX_PATHS_PER_RUN = 2000      # Global cap across all identities in a single run

# ── Privilege constants ──────────────────────────────────────────────

# Dangerous Entra directory roles that grant tenant-wide admin control
_DANGEROUS_ENTRA_ROLES = {
    'Global Administrator', 'Privileged Role Administrator',
    'Application Administrator', 'Cloud Application Administrator',
    'User Administrator', 'Exchange Administrator',
}

# Dangerous Graph API permissions enabling direct escalation
_DANGEROUS_GRAPH_PERMS = {
    'RoleManagement.ReadWrite.All', 'Application.ReadWrite.All',
    'AppRoleAssignment.ReadWrite.All', 'Directory.ReadWrite.All',
    'GroupMember.ReadWrite.All', 'ServicePrincipalEndpoint.ReadWrite.All',
}

# Broad RBAC roles at subscription scope
_BROAD_SUB_ROLES = {'Owner', 'Contributor', 'User Access Administrator'}

# Sensitivity-amplifying data classifications
_SENSITIVE_CLASSIFICATIONS = {'confidential', 'highly_confidential', 'restricted', 'pii', 'phi', 'pci'}

# ── Score weights ────────────────────────────────────────────────────

_PRIVILEGE_WEIGHT = {
    'Global Administrator': 50, 'Privileged Role Administrator': 45,
    'Owner': 40, 'User Access Administrator': 38,
    'Application Administrator': 35, 'Cloud Application Administrator': 35,
    'User Administrator': 30, 'Exchange Administrator': 28,
    'Contributor': 25,
}

_SCOPE_WEIGHT = {
    'management_group': 15,
    'subscription': 10,
    'resource_group': 5,
    'resource': 2,
}


def _severity_from_score(score: int) -> str:
    if score >= 80:
        return 'critical'
    if score >= 50:
        return 'high'
    return 'medium'


def compute_path_fingerprint(source_entity_id: str, path_type: str,
                             path_nodes: list) -> str:
    """Compute a deterministic SHA-256 fingerprint for an attack path.

    The fingerprint is stable across snapshots — identical logical paths
    (same source, type, and node structure) produce the same hash.
    """
    # Normalize nodes to only their identity-bearing keys (type + id),
    # sorted to ensure determinism regardless of dict key order.
    normalized = []
    for node in path_nodes:
        normalized.append({
            'type': node.get('type', ''),
            'id': node.get('id', ''),
        })
    payload = json.dumps({
        'source_entity_id': source_entity_id,
        'path_type': path_type,
        'nodes': normalized,
    }, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


class AttackPathEngine:
    """Tenant-wide attack path analysis via graph traversal."""

    def __init__(self, db):
        self.db = db

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, run_id: int) -> List[Dict]:
        """Run all path detectors for a single discovery run.

        Returns list of path dicts ready for save_attack_paths().
        Enforces MAX_PATHS_PER_IDENTITY across all detectors.
        """
        all_paths: List[Dict] = []
        # Track how many paths each identity has accumulated
        identity_path_counts: Dict[str, int] = defaultdict(int)

        detectors = [
            ('direct_escalation', self._detect_direct_escalation),
            ('ownership_chain', self._detect_ownership_chain),
            ('pim_escalation', self._detect_pim_escalation),
            ('lateral_movement', self._detect_lateral_movement),
            ('sensitive_data_exposure', self._detect_sensitive_data_exposure),
            ('external_identity_risk', self._detect_external_identity_risk),
        ]

        for name, detector in detectors:
            # Global cap: stop if we have already hit MAX_PATHS_PER_RUN
            if len(all_paths) >= MAX_PATHS_PER_RUN:
                logger.warning(f"  MAX_PATHS_PER_RUN ({MAX_PATHS_PER_RUN}) reached, "
                               f"skipping remaining detectors")
                break

            try:
                results = detector(run_id)
                # Apply per-identity cap + global cap
                accepted = []
                for p in results:
                    if len(all_paths) + len(accepted) >= MAX_PATHS_PER_RUN:
                        break
                    eid = p['source_entity_id']
                    if identity_path_counts[eid] >= MAX_PATHS_PER_IDENTITY:
                        continue
                    identity_path_counts[eid] += 1
                    accepted.append(p)
                all_paths.extend(accepted)
                if accepted:
                    logger.info(f"  Attack path '{name}': {len(accepted)} path(s) "
                                f"({len(results) - len(accepted)} capped)")
            except Exception as e:
                logger.error(f"  Attack path detector '{name}' failed: {e}")

        logger.info(f"Attack path engine: {len(all_paths)} total path(s) for run #{run_id}")
        return all_paths

    # ------------------------------------------------------------------
    # Path builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_path(
        path_type: str,
        source_entity_id: str,
        source_entity_name: str,
        source_entity_type: str,
        risk_score: int,
        path_nodes: list,
        description: str,
        narrative: str = None,
        impact: str = None,
        affected_resource_count: int = 0,
    ) -> Dict:
        # Enforce MAX_GRAPH_DEPTH — truncate nodes if chain is too long
        if len(path_nodes) > MAX_GRAPH_DEPTH:
            path_nodes = path_nodes[:MAX_GRAPH_DEPTH]

        fp = compute_path_fingerprint(source_entity_id, path_type, path_nodes)

        return {
            'path_type': path_type,
            'source_entity_id': source_entity_id,
            'source_entity_name': source_entity_name,
            'source_entity_type': source_entity_type,
            'risk_score': risk_score,
            'severity': _severity_from_score(risk_score),
            'path_nodes': path_nodes,
            'path_fingerprint': fp,
            'description': description,
            'narrative': narrative or '',
            'impact': impact or '',
            'affected_resource_count': affected_resource_count,
        }

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_score(privilege_name: str, scope_type: str = None,
                       is_external: bool = False,
                       has_sensitive_target: bool = False) -> int:
        """Compute composite risk score from factors."""
        score = _PRIVILEGE_WEIGHT.get(privilege_name, 15)
        score += _SCOPE_WEIGHT.get(scope_type, 0)
        if is_external:
            score += 15  # External identity amplifier
        if has_sensitive_target:
            score += 10  # Sensitive data amplifier
        return min(score, 100)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _count_resources_for_scope(self, run_id: int, scope: str) -> int:
        """Estimate affected resource count by matching scope against discovered resources."""
        if not scope:
            return 0
        scope_lower = scope.lower()
        cursor = self.db.conn.cursor()
        total = 0
        for table in ('azure_storage_accounts', 'azure_key_vaults'):
            try:
                cursor.execute(f"""
                    SELECT COUNT(*) FROM {table}
                    WHERE discovery_run_id = %s
                      AND LOWER(resource_id) LIKE %s
                """, (run_id, f'%{scope_lower}%'))
                total += cursor.fetchone()[0]
            except Exception:
                pass
        cursor.close()
        return total

    # ------------------------------------------------------------------
    # Detection rules
    # ------------------------------------------------------------------

    def _detect_direct_escalation(self, run_id: int) -> List[Dict]:
        """Identities with dangerous Entra roles or Graph API permissions.

        Path: Identity → Dangerous Role/Permission → Tenant-Wide Control
        """
        cursor = self.db.conn.cursor()
        paths = []

        # 1a. Dangerous Entra roles
        try:
            placeholders = ','.join(['%s'] * len(_DANGEROUS_ENTRA_ROLES))
            cursor.execute(f"""
                SELECT i.identity_id, i.display_name, i.identity_category,
                       era.role_name, era.directory_scope
                FROM identities i
                JOIN entra_role_assignments era ON era.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
                  AND era.role_name IN ({placeholders})
            """, (run_id, *_DANGEROUS_ENTRA_ROLES))
            for row in cursor.fetchall():
                identity_id, name, category, role, scope = row
                is_ext = category in ('guest', 'service_principal')
                score = self._compute_score(role, 'subscription', is_external=is_ext)
                paths.append(self._build_path(
                    path_type='direct_escalation',
                    source_entity_id=identity_id,
                    source_entity_name=name,
                    source_entity_type=category,
                    risk_score=score,
                    path_nodes=[
                        {'type': 'identity', 'id': identity_id, 'label': name,
                         'detail': f'{category}'},
                        {'type': 'entra_role', 'id': role, 'label': role,
                         'detail': f'Scope: {scope or "/"}'},
                        {'type': 'target', 'id': 'directory', 'label': 'Tenant-Wide Control',
                         'detail': 'Full directory administrative access'},
                    ],
                    description=f'{name} → {role} → Tenant-Wide Control',
                    narrative=(
                        f'{name} ({category}) holds the {role} Entra role, which provides '
                        f'administrative authority over the entire Entra ID directory. '
                        f'A compromised identity with this role can create, modify, or '
                        f'delete any directory object.'
                    ),
                    impact=f'{role} grants full directory control',
                ))
        except Exception:
            self.db._rollback()

        # 1b. Dangerous Graph API permissions
        try:
            placeholders = ','.join(['%s'] * len(_DANGEROUS_GRAPH_PERMS))
            cursor.execute(f"""
                SELECT i.identity_id, i.display_name, i.identity_category,
                       g.permission_name, g.permission_type
                FROM identities i
                JOIN graph_api_permissions g ON g.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
                  AND g.permission_name IN ({placeholders})
            """, (run_id, *_DANGEROUS_GRAPH_PERMS))
            for row in cursor.fetchall():
                identity_id, name, category, perm, perm_type = row
                is_ext = category in ('guest', 'service_principal')
                score = self._compute_score(perm, 'subscription', is_external=is_ext)
                # Graph perms are always critical-level
                score = max(score, 85)
                paths.append(self._build_path(
                    path_type='direct_escalation',
                    source_entity_id=identity_id,
                    source_entity_name=name,
                    source_entity_type=category,
                    risk_score=score,
                    path_nodes=[
                        {'type': 'identity', 'id': identity_id, 'label': name,
                         'detail': category},
                        {'type': 'permission', 'id': perm, 'label': perm,
                         'detail': f'{perm_type} permission'},
                        {'type': 'target', 'id': 'tenant', 'label': 'Tenant-Wide Control',
                         'detail': 'Can escalate to full tenant admin'},
                    ],
                    description=f'{name} → {perm} → Tenant-Wide Control',
                    narrative=(
                        f'{name} holds the {perm} ({perm_type}) permission, which '
                        f'allows direct escalation to tenant-wide administrative '
                        f'control without intermediate steps.'
                    ),
                    impact=f'Direct privilege escalation via {perm}',
                ))
        except Exception:
            self.db._rollback()

        cursor.close()
        return paths

    def _detect_ownership_chain(self, run_id: int) -> List[Dict]:
        """Identity owns an SPN that holds a privileged role.

        Path: Identity (owner) → Owned SPN → Privileged Role → Directory Control
        """
        cursor = self.db.conn.cursor()
        paths = []
        try:
            placeholders = ','.join(['%s'] * len(_DANGEROUS_ENTRA_ROLES))
            cursor.execute(f"""
                SELECT DISTINCT
                    i_owner.identity_id   AS owner_id,
                    i_owner.display_name  AS owner_name,
                    i_owner.identity_category AS owner_cat,
                    i_spn.identity_id     AS spn_id,
                    i_spn.display_name    AS spn_name,
                    era.role_name
                FROM sp_ownership o
                JOIN identities i_owner
                    ON (i_owner.object_id = o.owner_object_id OR i_owner.app_id = o.owner_object_id)
                    AND i_owner.discovery_run_id = %s
                    AND i_owner.is_microsoft_system = FALSE
                JOIN identities i_spn
                    ON i_spn.identity_id = o.identity_id
                    AND i_spn.discovery_run_id = %s
                JOIN entra_role_assignments era
                    ON era.identity_db_id = i_spn.id
                    AND era.role_name IN ({placeholders})
            """, (run_id, run_id, *_DANGEROUS_ENTRA_ROLES))
            for row in cursor.fetchall():
                owner_id, owner_name, owner_cat, spn_id, spn_name, role = row
                is_ext = owner_cat in ('guest',)
                score = self._compute_score(role, is_external=is_ext)
                # Ownership chain is indirect → slight discount
                score = max(int(score * 0.9), 50)
                paths.append(self._build_path(
                    path_type='ownership_chain',
                    source_entity_id=owner_id,
                    source_entity_name=owner_name,
                    source_entity_type=owner_cat,
                    risk_score=score,
                    path_nodes=[
                        {'type': 'identity', 'id': owner_id, 'label': owner_name,
                         'detail': f'{owner_cat} (owner)'},
                        {'type': 'owned_spn', 'id': spn_id, 'label': spn_name,
                         'detail': 'Owned service principal'},
                        {'type': 'entra_role', 'id': role, 'label': role,
                         'detail': 'Privileged role on owned SPN'},
                        {'type': 'target', 'id': 'directory', 'label': 'Directory Control',
                         'detail': 'Escalate via owned SPN credentials'},
                    ],
                    description=f'{owner_name} → owns {spn_name} → {role} → Directory Control',
                    narrative=(
                        f'{owner_name} owns {spn_name}, which holds the {role} role. '
                        f'An attacker could create new credentials on the owned SPN '
                        f'and use them to exercise its privileged role.'
                    ),
                    impact=f'Ownership of {spn_name} provides indirect {role} access',
                ))
        except Exception:
            self.db._rollback()

        cursor.close()
        return paths

    def _detect_pim_escalation(self, run_id: int) -> List[Dict]:
        """Identity eligible for dangerous roles via PIM.

        Path: Identity → PIM Eligible → Activated Role → Admin Control
        """
        cursor = self.db.conn.cursor()
        paths = []
        try:
            placeholders = ','.join(['%s'] * len(_DANGEROUS_ENTRA_ROLES))
            cursor.execute(f"""
                SELECT i.identity_id, i.display_name, i.identity_category,
                       p.role_name
                FROM identities i
                JOIN pim_eligible_assignments p ON p.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
                  AND p.role_name IN ({placeholders})
            """, (run_id, *_DANGEROUS_ENTRA_ROLES))
            for row in cursor.fetchall():
                identity_id, name, category, role = row
                score = self._compute_score(role)
                # PIM requires activation → slight discount
                score = max(int(score * 0.85), 45)
                paths.append(self._build_path(
                    path_type='pim_escalation',
                    source_entity_id=identity_id,
                    source_entity_name=name,
                    source_entity_type=category,
                    risk_score=score,
                    path_nodes=[
                        {'type': 'identity', 'id': identity_id, 'label': name,
                         'detail': category},
                        {'type': 'pim', 'id': role, 'label': f'PIM: {role}',
                         'detail': 'Eligible for privileged role activation'},
                        {'type': 'target', 'id': 'activated_role', 'label': role,
                         'detail': 'Activated role grants admin control'},
                    ],
                    description=f'{name} → PIM eligible → {role}',
                    narrative=(
                        f'{name} is eligible to activate {role} through Privileged '
                        f'Identity Management. While PIM requires justification, a '
                        f'compromised identity could activate this role and gain '
                        f'administrative control.'
                    ),
                    impact=f'Can activate {role} via PIM',
                ))
        except Exception:
            self.db._rollback()

        cursor.close()
        return paths

    def _detect_lateral_movement(self, run_id: int) -> List[Dict]:
        """Identity with broad RBAC at subscription scope enabling resource control.

        Path: Identity → Owner/Contributor → Subscription → All Resources
        """
        cursor = self.db.conn.cursor()
        paths = []
        try:
            placeholders = ','.join(['%s'] * len(_BROAD_SUB_ROLES))
            cursor.execute(f"""
                SELECT i.identity_id, i.display_name, i.identity_category,
                       ra.role_name, ra.scope
                FROM identities i
                JOIN role_assignments ra ON ra.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
                  AND ra.role_name IN ({placeholders})
                  AND ra.scope_type = 'subscription'
            """, (run_id, *_BROAD_SUB_ROLES))
            for row in cursor.fetchall():
                identity_id, name, category, role, scope = row
                is_ext = category in ('guest',)
                score = self._compute_score(role, 'subscription', is_external=is_ext)
                arc = self._count_resources_for_scope(run_id, scope)
                paths.append(self._build_path(
                    path_type='lateral_movement',
                    source_entity_id=identity_id,
                    source_entity_name=name,
                    source_entity_type=category,
                    risk_score=score,
                    path_nodes=[
                        {'type': 'identity', 'id': identity_id, 'label': name,
                         'detail': category},
                        {'type': 'rbac_role', 'id': role, 'label': f'{role}',
                         'detail': f'Subscription-level {role}'},
                        {'type': 'subscription', 'id': scope, 'label': scope[:60] if scope else 'Subscription',
                         'detail': 'All resources in subscription'},
                    ],
                    description=f'{name} → {role} → {scope[:50] if scope else "subscription"}',
                    narrative=(
                        f'{name} ({category}) holds {role} at subscription scope '
                        f'({scope[:60] if scope else "unknown"}), allowing modification '
                        f'or deletion of any resource within the subscription.'
                    ),
                    impact=f'{role} on subscription grants full resource control',
                    affected_resource_count=arc,
                ))
        except Exception:
            self.db._rollback()

        cursor.close()
        return paths

    def _detect_sensitive_data_exposure(self, run_id: int) -> List[Dict]:
        """Identity with RBAC path to classified sensitive resources.

        Path: Identity → Role → Resource Group/Subscription → Sensitive Resource
        """
        cursor = self.db.conn.cursor()
        paths = []
        try:
            # Gather classified resources
            classified = []
            for table, rtype in [('azure_storage_accounts', 'storage_account'),
                                  ('azure_key_vaults', 'key_vault')]:
                try:
                    cursor.execute(f"""
                        SELECT resource_id, name, data_classification,
                               resource_group, subscription_id
                        FROM {table}
                        WHERE discovery_run_id = %s
                          AND data_classification IS NOT NULL
                    """, (run_id,))
                    for r in cursor.fetchall():
                        classified.append({
                            'resource_id': r[0], 'name': r[1],
                            'classification': r[2], 'rg': r[3],
                            'sub': r[4], 'type': rtype,
                        })
                except Exception:
                    pass  # Table may not exist yet

            if not classified:
                cursor.close()
                return []

            # Get all identity role assignments
            cursor.execute("""
                SELECT i.identity_id, i.display_name, i.identity_category,
                       ra.role_name, ra.scope, ra.scope_type
                FROM identities i
                JOIN role_assignments ra ON ra.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
            """, (run_id,))
            assignments = cursor.fetchall()

            # Match scope hierarchy
            seen = set()
            for identity_id, name, category, role_name, scope, scope_type in assignments:
                scope_lower = (scope or '').lower()
                for res in classified:
                    res_sub = (res['sub'] or '').lower()
                    res_rg = (res['rg'] or '').lower()
                    res_id = (res['resource_id'] or '').lower()

                    match = False
                    if scope_type == 'subscription' and res_sub and res_sub in scope_lower:
                        match = True
                    elif scope_type == 'resource_group' and res_rg and res_rg.lower() in scope_lower:
                        match = True
                    elif res_id and res_id in scope_lower:
                        match = True

                    if match:
                        key = (identity_id, res['resource_id'])
                        if key in seen:
                            continue
                        seen.add(key)

                        is_highly_sensitive = (res['classification'] or '').lower() in _SENSITIVE_CLASSIFICATIONS
                        is_ext = category in ('guest',)
                        score = self._compute_score(
                            role_name, scope_type,
                            is_external=is_ext,
                            has_sensitive_target=is_highly_sensitive,
                        )

                        paths.append(self._build_path(
                            path_type='sensitive_data_exposure',
                            source_entity_id=identity_id,
                            source_entity_name=name,
                            source_entity_type=category,
                            risk_score=score,
                            path_nodes=[
                                {'type': 'identity', 'id': identity_id, 'label': name,
                                 'detail': category},
                                {'type': 'rbac_role', 'id': role_name, 'label': role_name,
                                 'detail': f'{scope_type} scope'},
                                {'type': res['type'], 'id': res['resource_id'], 'label': res['name'],
                                 'detail': f'Classification: {res["classification"]}'},
                            ],
                            description=f'{name} → {role_name} → {res["name"]} ({res["classification"]})',
                            narrative=(
                                f'{name} ({category}) has {role_name} access to '
                                f'{res["name"]} classified as {res["classification"]} '
                                f'via {scope_type} scope. This creates an exposure path '
                                f'to sensitive data.'
                            ),
                            impact=f'Access to {res["classification"]} data via {role_name}',
                            affected_resource_count=1,
                        ))
        except Exception:
            self.db._rollback()

        cursor.close()
        return paths

    def _detect_external_identity_risk(self, run_id: int) -> List[Dict]:
        """Guest/external identities with any privileged RBAC or Entra roles.

        Path: External Identity → Privileged Role → Internal Resources
        """
        cursor = self.db.conn.cursor()
        paths = []

        # Guests with RBAC roles at subscription or management group scope
        try:
            cursor.execute("""
                SELECT i.identity_id, i.display_name,
                       ra.role_name, ra.scope, ra.scope_type
                FROM identities i
                JOIN role_assignments ra ON ra.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
                  AND i.identity_category = 'guest'
                  AND ra.scope_type IN ('subscription', 'management_group')
            """, (run_id,))
            for row in cursor.fetchall():
                identity_id, name, role, scope, scope_type = row
                score = self._compute_score(role, scope_type, is_external=True)
                paths.append(self._build_path(
                    path_type='external_identity_risk',
                    source_entity_id=identity_id,
                    source_entity_name=name,
                    source_entity_type='guest',
                    risk_score=score,
                    path_nodes=[
                        {'type': 'identity', 'id': identity_id, 'label': name,
                         'detail': 'External guest identity'},
                        {'type': 'rbac_role', 'id': role, 'label': role,
                         'detail': f'{scope_type}-level role'},
                        {'type': 'target', 'id': scope, 'label': scope[:60] if scope else 'Internal Resources',
                         'detail': 'Internal resource access from external identity'},
                    ],
                    description=f'Guest {name} → {role} → {scope_type} scope',
                    narrative=(
                        f'External guest {name} holds {role} at {scope_type} scope '
                        f'({scope[:50] if scope else "unknown"}). External identities '
                        f'with broad internal access represent a supply-chain or B2B risk.'
                    ),
                    impact=f'External identity with {role} on {scope_type}',
                ))
        except Exception:
            self.db._rollback()

        cursor.close()
        return paths
