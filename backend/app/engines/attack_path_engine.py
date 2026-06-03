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

        # Load valid identity_ids for source_entity validation
        valid_ids = self._load_valid_identity_ids(run_id)
        logger.info(f"Attack path engine: {len(valid_ids)} identities for run #{run_id}")

        detectors = [
            ('direct_escalation', self._detect_direct_escalation),
            ('ownership_chain', self._detect_ownership_chain),
            ('pim_escalation', self._detect_pim_escalation),
            ('lateral_movement', self._detect_lateral_movement),
            ('sensitive_data_exposure', self._detect_sensitive_data_exposure),
            ('external_identity_risk', self._detect_external_identity_risk),
            ('ai_agent_exfiltration', self._detect_ai_agent_exfiltration),
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
                else:
                    logger.info(f"  Attack path '{name}': 0 path(s)")
            except Exception as e:
                logger.error(f"  Attack path detector '{name}' failed: {e}")

        # Validate: all source_entity_ids reference real identities
        if valid_ids:
            pre_count = len(all_paths)
            all_paths = [p for p in all_paths if p['source_entity_id'] in valid_ids]
            orphaned = pre_count - len(all_paths)
            if orphaned > 0:
                logger.warning(f"  Dropped {orphaned} attack path(s) with orphaned source_entity_id")

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

        # Extract target resource from last node in the path chain
        target_node = path_nodes[-1] if path_nodes else {}

        return {
            'path_type': path_type,
            'source_entity_id': source_entity_id,
            'source_entity_name': source_entity_name,
            'source_entity_type': source_entity_type,
            'risk_score': risk_score,
            'severity': _severity_from_score(risk_score),
            'path_nodes': path_nodes,
            'path_length': len(path_nodes),
            'path_fingerprint': fp,
            'description': description,
            'narrative': narrative or '',
            'impact': impact or '',
            'affected_resource_count': affected_resource_count,
            'target_resource_id': target_node.get('id', ''),
            'target_resource_type': target_node.get('type', ''),
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

    def _load_valid_identity_ids(self, run_id: int) -> set:
        """Load all identity_ids for a run to validate source_entity references."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("SELECT identity_id FROM identities WHERE discovery_run_id = %s", (run_id,))
            ids = {row[0] for row in cursor.fetchall()}
            cursor.close()
            return ids
        except Exception as e:
            logger.warning(f"Failed to load identity_ids for validation: {e}")
            return set()

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
                       g.permission_name, g.risk_level
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

    # ------------------------------------------------------------------
    # AG-178 — AI Agent Exfiltration chain detector
    # ------------------------------------------------------------------

    def _detect_ai_agent_exfiltration(self, run_id: int) -> List[Dict]:
        """AG-178: AI-agent → MI → KV secret → Storage → classified data → egress.

        Detects the canonical AI-agent exfiltration kill-chain:
          0. ai_agent (identity from agent_classifications)
          1. managed_identity (T1078.004)
          2. rbac_role (role linking MI to KV / storage)
          3. key_vault (with secrets_total + public_network_access)
          4. kv_secret (T1552.001) — synthesized aggregate
          5. storage_account (T1530, only if classified PHI/PCI/PII/HR/SOURCE)
          6. network_egress (T1041, T1567) — only if public_blob_access=True
             OR default_network_action='Allow'

        MITRE techniques are sourced via enrich_path_node_with_mitre.
        Data classification chip comes from constants.data_classification.
        Scope matching uses services.access_resolution.resolve_agent_resource_access.
        """
        from app.constants.data_classification import classify_resource
        from app.constants.mitre import enrich_path_node_with_mitre
        from app.services.access_resolution import resolve_agent_resource_access

        # AG-178 exfil target classifications: only chains terminating in one of
        # these classes are emitted (others are out-of-scope for this detector).
        _EXFIL_CLASSES = {"PHI", "PCI", "PII", "HR", "SOURCE"}

        org_id = getattr(self.db, '_organization_id', None)
        paths: List[Dict] = []
        cursor = self.db.conn.cursor()

        # ── 1. Find AI agents in this run ───────────────────────────────
        # AI agents are identities flagged by agent_classifications with type
        # 'ai_agent' or 'possible_ai_agent'. We need identity_db_id (FK for
        # role_assignments) and identity_id (external UUID for source_entity_id).
        try:
            cursor.execute("SAVEPOINT ag178_load_agents")
            cursor.execute("""
                SELECT i.id, i.identity_id, i.display_name, i.identity_category,
                       ac.agent_identity_type, ac.detected_platform,
                       ac.classification_confidence
                FROM identities i
                JOIN agent_classifications ac ON ac.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                  AND ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
                  AND i.is_microsoft_system = FALSE
            """, (run_id,))
            agents = cursor.fetchall()
            cursor.execute("RELEASE SAVEPOINT ag178_load_agents")
        except Exception as e:
            logger.debug(f"AG-178: agent_classifications query failed: {e}")
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT ag178_load_agents")
            except Exception:
                self.db._rollback()
            cursor.close()
            return []

        if not agents:
            cursor.close()
            return []

        # ── 2. Load this run's Key Vaults (need org_id-scoped query) ────
        key_vaults: List[dict] = []
        try:
            cursor.execute("SAVEPOINT ag178_load_kv")
            if org_id is not None:
                cursor.execute("""
                    SELECT resource_id, name, subscription_id, resource_group,
                           secrets_total, public_network_access,
                           default_network_action, private_endpoint_count
                    FROM azure_key_vaults
                    WHERE discovery_run_id = %s
                      AND organization_id = %s
                """, (run_id, org_id))
            else:
                cursor.execute("""
                    SELECT resource_id, name, subscription_id, resource_group,
                           secrets_total, public_network_access,
                           default_network_action, private_endpoint_count
                    FROM azure_key_vaults
                    WHERE discovery_run_id = %s
                """, (run_id,))
            for row in cursor.fetchall():
                key_vaults.append({
                    'resource_id': row[0],
                    'name': row[1],
                    'subscription_id': row[2],
                    'resource_group': row[3],
                    'secrets_total': row[4] or 0,
                    'public_network_access': row[5],
                    'default_network_action': row[6],
                    'private_endpoint_count': row[7] or 0,
                })
            cursor.execute("RELEASE SAVEPOINT ag178_load_kv")
        except Exception as e:
            logger.debug(f"AG-178: key_vaults query failed: {e}")
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT ag178_load_kv")
            except Exception:
                self.db._rollback()

        # ── 3. Load this run's Storage Accounts with non-null classifications.
        # Only classified storage participates in an exfil chain — un-classified
        # accounts are not "sensitive data" and the chain doesn't terminate.
        storage_accounts: List[dict] = []
        try:
            cursor.execute("SAVEPOINT ag178_load_storage")
            if org_id is not None:
                cursor.execute("""
                    SELECT resource_id, name, subscription_id, resource_group,
                           public_blob_access, default_network_action,
                           private_endpoint_count, data_classification,
                           classification_confidence, classification_source,
                           tags
                    FROM azure_storage_accounts
                    WHERE discovery_run_id = %s
                      AND organization_id = %s
                      AND data_classification IS NOT NULL
                """, (run_id, org_id))
            else:
                cursor.execute("""
                    SELECT resource_id, name, subscription_id, resource_group,
                           public_blob_access, default_network_action,
                           private_endpoint_count, data_classification,
                           classification_confidence, classification_source,
                           tags
                    FROM azure_storage_accounts
                    WHERE discovery_run_id = %s
                      AND data_classification IS NOT NULL
                """, (run_id,))
            for row in cursor.fetchall():
                cls_id = (row[7] or '').upper()
                if cls_id not in _EXFIL_CLASSES:
                    # Outside the AG-178 exfil scope (e.g. FINANCIAL/CONFIDENTIAL)
                    continue
                # Re-validate the classification through the SSOT taxonomy. If
                # the stored value is a known class we keep it; if not, fall
                # back to classify_resource() against name+tags (the SSOT).
                tags = row[10] if isinstance(row[10], dict) else None
                cls_result = classify_resource(row[1], tags, None)
                if cls_result and cls_result['classification'] in _EXFIL_CLASSES:
                    classification = cls_result['classification']
                    cls_confidence = cls_result['confidence']
                    cls_source = cls_result['source']
                else:
                    # Trust the stored classification only if SSOT agrees that
                    # it's a recognized class. No fabricated defaults.
                    classification = cls_id
                    cls_confidence = row[8] or 'medium'
                    cls_source = row[9] or 'stored'

                storage_accounts.append({
                    'resource_id': row[0],
                    'name': row[1],
                    'subscription_id': row[2],
                    'resource_group': row[3],
                    'public_blob_access': bool(row[4]) if row[4] is not None else False,
                    'default_network_action': row[5],
                    'private_endpoint_count': row[6] or 0,
                    'classification': classification,
                    'classification_confidence': cls_confidence,
                    'classification_source': cls_source,
                })
            cursor.execute("RELEASE SAVEPOINT ag178_load_storage")
        except Exception as e:
            logger.debug(f"AG-178: storage_accounts query failed: {e}")
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT ag178_load_storage")
            except Exception:
                self.db._rollback()

        # If we have no KV with secrets AND no classified storage, the chain
        # has no payload — nothing to emit.
        kv_with_secrets = [kv for kv in key_vaults if kv['secrets_total'] > 0]
        if not kv_with_secrets and not storage_accounts:
            cursor.close()
            return []

        # ── 4. For each AI agent, build chains via access_resolution ─────
        for (id_db_id, identity_id, display_name, category,
             agent_type, platform, agent_conf) in agents:

            # 4a. Determine which KV(s) and storage(s) this agent can reach.
            # We use the canonical resolver — single source of truth for
            # "does identity X reach scope Y."
            reachable_kvs: list[tuple[dict, dict]] = []
            for kv in kv_with_secrets:
                access = resolve_agent_resource_access(
                    cursor, id_db_id, kv['resource_id']
                )
                if access is not None:
                    reachable_kvs.append((kv, access))

            reachable_storage: list[tuple[dict, dict]] = []
            for sa in storage_accounts:
                access = resolve_agent_resource_access(
                    cursor, id_db_id, sa['resource_id']
                )
                if access is not None:
                    reachable_storage.append((sa, access))

            # AG-178 requires BOTH a KV-secret stage AND a classified-storage
            # stage. If either is missing for this agent, no chain.
            if not reachable_kvs or not reachable_storage:
                continue

            # 4b. Emit one chain per (kv, storage) pair the agent can reach.
            for kv, kv_access in reachable_kvs:
                for sa, sa_access in reachable_storage:

                    # Egress node only fires if storage has open egress.
                    egress_open = (
                        sa['public_blob_access']
                        or (sa['default_network_action'] or '').lower() == 'allow'
                    )

                    # ── Node 0: ai_agent ─────────────────────────────
                    node0 = {
                        'node_type': 'ai_agent',
                        'type': 'ai_agent',
                        'id': identity_id,
                        'label': display_name or identity_id,
                        'description': (
                            f"{agent_type or 'AI agent'} "
                            + (f"({platform})" if platform else "")
                        ).strip(),
                        'mitre_techniques': [],
                        'evidence_id': f'agent_cls:{identity_id}',
                        'severity': 'high',
                        'risk_contribution': 15,
                        'detail': {
                            'agent_identity_type': agent_type,
                            'detected_platform': platform,
                            'classification_confidence': agent_conf,
                            'identity_category': category,
                        },
                    }

                    # ── Node 1: managed_identity (T1078.004) ─────────
                    mi_mitre = enrich_path_node_with_mitre('managed_identity')
                    node1 = {
                        'node_type': 'managed_identity',
                        'type': 'managed_identity',
                        'id': identity_id,
                        'label': display_name or identity_id,
                        'description': (
                            f"Workload identity ({category}) used by the AI agent "
                            f"to authenticate to Azure."
                        ),
                        'mitre_techniques': mi_mitre,
                        'evidence_id': f'identity:{identity_id}',
                        'severity': 'high',
                        'risk_contribution': 10,
                    }

                    # ── Node 2: rbac_role linking MI → KV ─────────────
                    # We tag the role node with techniques driven by the KV
                    # role name (e.g. "Key Vault Administrator" yields
                    # T1552.001 + T1555.006 via ROLE_TO_TECHNIQUES).
                    kv_role_name = kv_access['role_name']
                    role_kv_mitre = enrich_path_node_with_mitre(
                        'role_assignment', role_name=kv_role_name,
                    )
                    node2 = {
                        'node_type': 'rbac_role',
                        'type': 'rbac_role',
                        'id': f'{kv_role_name}@{kv_access["scope"]}',
                        'label': kv_role_name,
                        'description': (
                            f"{kv_role_name} ({kv_access['access_level']}) "
                            f"derived via {kv_access['derivation_path']} "
                            f"on {kv['name']}."
                        ),
                        'mitre_techniques': role_kv_mitre,
                        'evidence_id': f'rbac:{id_db_id}:{kv["resource_id"]}',
                        'severity': 'high' if kv_access['access_level'] == 'owner' else 'medium',
                        'risk_contribution': (
                            20 if kv_access['access_level'] == 'owner' else 12
                        ),
                    }

                    # ── Node 3: key_vault ─────────────────────────────
                    kv_pna = (kv['public_network_access'] or '').lower()
                    kv_public_exposed = (
                        kv_pna == 'enabled'
                        and kv['private_endpoint_count'] == 0
                    )
                    node3 = {
                        'node_type': 'key_vault',
                        'type': 'key_vault',
                        'id': kv['resource_id'],
                        'label': kv['name'],
                        'description': (
                            f"Vault holds {kv['secrets_total']} secret(s); "
                            f"public_network_access={kv['public_network_access']}, "
                            f"default_network_action={kv['default_network_action']}."
                        ),
                        'mitre_techniques': [],
                        'evidence_id': f'kv:{kv["resource_id"]}',
                        'severity': 'high' if kv_public_exposed else 'medium',
                        'risk_contribution': 10 if kv_public_exposed else 5,
                        'detail': {
                            'secrets_total': kv['secrets_total'],
                            'public_network_access': kv['public_network_access'],
                            'default_network_action': kv['default_network_action'],
                            'private_endpoint_count': kv['private_endpoint_count'],
                        },
                    }

                    # ── Node 4: kv_secret (synthesized aggregate, T1552.001) ─
                    secret_mitre = enrich_path_node_with_mitre('kv_secret')
                    node4 = {
                        'node_type': 'kv_secret',
                        'type': 'kv_secret',
                        'id': f'{kv["resource_id"]}#secrets',
                        'label': f'{kv["secrets_total"]} secret(s) in {kv["name"]}',
                        'description': (
                            "Aggregate of all readable secrets in the vault — "
                            "compromising the agent yields every secret's "
                            "credentials for lateral pivot."
                        ),
                        'mitre_techniques': secret_mitre,
                        'evidence_id': f'kv_secrets:{kv["resource_id"]}',
                        'severity': 'critical',
                        'risk_contribution': 15,
                    }

                    # ── Node 5: storage_account (T1530) ───────────────
                    sa_mitre = enrich_path_node_with_mitre(
                        'storage_account',
                        has_sensitive_data=True,  # filtered to classified only
                    )
                    # Role techniques for the storage-side role too
                    sa_role_name = sa_access['role_name']
                    sa_role_mitre = enrich_path_node_with_mitre(
                        'role_assignment', role_name=sa_role_name,
                    )
                    # Merge, deduping by technique id
                    sa_all_mitre = sa_mitre + [
                        m for m in sa_role_mitre
                        if m['id'] not in {x['id'] for x in sa_mitre}
                    ]
                    node5 = {
                        'node_type': 'storage_account',
                        'type': 'storage_account',
                        'id': sa['resource_id'],
                        'label': sa['name'],
                        'description': (
                            f"Storage account classified {sa['classification']} "
                            f"(confidence={sa['classification_confidence']}, "
                            f"source={sa['classification_source']}); "
                            f"reached via {sa_role_name} "
                            f"({sa_access['access_level']})."
                        ),
                        'mitre_techniques': sa_all_mitre,
                        'evidence_id': f'storage:{sa["resource_id"]}',
                        'severity': 'critical',
                        'risk_contribution': 20,
                        'detail': {
                            'classification': sa['classification'],
                            'classification_confidence': sa['classification_confidence'],
                            'classification_source': sa['classification_source'],
                            'public_blob_access': sa['public_blob_access'],
                            'default_network_action': sa['default_network_action'],
                            'private_endpoint_count': sa['private_endpoint_count'],
                            'sa_role_name': sa_role_name,
                            'sa_access_level': sa_access['access_level'],
                            # records_estimate column not yet present (T2A
                            # migration adds record_count_estimate) → NULL.
                            'records_estimate': None,
                        },
                    }

                    chain_nodes = [node0, node1, node2, node3, node4, node5]

                    # ── Node 6: network_egress (T1041, T1567) — optional ─
                    if egress_open:
                        egress_mitre = enrich_path_node_with_mitre(
                            'network_egress', egress_open=True,
                        )
                        node6 = {
                            'node_type': 'network_egress',
                            'type': 'network_egress',
                            'id': f'{sa["resource_id"]}#egress',
                            'label': 'Open egress',
                            'description': (
                                "Storage permits outbound exfil: "
                                + ("public blob access enabled. "
                                   if sa['public_blob_access'] else "")
                                + (f"default network action = "
                                   f"{sa['default_network_action']}."
                                   if (sa['default_network_action'] or '').lower() == 'allow'
                                   else "")
                            ).strip(),
                            'mitre_techniques': egress_mitre,
                            'evidence_id': f'egress:{sa["resource_id"]}',
                            'severity': 'critical',
                            'risk_contribution': 15,
                        }
                        chain_nodes.append(node6)

                    # ── 5. Score, severity, dedup-fingerprint ─────────
                    risk_score = sum(
                        int(n.get('risk_contribution', 0)) for n in chain_nodes
                    )
                    risk_score = min(risk_score, 100)

                    # records_estimate stays None until T2A migration adds
                    # record_count_estimate to azure_storage_accounts. Until
                    # then we cannot legitimately compute it, so severity
                    # uses egress-openness + classification as the proxy.
                    records_estimate = None
                    if records_estimate is not None and records_estimate > 10000:
                        severity = 'critical'
                    elif egress_open or sa['classification'] in ('PHI', 'PCI'):
                        severity = 'critical'
                    else:
                        severity = 'high'

                    fingerprint = compute_path_fingerprint(
                        identity_id, 'ai_agent_exfiltration', chain_nodes,
                    )

                    description = (
                        f'AI agent {display_name or identity_id} → '
                        f'{kv["name"]} secret → {sa["name"]} '
                        f'({sa["classification"]})'
                        + (' → open egress' if egress_open else '')
                    )

                    paths.append({
                        'path_type': 'ai_agent_exfiltration',
                        'source_entity_id': identity_id,
                        'source_entity_name': display_name or identity_id,
                        'source_entity_type': 'ai_agent',
                        'target_resource_id': sa['resource_id'],
                        'target_resource_type': 'storage_account',
                        'severity': severity,
                        'risk_score': risk_score,
                        'path_nodes': chain_nodes,
                        'path_length': len(chain_nodes),
                        'path_fingerprint': fingerprint,
                        'description': description,
                        # Argus generates the narrative lazily on first detail view.
                        'narrative': None,
                        'impact': (
                            f'Exfiltration of {sa["classification"]} data via '
                            f'{kv["name"]} secrets and '
                            + ('open egress' if egress_open else 'reachable storage')
                        ),
                        'affected_resource_count': 2,  # 1 KV + 1 storage
                        'organization_id': org_id,
                        'discovery_run_id': run_id,
                    })

        cursor.close()
        return paths
