"""
Phase 6: Access Review Engine

Generates review assignments by auto-populating from privileged identities,
RBAC roles, Entra roles, attack paths, blast radius, and security findings.

This engine is called both on-demand (when an admin creates a review) and
periodically (quarterly/monthly scheduled reviews). It reads from existing
tables (identities, role_assignments, entra_role_assignments, attack_paths,
blast_radius_results, security_findings) and writes to review_assignments.

Safety:
- SELECT-only queries against upstream tables
- Organization-scoped via Database RLS
- MAX_ASSIGNMENTS_PER_REVIEW cap prevents runaway generation
"""

import logging
from collections import defaultdict
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Safety limits ──────────────────────────────────────────────────────

MAX_ASSIGNMENTS_PER_REVIEW = 500

# ── Privileged roles that ALWAYS trigger a review assignment ──────────

_PRIVILEGED_ENTRA_ROLES = {
    'Global Administrator', 'Privileged Role Administrator',
    'Privileged Authentication Administrator', 'Application Administrator',
    'Cloud Application Administrator', 'User Administrator',
    'Exchange Administrator', 'Hybrid Identity Administrator',
}

_PRIVILEGED_RBAC_ROLES = {
    'Owner', 'User Access Administrator', 'Contributor',
    'Key Vault Secrets Officer', 'Key Vault Administrator',
}

# ── Scope keywords for review description ────────────────────────────

_SCOPE_LABELS = {
    'privileged': 'Privileged identities (Entra admin + RBAC Owner/UAA/Contributor)',
    'all': 'All identities with any role assignment',
    'custom': 'Custom-scoped identity set',
}


class AccessReviewEngine:
    """Generates review assignments for an access review campaign."""

    def __init__(self, db):
        self.db = db

    def generate_assignments(self, review_id: int, scope: str = 'privileged',
                             custom_identity_ids: Optional[List[int]] = None) -> List[Dict]:
        """
        Generate review_assignments for a given access_review.

        Args:
            review_id: ID of the access_reviews row
            scope: 'privileged', 'all', or 'custom'
            custom_identity_ids: If scope='custom', only these identity IDs

        Returns:
            List of assignment dicts ready for DB insert
        """
        logger.info(f"Generating assignments for review #{review_id}, scope={scope}")

        # 1. Load identity-role pairs based on scope
        identity_roles = self._load_identity_roles(scope, custom_identity_ids)
        logger.info(f"Loaded {len(identity_roles)} identity-role pairs")

        if not identity_roles:
            return []

        # 2. Load enrichment data (attack paths, blast radius, findings)
        identity_ids = list({ir['identity_id'] for ir in identity_roles})
        attack_path_counts = self._load_attack_path_counts(identity_ids)
        blast_radius_scores = self._load_blast_radius_scores(identity_ids)
        finding_counts = self._load_finding_counts(identity_ids)

        # 3. Build assignments
        assignments = []
        for ir in identity_roles:
            if len(assignments) >= MAX_ASSIGNMENTS_PER_REVIEW:
                logger.warning(f"Hit MAX_ASSIGNMENTS_PER_REVIEW ({MAX_ASSIGNMENTS_PER_REVIEW}), truncating")
                break

            iid = ir['identity_id']
            br_score = blast_radius_scores.get(iid, 0)
            ap_count = attack_path_counts.get(iid, 0)
            f_count = finding_counts.get(iid, 0)

            risk_snapshot = {
                'blast_radius_score': br_score,
                'attack_path_count': ap_count,
                'finding_count': f_count,
            }

            assignment = {
                'review_id': review_id,
                'identity_id': iid,
                'identity_name': ir.get('identity_name'),
                'identity_type': ir.get('identity_type'),
                'role_name': ir['role_name'],
                'role_type': ir['role_type'],
                'scope': ir.get('scope'),
                'risk_level': ir.get('risk_level'),
                'risk_score': ir.get('risk_score', 0),
                'blast_radius_score': br_score,
                'attack_path_count': ap_count,
                'finding_count': f_count,
                'risk_snapshot': risk_snapshot,
            }
            assignments.append(assignment)

        logger.info(f"Generated {len(assignments)} assignments for review #{review_id}")
        return assignments

    # ── Data loaders ───────────────────────────────────────────────────

    def _load_identity_roles(self, scope: str,
                             custom_ids: Optional[List[int]] = None) -> List[Dict]:
        """Load identity-role pairs from RBAC + Entra role assignments."""
        pairs = []

        # RBAC roles
        try:
            pairs.extend(self._load_rbac_roles(scope, custom_ids))
        except Exception as e:
            logger.error(f"Error loading RBAC roles: {e}")

        # Entra roles
        try:
            pairs.extend(self._load_entra_roles(scope, custom_ids))
        except Exception as e:
            logger.error(f"Error loading Entra roles: {e}")

        return pairs

    def _load_rbac_roles(self, scope: str,
                         custom_ids: Optional[List[int]] = None) -> List[Dict]:
        """Load RBAC role assignments, optionally filtered to privileged roles."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)

        conditions = []
        params = []

        if scope == 'privileged':
            placeholders = ','.join(['%s'] * len(_PRIVILEGED_RBAC_ROLES))
            conditions.append(f"ra.role_name IN ({placeholders})")
            params.extend(_PRIVILEGED_RBAC_ROLES)
        elif scope == 'custom' and custom_ids:
            placeholders = ','.join(['%s'] * len(custom_ids))
            conditions.append(f"i.id IN ({placeholders})")
            params.extend(custom_ids)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        cursor.execute(f"""
            SELECT DISTINCT i.id as identity_id, i.display_name as identity_name,
                   i.identity_category as identity_type,
                   ra.role_name, ra.scope,
                   i.risk_level, i.risk_score
            FROM identities i
            JOIN role_assignments ra ON ra.identity_db_id = i.id
            {where}
            ORDER BY i.risk_score DESC NULLS LAST
        """, params)
        rows = cursor.fetchall()
        cursor.close()

        return [
            {**dict(r), 'role_type': 'rbac'}
            for r in rows
        ]

    def _load_entra_roles(self, scope: str,
                          custom_ids: Optional[List[int]] = None) -> List[Dict]:
        """Load Entra directory role assignments, optionally filtered to privileged roles."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)

        conditions = []
        params = []

        if scope == 'privileged':
            placeholders = ','.join(['%s'] * len(_PRIVILEGED_ENTRA_ROLES))
            conditions.append(f"era.role_name IN ({placeholders})")
            params.extend(_PRIVILEGED_ENTRA_ROLES)
        elif scope == 'custom' and custom_ids:
            placeholders = ','.join(['%s'] * len(custom_ids))
            conditions.append(f"i.id IN ({placeholders})")
            params.extend(custom_ids)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        cursor.execute(f"""
            SELECT DISTINCT i.id as identity_id, i.display_name as identity_name,
                   i.identity_category as identity_type,
                   era.role_name, era.scope,
                   i.risk_level, i.risk_score
            FROM identities i
            JOIN entra_role_assignments era ON era.identity_db_id = i.id
            {where}
            ORDER BY i.risk_score DESC NULLS LAST
        """, params)
        rows = cursor.fetchall()
        cursor.close()

        return [
            {**dict(r), 'role_type': 'entra'}
            for r in rows
        ]

    def _load_attack_path_counts(self, identity_ids: List[int]) -> Dict[int, int]:
        """Count attack paths per identity."""
        if not identity_ids:
            return {}
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        try:
            placeholders = ','.join(['%s'] * len(identity_ids))
            cursor.execute(f"""
                SELECT source_entity_id::integer as iid, COUNT(*) as cnt
                FROM attack_paths
                WHERE source_entity_id IN ({placeholders})
                GROUP BY source_entity_id
            """, identity_ids)
            return {r['iid']: r['cnt'] for r in cursor.fetchall()}
        except Exception:
            return {}
        finally:
            cursor.close()

    def _load_blast_radius_scores(self, identity_ids: List[int]) -> Dict[int, int]:
        """Get blast radius risk_score per identity."""
        if not identity_ids:
            return {}
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        try:
            placeholders = ','.join(['%s'] * len(identity_ids))
            cursor.execute(f"""
                SELECT identity_id, risk_score
                FROM blast_radius_results
                WHERE identity_id IN ({placeholders})
            """, identity_ids)
            return {r['identity_id']: r['risk_score'] for r in cursor.fetchall()}
        except Exception:
            return {}
        finally:
            cursor.close()

    def _load_finding_counts(self, identity_ids: List[int]) -> Dict[int, int]:
        """Count open security findings per identity entity_id."""
        if not identity_ids:
            return {}
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        try:
            # entity_id on security_findings is text, identity_id is integer
            str_ids = [str(iid) for iid in identity_ids]
            placeholders = ','.join(['%s'] * len(str_ids))
            cursor.execute(f"""
                SELECT entity_id, COUNT(*) as cnt
                FROM security_findings
                WHERE entity_id IN ({placeholders}) AND status = 'open'
                GROUP BY entity_id
            """, str_ids)
            return {int(r['entity_id']): r['cnt'] for r in cursor.fetchall()}
        except Exception:
            return {}
        finally:
            cursor.close()

    def auto_generate_evidence(self, assignment_id: int, identity_id: int) -> List[Dict]:
        """
        Auto-populate review_evidence for a given assignment from
        attack paths, blast radius, and findings.
        """
        evidence = []

        # Attack paths
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT id, path_type, severity, source_entity_name, impact
                FROM attack_paths
                WHERE source_entity_id = %s
                ORDER BY severity_rank ASC
                LIMIT 5
            """, (str(identity_id),))
            for row in cursor.fetchall():
                evidence.append({
                    'assignment_id': assignment_id,
                    'evidence_type': 'attack_path',
                    'source_id': str(row['id']),
                    'title': f"Attack path: {row['path_type']}",
                    'detail': {
                        'severity': row.get('severity'),
                        'impact': row.get('impact'),
                    },
                })
            cursor.close()
        except Exception as e:
            logger.debug(f"Could not load attack path evidence: {e}")

        # Blast radius
        try:
            br = self.db.get_blast_radius_for_identity(identity_id)
            if br:
                evidence.append({
                    'assignment_id': assignment_id,
                    'evidence_type': 'blast_radius',
                    'source_id': str(br.get('id', '')),
                    'title': f"Blast radius: {br.get('identity_exposure_level', 'N/A')} exposure",
                    'detail': {
                        'risk_score': br.get('risk_score'),
                        'reachable_resource_count': br.get('reachable_resource_count'),
                        'sensitive_resource_count': br.get('sensitive_resource_count'),
                    },
                })
        except Exception as e:
            logger.debug(f"Could not load blast radius evidence: {e}")

        # Security findings
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT id, finding_type, severity, title
                FROM security_findings
                WHERE entity_id = %s AND status = 'open'
                ORDER BY risk_score DESC
                LIMIT 5
            """, (str(identity_id),))
            for row in cursor.fetchall():
                evidence.append({
                    'assignment_id': assignment_id,
                    'evidence_type': 'finding',
                    'source_id': str(row['id']),
                    'title': row['title'],
                    'detail': {
                        'finding_type': row['finding_type'],
                        'severity': row.get('severity'),
                    },
                })
            cursor.close()
        except Exception as e:
            logger.debug(f"Could not load finding evidence: {e}")

        return evidence
