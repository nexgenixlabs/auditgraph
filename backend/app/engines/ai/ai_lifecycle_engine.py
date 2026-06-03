"""AG-181 (Tier 2C): AI Agent Lifecycle + Drift Engine.

Per-AI-agent J/M/L event detection. For every AI agent classified in the
current discovery run, compare its state against the previous run and emit
typed lifecycle events into ``ai_agent_lifecycle_events``.

Detected event types (taxonomy lives in
``backend/app/engines/drift_events_ai.py`` — this engine is a *consumer* of
those constants, never a re-definer):

  - AI_AGENT_JOINER          — first time we see this identity as an AI agent
  - AI_AGENT_LEAVER          — was an AI agent last run, missing/disabled now
  - AI_AGENT_MOVER           — scope of role_assignments changed materially
  - MODEL_CHANGED            — agent_classifications.model_name differs
  - MODEL_VERSION_BUMPED     — same family, different version (gpt-4 → gpt-4o)
  - AI_PERMISSIONS_ESCALATED — gained an access tier OR an Owner-equivalent role
  - AI_OWNER_CHANGED         — owner_display_name_at_classify differs
  - DEPLOYMENT_ADDED         — new deployment_name under this agent's account
  - DEPLOYMENT_REMOVED       — deployment that existed last run is gone
  - CAPACITY_EXPANDED        — sku_capacity increased for an existing deployment

Design rules:
  - First run (``prev_run_id is None``) only emits AI_AGENT_JOINER events.
    Lifecycle drift requires two snapshots; we never fabricate "before"
    state from nothing.
  - UPSERT on the (organization_id, identity_db_id, discovery_run_id,
    event_type) UNIQUE — re-running the engine for the same pair of runs is
    idempotent.
  - Every cluster of queries is wrapped in a SAVEPOINT so a single bad query
    can't poison the rest of the engine pass.
  - MITRE techniques are attached via ``enrich_path_node_with_mitre`` — we
    never invent new technique IDs here.

Public surface:
  - ``AILifecycleEngine(db).analyze(current_run_id, prev_run_id, organization_id)``
  - ``AILifecycleEngine(db).get_lifecycle_for_identity(identity_db_id, organization_id, limit=100)``
  - ``AILifecycleEngine(db).get_drift_for_identity(identity_db_id, current_run_id, prev_run_id, organization_id)``
  - ``AILifecycleEngine(db).get_jml_snapshot(organization_id, window_days=7)``
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from app.constants.mitre import enrich_path_node_with_mitre
from app.engines.drift_events_ai import (
    AI_EVENT_SEVERITY,
    AIDriftEventType,
)
from app.services.access_resolution import (
    _level_from_role,
    _LEVEL_RANK,
)

logger = logging.getLogger(__name__)


# ── Role categories used for AI_PERMISSIONS_ESCALATED ─────────────────────
# Owner-equivalent or tenant-broad role names that ALWAYS count as an
# escalation when newly attached to an AI agent (even if the existing
# strongest access tier didn't change — gaining UAA when you only had
# Contributor before is still an escalation worth flagging).
_OWNER_EQUIV_ROLES: frozenset[str] = frozenset({
    'Owner',
    'Contributor',
    'User Access Administrator',
    'Role Based Access Control Administrator',
    'Key Vault Administrator',
})


# Material mover threshold — fraction of resource scopes that must have
# turned over for AI_AGENT_MOVER to fire. Per the spec: >50% delta in
# touched resource_ids. Computed as |symmetric_diff| / |union|.
_MOVER_RESOURCE_DELTA = 0.5


# ── JSON helpers for snapshot columns ─────────────────────────────────────

def _json_default(obj: Any) -> Any:
    """JSON encoder for datetimes / sets so before/after snapshots survive
    psycopg2's JSONB adapter."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, set):
        return sorted(obj)
    return str(obj)


def _to_jsonb(value: Optional[Dict[str, Any]]) -> Optional[str]:
    """Serialize a dict for a JSONB column. None → None (let DB store NULL)."""
    if value is None:
        return None
    return json.dumps(value, default=_json_default, sort_keys=True)


# ── Model version parsing for MODEL_VERSION_BUMPED ────────────────────────
# We can't import the openai catalog here without a dep cycle, so we use a
# light heuristic that matches the spec: split on '-' / '.' / '_' / 'v' and
# compare token sets. If model_name (the base family) is identical but the
# token set diverges, that's a "version bump". This intentionally treats
# gpt-4 vs gpt-4o as a bump, gpt-4-0613 vs gpt-4-1106 as a bump, and
# claude-3-haiku vs claude-3.5-haiku as a bump.

_TOKEN_RE = re.compile(r"[\-_./v]+", flags=re.IGNORECASE)


def _model_tokens(model_name: Optional[str]) -> Tuple[str, ...]:
    """Tokenize a model name into a comparable tuple."""
    if not model_name:
        return ()
    parts = [p for p in _TOKEN_RE.split(model_name.strip().lower()) if p]
    return tuple(parts)


def _is_version_bump(prev_model: str, curr_model: str) -> bool:
    """True iff the two model names share their first token but differ overall.

    "gpt-4" / "gpt-4o"               → True (same family, different version)
    "gpt-4-0613" / "gpt-4-1106"      → True
    "gpt-4" / "claude-3-haiku"       → False (different family → MODEL_CHANGED)
    "gpt-4" / "gpt-4"                → False (no change)
    """
    p = _model_tokens(prev_model)
    c = _model_tokens(curr_model)
    if not p or not c:
        return False
    if p == c:
        return False
    return p[0] == c[0]


# ── Engine ────────────────────────────────────────────────────────────────

class AILifecycleEngine:
    """Per-AI-agent J/M/L lifecycle and drift detection.

    The engine is stateless beyond its DB handle — re-instantiate per
    analysis pass. ``db.conn`` must be an open psycopg2 connection.
    """

    def __init__(self, db: Any):
        self.db = db

    # ── Public API ────────────────────────────────────────────────────────

    def analyze(
        self,
        current_run_id: int,
        prev_run_id: Optional[int],
        organization_id: int,
    ) -> List[Dict[str, Any]]:
        """Detect lifecycle events between two runs and persist them.

        Returns the list of events written (each is a dict shaped like the
        ``ai_agent_lifecycle_events`` row plus a few render-friendly keys).
        On first run (``prev_run_id is None``) only AI_AGENT_JOINER events
        are emitted — every other event type requires a comparison snapshot.

        UPSERT semantics: re-running for the same (org, current_run_id)
        pair is idempotent because of the table's UNIQUE constraint on
        (organization_id, identity_db_id, discovery_run_id, event_type).
        """
        if not current_run_id or not organization_id:
            logger.warning(
                "ai_lifecycle.analyze: missing run/org (current_run_id=%s "
                "organization_id=%s) — skipping",
                current_run_id, organization_id,
            )
            return []

        events: List[Dict[str, Any]] = []

        # Snapshot of the current run's AI agents (always needed)
        try:
            curr_agents = self._load_agent_snapshot(current_run_id, organization_id)
        except Exception as exc:
            logger.warning("ai_lifecycle: current snapshot failed: %s", exc)
            self._safe_rollback()
            return []

        if not curr_agents:
            logger.debug("ai_lifecycle: no AI agents in current run %s", current_run_id)
            return []

        # Joiner-only mode when no baseline exists
        if prev_run_id is None:
            for ident_id, snap in curr_agents.items():
                events.append(self._build_joiner_event(
                    organization_id, current_run_id, None, snap,
                ))
            self._persist_events(events)
            logger.info(
                "ai_lifecycle: first-run mode — %d joiner event(s)",
                len(events),
            )
            return events

        # Full diff mode
        try:
            prev_agents = self._load_agent_snapshot(prev_run_id, organization_id)
        except Exception as exc:
            logger.warning("ai_lifecycle: prev snapshot failed: %s", exc)
            self._safe_rollback()
            prev_agents = {}

        # 1) JML cohorts
        joiners = set(curr_agents) - set(prev_agents)
        leavers = set(prev_agents) - set(curr_agents)
        common = set(curr_agents) & set(prev_agents)

        for ident_id in joiners:
            events.append(self._build_joiner_event(
                organization_id, current_run_id, prev_run_id, curr_agents[ident_id],
            ))

        for ident_id in leavers:
            events.append(self._build_leaver_event(
                organization_id, current_run_id, prev_run_id, prev_agents[ident_id],
            ))

        # 2) Movers + classifier diffs for identities present in both runs
        for ident_id in common:
            prev_snap = prev_agents[ident_id]
            curr_snap = curr_agents[ident_id]

            # If the agent is disabled in current and was enabled in prev,
            # treat as LEAVER (architecture-only signal, no log dependency).
            if curr_snap.get('enabled') is False and prev_snap.get('enabled') is not False:
                events.append(self._build_leaver_event(
                    organization_id, current_run_id, prev_run_id, prev_snap,
                ))
                continue

            events.extend(self._diff_classifier(
                organization_id, current_run_id, prev_run_id, prev_snap, curr_snap,
            ))
            events.extend(self._diff_role_scope(
                organization_id, current_run_id, prev_run_id, prev_snap, curr_snap,
            ))

        # 3) Deployment + capacity diffs (account-scoped, so load by org)
        try:
            events.extend(self._diff_deployments(
                organization_id, current_run_id, prev_run_id, curr_agents, prev_agents,
            ))
        except Exception as exc:
            logger.warning("ai_lifecycle: deployment diff failed: %s", exc)
            self._safe_rollback()

        # 4) Persist
        self._persist_events(events)
        logger.info(
            "ai_lifecycle: org=%s run=%s prev=%s → %d event(s) "
            "[joiners=%d leavers=%d common=%d]",
            organization_id, current_run_id, prev_run_id,
            len(events), len(joiners), len(leavers), len(common),
        )
        return events

    def get_lifecycle_for_identity(
        self,
        identity_db_id: int,
        organization_id: int,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """All persisted lifecycle events for one AI agent, newest first."""
        if not identity_db_id or not organization_id:
            return []
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("SAVEPOINT aile_get_for_id")
            cursor.execute(
                """
                SELECT id, organization_id, discovery_run_id, prev_run_id,
                       identity_db_id, identity_id, event_type, severity,
                       occurred_at, before_snapshot, after_snapshot,
                       description, mitre_techniques, resolved, resolved_at,
                       resolved_by
                  FROM ai_agent_lifecycle_events
                 WHERE organization_id = %s
                   AND identity_db_id = %s
                 ORDER BY occurred_at DESC, id DESC
                 LIMIT %s
                """,
                (organization_id, identity_db_id, int(limit)),
            )
            rows = cursor.fetchall()
            cursor.execute("RELEASE SAVEPOINT aile_get_for_id")
        except Exception as exc:
            logger.warning("ai_lifecycle.get_lifecycle_for_identity failed: %s", exc)
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT aile_get_for_id")
            except Exception:
                self._safe_rollback()
            cursor.close()
            return []
        cursor.close()
        return [self._row_to_event(r) for r in rows]

    def get_drift_for_identity(
        self,
        identity_db_id: int,
        current_run_id: int,
        prev_run_id: Optional[int],
        organization_id: int,
    ) -> Dict[str, Any]:
        """Drift events + summary for one AI agent across exactly two runs.

        Returns ``{drift_events: [...], summary: {by_type, by_severity,
        total, current_run_id, prev_run_id}}``. Both arrays are empty when
        no events were persisted for that pair.
        """
        empty: Dict[str, Any] = {
            'drift_events': [],
            'summary': {
                'total': 0,
                'by_type': {},
                'by_severity': {},
                'current_run_id': current_run_id,
                'prev_run_id': prev_run_id,
            },
        }
        if not identity_db_id or not organization_id or not current_run_id:
            return empty

        cursor = self.db.conn.cursor()
        try:
            cursor.execute("SAVEPOINT aile_drift_for_id")
            cursor.execute(
                """
                SELECT id, organization_id, discovery_run_id, prev_run_id,
                       identity_db_id, identity_id, event_type, severity,
                       occurred_at, before_snapshot, after_snapshot,
                       description, mitre_techniques, resolved, resolved_at,
                       resolved_by
                  FROM ai_agent_lifecycle_events
                 WHERE organization_id = %s
                   AND identity_db_id = %s
                   AND discovery_run_id = %s
                 ORDER BY occurred_at DESC, id DESC
                """,
                (organization_id, identity_db_id, current_run_id),
            )
            rows = cursor.fetchall()
            cursor.execute("RELEASE SAVEPOINT aile_drift_for_id")
        except Exception as exc:
            logger.warning("ai_lifecycle.get_drift_for_identity failed: %s", exc)
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT aile_drift_for_id")
            except Exception:
                self._safe_rollback()
            cursor.close()
            return empty
        cursor.close()

        drift_events = [self._row_to_event(r) for r in rows]
        by_type: Dict[str, int] = {}
        by_sev: Dict[str, int] = {}
        for ev in drift_events:
            by_type[ev['event_type']] = by_type.get(ev['event_type'], 0) + 1
            by_sev[ev['severity']] = by_sev.get(ev['severity'], 0) + 1
        return {
            'drift_events': drift_events,
            'summary': {
                'total': len(drift_events),
                'by_type': by_type,
                'by_severity': by_sev,
                'current_run_id': current_run_id,
                'prev_run_id': prev_run_id,
            },
        }

    def get_jml_snapshot(
        self,
        organization_id: int,
        window_days: int = 7,
    ) -> Dict[str, Any]:
        """Aggregate joiners / movers / leavers in the last ``window_days``.

        Returns ``{joiners: [...], movers: [...], leavers: [...],
        totals: {joiners, movers, leavers, all}, recent_events: [...]}``.
        Each item carries identity_id, display_name (when joinable),
        event_id, occurred_at, severity.
        """
        empty: Dict[str, Any] = {
            'joiners': [],
            'movers': [],
            'leavers': [],
            'totals': {'joiners': 0, 'movers': 0, 'leavers': 0, 'all': 0},
            'recent_events': [],
            'window_days': window_days,
        }
        if not organization_id:
            return empty

        # Cutoff in UTC — `occurred_at` is TIMESTAMPTZ DEFAULT NOW().
        cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, int(window_days)))

        cursor = self.db.conn.cursor()
        try:
            cursor.execute("SAVEPOINT aile_jml_snapshot")
            cursor.execute(
                """
                SELECT e.id, e.event_type, e.severity, e.identity_db_id,
                       e.identity_id, e.occurred_at, e.description,
                       e.discovery_run_id, e.prev_run_id,
                       i.display_name
                  FROM ai_agent_lifecycle_events e
             LEFT JOIN identities i ON i.id = e.identity_db_id
                 WHERE e.organization_id = %s
                   AND e.occurred_at >= %s
                 ORDER BY e.occurred_at DESC, e.id DESC
                """,
                (organization_id, cutoff),
            )
            rows = cursor.fetchall()
            cursor.execute("RELEASE SAVEPOINT aile_jml_snapshot")
        except Exception as exc:
            logger.warning("ai_lifecycle.get_jml_snapshot failed: %s", exc)
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT aile_jml_snapshot")
            except Exception:
                self._safe_rollback()
            cursor.close()
            return empty
        cursor.close()

        joiners: List[Dict[str, Any]] = []
        movers: List[Dict[str, Any]] = []
        leavers: List[Dict[str, Any]] = []
        recent: List[Dict[str, Any]] = []

        for row in rows:
            (eid, etype, sev, iddb, idext, occurred,
             desc, run_id, prev_rid, display_name) = row
            item = {
                'event_id': eid,
                'event_type': etype,
                'severity': sev,
                'identity_db_id': iddb,
                'identity_id': idext,
                'display_name': display_name,
                'occurred_at': occurred.isoformat() if hasattr(occurred, 'isoformat') else occurred,
                'description': desc,
                'discovery_run_id': run_id,
                'prev_run_id': prev_rid,
            }
            recent.append(item)
            if etype == AIDriftEventType.AI_AGENT_JOINER:
                joiners.append(item)
            elif etype == AIDriftEventType.AI_AGENT_MOVER:
                movers.append(item)
            elif etype == AIDriftEventType.AI_AGENT_LEAVER:
                leavers.append(item)

        return {
            'joiners': joiners,
            'movers': movers,
            'leavers': leavers,
            'totals': {
                'joiners': len(joiners),
                'movers': len(movers),
                'leavers': len(leavers),
                'all': len(rows),
            },
            'recent_events': recent,
            'window_days': window_days,
        }

    # ── Snapshot loading ──────────────────────────────────────────────────

    def _load_agent_snapshot(
        self,
        run_id: int,
        organization_id: int,
    ) -> Dict[str, Dict[str, Any]]:
        """Build a per-identity_id snapshot of every AI agent in a run.

        Returns ``{identity_id: {
            identity_db_id, display_name, identity_category,
            agent_identity_type, detected_platform, classification_confidence,
            classification_reason, model_name, owner_display_name_at_classify,
            account_resource_id, enabled, is_microsoft_system,
            roles: {role_name: {scope, scope_type, access_level}},
            resource_scopes: set(of normalized scope strings),
        }}``.

        Only identities with a classification of ``ai_agent`` or
        ``possible_ai_agent`` in this run are included — humans and plain
        SPNs are out-of-scope for lifecycle drift here.
        """
        snapshot: Dict[str, Dict[str, Any]] = {}
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("SAVEPOINT aile_load_snap")
            cursor.execute(
                """
                SELECT i.id, i.identity_id, i.display_name, i.identity_category,
                       i.enabled, i.is_microsoft_system,
                       ac.agent_identity_type, ac.detected_platform,
                       ac.classification_confidence, ac.classification_reason,
                       ac.model_name, ac.owner_display_name_at_classify,
                       ac.account_resource_id
                  FROM identities i
                  JOIN agent_classifications ac
                    ON ac.identity_db_id = i.id
                   AND ac.discovery_run_id = i.discovery_run_id
                 WHERE i.discovery_run_id = %s
                   AND i.organization_id = %s
                   AND ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
                """,
                (run_id, organization_id),
            )
            rows = cursor.fetchall()
            cursor.execute("RELEASE SAVEPOINT aile_load_snap")
        except Exception as exc:
            logger.debug("ai_lifecycle._load_agent_snapshot identity query failed: %s", exc)
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT aile_load_snap")
            except Exception:
                self._safe_rollback()
            cursor.close()
            return {}

        for row in rows:
            (db_id, ext_id, display_name, category, enabled, is_ms,
             agent_type, platform, conf, reason,
             model_name, owner_name, account_rid) = row
            snapshot[ext_id] = {
                'identity_db_id': db_id,
                'identity_id': ext_id,
                'display_name': display_name,
                'identity_category': category,
                'enabled': bool(enabled) if enabled is not None else True,
                'is_microsoft_system': bool(is_ms) if is_ms is not None else False,
                'agent_identity_type': agent_type,
                'detected_platform': platform,
                'classification_confidence': float(conf) if conf is not None else 0.0,
                'classification_reason': reason,
                'model_name': model_name,
                'owner_display_name_at_classify': owner_name,
                'account_resource_id': account_rid,
                'roles': {},
                'resource_scopes': set(),
            }

        if not snapshot:
            cursor.close()
            return snapshot

        # Pull role assignments for these agents in one query
        db_ids = [s['identity_db_id'] for s in snapshot.values()]
        try:
            cursor.execute("SAVEPOINT aile_load_roles")
            cursor.execute(
                """
                SELECT identity_db_id, role_name, scope, scope_type
                  FROM role_assignments
                 WHERE identity_db_id = ANY(%s)
                """,
                (db_ids,),
            )
            role_rows = cursor.fetchall()
            cursor.execute("RELEASE SAVEPOINT aile_load_roles")
        except Exception as exc:
            logger.debug("ai_lifecycle._load_agent_snapshot roles query failed: %s", exc)
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT aile_load_roles")
            except Exception:
                self._safe_rollback()
            role_rows = []

        # Build a reverse index db_id → external identity_id so role rows
        # can be grouped by snapshot key.
        db_to_ext: Dict[int, str] = {
            s['identity_db_id']: s['identity_id'] for s in snapshot.values()
        }
        for db_id, role_name, scope, scope_type in role_rows:
            ext_id = db_to_ext.get(db_id)
            if not ext_id:
                continue
            snap = snapshot[ext_id]
            access_level = _level_from_role(role_name or '')
            # Keep the strongest access for a (role, scope) — duplicate rows
            # are common in the underlying table. role_name@scope is the key.
            key = f"{role_name}@{scope}"
            snap['roles'][key] = {
                'role_name': role_name or '',
                'scope': scope or '',
                'scope_type': scope_type or '',
                'access_level': access_level,
            }
            if scope:
                snap['resource_scopes'].add(scope.strip().lower().rstrip('/'))

        cursor.close()
        return snapshot

    def _load_deployments(
        self,
        run_id: int,
        organization_id: int,
        account_resource_ids: Iterable[str],
    ) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """Return ``{account_resource_id: {deployment_name: row}}`` for the
        deployment-set under each AI agent's parent account in one run."""
        out: Dict[str, Dict[str, Dict[str, Any]]] = {}
        wanted = [a for a in account_resource_ids if a]
        if not wanted:
            return out
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("SAVEPOINT aile_load_dep")
            cursor.execute(
                """
                SELECT account_resource_id, deployment_name, model_name,
                       model_version, model_format, sku_name, sku_capacity,
                       provisioning_state
                  FROM azure_ai_model_deployments
                 WHERE discovery_run_id = %s
                   AND organization_id = %s
                   AND account_resource_id = ANY(%s)
                """,
                (run_id, organization_id, wanted),
            )
            rows = cursor.fetchall()
            cursor.execute("RELEASE SAVEPOINT aile_load_dep")
        except Exception as exc:
            logger.debug("ai_lifecycle._load_deployments failed: %s", exc)
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT aile_load_dep")
            except Exception:
                self._safe_rollback()
            cursor.close()
            return out
        cursor.close()

        for row in rows:
            (acct, dep_name, model_name, model_version, model_format,
             sku_name, sku_capacity, prov_state) = row
            if not acct or not dep_name:
                continue
            out.setdefault(acct, {})[dep_name] = {
                'deployment_name': dep_name,
                'model_name': model_name,
                'model_version': model_version,
                'model_format': model_format,
                'sku_name': sku_name,
                'sku_capacity': int(sku_capacity) if sku_capacity is not None else None,
                'provisioning_state': prov_state,
            }
        return out

    # ── Event builders ────────────────────────────────────────────────────

    def _build_joiner_event(
        self,
        organization_id: int,
        current_run_id: int,
        prev_run_id: Optional[int],
        curr_snap: Dict[str, Any],
    ) -> Dict[str, Any]:
        after = self._classifier_snapshot(curr_snap)
        platform_phrase = (
            f" on platform {curr_snap.get('detected_platform')}"
            if curr_snap.get('detected_platform') else ''
        )
        description = (
            f"AI agent first observed in discovery: "
            f"{curr_snap.get('display_name') or curr_snap['identity_id']} "
            f"(type={curr_snap.get('agent_identity_type')}{platform_phrase})."
        )
        return self._make_event(
            organization_id=organization_id,
            current_run_id=current_run_id,
            prev_run_id=prev_run_id,
            identity_db_id=curr_snap['identity_db_id'],
            identity_id=curr_snap['identity_id'],
            event_type=AIDriftEventType.AI_AGENT_JOINER,
            description=description,
            before=None,
            after=after,
            mitre_ids=[],
        )

    def _build_leaver_event(
        self,
        organization_id: int,
        current_run_id: int,
        prev_run_id: Optional[int],
        prev_snap: Dict[str, Any],
    ) -> Dict[str, Any]:
        before = self._classifier_snapshot(prev_snap)
        description = (
            f"AI agent no longer present (or disabled) in current discovery: "
            f"{prev_snap.get('display_name') or prev_snap['identity_id']}. "
            f"Last classification: {prev_snap.get('agent_identity_type')}."
        )
        return self._make_event(
            organization_id=organization_id,
            current_run_id=current_run_id,
            prev_run_id=prev_run_id,
            identity_db_id=prev_snap['identity_db_id'],
            identity_id=prev_snap['identity_id'],
            event_type=AIDriftEventType.AI_AGENT_LEAVER,
            description=description,
            before=before,
            after=None,
            mitre_ids=[],
        )

    def _diff_classifier(
        self,
        organization_id: int,
        current_run_id: int,
        prev_run_id: int,
        prev: Dict[str, Any],
        curr: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """MODEL_CHANGED + MODEL_VERSION_BUMPED + AI_OWNER_CHANGED."""
        events: List[Dict[str, Any]] = []

        prev_model = (prev.get('model_name') or '').strip()
        curr_model = (curr.get('model_name') or '').strip()
        if prev_model and curr_model and prev_model.lower() != curr_model.lower():
            if _is_version_bump(prev_model, curr_model):
                events.append(self._make_event(
                    organization_id=organization_id,
                    current_run_id=current_run_id,
                    prev_run_id=prev_run_id,
                    identity_db_id=curr['identity_db_id'],
                    identity_id=curr['identity_id'],
                    event_type=AIDriftEventType.MODEL_VERSION_BUMPED,
                    description=(
                        f"Model version bumped for "
                        f"{curr.get('display_name') or curr['identity_id']}: "
                        f"{prev_model} → {curr_model}."
                    ),
                    before={'model_name': prev_model},
                    after={'model_name': curr_model},
                    mitre_ids=[],
                ))
            else:
                events.append(self._make_event(
                    organization_id=organization_id,
                    current_run_id=current_run_id,
                    prev_run_id=prev_run_id,
                    identity_db_id=curr['identity_db_id'],
                    identity_id=curr['identity_id'],
                    event_type=AIDriftEventType.MODEL_CHANGED,
                    description=(
                        f"Model family changed for "
                        f"{curr.get('display_name') or curr['identity_id']}: "
                        f"{prev_model} → {curr_model}."
                    ),
                    before={'model_name': prev_model},
                    after={'model_name': curr_model},
                    mitre_ids=[],
                ))

        prev_owner = (prev.get('owner_display_name_at_classify') or '').strip()
        curr_owner = (curr.get('owner_display_name_at_classify') or '').strip()
        if prev_owner != curr_owner and (prev_owner or curr_owner):
            events.append(self._make_event(
                organization_id=organization_id,
                current_run_id=current_run_id,
                prev_run_id=prev_run_id,
                identity_db_id=curr['identity_db_id'],
                identity_id=curr['identity_id'],
                event_type=AIDriftEventType.AI_OWNER_CHANGED,
                description=(
                    f"AI agent owner changed for "
                    f"{curr.get('display_name') or curr['identity_id']}: "
                    f"{prev_owner or '(none)'} → {curr_owner or '(none)'}."
                ),
                before={'owner_display_name': prev_owner or None},
                after={'owner_display_name': curr_owner or None},
                mitre_ids=[],
            ))

        return events

    def _diff_role_scope(
        self,
        organization_id: int,
        current_run_id: int,
        prev_run_id: int,
        prev: Dict[str, Any],
        curr: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """AI_PERMISSIONS_ESCALATED + AI_AGENT_MOVER."""
        events: List[Dict[str, Any]] = []

        prev_roles: Dict[str, Dict[str, Any]] = prev.get('roles', {}) or {}
        curr_roles: Dict[str, Dict[str, Any]] = curr.get('roles', {}) or {}

        prev_role_names = {r['role_name'] for r in prev_roles.values() if r.get('role_name')}
        curr_role_names = {r['role_name'] for r in curr_roles.values() if r.get('role_name')}
        gained_role_names = curr_role_names - prev_role_names

        prev_max_rank = max(
            (_LEVEL_RANK.get(r.get('access_level', 'reader'), 0) for r in prev_roles.values()),
            default=0,
        )
        curr_max_rank = max(
            (_LEVEL_RANK.get(r.get('access_level', 'reader'), 0) for r in curr_roles.values()),
            default=0,
        )

        tier_jumped = curr_max_rank > prev_max_rank
        owner_equiv_gained = gained_role_names & _OWNER_EQUIV_ROLES

        if tier_jumped or owner_equiv_gained:
            # Tag MITRE via a role-driven enrichment for the strongest new role
            # (or the strongest current role if none of the gained are owner-equiv).
            tag_role = next(iter(owner_equiv_gained), None)
            if not tag_role and gained_role_names:
                tag_role = max(
                    gained_role_names,
                    key=lambda rn: _LEVEL_RANK.get(_level_from_role(rn), 0),
                )
            mitre_ids: List[str] = []
            if tag_role:
                # enrich_path_node_with_mitre returns full dicts; we keep
                # just the ID list to fit the JSONB column.
                mitre_ids = [
                    t['id'] for t in enrich_path_node_with_mitre(
                        'role_assignment', role_name=tag_role,
                    )
                ]
            # T1098 ("Account Manipulation") is always relevant for an
            # AI-agent permission escalation; add it if not already tagged
            # by the role enricher.
            if 'T1098' not in mitre_ids:
                mitre_ids.append('T1098')

            tier_label = {
                0: 'none', 1: 'reader', 2: 'contributor', 3: 'owner',
            }
            description = (
                f"AI agent permissions escalated for "
                f"{curr.get('display_name') or curr['identity_id']}: "
                f"tier {tier_label.get(prev_max_rank, 'unknown')} → "
                f"{tier_label.get(curr_max_rank, 'unknown')}"
                + (f"; gained owner-equivalent role(s): "
                   f"{', '.join(sorted(owner_equiv_gained))}" if owner_equiv_gained else '')
                + f". {len(gained_role_names)} role(s) added since last run."
            )
            events.append(self._make_event(
                organization_id=organization_id,
                current_run_id=current_run_id,
                prev_run_id=prev_run_id,
                identity_db_id=curr['identity_db_id'],
                identity_id=curr['identity_id'],
                event_type=AIDriftEventType.AI_PERMISSIONS_ESCALATED,
                description=description,
                before={
                    'max_access_tier': tier_label.get(prev_max_rank, 'unknown'),
                    'role_names': sorted(prev_role_names),
                },
                after={
                    'max_access_tier': tier_label.get(curr_max_rank, 'unknown'),
                    'role_names': sorted(curr_role_names),
                    'gained_roles': sorted(gained_role_names),
                    'gained_owner_equivalent': sorted(owner_equiv_gained),
                },
                mitre_ids=mitre_ids,
            ))

        # AI_AGENT_MOVER — material change in resource scope set
        prev_scopes: Set[str] = prev.get('resource_scopes') or set()
        curr_scopes: Set[str] = curr.get('resource_scopes') or set()
        union = prev_scopes | curr_scopes
        if union:
            sym = prev_scopes ^ curr_scopes
            delta = len(sym) / float(len(union))
            if delta > _MOVER_RESOURCE_DELTA:
                added = sorted(curr_scopes - prev_scopes)
                removed = sorted(prev_scopes - curr_scopes)
                events.append(self._make_event(
                    organization_id=organization_id,
                    current_run_id=current_run_id,
                    prev_run_id=prev_run_id,
                    identity_db_id=curr['identity_db_id'],
                    identity_id=curr['identity_id'],
                    event_type=AIDriftEventType.AI_AGENT_MOVER,
                    description=(
                        f"AI agent scope changed materially for "
                        f"{curr.get('display_name') or curr['identity_id']}: "
                        f"{len(added)} scope(s) added, {len(removed)} removed "
                        f"({delta:.0%} of total scope set changed)."
                    ),
                    before={
                        'resource_scopes': sorted(prev_scopes),
                        'scope_count': len(prev_scopes),
                    },
                    after={
                        'resource_scopes': sorted(curr_scopes),
                        'scope_count': len(curr_scopes),
                        'added_scopes': added,
                        'removed_scopes': removed,
                        'delta_fraction': round(delta, 4),
                    },
                    mitre_ids=['T1098.003'],  # Additional Cloud Roles
                ))

        return events

    def _diff_deployments(
        self,
        organization_id: int,
        current_run_id: int,
        prev_run_id: int,
        curr_agents: Dict[str, Dict[str, Any]],
        prev_agents: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """DEPLOYMENT_ADDED / DEPLOYMENT_REMOVED / CAPACITY_EXPANDED."""
        events: List[Dict[str, Any]] = []

        # Collect every account_resource_id mentioned by any agent in either
        # run — these are the scopes whose deployment set we need to diff.
        accounts: Set[str] = set()
        for snap in list(curr_agents.values()) + list(prev_agents.values()):
            acct = snap.get('account_resource_id')
            if acct:
                accounts.add(acct)
        if not accounts:
            return events

        curr_deps = self._load_deployments(current_run_id, organization_id, accounts)
        prev_deps = self._load_deployments(prev_run_id, organization_id, accounts)

        # Build account → list of (agent_snapshot) so we can attribute each
        # deployment event to the AI agents that own the parent account.
        # (Multiple agents can share one Cognitive Services account.)
        agents_by_acct: Dict[str, List[Dict[str, Any]]] = {}
        for snap in curr_agents.values():
            acct = snap.get('account_resource_id')
            if acct:
                agents_by_acct.setdefault(acct, []).append(snap)

        for acct in accounts:
            curr_set = curr_deps.get(acct, {})
            prev_set = prev_deps.get(acct, {})
            added = set(curr_set) - set(prev_set)
            removed = set(prev_set) - set(curr_set)
            common = set(curr_set) & set(prev_set)

            for dep_name in added:
                dep = curr_set[dep_name]
                for snap in agents_by_acct.get(acct, []):
                    events.append(self._make_event(
                        organization_id=organization_id,
                        current_run_id=current_run_id,
                        prev_run_id=prev_run_id,
                        identity_db_id=snap['identity_db_id'],
                        identity_id=snap['identity_id'],
                        event_type=AIDriftEventType.DEPLOYMENT_ADDED,
                        description=(
                            f"New model deployment under "
                            f"{snap.get('display_name') or snap['identity_id']}: "
                            f"{dep_name} ({dep.get('model_name') or 'unknown'})."
                        ),
                        before=None,
                        after={'account_resource_id': acct, **dep},
                        mitre_ids=[],
                    ))

            for dep_name in removed:
                dep = prev_set[dep_name]
                for snap in agents_by_acct.get(acct, []):
                    events.append(self._make_event(
                        organization_id=organization_id,
                        current_run_id=current_run_id,
                        prev_run_id=prev_run_id,
                        identity_db_id=snap['identity_db_id'],
                        identity_id=snap['identity_id'],
                        event_type=AIDriftEventType.DEPLOYMENT_REMOVED,
                        description=(
                            f"Model deployment removed under "
                            f"{snap.get('display_name') or snap['identity_id']}: "
                            f"{dep_name} ({dep.get('model_name') or 'unknown'})."
                        ),
                        before={'account_resource_id': acct, **dep},
                        after=None,
                        mitre_ids=[],
                    ))

            for dep_name in common:
                prev_dep = prev_set[dep_name]
                curr_dep = curr_set[dep_name]
                prev_cap = prev_dep.get('sku_capacity')
                curr_cap = curr_dep.get('sku_capacity')
                if (prev_cap is not None and curr_cap is not None
                        and curr_cap > prev_cap):
                    for snap in agents_by_acct.get(acct, []):
                        events.append(self._make_event(
                            organization_id=organization_id,
                            current_run_id=current_run_id,
                            prev_run_id=prev_run_id,
                            identity_db_id=snap['identity_db_id'],
                            identity_id=snap['identity_id'],
                            event_type=AIDriftEventType.CAPACITY_EXPANDED,
                            description=(
                                f"Model deployment capacity expanded for "
                                f"{snap.get('display_name') or snap['identity_id']} "
                                f"on {dep_name} ({curr_dep.get('model_name') or 'unknown'}): "
                                f"{prev_cap} → {curr_cap} units."
                            ),
                            before={
                                'account_resource_id': acct,
                                'deployment_name': dep_name,
                                'sku_capacity': prev_cap,
                            },
                            after={
                                'account_resource_id': acct,
                                'deployment_name': dep_name,
                                'sku_capacity': curr_cap,
                                'capacity_delta': curr_cap - prev_cap,
                            },
                            mitre_ids=[],
                        ))

        return events

    # ── Persistence ───────────────────────────────────────────────────────

    def _persist_events(self, events: List[Dict[str, Any]]) -> None:
        """UPSERT each event row. The UNIQUE constraint on
        (organization_id, identity_db_id, discovery_run_id, event_type) makes
        re-runs idempotent — we DO NOT delete and re-insert.
        """
        if not events:
            return
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("SAVEPOINT aile_persist")
            for ev in events:
                cursor.execute(
                    """
                    INSERT INTO ai_agent_lifecycle_events (
                        organization_id, discovery_run_id, prev_run_id,
                        identity_db_id, identity_id, event_type, severity,
                        before_snapshot, after_snapshot, description,
                        mitre_techniques
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (organization_id, identity_db_id,
                                 discovery_run_id, event_type)
                    DO UPDATE SET
                        severity         = EXCLUDED.severity,
                        before_snapshot  = EXCLUDED.before_snapshot,
                        after_snapshot   = EXCLUDED.after_snapshot,
                        description      = EXCLUDED.description,
                        mitre_techniques = EXCLUDED.mitre_techniques,
                        prev_run_id      = EXCLUDED.prev_run_id,
                        occurred_at      = NOW()
                    RETURNING id, occurred_at
                    """,
                    (
                        ev['organization_id'],
                        ev['discovery_run_id'],
                        ev['prev_run_id'],
                        ev['identity_db_id'],
                        ev['identity_id'],
                        ev['event_type'],
                        ev['severity'],
                        _to_jsonb(ev.get('before_snapshot')),
                        _to_jsonb(ev.get('after_snapshot')),
                        ev.get('description'),
                        _to_jsonb({'techniques': ev.get('mitre_techniques') or []}),
                    ),
                )
                row = cursor.fetchone()
                if row:
                    ev['id'] = row[0]
                    ev['occurred_at'] = (
                        row[1].isoformat() if hasattr(row[1], 'isoformat') else row[1]
                    )
            self.db.conn.commit()
            cursor.execute("SAVEPOINT aile_persist_done")  # marker; safe no-op
            cursor.execute("RELEASE SAVEPOINT aile_persist_done")
        except Exception as exc:
            logger.warning("ai_lifecycle._persist_events failed: %s", exc)
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT aile_persist")
            except Exception:
                self._safe_rollback()
        finally:
            cursor.close()

    # ── Helpers ───────────────────────────────────────────────────────────

    def _make_event(
        self,
        organization_id: int,
        current_run_id: int,
        prev_run_id: Optional[int],
        identity_db_id: int,
        identity_id: str,
        event_type: str,
        description: str,
        before: Optional[Dict[str, Any]],
        after: Optional[Dict[str, Any]],
        mitre_ids: List[str],
    ) -> Dict[str, Any]:
        """Compose an event dict in the schema's column order. Severity is
        sourced from the AI taxonomy — never hardcoded here."""
        return {
            'organization_id': organization_id,
            'discovery_run_id': current_run_id,
            'prev_run_id': prev_run_id,
            'identity_db_id': identity_db_id,
            'identity_id': identity_id,
            'event_type': event_type,
            'severity': AI_EVENT_SEVERITY.get(event_type, 'medium'),
            'before_snapshot': before,
            'after_snapshot': after,
            'description': description,
            'mitre_techniques': list(dict.fromkeys(mitre_ids or [])),
        }

    def _classifier_snapshot(self, snap: Dict[str, Any]) -> Dict[str, Any]:
        """Compact dict of the classifier+context fields suitable for the
        before/after JSONB columns. We deliberately omit the giant `roles`
        dict here — role-set deltas live in their own event."""
        return {
            'identity_id': snap.get('identity_id'),
            'display_name': snap.get('display_name'),
            'agent_identity_type': snap.get('agent_identity_type'),
            'detected_platform': snap.get('detected_platform'),
            'classification_confidence': snap.get('classification_confidence'),
            'classification_reason': snap.get('classification_reason'),
            'model_name': snap.get('model_name'),
            'owner_display_name': snap.get('owner_display_name_at_classify'),
            'account_resource_id': snap.get('account_resource_id'),
            'enabled': snap.get('enabled'),
            'role_count': len(snap.get('roles') or {}),
            'scope_count': len(snap.get('resource_scopes') or []),
        }

    def _row_to_event(self, row: Tuple[Any, ...]) -> Dict[str, Any]:
        """Materialize a DB row into the public event dict shape."""
        (eid, org_id, run_id, prev_rid, iddb, idext, etype, sev,
         occurred, before, after, desc, mitre, resolved,
         resolved_at, resolved_by) = row
        # before / after / mitre come back as Python dicts thanks to JSONB.
        mitre_list: List[str]
        if isinstance(mitre, dict):
            mitre_list = list(mitre.get('techniques') or [])
        elif isinstance(mitre, list):
            mitre_list = list(mitre)
        else:
            mitre_list = []
        return {
            'id': eid,
            'organization_id': org_id,
            'discovery_run_id': run_id,
            'prev_run_id': prev_rid,
            'identity_db_id': iddb,
            'identity_id': idext,
            'event_type': etype,
            'severity': sev,
            'occurred_at': (
                occurred.isoformat() if hasattr(occurred, 'isoformat') else occurred
            ),
            'before_snapshot': before,
            'after_snapshot': after,
            'description': desc,
            'mitre_techniques': mitre_list,
            'resolved': bool(resolved),
            'resolved_at': (
                resolved_at.isoformat() if hasattr(resolved_at, 'isoformat') else resolved_at
            ),
            'resolved_by': resolved_by,
        }

    def _safe_rollback(self) -> None:
        """Defensive rollback that tolerates either Database._rollback() or
        the raw psycopg2 connection."""
        try:
            rb = getattr(self.db, '_rollback', None)
            if callable(rb):
                rb()
                return
        except Exception:
            pass
        try:
            self.db.conn.rollback()
        except Exception:
            pass


__all__ = ['AILifecycleEngine']
