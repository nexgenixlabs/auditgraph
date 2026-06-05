"""
AI Supply Chain dependency graph (Tier 3.2).

Per-agent component tree:

    Agent
      ├─ model         (GPT-4o, dall-e-3, fine-tunes)
      ├─ plugin        (langchain modules, MCP servers)
      │   └─ vector_db (Pinecone, Azure PG/pgvector)
      ├─ external_api  (Salesforce, Hugging Face)
      └─ tool          (webBrowser, code execution)

Each component carries `risk_flags` (array of named flags) and a derived
`risk_score` 0-100. The engine walks the dependency tree from agent
outward and returns:

  - flat node + edge list (for UI)
  - aggregate risk score per agent (worst leaf + supply-chain depth)
  - top contributing flags (so the recommendation is concrete)

This is the consequence layer for "supply chain compromise of an AI
agent's dependency graph" — composes with the Tier 2.1 supply_chain
scenario which only checks the cog services account today.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


# Risk-flag → contribution score (0-100). Multiple flags compound,
# capped at 100. Values aren't hardcoded scores — they're a deliberate
# catalog so engineering can tune.
FLAG_WEIGHT = {
    'fine_tuned':           20,
    'unapproved':           25,
    'community_plugin':     15,
    'no_pinned_version':    15,
    'mutable_dependency':   20,
    'public_endpoint':      20,
    'external_managed':     10,
    'unbounded_scope':      25,
    'no_scope_audit':       15,
    'unverified_vendor':    20,
    'cve':                  30,
}

# Severity bucket from risk_score
SEVERITY_THRESHOLDS = [(80, 'critical'), (60, 'high'), (40, 'medium'), (0, 'low')]


def compute_component_risk(risk_flags: list[str]) -> tuple[int, str]:
    """Return (risk_score 0-100, severity)."""
    score = 0
    for f in risk_flags or []:
        score += FLAG_WEIGHT.get(f, 5)
    score = min(score, 100)
    sev = next(s for threshold, s in SEVERITY_THRESHOLDS if score >= threshold)
    return score, sev


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def get_agent_supply_chain(db, org_id: int, identity_db_id: int) -> dict[str, Any]:
    """Return the supply chain rooted at one AI agent — nodes + edges +
    aggregate risk.
    """
    cursor = db.conn.cursor()
    try:
        # 1) seed components: those directly linked to the agent
        cursor.execute("""
            SELECT target_component_id, relationship
              FROM ai_supply_chain_links
             WHERE organization_id = %s
               AND source_identity_db_id = %s
        """, (org_id, identity_db_id))
        seed_links = [{'target': r[0], 'relationship': r[1]} for r in cursor.fetchall()]
        if not seed_links:
            return _empty_for_agent(identity_db_id)

        # 2) BFS through component→component links
        all_component_ids: set[int] = {l['target'] for l in seed_links}
        edges_internal: list[dict] = []
        frontier = list(all_component_ids)
        visited: set[int] = set()
        while frontier:
            cursor.execute("""
                SELECT source_component_id, target_component_id, relationship
                  FROM ai_supply_chain_links
                 WHERE organization_id = %s
                   AND source_component_id = ANY(%s)
            """, (org_id, frontier))
            new_frontier = []
            for r in cursor.fetchall():
                src, tgt, rel = r
                edges_internal.append({'source': src, 'target': tgt, 'relationship': rel})
                if tgt not in all_component_ids and tgt not in visited:
                    new_frontier.append(tgt)
                    all_component_ids.add(tgt)
            visited.update(frontier)
            frontier = new_frontier

        # 3) load component metadata
        cursor.execute("""
            SELECT id, component_kind, component_name, vendor, version,
                   is_managed_by_customer, risk_flags, risk_score, metadata
              FROM ai_supply_chain_components
             WHERE organization_id = %s AND id = ANY(%s)
        """, (org_id, list(all_component_ids)))
        components = []
        agg_score = 0
        worst_flag_contrib: dict[str, int] = defaultdict(int)
        for r in cursor.fetchall():
            cid, kind, name, vendor, version, customer_managed, flags, persisted_score, meta = r
            flags = flags or []
            score, sev = compute_component_risk(flags)
            agg_score = max(agg_score, score)
            for f in flags:
                worst_flag_contrib[f] += FLAG_WEIGHT.get(f, 5)
            components.append({
                'id':                  cid,
                'kind':                kind,
                'name':                name,
                'vendor':              vendor,
                'version':             version,
                'is_managed_by_customer': customer_managed,
                'risk_flags':          flags,
                'risk_score':          score,
                'severity':            sev,
                'metadata':            meta or {},
            })

        # 4) build edges (agent → component + internal)
        edges = [{'source_type': 'agent',
                  'source_id':   identity_db_id,
                  'target_id':   l['target'],
                  'relationship': l['relationship']}
                 for l in seed_links] + \
                [{'source_type': 'component',
                  'source_id':   e['source'],
                  'target_id':   e['target'],
                  'relationship': e['relationship']}
                 for e in edges_internal]

        # 5) top contributing flags (for the recommendation)
        top_flags = sorted(worst_flag_contrib.items(), key=lambda x: -x[1])[:3]

        return {
            'identity_db_id':       identity_db_id,
            'components':           components,
            'edges':                edges,
            'component_count':      len(components),
            'edge_count':           len(edges),
            'aggregate_risk_score': agg_score,
            'aggregate_severity':   next(s for t, s in SEVERITY_THRESHOLDS if agg_score >= t),
            'top_risk_flags':       [{'flag': f, 'contribution': c} for f, c in top_flags],
            'computed_at':          datetime.now(timezone.utc).isoformat(),
        }
    finally:
        cursor.close()


def get_org_supply_chain_rollup(db, org_id: int) -> dict[str, Any]:
    """Org-wide rollup: per-agent risk + worst components.

    AG-PROD-H3 (2026-06-05): batched. Was O(N) get_agent_supply_chain calls,
    each issuing 3+ queries. Now 3 queries total regardless of N.
    """
    cursor = db.conn.cursor()
    try:
        # 1) All agents with supply chain links — single query
        cursor.execute("""
            SELECT DISTINCT l.source_identity_db_id, i.identity_id, i.display_name
              FROM ai_supply_chain_links l
              JOIN identities i ON i.id = l.source_identity_db_id
             WHERE l.organization_id = %s
               AND l.source_identity_db_id IS NOT NULL
               AND NOT COALESCE(i.is_microsoft_system, false)
               AND i.deleted_at IS NULL
        """, (org_id,))
        agents = [{'identity_db_id': r[0], 'identity_id': r[1], 'display_name': r[2]}
                  for r in cursor.fetchall()]
        if not agents:
            agent_ids = []
        else:
            agent_ids = [a['identity_db_id'] for a in agents]

        # 2) All agent→component edges in one go
        edges_by_agent: dict[int, list[int]] = {}
        if agent_ids:
            cursor.execute("""
                SELECT source_identity_db_id, target_component_id
                  FROM ai_supply_chain_links
                 WHERE organization_id = %s
                   AND source_identity_db_id = ANY(%s)
            """, (org_id, agent_ids))
            for r in cursor.fetchall():
                edges_by_agent.setdefault(r[0], []).append(r[1])

        # 3) Plus component→component edges (transitive deps) — one query
        transitive_targets: dict[int, list[int]] = {}
        cursor.execute("""
            SELECT source_component_id, target_component_id
              FROM ai_supply_chain_links
             WHERE organization_id = %s
               AND source_component_id IS NOT NULL
        """, (org_id,))
        for r in cursor.fetchall():
            transitive_targets.setdefault(r[0], []).append(r[1])

        # 4) All components for this org, indexed by id — one query
        cursor.execute("""
            SELECT id, component_kind, component_name, vendor, version,
                   is_managed_by_customer, risk_flags, risk_score
              FROM ai_supply_chain_components
             WHERE organization_id = %s
        """, (org_id,))
        comp_by_id = {}
        for r in cursor.fetchall():
            comp_by_id[r[0]] = {
                'id': r[0], 'kind': r[1], 'name': r[2], 'vendor': r[3],
                'version': r[4], 'is_managed_by_customer': r[5],
                'risk_flags': r[6] or [], 'risk_score': r[7] or 0,
            }
    finally:
        cursor.close()

    # Compute per-agent rollup in Python — no further SQL
    per_agent = []
    from collections import defaultdict
    for a in agents:
        seed = edges_by_agent.get(a['identity_db_id'], [])
        # BFS through transitive_targets
        visited = set(seed)
        frontier = list(seed)
        while frontier:
            next_frontier = []
            for cid in frontier:
                for tgt in transitive_targets.get(cid, []):
                    if tgt not in visited:
                        visited.add(tgt)
                        next_frontier.append(tgt)
            frontier = next_frontier
        agg_score = 0
        flag_contrib = defaultdict(int)
        for cid in visited:
            comp = comp_by_id.get(cid)
            if comp:
                agg_score = max(agg_score, comp['risk_score'])
                for f in comp['risk_flags']:
                    flag_contrib[f] += FLAG_WEIGHT.get(f, 5)
        top_flags = sorted(flag_contrib.items(), key=lambda x: -x[1])[:3]
        per_agent.append({
            'identity_db_id':  a['identity_db_id'],
            'identity_id':     a['identity_id'],
            'display_name':    a['display_name'],
            'component_count': len(visited),
            'aggregate_risk_score': agg_score,
            'aggregate_severity':   next(s for t, s in SEVERITY_THRESHOLDS if agg_score >= t),
            'top_risk_flags':  [{'flag': f, 'contribution': c} for f, c in top_flags],
        })
    per_agent.sort(key=lambda x: -x['aggregate_risk_score'])

    # Stats: count of components by kind / by severity
    cursor = db.conn.cursor()
    try:
        cursor.execute("""
            SELECT component_kind, count(*),
                   SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) AS critical_count,
                   SUM(CASE WHEN risk_score >= 60 AND risk_score < 80 THEN 1 ELSE 0 END) AS high_count
              FROM ai_supply_chain_components
             WHERE organization_id = %s
             GROUP BY component_kind
             ORDER BY component_kind
        """, (org_id,))
        by_kind = [{'kind': r[0], 'count': r[1],
                    'critical_count': int(r[2] or 0),
                    'high_count':     int(r[3] or 0)}
                   for r in cursor.fetchall()]
    finally:
        cursor.close()

    return {
        'agents': per_agent,
        'agent_count': len(per_agent),
        'by_kind': by_kind,
        'computed_at': datetime.now(timezone.utc).isoformat(),
    }


def _empty_for_agent(identity_db_id: int) -> dict:
    return {
        'identity_db_id':       identity_db_id,
        'components':           [],
        'edges':                [],
        'component_count':      0,
        'edge_count':           0,
        'aggregate_risk_score': 0,
        'aggregate_severity':   'low',
        'top_risk_flags':       [],
        'computed_at':          datetime.now(timezone.utc).isoformat(),
    }


__all__ = ['get_agent_supply_chain', 'get_org_supply_chain_rollup',
           'compute_component_risk', 'FLAG_WEIGHT']
