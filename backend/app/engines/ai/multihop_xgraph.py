"""
Multi-hop XGRAPH (Tier 3.1) — Agent A → Agent B → … → Resource

Reviewer #1 called this the patent-worthy differentiator. Single-hop XGRAPH
(Argus L8) already traces Identity → Resource. v2 traces transitive
agent-to-agent reach: a low-priv agent can effectively reach high-value
data IF it can invoke a high-priv agent.

Data model
──────────
agent_invocations is the edge table (source_agent → target_agent via
mechanism). agent_data_reachability tells us what each agent reaches.
This engine joins them:

  1. Build adjacency dict: {source_db_id → [edge, edge, ...]}
  2. BFS from the source agent up to MAX_DEPTH hops.
  3. At each visited agent, check what classified data it reaches.
  4. Emit one chain per (source, target, classification) tuple.

Severity heuristic
──────────────────
  - critical : chain reaches PHI/PCI with WRITE
  - high     : chain reaches PHI/PCI read OR any classified write
  - medium   : chain reaches PII/FINANCIAL/HR
  - low      : chain reaches SOURCE/CONFIDENTIAL or no classified data

Trust-link weakness multiplier:
  +1 severity step if ANY intermediate hop is via 'shared_secret' or
    'inferred' confidence (the chain has a weak edge — easier to abuse).

Returns
───────
  {
    'source_agent': {identity_id, display_name},
    'chains': [
      {
        'hops': [{identity_id, display_name, via_mechanism, confidence}, ...],
        'depth': N,
        'terminal_classification': 'PHI'|'PCI'|...,
        'terminal_records': int,
        'is_write': bool,
        'severity': 'critical'|...,
        'dollar_band': {low, mid, high, displays},
        'weakest_link': {hop_index, mechanism, confidence},
        'mitre_techniques': ['T1199','T1098',...],
      }, ...
    ],
    'computed_at': ISO
  }
"""
from __future__ import annotations

import logging
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Optional

from ..scoring.breach_cost import compute_exposure, format_dollar_short

logger = logging.getLogger(__name__)


MAX_DEPTH_DEFAULT = 4
MAX_CHAINS_DEFAULT = 200


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def trace_multihop(db, org_id: int,
                   source_identity_id: Optional[str] = None,
                   max_depth: int = MAX_DEPTH_DEFAULT,
                   classification_filter: Optional[str] = None,
                   max_chains: int = MAX_CHAINS_DEFAULT) -> dict[str, Any]:
    """BFS multi-hop traversal from `source_identity_id` (or all AI agents
    if omitted) up to `max_depth` invocation hops. Returns chains terminating
    at a classified-data reach.
    """
    cursor = db.conn.cursor()
    try:
        agents = _load_agents(cursor, org_id)
        if not agents:
            return _empty_result()

        edges_by_src = _load_edges(cursor, org_id)
        reach_by_id = _load_reachability(cursor, org_id)

        # Source set — either one agent or all AI agents
        if source_identity_id:
            src_rec = next((a for a in agents.values()
                            if a['identity_id'] == source_identity_id), None)
            if not src_rec:
                return _empty_result()
            sources = [src_rec]
        else:
            sources = list(agents.values())

        # Trace chains from each source
        all_chains: list[dict[str, Any]] = []
        for src in sources:
            chains = _bfs_from(src, agents, edges_by_src, reach_by_id,
                               max_depth, classification_filter)
            all_chains.extend(chains)
            if len(all_chains) >= max_chains:
                break

        # Enrich + score each chain
        enriched = [_enrich_chain(db, c) for c in all_chains[:max_chains]]
        # Sort by severity rank, then dollar mid, then shorter depth wins
        enriched.sort(key=lambda c: (
            -_SEV_RANK.get(c['severity'], 0),
            -(c.get('dollar_band', {}).get('mid') or 0),
            c['depth'],
        ))

        # Stats
        by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for c in enriched:
            sev = c.get('severity', 'low')
            if sev in by_severity:
                by_severity[sev] += 1

        return {
            'source_agent': ({
                'identity_id':  sources[0]['identity_id'],
                'display_name': sources[0]['display_name'],
            } if source_identity_id else None),
            'chains': enriched,
            'chain_count': len(enriched),
            'by_severity': by_severity,
            'max_depth_searched': max_depth,
            'classification_filter': classification_filter,
            'computed_at': datetime.now(timezone.utc).isoformat(),
        }
    finally:
        cursor.close()


def invocation_graph(db, org_id: int) -> dict[str, Any]:
    """Return the raw {nodes, edges} graph for the agent-invocation surface.

    Used by the UI to render the node/edge visualization. No traversal —
    just the snapshot of who invokes whom.
    """
    cursor = db.conn.cursor()
    try:
        agents = _load_agents(cursor, org_id)
        edges_by_src = _load_edges(cursor, org_id)
        reach_by_id = _load_reachability(cursor, org_id)

        # Only include agents that appear in the edge set
        edge_nodes: set[int] = set()
        for src_id, edges in edges_by_src.items():
            edge_nodes.add(src_id)
            for e in edges:
                edge_nodes.add(e['target_db_id'])

        nodes = []
        for db_id in edge_nodes:
            agent = agents.get(db_id)
            if not agent:
                continue
            reaches = reach_by_id.get(db_id, [])
            worst_classification = None
            worst_records = 0
            for r in reaches:
                if (r.get('est_records') or 0) > worst_records:
                    worst_records = r['est_records']
                    worst_classification = r['classification']
            nodes.append({
                'identity_db_id':       db_id,
                'identity_id':          agent['identity_id'],
                'display_name':         agent['display_name'],
                'risk_level':           agent.get('risk_level'),
                'agent_identity_type':  agent.get('agent_identity_type'),
                'worst_data_class':     worst_classification,
                'worst_records':        worst_records,
                'reaches_count':        len(reaches),
            })

        edges_out = []
        for src_id, edges in edges_by_src.items():
            for e in edges:
                edges_out.append({
                    'source_db_id':      src_id,
                    'source_identity_id': e['source_identity_id'],
                    'target_db_id':      e['target_db_id'],
                    'target_identity_id': e['target_identity_id'],
                    'via_mechanism':     e['via_mechanism'],
                    'invocation_name':   e.get('invocation_name'),
                    'observed_count':    e.get('observed_count'),
                    'confidence':        e.get('confidence'),
                    'source':            e.get('source'),
                })

        return {
            'nodes': nodes,
            'edges': edges_out,
            'node_count': len(nodes),
            'edge_count': len(edges_out),
            'computed_at': datetime.now(timezone.utc).isoformat(),
        }
    finally:
        cursor.close()


# ─────────────────────────────────────────────────────────────────────────────
# Loaders
# ─────────────────────────────────────────────────────────────────────────────

def _load_agents(cursor, org_id: int) -> dict[int, dict[str, Any]]:
    """Load all AI agents in the latest snapshot, keyed by identity_db_id."""
    cursor.execute("""
        SELECT DISTINCT ON (i.identity_id)
               i.id, i.identity_id, i.display_name, i.risk_level,
               ac.agent_identity_type
          FROM identities i
          JOIN agent_classifications ac ON ac.identity_db_id = i.id
         WHERE i.organization_id = %s
           AND NOT COALESCE(i.is_microsoft_system, false)
           AND i.deleted_at IS NULL
           AND ac.agent_identity_type IN ('ai_agent','possible_ai_agent','ai_privileged_human')
         ORDER BY i.identity_id, i.discovery_run_id DESC
    """, (org_id,))
    out = {}
    for r in cursor.fetchall():
        out[r[0]] = {
            'id': r[0], 'identity_id': r[1], 'display_name': r[2],
            'risk_level': r[3], 'agent_identity_type': r[4],
        }
    return out


def _load_edges(cursor, org_id: int) -> dict[int, list[dict]]:
    """Load all invocation edges grouped by source_identity_db_id."""
    cursor.execute("""
        SELECT source_identity_db_id, source_identity_id,
               target_identity_db_id, target_identity_id,
               via_mechanism, invocation_name,
               observed_count, confidence, source
          FROM agent_invocations
         WHERE organization_id = %s
    """, (org_id,))
    out: dict[int, list[dict]] = defaultdict(list)
    for r in cursor.fetchall():
        out[r[0]].append({
            'source_db_id': r[0], 'source_identity_id': r[1],
            'target_db_id': r[2], 'target_identity_id': r[3],
            'via_mechanism': r[4], 'invocation_name': r[5],
            'observed_count': r[6], 'confidence': r[7], 'source': r[8],
        })
    return out


def _load_reachability(cursor, org_id: int) -> dict[int, list[dict]]:
    """Load agent_data_reachability rows grouped by identity_db_id."""
    cursor.execute("""
        SELECT identity_db_id, data_classification, est_records,
               write_resource_count, resource_count
          FROM agent_data_reachability
         WHERE organization_id = %s
    """, (org_id,))
    out: dict[int, list[dict]] = defaultdict(list)
    for r in cursor.fetchall():
        out[r[0]].append({
            'classification': r[1],
            'est_records': r[2] or 0,
            'write_resource_count': r[3] or 0,
            'resource_count': r[4] or 0,
        })
    return out


# ─────────────────────────────────────────────────────────────────────────────
# BFS traversal
# ─────────────────────────────────────────────────────────────────────────────

def _bfs_from(src_agent, agents, edges_by_src, reach_by_id,
              max_depth, classification_filter) -> list[dict[str, Any]]:
    """BFS from one source. Returns one chain per (target, classification)
    tuple — multiple chains per source are possible.

    A chain is emitted whenever the BFS reaches a node that has classified
    data reach (the SOURCE node itself counts as depth 0).
    """
    chains: list[dict] = []
    start_id = src_agent['id']

    # Queue items: (current_db_id, path_so_far, edges_used)
    # path = [agent_meta, ...]
    # edges = [edge, ...] (len = depth)
    init_path = [{
        'identity_db_id': start_id,
        'identity_id':    src_agent['identity_id'],
        'display_name':   src_agent['display_name'],
    }]
    q = deque([(start_id, init_path, [])])
    # Track visited per (source, target) to avoid cycles
    visited_pairs: set[tuple] = set()

    while q:
        current_id, path, edges_used = q.popleft()
        depth = len(edges_used)

        # Emit chain(s) at this node if it has classified reach
        for reach in reach_by_id.get(current_id, []):
            cls = reach['classification']
            if classification_filter and cls != classification_filter.upper():
                continue
            if (reach.get('est_records') or 0) <= 0:
                continue
            # Skip emitting the trivial "source agent reaches data itself"
            # chain when we're tracing from a specific source — those
            # are already covered by the single-hop reach. v2 is about
            # transitive chains, so depth >= 1 is the interesting case.
            if depth == 0:
                continue
            chains.append({
                'hops': path[:],
                'edges': edges_used[:],
                'depth': depth,
                'terminal_classification': cls,
                'terminal_records': reach['est_records'],
                'is_write': (reach.get('write_resource_count') or 0) > 0,
                'source_identity_id': src_agent['identity_id'],
                'source_display_name': src_agent['display_name'],
            })

        # Expand if not at depth limit
        if depth >= max_depth:
            continue

        for edge in edges_by_src.get(current_id, []):
            target_id = edge['target_db_id']
            if target_id in {p['identity_db_id'] for p in path}:
                continue  # cycle guard
            target_agent = agents.get(target_id)
            if not target_agent:
                continue
            pair_key = (start_id, target_id, depth + 1)
            if pair_key in visited_pairs:
                continue
            visited_pairs.add(pair_key)
            new_path = path + [{
                'identity_db_id': target_id,
                'identity_id':    target_agent['identity_id'],
                'display_name':   target_agent['display_name'],
            }]
            new_edges = edges_used + [edge]
            q.append((target_id, new_path, new_edges))

    return chains


# ─────────────────────────────────────────────────────────────────────────────
# Scoring + enrichment
# ─────────────────────────────────────────────────────────────────────────────

_SEV_RANK = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
_RANK_SEV = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}

_BASE_SEVERITY_BY_CLASS_WRITE = {
    ('PHI', True):  'critical',
    ('PHI', False): 'high',
    ('PCI', True):  'critical',
    ('PCI', False): 'high',
    ('PII', True):  'high',
    ('PII', False): 'medium',
    ('FINANCIAL', True):  'high',
    ('FINANCIAL', False): 'medium',
    ('HR', True):  'medium',
    ('HR', False): 'medium',
    ('SOURCE', True):  'medium',
    ('SOURCE', False): 'low',
    ('CONFIDENTIAL', True):  'medium',
    ('CONFIDENTIAL', False): 'low',
}

_WEAK_MECHANISMS = {'shared_secret'}
_MITRE_BY_MECHANISM = {
    'mcp':            ['T1199'],
    'http':           ['T1199'],
    'azure_function': ['T1648'],
    'webhook':        ['T1199'],
    'event_grid':     ['T1199'],
    'shared_secret':  ['T1078.004', 'T1552'],
    'service_bus':    ['T1648'],
}


def _enrich_chain(db, c: dict) -> dict[str, Any]:
    cls = c['terminal_classification']
    records = c['terminal_records']
    is_write = c['is_write']

    base_sev = _BASE_SEVERITY_BY_CLASS_WRITE.get((cls, is_write), 'low')
    # Bump severity if a weak link exists in the chain
    weakest = None
    for i, edge in enumerate(c['edges']):
        mech = edge.get('via_mechanism')
        conf = edge.get('confidence')
        if mech in _WEAK_MECHANISMS or conf == 'inferred':
            weakest = {
                'hop_index': i,
                'mechanism': mech,
                'confidence': conf,
                'reason': ('shared-secret authentication makes the invocation easy to impersonate'
                           if mech == 'shared_secret'
                           else 'inferred edge — provenance is heuristic, validate'),
            }
            break

    severity = base_sev
    if weakest and _SEV_RANK.get(severity, 0) < 4:
        severity = _RANK_SEV[_SEV_RANK[severity] + 1]

    # Dollar band from the existing breach_cost factor table
    exp = compute_exposure(db, cls, records)
    if exp.get('has_factor'):
        dollar_band = {
            'low':  float(exp['estimated_exposure_low']),
            'mid':  float(exp['estimated_exposure_mid']),
            'high': float(exp['estimated_exposure_high']),
            'low_display':  format_dollar_short(exp['estimated_exposure_low']),
            'mid_display':  format_dollar_short(exp['estimated_exposure_mid']),
            'high_display': format_dollar_short(exp['estimated_exposure_high']),
            'source':       exp.get('source'),
        }
    else:
        dollar_band = None

    # MITRE = union of the per-mechanism MITRE codes across the chain
    mitre = set()
    for edge in c['edges']:
        for t in _MITRE_BY_MECHANISM.get(edge.get('via_mechanism', ''), []):
            mitre.add(t)
    if cls in ('PHI', 'PCI'):
        mitre.add('T1530')   # Data from Cloud Storage
    if is_write:
        mitre.add('T1565')   # Data Manipulation

    # Headline string for UI
    chain_str = ' → '.join(h['display_name'] or h['identity_id'] for h in c['hops'])
    verb = 'write' if is_write else 'read'
    headline = f"{chain_str} ⇒ {verb} {records:,} {cls} records"

    return {
        'hops':                 c['hops'],
        'edges':                [{
            'source_identity_id': e['source_identity_id'],
            'target_identity_id': e['target_identity_id'],
            'via_mechanism':      e['via_mechanism'],
            'invocation_name':    e.get('invocation_name'),
            'confidence':         e.get('confidence'),
            'observed_count':     e.get('observed_count'),
        } for e in c['edges']],
        'depth':                c['depth'],
        'terminal_classification': cls,
        'terminal_records':     records,
        'is_write':             is_write,
        'severity':             severity,
        'base_severity':        base_sev,
        'weakest_link':         weakest,
        'mitre_techniques':     sorted(mitre),
        'dollar_band':          dollar_band,
        'source_identity_id':   c['source_identity_id'],
        'source_display_name':  c['source_display_name'],
        'headline':             headline,
    }


def _empty_result() -> dict:
    return {
        'source_agent': None,
        'chains': [],
        'chain_count': 0,
        'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'max_depth_searched': 0,
        'classification_filter': None,
        'computed_at': datetime.now(timezone.utc).isoformat(),
    }


__all__ = ['trace_multihop', 'invocation_graph', 'MAX_DEPTH_DEFAULT']
