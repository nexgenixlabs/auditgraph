/**
 * AIIdentityGraph — Clustered relationship map of AI agent identities.
 *
 * AG-163: replaces the prior wall-of-circles grid with a real graph:
 *   - Central tenant node
 *   - 4 resource clusters (Vaults / Data / Network / Models)
 *   - AI agent leaves radiating from their primary cluster
 *   - Edge color = highest privilege the agent holds on that cluster
 *   - Node size = risk score
 *   - Right-side "Top 5 Risks" panel with a generated WHY sentence per agent
 *   - 3 KPI risk strip at the top, each clickable to filter the graph
 *
 * Data source: `/api/ai-security/inventory-graph` — live, tenant-scoped via RLS.
 */
import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { ReactFlow, Background, Controls, MiniMap, Position } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useConnection } from '../contexts/ConnectionContext';
import { formatPlatform } from '../constants/aiRisk';
import AIInvestigateDrawer from '../components/AIInvestigateDrawer';

interface Cluster {
  id: string;
  cluster: 'vaults' | 'data' | 'network' | 'models';
  label: string;
  description: string;
  agent_count: number;
  critical_count: number;
}

interface AgentSignal {
  key: string;
  title: string;
  weight: number;
  mitre: string[];
}

interface AgentNode {
  id: string;
  label: string;
  platform: string;
  agent_type: string;
  risk_score: number;                           // AG-164: CVSS-aligned 0–10
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  primary_cluster: Cluster['cluster'];
  edge_color: string;
  edge_label: string;
  access: Record<string, string>;
  signal_count?: number;                        // AG-164
  top_signals?: AgentSignal[];                  // AG-164
}

interface TopRisk {
  id: string;
  label: string;
  platform: string;
  score: number;                                // CVSS-aligned 0–10
  severity: string;
  why: string;
  mitre?: string[];                             // AG-164
}

interface InventoryGraphData {
  tenant_label?: string;   // org name (· connection label when in connection context)
  clusters: Cluster[];
  agents: AgentNode[];
  stats: {
    total_agents: number;
    critical_agents: number;
    with_subscription_owner: number;
    with_kv_admin_or_blob_owner: number;
  };
  top_risks: TopRisk[];
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#fb923c',
  medium:   '#facc15',
  low:      '#4ade80',
  info:     '#9ca3af',
};

// Compass positions for the 4 cluster spokes around the tenant center.
const CLUSTER_POS: Record<Cluster['cluster'], { x: number; y: number; ring: { dx: number; dy: number } }> = {
  vaults:  { x:  320, y: -200, ring: { dx:  120, dy:  -60 } },
  data:    { x:  320, y:  200, ring: { dx:  120, dy:   60 } },
  network: { x: -320, y:  200, ring: { dx: -120, dy:   60 } },
  models:  { x: -320, y: -200, ring: { dx: -120, dy:  -60 } },
};
const TENANT_POS = { x: 0, y: 0 };
const AGENTS_PER_CLUSTER_VISIBLE = 12;
const AGENT_RING_RADIUS = 180;

// ── Custom node components ──────────────────────────────────────────────────

function TenantNode({ data }: { data: Record<string, unknown> }) {
  return (
    <div
      className="rounded-full flex flex-col items-center justify-center border-2 shadow-2xl"
      style={{
        width: 110, height: 110,
        borderColor: '#24A2A1',
        background: 'radial-gradient(circle, rgba(36,162,161,0.25) 0%, rgba(36,162,161,0.05) 70%)',
        color: 'var(--text-primary)',
      }}
    >
      <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: '#24A2A1' }}>Tenant</span>
      <span className="text-sm font-bold truncate max-w-[90px] text-center">{(data.label as string) || 'AI Inventory'}</span>
      <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>{data.count as number} agents</span>
    </div>
  );
}

function ClusterNode({ data }: { data: Record<string, unknown> }) {
  const critical = (data.critical_count as number) || 0;
  return (
    <div
      className="rounded-xl border-2 px-3 py-2 min-w-[140px] text-center shadow-lg"
      style={{
        borderColor: critical > 0 ? '#ef4444' : '#475569',
        backgroundColor: critical > 0 ? 'rgba(239, 68, 68, 0.08)' : 'rgba(71, 85, 105, 0.15)',
      }}
    >
      <div className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: critical > 0 ? '#f87171' : '#94a3b8' }}>
        {data.label as string}
      </div>
      <div className="text-2xl font-bold font-mono" style={{ color: 'var(--text-primary)' }}>
        {data.count as number}
      </div>
      {critical > 0 && (
        <div className="text-[10px]" style={{ color: '#f87171' }}>
          {critical} critical
        </div>
      )}
      <div className="text-[9px] mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
        {data.description as string}
      </div>
    </div>
  );
}

function AgentLeafNode({ data }: { data: Record<string, unknown> }) {
  const score = (data.risk_score as number) || 0;
  // AG-164: scores are CVSS-aligned 0–10. Size scales 28→60 px.
  const size = Math.max(28, Math.min(60, 28 + score * 3.2));
  const sev = (data.severity as string) || 'low';
  const signals = (data.top_signals as AgentSignal[]) || [];
  const tipLines = [
    `${data.label}`,
    `Severity: ${sev.toUpperCase()}  ·  Score ${score.toFixed(1)}/10`,
    `Platform: ${formatPlatform(data.platform as string)}`,
    ...(signals.length ? ['Top signals:'] : []),
    ...signals.map(s => `  • ${s.title}`),
  ];
  return (
    <div className="flex flex-col items-center gap-0.5" style={{ cursor: 'pointer' }}>
      <div
        className="rounded-full flex items-center justify-center border-2 transition-transform hover:scale-110"
        style={{
          width: size, height: size,
          borderColor: SEVERITY_COLOR[sev] || SEVERITY_COLOR.low,
          backgroundColor: 'var(--bg-raised)',
        }}
        title={tipLines.join('\n')}
      >
        <span className="text-[10px] font-bold font-mono" style={{ color: SEVERITY_COLOR[sev] || SEVERITY_COLOR.low }}>
          {score.toFixed(1)}
        </span>
      </div>
      <span className="text-[9px] truncate max-w-[80px] text-center"
        style={{ color: 'var(--text-secondary)' }}>
        {(data.label as string)?.slice(0, 16) || ''}
      </span>
    </div>
  );
}

const NODE_TYPES = { tenant: TenantNode, cluster: ClusterNode, agent_leaf: AgentLeafNode };

// ── Page ─────────────────────────────────────────────────────────────────────

export default function AIIdentityGraph() {
  const { withConnection, selectedConnectionId } = useConnection();
  const navigate = useNavigate();
  const [data, setData] = useState<InventoryGraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [investigateId, setInvestigateId] = useState<string | null>(null);
  const [activeFilter, setActiveFilter] = useState<'all' | 'critical' | 'sub_owner' | 'kv_admin'>('all');

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetch(withConnection('/api/ai-security/inventory-graph'))
      .then(r => {
        if (r.status === 404) { setError('not_found'); return null; }
        if (!r.ok) { setError('fetch_error'); return null; }
        return r.json();
      })
      .then(d => { if (d) setData(d as InventoryGraphData); })
      .catch(() => setError('fetch_error'))
      .finally(() => setLoading(false));
  }, [withConnection, selectedConnectionId]);

  // Build ReactFlow nodes+edges from the inventory graph response.
  const { nodes, edges } = useMemo(() => {
    if (!data) return { nodes: [], edges: [] };

    // Filter agents per active KPI
    const matches = (a: AgentNode): boolean => {
      if (activeFilter === 'critical') return a.severity === 'critical';
      // sub_owner / kv_admin filters approximated client-side via access fields.
      if (activeFilter === 'sub_owner') {
        return a.access?.data_access === 'owner' || a.access?.data_access === 'contributor';
      }
      if (activeFilter === 'kv_admin') {
        return a.access?.key_vault_access === 'administrator' ||
               a.access?.key_vault_access === 'secrets_officer';
      }
      return true;
    };
    const visibleAgents = data.agents.filter(matches);

    // Group agents by cluster (already sorted by risk DESC server-side)
    const byCluster: Record<string, AgentNode[]> = {};
    for (const a of visibleAgents) {
      (byCluster[a.primary_cluster] ||= []).push(a);
    }

    const rfNodes: any[] = [];
    const rfEdges: any[] = [];

    // Tenant center
    rfNodes.push({
      id: 'tenant',
      type: 'tenant',
      position: TENANT_POS,
      data: { label: data.tenant_label || 'Your Tenant', count: visibleAgents.length },
      draggable: false,
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    });

    // Cluster nodes + edges from tenant
    for (const c of data.clusters) {
      const pos = CLUSTER_POS[c.cluster];
      if (!pos) continue;
      const visibleInCluster = byCluster[c.cluster] || [];
      rfNodes.push({
        id: c.id,
        type: 'cluster',
        position: { x: pos.x, y: pos.y },
        data: {
          label: c.label,
          description: c.description,
          count: visibleInCluster.length,
          critical_count: visibleInCluster.filter(a => a.severity === 'critical').length,
        },
        draggable: false,
      });
      rfEdges.push({
        id: `e-tenant-${c.id}`,
        source: 'tenant',
        target: c.id,
        style: { stroke: '#475569', strokeWidth: 2 },
      });

      // Place agents in a fan around the cluster
      const cap = Math.min(visibleInCluster.length, AGENTS_PER_CLUSTER_VISIBLE);
      for (let i = 0; i < cap; i++) {
        const a = visibleInCluster[i];
        // Fan angle: spread agents on the side of the cluster facing OUT from tenant
        const baseAngle = Math.atan2(pos.y, pos.x);
        const spread = Math.PI * 0.7;  // 126° fan
        const t = cap === 1 ? 0 : (i / (cap - 1)) - 0.5;
        const angle = baseAngle + spread * t;
        const ax = pos.x + AGENT_RING_RADIUS * Math.cos(angle);
        const ay = pos.y + AGENT_RING_RADIUS * Math.sin(angle);
        rfNodes.push({
          id: `agent:${a.id}`,
          type: 'agent_leaf',
          position: { x: ax, y: ay },
          data: { ...a },
          draggable: false,
        });
        rfEdges.push({
          id: `e-${c.id}-${a.id}`,
          source: c.id,
          target: `agent:${a.id}`,
          style: { stroke: a.edge_color, strokeWidth: a.severity === 'critical' ? 2.5 : 1.5 },
          animated: a.severity === 'critical',
        });
      }
    }

    return { nodes: rfNodes, edges: rfEdges };
  }, [data, activeFilter]);

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center py-20">
        <div className="animate-spin h-8 w-8 border-2 border-violet-500 border-t-transparent rounded-full" />
      </div>
    );
  }
  if (error === 'not_found') {
    return (
      <div className="p-6 max-w-[1600px] mx-auto">
        <h1 className="text-2xl font-bold text-white mb-2">AI Identity Graph</h1>
        <div className="rounded-lg border p-10 text-center mt-6"
          style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}>
          <p className="text-sm text-slate-400">AI agent governance not enabled. Run a discovery scan first.</p>
        </div>
      </div>
    );
  }
  if (!data) return null;

  // 3 KPI cards — clickable filter
  const KPIS: Array<{
    id: typeof activeFilter; label: string; value: number; tone: 'critical' | 'high' | 'medium';
    sub: string;
  }> = [
    { id: 'critical',  label: 'Critical Agents',          value: data.stats.critical_agents,             tone: 'critical', sub: 'CVSS ≥ 9.0' },
    { id: 'sub_owner', label: 'With Sub-Owner Access',    value: data.stats.with_subscription_owner,     tone: 'high',     sub: 'Owner / Contributor / UAA on subscription' },
    { id: 'kv_admin',  label: 'With KV-Admin or Blob-Owner', value: data.stats.with_kv_admin_or_blob_owner, tone: 'high',  sub: 'Direct secret / data ownership' },
  ];

  return (
    <div className="p-6 max-w-[1600px] mx-auto space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">AI Identity Graph</h1>
        <p className="text-sm text-slate-400 mt-1">
          Where {data.stats.total_agents} AI agent identit{data.stats.total_agents === 1 ? 'y is' : 'ies are'}
          {' '}touching the most sensitive resource clusters in your tenant
        </p>
      </div>

      {/* Risk strip — 3 clickable KPIs */}
      <div className="grid grid-cols-3 gap-3">
        {KPIS.map(k => {
          const active = activeFilter === k.id;
          const color = SEVERITY_COLOR[k.tone];
          return (
            <button
              key={k.id}
              onClick={() => setActiveFilter(active ? 'all' : k.id)}
              className="rounded-xl border p-4 text-left transition hover:scale-[1.01]"
              style={{
                borderColor: active ? color : 'var(--border-default)',
                backgroundColor: active
                  ? `${color}1a`
                  : 'var(--bg-raised)',
                outline: active ? `1px solid ${color}` : 'none',
              }}
            >
              <p className="text-[10px] uppercase tracking-wider font-semibold"
                style={{ color: 'var(--text-tertiary)' }}>{k.label}</p>
              <p className="text-3xl font-bold font-mono mt-1" style={{ color }}>{k.value}</p>
              <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>
                {k.sub}{active ? ' · filtering' : ' · click to filter'}
              </p>
            </button>
          );
        })}
      </div>

      {/* Body — graph + top risks side by side */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">
        {/* Force-directed graph */}
        <div className="lg:col-span-3 rounded-xl border overflow-hidden"
          style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-default)', height: 580 }}>
          {nodes.length === 0 ? (
            <div className="h-full flex items-center justify-center text-sm" style={{ color: 'var(--text-tertiary)' }}>
              No agents match the current filter
            </div>
          ) : (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={NODE_TYPES}
              fitView
              fitViewOptions={{ padding: 0.2 }}
              minZoom={0.3}
              maxZoom={1.4}
              proOptions={{ hideAttribution: true }}
              nodesDraggable={false}
              nodesConnectable={false}
              onNodeClick={(_e, node) => {
                if (node.id.startsWith('agent:')) {
                  setInvestigateId(node.id.slice('agent:'.length));
                }
              }}
            >
              <Background gap={20} size={1} color="#1e2d4a" />
              <Controls position="bottom-left" showInteractive={false} />
              <MiniMap nodeColor={(n) => {
                if (n.id === 'tenant') return '#24A2A1';
                if (n.id.startsWith('cluster:')) return '#475569';
                const sev = (n.data as any)?.severity || 'low';
                return SEVERITY_COLOR[sev] || SEVERITY_COLOR.low;
              }} maskColor="rgba(8,15,28,0.6)" pannable zoomable />
            </ReactFlow>
          )}
        </div>

        {/* Top 5 Risks with WHY */}
        <div className="lg:col-span-2 rounded-xl border"
          style={{ backgroundColor: 'var(--bg-raised)', borderColor: 'var(--border-default)' }}>
          <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
            <h3 className="text-sm font-semibold text-white">Top 5 AI Risks</h3>
            <p className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
              Sorted by CVSS-aligned score (0–10) · click any row to investigate
            </p>
          </div>
          <div className="p-2">
            {data.top_risks.length === 0 ? (
              <p className="text-xs text-emerald-400/80 py-6 text-center">
                ✓ No high-risk AI agents detected
              </p>
            ) : data.top_risks.map((r) => {
              const color = SEVERITY_COLOR[r.severity] || SEVERITY_COLOR.low;
              return (
                <button
                  key={r.id}
                  onClick={() => setInvestigateId(r.id)}
                  className="w-full text-left rounded-lg p-3 transition hover:bg-slate-800/40 border border-transparent hover:border-slate-700/60"
                >
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className="text-xs font-semibold truncate" style={{ color: 'var(--text-primary)' }}>
                      {r.label}
                    </span>
                    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded"
                      style={{ color, backgroundColor: `${color}1a`, border: `1px solid ${color}55` }}
                      title="CVSS-aligned 0–10 score"
                    >
                      {r.score.toFixed(1)}
                    </span>
                  </div>
                  <p className="text-[10px] mb-1.5" style={{ color: 'var(--text-tertiary)' }}>
                    {formatPlatform(r.platform)} · {r.severity.toUpperCase()}
                  </p>
                  <p className="text-[11px] leading-snug mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                    {r.why}
                  </p>
                  {/* AG-164: MITRE ATT&CK chips for defensibility */}
                  {r.mitre && r.mitre.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {r.mitre.slice(0, 4).map((tid) => (
                        <span
                          key={tid}
                          className="text-[9px] font-mono px-1.5 py-0.5 rounded border"
                          style={{
                            color: '#a78bfa',
                            borderColor: 'rgba(139, 92, 246, 0.35)',
                            backgroundColor: 'rgba(139, 92, 246, 0.08)',
                          }}
                          title={`MITRE ATT&CK technique ${tid}`}
                        >
                          {tid}
                        </span>
                      ))}
                    </div>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Legend — AG-164: cite the scoring standard prominently */}
      <div className="flex items-center gap-5 text-[10px] flex-wrap"
        style={{ color: 'var(--text-tertiary)' }}>
        <span className="font-semibold">CVSS v3.1 severity:</span>
        {(['critical','high','medium','low'] as const).map(s => (
          <span key={s} className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full border-2" style={{ borderColor: SEVERITY_COLOR[s] }} />
            {s.charAt(0).toUpperCase() + s.slice(1)}
          </span>
        ))}
        <span>·</span>
        <span>Node size = CVSS score (0–10)</span>
        <span>·</span>
        <span>Edge color = highest privilege in cluster</span>
        <span>·</span>
        <span title="Scoring methodology cites NIST SP 800-53 controls, CVSS v3.1 vectors, and MITRE ATT&CK techniques per signal">
          NIST · CVSS · MITRE-aligned
        </span>
        <button
          onClick={() => navigate('/ai-inventory/agents')}
          className="ml-auto text-xs hover:underline"
          style={{ color: '#60a5fa' }}
        >
          See full agent table →
        </button>
      </div>

      {investigateId && (
        <AIInvestigateDrawer identityId={investigateId} onClose={() => setInvestigateId(null)} />
      )}
    </div>
  );
}
