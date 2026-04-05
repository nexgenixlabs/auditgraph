import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { ReactFlow, Controls, Background, MiniMap, Handle, Position, type Node, type Edge, type NodeProps } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useCopilot } from '../contexts/CopilotContext';
import { getMitreTechnique, collectMitreTags } from '../constants/mitre';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';

interface SimulationResult {
  simulation_id: string;
  identity_id: string;
  depth_limit: number;
  reachable_resources: number;
  reachable_identities: number;
  reachable_subscriptions: number;
  privilege_escalations: EscalationPath[];
  risk_score: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
  paths: Array<{ steps: string[]; risk_level: string; path_nodes?: string[] }>;
  blast_radius: {
    blast_radius_score: number;
    reachable_resources: number;
    reachable_identities: number;
    reachable_subscriptions: number;
  };
}

interface EscalationPath {
  type: string;
  source: string;
  target: string;
  risk_level: string;
  description: string;
}

interface GraphNode {
  id: string;
  label: string;
  type: string;
  depth?: number;
  is_start?: boolean;
  risk_level?: string;
}

interface GraphEdge {
  source: string;
  target: string;
  label: string;
}

interface IdentityResult {
  identity_id: string;
  display_name: string;
  identity_category: string;
  cloud: string;
  risk_score: number;
  risk_level: string;
}

const RISK_COLOR: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-emerald-400',
};

const RISK_BADGE: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400',
  high: 'bg-orange-500/20 text-orange-400',
  medium: 'bg-yellow-500/20 text-yellow-400',
  low: 'bg-emerald-500/20 text-emerald-400',
};

const NODE_COLORS: Record<string, { bg: string; border: string }> = {
  identity: { bg: '#1e40af', border: '#3b82f6' },
  role: { bg: '#7c3aed', border: '#a78bfa' },
  resource: { bg: '#059669', border: '#34d399' },
  subscription: { bg: '#d97706', border: '#fbbf24' },
  unknown: { bg: '#475569', border: '#94a3b8' },
};

const NODE_ICONS: Record<string, string> = {
  identity: '\uD83D\uDC64',
  role: '\uD83D\uDD12',
  resource: '\uD83D\uDCC1',
  subscription: '\u2601\uFE0F',
};

// ── Collapsible Section ──────────────────────────────────────────

function Section({ title, defaultOpen = true, badge, children }: {
  title: string; defaultOpen?: boolean; badge?: React.ReactNode; children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-slate-700/20 transition"
      >
        <div className="flex items-center gap-2">
          <svg className={`w-3 h-3 text-slate-500 transition-transform ${open ? 'rotate-90' : ''}`} fill="currentColor" viewBox="0 0 20 20">
            <path d="M6 4l8 6-8 6V4z" />
          </svg>
          <span className="text-xs font-semibold text-white uppercase tracking-wider">{title}</span>
          {badge}
        </div>
        <span className="text-[9px] text-slate-600">{open ? 'Collapse' : 'Expand'}</span>
      </button>
      {open && <div className="border-t border-slate-700/50">{children}</div>}
    </div>
  );
}

// ── Custom Attack Node ──────────────────────────────────────────────

function AttackSimNode({ data }: NodeProps) {
  const nodeType = (data.nodeType as string) || 'unknown';
  const isStart = !!data.isStart;
  const riskLevel = (data.riskLevel as string) || '';
  const colors = NODE_COLORS[nodeType] || NODE_COLORS.unknown;
  const icon = NODE_ICONS[nodeType] || '';
  const label = (data.label as string) || '';
  const nodeId = (data.nodeId as string) || '';

  return (
    <div
      className="rounded-lg px-3 py-2 min-w-[140px] max-w-[200px] cursor-pointer"
      style={{
        background: colors.bg,
        border: `2px solid ${colors.border}`,
        boxShadow: isStart ? `0 0 16px ${colors.border}, 0 0 32px ${colors.border}40` : `0 2px 8px rgba(0,0,0,0.3)`,
      }}
      title={nodeId}
    >
      <Handle type="target" position={Position.Top} style={{ background: colors.border, width: 6, height: 6 }} />
      <div className="flex items-center gap-1.5">
        {icon && <span className="text-sm">{icon}</span>}
        <span className="text-[11px] font-semibold text-white truncate flex-1">
          {label.length > 20 ? label.slice(0, 18) + '\u2026' : label}
        </span>
      </div>
      {riskLevel && (
        <div className="mt-1">
          <span className={`px-1.5 py-px rounded text-[9px] font-bold uppercase ${RISK_BADGE[riskLevel] || 'bg-slate-700 text-slate-400'}`}>
            {riskLevel}
          </span>
        </div>
      )}
      <Handle type="source" position={Position.Bottom} style={{ background: colors.border, width: 6, height: 6 }} />
    </div>
  );
}

const customNodeTypes = { attack_sim_node: AttackSimNode };

// ── Impact Classification ───────────────────────────────────────────

function getImpactLevel(score: number): { label: string; color: string; barColor: string } {
  if (score >= 80) return { label: 'CRITICAL', color: 'text-red-400', barColor: 'bg-red-500' };
  if (score >= 60) return { label: 'HIGH', color: 'text-orange-400', barColor: 'bg-orange-500' };
  if (score >= 40) return { label: 'MEDIUM', color: 'text-yellow-400', barColor: 'bg-yellow-500' };
  return { label: 'LOW', color: 'text-emerald-400', barColor: 'bg-emerald-500' };
}

// ── Inline Path Preview ──────────────────────────────────────────────

function PathPreview({ source, target, type }: { source: string; target: string; type: string }) {
  const typeIcon = NODE_ICONS[type === 'lateral_movement' ? 'identity' : type === 'credential_exposure' ? 'resource' : 'role'] || '\uD83D\uDD12';
  const s = source.length > 14 ? source.slice(0, 12) + '\u2026' : source;
  const t = target.length > 14 ? target.slice(0, 12) + '\u2026' : target;
  return (
    <div className="flex items-center gap-1 text-[9px]">
      <span className="px-1.5 py-0.5 bg-blue-500/10 border border-blue-500/20 rounded text-blue-400 font-mono truncate max-w-[80px]">{s}</span>
      <svg className="w-3 h-3 text-slate-600 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
      </svg>
      <span className="text-xs shrink-0">{typeIcon}</span>
      <svg className="w-3 h-3 text-slate-600 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
      </svg>
      <span className="px-1.5 py-0.5 bg-red-500/10 border border-red-500/20 rounded text-red-400 font-mono truncate max-w-[80px]">{t}</span>
    </div>
  );
}

// ── Main Component ──────────────────────────────────────────────────

export default function AttackSimulator() {
  const navigate = useNavigate();
  const { openCopilot } = useCopilot();
  const { withConnection, selectedConnectionId } = useConnection();
  const { activeOrgId } = useAuth();
  const [identityId, setIdentityId] = useState('');
  const [depthLimit, setDepthLimit] = useState(6);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<SimulationResult | null>(null);

  // Identity search state
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<IdentityResult[]>([]);
  const [searchOpen, setSearchOpen] = useState(false);
  const [selectedName, setSelectedName] = useState('');
  const [selectedIdentity, setSelectedIdentity] = useState<IdentityResult | null>(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as HTMLElement)) {
        setSearchOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  const searchIdentities = useCallback(async (q: string) => {
    if (q.length < 2) { setSearchResults([]); setSearchLoading(false); return; }
    setSearchLoading(true);
    try {
      const res = await fetch(withConnection(`/api/identities?search=${encodeURIComponent(q)}&limit=10`));
      if (res.ok) {
        const data = await res.json();
        setSearchResults(data.identities || []);
        setSearchOpen(true);
      }
    } catch { /* ignore */ }
    setSearchLoading(false);
  }, [withConnection, selectedConnectionId, activeOrgId]);

  const handleSearchInput = useCallback((value: string) => {
    setSearchQuery(value);
    setSelectedName('');
    setIdentityId('');
    setSelectedIdentity(null);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => searchIdentities(value), 300);
  }, [searchIdentities]);

  const handleSelectIdentity = useCallback((ident: IdentityResult) => {
    setIdentityId(ident.identity_id);
    setSelectedName(ident.display_name);
    setSelectedIdentity(ident);
    setSearchQuery('');
    setSearchOpen(false);
    setSearchResults([]);
  }, []);

  const simulate = async () => {
    if (!identityId) { setError('Select an identity first.'); return; }
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const res = await fetch(withConnection('/api/attack/simulate'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identity_id: identityId, max_depth: depthLimit }),
      });
      let data;
      try { data = await res.json(); } catch { data = { error: 'Server error — check logs.' }; }
      if (!res.ok) {
        setError(data.error || 'Simulation failed.');
      } else {
        setResult(data);
      }
    } catch {
      setError('Network error.');
    }
    setLoading(false);
  };

  const { flowNodes, flowEdges } = useMemo(() => {
    if (!result || !result.nodes || result.nodes.length === 0) {
      return { flowNodes: [] as Node[], flowEdges: [] as Edge[] };
    }
    const byDepth: Record<number, GraphNode[]> = {};
    for (const n of result.nodes) {
      const d = n.depth ?? 0;
      if (!byDepth[d]) byDepth[d] = [];
      byDepth[d].push(n);
    }
    const nodes: Node[] = [];
    for (const [depthStr, group] of Object.entries(byDepth)) {
      const depth = Number(depthStr);
      const centerX = 400;
      const startY = depth * 180;
      const spacing = Math.max(200, 800 / (group.length || 1));
      const offsetX = -(group.length - 1) * spacing / 2;
      group.forEach((n, i) => {
        nodes.push({
          id: n.id,
          type: 'attack_sim_node',
          position: { x: centerX + offsetX + i * spacing, y: startY },
          data: { label: n.label, nodeType: n.type, isStart: n.is_start || false, riskLevel: n.risk_level || '', nodeId: n.id },
        });
      });
    }
    const edges: Edge[] = result.edges.map((e, i) => ({
      id: `e-${i}`, source: e.source, target: e.target, label: e.label,
      animated: true, style: { stroke: '#64748b', strokeWidth: 1.5 }, labelStyle: { fill: '#94a3b8', fontSize: 9 },
    }));
    return { flowNodes: nodes, flowEdges: edges };
  }, [result]);

  const handleNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    const nodeType = node.data.nodeType as string;
    const nodeId = node.data.nodeId as string;
    if (nodeType === 'identity' && nodeId) navigate(`/identities/${nodeId}`);
    else if (nodeType === 'resource' && nodeId) navigate(`/resources/${encodeURIComponent(nodeId)}`);
  }, [navigate]);

  const impactData = useMemo(() => {
    if (!result) return null;
    const impact = getImpactLevel(result.risk_score);
    const longestPath = (result.paths || []).reduce((max, p) => Math.max(max, (p.steps || []).length), 0);
    const escalationTypes = result.privilege_escalations.map(e => e.type);
    const mitreTags = collectMitreTags(escalationTypes);
    const privilegedRoles = result.privilege_escalations.filter(e => e.type === 'direct_escalation' || e.risk_level === 'critical').length;
    const lateralDepth = result.privilege_escalations.filter(e => e.type === 'lateral_movement').length;
    const externalIdents = result.privilege_escalations.filter(e => e.type === 'external_identity_risk').length;
    const keyVaults = result.nodes.filter(n => n.type === 'resource' && n.label.toLowerCase().includes('vault')).length;
    return { impact, longestPath, mitreTags, privilegedRoles, lateralDepth, externalIdents, keyVaults };
  }, [result]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Attack Path Simulator</h1>
        <p className="text-sm text-slate-400 mt-1">
          Simulate lateral movement and privilege escalation from a compromised identity.
        </p>
      </div>

      {/* Input Controls */}
      <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div className="md:col-span-3 relative" ref={dropdownRef}>
            <label className="block text-xs font-medium text-slate-400 mb-1">Target Identity</label>
            <input
              type="text"
              value={selectedName || searchQuery}
              onChange={(e) => handleSearchInput(e.target.value)}
              onFocus={() => searchResults.length > 0 && setSearchOpen(true)}
              placeholder="Search by identity name..."
              className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 outline-none"
            />
            {searchLoading && <div className="absolute right-3 top-8 text-xs text-slate-500">Searching...</div>}
            {identityId && <div className="mt-1 text-[10px] text-slate-500 font-mono truncate">ID: {identityId}</div>}
            {searchOpen && searchResults.length > 0 && (
              <div className="absolute z-20 w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg shadow-xl max-h-72 overflow-y-auto">
                {searchResults.map((ident) => (
                  <button key={ident.identity_id} onClick={() => handleSelectIdentity(ident)}
                    className="w-full text-left px-3 py-2.5 hover:bg-slate-700/50 text-sm flex items-center justify-between gap-2 border-b border-slate-700/50 last:border-0">
                    <div className="min-w-0 flex-1">
                      <div className="font-medium text-white truncate">{ident.display_name}</div>
                      <div className="text-[10px] text-slate-500 mt-0.5">{ident.identity_category} · {ident.cloud}</div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {ident.risk_score > 0 && <span className="text-[10px] font-mono text-slate-400">{ident.risk_score}</span>}
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${RISK_BADGE[ident.risk_level] || 'bg-slate-700 text-slate-400'}`}>
                        {ident.risk_level || 'info'}
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            )}
            {searchOpen && searchQuery.length >= 2 && searchResults.length === 0 && !searchLoading && (
              <div className="absolute z-20 w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg shadow-xl p-4 text-center text-sm text-slate-500">
                No identities found
              </div>
            )}
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Depth: {depthLimit}</label>
            <input type="range" min={1} max={10} value={depthLimit} onChange={(e) => setDepthLimit(Number(e.target.value))} className="w-full mt-2 accent-red-500" />
            <div className="flex justify-between text-[10px] text-slate-500"><span>1</span><span>10</span></div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={simulate} disabled={loading || !identityId}
            className="px-5 py-2 rounded-lg text-sm font-semibold text-white bg-red-600 hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition">
            {loading ? 'Simulating...' : 'Simulate Attack'}
          </button>
          {identityId && (
            <button onClick={() => { setIdentityId(''); setSelectedName(''); setSelectedIdentity(null); setSearchQuery(''); setResult(null); setError(''); }}
              className="px-3 py-2 rounded-lg text-sm text-slate-400 hover:text-white hover:bg-slate-700 transition">Clear</button>
          )}
          {error && <span className="text-sm text-red-400">{error}</span>}
        </div>
      </div>

      {/* ── Results ── */}
      {result && impactData && (
        <div className="space-y-3">

          {/* "If This Identity Is Compromised" — always visible above fold */}
          <div className="bg-slate-800/50 border border-red-500/20 rounded-xl p-5">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-8 h-8 rounded-full bg-red-500/15 flex items-center justify-center shrink-0">
                <svg className="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-xs text-slate-500 uppercase tracking-wider font-semibold">If This Identity Is Compromised</div>
                <button onClick={() => navigate(`/identities/${result.identity_id}`)}
                  className="text-sm font-bold text-blue-400 hover:underline truncate block">
                  {selectedIdentity?.display_name || result.identity_id}
                </button>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {selectedIdentity && (
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${RISK_BADGE[selectedIdentity.risk_level] || 'bg-slate-700 text-slate-400'}`}>
                    {selectedIdentity.risk_level}
                  </span>
                )}
                <span className={`px-3 py-1 rounded-lg text-xs font-bold ${impactData.impact.color} bg-slate-900/50 border border-slate-700/50`}>
                  {impactData.impact.label}
                </span>
              </div>
            </div>

            {/* Blast Radius Grid — all numbers clickable */}
            <div className="grid grid-cols-3 md:grid-cols-6 gap-2 mb-4">
              {[
                { label: 'Risk Score', value: result.risk_score, color: impactData.impact.color, nav: '' },
                { label: 'Subscriptions', value: result.reachable_subscriptions, color: 'text-white', nav: '/identities' },
                { label: 'Resources', value: result.reachable_resources, color: 'text-white', nav: '/resources' },
                { label: 'Key Vaults', value: impactData.keyVaults, color: 'text-white', nav: '/resources?resource_type=key_vault' },
                { label: 'Privileged Roles', value: impactData.privilegedRoles, color: 'text-white', nav: '/identities?risk_level=critical' },
                { label: 'Escalation Steps', value: impactData.longestPath, color: 'text-white', nav: '' },
              ].map(m => (
                <div key={m.label} className={`p-2.5 bg-slate-900/50 rounded-lg border border-slate-700/30 ${m.nav ? 'cursor-pointer hover:bg-slate-700/20' : ''} transition`}
                  onClick={() => m.nav && navigate(m.nav)}>
                  <div className={`text-xl font-bold font-mono ${m.color}`}>{m.value}</div>
                  <div className="text-[9px] text-slate-500 uppercase">{m.label}</div>
                </div>
              ))}
            </div>

            {/* Impact bar + MITRE tags in one row */}
            <div className="flex items-center gap-4">
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-2 bg-slate-900 rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${impactData.impact.barColor}`} style={{ width: `${Math.min(result.risk_score, 100)}%` }} />
                  </div>
                  <span className={`text-[10px] font-bold ${impactData.impact.color}`}>{result.risk_score}/100</span>
                </div>
              </div>
              {impactData.mitreTags.length > 0 && (
                <div className="flex gap-1.5 shrink-0">
                  {impactData.mitreTags.slice(0, 4).map(tech => (
                    <a key={tech.id} href={tech.url} target="_blank" rel="noopener noreferrer"
                      className="px-2 py-0.5 rounded text-[9px] bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 transition font-mono font-bold">
                      {tech.id}
                    </a>
                  ))}
                </div>
              )}
            </div>

            {/* Top Escalation Chain */}
            {(result.paths || []).length > 0 && (
              <div className="mt-3 pt-3 border-t border-slate-700/30">
                <div className="text-[9px] text-slate-500 uppercase tracking-wider mb-1.5">Top Escalation Chain</div>
                <div className="flex items-center gap-1 flex-wrap">
                  {(result.paths[0].steps || []).map((step, i, arr) => (
                    <React.Fragment key={i}>
                      <span className="px-2 py-0.5 bg-slate-900/80 border border-slate-700/50 rounded text-[9px] text-slate-300 font-mono truncate max-w-[120px]" title={step}>
                        {step.length > 16 ? step.slice(0, 14) + '\u2026' : step}
                      </span>
                      {i < arr.length - 1 && (
                        <svg className="w-2.5 h-2.5 text-slate-600 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
                      )}
                    </React.Fragment>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Attack Path Graph — collapsible */}
          {flowNodes.length > 0 && (
            <Section title="Attack Path Graph" badge={
              <span className="text-[9px] text-slate-500 font-mono">{result.nodes.length} nodes · {result.edges.length} edges</span>
            }>
              <div className="px-3 py-2 flex items-center gap-3 text-[10px] text-slate-500 bg-slate-900/30">
                {Object.entries(NODE_COLORS).filter(([k]) => k !== 'unknown').map(([type, colors]) => (
                  <span key={type} className="flex items-center gap-1">
                    <span className="text-xs">{NODE_ICONS[type] || ''}</span>
                    <span className="w-2 h-2 rounded-sm" style={{ background: colors.bg, border: `1px solid ${colors.border}` }} />
                    {type}
                  </span>
                ))}
                <span className="ml-auto text-slate-600">|</span>
                {['critical', 'high', 'medium', 'low'].map(level => (
                  <span key={level} className={`px-1 py-px rounded text-[8px] font-bold uppercase ${RISK_BADGE[level]}`}>{level}</span>
                ))}
              </div>
              <div style={{ height: 420 }}>
                <ReactFlow nodes={flowNodes} edges={flowEdges} nodeTypes={customNodeTypes} onNodeClick={handleNodeClick}
                  fitView proOptions={{ hideAttribution: true }} style={{ background: '#0f172a' }}>
                  <Background color="#1e293b" gap={20} />
                  <Controls showInteractive={false} style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }} />
                  <MiniMap nodeColor={() => '#3b82f6'} style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }} />
                </ReactFlow>
              </div>
            </Section>
          )}

          {/* Copilot */}
          <button onClick={() => openCopilot({ contextType: 'attack_path', contextId: String(result.identity_id), contextLabel: `Attack Simulation (score: ${result.risk_score})`, initialQuestion: 'Analyze this attack simulation and recommend mitigations' })}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-indigo-400 bg-indigo-500/10 hover:bg-indigo-500/20 rounded-lg border border-indigo-500/30 transition">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
            Analyze with Copilot
          </button>

          {/* Escalation Paths — collapsible with inline path previews */}
          {result.privilege_escalations.length > 0 && (
            <Section title="Privilege Escalation Paths" defaultOpen={false} badge={
              <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-red-500/20 text-red-400">{result.privilege_escalations.length}</span>
            }>
              <table className="w-full text-sm">
                <thead className="bg-slate-900/50 text-slate-400 uppercase text-xs tracking-wider">
                  <tr>
                    <th className="px-4 py-2 text-left">Path</th>
                    <th className="px-4 py-2 text-left">Type</th>
                    <th className="px-4 py-2 text-left">Risk</th>
                    <th className="px-4 py-2 text-left">MITRE</th>
                    <th className="px-4 py-2 text-left">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/50">
                  {result.privilege_escalations.map((path, i) => {
                    const mitre = getMitreTechnique(path.type);
                    return (
                      <tr key={i} className="hover:bg-slate-700/20">
                        <td className="px-4 py-2">
                          <PathPreview source={path.source} target={path.target} type={path.type} />
                        </td>
                        <td className="px-4 py-2 text-xs font-medium text-slate-300">{path.type}</td>
                        <td className="px-4 py-2">
                          <span className={`text-xs font-bold uppercase ${RISK_COLOR[path.risk_level] || 'text-slate-500'}`}>{path.risk_level}</span>
                        </td>
                        <td className="px-4 py-2">
                          {mitre ? (
                            <a href={mitre.url} target="_blank" rel="noopener noreferrer"
                              className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 transition">
                              <span className="font-mono font-bold">{mitre.id}</span>
                              <span className="text-slate-600">{'\u00B7'}</span>
                              <span className="truncate max-w-[80px]">{mitre.tactic}</span>
                            </a>
                          ) : <span className="text-[10px] text-slate-600">—</span>}
                        </td>
                        <td className="px-4 py-2 text-xs text-slate-400 max-w-[200px] truncate" title={path.description}>{path.description}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </Section>
          )}
        </div>
      )}

      {/* Empty state */}
      {!result && !loading && (
        <div className="bg-slate-800/30 border border-dashed border-slate-700/50 rounded-xl p-12 text-center">
          <svg className="w-12 h-12 text-slate-600 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <div className="text-sm font-semibold text-slate-400">Select an identity and run a simulation</div>
          <div className="text-xs text-slate-500 mt-1">The simulator will trace lateral movement and privilege escalation paths.</div>
        </div>
      )}
    </div>
  );
}
