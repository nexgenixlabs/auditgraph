import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { ReactFlow, Controls, Background, MiniMap, type Node, type Edge } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useCopilot } from '../contexts/CopilotContext';

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

export default function AttackSimulator() {
  const { openCopilot } = useCopilot();
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
  const [searchLoading, setSearchLoading] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  // Close dropdown on outside click
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
      const res = await fetch(`/api/identities?search=${encodeURIComponent(q)}&limit=10`);
      if (res.ok) {
        const data = await res.json();
        setSearchResults(data.identities || []);
        setSearchOpen(true);
      }
    } catch { /* ignore */ }
    setSearchLoading(false);
  }, []);

  const handleSearchInput = useCallback((value: string) => {
    setSearchQuery(value);
    setSelectedName('');
    setIdentityId('');
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => searchIdentities(value), 300);
  }, [searchIdentities]);

  const handleSelectIdentity = useCallback((ident: IdentityResult) => {
    setIdentityId(ident.identity_id);
    setSelectedName(ident.display_name);
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
      const res = await fetch('/api/attack/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identity_id: identityId, max_depth: depthLimit }),
      });
      const data = await res.json();
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

  // Build ReactFlow nodes/edges from simulation result
  const { flowNodes, flowEdges } = useMemo(() => {
    if (!result || !result.nodes || result.nodes.length === 0) {
      return { flowNodes: [] as Node[], flowEdges: [] as Edge[] };
    }

    // Layout: concentric by depth
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
        const colors = NODE_COLORS[n.type] || NODE_COLORS.unknown;
        nodes.push({
          id: n.id,
          position: { x: centerX + offsetX + i * spacing, y: startY },
          data: { label: n.label },
          style: {
            background: colors.bg,
            border: `2px solid ${colors.border}`,
            color: '#fff',
            borderRadius: 8,
            padding: '8px 14px',
            fontSize: 11,
            fontWeight: n.is_start ? 700 : 500,
            boxShadow: n.is_start ? `0 0 12px ${colors.border}` : 'none',
            maxWidth: 180,
          },
        });
      });
    }

    const edges: Edge[] = result.edges.map((e, i) => ({
      id: `e-${i}`,
      source: e.source,
      target: e.target,
      label: e.label,
      animated: true,
      style: { stroke: '#64748b', strokeWidth: 1.5 },
      labelStyle: { fill: '#94a3b8', fontSize: 9 },
    }));

    return { flowNodes: nodes, flowEdges: edges };
  }, [result]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Attack Path Simulator</h1>
        <p className="text-sm text-slate-400 mt-1">
          Simulate lateral movement and privilege escalation from a compromised identity to assess blast radius.
        </p>
      </div>

      {/* Input Controls */}
      <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-5 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Identity search */}
          <div className="md:col-span-2 relative" ref={dropdownRef}>
            <label className="block text-xs font-medium text-slate-400 mb-1">Target Identity</label>
            <input
              type="text"
              value={selectedName || searchQuery}
              onChange={(e) => handleSearchInput(e.target.value)}
              onFocus={() => searchResults.length > 0 && setSearchOpen(true)}
              placeholder="Search by identity name..."
              className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 outline-none"
            />
            {searchLoading && (
              <div className="absolute right-3 top-8 text-xs text-slate-500">Searching...</div>
            )}
            {/* Hidden field indicator */}
            {identityId && (
              <div className="mt-1 text-[10px] text-slate-500 font-mono truncate">
                ID: {identityId}
              </div>
            )}
            {searchOpen && searchResults.length > 0 && (
              <div className="absolute z-20 w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg shadow-xl max-h-72 overflow-y-auto">
                {searchResults.map((ident) => (
                  <button
                    key={ident.identity_id}
                    onClick={() => handleSelectIdentity(ident)}
                    className="w-full text-left px-3 py-2.5 hover:bg-slate-700/50 text-sm flex items-center justify-between gap-2 border-b border-slate-700/50 last:border-0"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="font-medium text-white truncate">{ident.display_name}</div>
                      <div className="text-[10px] text-slate-500 mt-0.5">
                        {ident.identity_category} · {ident.cloud}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {ident.risk_score > 0 && (
                        <span className="text-[10px] font-mono text-slate-400">{ident.risk_score}</span>
                      )}
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

          {/* Depth */}
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Max Depth: {depthLimit}
            </label>
            <input
              type="range"
              min={1}
              max={10}
              value={depthLimit}
              onChange={(e) => setDepthLimit(Number(e.target.value))}
              className="w-full mt-2 accent-red-500"
            />
            <div className="flex justify-between text-[10px] text-slate-500">
              <span>1</span><span>10</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={simulate}
            disabled={loading || !identityId}
            className="px-5 py-2 rounded-lg text-sm font-semibold text-white bg-red-600 hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition"
          >
            {loading ? 'Simulating...' : 'Simulate Attack'}
          </button>
          {identityId && (
            <button
              onClick={() => {
                setIdentityId('');
                setSelectedName('');
                setSearchQuery('');
                setResult(null);
                setError('');
              }}
              className="px-3 py-2 rounded-lg text-sm text-slate-400 hover:text-white hover:bg-slate-700 transition"
            >
              Clear
            </button>
          )}
          {error && <span className="text-sm text-red-400">{error}</span>}
        </div>
      </div>

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* Blast Radius Summary */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
              <div className="text-2xl font-bold text-red-400">{result.risk_score}</div>
              <div className="text-xs text-slate-400">Blast Radius Score</div>
            </div>
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
              <div className="text-2xl font-bold text-white">{result.reachable_resources}</div>
              <div className="text-xs text-slate-400">Reachable Resources</div>
            </div>
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
              <div className="text-2xl font-bold text-white">{result.reachable_identities}</div>
              <div className="text-xs text-slate-400">Reachable Identities</div>
            </div>
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
              <div className="text-2xl font-bold text-white">{result.reachable_subscriptions}</div>
              <div className="text-xs text-slate-400">Reachable Subscriptions</div>
            </div>
          </div>

          {/* Attack Path Graph */}
          {flowNodes.length > 0 && (
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-700/50 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-white">Attack Path Graph</h3>
                <div className="flex items-center gap-3 text-[10px] text-slate-500">
                  {Object.entries(NODE_COLORS).filter(([k]) => k !== 'unknown').map(([type, colors]) => (
                    <span key={type} className="flex items-center gap-1">
                      <span className="w-2.5 h-2.5 rounded-sm" style={{ background: colors.bg, border: `1px solid ${colors.border}` }} />
                      {type}
                    </span>
                  ))}
                </div>
              </div>
              <div style={{ height: 500 }}>
                <ReactFlow
                  nodes={flowNodes}
                  edges={flowEdges}
                  fitView
                  proOptions={{ hideAttribution: true }}
                  style={{ background: '#0f172a' }}
                >
                  <Background color="#1e293b" gap={20} />
                  <Controls
                    showInteractive={false}
                    style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }}
                  />
                  <MiniMap
                    nodeColor={(node) => {
                      const bg = (node.style as Record<string, string>)?.background;
                      return typeof bg === 'string' ? bg : '#475569';
                    }}
                    style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }}
                  />
                </ReactFlow>
              </div>
            </div>
          )}

          {/* Analyze with Copilot */}
          <button
            onClick={() => openCopilot({
              contextType: 'attack_path',
              contextId: String(result.identity_id),
              contextLabel: `Attack Simulation (score: ${result.risk_score})`,
              initialQuestion: 'Analyze this attack simulation and recommend mitigations',
            })}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-indigo-400 bg-indigo-500/10 hover:bg-indigo-500/20 rounded-lg border border-indigo-500/30 transition"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
            Analyze with Copilot
          </button>

          {/* Escalation Paths */}
          {result.privilege_escalations.length > 0 && (
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-700/50">
                <h3 className="text-sm font-bold text-red-400">
                  Privilege Escalation Paths ({result.privilege_escalations.length})
                </h3>
              </div>
              <table className="w-full text-sm">
                <thead className="bg-slate-900/50 text-slate-400 uppercase text-xs tracking-wider">
                  <tr>
                    <th className="px-4 py-2">Type</th>
                    <th className="px-4 py-2">Source</th>
                    <th className="px-4 py-2">Target</th>
                    <th className="px-4 py-2">Risk</th>
                    <th className="px-4 py-2">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/50">
                  {result.privilege_escalations.map((path, i) => (
                    <tr key={i} className="hover:bg-slate-700/20">
                      <td className="px-4 py-2 text-xs font-medium text-slate-300">{path.type}</td>
                      <td className="px-4 py-2 text-xs text-slate-400 max-w-[150px] truncate">{path.source}</td>
                      <td className="px-4 py-2 text-xs text-slate-400 max-w-[150px] truncate">{path.target}</td>
                      <td className="px-4 py-2">
                        <span className={`text-xs font-bold uppercase ${RISK_COLOR[path.risk_level] || 'text-slate-500'}`}>
                          {path.risk_level}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-xs text-slate-400 max-w-[250px] truncate" title={path.description}>
                        {path.description}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Graph Summary Stats */}
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
            <h3 className="text-sm font-semibold text-white mb-3">Attack Graph Summary</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
              <div>
                <div className="text-xl font-bold text-white">{result.nodes.length}</div>
                <div className="text-xs text-slate-400">Nodes</div>
              </div>
              <div>
                <div className="text-xl font-bold text-white">{result.edges.length}</div>
                <div className="text-xs text-slate-400">Edges</div>
              </div>
              <div>
                <div className="text-xl font-bold text-white">{(result.paths || []).length}</div>
                <div className="text-xs text-slate-400">Paths</div>
              </div>
              <div>
                <div className="text-xl font-bold text-white">{result.privilege_escalations.length}</div>
                <div className="text-xs text-slate-400">Escalations</div>
              </div>
            </div>
          </div>
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
