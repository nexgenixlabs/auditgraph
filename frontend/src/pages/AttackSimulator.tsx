import React, { useState, useCallback } from 'react';
import { useCopilot } from '../contexts/CopilotContext';

interface SimulationResult {
  simulation_id: string;
  identity_id: number;
  depth_limit: number;
  reachable_resources: number;
  reachable_identities: number;
  reachable_subscriptions: number;
  privilege_escalations: EscalationPath[];
  risk_score: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
  paths: Array<{ steps: string[]; risk_level: string }>;
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
}

interface GraphEdge {
  source: string;
  target: string;
  label: string;
}

const RISK_COLOR: Record<string, string> = {
  critical: 'text-red-600',
  high: 'text-orange-600',
  medium: 'text-yellow-600',
  low: 'text-green-600',
};

export default function AttackSimulator() {
  const { openCopilot } = useCopilot();
  const [identityId, setIdentityId] = useState('');
  const [depthLimit, setDepthLimit] = useState(6);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<SimulationResult | null>(null);

  // Identity search
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<Array<{ id: number; display_name: string; identity_category: string; cloud: string }>>([]);
  const [searchOpen, setSearchOpen] = useState(false);
  const [selectedName, setSelectedName] = useState('');

  const searchIdentities = useCallback(async (q: string) => {
    if (q.length < 2) { setSearchResults([]); return; }
    try {
      const res = await fetch(`/api/identities?search=${encodeURIComponent(q)}&limit=10`);
      if (res.ok) {
        const data = await res.json();
        setSearchResults(data.identities || []);
      }
    } catch { /* ignore */ }
  }, []);

  const simulate = async () => {
    if (!identityId) { setError('Select an identity first.'); return; }
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const res = await fetch('/api/attack-path/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identity_id: Number(identityId), depth_limit: depthLimit }),
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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Attack Path Simulator</h1>
        <p className="text-sm text-gray-500 mt-1">
          Simulate lateral movement and privilege escalation from a compromised identity to assess blast radius.
        </p>
      </div>

      {/* Input Controls */}
      <div className="bg-white border rounded-xl p-5 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Identity search */}
          <div className="md:col-span-2 relative">
            <label className="block text-xs font-medium text-gray-600 mb-1">Target Identity</label>
            <input
              type="text"
              value={selectedName || searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setSelectedName('');
                setIdentityId('');
                setSearchOpen(true);
                searchIdentities(e.target.value);
              }}
              onFocus={() => searchResults.length > 0 && setSearchOpen(true)}
              placeholder="Search by identity name..."
              className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-indigo-200 focus:border-indigo-400 outline-none"
            />
            {searchOpen && searchResults.length > 0 && (
              <div className="absolute z-20 w-full mt-1 bg-white border rounded-lg shadow-lg max-h-60 overflow-y-auto">
                {searchResults.map((ident) => (
                  <button
                    key={ident.id}
                    onClick={() => {
                      setIdentityId(String(ident.id));
                      setSelectedName(ident.display_name);
                      setSearchQuery('');
                      setSearchOpen(false);
                    }}
                    className="w-full text-left px-3 py-2 hover:bg-gray-50 text-sm flex items-center justify-between"
                  >
                    <span className="font-medium text-gray-800 truncate">{ident.display_name}</span>
                    <span className="text-[10px] text-gray-400 uppercase ml-2 shrink-0">
                      {ident.cloud} / {ident.identity_category}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Depth */}
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Max Depth: {depthLimit}
            </label>
            <input
              type="range"
              min={1}
              max={10}
              value={depthLimit}
              onChange={(e) => setDepthLimit(Number(e.target.value))}
              className="w-full mt-2"
            />
            <div className="flex justify-between text-[10px] text-gray-400">
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
          {error && <span className="text-sm text-red-600">{error}</span>}
        </div>
      </div>

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* Blast Radius Summary */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-white border rounded-xl p-4">
              <div className="text-2xl font-bold text-red-600">{result.risk_score}</div>
              <div className="text-xs text-gray-500">Blast Radius Score</div>
            </div>
            <div className="bg-white border rounded-xl p-4">
              <div className="text-2xl font-bold text-gray-900">{result.reachable_resources}</div>
              <div className="text-xs text-gray-500">Reachable Resources</div>
            </div>
            <div className="bg-white border rounded-xl p-4">
              <div className="text-2xl font-bold text-gray-900">{result.reachable_identities}</div>
              <div className="text-xs text-gray-500">Reachable Identities</div>
            </div>
            <div className="bg-white border rounded-xl p-4">
              <div className="text-2xl font-bold text-gray-900">{result.reachable_subscriptions}</div>
              <div className="text-xs text-gray-500">Reachable Subscriptions</div>
            </div>
          </div>

          {/* Analyze with Copilot */}
          <button
            onClick={() => openCopilot({
              contextType: 'attack_path',
              contextId: String(result.identity_id),
              contextLabel: `Attack Simulation (score: ${result.risk_score})`,
              initialQuestion: 'Analyze this attack simulation and recommend mitigations',
            })}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-indigo-700 bg-indigo-50 hover:bg-indigo-100 rounded-lg border border-indigo-200 transition"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
            Analyze with Copilot
          </button>

          {/* Escalation Paths */}
          {result.privilege_escalations.length > 0 && (
            <div className="bg-white border rounded-xl overflow-hidden">
              <div className="px-4 py-3 border-b bg-red-50">
                <h3 className="text-sm font-bold text-red-800">
                  Privilege Escalation Paths ({result.privilege_escalations.length})
                </h3>
              </div>
              <table className="w-full text-sm">
                <thead className="bg-gray-50 border-b text-left text-xs text-gray-500 uppercase">
                  <tr>
                    <th className="px-4 py-2">Type</th>
                    <th className="px-4 py-2">Source</th>
                    <th className="px-4 py-2">Target</th>
                    <th className="px-4 py-2">Risk</th>
                    <th className="px-4 py-2">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y">
                  {result.privilege_escalations.map((path, i) => (
                    <tr key={i} className="hover:bg-gray-50">
                      <td className="px-4 py-2 text-xs font-medium text-gray-700">{path.type}</td>
                      <td className="px-4 py-2 text-xs text-gray-600 max-w-[150px] truncate">{path.source}</td>
                      <td className="px-4 py-2 text-xs text-gray-600 max-w-[150px] truncate">{path.target}</td>
                      <td className="px-4 py-2">
                        <span className={`text-xs font-bold uppercase ${RISK_COLOR[path.risk_level] || 'text-gray-500'}`}>
                          {path.risk_level}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-xs text-gray-600 max-w-[250px] truncate" title={path.description}>
                        {path.description}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Graph Nodes & Edges Summary */}
          <div className="bg-white border rounded-xl p-4">
            <h3 className="text-sm font-semibold text-gray-800 mb-3">Attack Graph Summary</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
              <div>
                <div className="text-xl font-bold text-gray-900">{result.nodes.length}</div>
                <div className="text-xs text-gray-500">Nodes</div>
              </div>
              <div>
                <div className="text-xl font-bold text-gray-900">{result.edges.length}</div>
                <div className="text-xs text-gray-500">Edges</div>
              </div>
              <div>
                <div className="text-xl font-bold text-gray-900">{(result.paths || []).length}</div>
                <div className="text-xs text-gray-500">Paths</div>
              </div>
              <div>
                <div className="text-xl font-bold text-gray-900">{result.privilege_escalations.length}</div>
                <div className="text-xs text-gray-500">Escalations</div>
              </div>
            </div>

            {/* Node list */}
            {result.nodes.length > 0 && (
              <div className="mt-4">
                <div className="text-xs font-medium text-gray-500 mb-2">Reachable Nodes</div>
                <div className="flex flex-wrap gap-1.5">
                  {result.nodes.slice(0, 30).map((node) => (
                    <span
                      key={node.id}
                      className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-gray-100 text-gray-700"
                      title={`${node.type}: ${node.label}`}
                    >
                      {node.label}
                    </span>
                  ))}
                  {result.nodes.length > 30 && (
                    <span className="px-2 py-0.5 rounded-full text-[10px] text-gray-400">
                      +{result.nodes.length - 30} more
                    </span>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Empty state */}
      {!result && !loading && (
        <div className="bg-gray-50 border border-dashed rounded-xl p-12 text-center">
          <svg className="w-12 h-12 text-gray-300 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <div className="text-sm font-semibold text-gray-500">Select an identity and run a simulation</div>
          <div className="text-xs text-gray-400 mt-1">The simulator will trace lateral movement and privilege escalation paths.</div>
        </div>
      )}
    </div>
  );
}
