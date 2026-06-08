/**
 * MultiHopXGraph — Tier 3.1 page
 *
 * Multi-hop agent-to-agent reachability surface. Reviewer #1 called this
 * the patent-worthy differentiator: traces transitive reach where a
 * low-priv agent reaches high-value data via N hops through higher-priv
 * agents.
 *
 * Sources:
 *   GET /api/argus/multi-hop-reachability?source=<id>&classification=<X>&max_depth=N
 *   GET /api/ai-security/invocation-graph
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { BreachCostMethodologyButton } from '../components/ciso/BreachCostMethodology';

type Severity = 'critical' | 'high' | 'medium' | 'low';

interface Hop {
  identity_db_id: number;
  identity_id: string;
  display_name: string;
}

interface Edge {
  source_identity_id: string;
  target_identity_id: string;
  via_mechanism: string;
  invocation_name: string | null;
  confidence: string | null;
  observed_count: number | null;
}

interface DollarBand {
  low: number; mid: number; high: number;
  low_display: string; mid_display: string; high_display: string;
  source: string | null;
}

interface WeakestLink {
  hop_index: number;
  mechanism: string;
  confidence: string;
  reason: string;
}

interface Chain {
  hops: Hop[];
  edges: Edge[];
  depth: number;
  terminal_classification: string;
  terminal_records: number;
  is_write: boolean;
  severity: Severity;
  base_severity: Severity;
  weakest_link: WeakestLink | null;
  mitre_techniques: string[];
  dollar_band: DollarBand | null;
  source_identity_id: string;
  source_display_name: string;
  headline: string;
}

interface MultiHopResponse {
  chains: Chain[];
  chain_count: number;
  by_severity: Record<Severity, number>;
  max_depth_searched: number;
  classification_filter: string | null;
}

interface InvocationGraphNode {
  identity_db_id: number;
  identity_id: string;
  display_name: string;
  worst_data_class: string | null;
  worst_records: number;
  reaches_count: number;
}

interface InvocationGraph {
  nodes: InvocationGraphNode[];
  edges: Edge[];
  node_count: number;
  edge_count: number;
}

const SEV_STYLE: Record<Severity, { text: string; bg: string; border: string; dot: string }> = {
  critical: { text: 'text-red-300',     bg: 'bg-red-900/30',     border: 'border-red-800/50',     dot: 'bg-red-400'     },
  high:     { text: 'text-orange-300',  bg: 'bg-orange-900/30',  border: 'border-orange-800/50',  dot: 'bg-orange-400'  },
  medium:   { text: 'text-amber-300',   bg: 'bg-amber-900/30',   border: 'border-amber-800/50',   dot: 'bg-amber-400'   },
  low:      { text: 'text-emerald-300', bg: 'bg-emerald-900/30', border: 'border-emerald-800/50', dot: 'bg-emerald-400' },
};

const MECHANISM_ICON: Record<string, string> = {
  mcp:            'M',
  http:           'H',
  webhook:        'W',
  azure_function: 'F',
  event_grid:     'E',
  shared_secret:  '⚠',
  service_bus:    'B',
};

export default function MultiHopXGraph() {
  const [data, setData] = useState<MultiHopResponse | null>(null);
  const [graph, setGraph] = useState<InvocationGraph | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterClass, setFilterClass] = useState<string>('');
  const [maxDepth, setMaxDepth] = useState<number>(4);
  const [activeChain, setActiveChain] = useState<Chain | null>(null);
  const [view, setView] = useState<'chains' | 'graph'>('chains');

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams();
    if (filterClass) params.set('classification', filterClass);
    params.set('max_depth', String(maxDepth));
    Promise.all([
      fetch(`/api/argus/multi-hop-reachability?${params.toString()}`).then(r => r.json()),
      fetch('/api/ai-security/invocation-graph').then(r => r.json()),
    ])
      .then(([d, g]) => {
        setData(d as MultiHopResponse);
        setGraph(g as InvocationGraph);
        setLoading(false);
      })
      .catch((e: Error) => { setError(e.message); setLoading(false); });
  }, [filterClass, maxDepth]);

  useEffect(() => { load(); }, [load]);

  const summary = useMemo(() => {
    if (!data) return { total: 0, critical: 0, high: 0, deepest: 0 };
    const deepest = Math.max(0, ...data.chains.map(c => c.depth));
    return {
      total: data.chain_count,
      critical: data.by_severity.critical || 0,
      high: data.by_severity.high || 0,
      deepest,
    };
  }, [data]);

  if (loading && !data) {
    return <div className="p-6 text-sm text-slate-400">Tracing invocation graph…</div>;
  }
  if (error) return <div className="p-6 text-sm text-rose-400">{error}</div>;
  if (!data) return null;

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-5">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <h1 className="text-2xl font-bold text-slate-100">Multi-Hop XGRAPH</h1>
          <span className="text-[10px] uppercase tracking-wider font-bold px-2 py-0.5 rounded
                           bg-violet-900/40 text-violet-300 border border-violet-800">
            v2 · agent-to-agent
          </span>
          <BreachCostMethodologyButton compact />
        </div>
        <p className="text-sm text-slate-400 max-w-3xl">
          Transitive reachability: when a low-privilege agent invokes a higher-privilege
          agent, the caller inherits the callee's blast radius under compromise. Chains
          here are derived from the captured agent_invocations graph + per-agent data
          reachability. <span className="text-slate-500">Edges sourced from MCP traces,
          Azure OpenAI logs, or customer-declared service maps.</span>
        </p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <SummaryCard label="Chains discovered"  value={summary.total} />
        <SummaryCard label="Critical chains"    value={summary.critical} valueClass="text-red-300" />
        <SummaryCard label="High chains"        value={summary.high}     valueClass="text-orange-300" />
        <SummaryCard label="Deepest chain"      value={summary.deepest} hint={`${summary.deepest} hop${summary.deepest === 1 ? '' : 's'}`} />
      </div>

      {/* View toggle + filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex border border-slate-800 rounded overflow-hidden text-xs">
          <button onClick={() => setView('chains')}
                  className={`px-3 py-1 ${view === 'chains'
                    ? 'bg-violet-900/30 text-violet-200'
                    : 'text-slate-400 hover:text-slate-200'}`}>
            Chains
          </button>
          <button onClick={() => setView('graph')}
                  className={`px-3 py-1 ${view === 'graph'
                    ? 'bg-violet-900/30 text-violet-200'
                    : 'text-slate-400 hover:text-slate-200'}`}>
            Graph
          </button>
        </div>

        <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold ml-3">Class</span>
        {(['', 'PHI', 'PCI', 'PII', 'FINANCIAL', 'HR'] as const).map(k => (
          <button key={k || 'all'} onClick={() => setFilterClass(k)}
                  className={`text-xs px-2 py-1 rounded border transition ${
                    filterClass === k
                      ? 'border-violet-700 bg-violet-900/30 text-violet-200'
                      : 'border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                  }`}>
            {k || 'all'}
          </button>
        ))}

        <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold ml-3">Depth</span>
        {[2, 3, 4, 5].map(n => (
          <button key={n} onClick={() => setMaxDepth(n)}
                  className={`text-xs px-2 py-1 rounded border transition ${
                    maxDepth === n
                      ? 'border-violet-700 bg-violet-900/30 text-violet-200'
                      : 'border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                  }`}>
            ≤{n}
          </button>
        ))}
      </div>

      {/* Content */}
      {view === 'chains' ? (
        <ChainsList chains={data.chains} onChainClick={setActiveChain} />
      ) : (
        <GraphView graph={graph} />
      )}

      {activeChain && (
        <ChainDetailModal chain={activeChain} onClose={() => setActiveChain(null)} />
      )}
    </div>
  );
}

function SummaryCard({ label, value, valueClass, hint }:
  { label: string; value: number; valueClass?: string; hint?: string }) {
  return (
    <div className="rounded-xl border border-white/5 bg-slate-900/40 p-3">
      <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500">{label}</p>
      <p className={`text-2xl font-bold font-mono mt-1 ${valueClass || 'text-slate-100'}`}>{value}</p>
      {hint && <p className="text-[10px] text-slate-500 mt-0.5">{hint}</p>}
    </div>
  );
}

function ChainsList({ chains, onChainClick }: { chains: Chain[]; onChainClick: (c: Chain) => void }) {
  if (chains.length === 0) {
    return (
      <div className="rounded-xl border border-white/5 bg-slate-900/40 p-8 text-center text-slate-500 text-sm">
        No multi-hop chains match these filters.
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {chains.map((c, i) => {
        const st = SEV_STYLE[c.severity];
        return (
          <button key={i}
                  onClick={() => onChainClick(c)}
                  className={`w-full text-left rounded-lg border ${st.border} ${st.bg}
                              p-3 hover:brightness-110 transition`}>
            <div className="flex items-start gap-3">
              <span className={`mt-1 w-2 h-2 rounded-full flex-shrink-0 ${st.dot}`} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-[10px] font-bold uppercase ${st.text}`}>{c.severity}</span>
                  <span className="text-[10px] font-mono text-slate-500">depth {c.depth}</span>
                  <span className="text-[10px] font-mono text-slate-500">{c.terminal_classification}</span>
                  {c.is_write && <span className="text-[10px] font-mono text-rose-400">WRITE</span>}
                  {c.weakest_link && (
                    <span className="text-[10px] font-mono text-amber-400" title={c.weakest_link.reason}>
                      ⚠ weak link
                    </span>
                  )}
                </div>
                <div className="text-xs text-slate-200 leading-relaxed">
                  {renderChainInline(c)}
                </div>
                {c.dollar_band && (
                  <div className="mt-1 flex items-center gap-2 text-[10px] font-mono">
                    <span className="text-rose-400 font-bold">{c.dollar_band.mid_display}</span>
                    <span className="text-slate-500">{c.dollar_band.low_display} – {c.dollar_band.high_display}</span>
                    <span className="text-slate-600">·</span>
                    <span className="text-slate-500">{c.terminal_records.toLocaleString()} records</span>
                  </div>
                )}
              </div>
              <span className="text-violet-300 text-xs flex-shrink-0 mt-0.5">Inspect →</span>
            </div>
          </button>
        );
      })}
    </div>
  );
}

function renderChainInline(c: Chain) {
  const parts: React.ReactNode[] = [];
  c.hops.forEach((h, i) => {
    parts.push(
      <span key={`h${i}`} className="font-mono text-slate-200">{h.display_name || h.identity_id}</span>
    );
    if (i < c.edges.length) {
      const e = c.edges[i];
      parts.push(
        <span key={`e${i}`} className="mx-1.5 text-violet-300 font-mono">
          ─{MECHANISM_ICON[e.via_mechanism] || '•'}→
        </span>
      );
    }
  });
  parts.push(<span key="reach" className="ml-1.5 text-rose-400">⇒ {c.terminal_classification}</span>);
  return parts;
}

function ChainDetailModal({ chain, onClose }: { chain: Chain; onClose: () => void }) {
  const st = SEV_STYLE[chain.severity];

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0f172a] rounded-xl border border-white/10 max-w-3xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-5 border-b border-white/5">
          <div className="flex items-center gap-2 mb-2">
            <span className={`text-xs font-bold px-2 py-0.5 rounded uppercase ${st.bg} ${st.text} ${st.border} border`}>
              {chain.severity}
            </span>
            <span className="text-xs text-slate-500 font-mono">depth {chain.depth}</span>
            <span className="text-xs text-slate-500 font-mono">
              terminal: {chain.terminal_classification} · {chain.terminal_records.toLocaleString()} records
            </span>
          </div>
          <h2 className="text-base font-bold text-slate-100 font-mono">{chain.headline}</h2>
        </div>

        <div className="p-5 space-y-4 text-sm">
          {/* Hop diagram */}
          <div>
            <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-2">Invocation path</p>
            <div className="space-y-2">
              {chain.hops.map((h, i) => (
                <React.Fragment key={i}>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-slate-500 w-12">hop {i}</span>
                    <span className="font-mono text-xs text-slate-200 bg-slate-900/60 border border-slate-700 rounded px-2 py-1">
                      {h.display_name || h.identity_id}
                    </span>
                    {i === 0 && <span className="text-[10px] text-violet-300 uppercase">source</span>}
                    {i === chain.hops.length - 1 && i > 0 && (
                      <span className="text-[10px] text-rose-400 uppercase">terminal reach: {chain.terminal_classification}</span>
                    )}
                  </div>
                  {i < chain.edges.length && (
                    <div className="ml-12 flex items-center gap-2 text-[10px]">
                      <span className="font-mono text-violet-300">└─ {chain.edges[i].via_mechanism}</span>
                      {chain.edges[i].invocation_name && (
                        <span className="text-slate-400">·</span>
                      )}
                      {chain.edges[i].invocation_name && (
                        <span className="font-mono text-slate-300">{chain.edges[i].invocation_name}</span>
                      )}
                      {chain.edges[i].confidence && (
                        <span className={`font-mono ${
                          chain.edges[i].confidence === 'inferred' ? 'text-amber-400'
                          : chain.edges[i].confidence === 'declared' ? 'text-blue-400'
                          : 'text-emerald-400'
                        }`}>
                          [{chain.edges[i].confidence}]
                        </span>
                      )}
                      {chain.edges[i].observed_count != null && (chain.edges[i].observed_count ?? 0) > 0 && (
                        <span className="text-slate-500 font-mono">×{chain.edges[i].observed_count}</span>
                      )}
                    </div>
                  )}
                </React.Fragment>
              ))}
            </div>
          </div>

          {/* Weak link */}
          {chain.weakest_link && (
            <div className="rounded bg-amber-900/20 border border-amber-800/40 p-3">
              <p className="text-[10px] uppercase tracking-wider text-amber-400 font-semibold mb-1">Weakest link</p>
              <p className="text-amber-200 text-xs leading-relaxed">
                Hop {chain.weakest_link.hop_index} uses <span className="font-mono">{chain.weakest_link.mechanism}</span>{' '}
                ({chain.weakest_link.confidence}). {chain.weakest_link.reason}.
              </p>
              <p className="text-[10px] text-amber-400/70 mt-1">
                Severity bumped from {chain.base_severity} → {chain.severity}.
              </p>
            </div>
          )}

          {/* Dollar */}
          {chain.dollar_band && (
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1">Estimated exposure</p>
              <div className="text-sm">
                <span className="text-rose-300 font-mono font-bold">{chain.dollar_band.mid_display}</span>
                <span className="text-slate-500 font-mono ml-2">
                  {chain.dollar_band.low_display} – {chain.dollar_band.high_display}
                </span>
              </div>
              {chain.dollar_band.source && (
                <p className="text-[10px] text-slate-500 mt-1">Source: {chain.dollar_band.source}</p>
              )}
            </div>
          )}

          {/* MITRE */}
          {chain.mitre_techniques.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1">MITRE ATT&amp;CK</p>
              <div className="flex flex-wrap gap-1">
                {chain.mitre_techniques.map(t => (
                  <span key={t}
                        className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-violet-900/30 text-violet-300 border border-violet-800/40">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="p-3 border-t border-white/5 flex justify-end">
          <button onClick={onClose} className="text-xs text-slate-400 hover:text-slate-200 px-3 py-1">Close</button>
        </div>
      </div>
    </div>
  );
}

function GraphView({ graph }: { graph: InvocationGraph | null }) {
  if (!graph || graph.node_count === 0) {
    return (
      <div className="rounded-xl border border-white/5 bg-slate-900/40 p-8 text-center text-slate-500 text-sm">
        No invocation edges captured yet. Connect an MCP trace source or
        declare the service map via /api/agent-invocations.
      </div>
    );
  }
  // Compute out-degree + in-degree
  const outBy: Record<string, number> = {};
  const inBy:  Record<string, number> = {};
  graph.edges.forEach(e => {
    outBy[e.source_identity_id] = (outBy[e.source_identity_id] || 0) + 1;
    inBy[e.target_identity_id]  = (inBy[e.target_identity_id]  || 0) + 1;
  });
  const sortedNodes = [...graph.nodes].sort((a, b) =>
    ((inBy[b.identity_id] || 0) + (outBy[b.identity_id] || 0))
    - ((inBy[a.identity_id] || 0) + (outBy[a.identity_id] || 0))
  );

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-white/5 overflow-hidden">
        <div className="bg-slate-900/60 px-3 py-2 border-b border-white/5 text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
          Nodes — {graph.node_count} agents in the invocation graph
        </div>
        <table className="w-full text-xs">
          <thead className="bg-slate-900/40 text-[10px] uppercase tracking-wider text-slate-500">
            <tr>
              <th className="text-left px-3 py-1.5">Agent</th>
              <th className="text-right px-3 py-1.5">In-degree</th>
              <th className="text-right px-3 py-1.5">Out-degree</th>
              <th className="text-left px-3 py-1.5">Worst data class</th>
              <th className="text-right px-3 py-1.5">Reaches (records)</th>
            </tr>
          </thead>
          <tbody>
            {sortedNodes.map(n => (
              <tr key={n.identity_db_id} className="border-t border-white/5">
                <td className="px-3 py-1.5 font-mono text-slate-200">{n.display_name || n.identity_id}</td>
                <td className="px-3 py-1.5 text-right text-slate-400 font-mono">{inBy[n.identity_id] || 0}</td>
                <td className="px-3 py-1.5 text-right text-slate-400 font-mono">{outBy[n.identity_id] || 0}</td>
                <td className="px-3 py-1.5">
                  {n.worst_data_class ? (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-900/30 text-rose-300 border border-rose-800/40">
                      {n.worst_data_class}
                    </span>
                  ) : (
                    <span className="text-slate-600">—</span>
                  )}
                </td>
                <td className="px-3 py-1.5 text-right text-slate-400 font-mono">
                  {n.worst_records > 0 ? n.worst_records.toLocaleString() : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="rounded-xl border border-white/5 overflow-hidden">
        <div className="bg-slate-900/60 px-3 py-2 border-b border-white/5 text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
          Edges — {graph.edge_count} invocations
        </div>
        <table className="w-full text-xs">
          <thead className="bg-slate-900/40 text-[10px] uppercase tracking-wider text-slate-500">
            <tr>
              <th className="text-left px-3 py-1.5">From</th>
              <th className="text-left px-3 py-1.5">Mechanism</th>
              <th className="text-left px-3 py-1.5">To</th>
              <th className="text-left px-3 py-1.5">Invocation</th>
              <th className="text-left px-3 py-1.5">Confidence</th>
              <th className="text-right px-3 py-1.5">Observed</th>
            </tr>
          </thead>
          <tbody>
            {graph.edges.map((e, i) => (
              <tr key={i} className="border-t border-white/5">
                <td className="px-3 py-1.5 font-mono text-slate-300">{e.source_identity_id}</td>
                <td className="px-3 py-1.5">
                  <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                    e.via_mechanism === 'shared_secret'
                      ? 'bg-amber-900/30 text-amber-300 border border-amber-800/40'
                      : 'bg-violet-900/30 text-violet-300 border border-violet-800/40'
                  }`}>
                    {e.via_mechanism}
                  </span>
                </td>
                <td className="px-3 py-1.5 font-mono text-slate-300">{e.target_identity_id}</td>
                <td className="px-3 py-1.5 text-slate-400">{e.invocation_name || '—'}</td>
                <td className="px-3 py-1.5">
                  <span className={`text-[10px] font-mono ${
                    e.confidence === 'observed' ? 'text-emerald-300'
                    : e.confidence === 'declared' ? 'text-blue-300'
                    : 'text-amber-300'
                  }`}>
                    {e.confidence}
                  </span>
                </td>
                <td className="px-3 py-1.5 text-right text-slate-400 font-mono">
                  {(e.observed_count ?? 0) > 0 ? e.observed_count?.toLocaleString() : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
