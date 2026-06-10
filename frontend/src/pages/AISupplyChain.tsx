/**
 * AISupplyChain — Tier 3.2 page
 *
 * AI Supply Chain dependency graph. For each AI agent, walks the
 * Model → Plugin → Vector DB → External API → Tool tree and surfaces
 * per-component risk + aggregate risk.
 *
 * Sources:
 *   GET /api/ai-security/supply-chain          — org rollup
 *   GET /api/ai-security/supply-chain/<id>     — per-agent tree
 */
import React, { useCallback, useEffect, useState } from 'react';
// AG-POLISH-D (2026-06-10)
import { LoadingState } from '../components/LoadingState';

type Severity = 'critical' | 'high' | 'medium' | 'low';

interface Component {
  id: number;
  kind: 'model' | 'plugin' | 'vector_db' | 'external_api' | 'tool';
  name: string;
  vendor: string | null;
  version: string | null;
  is_managed_by_customer: boolean;
  risk_flags: string[];
  risk_score: number;
  severity: Severity;
  metadata: Record<string, unknown>;
}

interface Edge {
  source_type: 'agent' | 'component';
  source_id: number;
  target_id: number;
  relationship: string;
}

interface AgentSupplyChain {
  identity_db_id: number;
  components: Component[];
  edges: Edge[];
  component_count: number;
  edge_count: number;
  aggregate_risk_score: number;
  aggregate_severity: Severity;
  top_risk_flags: { flag: string; contribution: number }[];
}

interface OrgRollup {
  agents: {
    identity_db_id: number;
    identity_id: string;
    display_name: string;
    component_count: number;
    aggregate_risk_score: number;
    aggregate_severity: Severity;
    top_risk_flags: { flag: string; contribution: number }[];
  }[];
  agent_count: number;
  by_kind: { kind: string; count: number; critical_count: number; high_count: number }[];
}

const SEV_STYLE: Record<Severity, { text: string; bg: string; border: string; dot: string }> = {
  critical: { text: 'text-red-300',     bg: 'bg-red-900/30',     border: 'border-red-800/50',     dot: 'bg-red-400'     },
  high:     { text: 'text-orange-300',  bg: 'bg-orange-900/30',  border: 'border-orange-800/50',  dot: 'bg-orange-400'  },
  medium:   { text: 'text-amber-300',   bg: 'bg-amber-900/30',   border: 'border-amber-800/50',   dot: 'bg-amber-400'   },
  low:      { text: 'text-emerald-300', bg: 'bg-emerald-900/30', border: 'border-emerald-800/50', dot: 'bg-emerald-400' },
};

const KIND_ICON: Record<string, string> = {
  model:        'M',
  plugin:       'P',
  vector_db:    'V',
  external_api: 'A',
  tool:         'T',
};

const KIND_LABEL: Record<string, string> = {
  model:        'Model',
  plugin:       'Plugin',
  vector_db:    'Vector DB',
  external_api: 'External API',
  tool:         'Tool',
};

export default function AISupplyChain() {
  const [rollup, setRollup] = useState<OrgRollup | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [agentChain, setAgentChain] = useState<AgentSupplyChain | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadRollup = useCallback(() => {
    setLoading(true);
    fetch('/api/ai-security/supply-chain')
      .then(r => r.json())
      .then((d: OrgRollup) => {
        setRollup(d);
        if (d.agents.length > 0 && !selectedAgent) {
          setSelectedAgent(d.agents[0].identity_id);
        }
        setLoading(false);
      })
      .catch((e: Error) => { setError(e.message); setLoading(false); });
  }, [selectedAgent]);

  useEffect(() => { loadRollup(); }, [loadRollup]);

  useEffect(() => {
    if (!selectedAgent) return;
    fetch(`/api/ai-security/supply-chain/${encodeURIComponent(selectedAgent)}`)
      .then(r => r.json())
      .then((d: AgentSupplyChain) => setAgentChain(d))
      .catch((e: Error) => setError(e.message));
  }, [selectedAgent]);

  {/* AG-POLISH-D (2026-06-10) */}
  if (loading && !rollup) return <div className="p-6"><LoadingState message="Loading supply chain…" detail="Walking model → plugin → vector store → API dependencies" /></div>;
  if (error) return <div className="p-6 text-sm text-rose-400">{error}</div>;
  if (!rollup) return null;

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">AI Supply Chain</h1>
        <p className="text-sm text-slate-400 max-w-3xl mt-1">
          Model → Plugin → Vector DB → External API. Each layer carries its
          own risk surface. AuditGraph composes the dependency tree per agent
          and quantifies the aggregated supply-chain risk.
        </p>
      </div>

      {/* By-kind strip */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {rollup.by_kind.map(k => (
          <div key={k.kind} className="rounded-xl border border-white/5 bg-slate-900/40 p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="w-5 h-5 rounded bg-violet-900/40 border border-violet-800 text-violet-200 text-[10px] font-bold flex items-center justify-center">
                {KIND_ICON[k.kind] || '?'}
              </span>
              <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500">
                {KIND_LABEL[k.kind] || k.kind}
              </p>
            </div>
            <p className="text-2xl font-bold font-mono text-slate-100">{k.count}</p>
            <div className="text-[10px] mt-0.5 flex gap-2">
              {k.critical_count > 0 && (
                <span className="text-red-300">{k.critical_count} crit</span>
              )}
              {k.high_count > 0 && (
                <span className="text-orange-300">{k.high_count} high</span>
              )}
              {k.critical_count + k.high_count === 0 && <span className="text-slate-500">all clear</span>}
            </div>
          </div>
        ))}
      </div>

      {/* Agent picker + detail */}
      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-12 md:col-span-4 space-y-2">
          <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500">Agents</p>
          {rollup.agents.map(a => {
            const st = SEV_STYLE[a.aggregate_severity];
            const isActive = a.identity_id === selectedAgent;
            return (
              <button key={a.identity_id}
                      onClick={() => setSelectedAgent(a.identity_id)}
                      className={`w-full text-left rounded-lg border ${st.border} p-3 transition ${
                        isActive ? `${st.bg} brightness-110` : 'bg-slate-900/40 hover:bg-slate-900/60'
                      }`}>
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${st.dot}`} />
                  <span className="text-xs font-mono text-slate-200 truncate flex-1">{a.display_name}</span>
                  <span className={`text-[10px] font-bold font-mono ${st.text}`}>{a.aggregate_risk_score}</span>
                </div>
                <p className="text-[10px] text-slate-500 mt-1">
                  {a.component_count} components · {a.aggregate_severity}
                </p>
              </button>
            );
          })}
        </div>

        <div className="col-span-12 md:col-span-8">
          {agentChain ? (
            <ChainTree chain={agentChain} agentName={selectedAgent || ''} />
          ) : (
            <div className="rounded-xl border border-white/5 bg-slate-900/40 p-6 text-sm text-slate-500">
              Select an agent to see its supply chain.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ChainTree({ chain, agentName }: { chain: AgentSupplyChain; agentName: string }) {
  const st = SEV_STYLE[chain.aggregate_severity];
  // Group components by kind for hierarchical render
  const byKind: Record<string, Component[]> = {};
  chain.components.forEach(c => {
    (byKind[c.kind] = byKind[c.kind] || []).push(c);
  });
  const kindOrder = ['model','plugin','vector_db','external_api','tool'];

  return (
    <div className="rounded-xl border border-white/5 bg-slate-900/40 p-4 space-y-4">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500">Supply chain root</p>
          <p className="text-base font-bold text-slate-100 font-mono mt-0.5">{agentName}</p>
        </div>
        <div className={`text-right rounded border ${st.border} ${st.bg} px-3 py-2`}>
          <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Aggregate risk</p>
          <p className={`text-2xl font-bold font-mono ${st.text}`}>{chain.aggregate_risk_score}</p>
          <p className={`text-[10px] uppercase ${st.text}`}>{chain.aggregate_severity}</p>
        </div>
      </div>

      {chain.top_risk_flags.length > 0 && (
        <div>
          <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500 mb-1">Top risk contributors</p>
          <div className="flex flex-wrap gap-2">
            {chain.top_risk_flags.map(f => (
              <span key={f.flag}
                    className="text-[11px] font-mono px-2 py-0.5 rounded bg-rose-900/30 text-rose-300 border border-rose-800/40">
                {f.flag} <span className="text-rose-400/70">+{f.contribution}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="space-y-3 mt-2">
        {kindOrder.map(kind => byKind[kind] && byKind[kind].length > 0 && (
          <div key={kind}>
            <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500 mb-1">
              {KIND_LABEL[kind] || kind} ({byKind[kind].length})
            </p>
            <div className="space-y-1.5">
              {byKind[kind].sort((a, b) => b.risk_score - a.risk_score).map(c => {
                const cst = SEV_STYLE[c.severity];
                return (
                  <div key={c.id}
                       className={`rounded border ${cst.border} ${cst.bg} px-3 py-2 flex items-start gap-2`}>
                    <span className={`mt-1 w-1.5 h-1.5 rounded-full flex-shrink-0 ${cst.dot}`} />
                    <span className="w-5 h-5 mt-0.5 rounded bg-violet-900/40 border border-violet-800 text-violet-200 text-[10px] font-bold flex items-center justify-center flex-shrink-0">
                      {KIND_ICON[kind] || '?'}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-mono text-slate-200 truncate">{c.name}</span>
                        {c.version && (
                          <span className="text-[10px] font-mono text-slate-500">v{c.version}</span>
                        )}
                        {c.is_managed_by_customer && (
                          <span className="text-[9px] uppercase font-bold text-emerald-400 border border-emerald-800/40 px-1 rounded">
                            customer-managed
                          </span>
                        )}
                      </div>
                      {c.vendor && (
                        <p className="text-[10px] text-slate-500 mt-0.5">{c.vendor}</p>
                      )}
                      {c.risk_flags.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-1">
                          {c.risk_flags.map(f => (
                            <span key={f}
                                  className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-amber-900/30 text-amber-300 border border-amber-800/40">
                              {f}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                    <span className={`text-xs font-bold font-mono ${cst.text} flex-shrink-0`}>
                      {c.risk_score}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
