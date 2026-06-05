/**
 * AI Runtime — fleet view of where AI executes and whether it's observable.
 *
 * Aggregates the architecture-derived runtime signals (platforms, model
 * deployments reachable org-wide, network exposure, telemetry coverage) that
 * also appear per-agent in the investigate drawer. No telemetry required to
 * derive — telemetry coverage is itself reported as an observability metric.
 *
 * Falls back to a capability preview when no AI agents are discovered.
 */
import React, { useState, useEffect } from 'react';
import { useConnection } from '../contexts/ConnectionContext';
import { formatPlatform } from '../constants/aiRisk';
import ComingSoonPage from '../components/ComingSoonPage';

interface RuntimeData {
  summary: {
    total_agents: number;
    platform_count: number;
    distinct_models: number;
    total_deployments: number;
    cognitive_accounts: number;
    public_egress_resources: number;
    telemetry_coverage_pct: number;
  };
  platforms: Array<{ platform: string; agent_count: number }>;
  models: Array<{ model_name: string; account_count: number; deployment_count: number; max_capacity: number | null }>;
  network_exposure: { public: number; restricted: number; private: number; unknown: number };
}

export default function AIRuntime() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [data, setData] = useState<RuntimeData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true); setError(null);
    fetch(withConnection('/api/ai-security/runtime'))
      .then(r => {
        if (r.status === 404) { setError('not_found'); return null; }
        if (!r.ok) { setError('fetch_error'); return null; }
        return r.json();
      })
      .then(d => { if (d) setData(d as RuntimeData); })
      .catch(() => setError('fetch_error'))
      .finally(() => setLoading(false));
  }, [withConnection, selectedConnectionId]);

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center py-20">
        <div className="animate-spin h-8 w-8 border-2 border-violet-500 border-t-transparent rounded-full" />
      </div>
    );
  }

  if (error || !data || data.summary.total_agents === 0) {
    return (
      <ComingSoonPage
        pillar="AI Runtime"
        tagline="Where AI workloads execute and whether they are observable."
        overview="AI Runtime aggregates the runtime layer of your AI footprint — platforms in use, model deployments reachable across the org, resource network exposure, and telemetry coverage — all derived from the cloud control plane. Run a discovery scan with AI agents to populate the fleet view."
        capabilities={[
          { title: 'Platform distribution', description: 'Azure OpenAI / ML / Cognitive / Copilot Studio / Anthropic agent counts.' },
          { title: 'Models in use', description: 'Every model deployment reachable org-wide (gpt-4o, gpt-5.x, embeddings) with capacity.' },
          { title: 'Network exposure rollup', description: 'How many AI resources are public vs Private-Endpoint-only.' },
          { title: 'Telemetry coverage', description: 'Observability metric — % of AI agents with usage telemetry.' },
          { title: 'AKS workload-identity mapping', description: 'Pod → managed identity → cloud RBAC (coming next).' },
        ]}
        targetWindow="Live once AI agents are discovered"
        roadmapRef="AI Runtime pillar"
      />
    );
  }

  const s = data.summary;
  const ne = data.network_exposure;
  const telColor = s.telemetry_coverage_pct >= 80 ? '#4ade80' : s.telemetry_coverage_pct >= 50 ? '#facc15' : '#fb923c';

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">AI Runtime</h1>
        <p className="text-sm text-slate-400 mt-1">
          Where your {s.total_agents} AI agent{s.total_agents === 1 ? '' : 's'} execute — platforms,
          models, network exposure, observability. Derived from architecture.
        </p>
      </div>

      {/* Summary strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="rounded-xl border p-4" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Distinct Models</p>
          <p className="text-3xl font-bold font-mono mt-1 text-violet-400">{s.distinct_models}</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>{s.total_deployments} deployments · {s.cognitive_accounts} accounts</p>
        </div>
        <div className="rounded-xl border p-4" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Platforms</p>
          <p className="text-3xl font-bold font-mono mt-1 text-teal-400">{s.platform_count}</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>AI execution platforms</p>
        </div>
        <div className="rounded-xl border p-4" style={{ borderColor: s.public_egress_resources > 0 ? 'rgba(239,68,68,0.35)' : 'var(--border-default)', backgroundColor: s.public_egress_resources > 0 ? 'rgba(239,68,68,0.10)' : 'var(--bg-raised)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Public AI Resources</p>
          <p className="text-3xl font-bold font-mono mt-1" style={{ color: s.public_egress_resources > 0 ? '#f87171' : '#4ade80' }}>{s.public_egress_resources}</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>internet-reachable endpoints</p>
        </div>
        <div className="rounded-xl border p-4" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Telemetry Coverage</p>
          <p className="text-3xl font-bold font-mono mt-1" style={{ color: telColor }}>{s.telemetry_coverage_pct}%</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>observability metric</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Platform distribution */}
        <div className="rounded-xl border" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
          <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
            <h3 className="text-sm font-semibold text-white">Where AI Runs</h3>
            <p className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>Agents by execution platform</p>
          </div>
          <div className="p-4 space-y-1.5">
            {data.platforms.map(p => {
              const maxN = data.platforms[0]?.agent_count || 1;
              return (
                <div key={p.platform} className="flex items-center justify-between text-xs">
                  <span className="text-slate-300">{formatPlatform(p.platform)}</span>
                  <div className="flex items-center gap-2">
                    <div className="w-24 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                      <div className="h-full rounded-full bg-teal-500/60" style={{ width: `${(p.agent_count / maxN) * 100}%` }} />
                    </div>
                    <span className="text-slate-500 font-mono w-8 text-right">{p.agent_count}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Network exposure rollup */}
        <div className="rounded-xl border" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
          <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
            <h3 className="text-sm font-semibold text-white">AI Resource Network Exposure</h3>
            <p className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>Derived from resource network config — no logs</p>
          </div>
          <div className="p-4 grid grid-cols-2 gap-3">
            {([
              ['Public (internet-reachable)', ne.public, '#f87171'],
              ['Restricted (firewall)', ne.restricted, '#facc15'],
              ['Private Endpoint only', ne.private, '#4ade80'],
              ['Unknown', ne.unknown, '#9ca3af'],
            ] as Array<[string, number, string]>).map(([label, count, color]) => (
              <div key={label} className="rounded-lg border p-3" style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
                <p className="text-2xl font-bold font-mono" style={{ color }}>{count}</p>
                <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-tertiary)' }}>{label}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Models in use */}
      <div className="rounded-xl border" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
        <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
          <h3 className="text-sm font-semibold text-white">Models in Use</h3>
          <p className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>Every model deployment reachable across your tenant</p>
        </div>
        <div className="p-4">
          {data.models.length === 0 ? (
            <p className="text-xs text-slate-500 py-2">No model deployments discovered. Run AI model discovery to populate.</p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5">
              {data.models.map(m => (
                <div key={m.model_name} className="flex items-center justify-between text-xs rounded px-2.5 py-1.5"
                  style={{ backgroundColor: 'var(--bg-surface)' }}>
                  <span className="font-mono font-semibold" style={{ color: 'var(--text-primary)' }}>{m.model_name}</span>
                  <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
                    {m.deployment_count} deploy · {m.account_count} acct{m.account_count === 1 ? '' : 's'}
                    {m.max_capacity != null ? ` · cap ${m.max_capacity}` : ''}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
