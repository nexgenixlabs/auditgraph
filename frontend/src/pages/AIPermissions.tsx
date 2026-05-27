/**
 * AIPermissions — Org-wide AI permission analysis page.
 *
 * Shows which AI agents have which types of access (model, key vault, data, etc.)
 * with aggregated counts and overprivileged agent identification.
 */
import React, { useState, useEffect } from 'react';
import { useConnection } from '../contexts/ConnectionContext';
import { ACCESS_CATEGORIES, formatAccessLevel } from '../constants/aiRisk';
import AIInvestigateDrawer from '../components/AIInvestigateDrawer';

interface PermissionsData {
  agents_with_model_access: number;
  agents_with_key_vault_access: number;
  agents_with_data_access: number;
  agents_with_telemetry: number;
  agents_with_internet_egress: number;
  agents_with_broad_privilege: number;
  total_agents: number;
  role_frequency: Array<{ role_name: string; count: number }>;
  overprivileged_agents: Array<{
    identity_id: string;
    display_name: string;
    risk_score: number;
  }>;
}

function riskColor(score: number): string {
  if (score >= 75) return 'text-red-400';
  if (score >= 50) return 'text-orange-400';
  if (score >= 25) return 'text-yellow-400';
  return 'text-green-400';
}

export default function AIPermissions() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [data, setData] = useState<PermissionsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [investigateId, setInvestigateId] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetch(withConnection('/api/ai-security/permissions'))
      .then(r => {
        if (r.status === 404) { setError('not_found'); return null; }
        if (!r.ok) { setError('fetch_error'); return null; }
        return r.json();
      })
      .then(d => { if (d) setData(d); })
      .catch(() => setError('fetch_error'))
      .finally(() => setLoading(false));
  }, [withConnection, selectedConnectionId]);

  if (loading) {
    return (
      <div className="p-6">
        <div className="flex items-center justify-center py-20">
          <div className="animate-spin h-8 w-8 border-2 border-violet-500 border-t-transparent rounded-full" />
        </div>
      </div>
    );
  }

  if (error === 'not_found') {
    return (
      <div className="p-6 max-w-[1400px] mx-auto">
        <h1 className="text-2xl font-bold text-white mb-2">AI Permissions</h1>
        <div className="rounded-lg border p-10 text-center mt-6" style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}>
          <p className="text-sm text-slate-400">AI agent governance not enabled. Run a discovery scan first.</p>
        </div>
      </div>
    );
  }

  if (!data) return null;

  const accessCards = [
    { key: 'agents_with_model_access', label: 'Model Access', color: '#8b5cf6' },
    { key: 'agents_with_key_vault_access', label: 'Key Vault', color: '#ef4444' },
    { key: 'agents_with_data_access', label: 'Data Access', color: '#f97316' },
    { key: 'agents_with_telemetry', label: 'Telemetry', color: '#22c55e' },
    { key: 'agents_with_internet_egress', label: 'Internet Egress', color: '#06b6d4' },
    { key: 'agents_with_broad_privilege', label: 'Broad Privilege', color: '#ef4444' },
  ];

  return (
    <div className="p-6 max-w-[1400px] mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">AI Permissions</h1>
        <p className="text-sm text-slate-400 mt-1">
          Organization-wide AI agent permission analysis — {data.total_agents} agents analyzed
        </p>
      </div>

      {/* Access category cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-8">
        {accessCards.map(card => {
          const count = (data as any)[card.key] || 0;
          const pct = data.total_agents > 0 ? Math.round((count / data.total_agents) * 100) : 0;
          return (
            <div key={card.key} className="rounded-lg border p-4" style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}>
              <p className="text-[10px] text-slate-500">{card.label}</p>
              <p className="text-2xl font-bold mt-1" style={{ color: card.color }}>{count}</p>
              <p className="text-[10px] text-slate-600 mt-0.5">{pct}% of agents</p>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top roles */}
        <div className="rounded-lg border" style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}>
          <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
            <h3 className="text-sm font-semibold text-white">Most Common Roles</h3>
            <p className="text-[10px] text-slate-500">Across all AI agent identities</p>
          </div>
          <div className="p-4 space-y-1.5">
            {data.role_frequency.slice(0, 15).map((role, i) => (
              <div key={i} className="flex items-center justify-between text-xs">
                <span className="text-slate-300 truncate max-w-[300px]">{role.role_name}</span>
                <div className="flex items-center gap-2">
                  <div className="w-20 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-violet-500/60"
                      style={{ width: `${Math.min(100, (role.count / (data.role_frequency[0]?.count || 1)) * 100)}%` }}
                    />
                  </div>
                  <span className="text-slate-500 font-mono w-6 text-right">{role.count}</span>
                </div>
              </div>
            ))}
            {data.role_frequency.length === 0 && (
              <p className="text-xs text-slate-500 py-4 text-center">No role data available</p>
            )}
          </div>
        </div>

        {/* Overprivileged agents */}
        <div className="rounded-lg border" style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}>
          <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
            <h3 className="text-sm font-semibold text-white">Overprivileged AI Agents</h3>
            <p className="text-[10px] text-slate-500">Agents with broad privilege roles (Owner, Contributor, UAA)</p>
          </div>
          <div className="p-4 space-y-1.5">
            {data.overprivileged_agents.map((agent, i) => (
              <button
                key={i}
                onClick={() => setInvestigateId(agent.identity_id)}
                className="w-full flex items-center justify-between text-xs rounded-lg px-3 py-2 hover:bg-slate-800/50 transition-colors text-left"
              >
                <span className="text-slate-300 truncate max-w-[250px]">{agent.display_name}</span>
                <span className={`font-mono font-bold ${riskColor(agent.risk_score)}`}>{agent.risk_score}</span>
              </button>
            ))}
            {data.overprivileged_agents.length === 0 && (
              <p className="text-xs text-slate-500 py-4 text-center">No overprivileged agents detected</p>
            )}
          </div>
        </div>
      </div>

      {/* Investigate drawer */}
      {investigateId && (
        <AIInvestigateDrawer
          identityId={investigateId}
          onClose={() => setInvestigateId(null)}
        />
      )}
    </div>
  );
}
