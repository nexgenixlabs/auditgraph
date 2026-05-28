/**
 * AIPermissions — Org-wide AI permission analysis page.
 *
 * AG-162: enterprise-grade rewrite.
 *   - Findings narrative panel (3–5 generated sentences from live counts)
 *   - Assessment-tone cards (healthy / borderline / concerning) with action prompts
 *   - Interactive "Most Common Roles" — click a role to drill into AI Inventory filtered
 *   - "Overprivileged AI Agents" with cited industry guidance
 *
 * NO hardcoded thresholds or copy — all assessment text comes from
 * `app/constants/ai_risk.py` via `/api/ai-security/permissions`.
 */
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import AIInvestigateDrawer from '../components/AIInvestigateDrawer';

interface Assessment {
  pct: number;
  tone: 'healthy' | 'borderline' | 'concerning' | 'unknown';
  action_prompt: string;
  benchmark: string;
}

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
  assessments: Record<string, Assessment>;
  findings: string[];
}

const METRIC_CARDS: Array<{ key: string; countKey: keyof PermissionsData; label: string }> = [
  { key: 'model_access',     countKey: 'agents_with_model_access',     label: 'Model Access' },
  { key: 'key_vault_access', countKey: 'agents_with_key_vault_access', label: 'Key Vault' },
  { key: 'data_access',      countKey: 'agents_with_data_access',      label: 'Data Access' },
  { key: 'telemetry',        countKey: 'agents_with_telemetry',        label: 'Telemetry' },
  { key: 'internet_egress',  countKey: 'agents_with_internet_egress',  label: 'Internet Egress' },
  { key: 'broad_privilege',  countKey: 'agents_with_broad_privilege',  label: 'Broad Privilege' },
];

const TONE_STYLE: Record<Assessment['tone'], { bg: string; border: string; text: string; label: string }> = {
  healthy:    { bg: 'rgba(34, 197, 94, 0.10)',  border: 'rgba(34, 197, 94, 0.35)',  text: '#4ade80', label: 'Healthy' },
  borderline: { bg: 'rgba(245, 158, 11, 0.10)', border: 'rgba(245, 158, 11, 0.35)', text: '#fbbf24', label: 'Borderline' },
  concerning: { bg: 'rgba(239, 68, 68, 0.10)',  border: 'rgba(239, 68, 68, 0.35)',  text: '#f87171', label: 'Concerning' },
  unknown:    { bg: 'rgba(107, 114, 128, 0.10)',border: 'rgba(107, 114, 128, 0.30)',text: '#9ca3af', label: 'Unknown' },
};

function riskColor(score: number): string {
  if (score >= 75) return 'text-red-400';
  if (score >= 50) return 'text-orange-400';
  if (score >= 25) return 'text-yellow-400';
  return 'text-green-400';
}

export default function AIPermissions() {
  const { withConnection, selectedConnectionId } = useConnection();
  const navigate = useNavigate();
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
        <div className="rounded-lg border p-10 text-center mt-6"
          style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}>
          <p className="text-sm text-slate-400">AI agent governance not enabled. Run a discovery scan first.</p>
        </div>
      </div>
    );
  }

  if (!data) return null;

  // Navigate to AI Inventory agents tab filtered by role (AG-162 interactive roles)
  const drillToRole = (roleName: string) => {
    navigate(`/ai-inventory/agents?role=${encodeURIComponent(roleName)}`);
  };
  // Tone-card click → filter AI Inventory by that access metric
  // (`metric` must match the frontend AgentRow column name).
  const drillToMetric = (metric: string) => {
    // broad_privilege has no per-agent access-level column; route by role instead
    if (metric === 'broad_privilege') {
      navigate(`/ai-inventory/agents?role=Owner`);
      return;
    }
    navigate(`/ai-inventory/agents?filter=${encodeURIComponent(metric)}`);
  };

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">AI Permissions</h1>
        <p className="text-sm text-slate-400 mt-1">
          Organization-wide AI agent permission analysis — {data.total_agents} agent{data.total_agents === 1 ? '' : 's'} analyzed
        </p>
      </div>

      {/* AG-162: Findings narrative panel — plain-English summary from live counts */}
      {data.findings && data.findings.length > 0 && (
        <div className="rounded-xl border p-5"
          style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
          <h2 className="text-xs font-semibold uppercase tracking-wider mb-3"
            style={{ color: 'var(--text-tertiary)' }}>
            Findings
          </h2>
          <ul className="space-y-2">
            {data.findings.map((f, i) => (
              <li key={i} className="flex gap-2.5 text-sm leading-relaxed"
                style={{ color: 'var(--text-primary)' }}>
                <span className="flex-shrink-0 w-1 h-1 rounded-full mt-2"
                  style={{ backgroundColor: '#24A2A1' }} />
                <span>{f}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* AG-162: Assessment-tone cards — color + action per metric. Click → drill into AI Inventory filtered. */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {METRIC_CARDS.map(card => {
          const count = (data[card.countKey] as number) || 0;
          const assessment = data.assessments?.[card.key];
          const tone = assessment?.tone || 'unknown';
          const style = TONE_STYLE[tone];
          const pct = assessment?.pct ?? 0;
          const clickable = count > 0;
          return (
            <button
              key={card.key}
              onClick={() => clickable && drillToMetric(card.key)}
              disabled={!clickable}
              className={`rounded-xl border p-4 flex flex-col justify-between min-h-[148px] text-left transition ${clickable ? 'hover:scale-[1.02] cursor-pointer' : 'cursor-default opacity-80'}`}
              style={{ backgroundColor: style.bg, borderColor: style.border }}
              title={assessment?.benchmark || ''}
            >
              <div>
                <div className="flex items-start justify-between gap-1.5">
                  <p className="text-[10px] uppercase tracking-wider font-semibold"
                    style={{ color: 'var(--text-tertiary)' }}>{card.label}</p>
                  <span
                    className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded"
                    style={{ backgroundColor: style.bg, color: style.text, border: `1px solid ${style.border}` }}
                  >
                    {style.label}
                  </span>
                </div>
                <p className="text-3xl font-bold font-mono mt-2" style={{ color: style.text }}>{count}</p>
                <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                  {pct}% of agents{clickable ? ' · click to view' : ''}
                </p>
              </div>
              {assessment?.action_prompt && (
                <p className="text-[10px] mt-3 leading-snug" style={{ color: 'var(--text-secondary)' }}>
                  {assessment.action_prompt}
                </p>
              )}
            </button>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Most Common Roles — AG-162: clickable rows */}
        <div className="rounded-xl border"
          style={{ backgroundColor: 'var(--bg-raised)', borderColor: 'var(--border-default)' }}>
          <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
            <h3 className="text-sm font-semibold text-white">Most Common Roles</h3>
            <p className="text-[10px] text-slate-500">
              Across all AI agent identities · click a role to filter the inventory
            </p>
          </div>
          <div className="p-4 space-y-1">
            {data.role_frequency.slice(0, 15).map((role, i) => {
              const maxCount = data.role_frequency[0]?.count || 1;
              return (
                <button
                  key={i}
                  onClick={() => drillToRole(role.role_name)}
                  className="w-full flex items-center justify-between text-xs rounded px-2 py-1.5 hover:bg-slate-800/40 transition-colors text-left group"
                  title={`Show all agents holding ${role.role_name}`}
                >
                  <span className="text-slate-300 truncate max-w-[300px] group-hover:text-white transition-colors">
                    {role.role_name}
                  </span>
                  <div className="flex items-center gap-2">
                    <div className="w-20 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-violet-500/60 group-hover:bg-violet-500"
                        style={{ width: `${Math.min(100, (role.count / maxCount) * 100)}%` }}
                      />
                    </div>
                    <span className="text-slate-500 font-mono w-6 text-right group-hover:text-slate-300">
                      {role.count}
                    </span>
                  </div>
                </button>
              );
            })}
            {data.role_frequency.length === 0 && (
              <p className="text-xs text-slate-500 py-4 text-center">No role data available</p>
            )}
          </div>
        </div>

        {/* Overprivileged agents — AG-162: cited benchmark */}
        <div className="rounded-xl border"
          style={{ backgroundColor: 'var(--bg-raised)', borderColor: 'var(--border-default)' }}>
          <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
            <h3 className="text-sm font-semibold text-white">Overprivileged AI Agents</h3>
            <p className="text-[10px] text-slate-500">
              Agents holding Owner, Contributor, or User Access Administrator ·
              {' '}<span style={{ color: '#fbbf24' }}>Industry guidance: 0 in production</span>
            </p>
          </div>
          <div className="p-4 space-y-1">
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
              <p className="text-xs text-emerald-400/80 py-4 text-center">
                ✓ No overprivileged AI agents detected
              </p>
            )}
          </div>
        </div>
      </div>

      {investigateId && (
        <AIInvestigateDrawer
          identityId={investigateId}
          onClose={() => setInvestigateId(null)}
        />
      )}
    </div>
  );
}
