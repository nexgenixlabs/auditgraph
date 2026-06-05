/**
 * AI Risk — attack scenarios for AI agents.
 *
 * "How could AI be exploited?" — derives named, MITRE-mapped attack scenarios
 * from signal combinations (e.g. data access + unrestricted egress = exfiltration
 * path). Architecture-derived; no telemetry.
 *
 * Falls back to a capability preview when no AI agents are discovered.
 */
import React, { useState, useEffect } from 'react';
import { useConnection } from '../contexts/ConnectionContext';
import AIInvestigateDrawer from '../components/AIInvestigateDrawer';
import ComingSoonPage from '../components/ComingSoonPage';

interface Affected { identity_id: string; display_name: string; }
interface Scenario {
  scenario_id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  narrative: string;
  mitre: string[];
  prevented_by: string;
  affected_count: number;
  top_affected: Affected[];
}
interface RiskData {
  summary: {
    total_agents: number;
    exploitable_agents: number;
    scenario_types: number;
    by_severity: Record<string, number>;
  };
  scenarios: Scenario[];
}

const SEV_STYLE: Record<string, { text: string; bg: string; border: string }> = {
  critical: { text: '#f87171', bg: 'rgba(239,68,68,0.10)',  border: 'rgba(239,68,68,0.35)' },
  high:     { text: '#fb923c', bg: 'rgba(249,115,22,0.10)', border: 'rgba(249,115,22,0.35)' },
  medium:   { text: '#facc15', bg: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.35)' },
  low:      { text: '#4ade80', bg: 'rgba(34,197,94,0.10)',  border: 'rgba(34,197,94,0.35)' },
};

export default function AIRisk() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [data, setData] = useState<RiskData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [investigateId, setInvestigateId] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true); setError(null);
    fetch(withConnection('/api/ai-security/risk'))
      .then(r => {
        if (r.status === 404) { setError('not_found'); return null; }
        if (!r.ok) { setError('fetch_error'); return null; }
        return r.json();
      })
      .then(d => { if (d) setData(d as RiskData); })
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
        pillar="AI Risk"
        tagline="How an attacker could exploit your AI footprint — modeled from architecture."
        overview="AI Risk derives named attack scenarios (secret exposure, data exfiltration, subscription takeover) from combinations of the architecture-level signals AuditGraph already computes. Run a discovery scan with AI agents to populate live exploitable-path analysis."
        capabilities={[
          { title: 'AI attack scenarios', description: 'Subscription takeover, secret theft, data exfiltration, ungoverned privilege — derived from signal combinations.' },
          { title: 'MITRE ATT&CK mapping', description: 'Every scenario maps to ATT&CK techniques for defensible reporting.' },
          { title: 'Exploitable-agent counts', description: 'Fleet view of how many agents each scenario applies to.' },
          { title: 'Prompt-injection blast radius', description: 'What an attacker reaches if the agent’s prompts are hijacked (coming next).' },
          { title: 'Attack simulation', description: 'Dry-run “what if this agent were compromised” (coming next).' },
        ]}
        targetWindow="Live once AI agents are discovered"
        roadmapRef="AI Risk pillar"
      />
    );
  }

  const s = data.summary;
  const activeScenarios = data.scenarios.filter(x => x.affected_count > 0);

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">AI Abuse Scenarios</h1>
        <p className="text-sm text-slate-400 mt-1">
          Named attack scenarios across {s.total_agents} AI agent{s.total_agents === 1 ? '' : 's'} —
          derived from architecture, mapped to MITRE ATT&amp;CK. No content detection
          required: AuditGraph quantifies impact; partners (Lakera, Bedrock, NeMo) detect.
        </p>
      </div>

      {/* Summary strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="rounded-xl border p-4" style={{ borderColor: 'rgba(239,68,68,0.35)', backgroundColor: 'rgba(239,68,68,0.10)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Exploitable Agents</p>
          <p className="text-3xl font-bold font-mono mt-1" style={{ color: '#f87171' }}>{s.exploitable_agents}</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>of {s.total_agents} have ≥1 scenario</p>
        </div>
        <div className="rounded-xl border p-4" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Critical Scenarios</p>
          <p className="text-3xl font-bold font-mono mt-1" style={{ color: '#f87171' }}>{s.by_severity.critical || 0}</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>agent-scenario hits</p>
        </div>
        <div className="rounded-xl border p-4" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>High Scenarios</p>
          <p className="text-3xl font-bold font-mono mt-1" style={{ color: '#fb923c' }}>{s.by_severity.high || 0}</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>agent-scenario hits</p>
        </div>
        <div className="rounded-xl border p-4" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Scenario Types Active</p>
          <p className="text-3xl font-bold font-mono mt-1 text-white">{s.scenario_types}</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>distinct attack paths</p>
        </div>
      </div>

      {/* Scenario cards */}
      <div className="space-y-3">
        {activeScenarios.length === 0 ? (
          <div className="rounded-xl border p-8 text-center" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
            <p className="text-sm text-emerald-400/80">✓ No exploitable attack scenarios detected across your AI agents.</p>
          </div>
        ) : activeScenarios.map(sc => {
          const sev = SEV_STYLE[sc.severity] || SEV_STYLE.low;
          const isOpen = expanded === sc.scenario_id;
          return (
            <div key={sc.scenario_id} className="rounded-xl border"
              style={{ borderColor: sev.border, backgroundColor: 'var(--bg-raised)' }}>
              <button onClick={() => setExpanded(isOpen ? null : sc.scenario_id)}
                className="w-full text-left px-4 py-3 hover:bg-slate-800/30 transition">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border flex-shrink-0"
                      style={{ color: sev.text, backgroundColor: sev.bg, borderColor: sev.border }}>
                      {sc.severity}
                    </span>
                    <span className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>{sc.name}</span>
                  </div>
                  <span className="text-xs font-mono flex-shrink-0" style={{ color: sev.text }}>
                    {sc.affected_count} agent{sc.affected_count === 1 ? '' : 's'}
                  </span>
                </div>
                <div className="flex flex-wrap gap-1 mt-1.5 ml-1">
                  {sc.mitre.map(m => (
                    <span key={m} className="text-[9px] font-mono px-1.5 py-0.5 rounded border"
                      style={{ color: '#a78bfa', borderColor: 'rgba(139,92,246,0.3)', backgroundColor: 'rgba(139,92,246,0.07)' }}>
                      {m}
                    </span>
                  ))}
                </div>
              </button>
              {isOpen && (
                <div className="px-4 pb-3 space-y-2" style={{ backgroundColor: 'var(--bg-surface)' }}>
                  <p className="text-[11px] leading-relaxed pt-2" style={{ color: 'var(--text-secondary)' }}>{sc.narrative}</p>
                  <p className="text-[11px] leading-snug" style={{ color: 'var(--text-secondary)' }}>
                    <span className="font-semibold" style={{ color: '#4ade80' }}>Prevented by: </span>{sc.prevented_by}
                  </p>
                  <div>
                    <p className="text-[10px] uppercase tracking-wider font-semibold mt-2 mb-1" style={{ color: 'var(--text-tertiary)' }}>
                      Affected agents ({sc.affected_count})
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {sc.top_affected.map(a => (
                        <button key={a.identity_id} onClick={() => setInvestigateId(a.identity_id)}
                          className="text-[10px] px-2 py-1 rounded border hover:bg-slate-700/40 transition"
                          style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-subtle)' }}>
                          {a.display_name}
                        </button>
                      ))}
                      {sc.affected_count > sc.top_affected.length && (
                        <span className="text-[10px] self-center" style={{ color: 'var(--text-tertiary)' }}>
                          +{sc.affected_count - sc.top_affected.length} more
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {investigateId && (
        <AIInvestigateDrawer identityId={investigateId} onClose={() => setInvestigateId(null)} />
      )}
    </div>
  );
}
