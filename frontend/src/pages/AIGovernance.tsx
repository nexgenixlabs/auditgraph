/**
 * AI Governance — policy compliance for AI agents.
 *
 * "Are you within policy?" — evaluates every AI agent against the governance
 * policy catalog (no Owner, must have human owner, no KV admin, etc.) using the
 * same architecture-derived signals the risk score is built from. No telemetry.
 *
 * Falls back to a Coming Soon preview if the feature/data isn't available.
 */
import React, { useState, useEffect } from 'react';
import { useConnection } from '../contexts/ConnectionContext';
import AIInvestigateDrawer from '../components/AIInvestigateDrawer';
import ComingSoonPage from '../components/ComingSoonPage';

interface Violator { identity_id: string; display_name: string; }
interface PolicyResult {
  policy_id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  framework: string[];
  rationale: string;
  remediation: string;
  violating_count: number;
  compliant_count: number;
  compliance_pct: number;
  top_violators: Violator[];
}
interface GovernanceData {
  summary: {
    total_agents: number;
    agents_in_violation: number;
    total_violations: number;
    policy_count: number;
    overall_compliance_pct: number;
  };
  policies: PolicyResult[];
}

const SEV_STYLE: Record<string, { text: string; bg: string; border: string }> = {
  critical: { text: '#f87171', bg: 'rgba(239,68,68,0.10)',  border: 'rgba(239,68,68,0.35)' },
  high:     { text: '#fb923c', bg: 'rgba(249,115,22,0.10)', border: 'rgba(249,115,22,0.35)' },
  medium:   { text: '#facc15', bg: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.35)' },
  low:      { text: '#4ade80', bg: 'rgba(34,197,94,0.10)',  border: 'rgba(34,197,94,0.35)' },
};

function complianceColor(pct: number): string {
  if (pct >= 95) return '#4ade80';
  if (pct >= 80) return '#facc15';
  if (pct >= 50) return '#fb923c';
  return '#f87171';
}

export default function AIGovernance() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [data, setData] = useState<GovernanceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [investigateId, setInvestigateId] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true); setError(null);
    fetch(withConnection('/api/ai-security/governance'))
      .then(r => {
        if (r.status === 404) { setError('not_found'); return null; }
        if (!r.ok) { setError('fetch_error'); return null; }
        return r.json();
      })
      .then(d => { if (d) setData(d as GovernanceData); })
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

  // No data / not enabled → show the capability preview (keeps the pillar coherent)
  if (error || !data || data.summary.total_agents === 0) {
    return (
      <ComingSoonPage
        pillar="AI Governance"
        tagline="Policies, exceptions, and audit-grade evidence for every AI agent in your tenant."
        overview="AI Governance evaluates every AI agent against a policy catalog (no Owner role on AI identities, mandatory human owner, no Key Vault admin, no unrestricted egress) using the same architecture-derived signals as the risk score. Run a discovery scan with AI agents to populate live compliance posture."
        capabilities={[
          { title: 'Policy library', description: '7 built-in policies mapped to NIST SP 800-53, CIS Azure, ISO 27001 controls.' },
          { title: 'Violation tracking', description: 'Every AI agent evaluated; violations flagged with severity + remediation.' },
          { title: 'Compliance scoring', description: 'Per-policy and overall compliance %, audit-ready.' },
          { title: 'Exception workflow', description: 'Risk-accepted exceptions with expiry + approver (coming next).' },
          { title: 'Evidence export', description: 'One-click compliance pack for SOC 2 / ISO / FedRAMP auditors (coming next).' },
        ]}
        targetWindow="Live once AI agents are discovered"
        roadmapRef="AI Governance pillar"
      />
    );
  }

  const s = data.summary;
  const overallColor = complianceColor(s.overall_compliance_pct);

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">AI Governance</h1>
        <p className="text-sm text-slate-400 mt-1">
          Policy compliance across {s.total_agents} AI agent{s.total_agents === 1 ? '' : 's'} —
          derived from architecture, mapped to NIST / CIS / ISO controls
        </p>
      </div>

      {/* Summary strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="rounded-xl border p-4" style={{ borderColor: `${overallColor}55`, backgroundColor: `${overallColor}14` }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Overall Compliance</p>
          <p className="text-3xl font-bold font-mono mt-1" style={{ color: overallColor }}>{s.overall_compliance_pct}%</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>mean across {s.policy_count} policies</p>
        </div>
        <div className="rounded-xl border p-4" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Agents in Violation</p>
          <p className="text-3xl font-bold font-mono mt-1" style={{ color: '#f87171' }}>{s.agents_in_violation}</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>of {s.total_agents} agents</p>
        </div>
        <div className="rounded-xl border p-4" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Total Violations</p>
          <p className="text-3xl font-bold font-mono mt-1" style={{ color: '#fb923c' }}>{s.total_violations}</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>across all policies</p>
        </div>
        <div className="rounded-xl border p-4" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Active Policies</p>
          <p className="text-3xl font-bold font-mono mt-1 text-white">{s.policy_count}</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>NIST / CIS / ISO mapped</p>
        </div>
      </div>

      {/* Policy compliance table */}
      <div className="rounded-xl border" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
        <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
          <h3 className="text-sm font-semibold text-white">Policy Compliance</h3>
          <p className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>Most-violated first · click a policy to see violating agents</p>
        </div>
        <div className="divide-y" style={{ borderColor: 'var(--border-subtle)' }}>
          {data.policies.map(p => {
            const sev = SEV_STYLE[p.severity] || SEV_STYLE.low;
            const isOpen = expanded === p.policy_id;
            const barColor = complianceColor(p.compliance_pct);
            return (
              <div key={p.policy_id}>
                <button
                  onClick={() => setExpanded(isOpen ? null : p.policy_id)}
                  className="w-full text-left px-4 py-3 hover:bg-slate-800/30 transition"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border flex-shrink-0"
                        style={{ color: sev.text, backgroundColor: sev.bg, borderColor: sev.border }}>
                        {p.severity}
                      </span>
                      <span className="text-xs font-medium truncate" style={{ color: 'var(--text-primary)' }}>{p.name}</span>
                    </div>
                    <div className="flex items-center gap-3 flex-shrink-0">
                      {p.violating_count > 0 ? (
                        <span className="text-xs font-mono" style={{ color: '#f87171' }}>{p.violating_count} violating</span>
                      ) : (
                        <span className="text-xs font-mono" style={{ color: '#4ade80' }}>✓ compliant</span>
                      )}
                      <div className="w-24 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                        <div className="h-full rounded-full" style={{ width: `${p.compliance_pct}%`, backgroundColor: barColor }} />
                      </div>
                      <span className="text-xs font-mono w-12 text-right" style={{ color: barColor }}>{p.compliance_pct}%</span>
                    </div>
                  </div>
                  {/* framework chips */}
                  <div className="flex flex-wrap gap-1 mt-1.5 ml-1">
                    {p.framework.map(f => (
                      <span key={f} className="text-[9px] font-mono px-1.5 py-0.5 rounded border"
                        style={{ color: '#60a5fa', borderColor: 'rgba(59,130,246,0.3)', backgroundColor: 'rgba(59,130,246,0.07)' }}>
                        {f}
                      </span>
                    ))}
                  </div>
                </button>
                {isOpen && (
                  <div className="px-4 pb-3 space-y-2" style={{ backgroundColor: 'var(--bg-surface)' }}>
                    <p className="text-[11px] leading-snug pt-2" style={{ color: 'var(--text-secondary)' }}>{p.rationale}</p>
                    <p className="text-[11px] leading-snug" style={{ color: 'var(--text-secondary)' }}>
                      <span className="font-semibold" style={{ color: '#4ade80' }}>Remediation: </span>{p.remediation}
                    </p>
                    {p.top_violators.length > 0 ? (
                      <div>
                        <p className="text-[10px] uppercase tracking-wider font-semibold mt-2 mb-1" style={{ color: 'var(--text-tertiary)' }}>
                          Violating agents ({p.violating_count})
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                          {p.top_violators.map(v => (
                            <button key={v.identity_id} onClick={() => setInvestigateId(v.identity_id)}
                              className="text-[10px] px-2 py-1 rounded border hover:bg-slate-700/40 transition"
                              style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-subtle)' }}>
                              {v.display_name}
                            </button>
                          ))}
                          {p.violating_count > p.top_violators.length && (
                            <span className="text-[10px] self-center" style={{ color: 'var(--text-tertiary)' }}>
                              +{p.violating_count - p.top_violators.length} more
                            </span>
                          )}
                        </div>
                      </div>
                    ) : (
                      <p className="text-[11px] text-emerald-400/80 pt-1">✓ All agents compliant with this policy</p>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {investigateId && (
        <AIInvestigateDrawer identityId={investigateId} onClose={() => setInvestigateId(null)} />
      )}
    </div>
  );
}
