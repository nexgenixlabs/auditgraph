import React, { useMemo } from 'react';
import type { CISOViewModel, PostureV31Response } from '../../utils/cisoViewModel';
import { DN } from '../dashboard/ciso-shared';
import { postureBandFromScore } from '../../constants/cisoColors';

// ── Compliance tag navigation + tooltips ─────────────────────

const COMPLIANCE_ROUTES: Record<string, string> = {
  CIS: '/compliance?framework=CIS&control=CIS-1.4',
  NIST: '/compliance?framework=NIST&control=AC-6',
  ISO27001: '/compliance?framework=ISO27001&control=A.9.2',
  SOC2: '/compliance?framework=SOC2&control=CC6.2',
};

const COMPLIANCE_TOOLTIPS: Record<string, string> = {
  CIS: 'CIS v8 5.1 — Establish and Maintain an Inventory of Accounts',
  'CIS 5.1': 'CIS v8 5.1 — Establish and Maintain an Inventory of Accounts',
  'CIS 5.3': 'CIS v8 5.3 — Disable Dormant Accounts',
  NIST: 'NIST SP 800-207 §3.3 — Zero Trust Least-Privilege Access',
  'NIST 800-207': 'NIST SP 800-207 §3.3 — Zero Trust Least-Privilege Access',
  ISO27001: 'ISO 27001 A.9.2 — User Access Management',
  SOC2: 'SOC 2 CC6.2 — Logical Access Controls',
};

// ── Helpers ──────────────────────────────────────────────────

function splitActionVerb(text: string): { verb: string; rest: string } {
  const match = text.match(/^(\S+)\s(.+)$/);
  if (!match) return { verb: text.toUpperCase(), rest: '' };
  return { verb: match[1].toUpperCase(), rest: match[2] };
}

const EFFORT_ESTIMATES = ['15m', '30m', '20m'];

const BLAST_PHRASE: Record<string, (pct: number) => string> = {
  REDUCE:    (p) => `\u2192 Reduces overall exposure by ${p}%`,
  SCOPE:     (p) => `\u2192 Reduces overall exposure by ${p}%`,
  ESTABLISH: (p) => `\u2192 Eliminates ownership gaps (${p}% risk reduction)`,
  ASSIGN:    (p) => `\u2192 Eliminates ownership gaps (${p}% risk reduction)`,
  REMOVE:    (p) => `\u2192 Closes hidden access paths (${p}% reduction)`,
  REVOKE:    (p) => `\u2192 Closes hidden access paths (${p}% reduction)`,
  ROTATE:    (p) => `\u2192 Removes credential exposure (${p}% reduction)`,
  ELIMINATE: (p) => `\u2192 Removes credential exposure (${p}% reduction)`,
  DISABLE:   (p) => `\u2192 Reduces dormant privilege surface (${p}%)`,
  DEACTIVATE:(p) => `\u2192 Reduces dormant privilege surface (${p}%)`,
};

// ── TopActionsPanel (legacy VM) ──────────────────────────────

export function TopActionsPanel({ vm }: { vm: CISOViewModel }) {
  const actions = vm.immediate_actions.slice(0, 3);
  const drivers = vm.top_risk_drivers;

  const summary = useMemo(() => {
    const totalCount = drivers.reduce((s, d) => s + d.count, 0);
    const top3Count = drivers.slice(0, 3).reduce((s, d) => s + d.count, 0);
    const riskReduction = totalCount > 0 ? Math.round((top3Count / totalCount) * 100) : 0;
    const criticalCount = drivers.filter(d => d.severity === 'critical').reduce((s, d) => s + d.count, 0);
    const pathElimination = totalCount > 0 ? Math.round((criticalCount / totalCount) * 100) : 0;
    const effortMinutes = actions.reduce((s, _, i) => s + parseInt(EFFORT_ESTIMATES[i] || '20', 10), 0);
    const effortLabel = effortMinutes >= 60
      ? `in under ${Math.ceil(effortMinutes / 60)} hour${Math.ceil(effortMinutes / 60) !== 1 ? 's' : ''}`
      : `in ${effortMinutes} minutes`;
    const primary = riskReduction > 0 ? `Reduce risk by ${riskReduction}% today ${effortLabel}` : null;
    const hasCritical = drivers.some(d => d.severity === 'critical');
    let secondary: string | null = null;
    if (hasCritical) secondary = 'Immediate action recommended';
    else if (pathElimination >= 50) secondary = 'Eliminates most lateral movement paths';
    else if (pathElimination > 0) secondary = `Addresses ${pathElimination}% of escalation paths`;
    return { primary, secondary };
  }, [drivers, actions]);

  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg overflow-hidden flex flex-col h-full"
         title="Prioritized actions ranked by risk reduction impact">
      <div className="p-3 border-b border-white/5 flex justify-between items-center flex-shrink-0">
        <span className="text-xs font-semibold text-gray-200">Priority Actions</span>
        <DN navigateTo="/remediation">
          <span className="text-xs text-[#24A2A1] cursor-pointer">Full plan →</span>
        </DN>
      </div>
      {actions.length === 0 ? (
        <div className="p-3 flex items-center justify-center flex-1">
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span className="text-xs text-emerald-400 font-medium">No remediation actions needed</span>
          </div>
        </div>
      ) : (
        <>
          {summary.primary && (
            <div className="px-3 py-2 border-b border-white/5 bg-[rgba(36,162,161,0.04)]">
              <p className="text-xs text-[#24A2A1] font-semibold">{summary.primary}</p>
              {summary.secondary && <p className="text-xs text-gray-400 mt-0.5">{summary.secondary}</p>}
            </div>
          )}
          <div className="flex-1 overflow-hidden">
            {actions.map((action, i) => {
              const { verb, rest } = splitActionVerb(action.action);
              const driver = drivers[i];
              return (
                <DN key={action.action} navigateTo={action.nav}>
                  <div className="flex items-center gap-3 px-3 py-2 border-b border-white/5 last:border-0 hover:bg-white/[0.02] transition cursor-pointer">
                    <span className="w-5 h-5 rounded-full bg-[rgba(36,162,161,0.12)] text-[#24A2A1] text-xs font-semibold font-mono flex items-center justify-center flex-shrink-0">
                      {i + 1}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-medium text-gray-200 truncate">
                        <span className="font-bold text-[#FF7216]">{verb}</span> {rest}
                      </div>
                      {driver && <span className="text-xs text-gray-400">{driver.count} identit{driver.count !== 1 ? 'ies' : 'y'}</span>}
                    </div>
                    <span className="text-xs font-mono text-gray-400 flex-shrink-0">{EFFORT_ESTIMATES[i] || '20m'}</span>
                  </div>
                </DN>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

// ── v3.1 Priority Actions ────────────────────────────────────

export function PriorityActionsPanelV31({ data }: { data: PostureV31Response }) {
  const actions = data.priority_actions || [];

  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg overflow-hidden flex flex-col h-full"
         title="Prioritized actions ranked by risk reduction impact">
      <div className="p-3 border-b border-white/5 flex-shrink-0">
        <div className="flex justify-between items-center">
          <span className="text-xs font-semibold text-gray-200">Priority Actions</span>
          <DN navigateTo="/identities?risk=critical,high">
            <span className="text-xs text-[#24A2A1] cursor-pointer">View all at-risk identities →</span>
          </DN>
        </div>
        <p style={{ fontSize: 10, color: 'var(--text-muted, #484F58)', marginTop: 2, marginBottom: 0 }}>Recommended actions ranked by risk reduction</p>
      </div>
      {actions.length === 0 ? (
        <div className="p-3 flex items-center justify-center flex-1">
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span className="text-xs text-emerald-400 font-medium">No remediation actions needed</span>
          </div>
        </div>
      ) : (
        <div className="flex-1 overflow-hidden">
          {actions.map((act) => {
            const actionText = act.action || act.title || '';
            const { verb, rest } = splitActionVerb(actionText);
            return (
              <DN key={act.rank} navigateTo={act.route || '/identities'}>
                <div className="flex items-center gap-3 px-3 py-2 border-b border-white/5 last:border-0 hover:bg-white/[0.02] transition cursor-pointer">
                  <span className="w-5 h-5 rounded-full bg-[rgba(36,162,161,0.12)] text-[#24A2A1] text-xs font-semibold font-mono flex items-center justify-center flex-shrink-0">
                    {act.rank}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-xs font-medium text-gray-200 truncate">
                        <span className="font-bold text-[#FF7216]">{verb}</span> {rest}
                      </div>
                      <div className="flex items-center gap-1.5 flex-shrink-0">
                        {(act.impact_level === 'HIGH' || act.impact_tag === 'High Impact') && (
                          <span className="text-[9px] font-mono px-1 py-0.5 rounded bg-[rgba(232,70,90,0.12)] text-[#e8465a]">High impact</span>
                        )}
                        {(act.is_quick_win || act.impact_tag === 'Quick Win') && act.impact_level !== 'HIGH' && act.impact_tag !== 'High Impact' && (
                          <span className="text-[9px] font-mono px-1 py-0.5 rounded bg-[rgba(34,197,94,0.12)] text-emerald-400">Quick win</span>
                        )}
                        {(act.compliance_tags || act.framework_badges || []).slice(0, 2).map(tag => (
                          <DN key={tag} navigateTo={COMPLIANCE_ROUTES[tag] || '/compliance'}>
                            <span
                              className="text-[9px] font-mono text-gray-500 cursor-pointer hover:text-gray-300 transition"
                              title={COMPLIANCE_TOOLTIPS[tag] || `View ${tag} compliance mapping`}
                            >{tag}</span>
                          </DN>
                        ))}
                      </div>
                    </div>
                    {(act.impact_description || act.description) && (
                      <p className="text-[11px] text-gray-400 mt-0.5 line-clamp-2">{act.impact_description || act.description}</p>
                    )}
                    {(act.blast_reduction_pct || act.risk_reduction_pct || 0) > 0 && (
                      <p className="text-[11px] text-gray-500 mt-px">{(BLAST_PHRASE[verb] || BLAST_PHRASE.REDUCE)(act.blast_reduction_pct || act.risk_reduction_pct || 0)}</p>
                    )}
                    <span className="text-xs text-gray-400 mt-0.5">{act.scope_label || `${act.affected_count ?? act.affected_identities ?? 0} identit${(act.affected_count ?? act.affected_identities ?? 0) !== 1 ? 'ies' : 'y'}`}</span>
                  </div>
                </div>
              </DN>
            );
          })}
          {data.projected && data.projected.score_improvement > 0 && (
            <div className="mx-3 mb-3 mt-2 flex-shrink-0" style={{
              background: 'var(--surface3, #1e2d4a)',
              padding: '12px 16px',
              borderRadius: 8,
              fontSize: 11,
              borderLeft: '3px solid rgba(36, 162, 161, 0.4)',
            }}>
              <p style={{ fontSize: 9, fontWeight: 600, color: 'var(--teal, #24A2A1)', letterSpacing: '0.6px', textTransform: 'uppercase', marginBottom: 8 }}>
                PROJECTED IMPACT
              </p>
              <p style={{ color: 'var(--text-secondary, #8B949E)', marginBottom: 4 }}>
                After applying these top {data.projected.actions_applied} actions:
                <span
                  title="Projected improvement assumes partial remediation effectiveness (historical average: ~60%)"
                  style={{ cursor: 'help', fontSize: '11px', color: 'var(--text-muted)', marginLeft: '6px' }}
                >ⓘ</span>
              </p>
              <p>
                <span style={{ color: 'var(--text-muted, #484F58)' }}>Score: {data.posture_score?.toFixed(0) ?? '--'} · {postureBandFromScore(data.posture_score ?? 0).label}</span>
                <span style={{ color: 'var(--text-muted, #484F58)' }}> → </span>
                <span style={{ color: 'var(--teal, #24A2A1)', fontWeight: 600 }}>{data.projected.score} · {postureBandFromScore(data.projected.score).label}</span>
                <span style={{ color: 'var(--text-muted, #484F58)' }}>  ·  At-risk: </span>
                <span style={{ color: 'var(--text-muted, #484F58)' }}>{data.if_unaddressed_count ?? '--'}</span>
                <span style={{ color: 'var(--text-muted, #484F58)' }}> → </span>
                <span style={{ color: 'var(--teal, #24A2A1)', fontWeight: 600 }}>{data.projected.at_risk_count}</span>
              </p>
              {data.projected.status !== data.posture_status && (
                <p style={{ marginTop: 2 }}>
                  <span style={{ color: 'var(--text-muted, #484F58)' }}>Status: {data.posture_status}</span>
                  <span style={{ color: 'var(--text-muted, #484F58)' }}> → </span>
                  <span style={{ color: data.projected.status === 'STRONG' ? 'var(--green, #22C55E)' : 'var(--teal, #24A2A1)', fontWeight: 600 }}>
                    {data.projected.status}
                  </span>
                </p>
              )}
              {data.projected.status === data.posture_status && (
                <p style={{ marginTop: 2 }}>
                  <span style={{ color: 'var(--text-muted, #484F58)' }}>Status: {data.projected.status} — with reduced exposure</span>
                </p>
              )}
              {data.projected.risk_reduction_pct > 0 && (
                <p style={{ marginTop: 2, color: 'var(--green, #22C55E)', fontWeight: 500 }}>
                  ↓ Reduces overall risk exposure by ~{data.projected.risk_reduction_pct}%
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Default export (backwards compat) ────────────────────────

export default function RemediationImpactSection({ vm }: { vm: CISOViewModel }) {
  return <TopActionsPanel vm={vm} />;
}
