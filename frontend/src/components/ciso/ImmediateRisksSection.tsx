import React from 'react';
import type { CISOViewModel, PostureV31Response } from '../../utils/cisoViewModel';
import { DN } from '../dashboard/ciso-shared';

// ── Severity styling ─────────────────────────────────────────

const SEV_DOT: Record<string, string> = {
  critical: 'bg-[#e8465a]',
  high: 'bg-[#FF7216]',
  medium: 'bg-[#f59e0b]',
};

// ── ImmediateRisksPanel (legacy VM) ──────────────────────────

export function ImmediateRisksPanel({ vm }: { vm: CISOViewModel }) {
  const drivers = vm.top_risk_drivers.slice(0, 3);

  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg overflow-hidden flex flex-col h-full"
         title="Top risk drivers requiring immediate attention">
      <div className="p-3 border-b border-white/5 flex justify-between items-center flex-shrink-0">
        <span className="text-xs font-semibold text-gray-200">Immediate Risks</span>
        <span className="text-xs font-mono text-gray-400">{drivers.length}</span>
      </div>
      {drivers.length === 0 ? (
        <div className="flex-1 flex items-center justify-center">
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span className="text-xs text-emerald-400 font-medium">No active risks</span>
          </div>
        </div>
      ) : (
        <div className="flex-1 overflow-hidden">
          {drivers.map(d => (
            <DN key={d.title} navigateTo={d.nav}>
              <div className="px-3 py-2 border-b border-white/5 last:border-0 hover:bg-white/[0.02] transition cursor-pointer">
                <div className="flex items-center gap-1.5 mb-0.5">
                  <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${SEV_DOT[d.severity] || SEV_DOT.medium}`} />
                  <span className="text-xs font-medium text-gray-200 truncate">{d.title}</span>
                  <span className="text-xs font-mono text-gray-400 flex-shrink-0 ml-auto">{d.count}</span>
                </div>
                <p className="text-xs text-gray-400 truncate pl-3">{d.narrative.split('—')[0].trim()}</p>
              </div>
            </DN>
          ))}
        </div>
      )}
    </div>
  );
}

// ── v3.1 Immediate Risks Panel ───────────────────────────────

const RISK_TYPE_BADGE_LABEL: Record<string, string> = {
  over_privileged: 'Excess Privilege',
  dormant_privileged: 'Dormant Access',
  unowned_nhi: 'Ownership Gap',
  ghost_accounts: 'Ghost Access',
  credential_risk: 'Credential Risk',
};

const RISK_TYPE_ROUTES: Record<string, string> = {
  over_privileged: '/identity-explorer?tab=all&metric=over_permissioned',
  dormant_privileged: '/identity-explorer?tab=all&metric=dormant_privileged',
  unowned_nhi: '/identity-explorer?tab=all&metric=unowned_nhi',
  ghost_accounts: '/identity-explorer?tab=all&metric=ghost',
  credential_risk: '/identity-explorer?tab=all&metric=credential_expired',
  provisioned_unowned: '/identity-explorer?tab=all&metric=provisioned_unowned',
};

export function ImmediateRisksPanelV31({ data }: { data: PostureV31Response }) {
  const risks = data.immediate_risks || [];
  const topNarrative = data.top_risk_narrative;
  const highestType = data.highest_risk_type;

  const badgeLabel = highestType
    ? `Primary Risk: ${RISK_TYPE_BADGE_LABEL[highestType] || highestType.replace(/_/g, ' ')}`
    : null;

  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg overflow-hidden flex flex-col h-full"
         title="Top risk drivers requiring immediate attention">
      <div className="p-3 border-b border-white/5 flex-shrink-0">
        <div className="flex justify-between items-center">
          <span className="text-xs font-semibold text-gray-200">Immediate Risks</span>
          {badgeLabel && (
            <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-md bg-[rgba(232,70,90,0.12)] text-[#e8465a]">
              {badgeLabel}
            </span>
          )}
        </div>
        <p style={{ fontSize: 10, color: 'var(--text-muted, #484F58)', marginTop: 2, marginBottom: 0 }}>Current risk exposure across identities</p>
      </div>

      {/* Top risk narrative */}
      {topNarrative && (
        <div className="px-3 pt-2 pb-3 mb-3 border-b border-white/5">
          <div className="border-l-[3px] border-[rgba(232,70,90,0.7)] pl-3">
            <p className="text-[11px] italic text-gray-300 leading-relaxed">{topNarrative}</p>
          </div>
        </div>
      )}

      {risks.length === 0 ? (
        <div className="flex-1 flex items-center justify-center">
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span className="text-xs text-emerald-400 font-medium">No active risks</span>
          </div>
        </div>
      ) : (
        <div className="flex-1 overflow-hidden">
          {risks.map(r => (
            <DN key={r.type} navigateTo={RISK_TYPE_ROUTES[r.type] || '/identities'}>
              <div className="px-3 py-2 border-b border-white/5 last:border-0 hover:bg-white/[0.02] transition cursor-pointer">
                <div className="flex items-center gap-1.5 mb-0.5">
                  <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${SEV_DOT[r.severity] || SEV_DOT.medium}`} />
                  <span className="text-xs font-medium text-gray-200 truncate">{r.label}</span>
                  <span className="text-sm font-semibold font-mono text-gray-200 flex-shrink-0 ml-auto">{r.count}</span>
                </div>
              </div>
            </DN>
          ))}
        </div>
      )}
      {risks.length > 0 && (() => {
        const atRisk = data.if_unaddressed_count ?? risks.reduce((s, r) => s + r.count, 0);
        const subCount = data.coverage?.sub_count ?? 0;
        return atRisk > 0 ? (
          <div className="px-3 pb-2 pt-2 border-t border-white/5 flex-shrink-0">
            {data.has_overlapping_identities && (
              <p style={{ fontSize: '10px', color: 'var(--text-secondary, #8B949E)', fontStyle: 'italic', fontWeight: 500, marginBottom: 6 }}>
                {'\u24D8'} Some identities contribute to multiple risk categories
              </p>
            )}
            <p className="text-[11px] italic text-gray-400 font-medium">
              <span className="not-italic text-[#f59e0b]">{'\u26A0'}</span>{' '}
              If unaddressed: {atRisk} identit{atRisk !== 1 ? 'ies' : 'y'} retain access to {subCount} subscription{subCount !== 1 ? 's' : ''}.
            </p>
          </div>
        ) : null;
      })()}
    </div>
  );
}

// ── Default export (backwards compat) ────────────────────────

export default function ImmediateRisksSection({ vm }: { vm: CISOViewModel }) {
  return <ImmediateRisksPanel vm={vm} />;
}
