import React from 'react';
import type { CISOViewModel, PostureV31Response } from '../../utils/cisoViewModel';
import { DN } from '../dashboard/ciso-shared';
import { VERDICT_CLS } from '../../constants/cisoColors';

// ── Anomaly Widget (right rail — legacy VM) ──────────────────

function anomalyInsight(vm: CISOViewModel): string {
  const a = vm.anomaly_summary;
  if (!a.available) return 'Enable anomaly detection for continuous monitoring';
  if (a.unresolved === 0) return 'No open anomalies detected';

  const top = a.top_anomalies[0];
  if (top) {
    const verb = top.type === 'permission_escalation' ? 'escalated privileges'
      : top.type === 'dormant_reactivation' ? 'reactivated after dormancy'
      : top.type === 'credential_surge' ? 'added new credentials'
      : top.type === 'off_hours_pim' ? 'activated PIM off-hours'
      : top.type === 'risk_score_spike' ? 'risk score spiked'
      : 'flagged';
    return `${top.identity_name} ${verb}`;
  }

  const crit = a.by_severity['critical'] || 0;
  if (crit > 0) return `${crit} critical anomal${crit !== 1 ? 'ies' : 'y'} unresolved`;
  return `${a.unresolved} anomal${a.unresolved !== 1 ? 'ies' : 'y'} need review`;
}

export function AnomalyWidget({ vm }: { vm: CISOViewModel }) {
  const a = vm.anomaly_summary;
  const insight = anomalyInsight(vm);

  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg p-3 overflow-hidden hover:border-white/10 hover:scale-[1.01] transition flex-shrink-0"
         title={a.available ? (a.unresolved > 0 ? `${a.unresolved} anomalies require investigation` : 'Anomaly detection active') : 'Enable anomaly detection in Settings'}>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-gray-400 uppercase tracking-wider font-medium">Anomalies</span>
        {a.available && a.unresolved > 0 && (
          <span className="text-xs font-mono font-semibold px-1.5 py-0.5 rounded bg-[rgba(232,70,90,0.15)] text-[#e8465a]">
            {a.unresolved}
          </span>
        )}
      </div>
      {a.available && a.unresolved === 0 ? (
        <div className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 flex-shrink-0" />
          <span className="text-xs text-emerald-400 font-medium">Clear</span>
        </div>
      ) : (
        <p className="text-xs text-gray-400 line-clamp-2">{insight}</p>
      )}
    </div>
  );
}

// ── v3.1 Anomaly Widget ──────────────────────────────────────

const ANOMALY_CONSEQUENCE: Record<string, string> = {
  'ghost identity': 'inactive account retains active access',
  'dormant admin': 'privileged account shows no recent activity',
  'dormant reactivation': 'privileged account shows no recent activity',
  'unowned identity': 'no accountable owner assigned',
  'external guest': 'external user has ongoing resource access',
  'permission escalation': 'unexpected privilege increase detected',
  'credential surge': 'unusual credential activity detected',
  'risk score spike': 'risk posture deteriorated rapidly',
};

export function AnomalyWidgetV31({ data }: { data: PostureV31Response }) {
  const anomalies = data.anomalies || [];

  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg p-3 overflow-hidden hover:border-white/10 hover:scale-[1.01] transition flex-shrink-0"
         title={anomalies.length > 0 ? `${anomalies.length} anomalies detected` : 'No anomalies detected'}>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-gray-400 uppercase tracking-wider font-medium">Anomalies</span>
        {anomalies.length > 0 && (
          <span className="text-xs font-mono font-semibold px-1.5 py-0.5 rounded bg-[rgba(232,70,90,0.15)] text-[#e8465a]">
            {anomalies.length}
          </span>
        )}
      </div>
      {anomalies.length === 0 ? (
        <div className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 flex-shrink-0" />
          <span className="text-xs text-emerald-400 font-medium">Clear</span>
        </div>
      ) : (
        <div className="space-y-1.5">
          {anomalies.slice(0, 2).map(a => {
            const sev = (a.severity || '').toUpperCase();
            const isUrgent = sev === 'HIGH' || sev === 'CRITICAL';
            const isMedium = sev === 'MEDIUM';
            return (
              <DN key={a.id} navigateTo={`/identities/${a.identity_id}`}>
                <div className="cursor-pointer hover:bg-white/[0.02] transition rounded">
                  <p className="text-[11px] text-gray-400">
                    <span className="text-red-400/70 mr-1">&bull;</span>
                    <span className="text-gray-300">{a.identity_name}</span> &mdash; {a.type.replace(/_/g, ' ')}
                  </p>
                  {ANOMALY_CONSEQUENCE[a.type.replace(/_/g, ' ')] && (
                    <p className="text-[10px] text-gray-500 pl-2.5">{ANOMALY_CONSEQUENCE[a.type.replace(/_/g, ' ')].charAt(0).toUpperCase() + ANOMALY_CONSEQUENCE[a.type.replace(/_/g, ' ')].slice(1)}</p>
                  )}
                  {isUrgent && (
                    <>
                      <p className="text-[10px] font-medium text-[#e8465a] pl-2.5">{'\u26A0'} Requires immediate review</p>
                      <p className="text-[10px] text-[#24A2A1] pl-2.5">&rarr; View identity</p>
                    </>
                  )}
                  {isMedium && (
                    <>
                      <p className="text-[10px] font-medium text-[#f59e0b] pl-2.5">Review recommended</p>
                      <p className="text-[10px] text-[#24A2A1] pl-2.5">&rarr; Review</p>
                    </>
                  )}
                </div>
              </DN>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Findings Panel ───────────────────────────────────────────

export function FindingsPanel({ vm }: { vm: CISOViewModel }) {
  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg overflow-hidden flex flex-col h-full">
      <div className="p-3 border-b border-white/5 flex justify-between items-center flex-shrink-0">
        <span className="text-xs font-semibold text-gray-200">Key Risk Findings</span>
        <DN navigateTo="/identity-exposures">
          <span className="text-xs text-[#24A2A1] cursor-pointer">View all →</span>
        </DN>
      </div>
      <div className="flex-1 overflow-hidden">
        {vm.findings.length === 0 ? (
          <div className="p-3 text-center text-xs text-gray-400">No risk findings detected</div>
        ) : (
          vm.findings.slice(0, 4).map((f, i) => (
            <DN key={f.name + i} navigateTo={f.nav} prefill={f.prefill}>
              <div className="grid items-center gap-3 px-3 py-2 border-b border-white/5 last:border-0 hover:bg-white/[0.02] transition cursor-pointer"
                   style={{ gridTemplateColumns: '1fr 60px 50px' }}>
                <div className="min-w-0">
                  <div className="text-xs font-medium text-gray-200 truncate">{f.name}</div>
                  <div className="text-xs text-gray-400 truncate">{f.sub}</div>
                </div>
                <span className={`font-mono text-xs font-semibold uppercase px-1.5 py-0.5 rounded-full text-center whitespace-nowrap ${VERDICT_CLS[f.verdict_variant] || VERDICT_CLS.teal}`}>
                  {f.verdict}
                </span>
                <span className="text-xs font-semibold px-1.5 py-0.5 rounded bg-[rgba(36,162,161,0.1)] text-[#24A2A1] border border-[rgba(36,162,161,0.15)] text-center">
                  {f.action_label}
                </span>
              </div>
            </DN>
          ))
        )}
      </div>
    </div>
  );
}

// ── Default export (backwards compat) ────────────────────────

export default function ActiveThreatsSection({ vm }: { vm: CISOViewModel }) {
  return (
    <div className="grid gap-3" style={{ gridTemplateColumns: '1fr 280px' }}>
      <FindingsPanel vm={vm} />
      <AnomalyWidget vm={vm} />
    </div>
  );
}
