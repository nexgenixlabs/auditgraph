import React from 'react';
import { useNavigate } from 'react-router-dom';
import { COLORS, RISK_COLORS, scoreToColor } from '../../constants/design';
import ArcGauge from './ArcGauge';

interface PillarData {
  score: number;
  weight: number;
  detail: Record<string, number>;
}

interface NhiBreakdown {
  human: number;
  service_principal: number;
  managed_identity_system: number;
  managed_identity_user: number;
  guest: number;
  nhi_total: number;
  nhi_pct: number;
}

interface ExecutiveRiskHeaderProps {
  score: number | null;
  grade: string | null;
  totalIdentities: number;
  criticalCount: number;
  highCount: number;
  previousCritical?: number;
  cisoSummary?: string;
  lastScan?: string | null;
  pillars?: Record<string, PillarData>;
  nhiBreakdown?: NhiBreakdown;
  improvementPotential?: number;
  cloudCoverage?: { azure: boolean; aws: boolean; gcp: boolean };
}

const PILLAR_LABELS = [
  { key: 'effective_privilege', short: 'Privilege' },
  { key: 'credential_risk', short: 'Creds' },
  { key: 'trust_federation', short: 'Trust' },
  { key: 'usage_dormancy', short: 'Usage' },
  { key: 'ownership_governance', short: 'Ownership' },
  { key: 'external_exposure', short: 'Exposure' },
];

const CLOUD_PROVIDERS = [
  { key: 'azure', label: 'Azure', color: '#0078D4' },
  { key: 'aws', label: 'AWS', color: '#FF9900' },
  { key: 'gcp', label: 'GCP', color: '#4285F4' },
] as const;

export default function ExecutiveRiskHeader({
  score, grade, totalIdentities, criticalCount, highCount, previousCritical,
  cisoSummary, lastScan, pillars, nhiBreakdown, improvementPotential, cloudCoverage,
}: ExecutiveRiskHeaderProps) {
  const navigate = useNavigate();
  const criticalDelta = previousCritical != null ? criticalCount - previousCritical : undefined;

  return (
    <div className="rounded-2xl p-8 flex items-center gap-10" style={{ background: 'var(--gradient-hero)', minHeight: 180 }}>
      <div className="flex-shrink-0 relative">
        <ArcGauge score={score} grade={grade} />
        {improvementPotential != null && improvementPotential > 0 && (
          <div className="absolute -bottom-2 left-1/2 -translate-x-1/2 whitespace-nowrap px-2 py-0.5 rounded-full text-[9px] font-bold"
            style={{ backgroundColor: 'rgba(34, 197, 94, 0.2)', color: '#22C55E', border: '1px solid rgba(34, 197, 94, 0.3)' }}>
            Potential: -{Math.round(improvementPotential)} pts
          </div>
        )}
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-lg font-bold text-white mb-1">Identity Attack Surface Score</div>
        <p className="text-xs text-slate-400 mb-3 max-w-xl leading-relaxed">
          6-pillar weighted score: effective privilege, credential exposure, trust relationships, usage dormancy, ownership governance, and external exposure.
        </p>

        {/* Key metrics row */}
        <div className="flex items-center gap-8 flex-wrap">
          <Metric label="Identities" value={totalIdentities} color="text-white" onClick={() => navigate('/identities')} />
          <Metric label="Critical" value={criticalCount} color={RISK_COLORS.critical.color} onClick={() => navigate('/identities?risk_level=critical')} />
          <Metric label="High" value={highCount} color={RISK_COLORS.high.color} onClick={() => navigate('/identities?risk_level=high')} />
          {nhiBreakdown && (
            <Metric label="NHI %" value={`${Math.round(nhiBreakdown.nhi_pct)}%`} color="#60A5FA" onClick={() => navigate('/workload-identities')} />
          )}
          {criticalDelta != null && (
            <div>
              <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-0.5">30-Day Trend</div>
              <div className="flex items-center gap-1 text-sm font-semibold">
                {criticalDelta > 0
                  ? <span style={{ color: RISK_COLORS.critical.color }}>↑ +{criticalDelta} critical</span>
                  : criticalDelta < 0
                    ? <span style={{ color: RISK_COLORS.low.color }}>↓ {criticalDelta} critical</span>
                    : <span className="text-slate-400">→ No change</span>
                }
              </div>
            </div>
          )}
        </div>

        {/* Pillar mini-bars */}
        {pillars && (
          <div className="flex items-center gap-4 mt-4">
            {PILLAR_LABELS.map(p => {
              const pillar = pillars[p.key];
              if (!pillar) return null;
              const pillarNav: Record<string, string> = {
                effective_privilege: '/identities?risk_level=critical',
                credential_risk: '/spns',
                trust_federation: '/identities?identity_category=guest',
                usage_dormancy: '/identities?activity_status=stale',
                ownership_governance: '/service-accounts',
                external_exposure: '/identities',
              };
              return (
                <button key={p.key} className="flex-1 cursor-pointer hover:opacity-70 transition text-left" onClick={() => navigate(pillarNav[p.key] || '/identities')}>
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="text-[9px] uppercase tracking-wider text-slate-500">{p.short}</span>
                    <span className="text-[10px] font-bold" style={{ color: scoreToColor(pillar.score) }}>{Math.round(pillar.score)}</span>
                  </div>
                  <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: '#334155' }}>
                    <div className="h-full rounded-full transition-all duration-700" style={{ width: `${Math.min(pillar.score, 100)}%`, backgroundColor: scoreToColor(pillar.score) }} />
                  </div>
                </button>
              );
            })}
          </div>
        )}

        {/* Cloud coverage bar */}
        {cloudCoverage && (
          <div className="flex items-center gap-5 mt-4">
            {CLOUD_PROVIDERS.map(cp => {
              const connected = cloudCoverage[cp.key];
              return (
                <div key={cp.key} className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: connected ? cp.color : '#475569' }} />
                  <span className="text-[10px] font-medium" style={{ color: connected ? cp.color : '#64748B' }}>{cp.label}</span>
                  <span className="text-[9px]" style={{ color: connected ? '#94A3B8' : '#475569' }}>
                    {connected ? 'Connected' : 'Not Connected'}
                  </span>
                </div>
              );
            })}
          </div>
        )}

        {/* CISO summary + last scan */}
        <div className="flex items-center justify-between mt-4 gap-4">
          {cisoSummary && (
            <p className="text-[11px] text-slate-400 leading-relaxed flex-1">{cisoSummary}</p>
          )}
          <div className="flex items-center gap-3 flex-shrink-0">
            {lastScan && (
              <span className="text-[10px] text-slate-500">
                Last scan: {new Date(lastScan).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function Metric({ label, value, color, onClick }: { label: string; value: number | string; color: string; onClick?: () => void }) {
  const Tag = onClick ? 'button' : 'div';
  return (
    <Tag onClick={onClick} className={onClick ? 'cursor-pointer hover:opacity-70 transition text-left' : ''}>
      <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-0.5">{label}</div>
      <div className="text-xl font-bold" style={{ color: color.startsWith('text-') ? undefined : color }}>
        {value}
      </div>
    </Tag>
  );
}
