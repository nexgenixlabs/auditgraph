import React from 'react';
import { useNavigate } from 'react-router-dom';
import { COLORS } from '../../constants/design';

interface Framework {
  name: string;
  score: number;
  pass_count: number;
  total_controls: number;
  tier?: string;
  category?: string;
  short_name?: string;
  identity_controls_count?: number;
  total_framework_controls?: number;
  scope_label?: string;
}

interface CompliancePostureSummaryProps {
  frameworks?: Framework[];
  remediationPct?: number;
  saGovernancePct?: number;
}

function scoreColor(pct: number): string {
  if (pct >= 80) return '#22C55E';
  if (pct >= 50) return '#F59E0B';
  return '#EF4444';
}

function MiniDonut({ pct, label, passCount, totalControls, identityControls, totalFrameworkControls, onClick }: {
  pct: number; label: string; passCount: number; totalControls: number;
  identityControls?: number; totalFrameworkControls?: number;
  onClick?: () => void;
}) {
  const color = scoreColor(pct);
  const r = 32;
  const circumference = 2 * Math.PI * r;
  const dashOffset = circumference * (1 - Math.min(pct, 100) / 100);

  return (
    <button onClick={onClick} className={`flex flex-col items-center${onClick ? ' cursor-pointer hover:opacity-70 transition' : ''}`}>
      <div className="relative w-20 h-20">
        <svg viewBox="0 0 80 80" className="w-full h-full">
          <circle cx="40" cy="40" r={r} fill="none" stroke="var(--border-subtle)" strokeWidth="6" />
          <circle cx="40" cy="40" r={r} fill="none" stroke={color} strokeWidth="6"
            strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={dashOffset}
            transform="rotate(-90 40 40)" className="transition-all duration-700" />
          <text x="40" y="38" textAnchor="middle" fill={color} fontSize="14" fontWeight="800">
            {Math.round(pct)}%
          </text>
          <text x="40" y="50" textAnchor="middle" fill="var(--text-tertiary)" fontSize="7">
            passing
          </text>
        </svg>
      </div>
      <div className="text-[11px] font-semibold mt-1 text-center" style={{ color: COLORS.textPrimary }}>{label}</div>
      <div className="text-[9px]" style={{ color: COLORS.textMuted }}>{passCount}/{totalControls} controls</div>
      {!!identityControls && !!totalFrameworkControls && totalFrameworkControls > 0 && (
        <div className="text-[8px]" style={{ color: COLORS.textMuted }}>
          {identityControls} of {totalFrameworkControls} assessed
        </div>
      )}
    </button>
  );
}

function SummaryBar({ label, pct, onClick }: { label: string; pct: number; onClick?: () => void }) {
  const color = scoreColor(pct);
  return (
    <button onClick={onClick} className={`text-left w-full${onClick ? ' cursor-pointer hover:opacity-80 transition' : ''}`}>
      <div className="flex items-center justify-between mb-1">
        <span className="text-[11px] font-medium" style={{ color: COLORS.textSecondary }}>{label}</span>
        <span className="text-[11px] font-bold" style={{ color }}>{Math.round(pct)}%</span>
      </div>
      <div className="h-2 rounded-full overflow-hidden" style={{ backgroundColor: COLORS.borderLight }}>
        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${Math.min(pct, 100)}%`, backgroundColor: color }} />
      </div>
    </button>
  );
}

const TIER_ORDER = ['core', 'industry', 'privacy', 'benchmark'];
const TIER_LABELS: Record<string, string> = {
  core: 'Core Governance',
  industry: 'Industry Specific',
  privacy: 'Privacy & Data Protection',
  benchmark: 'Technical Benchmarks',
};

export default function CompliancePostureSummary({ frameworks, remediationPct, saGovernancePct }: CompliancePostureSummaryProps) {
  const navigate = useNavigate();
  const hasData = (frameworks && frameworks.length > 0) || remediationPct != null || saGovernancePct != null;
  if (!hasData) return null;

  const displayFrameworks = frameworks && frameworks.length > 0 ? frameworks : [];

  // Group by tier
  const tierGroups: Record<string, Framework[]> = {};
  for (const fw of displayFrameworks) {
    const tier = fw.tier || 'core';
    if (!tierGroups[tier]) tierGroups[tier] = [];
    tierGroups[tier].push(fw);
  }
  const orderedTiers = TIER_ORDER.filter(t => tierGroups[t]?.length);

  return (
    <div>
      <div className="flex items-center gap-3 mb-3">
        <h3 className="text-[14px] font-bold" style={{ color: COLORS.textPrimary }}>Compliance Posture</h3>
        <span className="text-[9px] px-2 py-0.5 rounded-full font-medium" style={{ background: 'rgba(139,92,246,0.1)', color: '#8B5CF6' }}>
          Identity Controls Only
        </span>
      </div>
      <div className="bg-white rounded-xl p-5" style={{ border: `1px solid ${COLORS.border}` }}>
        <p className="text-[10px] mb-4" style={{ color: COLORS.textMuted }}>
          Assessing identity, access, and privilege controls only
        </p>

        {/* Tier-grouped framework donuts */}
        {orderedTiers.map(tier => (
          <div key={tier} className="mb-4 last:mb-0">
            <div className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: COLORS.textMuted }}>
              {TIER_LABELS[tier] || tier}
            </div>
            <div className="flex items-start justify-around flex-wrap gap-2">
              {tierGroups[tier].map(fw => (
                <MiniDonut
                  key={fw.name}
                  pct={fw.score ?? 0}
                  label={fw.short_name || fw.name}
                  passCount={fw.pass_count ?? 0}
                  totalControls={fw.total_controls ?? 0}
                  identityControls={fw.identity_controls_count}
                  totalFrameworkControls={fw.total_framework_controls}
                  onClick={() => navigate('/dashboard?tab=governance')}
                />
              ))}
            </div>
          </div>
        ))}

        {/* Fallback if no tier data */}
        {orderedTiers.length === 0 && displayFrameworks.length > 0 && (
          <div className="flex items-start justify-around mb-5">
            {displayFrameworks.slice(0, 6).map(fw => (
              <MiniDonut
                key={fw.name}
                pct={fw.score ?? 0}
                label={fw.short_name || fw.name}
                passCount={fw.pass_count ?? 0}
                totalControls={fw.total_controls ?? 0}
                identityControls={fw.identity_controls_count}
                totalFrameworkControls={fw.total_framework_controls}
                onClick={() => navigate('/dashboard?tab=governance')}
              />
            ))}
          </div>
        )}

        {/* Row 2: Summary bars */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 border-t" style={{ borderColor: COLORS.borderLight }}>
          <SummaryBar label="Remediation Progress" pct={remediationPct ?? 0} onClick={() => navigate('/dashboard?tab=governance')} />
          <SummaryBar label="SA Governance Compliance" pct={saGovernancePct ?? 0} onClick={() => navigate('/service-accounts')} />
        </div>
      </div>
    </div>
  );
}
