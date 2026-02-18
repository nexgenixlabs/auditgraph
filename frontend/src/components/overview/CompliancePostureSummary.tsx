import React from 'react';
import { COLORS } from '../../constants/design';

interface Framework {
  name: string;
  score: number;
  pass_count: number;
  total_controls: number;
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

function MiniDonut({ pct, label, passCount, totalControls }: { pct: number; label: string; passCount: number; totalControls: number }) {
  const color = scoreColor(pct);
  const r = 32;
  const circumference = 2 * Math.PI * r;
  const dashOffset = circumference * (1 - Math.min(pct, 100) / 100);

  return (
    <div className="flex flex-col items-center">
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
    </div>
  );
}

function SummaryBar({ label, pct }: { label: string; pct: number }) {
  const color = scoreColor(pct);
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-[11px] font-medium" style={{ color: COLORS.textSecondary }}>{label}</span>
        <span className="text-[11px] font-bold" style={{ color }}>{Math.round(pct)}%</span>
      </div>
      <div className="h-2 rounded-full overflow-hidden" style={{ backgroundColor: COLORS.borderLight }}>
        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${Math.min(pct, 100)}%`, backgroundColor: color }} />
      </div>
    </div>
  );
}

const DEFAULT_FRAMEWORKS = [
  { name: 'CIS Azure', score: 0, pass_count: 0, total_controls: 0 },
  { name: 'HIPAA', score: 0, pass_count: 0, total_controls: 0 },
  { name: 'NIST 800-53', score: 0, pass_count: 0, total_controls: 0 },
  { name: 'SOC 2', score: 0, pass_count: 0, total_controls: 0 },
];

export default function CompliancePostureSummary({ frameworks, remediationPct, saGovernancePct }: CompliancePostureSummaryProps) {
  const displayFrameworks = (frameworks && frameworks.length > 0)
    ? frameworks.slice(0, 4)
    : DEFAULT_FRAMEWORKS;

  const hasData = (frameworks && frameworks.length > 0) || remediationPct != null || saGovernancePct != null;
  if (!hasData) return null;

  return (
    <div>
      <h3 className="text-[14px] font-bold mb-3" style={{ color: COLORS.textPrimary }}>Compliance Posture</h3>
      <div className="bg-white rounded-xl p-5" style={{ border: `1px solid ${COLORS.border}` }}>
        {/* Row 1: Framework donut rings */}
        <div className="flex items-start justify-around mb-5">
          {displayFrameworks.map(fw => (
            <MiniDonut
              key={fw.name}
              pct={fw.score ?? 0}
              label={fw.name}
              passCount={fw.pass_count ?? 0}
              totalControls={fw.total_controls ?? 0}
            />
          ))}
        </div>
        {/* Row 2: Summary bars */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 border-t" style={{ borderColor: COLORS.borderLight }}>
          <SummaryBar label="Remediation Progress" pct={remediationPct ?? 0} />
          <SummaryBar label="SA Governance Compliance" pct={saGovernancePct ?? 0} />
        </div>
      </div>
    </div>
  );
}
