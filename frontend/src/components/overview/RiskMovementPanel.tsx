import React from 'react';
import { COLORS, RISK_COLORS } from '../../constants/design';

interface NhiBreakdown {
  human: number;
  service_principal: number;
  managed_identity_system: number;
  managed_identity_user: number;
  guest: number;
  nhi_total: number;
  nhi_pct: number;
}

interface TrendRun {
  run_id: number;
  date: string | null;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface RiskMovementPanelProps {
  trends: TrendRun[];
  nhiBreakdown?: NhiBreakdown;
  previousRun?: { critical: number; high: number; total: number };
  currentRun?: { critical: number; high: number; total: number };
  driftCounts?: { new: number; removed: number };
}

const NHI_COLORS: { key: keyof NhiBreakdown; label: string; color: string }[] = [
  { key: 'human', label: 'Human Users', color: '#3B82F6' },
  { key: 'service_principal', label: 'Service Principals', color: '#F97316' },
  { key: 'managed_identity_system', label: 'System MI', color: '#8B5CF6' },
  { key: 'managed_identity_user', label: 'User MI', color: '#06B6D4' },
  { key: 'guest', label: 'Guests', color: '#EF4444' },
];

interface MetricRow {
  label: string;
  current: number;
  previous?: number;
}

export default function RiskMovementPanel({ trends, nhiBreakdown, previousRun, currentRun, driftCounts }: RiskMovementPanelProps) {
  // Build metric rows
  const metrics: MetricRow[] = [
    { label: 'Critical', current: currentRun?.critical ?? 0, previous: previousRun?.critical },
    { label: 'High', current: currentRun?.high ?? 0, previous: previousRun?.high },
    { label: 'New Identities', current: driftCounts?.new ?? 0 },
    { label: 'Removed Identities', current: driftCounts?.removed ?? 0 },
  ];

  // Compute dormant delta from trends if available
  const latestTrend = trends.length > 0 ? trends[trends.length - 1] : null;
  const prevTrend = trends.length > 1 ? trends[trends.length - 2] : null;
  if (latestTrend && prevTrend) {
    // Approximate dormant from total - (critical+high+medium+low)
    const latestActive = latestTrend.critical + latestTrend.high + latestTrend.medium + latestTrend.low;
    const prevActive = prevTrend.critical + prevTrend.high + prevTrend.medium + prevTrend.low;
    const dormantDelta = (latestTrend.total - latestActive) - (prevTrend.total - prevActive);
    metrics.push({ label: 'Dormant Delta', current: dormantDelta });
  }

  const hasWorsened = metrics.some(m => {
    if (m.previous != null) {
      return m.current > m.previous;
    }
    return false;
  });

  // NHI donut data
  const donutSegments = nhiBreakdown ? NHI_COLORS.map(c => ({
    ...c,
    value: (nhiBreakdown[c.key] as number) ?? 0,
  })).filter(s => s.value > 0) : [];
  const donutTotal = donutSegments.reduce((a, s) => a + s.value, 0) || 1;

  return (
    <div>
      <h3 className="text-[14px] font-bold mb-3" style={{ color: COLORS.textPrimary }}>Risk Movement & Identity Composition</h3>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Risk Movement — Text-Based */}
        <div className="bg-white rounded-xl p-5" style={{ border: `1px solid ${COLORS.border}` }}>
          <div className="text-[12px] font-bold mb-4" style={{ color: COLORS.textPrimary }}>Risk Level Movement</div>
          <div className="space-y-3">
            {metrics.map(m => {
              const delta = m.previous != null ? m.current - m.previous : null;
              const worsened = delta != null && delta > 0;
              const improved = delta != null && delta < 0;
              return (
                <div key={m.label} className="flex items-center justify-between py-1.5 border-b" style={{ borderColor: COLORS.borderLight }}>
                  <span className="text-[12px] font-medium" style={{ color: COLORS.textSecondary }}>{m.label}</span>
                  <div className="flex items-center gap-3">
                    <span className="text-[14px] font-bold tabular-nums" style={{ color: COLORS.textPrimary }}>{m.current}</span>
                    {delta != null && (
                      <div className="flex items-center gap-1.5">
                        <span className="text-[11px] font-semibold" style={{ color: worsened ? RISK_COLORS.critical.color : improved ? '#22C55E' : COLORS.textMuted }}>
                          {delta > 0 ? `↑ +${delta}` : delta < 0 ? `↓ ${delta}` : '→ 0'}
                        </span>
                        {(worsened || improved) && (
                          <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full"
                            style={{
                              backgroundColor: worsened ? RISK_COLORS.critical.bg : 'rgba(34, 197, 94, 0.1)',
                              color: worsened ? RISK_COLORS.critical.color : '#22C55E',
                            }}>
                            {worsened ? 'Worsened' : 'Improved'}
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
          {/* Warning block */}
          {hasWorsened && (
            <div className="mt-4 p-3 rounded-lg" style={{ backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)' }}>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[11px] font-bold" style={{ color: RISK_COLORS.critical.color }}>IF NO ACTION TAKEN</span>
              </div>
              <p className="text-[10px]" style={{ color: COLORS.textSecondary }}>
                Risk levels have increased since the last scan. Without remediation, the attack surface will continue to expand.
              </p>
            </div>
          )}
        </div>

        {/* NHI Dominance Donut */}
        <div className="bg-white rounded-xl p-5" style={{ border: `1px solid ${COLORS.border}` }}>
          <div className="text-[12px] font-bold mb-3" style={{ color: COLORS.textPrimary }}>NHI Dominance</div>
          {nhiBreakdown ? (
            <div className="flex flex-col items-center">
              <div className="relative w-48 h-48">
                <svg viewBox="0 0 200 200" className="w-full h-full">
                  {(() => {
                    let cumAngle = -90;
                    return donutSegments.map((seg, idx) => {
                      const angle = (seg.value / donutTotal) * 360;
                      const startRad = (cumAngle * Math.PI) / 180;
                      const endRad = ((cumAngle + angle) * Math.PI) / 180;
                      const largeArc = angle > 180 ? 1 : 0;
                      const outerR = 85;
                      const innerR = 55;
                      const x1 = 100 + outerR * Math.cos(startRad);
                      const y1 = 100 + outerR * Math.sin(startRad);
                      const x2 = 100 + outerR * Math.cos(endRad);
                      const y2 = 100 + outerR * Math.sin(endRad);
                      const x3 = 100 + innerR * Math.cos(endRad);
                      const y3 = 100 + innerR * Math.sin(endRad);
                      const x4 = 100 + innerR * Math.cos(startRad);
                      const y4 = 100 + innerR * Math.sin(startRad);
                      cumAngle += angle;
                      return (
                        <path
                          key={idx}
                          d={`M ${x1} ${y1} A ${outerR} ${outerR} 0 ${largeArc} 1 ${x2} ${y2} L ${x3} ${y3} A ${innerR} ${innerR} 0 ${largeArc} 0 ${x4} ${y4} Z`}
                          fill={seg.color}
                          stroke="white"
                          strokeWidth="2"
                        />
                      );
                    });
                  })()}
                  {/* Center text */}
                  <text x="100" y="95" textAnchor="middle" fill="var(--text-primary)" fontSize="28" fontWeight="800">
                    {Math.round(nhiBreakdown.nhi_pct)}%
                  </text>
                  <text x="100" y="115" textAnchor="middle" fill="var(--text-tertiary)" fontSize="10">
                    Non-Human
                  </text>
                </svg>
              </div>
              {/* Legend */}
              <div className="flex flex-wrap justify-center gap-x-4 gap-y-1 mt-3">
                {donutSegments.map(seg => (
                  <div key={seg.key} className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full" style={{ backgroundColor: seg.color }} />
                    <span className="text-[10px]" style={{ color: COLORS.textSecondary }}>
                      {seg.label} ({seg.value})
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="h-[240px] flex items-center justify-center text-[12px]" style={{ color: COLORS.textMuted }}>
              No data
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
