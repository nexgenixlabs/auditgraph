import React from 'react';
import {
  TenantData, Nav,
  F, P, MOVE_NAV,
  getTierColor,
  Card, SectionTitle, DrillableNumber,
} from './overview-shared';
import { formatDate, formatCompleteness } from '../../utils/displayHelpers';

function getTier(score: number): string {
  if (score === 0) return 'No Data';
  if (score <= 40) return 'Critical';
  if (score <= 60) return 'Elevated';
  if (score <= 80) return 'Controlled';
  return 'Resilient';
}

function getTierBg(tier: string): string {
  const m: Record<string, string> = { 'No Data': 'rgba(90,111,150,0.12)', Critical: 'rgba(255,68,68,0.15)', Elevated: 'rgba(255,140,0,0.15)', Controlled: 'rgba(234,179,8,0.15)', Resilient: 'rgba(34,197,94,0.15)' };
  return m[tier] || 'rgba(255,255,255,0.05)';
}

function RiskTierBadge({ tier }: { tier: string }) {
  return (
    <span style={{
      display: 'inline-block', padding: '4px 14px', borderRadius: 6,
      fontFamily: F.data, fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1.5,
      color: getTierColor(tier), background: getTierBg(tier),
    }}>{tier}</span>
  );
}

function SparklineChart({ data, width = 200, height = 40, color }: { data: { day: number; score: number }[]; width?: number; height?: number; color: string }) {
  if (!data.length) return null;
  const minS = Math.min(...data.map(d => d.score)) - 2;
  const maxS = Math.max(...data.map(d => d.score)) + 2;
  const points = data.map((d, i) => {
    const x = (i / Math.max(1, data.length - 1)) * width;
    const y = height - ((d.score - minS) / (maxS - minS)) * height;
    return `${x},${y}`;
  }).join(' ');
  const last = data[data.length - 1];
  const lx = width;
  const ly = height - ((last.score - minS) / (maxS - minS)) * height;
  return (
    <svg width={width} height={height} style={{ overflow: 'visible' }}>
      <polyline points={points} fill="none" stroke={color} strokeWidth={1.5} />
      <circle cx={lx} cy={ly} r={3} fill={color} stroke={P.tooltipBg} strokeWidth={1.5} />
    </svg>
  );
}

export function RiskMovementTab({ d, nav }: { d: TenantData; nav: Nav }) {
  const tier = d.riskScore.tier;
  const color = getTierColor(tier);
  return (
    <div>
      {/* Full-width sparkline */}
      <Card style={{ marginBottom: 16 }}>
        <SectionTitle>Score Trajectory &mdash; 30 Days</SectionTitle>
        <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
          <SparklineChart data={d.riskScore.history} width={500} height={60} color={color} />
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim, textTransform: 'uppercase' }}>Projected</div>
            <div style={{ fontFamily: F.data, fontSize: 24, fontWeight: 800, color: P.textBright }}>{d.riskScore.projectedNoAction != null ? d.riskScore.projectedNoAction.toFixed(1) : '\u2014'}</div>
            {d.riskScore.projectedNoAction != null ? <RiskTierBadge tier={getTier(d.riskScore.projectedNoAction)} /> : <div style={{ fontFamily: F.ui, fontSize: 10, color: P.textDim }}>Insufficient data</div>}
          </div>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8 }}>
          <span style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint }}>Day 1</span>
          <span style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint }}>Day 15</span>
          <span style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint }}>Day 30</span>
        </div>
      </Card>

      {/* Movement table + No Action */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        <Card>
          <SectionTitle>Risk Movement &mdash; 30 Days</SectionTitle>
          {d.trends.movement30d.map((t, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10, padding: '6px 0', borderBottom: `1px solid ${P.divider}` }}>
              <span style={{ fontFamily: F.ui, fontSize: 12, color: P.textSub, flex: 1 }}>{t.label}</span>
              <span style={{ fontFamily: F.data, fontSize: 12, color: P.textDim }}><DrillableNumber value={t.previous} label={`Previous ${t.label}`} onClick={() => nav(MOVE_NAV[t.label] || '/identities')} /></span>
              <span style={{ fontFamily: F.data, fontSize: 10, color: P.textFaint }}>&rarr;</span>
              <span style={{ fontFamily: F.data, fontSize: 12, color: P.textLight, fontWeight: 600 }}><DrillableNumber value={t.current} label={`Drill into ${t.label}`} onClick={() => nav(MOVE_NAV[t.label] || '/identities')} /></span>
              <span style={{
                fontFamily: F.data, fontSize: 10, fontWeight: 600,
                color: t.direction === 'up' ? '#ff4444' : t.direction === 'down' ? '#22c55e' : '#64748b',
              }}>{t.direction === 'up' ? '\u2191' : t.direction === 'down' ? '\u2193' : '\u2014'}</span>
            </div>
          ))}
        </Card>

        <Card>
          {/* What Changed Most box */}
          <div style={{ padding: 12, background: 'rgba(255,140,0,0.06)', borderRadius: 8, marginBottom: 16, borderLeft: '3px solid #ff8c00' }}>
            <div style={{ fontFamily: F.data, fontSize: 9, color: '#ff8c00', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>What Changed Most</div>
            <div style={{ fontFamily: F.ui, fontSize: 13, color: P.textLight, fontWeight: 600 }}>{d.trends.biggestContributor.label}</div>
            <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
              <span style={{ fontFamily: F.data, fontSize: 11, color: '#ff8c00' }}>{d.trends.biggestContributor.delta}</span>
              <span style={{ fontFamily: F.data, fontSize: 9, padding: '1px 6px', borderRadius: 3, background: P.bgActive, color: P.textMuted }}>{d.trends.biggestContributor.pillar}</span>
            </div>
          </div>

          <SectionTitle>If No Action Taken</SectionTitle>
          {d.trends.noActionImpact.map((c, i) => (
            <div key={i} style={{ fontFamily: F.ui, fontSize: 11, color: P.textMuted, marginBottom: 6, paddingLeft: 12, position: 'relative' }}>
              <span style={{ position: 'absolute', left: 0, color: '#ff4444' }}>&bull;</span>{c}
            </div>
          ))}
          <div style={{ marginTop: 10, fontFamily: F.data, fontSize: 10, color: '#ff8c00' }}>
            Estimated Breach Impact: {d.trends.estimatedBreachImpact}
          </div>
        </Card>
      </div>

      {/* Model Confidence Footer */}
      <Card style={{ background: P.bgCardMuted }}>
        <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', alignItems: 'center' }}>
          {[
            { l: 'Confidence', v: d.tenant.scanConfidence || 'No data' },
            { l: 'Last Snapshot', v: formatDate(d.tenant.lastScan, 'No snapshot data') },
            { l: 'Sources', v: d.tenant.sources?.length ? d.tenant.sources.join(', ') : 'No data' },
            { l: 'Duration', v: d.tenant.scanDuration ? `${d.tenant.scanDuration.toFixed(1)}s` : '\u2014' },
            { l: 'Completeness', v: formatCompleteness(d.tenant.scanCompleteness).text },
          ].map((f, i) => (
            <div key={i}>
              <span style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint, textTransform: 'uppercase', marginRight: 6 }}>{f.l}:</span>
              <span style={{ fontFamily: F.data, fontSize: 11, color: P.textMuted }}>{f.v}</span>
            </div>
          ))}
        </div>
        <div style={{ fontFamily: F.ui, fontSize: 11, color: P.textDim, marginTop: 8 }}>{d.tenant.confidenceModelBasis}</div>
      </Card>
    </div>
  );
}
