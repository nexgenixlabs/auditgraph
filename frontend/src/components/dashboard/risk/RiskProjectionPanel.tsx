import React from 'react';
import { FONT, CISOCard, SectionTitle, DN } from '../ciso-shared';
import { COLORS, getTierColor, type TenantData, type Remediation } from '../../../constants/ciso';

interface RiskProjectionPanelProps {
  d: TenantData;
}

export function RiskProjectionPanel({ d }: RiskProjectionPanelProps) {
  const rems = d.remediations;
  if (rems.length === 0) return null;

  const current = d.riskScore.current;
  const projected = d.projection.remediated.score;
  const delta = projected - current;
  const top5: Remediation[] = [...rems].sort((a, b) => b.gain - a.gain).slice(0, 5);
  const totalGain = top5.reduce((s, r) => s + r.gain, 0);

  if (totalGain <= 0) return null;

  return (
    <CISOCard>
      <SectionTitle>Risk Projection (If Top Remediations Applied)</SectionTitle>

      {/* Two-column score cards */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 12 }}>
        {/* Current */}
        <div style={{
          background: COLORS.surfaceAlt,
          border: `1px solid ${COLORS.border}`,
          borderRadius: 8,
          padding: '14px 18px',
        }}>
          <div style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' as const, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
            Current Posture Score
          </div>
          <DN navigateTo="/dashboard">
            <div style={{ fontSize: 28, fontWeight: 700, fontFamily: FONT.mono, color: getTierColor(d.riskScore.tier), marginTop: 4 }}>
              {current.toFixed(1)}
            </div>
          </DN>
          <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 2 }}>
            {d.riskScore.tier}
          </div>
          <div style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui, marginTop: 4 }}>
            Latest snapshot
          </div>
        </div>

        {/* Projected */}
        <div style={{
          background: COLORS.surfaceAlt,
          border: `1px solid ${COLORS.border}`,
          borderRadius: 8,
          padding: '14px 18px',
        }}>
          <div style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' as const, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
            Projected Posture Score
          </div>
          <div style={{ fontSize: 28, fontWeight: 700, fontFamily: FONT.mono, color: getTierColor(d.projection.remediated.tier), marginTop: 4 }}>
            {projected.toFixed(1)}
          </div>
          <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 2 }}>
            {d.projection.remediated.tier}
          </div>
          <div style={{ fontSize: 9, color: COLORS.success, fontFamily: FONT.mono, marginTop: 4 }}>
            +{delta.toFixed(1)} improvement
          </div>
        </div>
      </div>

      {/* Top remediation items table */}
      <div style={{ marginTop: 16 }}>
        {/* Header row */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 100px 100px 90px',
          padding: '6px 0',
          borderBottom: `1px solid ${COLORS.borderAccent}`,
        }}>
          {['Issue', 'Affected', 'Risk Contribution', 'Projected Impact'].map(h => (
            <div key={h} style={{
              fontSize: 9, fontWeight: 600, letterSpacing: '0.06em',
              textTransform: 'uppercase' as const,
              color: COLORS.textMuted, fontFamily: FONT.ui,
              textAlign: h === 'Issue' ? ('left' as const) : ('right' as const),
            }}>
              {h}
            </div>
          ))}
        </div>

        {/* Data rows */}
        {top5.map((r, i) => {
          const contribution = totalGain > 0 ? Math.round((r.gain / totalGain) * 100) : 0;
          return (
            <div key={r.id || i} style={{
              display: 'grid',
              gridTemplateColumns: '1fr 100px 100px 90px',
              padding: '8px 0',
              borderBottom: `1px solid ${COLORS.border}`,
              alignItems: 'center',
            }}>
              <div style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>{r.title}</div>
              <DN navigateTo="/identities">
                <div style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.textSecondary, textAlign: 'right' as const }}>{r.affected}</div>
              </DN>
              <div style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.textSecondary, textAlign: 'right' as const }}>{contribution}%</div>
              <div style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.success, textAlign: 'right' as const }}>+{r.gain}</div>
            </div>
          );
        })}
      </div>
    </CISOCard>
  );
}
