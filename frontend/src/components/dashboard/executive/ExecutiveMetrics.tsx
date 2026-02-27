import React from 'react';
import { FONT, ScoreRing, CISOCard, DN } from '../ciso-shared';
import { COLORS } from '../../../constants/ciso';
import { getAGIRSColor } from '../../../constants/metrics';

interface ExecutiveMetricsProps {
  score: number;
  tier: string;
  delta: number | null | undefined;
  identityCount: number;
  privilegedValue: number;
  privilegedSubtitle: string;
  workloadCount: number;
  t0Count: number;
}

export function ExecutiveMetrics({
  score, tier, delta, identityCount,
  privilegedValue, privilegedSubtitle,
  workloadCount, t0Count,
}: ExecutiveMetricsProps) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr 1fr 1fr 1fr', gap: 14, alignItems: 'stretch' }}>
      {/* AGIRS Score Ring */}
      <CISOCard style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '16px 24px' }}>
        <ScoreRing score={score} size={64} strokeWidth={5} color={getAGIRSColor(score)} displayValue={score.toFixed(1)} />
        <div style={{ marginTop: 6, display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{
            display: 'inline-block', padding: '1px 8px', borderRadius: 3, fontSize: 9, fontWeight: 700,
            fontFamily: FONT.mono, background: `${getAGIRSColor(score)}20`, color: getAGIRSColor(score),
          }}>
            {tier}
          </span>
          {delta != null && (
            <span style={{ fontSize: 10, fontWeight: 700, fontFamily: FONT.mono, color: delta >= 0 ? COLORS.success : COLORS.danger }}>
              {delta >= 0 ? '+' : ''}{delta.toFixed(1)}
            </span>
          )}
        </div>
        <div style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 4 }}>AGIRS</div>
      </CISOCard>

      {/* Total Identities */}
      <CISOCard style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '16px 12px' }}>
        <DN navigateTo="/identities">
          <span style={{ fontSize: 28, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.text }}>{identityCount}</span>
        </DN>
        <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 4 }}>Total Identities</span>
      </CISOCard>

      {/* Privileged */}
      <CISOCard style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '16px 12px' }}>
        <DN navigateTo="/identities?pillar=effective-privilege">
          <span style={{ fontSize: 28, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.elevated }}>{privilegedValue}</span>
        </DN>
        <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 4 }}>Privileged</span>
        <span style={{ fontSize: 9, color: COLORS.textDim, fontFamily: FONT.mono, marginTop: 2 }}>{privilegedSubtitle}</span>
      </CISOCard>

      {/* Non-Human */}
      <CISOCard style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '16px 12px' }}>
        <DN navigateTo="/identities?workload=true">
          <span style={{ fontSize: 28, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.nhiri }}>{workloadCount}</span>
        </DN>
        <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 4 }}>Non-Human</span>
      </CISOCard>

      {/* Sensitive Admin (T0) */}
      <CISOCard style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '16px 12px' }}>
        <DN navigateTo="/identities?privilege_tier=0">
          <span style={{ fontSize: 28, fontWeight: 700, fontFamily: FONT.mono, color: t0Count > 0 ? COLORS.danger : COLORS.textDim }}>{t0Count}</span>
        </DN>
        <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 4 }}>Sensitive Admin (T0)</span>
      </CISOCard>
    </div>
  );
}
