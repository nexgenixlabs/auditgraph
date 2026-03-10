import React, { useState } from 'react';
import { FONT, ScoreRing, CISOCard, DN } from '../ciso-shared';
import { COLORS } from '../../../constants/ciso';
import { getAGIRSColor } from '../../../constants/metrics';

interface PillarBreakdown {
  name: string;
  score: number;
  weight: number;
}

interface ExecutiveMetricsProps {
  score: number;
  tier: string;
  delta: number | null | undefined;
  identityCount: number;
  privilegedValue: number;
  privilegedSubtitle: string;
  workloadCount: number;
  t0Count: number;
  projectedScore?: number;
  industryBenchmark?: number | null;
  pillars?: PillarBreakdown[];
}

function Tooltip({ text, children }: { text: string; children: React.ReactNode }) {
  const [show, setShow] = useState(false);
  return (
    <span style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}
      onMouseEnter={() => setShow(true)} onMouseLeave={() => setShow(false)}>
      {children}
      {show && (
        <span style={{
          position: 'absolute', bottom: '100%', left: '50%', transform: 'translateX(-50%)',
          background: '#0f172a', border: `1px solid ${COLORS.border}`, padding: '6px 10px',
          borderRadius: 6, fontSize: 10, color: '#e2e8f0', maxWidth: 260, whiteSpace: 'normal',
          zIndex: 100, boxShadow: '0 4px 12px rgba(0,0,0,0.5)', marginBottom: 6, pointerEvents: 'none',
          fontFamily: FONT.ui, lineHeight: 1.4, fontWeight: 400,
        }}>{text}</span>
      )}
    </span>
  );
}

function ScoreBreakdownTooltip({ pillars, total, children }: { pillars: PillarBreakdown[]; total: number; children: React.ReactNode }) {
  const [show, setShow] = useState(false);
  const contributions = pillars.map(p => ({
    name: p.name,
    contribution: Math.round((p.score * p.weight / 100) * 10) / 10,
  })).sort((a, b) => b.contribution - a.contribution);

  return (
    <div
      style={{ position: 'relative', display: 'inline-flex' }}
      onMouseEnter={() => setShow(true)}
      onMouseLeave={() => setShow(false)}
    >
      {children}
      {show && (
        <div style={{
          position: 'absolute', bottom: '100%', left: '50%', transform: 'translateX(-50%)',
          background: '#0f172a', border: `1px solid ${COLORS.border}`, padding: '10px 14px',
          borderRadius: 8, zIndex: 100, boxShadow: '0 6px 20px rgba(0,0,0,0.6)',
          marginBottom: 8, pointerEvents: 'none', width: 220,
        }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui, marginBottom: 8, letterSpacing: '0.03em' }}>
            AGIRS Score Breakdown
          </div>
          {contributions.map(c => (
            <div key={c.name} style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '3px 0',
            }}>
              <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui }}>{c.name}</span>
              <span style={{ fontSize: 10, fontWeight: 600, color: COLORS.text, fontFamily: FONT.mono }}>{c.contribution.toFixed(1)}</span>
            </div>
          ))}
          <div style={{
            borderTop: `1px solid ${COLORS.border}`, marginTop: 6, paddingTop: 6,
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          }}>
            <span style={{ fontSize: 10, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui }}>Total</span>
            <span style={{ fontSize: 11, fontWeight: 700, color: getAGIRSColor(total), fontFamily: FONT.mono }}>{total.toFixed(1)}</span>
          </div>
        </div>
      )}
    </div>
  );
}

export function ExecutiveMetrics({
  score, tier, delta, identityCount,
  privilegedValue, privilegedSubtitle,
  workloadCount, t0Count,
  projectedScore, industryBenchmark,
  pillars,
}: ExecutiveMetricsProps) {
  const scoreCard = (
    <CISOCard style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '16px 24px', minWidth: 140 }}>
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
        <div style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 4 }}>
          AGIRS
          <Tooltip text="AuditGraph Identity Risk Score: Composite of Human Identity Risk (40%), Machine Identity Risk (40%), and Governance Effectiveness (20%). Higher = better posture.">
            <span style={{ marginLeft: 4, color: COLORS.textDim, cursor: 'help' }}>{'\u24D8'}</span>
          </Tooltip>
        </div>
        {/* Projected + Benchmark mini row */}
        <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
          {projectedScore != null && (
            <Tooltip text="Projected score if all recommended remediations are applied">
              <span style={{ fontSize: 9, fontFamily: FONT.mono, color: COLORS.success, background: `${COLORS.success}15`, padding: '1px 5px', borderRadius: 3 }}>
                {'\u2192'} {projectedScore.toFixed(0)}
              </span>
            </Tooltip>
          )}
          {industryBenchmark != null && (
            <Tooltip text="Industry average AGIRS score based on peer organizations of similar size">
              <span style={{ fontSize: 9, fontFamily: FONT.mono, color: COLORS.textMuted, background: `${COLORS.textMuted}15`, padding: '1px 5px', borderRadius: 3 }}>
                Avg {industryBenchmark}
              </span>
            </Tooltip>
          )}
        </div>
      </CISOCard>
  );

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr 1fr 1fr 1fr', gap: 14, alignItems: 'stretch' }}>
      {/* AGIRS Score Ring — with breakdown tooltip on hover */}
      {pillars && pillars.length > 0 ? (
        <ScoreBreakdownTooltip pillars={pillars} total={score}>
          {scoreCard}
        </ScoreBreakdownTooltip>
      ) : scoreCard}

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
