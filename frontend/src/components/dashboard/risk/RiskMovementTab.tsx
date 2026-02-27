import React from 'react';
import { FONT, Sparkline, CISOBadge, CISOCard, SectionTitle, DN } from '../ciso-shared';
import { COLORS, getTierColor, getScoreColor, type TenantData } from '../../../constants/ciso';
import { formatDate } from '../../../utils/displayHelpers';
import { RiskProjectionPanel } from './RiskProjectionPanel';

interface RiskMovementTabProps {
  d: TenantData;
}

export function RiskMovementTab({ d }: RiskMovementTabProps) {
  // v3.0.9: Predictive scores — extrapolate from trajectory + remediation potential
  const trajectory = d.riskMovement.trajectory;
  const recentDelta = trajectory.length >= 3 ? (trajectory[trajectory.length - 1] - trajectory[trajectory.length - 3]) / 3 : 0;
  const predicted30d = Math.max(0, Math.min(100, d.riskScore.current + recentDelta * 3));
  const predicted90d = Math.max(0, Math.min(100, d.riskScore.current + recentDelta * 9));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* Score Trajectory */}
      <CISOCard>
        <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
          <div>
            <DN navigateTo="/dashboard">
              <div style={{ fontSize: 36, fontWeight: 700, fontFamily: FONT.mono, color: getTierColor(d.riskScore.tier) }}>{d.riskScore.current.toFixed(1)}</div>
            </DN>
            <CISOBadge label={d.riskScore.tier} color={getTierColor(d.riskScore.tier)} />
          </div>
          <div style={{ flex: 1 }}>
            <Sparkline data={d.riskMovement.trajectory} width={400} height={80} color={getTierColor(d.riskScore.tier)} />
          </div>
          {/* v3.0.9: Predictive score cards */}
          <div style={{ display: 'flex', gap: 10, flexShrink: 0 }}>
            <div style={{
              background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
              borderRadius: 8, padding: '10px 14px', textAlign: 'center' as const,
            }}>
              <div style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' as const, color: COLORS.textSecondary, fontFamily: FONT.ui }}>30-Day</div>
              <DN navigateTo="/drift">
                <div style={{ fontSize: 20, fontWeight: 700, fontFamily: FONT.mono, color: getScoreColor(predicted30d), marginTop: 2 }}>{predicted30d.toFixed(1)}</div>
              </DN>
              <div style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.ui }}>projected</div>
            </div>
            <div style={{
              background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
              borderRadius: 8, padding: '10px 14px', textAlign: 'center' as const,
            }}>
              <div style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' as const, color: COLORS.textSecondary, fontFamily: FONT.ui }}>90-Day</div>
              <DN navigateTo="/drift">
                <div style={{ fontSize: 20, fontWeight: 700, fontFamily: FONT.mono, color: getScoreColor(predicted90d), marginTop: 2 }}>{predicted90d.toFixed(1)}</div>
              </DN>
              <div style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.ui }}>projected</div>
            </div>
          </div>
        </div>
      </CISOCard>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 }}>
        {/* Risk Movement Table */}
        <CISOCard>
          <SectionTitle>Risk Movement</SectionTitle>
          {d.riskMovement.changes.map((ch, i) => (
            <div key={i} style={{ display: 'grid', gridTemplateColumns: '1fr 60px 20px 60px 30px', alignItems: 'center', padding: '6px 0', borderBottom: `1px solid ${COLORS.border}` }}>
              <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>{ch.label}</span>
              {(() => {
                const chNav = ch.label === 'Critical Identities' ? '/identities?risk_level=critical' :
                  ch.label === 'High-Risk Identities' ? '/identities?risk_level=high' :
                  ch.label === 'Ghost Accounts' ? '/identities?status=disabled&hasRoles=true' :
                  ch.label === 'Zombie Personas' ? '/identity-correlation' :
                  ch.label === 'New Identities' ? '/identities' :
                  ch.label === 'Removed' ? '/identities?status=disabled' :
                  ch.label === 'Total Identities' ? '/identities' : '/identities';
                return (
                  <>
                    <DN navigateTo={chNav} tooltip={`Previous: ${ch.before}`}>
                      <span style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.textSecondary, textAlign: 'right' as const, display: 'inline-block' }}>{ch.before}</span>
                    </DN>
                    <span style={{ fontSize: 11, color: COLORS.textSecondary, textAlign: 'center' as const }}>→</span>
                    <DN navigateTo={chNav}>
                      <span style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.text }}>{ch.after}</span>
                    </DN>
                  </>
                );
              })()}
              <span style={{
                fontSize: 12, textAlign: 'right' as const,
                color: ch.direction === 'up' ? COLORS.danger : ch.direction === 'down' ? COLORS.success : COLORS.textMuted,
              }}>{ch.direction === 'up' ? '↑' : ch.direction === 'down' ? '↓' : '—'}</span>
            </div>
          ))}
        </CISOCard>

        {/* Consequence Panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Most Changed */}
          <CISOCard style={{ background: d.riskMovement.mostChanged.score === 0 ? COLORS.surfaceAlt : COLORS.dangerSoft, borderColor: d.riskMovement.mostChanged.score === 0 ? COLORS.border : `${COLORS.danger}30` }}>
            <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>Most Changed Risk</div>
            <div style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui, marginTop: 4 }}>{d.riskMovement.mostChanged.name}</div>
            <DN navigateTo="/drift">
              <div style={{ fontSize: 12, fontFamily: FONT.mono, color: d.riskMovement.mostChanged.score === 0 ? COLORS.textMuted : COLORS.danger, marginTop: 2 }}>Score {d.riskMovement.mostChanged.score}/100</div>
            </DN>
          </CISOCard>

          {/* If No Action */}
          <CISOCard>
            <SectionTitle>If No Action Taken</SectionTitle>
            {d.projection.noAction.consequences.map((c, i) => (
              <div key={i} style={{ display: 'flex', gap: 6, padding: '4px 0', fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>
                <span style={{ color: COLORS.danger }}>▸</span>
                <span>{c}</span>
              </div>
            ))}
            <div style={{
              marginTop: 12, padding: '8px 12px', borderRadius: 6,
              background: COLORS.dangerSoft, border: `1px solid ${COLORS.danger}2e`,
              fontSize: 10, color: COLORS.danger, fontFamily: FONT.ui,
            }}>
              Estimated Breach Impact: {d.projection.noAction.breachImpact ?? 'Insufficient data'}
            </div>
          </CISOCard>
        </div>
      </div>

      {/* Scan Metadata */}
      <CISOCard style={{ padding: '10px 20px' }}>
        <div style={{ display: 'flex', gap: 24, justifyContent: 'center', flexWrap: 'wrap' as const }}>
          {Object.entries(d.riskMovement.scanMeta).map(([key, val]) => {
            const metaNav = key === 'identities' || key === 'totalIdentities' ? '/identities' :
              key === 'subscriptions' ? '/resources' : '';
            const isNum = typeof val === 'number' || (!isNaN(Number(val)) && key !== 'lastRun');
            return (
            <div key={key} style={{ textAlign: 'center' as const }}>
              <div style={{ fontSize: 9, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>{key}</div>
              <div style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.text, marginTop: 2 }}>
                {key === 'lastRun' ? formatDate(String(val), 'No data') :
                 key === 'frequency' && (val === 'Unknown' || !val) ? 'Not configured' :
                 key === 'duration' && (val === 'Unknown' || !val) ? '—' :
                 key === 'completeness' && val === '0%' ? 'No snapshot captured' :
                 isNum && metaNav ? (
                  <DN navigateTo={metaNav}>{val}</DN>
                ) : String(val)}
              </div>
            </div>
            );
          })}
        </div>
      </CISOCard>

      {/* Risk Projection — hidden if no remediation data */}
      <RiskProjectionPanel d={d} />
    </div>
  );
}
