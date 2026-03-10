import React, { useState } from 'react';
import { FONT, Sparkline, CISOBadge, CISOCard, SectionTitle, DN } from '../ciso-shared';
import { COLORS, getTierColor, getScoreColor, type TenantData } from '../../../constants/ciso';
import { formatDate } from '../../../utils/displayHelpers';
import { RiskProjectionPanel } from './RiskProjectionPanel';

interface RiskMovementTabProps {
  d: TenantData;
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
          borderRadius: 6, fontSize: 10, color: '#e2e8f0', maxWidth: 280, whiteSpace: 'normal',
          zIndex: 100, boxShadow: '0 4px 12px rgba(0,0,0,0.5)', marginBottom: 6, pointerEvents: 'none',
          fontFamily: FONT.ui, lineHeight: 1.4, fontWeight: 400,
        }}>{text}</span>
      )}
    </span>
  );
}

export function RiskMovementTab({ d }: RiskMovementTabProps) {
  // v3.0.9: Predictive scores — extrapolate from trajectory + remediation potential
  const trajectory = d.riskMovement.trajectory;
  const recentDelta = trajectory.length >= 3 ? (trajectory[trajectory.length - 1] - trajectory[trajectory.length - 3]) / 3 : 0;
  const predicted30d = Math.max(0, Math.min(100, d.riskScore.current + recentDelta * 3));
  const predicted90d = Math.max(0, Math.min(100, d.riskScore.current + recentDelta * 9));
  const trendDir = recentDelta > 0.5 ? 'improving' : recentDelta < -0.5 ? 'declining' : 'stable';
  const trendColor = trendDir === 'improving' ? COLORS.success : trendDir === 'declining' ? COLORS.danger : COLORS.textMuted;
  const trendArrow = trendDir === 'improving' ? '↑' : trendDir === 'declining' ? '↓' : '→';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* Score Trajectory — enhanced with trend indicator */}
      <CISOCard>
        <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
          <div>
            <DN navigateTo="/dashboard">
              <div style={{ fontSize: 36, fontWeight: 700, fontFamily: FONT.mono, color: getTierColor(d.riskScore.tier) }}>{d.riskScore.current.toFixed(1)}</div>
            </DN>
            <CISOBadge label={d.riskScore.tier} color={getTierColor(d.riskScore.tier)} />
            {/* Trend indicator */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 6 }}>
              <span style={{ fontSize: 14, color: trendColor }}>{trendArrow}</span>
              <span style={{ fontSize: 10, fontWeight: 600, fontFamily: FONT.ui, color: trendColor, textTransform: 'capitalize' as const }}>{trendDir}</span>
              <Tooltip text="Trend direction based on the last 3 snapshots. Improving means the AGIRS score is increasing (better posture). Declining means the score is dropping (worsening posture).">
                <span style={{ fontSize: 10, color: COLORS.textDim, cursor: 'help' }}>{'\u24D8'}</span>
              </Tooltip>
            </div>
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
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
            <SectionTitle>Risk Movement</SectionTitle>
            <Tooltip text="Compares identity risk metrics between the current and previous snapshots. Upward arrows indicate worsening risk (more critical identities, ghost accounts, etc.). Downward arrows indicate improvement.">
              <span style={{ fontSize: 12, color: COLORS.textDim, cursor: 'help', marginBottom: 16 }}>{'\u24D8'}</span>
            </Tooltip>
          </div>
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
          {/* Most Changed — enhanced with visual emphasis + narrative */}
          <CISOCard style={{
            background: d.riskMovement.mostChanged.score === 0 ? COLORS.surfaceAlt : COLORS.dangerSoft,
            borderColor: d.riskMovement.mostChanged.score === 0 ? COLORS.border : `${COLORS.danger}30`,
            borderLeft: d.riskMovement.mostChanged.score > 0 ? `3px solid ${COLORS.danger}` : undefined,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>Most Changed Risk</div>
              {d.riskMovement.mostChanged.score > 0 && (
                <span style={{
                  fontSize: 8, fontWeight: 700, padding: '2px 6px', borderRadius: 3,
                  background: `${COLORS.danger}20`, color: COLORS.danger, fontFamily: FONT.mono,
                  textTransform: 'uppercase' as const, letterSpacing: '0.05em',
                }}>Attention Required</span>
              )}
            </div>
            <div style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui, marginTop: 6 }}>{d.riskMovement.mostChanged.name}</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 6 }}>
              <DN navigateTo="/drift">
                <span style={{ fontSize: 22, fontWeight: 700, fontFamily: FONT.mono, color: d.riskMovement.mostChanged.score === 0 ? COLORS.textMuted : COLORS.danger }}>{d.riskMovement.mostChanged.score}</span>
              </DN>
              <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui }}>/100 risk score</span>
            </div>
            {d.riskMovement.mostChanged.score > 0 && (
              <div style={{
                marginTop: 8, padding: '6px 10px', borderRadius: 5,
                background: COLORS.surfaceAlt, fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, lineHeight: 1.5,
              }}>
                {d.riskMovement.mostChanged.name === 'Effective Privilege'
                  ? 'Privilege escalation or new Tier-0 assignments detected. Review Global Admin and Owner role changes immediately.'
                  : d.riskMovement.mostChanged.name === 'Credential Risk'
                  ? 'Credential rotation failures or expired secrets detected. Compromised credentials are the top initial access vector.'
                  : d.riskMovement.mostChanged.name === 'Usage Dormancy'
                  ? 'Dormant identities with active privileges increased. These are prime targets for lateral movement attacks.'
                  : d.riskMovement.mostChanged.name === 'Trust & Federation'
                  ? 'External trust changes detected. Cross-tenant federation combined with privilege amplifies attack surface.'
                  : d.riskMovement.mostChanged.name === 'Ownership Governance'
                  ? 'Orphaned identity coverage declined. Unowned identities lack accountability for access reviews.'
                  : d.riskMovement.mostChanged.name === 'External Exposure'
                  ? 'Broad-scope access patterns detected. Identities with tenant-wide or multi-subscription access increase blast radius.'
                  : 'This pillar shows the largest score change since the previous snapshot. Investigate the contributing factors.'}
              </div>
            )}
          </CISOCard>

          {/* If No Action — enhanced with visual path comparison */}
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
            {/* Path comparison: No-Action vs Remediated */}
            {d.projection.remediated.score > d.riskScore.current && (
              <div style={{
                marginTop: 12, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10,
              }}>
                <div style={{
                  padding: '8px 12px', borderRadius: 6,
                  background: `${COLORS.danger}08`, border: `1px solid ${COLORS.danger}15`,
                  textAlign: 'center' as const,
                }}>
                  <div style={{ fontSize: 8, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.danger, fontFamily: FONT.ui }}>No Action (90d)</div>
                  <div style={{ fontSize: 18, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.danger, marginTop: 4 }}>{predicted90d.toFixed(1)}</div>
                </div>
                <div style={{
                  padding: '8px 12px', borderRadius: 6,
                  background: `${COLORS.success}08`, border: `1px solid ${COLORS.success}15`,
                  textAlign: 'center' as const,
                }}>
                  <div style={{ fontSize: 8, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.success, fontFamily: FONT.ui }}>If Remediated</div>
                  <div style={{ fontSize: 18, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.success, marginTop: 4 }}>{d.projection.remediated.score.toFixed(1)}</div>
                </div>
              </div>
            )}
          </CISOCard>
        </div>
      </div>

      {/* Top Changes Since Last Snapshot */}
      {(() => {
        const snapshotChanges = d.riskMovement.changes
          .map(ch => ({ label: ch.label, delta: ch.after - ch.before, direction: ch.direction }))
          .filter(ch => ch.delta !== 0);
        if (snapshotChanges.length === 0) return null;

        // Map labels to more descriptive posture-change phrasing + nav targets
        const changeMap: Record<string, { display: string; nav: string; riskDir: 'increase' | 'decrease' }> = {
          'Critical Identities': { display: 'New critical-risk identities', nav: '/identities?risk_level=critical', riskDir: 'increase' },
          'High-Risk Identities': { display: 'New high-risk identities', nav: '/identities?risk_level=high', riskDir: 'increase' },
          'Ghost Accounts': { display: 'New ghost accounts (disabled + active roles)', nav: '/identities?agirs_factor=h1_ghost&show_deleted=true', riskDir: 'increase' },
          'Zombie Personas': { display: 'New zombie personas', nav: '/identity-correlation', riskDir: 'increase' },
          'New Identities': { display: 'New identities provisioned', nav: '/identities', riskDir: 'increase' },
          'Removed': { display: 'Identities removed / disabled', nav: '/identities?status=disabled', riskDir: 'decrease' },
          'Total Identities': { display: 'Total identity count change', nav: '/identities', riskDir: 'increase' },
        };

        return (
          <CISOCard>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <SectionTitle>Top Changes Since Last Snapshot</SectionTitle>
              <Tooltip text="Changes detected since the previous identity graph analysis.">
                <span style={{ fontSize: 12, color: COLORS.textDim, cursor: 'help', marginBottom: 16 }}>{'\u24D8'}</span>
              </Tooltip>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
              {snapshotChanges.map((ch, i) => {
                const meta = changeMap[ch.label];
                const displayLabel = meta?.display || ch.label;
                const nav = meta?.nav || '/identities';
                // Red if delta increases risk, green if reduces risk
                const isRiskIncrease = meta?.riskDir === 'decrease' ? ch.delta < 0 : ch.delta > 0;
                const deltaColor = isRiskIncrease ? COLORS.danger : COLORS.success;
                const prefix = ch.delta > 0 ? '+' : '';

                return (
                  <div key={i} style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    padding: '8px 0',
                    borderBottom: i < snapshotChanges.length - 1 ? `1px solid ${COLORS.border}` : 'none',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ width: 6, height: 6, borderRadius: '50%', background: deltaColor, flexShrink: 0 }} />
                      <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>{displayLabel}</span>
                    </div>
                    <DN navigateTo={nav} tooltip="Click to view affected identities.">
                      <span style={{ fontSize: 13, fontWeight: 700, fontFamily: FONT.mono, color: deltaColor }}>
                        {prefix}{ch.delta}
                      </span>
                    </DN>
                  </div>
                );
              })}
            </div>
          </CISOCard>
        );
      })()}

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
