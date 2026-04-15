import React from 'react';
import {
  TenantData, Nav,
  F, P, GOV_NAV, POLICY_GAP_NAV,
  getTier, getTierColor, getTierBg,
  Card, SectionTitle, TooltipWrap, TrendArrow, MiniProgressBar,
  SeverityDot, MaturityBadge, DrillableNumber,
} from './overview-shared';

function RiskTierBadge({ tier }: { tier: string }) {
  return (
    <span style={{
      display: 'inline-block', padding: '4px 14px', borderRadius: 6,
      fontFamily: F.data, fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1.5,
      color: getTierColor(tier), background: getTierBg(tier),
    }}>{tier}</span>
  );
}

export function ControlGovernanceTab({ d, nav }: { d: TenantData; nav: Nav }) {
  const gov = d.governance;
  return (
    <div>
      {/* Governance Metrics (4-column) */}
      <Card style={{ marginBottom: 16 }}>
        <SectionTitle>Governance Metrics</SectionTitle>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
          {gov.metrics.map((m, i) => (
            <div key={i} style={{ padding: 14, background: P.bgHover, borderRadius: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <span style={{ fontSize: 16 }}>{m.icon}</span>
                <span style={{ fontFamily: F.ui, fontSize: 12, color: P.textMuted }}>{m.label}</span>
              </div>
              {m.configured ? (
                <>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
                    <span style={{ fontFamily: F.data, fontSize: 28, fontWeight: 800, color: P.textBright }}><DrillableNumber value={`${m.value}%`} label={`Drill into ${m.label}`} onClick={() => nav(GOV_NAV[m.label] || '/identities')} /></span>
                    <span style={{ fontFamily: F.data, fontSize: 11, color: P.textDim }}>/ <DrillableNumber value={`${m.target}%`} label={`${m.label} target`} onClick={() => nav('/settings')} /></span>
                  </div>
                  <MiniProgressBar value={m.value} max={m.target} color={m.value >= m.target ? '#22c55e' : m.value >= m.target * 0.5 ? '#eab308' : '#ff4444'} height={4} />
                  <div style={{ marginTop: 6 }}><TrendArrow value={m.trend30d} /></div>
                </>
              ) : (
                <>
                  <div style={{ fontFamily: F.data, fontSize: 22, fontWeight: 800, color: P.textFaint, marginBottom: 4 }}>&mdash;</div>
                  <div style={{ fontFamily: F.data, fontSize: 10, color: P.textDim, textTransform: 'uppercase', letterSpacing: 0.5 }}>
                    {m.label === 'Access Reviews Done' ? 'No access reviews configured' : 'Not Configured'}
                  </div>
                  <div style={{ marginTop: 6 }}>
                    <span onClick={() => nav(m.label === 'Access Reviews Done' ? '/access-reviews' : '/settings')} style={{ fontFamily: F.data, fontSize: 10, color: P.accentStrong, cursor: 'pointer' }}>
                      {m.label === 'Access Reviews Done' ? 'Create review \u2192' : 'Configure \u2192'}
                    </span>
                  </div>
                </>
              )}
            </div>
          ))}
        </div>
      </Card>

      {/* Control Failures + Effectiveness */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Card>
          <SectionTitle>Control Failures</SectionTitle>
          {gov.policyGaps.preventiveFailures.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontFamily: F.data, fontSize: 10, color: '#ff4444', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>{'\u25B8'} Preventive Failures</div>
              {gov.policyGaps.preventiveFailures.map((g, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                  <SeverityDot severity={g.severity} />
                  <span style={{ fontFamily: F.ui, fontSize: 12, color: P.textSub, flex: 1 }}>{g.label}</span>
                  <span style={{ fontFamily: F.data, fontSize: 11, color: P.textMuted }}><DrillableNumber value={g.count} label={`Drill into ${g.label}`} onClick={() => nav(POLICY_GAP_NAV[g.label] || '/identities')} /></span>
                </div>
              ))}
            </div>
          )}
          {gov.policyGaps.operationalGaps.length > 0 && (
            <div>
              <div style={{ fontFamily: F.data, fontSize: 10, color: '#ff8c00', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>{'\u25B8'} Operational Gaps</div>
              {gov.policyGaps.operationalGaps.map((g, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                  <SeverityDot severity={g.severity} />
                  <span style={{ fontFamily: F.ui, fontSize: 12, color: P.textSub, flex: 1 }}>{g.label}</span>
                  <span style={{ fontFamily: F.data, fontSize: 11, color: P.textMuted }}><DrillableNumber value={g.count} label={`Drill into ${g.label}`} onClick={() => nav(POLICY_GAP_NAV[g.label] || '/identities')} /></span>
                </div>
              ))}
            </div>
          )}
          {gov.policyGaps.preventiveFailures.length === 0 && gov.policyGaps.operationalGaps.length === 0 && (
            <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textDim }}>No policy gaps detected</div>
          )}
        </Card>

        <Card>
          <SectionTitle>Governance Effectiveness</SectionTitle>
          {gov.effectivenessConfigured ? (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 16 }}>
                <span style={{ fontFamily: F.data, fontSize: 48, fontWeight: 800, color: P.textBright }}><DrillableNumber value={gov.effectivenessScore} label="Governance effectiveness" onClick={() => nav('/service-accounts')} /></span>
                <div>
                  <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textMuted, marginBottom: 4 }}>/ 100</div>
                  <RiskTierBadge tier={getTier(gov.effectivenessScore)} />
                  <div style={{ marginTop: 6 }}><MaturityBadge level={d.governance.maturityLevel} /></div>
                </div>
                <TooltipWrap content={gov.effectivenessTooltip}>
                  <span style={{ cursor: 'help', fontFamily: F.data, fontSize: 14, color: P.textDim, marginLeft: 'auto' }}>{'\u2139'}</span>
                </TooltipWrap>
              </div>
              <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textMuted }}>
                Governance effectiveness measures the combined strength of ownership coverage, PIM enforcement, access review completion, and policy alignment across your identity estate.
              </div>
            </>
          ) : (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 16 }}>
                <span style={{ fontFamily: F.data, fontSize: 48, fontWeight: 800, color: P.textFaint }}>&mdash;</span>
                <div>
                  <div style={{ fontFamily: F.data, fontSize: 10, fontWeight: 700, padding: '3px 8px', borderRadius: 4, background: 'rgba(71,85,105,0.15)', color: P.textDim, textTransform: 'uppercase', letterSpacing: 0.5, display: 'inline-block', marginBottom: 4 }}>NOT CONFIGURED</div>
                  <div><MaturityBadge level="Not Assessed" /></div>
                </div>
              </div>
              <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textDim }}>
                Configure ownership, PIM, and access review policies in <span onClick={() => nav('/settings')} style={{ color: P.accentStrong, cursor: 'pointer' }}>Settings</span> to enable governance effectiveness scoring.
              </div>
            </>
          )}
        </Card>
      </div>
    </div>
  );
}
