import React from 'react';
import {
  TenantData, Nav, Framework,
  F, P, GOV_NAV,
  getTierColor, getTier, getTierBg, formatDelta, getMaturityLevel,
  Card, SectionTitle, NarrativeBanner, ScoreRing, RiskTierBadge,
  SeverityDot, DrillableNumber, SparklineChart, MiniProgressBar,
  CircularGauge, TooltipWrap, TrendArrow, MaturityBadge,
  AutomationBadge, RollbackBadge,
} from './overview-shared';

export function ExecutiveSummaryTab({ d, nav, openDrill, setActiveTab, openComplianceDetail }: { d: TenantData; nav: Nav; openDrill: (title: string, filterUrl: string) => void; setActiveTab: (tab: string) => void; openComplianceDetail: (fw: Framework) => void }) {
  const tier = d.riskScore.tier;
  const color = getTierColor(tier);
  const topFw: Framework[] = [];
  Object.values(d.compliance.frameworks).forEach(arr => arr.forEach(fw => topFw.push(fw)));
  const top6 = topFw.slice(0, 6);

  return (
    <div>
      {/* ROW 0: Narrative Banner */}
      <NarrativeBanner narrative={d.executiveSummary.riskNarrative} exposure={d.executiveSummary.businessExposure} tier={tier} nav={nav} />

      {/* ROW 1: Score + Top Risk Drivers */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        <Card glow>
          <SectionTitle>Identity Attack Surface</SectionTitle>
          <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
            <ScoreRing score={d.riskScore.current} grade={d.riskScore.grade} />
            <div>
              <RiskTierBadge tier={tier} />
              {d.insufficientData && (
                <div style={{ marginTop: 4, padding: '2px 8px', borderRadius: 4, background: 'rgba(255,180,0,0.12)', border: '1px solid rgba(255,180,0,0.25)', display: 'inline-block' }}>
                  <span style={{ fontFamily: F.ui, fontSize: 9, color: '#ffb400', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Insufficient data</span>
                </div>
              )}
              <div style={{ marginTop: 12 }}>
                <div style={{ fontFamily: F.data, fontSize: 10, color: P.textDim, marginBottom: 4 }}>vs 30 days</div>
                {d.riskScore.delta30d != null ? (
                  <span style={{ fontFamily: F.data, fontSize: 13, color: d.riskScore.delta30d >= 0 ? '#22c55e' : '#ff4444' }}>
                    {formatDelta(d.riskScore.delta30d)} pts
                  </span>
                ) : (
                  <span style={{ fontFamily: F.data, fontSize: 13, color: P.textDim }}>No previous scan</span>
                )}
              </div>
              <div style={{ display: 'flex', gap: 16, marginTop: 8, flexWrap: 'wrap' }}>
                {[
                  { l: 'Industry', v: d.riskScore.industryAvg != null ? d.riskScore.industryAvg : 'N/A', url: '/identities' },
                  { l: 'Target', v: d.riskScore.target, url: '/settings' },
                  { l: 'Potential', v: `+${d.riskScore.potentialGain}`, url: '/identities?risk_level=critical' },
                ].map(b => (
                  <div key={b.l}>
                    <div style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint, textTransform: 'uppercase' }}>{b.l}</div>
                    <div style={{ fontFamily: F.data, fontSize: 13, color: P.textSub }}><DrillableNumber value={b.v} label={`${b.l} score`} onClick={() => nav(b.url)} /></div>
                  </div>
                ))}
              </div>
              <div style={{ marginTop: 10 }}>
                <SparklineChart data={d.riskScore.history} width={160} height={30} color={color} />
              </div>
            </div>
          </div>
        </Card>

        <Card>
          <SectionTitle right={<span style={{ fontFamily: F.data, fontSize: 10, color: P.textDim }}>{d.topRiskDrivers.length} drivers</span>}>Top Risk Drivers</SectionTitle>
          {d.topRiskDrivers.slice(0, 5).map((dr, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
              <SeverityDot severity={dr.impact} />
              <span style={{ fontFamily: F.ui, fontSize: 12, color: P.textSub, flex: 1 }}>{dr.label}</span>
              <span style={{ fontFamily: F.data, fontSize: 9, color: P.textDim }}>{dr.pillar}</span>
            </div>
          ))}
        </Card>
      </div>

      {/* ROW 2: Immediate Actions + Compliance */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        <Card>
          <SectionTitle>Immediate Actions</SectionTitle>
          {(() => {
            const identityRemediations = d.remediations.filter(r => r.type === 'identity-remediation' && r.gain > 0);
            if (!identityRemediations.length) return (
              <div style={{ padding: 16, background: P.bgHover, borderRadius: 8, textAlign: 'center' }}>
                <div style={{ fontFamily: F.ui, fontSize: 13, color: P.textMuted, marginBottom: 8 }}>No identity remediation actions available</div>
                <div style={{ fontFamily: F.data, fontSize: 11, color: P.textDim }}>Capture a snapshot to generate recommendations</div>
              </div>
            );
            return identityRemediations.slice(0, 3).map(r => (
              <div key={r.rank} style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12, padding: 10, background: P.bgHover, borderRadius: 8 }}>
                <span style={{ fontFamily: F.data, fontSize: 18, fontWeight: 800, color: P.accentStrong, minWidth: 24 }}>#{r.rank}</span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontFamily: F.ui, fontSize: 13, color: P.textLight, fontWeight: 600 }}>{r.action}</div>
                  <div style={{ display: 'flex', gap: 8, marginTop: 4, flexWrap: 'wrap' }}>
                    <span style={{ fontFamily: F.data, fontSize: 16, color: '#22c55e', fontWeight: 700 }}>+{r.gain}</span>
                    <AutomationBadge level={r.automation} />
                    <RollbackBadge safety={r.rollbackSafety} />
                  </div>
                </div>
              </div>
            ));
          })()}
          <div style={{ marginTop: 8 }}>
            <div style={{ fontFamily: F.data, fontSize: 10, color: P.textDim, marginBottom: 4 }}>Total potential gain: +{d.riskScore.potentialGain} pts</div>
            <MiniProgressBar value={d.riskScore.potentialGain} max={30} color={P.accentStrong} height={6} />
          </div>
        </Card>

        <Card>
          <SectionTitle right={<span style={{ fontFamily: F.data, fontSize: 9, color: P.accentIndigo, background: P.accentIndigoSubtle, padding: '2px 8px', borderRadius: 4 }}>Identity Controls Only</span>}>
            Compliance Gap Snapshot
          </SectionTitle>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 16 }}>
            {top6.map((fw, i) => {
              const fwColor = fw.pct >= 60 ? '#22c55e' : fw.pct >= 30 ? '#eab308' : '#ff4444';
              return (
                <div key={i} onClick={() => openComplianceDetail(fw)}
                  style={{ textAlign: 'center', cursor: 'pointer', padding: 8, borderRadius: 8, transition: 'background 0.15s' }}
                  onMouseEnter={e => (e.currentTarget.style.background = P.accentIndigoFaint)}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  <CircularGauge value={fw.pct} color={fwColor} />
                  <div style={{ fontFamily: F.ui, fontSize: 11, color: P.textSub, marginTop: 4 }}>{fw.name}</div>
                  <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim }}>{fw.passed}/{fw.total}</div>
                  <div style={{ fontFamily: F.data, fontSize: 9, color: '#ff8c00' }}>
                    <span onClick={e => e.stopPropagation()}>
                      <DrillableNumber value={fw.failingIdentities} label={`${fw.name} identity control failures`} onClick={() => {
                        const evIds = fw.controls.filter(c => c.status !== 'pass').flatMap(c => c.evidenceIdentities);
                        if (evIds.length > 0) openDrill(`${fw.name} Failures`, '/identities?risk_level=critical');
                        else setActiveTab('compliance');
                      }} />
                    </span>
                    {' '}identity control failures
                  </div>
                </div>
              );
            })}
          </div>
          <div style={{ display: 'flex', gap: 16 }}>
            <div style={{ flex: 1, cursor: 'pointer' }} onClick={() => setActiveTab('action')}>
              <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim, marginBottom: 4 }}>Remediation</div>
              <MiniProgressBar value={d.compliance.remediationProgress} color={P.accentStrong} height={4} />
              <span style={{ fontFamily: F.data, fontSize: 10, color: P.textMuted }}><DrillableNumber value={`${d.compliance.remediationProgress}%`} label="Remediation progress" onClick={() => setActiveTab('action')} /></span>
            </div>
            <div style={{ flex: 1, cursor: 'pointer' }} onClick={() => setActiveTab('governance')}>
              <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim, marginBottom: 4 }}>SA Governance</div>
              <MiniProgressBar value={d.compliance.saGovernance} color="#eab308" height={4} />
              <span style={{ fontFamily: F.data, fontSize: 10, color: P.textMuted }}><DrillableNumber value={`${d.compliance.saGovernance}%`} label="SA Governance" onClick={() => setActiveTab('governance')} /></span>
            </div>
          </div>
        </Card>
      </div>

      {/* ROW 3: Governance + 30-Day Projection */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Card>
          <SectionTitle>Governance Health</SectionTitle>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
            {d.governance.metrics.map((m, i) => (
              <div key={i} style={{ padding: 10, background: P.bgHover, borderRadius: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ fontSize: 14 }}>{m.icon}</span>
                  <span style={{ fontFamily: F.ui, fontSize: 11, color: P.textMuted }}>{m.label}</span>
                </div>
                {m.configured ? (
                  <>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginTop: 4 }}>
                      <span style={{ fontFamily: F.data, fontSize: 24, fontWeight: 800, color: P.textBright }}><DrillableNumber value={`${m.value}%`} label={`Drill into ${m.label}`} onClick={() => nav(GOV_NAV[m.label] || '/identities')} /></span>
                      <span style={{ fontFamily: F.data, fontSize: 10, color: P.textDim }}>/ <DrillableNumber value={`${m.target}%`} label={`${m.label} target`} onClick={() => nav('/settings')} /></span>
                    </div>
                    <MiniProgressBar value={m.value} max={m.target} color={m.value >= m.target ? '#22c55e' : m.value >= m.target * 0.5 ? '#eab308' : '#ff4444'} height={3} />
                    <div style={{ marginTop: 4 }}><TrendArrow value={m.trend30d} /></div>
                  </>
                ) : (
                  <div style={{ marginTop: 4 }}>
                    <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textDim, fontStyle: 'italic' }}>Not Configured</div>
                    <div style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint, marginTop: 2 }}>Target: {m.target}%</div>
                    <span onClick={() => nav('/settings')} style={{ fontFamily: F.data, fontSize: 10, color: P.accentIndigo, cursor: 'pointer', marginTop: 4, display: 'inline-block' }}>Configure &rarr;</span>
                  </div>
                )}
              </div>
            ))}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', background: P.bgHover, borderRadius: 8, cursor: 'pointer' }} onClick={() => nav('/service-accounts')}>
            {d.governance.effectivenessConfigured ? (
              <>
                <span style={{ fontFamily: F.data, fontSize: 36, fontWeight: 800, color: P.textBright }}><DrillableNumber value={d.governance.effectivenessScore} label="Governance effectiveness" onClick={() => nav('/service-accounts')} /></span>
                <div>
                  <div style={{ fontFamily: F.ui, fontSize: 11, color: P.textMuted }}>Governance Effectiveness</div>
                  <RiskTierBadge tier={getTier(d.governance.effectivenessScore)} />
                  <div style={{ marginTop: 4 }}><MaturityBadge level={d.governance.maturityLevel} /></div>
                </div>
                <TooltipWrap content={d.governance.effectivenessTooltip}>
                  <span style={{ cursor: 'help', fontFamily: F.data, fontSize: 12, color: P.textDim, marginLeft: 'auto' }}>{'\u2139'}</span>
                </TooltipWrap>
              </>
            ) : (
              <>
                <span style={{ fontFamily: F.data, fontSize: 36, fontWeight: 800, color: P.textFaint }}>&mdash;</span>
                <div>
                  <div style={{ fontFamily: F.ui, fontSize: 11, color: P.textMuted }}>Governance Effectiveness</div>
                  <span style={{ display: 'inline-block', padding: '4px 14px', borderRadius: 6, fontFamily: F.data, fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1.5, color: P.textFaint, background: 'rgba(71,85,105,0.15)' }}>Not Configured</span>
                  <div style={{ marginTop: 4 }}><MaturityBadge level="Not Assessed" /></div>
                </div>
              </>
            )}
          </div>
          {!d.governance.effectivenessConfigured && (
            <div style={{ fontFamily: F.ui, fontSize: 11, color: P.textDim, fontStyle: 'italic', marginTop: 8 }}>
              Governance controls not yet configured. Risk score reflects structural identity posture only.
            </div>
          )}
        </Card>

        <Card>
          <SectionTitle>30-Day Projection</SectionTitle>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div style={{ padding: 12, background: 'rgba(255,68,68,0.05)', borderRadius: 8, borderLeft: '3px solid #ff4444' }}>
              <div style={{ fontFamily: F.data, fontSize: 9, color: '#ff4444', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>No Action</div>
              <div style={{ fontFamily: F.data, fontSize: 28, fontWeight: 800, color: P.textBright }}>{d.riskScore.projectedNoAction != null ? d.riskScore.projectedNoAction.toFixed(1) : '\u2014'}</div>
              {d.riskScore.projectedNoAction != null && <RiskTierBadge tier={getTier(d.riskScore.projectedNoAction)} />}
              {d.riskScore.projectedNoAction == null && <div style={{ fontFamily: F.ui, fontSize: 10, color: P.textDim, marginTop: 4 }}>Insufficient trend data</div>}
              <div style={{ marginTop: 12 }}>
                {d.trends.noActionImpact.map((c, i) => (
                  <div key={i} style={{ fontFamily: F.ui, fontSize: 11, color: P.textMuted, marginBottom: 4, paddingLeft: 12, position: 'relative' }}>
                    <span style={{ position: 'absolute', left: 0, color: '#ff4444' }}>&bull;</span>{c}
                  </div>
                ))}
              </div>
              <div style={{ marginTop: 8, fontFamily: F.data, fontSize: 10, color: '#ff8c00' }}>
                Breach Impact: {d.trends.estimatedBreachImpact}
              </div>
            </div>
            <div style={{ padding: 12, background: 'rgba(34,197,94,0.05)', borderRadius: 8, borderLeft: '3px solid #22c55e' }}>
              <div style={{ fontFamily: F.data, fontSize: 9, color: '#22c55e', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>Remediated</div>
              <div style={{ fontFamily: F.data, fontSize: 28, fontWeight: 800, color: P.textBright }}>{d.riskScore.projectedRemediated.toFixed(1)}</div>
              <RiskTierBadge tier={getTier(d.riskScore.projectedRemediated)} />
              <div style={{ marginTop: 12 }}>
                {d.trends.remediatedConsequences.map((c, i) => (
                  <div key={i} style={{ fontFamily: F.ui, fontSize: 11, color: P.textMuted, marginBottom: 4, paddingLeft: 12, position: 'relative' }}>
                    <span style={{ position: 'absolute', left: 0, color: '#22c55e' }}>&bull;</span>{c}
                  </div>
                ))}
              </div>
              <div style={{ marginTop: 8, fontFamily: F.data, fontSize: 10, color: '#22c55e' }}>
                Breach Impact: {d.trends.remediatedBreachImpact}
              </div>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
