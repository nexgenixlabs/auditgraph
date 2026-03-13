import React, { useState } from 'react';
import { FONT, CISOCard, SectionTitle, DN, ProgressBar, StatBox, Sparkline, pillarNav } from '../ciso-shared';
import { COLORS, getPillarColor, type TenantData } from '../../../constants/ciso';

interface RiskMonitoringTabProps {
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

// ── Severity helpers ─────────────────────────────────────────────
function getSeverityLabel(score: number): string {
  if (score >= 71) return 'Critical';
  if (score >= 41) return 'High';
  if (score >= 21) return 'Moderate';
  return 'Healthy';
}

function getSeverityColor(score: number): string {
  if (score >= 71) return COLORS.danger;
  if (score >= 41) return COLORS.elevated;
  if (score >= 21) return COLORS.warning;
  return COLORS.success;
}

function getPostureLabel(posture: number): string {
  if (posture >= 80) return 'Healthy';
  if (posture >= 60) return 'Moderate';
  if (posture >= 40) return 'Elevated';
  return 'Critical';
}

function getPostureColor(posture: number): string {
  if (posture >= 80) return COLORS.success;
  if (posture >= 60) return COLORS.warning;
  if (posture >= 40) return COLORS.elevated;
  return COLORS.danger;
}

// ── Risk statement generation (from real pillar data) ────────────
const RISK_STATEMENTS: Record<string, { problem: (detail: string, count: number) => string; impact: string }> = {
  'Effective Privilege': {
    problem: (_d, count) => `${count} identities hold Tier-0/Tier-1 roles (Global Admin, Owner, User Access Admin) as standing access`,
    impact: 'A single compromised privileged identity can escalate access tenant-wide, modify security policies, or exfiltrate data across all subscriptions.',
  },
  'Credential Risk': {
    problem: (d) => `${d} require rotation or have expired`,
    impact: 'Expired or stale credentials increase the window for credential stuffing and secret theft attacks.',
  },
  'Trust & Federation': {
    problem: (d) => `${d} have elevated permissions in your tenant`,
    impact: 'External identities with privileged roles bypass organizational controls and create cross-tenant attack chains.',
  },
  'Usage Dormancy': {
    problem: (d) => `${d} still retain active role assignments`,
    impact: 'Dormant accounts with live access are the #1 vector for lateral movement in identity-based attacks.',
  },
  'Ownership Governance': {
    problem: (d) => `${d} lack a designated owner`,
    impact: 'Unowned identities skip access reviews and have no accountability, creating compliance gaps in SOC2 and NIST.',
  },
  'External Exposure': {
    problem: (d) => `${d} across your environment`,
    impact: 'Broad scope amplifies blast radius \u2014 a compromised identity with tenant-wide access can reach every resource.',
  },
};

const PILLAR_TOOLTIPS: Record<string, string> = {
  'Effective Privilege': 'Measures the density and blast radius of Tier-0 and Tier-1 role assignments (Global Admin, Owner, User Access Admin). Higher scores indicate excessive standing privilege that should be reduced via PIM or role scoping.',
  'Credential Risk': 'Tracks expired secrets, soon-to-expire certificates, and rotation compliance across service principals and app registrations. Failed rotation increases credential theft risk.',
  'Trust & Federation': 'Evaluates external guest identities with privileged roles, cross-tenant federation configurations, and B2B trust chains. External access combined with high privilege multiplies attack surface.',
  'Usage Dormancy': 'Identifies identities inactive for 30+ days that still retain active role assignments. Dormant accounts with live access are frequently exploited in lateral movement attacks.',
  'Ownership Governance': 'Measures orphaned service principal coverage, attestation freshness, and ownership assignment completeness. Unowned identities lack accountability for access reviews.',
  'External Exposure': 'Detects identities with tenant-wide scope, multi-subscription access at Contributor+, and publicly exposed service principals. Broad scope amplifies blast radius.',
};

export function RiskMonitoringTab({ d }: RiskMonitoringTabProps) {
  const [expandedPillar, setExpandedPillar] = useState<number | null>(null);

  const sortedPillars = [...d.pillars].sort((a, b) => b.score - a.score);
  const topDrivers = sortedPillars.filter(p => p.score > 10).slice(0, 4);
  const topRem = d.remediations.slice(0, 3);

  // Trend awareness
  const posture = d.riskScore.current;
  const delta = d.riskScore.delta;
  const hasDelta = delta != null && delta !== 0;
  const improving = hasDelta && (delta ?? 0) > 0;
  const postureLabel = getPostureLabel(posture);
  const postureColor = getPostureColor(posture);

  // Build executive summary narrative from real data
  const worstPillar = sortedPillars[0];
  const criticalPillars = sortedPillars.filter(p => p.score >= 71);
  const highPillars = sortedPillars.filter(p => p.score >= 41 && p.score < 71);
  const totalAffected = sortedPillars.filter(p => p.score > 10).reduce((s, p) => s + p.identityCount, 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>

      {/* ═══ 1. Executive Risk Summary ═══ */}
      <CISOCard style={{ borderLeft: `3px solid ${postureColor}` }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 24 }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
              <SectionTitle>Executive Risk Summary</SectionTitle>
              <span style={{
                fontSize: 9, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                background: `${postureColor}20`, color: postureColor, fontFamily: FONT.mono,
                textTransform: 'uppercase' as const, letterSpacing: '0.06em',
              }}>{postureLabel}</span>
            </div>
            <p style={{ fontSize: 13, color: COLORS.text, fontFamily: FONT.ui, lineHeight: 1.6, margin: 0 }}>
              {posture >= 80 ? (
                <>Your identity security posture is <strong style={{ color: COLORS.success }}>healthy</strong>. No critical risk pillars detected across <DN navigateTo="/identities"><strong>{d.tenant.identityCount}</strong></DN> monitored identities.</>
              ) : posture >= 60 ? (
                <>Your identity posture shows <strong style={{ color: COLORS.warning }}>moderate risk</strong>. {!!worstPillar && worstPillar.score > 0 && <><strong>{worstPillar.name}</strong> is your highest concern with <DN navigateTo={pillarNav(worstPillar.name)}><strong>{worstPillar.identityCount} affected identities</strong></DN>. </>}{totalAffected > 0 && <>{totalAffected} identities across {sortedPillars.filter(p => p.score > 10).length} risk pillars require attention.</>}</>
              ) : (
                <>Your identity posture is at <strong style={{ color: COLORS.danger }}>{postureLabel.toLowerCase()} risk</strong>. {criticalPillars.length > 0 && <><strong style={{ color: COLORS.danger }}>{criticalPillars.length} critical</strong>{highPillars.length > 0 && <> and <strong style={{ color: COLORS.elevated }}>{highPillars.length} high</strong></>} risk {criticalPillars.length + highPillars.length === 1 ? 'pillar requires' : 'pillars require'} immediate action. </>}{!!worstPillar && worstPillar.score > 0 && <><strong>{worstPillar.name}</strong> is the top threat with <DN navigateTo={pillarNav(worstPillar.name)}><strong>{worstPillar.identityCount} affected identities</strong></DN>. </>}{totalAffected > 0 && <>{totalAffected} identities contribute to elevated risk.</>}</>
              )}
            </p>

            {/* Trend indicator */}
            {hasDelta && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 10 }}>
                <span style={{
                  fontSize: 14, color: improving ? COLORS.success : COLORS.danger,
                }}>{improving ? '\u25B2' : '\u25BC'}</span>
                <span style={{ fontSize: 11, color: improving ? COLORS.success : COLORS.danger, fontFamily: FONT.mono, fontWeight: 600 }}>
                  {improving ? '+' : ''}{delta?.toFixed(1)} pts
                </span>
                <span style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
                  vs previous scan ({d.riskScore.previous.toFixed(1)})
                </span>
              </div>
            )}
          </div>

          {/* Sparkline + score */}
          <div style={{ textAlign: 'center' as const, minWidth: 120 }}>
            <div style={{ fontSize: 36, fontWeight: 700, fontFamily: FONT.mono, color: postureColor }}>{posture.toFixed(1)}</div>
            <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 6 }}>Posture Score</div>
            {d.riskScore.trend.length > 2 && (
              <Sparkline data={d.riskScore.trend} width={100} height={24} color={postureColor} />
            )}
          </div>
        </div>
      </CISOCard>

      {/* ═══ 2. Risk Statement Cards ═══ */}
      {topDrivers.length > 0 && (
        <CISOCard>
          <SectionTitle>Top Risk Drivers</SectionTitle>
          <div style={{ display: 'grid', gridTemplateColumns: `repeat(${Math.min(topDrivers.length, 2)}, 1fr)`, gap: 14 }}>
            {topDrivers.map((p, i) => {
              const sevLabel = getSeverityLabel(p.score);
              const sevColor = getSeverityColor(p.score);
              const stmt = RISK_STATEMENTS[p.name];
              return (
                <div key={i} style={{
                  padding: '14px 16px', borderRadius: 10,
                  background: COLORS.surfaceAlt, borderLeft: `3px solid ${sevColor}`,
                }}>
                  {/* Header: pillar name + severity badge */}
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                    <span style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui }}>{p.name}</span>
                    <span style={{
                      fontSize: 9, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                      background: `${sevColor}20`, color: sevColor, fontFamily: FONT.mono,
                      textTransform: 'uppercase' as const, letterSpacing: '0.06em',
                    }}>{sevLabel}</span>
                  </div>
                  {/* Problem statement */}
                  <p style={{ fontSize: 12, color: COLORS.text, fontFamily: FONT.ui, lineHeight: 1.5, margin: '0 0 8px 0' }}>
                    {stmt ? stmt.problem(p.detail, p.identityCount) : p.detail}
                  </p>
                  {/* Affected count */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                    <DN navigateTo={pillarNav(p.name)}>
                      <span style={{ fontSize: 20, fontWeight: 700, fontFamily: FONT.mono, color: sevColor }}>{p.identityCount}</span>
                    </DN>
                    <span style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui }}>identities affected</span>
                    <span style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.mono, marginLeft: 'auto' }}>{p.weight}% weight</span>
                  </div>
                  {/* Why it matters */}
                  {stmt && (
                    <div style={{
                      fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, lineHeight: 1.5,
                      padding: '8px 10px', background: `${sevColor}08`, borderRadius: 6, borderLeft: `2px solid ${sevColor}30`,
                    }}>
                      {stmt.impact}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </CISOCard>
      )}

      {/* ═══ 3. Risk Pillars ═══ */}
      <CISOCard>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <SectionTitle>Risk Pillars</SectionTitle>
          <Tooltip text="Each pillar contributes to the overall AGIRS score. Severity reflects risk level: Healthy (0-20), Moderate (21-40), High (41-70), Critical (71-100).">
            <span style={{ fontSize: 12, color: COLORS.textDim, cursor: 'help', marginBottom: 16 }}>{'\u24D8'}</span>
          </Tooltip>
        </div>
        {/* Column headers */}
        <div style={{
          display: 'grid', gridTemplateColumns: '180px 80px 1fr 60px 80px 110px', alignItems: 'center',
          padding: '0 0 6px 0', borderBottom: `1px solid ${COLORS.borderAccent}`,
        }}>
          <span style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' as const, color: COLORS.textMuted, fontFamily: FONT.ui }}>Pillar</span>
          <span style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' as const, color: COLORS.textMuted, fontFamily: FONT.ui, textAlign: 'center' as const }}>Severity</span>
          <span />
          <span style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' as const, color: COLORS.textMuted, fontFamily: FONT.ui, textAlign: 'center' as const }}>Score</span>
          <span style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' as const, color: COLORS.textMuted, fontFamily: FONT.ui, textAlign: 'center' as const }}>Weight</span>
          <span style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' as const, color: COLORS.textMuted, fontFamily: FONT.ui, textAlign: 'right' as const }}>Affected</span>
        </div>
        {d.pillars.map((p, i) => {
          const pZero = p.score === 0;
          const pColor = pZero ? COLORS.textMuted : getPillarColor(p.score);
          const sevLabel = pZero ? '\u2014' : getSeverityLabel(p.score);
          const sevColor = pZero ? COLORS.textMuted : getSeverityColor(p.score);
          return (
          <div key={i}>
            <div onClick={() => setExpandedPillar(expandedPillar === i ? null : i)} style={{
              display: 'grid', gridTemplateColumns: '180px 80px 1fr 60px 80px 110px', alignItems: 'center',
              padding: '10px 0', borderBottom: `1px solid ${COLORS.border}`, cursor: 'pointer',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: pZero ? COLORS.textMuted : COLORS.text, fontFamily: FONT.ui }}>{p.name}</span>
                <Tooltip text={PILLAR_TOOLTIPS[p.name] || ''}>
                  <span style={{ fontSize: 10, color: COLORS.textDim, cursor: 'help' }}>{'\u24D8'}</span>
                </Tooltip>
              </div>
              {/* Severity badge */}
              <div style={{ textAlign: 'center' as const }}>
                {!pZero && (
                  <span style={{
                    fontSize: 8, fontWeight: 700, padding: '2px 6px', borderRadius: 3,
                    background: `${sevColor}20`, color: sevColor, fontFamily: FONT.mono,
                    textTransform: 'uppercase' as const, letterSpacing: '0.05em',
                  }}>{sevLabel}</span>
                )}
              </div>
              {/* Severity-colored progress bar */}
              <ProgressBar value={p.score} color={pColor} height={8} />
              {/* Score */}
              <DN navigateTo={pillarNav(p.name)}>
                <span style={{ fontSize: 16, fontWeight: 700, fontFamily: FONT.mono, color: pColor, display: 'block', textAlign: 'center' as const }}>{pZero ? '\u2014' : p.score}</span>
              </DN>
              {/* Weight */}
              <span style={{ fontSize: 12, fontWeight: 600, fontFamily: FONT.mono, color: COLORS.textSecondary, display: 'block', textAlign: 'center' as const }}>{p.weight}%</span>
              {/* Affected count */}
              <span style={{ fontSize: 11, color: pZero ? COLORS.textMuted : COLORS.textSecondary, fontFamily: FONT.mono, textAlign: 'right' as const }}>
                {pZero ? '\u2014' : <><DN navigateTo={pillarNav(p.name)}>{p.identityCount}</DN> identities</>}
              </span>
            </div>
            {expandedPillar === i && p.subMetrics.length > 0 && (
              <div style={{ background: COLORS.surfaceAlt, padding: '10px 16px', borderBottom: `1px solid ${COLORS.border}` }}>
                {p.subMetrics.map((sm, j) => {
                  const smNav = pillarNav(p.name);
                  return (
                  <div key={j} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '4px 0' }}>
                    <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, width: 140 }}>{sm.name}</span>
                    <div style={{ flex: 1 }}><ProgressBar value={(sm.value / sm.max) * 100} color={COLORS.accent} height={4} /></div>
                    <DN navigateTo={smNav}><span style={{ fontSize: 10, fontFamily: FONT.mono, color: COLORS.text }}>{sm.value}</span></DN>
                    <span style={{ fontSize: 10, fontFamily: FONT.mono, color: COLORS.textDim }}>/ {sm.max}</span>
                  </div>
                  );
                })}
              </div>
            )}
          </div>
          );
        })}
      </CISOCard>

      {/* ═══ 4. KPI Cards ═══ */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 14 }}>
        {Object.entries(d.kpis).map(([key, kpi]) => {
          const isGhost = key === 'ghostAccounts';
          const isZeroValue = kpi.value === 0;
          const valueColor = isZeroValue ? COLORS.textMuted : (isGhost && kpi.value > 0 ? COLORS.danger : COLORS.text);
          const navTo = key === 'privilegedRoles' ? '/identities?pillar=effective-privilege' :
            key === 'dormantPrivileged' ? '/identities?activity_status=dormant_strict&privileged=true' :
            key === 'ghostAccounts' ? '/identities?status=disabled&hasRoles=true' :
            key === 'subscriptionAccess' ? '/identities?privileged=true' :
            key === 'rbacModifiers' ? '/identities?privileged=true' :
            '/identities';
          return (
            <CISOCard key={key} style={isGhost && kpi.value > 0 ? { borderColor: `${COLORS.danger}40` } : undefined}>
              <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>
                {key.replace(/([A-Z])/g, ' $1').trim()}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
                <DN navigateTo={navTo}>
                  <span style={{ fontSize: 32, fontWeight: 700, fontFamily: FONT.mono, color: valueColor }}>{kpi.value}</span>
                </DN>
                {isGhost && kpi.value > 0 && (
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: COLORS.danger }} />
                )}
              </div>
              <div style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 2 }}>{kpi.subtitle}</div>
            </CISOCard>
          );
        })}
      </div>

      {/* ═══ 5. Blast Radius Analysis ═══ */}
      <CISOCard>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
          <SectionTitle>Blast Radius Analysis</SectionTitle>
          <Tooltip text="Blast radius measures the potential impact of a compromised identity. High-risk identities can modify access policies and reach resources across multiple subscriptions. Low-risk identities have read-only or tightly scoped access.">
            <span style={{ fontSize: 12, color: COLORS.textDim, cursor: 'help', marginBottom: 16 }}>{'\u24D8'}</span>
          </Tooltip>
        </div>

        {/* Segmented bar with labels */}
        <div style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: 10, color: COLORS.danger, fontFamily: FONT.ui, fontWeight: 600 }}>
              High Blast Radius ({d.blastRadius.highRisk})
            </span>
            <span style={{ fontSize: 10, color: COLORS.success, fontFamily: FONT.ui, fontWeight: 600 }}>
              Contained ({d.blastRadius.lowRisk})
            </span>
          </div>
          <div style={{ display: 'flex', height: 12, borderRadius: 6, overflow: 'hidden', background: COLORS.border }}>
            <div style={{ width: `${Math.max(3, (d.blastRadius.highRisk / (d.blastRadius.highRisk + d.blastRadius.lowRisk + 1)) * 100)}%`, background: COLORS.danger, transition: 'width 1s ease' }} />
            <div style={{ flex: 1, background: COLORS.success }} />
          </div>
        </div>

        {/* Stats row */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 16 }}>
          <StatBox label="High Risk" value={<DN navigateTo="/identities?risk_level=critical,high">{d.blastRadius.highRisk}</DN>} color={COLORS.danger} sub="Can modify policies" />
          <StatBox label="Low Risk" value={<DN navigateTo="/identities?risk_level=low">{d.blastRadius.lowRisk}</DN>} color={COLORS.success} sub="Read-only / scoped" />
          <StatBox label="Orphaned" value={<DN navigateTo="/identities?pillar=ownership-governance">{d.blastRadius.orphaned}</DN>} color={COLORS.warning} sub="No owner assigned" />
          <StatBox label="Subscriptions" value={<DN navigateTo="/identities?privileged=true">{d.tenant.subscriptions}</DN>} color={COLORS.accent} sub="In scope" />
        </div>

        {/* Category risk scores */}
        <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, marginBottom: 10, fontFamily: FONT.ui }}>Exposure by Category</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
          {d.blastRadius.categories.map((cat, i) => {
            const catSev = getSeverityLabel(cat.score * 10);
            const catNav = cat.name.toLowerCase().includes('human') ? '/identities?identity_category=human_user' :
              cat.name.toLowerCase().includes('service') || cat.name.toLowerCase().includes('workload') ? '/workload-identities' :
              cat.name.toLowerCase().includes('guest') ? '/identities?identity_category=guest' :
              '/identities';
            return (
            <div key={i} style={{ textAlign: 'center' as const }}>
              <div style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 4 }}>{cat.name}</div>
              <ProgressBar value={cat.score * 10} color={cat.color} height={5} />
              <DN navigateTo={catNav}>
                <div style={{ fontSize: 14, fontWeight: 700, fontFamily: FONT.mono, color: cat.color, marginTop: 4 }}>{cat.score}</div>
              </DN>
              <div style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui, marginTop: 2 }}>{catSev}</div>
            </div>
            );
          })}
        </div>
      </CISOCard>

      {/* ═══ 6. Top Remediation Actions ═══ */}
      {topRem.length > 0 && (
        <CISOCard>
          <SectionTitle>Top Remediation Actions</SectionTitle>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {topRem.map((rem, i) => {
              const remColor = rem.color === 'danger' ? COLORS.danger : rem.color === 'warning' ? COLORS.warning : rem.color === 'elevated' ? COLORS.elevated : COLORS.accent;
              return (
                <div key={rem.id} style={{
                  display: 'flex', alignItems: 'flex-start', gap: 14, padding: '14px 16px',
                  background: COLORS.surfaceAlt, borderRadius: 10, borderLeft: `3px solid ${remColor}`,
                }}>
                  {/* Priority number */}
                  <div style={{
                    width: 28, height: 28, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                    background: `${remColor}20`, color: remColor, fontSize: 13, fontWeight: 700, fontFamily: FONT.mono, flexShrink: 0,
                  }}>{i + 1}</div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui, marginBottom: 4 }}>{rem.title}</div>
                    <div style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, lineHeight: 1.4 }}>{rem.subtitle}</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 8 }}>
                      <span style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.ui }}>
                        Risk: <span style={{ color: remColor, fontWeight: 600 }}>{rem.risk}</span>
                      </span>
                      <span style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.ui }}>
                        Affected: <span style={{ color: COLORS.text, fontWeight: 600 }}>{rem.affected}</span>
                      </span>
                      <span style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.ui }}>
                        Mode: <span style={{ fontWeight: 600, color: rem.automation === 'Auto' ? COLORS.success : COLORS.textSecondary }}>{rem.automation}</span>
                      </span>
                    </div>
                  </div>
                  {/* Score gain */}
                  <div style={{ textAlign: 'center' as const, minWidth: 70, flexShrink: 0 }}>
                    <div style={{ fontSize: 18, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.success }}>+{rem.gain}</div>
                    <div style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.ui }}>pts gain</div>
                    <div style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.mono, marginTop: 2 }}>{'\u2192'} {rem.projectedScore}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </CISOCard>
      )}
    </div>
  );
}
