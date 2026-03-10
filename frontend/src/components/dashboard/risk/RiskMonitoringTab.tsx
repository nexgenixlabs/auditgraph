import React, { useState } from 'react';
import { FONT, CISOCard, SectionTitle, DN, ProgressBar, StatBox, pillarNav } from '../ciso-shared';
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

  // Top risk drivers derived from pillars
  const sortedPillars = [...d.pillars].sort((a, b) => b.score - a.score);
  const topDrivers = sortedPillars.filter(p => p.score > 10).slice(0, 5);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* Top Risk Drivers — new section */}
      {topDrivers.length > 0 && (
        <CISOCard>
          <SectionTitle>Top Risk Drivers</SectionTitle>
          <div style={{ display: 'grid', gridTemplateColumns: `repeat(${Math.min(topDrivers.length, 5)}, 1fr)`, gap: 12 }}>
            {topDrivers.map((p, i) => {
              const pColor = getPillarColor(p.score);
              const severity = p.score >= 80 ? 'CRITICAL' : p.score >= 50 ? 'HIGH' : p.score >= 20 ? 'MEDIUM' : 'LOW';
              return (
                <div key={i} style={{
                  padding: '12px 14px', borderRadius: 8,
                  background: COLORS.surfaceAlt, borderLeft: `3px solid ${pColor}`,
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui }}>{p.name}</span>
                    <span style={{
                      fontSize: 8, fontWeight: 700, padding: '1px 6px', borderRadius: 3,
                      background: `${pColor}20`, color: pColor, fontFamily: FONT.mono,
                      textTransform: 'uppercase' as const, letterSpacing: '0.05em',
                    }}>{severity}</span>
                  </div>
                  <DN navigateTo={pillarNav(p.name)}>
                    <span style={{ fontSize: 22, fontWeight: 700, fontFamily: FONT.mono, color: pColor }}>{p.score}</span>
                  </DN>
                  <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 4 }}>
                    {p.detail} ({p.weight}% weight)
                  </div>
                </div>
              );
            })}
          </div>
        </CISOCard>
      )}

      {/* Pillar Breakdown — enhanced with score, contribution weight, identity count */}
      <CISOCard>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <SectionTitle>Risk Pillars</SectionTitle>
          <Tooltip text="Contribution indicates how strongly this pillar affects the AGIRS score.">
            <span style={{ fontSize: 12, color: COLORS.textDim, cursor: 'help', marginBottom: 16 }}>{'\u24D8'}</span>
          </Tooltip>
        </div>
        <div style={{ fontSize: 10, color: COLORS.textSecondary, marginBottom: 12, fontFamily: FONT.ui }}>Score scale: 0 = no risk · 100 = maximum risk</div>
        {/* Column headers */}
        <div style={{
          display: 'grid', gridTemplateColumns: '200px 1fr 70px 80px 120px', alignItems: 'center',
          padding: '0 0 6px 0', borderBottom: `1px solid ${COLORS.borderAccent}`,
        }}>
          <span style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' as const, color: COLORS.textMuted, fontFamily: FONT.ui }}>Pillar</span>
          <span />
          <span style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' as const, color: COLORS.textMuted, fontFamily: FONT.ui, textAlign: 'center' as const }}>Score</span>
          <span style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' as const, color: COLORS.textMuted, fontFamily: FONT.ui, textAlign: 'center' as const }}>Weight</span>
          <span style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' as const, color: COLORS.textMuted, fontFamily: FONT.ui, textAlign: 'right' as const }}>Identities</span>
        </div>
        {d.pillars.map((p, i) => {
          const pZero = p.score === 0;
          const pColor = pZero ? COLORS.textMuted : getPillarColor(p.score);
          return (
          <div key={i}>
            <div onClick={() => setExpandedPillar(expandedPillar === i ? null : i)} style={{
              display: 'grid', gridTemplateColumns: '200px 1fr 70px 80px 120px', alignItems: 'center',
              padding: '10px 0', borderBottom: `1px solid ${COLORS.border}`, cursor: 'pointer',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: pZero ? COLORS.textMuted : COLORS.text, fontFamily: FONT.ui }}>{p.name}</span>
                <Tooltip text={PILLAR_TOOLTIPS[p.name] || ''}>
                  <span style={{ fontSize: 10, color: COLORS.textDim, cursor: 'help' }}>{'\u24D8'}</span>
                </Tooltip>
              </div>
              <ProgressBar value={p.score} color={pColor} height={8} />
              <DN navigateTo={pillarNav(p.name)}>
                <span style={{ fontSize: 16, fontWeight: 700, fontFamily: FONT.mono, color: pColor, display: 'block', textAlign: 'center' as const }}>{pZero ? '\u2014' : p.score}</span>
              </DN>
              <Tooltip text="Contribution indicates how strongly this pillar affects the AGIRS score.">
                <span style={{ fontSize: 12, fontWeight: 600, fontFamily: FONT.mono, color: COLORS.textSecondary, display: 'block', textAlign: 'center' as const }}>{p.weight}%</span>
              </Tooltip>
              <span style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.mono, textAlign: 'right' as const }}>
                <DN navigateTo={pillarNav(p.name)}>{p.identityCount}</DN> contributing
              </span>
            </div>
            {expandedPillar === i && p.subMetrics.length > 0 && (
              <div style={{ background: COLORS.surfaceAlt, padding: '10px 16px', borderBottom: `1px solid ${COLORS.border}` }}>
                {p.subMetrics.map((sm, j) => {
                  const smNav = pillarNav(p.name);
                  return (
                  <div key={j} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '4px 0' }}>
                    <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, width: 120 }}>{sm.name}</span>
                    <div style={{ flex: 1 }}><ProgressBar value={(sm.value / sm.max) * 100} color={COLORS.accent} height={4} /></div>
                    <DN navigateTo={smNav}><span style={{ fontSize: 10, fontFamily: FONT.mono, color: COLORS.text }}>{sm.value}</span></DN>
                    <span style={{ fontSize: 10, fontFamily: FONT.mono, color: COLORS.textDim }}>/{sm.max}</span>
                  </div>
                  );
                })}
              </div>
            )}
          </div>
          );
        })}
      </CISOCard>

      {/* KPI Cards — 5 columns */}
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

      {/* Blast Radius — enhanced with explanation tooltip */}
      <CISOCard>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
          <SectionTitle>Blast Radius Analysis</SectionTitle>
          <Tooltip text="Blast radius measures the potential impact of a compromised identity. It considers the number of resources accessible, privilege level, and scope breadth. High-risk identities can modify access policies, while low-risk identities have read-only or scoped access.">
            <span style={{ fontSize: 12, color: COLORS.textDim, cursor: 'help', marginBottom: 16 }}>{'\u24D8'}</span>
          </Tooltip>
        </div>
        <div style={{ display: 'flex', height: 10, borderRadius: 5, overflow: 'hidden', marginBottom: 16, background: COLORS.border }}>
          <div style={{ width: `${Math.max(3, (d.blastRadius.highRisk / (d.blastRadius.highRisk + d.blastRadius.lowRisk + 1)) * 100)}%`, background: COLORS.danger }} />
          <div style={{ flex: 1, background: COLORS.success }} />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 16 }}>
          <StatBox label="High Risk" value={<DN navigateTo="/identities?risk_level=critical,high">{d.blastRadius.highRisk}</DN>} color={COLORS.danger} />
          <StatBox label="Low Risk" value={<DN navigateTo="/identities?risk_level=low">{d.blastRadius.lowRisk}</DN>} color={COLORS.success} />
          <StatBox label="Orphaned" value={<DN navigateTo="/identities?pillar=ownership-governance">{d.blastRadius.orphaned}</DN>} color={COLORS.warning} />
        </div>
        <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, marginBottom: 10, fontFamily: FONT.ui }}>Category Scores</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
          {d.blastRadius.categories.map((cat, i) => {
            const catNav = cat.name.toLowerCase().includes('human') ? '/identities?identity_category=human_user' :
              cat.name.toLowerCase().includes('service') || cat.name.toLowerCase().includes('workload') ? '/workload-identities' :
              cat.name.toLowerCase().includes('guest') ? '/identities?identity_category=guest' :
              '/identities';
            return (
            <div key={i} style={{ textAlign: 'center' as const }}>
              <div style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 4 }}>{cat.name}</div>
              <ProgressBar value={cat.score * 10} color={cat.color} height={4} />
              <DN navigateTo={catNav}>
                <div style={{ fontSize: 13, fontWeight: 700, fontFamily: FONT.mono, color: cat.color, marginTop: 4 }}>{cat.score}</div>
              </DN>
            </div>
            );
          })}
        </div>
      </CISOCard>
    </div>
  );
}
