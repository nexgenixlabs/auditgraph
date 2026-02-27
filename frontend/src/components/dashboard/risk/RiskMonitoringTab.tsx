import React, { useState } from 'react';
import { FONT, CISOCard, SectionTitle, DN, ProgressBar, StatBox, pillarNav } from '../ciso-shared';
import { COLORS, getPillarColor, type TenantData } from '../../../constants/ciso';

interface RiskMonitoringTabProps {
  d: TenantData;
}

export function RiskMonitoringTab({ d }: RiskMonitoringTabProps) {
  const [expandedPillar, setExpandedPillar] = useState<number | null>(null);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* Pillar Breakdown */}
      <CISOCard>
        <SectionTitle>Risk Pillars</SectionTitle>
        <div style={{ fontSize: 10, color: COLORS.textSecondary, marginBottom: 12, fontFamily: FONT.ui }}>Score scale: 0 = no risk · 100 = maximum risk</div>
        {d.pillars.map((p, i) => {
          const pZero = p.score === 0;
          const pColor = pZero ? COLORS.textMuted : getPillarColor(p.score);
          return (
          <div key={i}>
            <div onClick={() => setExpandedPillar(expandedPillar === i ? null : i)} style={{
              display: 'grid', gridTemplateColumns: '200px 1fr 80px 120px', alignItems: 'center',
              padding: '10px 0', borderBottom: `1px solid ${COLORS.border}`, cursor: 'pointer',
            }}>
              <span style={{ fontSize: 12, fontWeight: 600, color: pZero ? COLORS.textMuted : COLORS.text, fontFamily: FONT.ui }}>{p.name}</span>
              <ProgressBar value={p.score} color={pColor} height={8} />
              <DN navigateTo={pillarNav(p.name)}>
                <span style={{ fontSize: 16, fontWeight: 700, fontFamily: FONT.mono, color: pColor, textAlign: 'center' as const }}>{pZero ? '—' : p.score}</span>
              </DN>
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

      {/* KPI Cards — 5 columns per v3.0.1 */}
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

      {/* Blast Radius Full */}
      <CISOCard>
        <SectionTitle>Blast Radius Analysis</SectionTitle>
        <div style={{ display: 'flex', height: 10, borderRadius: 5, overflow: 'hidden', marginBottom: 16, background: COLORS.border }}>
          <div style={{ width: `${Math.max(3, (d.blastRadius.highRisk / (d.blastRadius.highRisk + d.blastRadius.lowRisk + 1)) * 100)}%`, background: COLORS.danger }} />
          <div style={{ flex: 1, background: COLORS.success }} />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 16 }}>
          <StatBox label="Risk" value={<DN navigateTo="/identities?risk_level=critical,high">{d.blastRadius.highRisk}</DN>} color={COLORS.danger} />
          <StatBox label="Low" value={<DN navigateTo="/identities?risk_level=low">{d.blastRadius.lowRisk}</DN>} color={COLORS.success} />
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
