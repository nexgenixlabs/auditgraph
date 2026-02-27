import React from 'react';
import { FONT, CISOCard, SectionTitle, DN } from '../ciso-shared';
import { COLORS, type AGIRSData } from '../../../constants/ciso';

interface HumanIdentityRiskTableProps {
  hiri: AGIRSData['hiri'];
}

export function HumanIdentityRiskTable({ hiri }: HumanIdentityRiskTableProps) {
  const factors = [
    { key: 'h1_ghost', label: 'Ghost Humans', count: hiri?.h1_ghost ?? 0, color: COLORS.danger, nav: '/identities?agirs_factor=h1_ghost&show_deleted=true' },
    { key: 'h2_dormant_priv', label: 'Dormant Privileged', count: hiri?.h2_dormant_priv ?? 0, color: COLORS.elevated, nav: '/identities?activity_status=dormant_strict&privileged=true' },
    { key: 'h3_over_priv', label: 'Over-Privileged', count: hiri?.h3_over_priv ?? 0, color: COLORS.warning, nav: '/identities?pillar=effective-privilege' },
    { key: 'h4_ext_guest', label: 'Privileged Guests', count: hiri?.h4_ext_guest ?? 0, color: COLORS.purple, nav: '/identities?agirs_factor=h4_ext_guest' },
    { key: 'h5_zombie', label: 'Zombie Personas', count: hiri?.h5_zombie ?? 0, color: COLORS.danger, nav: '/identity-correlation' },
  ];
  return (
    <CISOCard>
      <SectionTitle>Human Identity Risk (HIRI)</SectionTitle>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
        {factors.map((f, i) => (
          <div key={f.key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '7px 0', borderBottom: i < factors.length - 1 ? `1px solid ${COLORS.border}` : 'none' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 6, height: 6, borderRadius: 1, background: f.color, flexShrink: 0 }} />
              <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>{f.label}</span>
            </div>
            <DN navigateTo={f.nav}>
              <span style={{ fontSize: 12, fontWeight: 700, fontFamily: FONT.mono, color: f.count > 0 ? f.color : COLORS.textDim }}>{f.count}</span>
            </DN>
          </div>
        ))}
      </div>
    </CISOCard>
  );
}
