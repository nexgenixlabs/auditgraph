import React, { useState } from 'react';
import { FONT, CISOCard, SectionTitle, DN } from '../ciso-shared';
import { COLORS, type AGIRSData } from '../../../constants/ciso';

interface HumanIdentityRiskTableProps {
  hiri: AGIRSData['hiri'];
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
          borderRadius: 6, fontSize: 10, color: '#e2e8f0', maxWidth: 240, whiteSpace: 'normal',
          zIndex: 100, boxShadow: '0 4px 12px rgba(0,0,0,0.5)', marginBottom: 6, pointerEvents: 'none',
          fontFamily: FONT.ui, lineHeight: 1.4, fontWeight: 400,
        }}>{text}</span>
      )}
    </span>
  );
}

export function HumanIdentityRiskTable({ hiri }: HumanIdentityRiskTableProps) {
  const factors = [
    { key: 'h1_ghost', label: 'Ghost Humans', count: hiri?.h1_ghost ?? 0, color: COLORS.danger, nav: '/identities?agirs_factor=h1_ghost&show_deleted=true', tooltip: 'User accounts disabled in Entra ID that still retain active RBAC role assignments. These "ghost" accounts can be exploited if re-enabled or if role assignments are inherited.', filter: 'last_login > 90d, account disabled' },
    { key: 'h2_dormant_priv', label: 'Dormant Privileged', count: hiri?.h2_dormant_priv ?? 0, color: COLORS.elevated, nav: '/identities?activity_status=dormant_strict&privileged=true', tooltip: 'Human users with privileged roles (Owner, Contributor, User Access Administrator) who have not signed in for 90+ days. Standing privilege without active use is a primary attack vector.', filter: 'privileged + inactive 30d+' },
    { key: 'h3_over_priv', label: 'Over-Privileged', count: hiri?.h3_over_priv ?? 0, color: COLORS.warning, nav: '/identities?pillar=effective-privilege', tooltip: 'Identities holding Tier-0 or Tier-1 role assignments (Global Admin, Owner, User Access Admin). Review whether this access level is operationally justified.', filter: 'privilege_tier 0-1' },
    { key: 'h4_ext_guest', label: 'Privileged Guests', count: hiri?.h4_ext_guest ?? 0, color: COLORS.purple, nav: '/identities?agirs_factor=h4_ext_guest', tooltip: 'External guest users (B2B) who hold privileged roles such as Owner or Contributor. Guest access combined with high privilege significantly increases breach exposure.', filter: 'guest + privileged role' },
    { key: 'h5_zombie', label: 'Zombie Personas', count: hiri?.h5_zombie ?? 0, color: COLORS.danger, nav: '/identity-correlation', tooltip: 'Identities that appear across multiple identity providers or tenants with inconsistent lifecycle states. May indicate credential reuse, shadow accounts, or incomplete offboarding.', filter: 'cross-IdP inconsistent state' },
  ];
  return (
    <CISOCard>
      <SectionTitle>Human Identity Risk (HIRI)</SectionTitle>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
        {factors.map((f, i) => (
          <div key={f.key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', borderBottom: i < factors.length - 1 ? `1px solid ${COLORS.border}` : 'none' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2, flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 6, height: 6, borderRadius: 1, background: f.color, flexShrink: 0 }} />
                <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>{f.label}</span>
                <Tooltip text={f.tooltip}>
                  <span style={{ fontSize: 10, color: COLORS.textDim, cursor: 'help' }}>{'\u24D8'}</span>
                </Tooltip>
              </div>
              <div style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.mono, paddingLeft: 14 }}>{f.filter}</div>
            </div>
            <DN navigateTo={f.nav} tooltip="Click to view affected identities.">
              <span style={{ fontSize: 12, fontWeight: 700, fontFamily: FONT.mono, color: f.count > 0 ? f.color : COLORS.textDim }}>{f.count}</span>
            </DN>
          </div>
        ))}
      </div>
    </CISOCard>
  );
}
