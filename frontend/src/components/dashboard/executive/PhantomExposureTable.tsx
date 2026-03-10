import React, { useState } from 'react';
import { FONT, CISOCard, SectionTitle, DN } from '../ciso-shared';
import { COLORS, type AGIRSData } from '../../../constants/ciso';

interface PhantomExposureTableProps {
  nhiri: AGIRSData['nhiri'];
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

export function PhantomExposureTable({ nhiri }: PhantomExposureTableProps) {
  const pb = nhiri?.phantom_breakdown ?? { orphaned: 0, dormant: 0, zombie_nhi: 0, expired_creds: 0, ownerless_apps: 0 };
  const categories: { key: string; label: string; count: number | null; color: string; nav: string; tooltip: string; filter: string }[] = [
    { key: 'orphaned', label: 'Orphaned (No Owner)', count: pb.orphaned, color: COLORS.danger, nav: '/identities?agirs_factor=n1_orphaned', tooltip: 'Service principals and app registrations with no designated owner. These identities lack accountability and may retain excessive permissions undetected.', filter: 'owner = none, NHI' },
    { key: 'dormant', label: 'Dormant NHIs', count: pb.dormant, color: COLORS.elevated, nav: '/identities?agirs_factor=n2_dormant', tooltip: 'Non-human identities with stale, never-used, or inactive status that still retain active role assignments. These represent latent attack surface.', filter: 'NHI + inactive 30d+' },
    { key: 'zombie_nhi', label: 'Zombie NHIs', count: pb.zombie_nhi, color: COLORS.danger, nav: '/identity-correlation', tooltip: 'Machine identities that appear decommissioned but retain active credentials or role assignments. Often created by departed teams or deprecated automation.', filter: 'decommissioned + active creds' },
    { key: 'expired_creds', label: 'Expired Credentials', count: pb.expired_creds, color: COLORS.warning, nav: '/identities?agirs_factor=n4_expired', tooltip: 'Service principals and app registrations with expired secrets or certificates. May indicate abandoned automation or failed rotation processes.', filter: 'cred_expiry < now' },
    { key: 'ownerless_apps', label: 'Ownerless High-Risk Apps', count: pb.ownerless_apps, color: COLORS.purple, nav: '/app-registrations', tooltip: 'App registrations with dangerous API permissions (e.g. RoleManagement.ReadWrite.All) but no assigned owner. High blast radius with no accountability.', filter: 'owner = none, high-risk perms' },
  ];
  return (
    <CISOCard>
      <SectionTitle>Machine Identity Risk (NHIRI)</SectionTitle>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
        {categories.map((c, i) => (
          <div key={c.key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', borderBottom: i < categories.length - 1 ? `1px solid ${COLORS.border}` : 'none' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2, flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 6, height: 6, borderRadius: 1, background: c.color, flexShrink: 0 }} />
                <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>{c.label}</span>
                <Tooltip text={c.tooltip}>
                  <span style={{ fontSize: 10, color: COLORS.textDim, cursor: 'help' }}>{'\u24D8'}</span>
                </Tooltip>
              </div>
              <div style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.mono, paddingLeft: 14 }}>{c.filter}</div>
            </div>
            <DN navigateTo={c.nav} tooltip="Click to view affected identities.">
              <span style={{ fontSize: 12, fontWeight: 700, fontFamily: FONT.mono, color: (c.count ?? 0) > 0 ? c.color : COLORS.textDim }}>{c.count ?? 0}</span>
            </DN>
          </div>
        ))}
      </div>
    </CISOCard>
  );
}
