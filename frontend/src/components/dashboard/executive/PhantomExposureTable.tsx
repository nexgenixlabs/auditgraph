import React from 'react';
import { FONT, CISOCard, SectionTitle, DN } from '../ciso-shared';
import { COLORS, type AGIRSData } from '../../../constants/ciso';

interface PhantomExposureTableProps {
  nhiri: AGIRSData['nhiri'];
}

export function PhantomExposureTable({ nhiri }: PhantomExposureTableProps) {
  const pb = nhiri?.phantom_breakdown ?? { orphaned: 0, dormant: 0, zombie_nhi: 0, expired_creds: 0, ownerless_apps: 0 };
  const categories: { key: string; label: string; count: number | null; color: string; nav: string; tooltip?: string }[] = [
    { key: 'orphaned', label: 'Orphaned (No Owner)', count: pb.orphaned, color: COLORS.danger, nav: '/identities?agirs_factor=n1_orphaned' },
    { key: 'dormant', label: 'Dormant NHIs', count: pb.dormant, color: COLORS.elevated, nav: '/identities?agirs_factor=n2_dormant', tooltip: 'NHIs with stale/never_used/inactive status + role assignments' },
    { key: 'zombie_nhi', label: 'Zombie NHIs', count: pb.zombie_nhi, color: COLORS.danger, nav: '/identity-correlation', tooltip: 'Zombie NHI detection' },
    { key: 'expired_creds', label: 'Expired Credentials', count: pb.expired_creds, color: COLORS.warning, nav: '/identities?agirs_factor=n4_expired' },
    { key: 'ownerless_apps', label: 'Ownerless High-Risk Apps', count: pb.ownerless_apps, color: COLORS.purple, nav: '/app-registrations' },
  ];
  return (
    <CISOCard>
      <SectionTitle>Phantom Identity Exposure (NHIRI)</SectionTitle>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
        {categories.map((c, i) => (
          <div key={c.key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '7px 0', borderBottom: i < categories.length - 1 ? `1px solid ${COLORS.border}` : 'none' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 6, height: 6, borderRadius: 1, background: c.color, flexShrink: 0 }} />
              <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>{c.label}</span>
            </div>
            <DN navigateTo={c.nav} tooltip={c.tooltip}>
              <span style={{ fontSize: 12, fontWeight: 700, fontFamily: FONT.mono, color: (c.count ?? 0) > 0 ? c.color : COLORS.textDim }}>{c.count ?? 0}</span>
            </DN>
          </div>
        ))}
      </div>
    </CISOCard>
  );
}
