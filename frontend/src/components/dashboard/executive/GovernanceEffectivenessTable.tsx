import React from 'react';
import { useNavigate } from 'react-router-dom';
import { FONT, CISOCard, SectionTitle, DN } from '../ciso-shared';
import { COLORS, type AGIRSData } from '../../../constants/ciso';
import { getAGIRSColor } from '../../../constants/metrics';

interface GovernanceEffectivenessTableProps {
  gei: AGIRSData['gei'];
}

export function GovernanceEffectivenessTable({ gei }: GovernanceEffectivenessTableProps) {
  const navigate = useNavigate();
  const defaultComponents = [
    { name: 'Ownership Coverage', score: 0, configured: true },
    { name: 'PIM Adoption', score: 0, configured: true },
    { name: 'Access Reviews', score: 0, configured: false },
    { name: 'Monitoring (P2)', score: 0, configured: true },
  ];
  return (
    <CISOCard>
      <SectionTitle>Governance Effectiveness (GEI)</SectionTitle>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {(gei?.components ?? defaultComponents).map((c, i) => (
          <div key={i}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>{c.name}</span>
              {!c.configured ? (
                <span
                  onClick={() => navigate('/settings')}
                  style={{ fontSize: 9, color: COLORS.accent, fontFamily: FONT.mono, cursor: 'pointer', textDecoration: 'underline', textDecorationStyle: 'dashed' as const }}
                >
                  Not configured
                </span>
              ) : (
                <DN navigateTo="/service-accounts">
                  <span style={{ fontSize: 11, fontWeight: 700, fontFamily: FONT.mono, color: getAGIRSColor(c.score) }}>{c.score.toFixed(0)}%</span>
                </DN>
              )}
            </div>
            <div style={{ height: 4, borderRadius: 2, background: COLORS.border }}>
              <div style={{
                height: '100%', borderRadius: 2, width: `${c.configured ? c.score : 0}%`,
                background: c.configured ? getAGIRSColor(c.score) : COLORS.textDim,
                transition: 'width 1s ease',
              }} />
            </div>
          </div>
        ))}
      </div>
    </CISOCard>
  );
}
