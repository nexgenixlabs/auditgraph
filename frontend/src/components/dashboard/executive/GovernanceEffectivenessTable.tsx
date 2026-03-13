import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FONT, CISOCard, SectionTitle, DN } from '../ciso-shared';
import { COLORS, type AGIRSData } from '../../../constants/ciso';
import { getAGIRSColor } from '../../../constants/metrics';

interface GovernanceEffectivenessTableProps {
  gei: AGIRSData['gei'];
  maturity?: { preventive: number; detective: number; compensating: number; missing: number };
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
          borderRadius: 6, fontSize: 10, color: '#e2e8f0', maxWidth: 260, whiteSpace: 'normal',
          zIndex: 100, boxShadow: '0 4px 12px rgba(0,0,0,0.5)', marginBottom: 6, pointerEvents: 'none',
          fontFamily: FONT.ui, lineHeight: 1.4, fontWeight: 400,
        }}>{text}</span>
      )}
    </span>
  );
}

const GEI_TOOLTIPS: Record<string, string> = {
  'Ownership Coverage': 'Percentage of service principals and app registrations with a designated owner. Unowned identities lack accountability for access reviews and credential rotation.',
  'PIM Adoption': 'Percentage of privileged roles using Privileged Identity Management (just-in-time activation). Standing privilege without PIM is a primary attack vector.',
  'Access Reviews': 'Completion rate of periodic access reviews for privileged identities. Regular reviews catch over-provisioned access and orphaned assignments.',
  'Monitoring (P2)': 'Coverage of P2-level workload identity telemetry. Without sign-in monitoring, dormant and compromised identities remain invisible.',
};

export function GovernanceEffectivenessTable({ gei, maturity }: GovernanceEffectivenessTableProps) {
  const navigate = useNavigate();
  const components = gei?.components ?? [];
  const avgScore = components.filter(c => c.configured).reduce((s, c) => s + c.score, 0) / Math.max(1, components.filter(c => c.configured).length);
  const geiLabel = avgScore >= 80 ? 'Strong' : avgScore >= 50 ? 'Developing' : avgScore > 0 ? 'Weak' : 'Not Assessed';
  const geiColor = avgScore >= 80 ? COLORS.success : avgScore >= 50 ? COLORS.warning : avgScore > 0 ? COLORS.danger : COLORS.textDim;

  return (
    <CISOCard>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <SectionTitle>Governance Effectiveness (GEI)</SectionTitle>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 9, fontFamily: FONT.mono, fontWeight: 700, color: geiColor, background: `${geiColor}15`, padding: '2px 8px', borderRadius: 3, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            {geiLabel}
          </span>
          <span style={{ fontSize: 11, fontFamily: FONT.mono, fontWeight: 700, color: geiColor }}>
            {gei?.score != null ? `${gei.score.toFixed(0)}%` : '\u2014'}
          </span>
        </div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {components.length === 0 && (
          <div style={{ padding: '12px 0', fontSize: 11, color: COLORS.textDim, fontFamily: FONT.ui }}>
            No governance data available. Capture a snapshot to populate governance metrics.
          </div>
        )}
        {components.map((c, i) => (
          <div key={i}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>{c.name}</span>
                <Tooltip text={GEI_TOOLTIPS[c.name] || ''}>
                  <span style={{ fontSize: 10, color: COLORS.textDim, cursor: 'help' }}>{'\u24D8'}</span>
                </Tooltip>
              </div>
              {!c.configured ? (
                <span
                  onClick={() => navigate(c.name === 'Access Reviews' ? '/access-reviews' : '/settings')}
                  style={{ fontSize: 9, color: COLORS.accent, fontFamily: FONT.mono, cursor: 'pointer', textDecoration: 'underline', textDecorationStyle: 'dashed' as const }}
                >
                  {c.name === 'Access Reviews' ? 'No access reviews configured' : 'Not configured'}
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

      {/* Control Maturity Heatmap */}
      {maturity && (() => {
        const total = maturity.preventive + maturity.detective + maturity.compensating + maturity.missing;
        const pct = (v: number) => total > 0 ? Math.round((v / total) * 100) : 0;
        const preventivePct = pct(maturity.preventive);
        const detectivePct = pct(maturity.detective);
        const compensatingPct = pct(maturity.compensating);
        const heatColor = (v: number) => v >= 60 ? COLORS.success : v >= 30 ? COLORS.warning : v > 0 ? COLORS.danger : COLORS.textDim;
        const categories = [
          { label: 'Preventive Controls', pct: preventivePct, color: heatColor(preventivePct), tooltip: 'Controls that block threats before they occur: PIM enforcement, conditional access, role scoping, MFA requirements.' },
          { label: 'Detective Controls', pct: detectivePct, color: heatColor(detectivePct), tooltip: 'Controls that identify threats after they occur: sign-in monitoring, anomaly detection, access reviews, audit logging.' },
          { label: 'Compensating Controls', pct: compensatingPct, color: heatColor(compensatingPct), tooltip: 'Controls that mitigate risk when primary controls are absent: ownership attestation, manual reviews, credential rotation policies.' },
        ];

        return (
          <div style={{ marginTop: 16, paddingTop: 14, borderTop: `1px solid ${COLORS.border}` }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
              <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>
                Control Maturity
              </span>
              <Tooltip text="Control maturity reflects the balance between preventive, detective, and compensating security controls.">
                <span style={{ fontSize: 10, color: COLORS.textDim, cursor: 'help' }}>{'\u24D8'}</span>
              </Tooltip>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {categories.map((cat) => (
                <div key={cat.label}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 3 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>{cat.label}</span>
                      <Tooltip text={cat.tooltip}>
                        <span style={{ fontSize: 10, color: COLORS.textDim, cursor: 'help' }}>{'\u24D8'}</span>
                      </Tooltip>
                    </div>
                    <DN navigateTo="/compliance">
                      <span style={{ fontSize: 11, fontWeight: 700, fontFamily: FONT.mono, color: cat.color }}>{cat.pct}%</span>
                    </DN>
                  </div>
                  <div style={{ height: 6, borderRadius: 3, background: COLORS.border, overflow: 'hidden' }}>
                    <div style={{
                      height: '100%', borderRadius: 3, width: `${cat.pct}%`,
                      background: cat.color,
                      transition: 'width 1s ease',
                    }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })()}
    </CISOCard>
  );
}
