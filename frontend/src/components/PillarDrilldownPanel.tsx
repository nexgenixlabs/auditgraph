import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

// ─── Design Tokens (matches Overview.tsx) ─────────────────────────
const C = {
  bg:           '#060a13',
  surface:      '#0c1220',
  card:         '#0f1729',
  border:       '#1a2744',
  borderHover:  '#253a5e',
  accent:       '#FFB938',
  accentGlow:   'rgba(255,185,56,0.08)',
  accentBorder: 'rgba(255,185,56,0.18)',
  critical:     '#FF4D4D',
  high:         '#FF8C42',
  warning:      '#FFB938',
  good:         '#36D986',
  info:         '#4E9FFF',
  purple:       '#A78BFA',
  text:         '#F1F5F9',
  textSec:      '#94A3B8',
  textTer:      '#64748B',
  textDim:      '#475569',
};
const F = {
  body:    "'Inter', 'Outfit', sans-serif",
  mono:    "'JetBrains Mono', 'Fira Code', monospace",
};

const PILLAR_META: Record<string, { label: string; color: string }> = {
  effective_privilege:    { label: 'Effective Privilege',  color: C.critical },
  credential_risk:       { label: 'Credential Risk',      color: C.high },
  trust_federation:      { label: 'Trust & Federation',   color: C.purple },
  usage_dormancy:        { label: 'Usage Dormancy',       color: C.info },
  ownership_governance:  { label: 'Ownership Governance', color: C.warning },
  external_exposure:     { label: 'External Exposure',    color: '#E879F9' },
};

const PILLAR_NAV: Record<string, string> = {
  effective_privilege:   '/workload-identities?escalate=true',
  credential_risk:       '/workload-identities?exposure=critical',
  trust_federation:      '/identities?identity_category=guest',
  usage_dormancy:        '/workload-identities?lifecycle=likely_dormant',
  ownership_governance:  '/workload-identities?owner=orphaned',
  external_exposure:     '/workload-identities?scope=tenant',
};

interface PillarData {
  score: number;
  weight: number;
  detail: Record<string, number>;
}

interface Props {
  open: boolean;
  onClose: () => void;
  pillarKey: string;
  pillarData?: PillarData;
  attackData?: any;
}

function scoreColor(s: number) { return s <= 30 ? C.good : s <= 60 ? C.warning : C.critical; }

export default function PillarDrilldownPanel({ open, onClose, pillarKey, pillarData, attackData }: Props) {
  const navigate = useNavigate();

  // Escape key closes
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, onClose]);

  if (!open || !pillarKey) return null;

  const meta = PILLAR_META[pillarKey] || { label: pillarKey, color: C.textSec };
  const score = pillarData?.score ?? 0;
  const color = meta.color;
  const sColor = scoreColor(score);
  const navTarget = PILLAR_NAV[pillarKey] || '/workload-identities';

  // Top riskiest identities from attack surface data
  const topRiskiest = attackData?.attack_opportunities?.top_riskiest?.slice(0, 5) || [];

  // Detail metrics
  const details = pillarData?.detail || {};

  return (
    <>
      {/* Backdrop */}
      <div style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.35)', zIndex: 40,
      }} onClick={onClose} />

      {/* Panel */}
      <div style={{
        position: 'fixed', right: 0, top: 0, height: '100%', width: 420,
        background: C.bg, borderLeft: `1px solid ${C.border}`, zIndex: 50,
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
        boxShadow: '-8px 0 40px rgba(0,0,0,0.5)',
        animation: 'pillarSlideIn 0.25s ease',
      }}>
        <style>{`@keyframes pillarSlideIn { from { transform: translateX(100%); } to { transform: translateX(0); } }`}</style>

        {/* Header */}
        <div style={{
          padding: '20px 24px', borderBottom: `1px solid ${C.border}`,
          background: `linear-gradient(135deg, ${C.card} 0%, ${C.bg} 100%)`,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{
                width: 8, height: 8, borderRadius: '50%', background: color,
                boxShadow: `0 0 10px ${color}60`,
              }} />
              <span style={{ fontSize: 14, fontWeight: 700, color: C.text, fontFamily: F.body }}>
                {meta.label}
              </span>
            </div>
            <button onClick={onClose} style={{
              background: 'none', border: 'none', color: C.textTer, cursor: 'pointer',
              fontSize: 18, lineHeight: 1, padding: 4,
            }} title="Close">&times;</button>
          </div>

          {/* Score bar */}
          <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{
              fontSize: 36, fontWeight: 900, fontFamily: F.mono, color: sColor,
              textShadow: `0 0 16px ${sColor}30`,
            }}>{score}</div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 10, fontFamily: F.mono, color: C.textTer, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>
                Risk Score &middot; Weight {pillarData?.weight ?? 0}%
              </div>
              <div style={{ height: 6, background: C.border, borderRadius: 3 }}>
                <div style={{
                  width: `${Math.min(score, 100)}%`, height: '100%', borderRadius: 3,
                  background: sColor, boxShadow: `0 0 8px ${sColor}40`,
                  transition: 'width 0.8s ease',
                }} />
              </div>
            </div>
          </div>
        </div>

        {/* Content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>

          {/* Key Metrics */}
          {Object.keys(details).length > 0 && (
            <div style={{ marginBottom: 24 }}>
              <div style={{
                fontSize: 10, fontFamily: F.mono, color: C.textTer, textTransform: 'uppercase',
                letterSpacing: 1.5, marginBottom: 10, fontWeight: 700,
              }}>Risk Drivers</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                {Object.entries(details).map(([k, v]) => (
                  <div key={k} style={{
                    padding: '10px 12px', borderRadius: 8,
                    background: C.card, border: `1px solid ${C.border}`,
                  }}>
                    <div style={{ fontSize: 18, fontWeight: 800, fontFamily: F.mono, color: Number(v) > 0 ? color : C.textDim }}>
                      {v}
                    </div>
                    <div style={{ fontSize: 10, fontFamily: F.mono, color: C.textTer, marginTop: 2, textTransform: 'capitalize' }}>
                      {k.replace(/_/g, ' ')}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Top Riskiest Identities */}
          {topRiskiest.length > 0 && (
            <div style={{ marginBottom: 24 }}>
              <div style={{
                fontSize: 10, fontFamily: F.mono, color: C.textTer, textTransform: 'uppercase',
                letterSpacing: 1.5, marginBottom: 10, fontWeight: 700,
              }}>Top Riskiest Identities</div>
              {topRiskiest.map((id: any, i: number) => {
                const rColor = id.risk_level === 'critical' ? C.critical
                  : id.risk_level === 'high' ? C.high
                  : id.risk_level === 'medium' ? C.warning : C.good;
                return (
                  <div key={id.id || i} style={{
                    display: 'flex', alignItems: 'center', gap: 10, padding: '8px 10px',
                    borderRadius: 8, marginBottom: 4, cursor: 'pointer',
                    transition: 'background 0.2s',
                  }}
                  onClick={() => navigate(`/identities/${id.id}`)}
                  title={`View ${id.display_name}`}
                  onMouseEnter={e => { (e.currentTarget as any).style.background = C.surface; }}
                  onMouseLeave={e => { (e.currentTarget as any).style.background = 'transparent'; }}>
                    <span style={{
                      width: 22, height: 22, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                      background: `${rColor}15`, border: `1px solid ${rColor}30`,
                      fontSize: 10, fontFamily: F.mono, fontWeight: 700, color: rColor,
                    }}>{i + 1}</span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{
                        fontSize: 12, fontFamily: F.body, color: C.text, fontWeight: 500,
                        whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                      }}>{id.display_name}</div>
                      <div style={{ fontSize: 10, fontFamily: F.mono, color: C.textTer }}>
                        {id.identity_category?.replace(/_/g, ' ')}
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{
                        fontSize: 14, fontFamily: F.mono, fontWeight: 800, color: rColor,
                      }}>{id.risk_score}</span>
                      <span style={{
                        fontSize: 8, fontFamily: F.mono, fontWeight: 700, textTransform: 'uppercase',
                        padding: '1px 5px', borderRadius: 3, color: rColor,
                        background: `${rColor}15`, border: `1px solid ${rColor}30`,
                      }}>{id.risk_level}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Empty state */}
          {topRiskiest.length === 0 && Object.keys(details).length === 0 && (
            <div style={{ textAlign: 'center', padding: '40px 20px', color: C.textTer, fontSize: 12, fontFamily: F.body }}>
              No detail data available. Run a discovery scan to populate pillar metrics.
            </div>
          )}
        </div>

        {/* Footer */}
        <div style={{
          padding: '16px 24px', borderTop: `1px solid ${C.border}`,
          background: C.card,
        }}>
          <button onClick={() => { navigate(navTarget); onClose(); }} style={{
            width: '100%', padding: '10px 16px', borderRadius: 8,
            border: `1px solid ${C.accentBorder}`, background: C.accentGlow,
            color: C.accent, fontSize: 12, fontFamily: F.mono, fontWeight: 700,
            cursor: 'pointer', transition: 'all 0.2s', textAlign: 'center',
          }}
          onMouseEnter={e => { (e.currentTarget as any).style.background = `${C.accent}18`; }}
          onMouseLeave={e => { (e.currentTarget as any).style.background = C.accentGlow; }}>
            View All {meta.label} →
          </button>
        </div>
      </div>
    </>
  );
}
