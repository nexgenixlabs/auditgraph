/**
 * AuditGraph v3.0.5 — Executive Summary
 *
 * Dark-themed executive risk intelligence view with 6 tabs:
 *   1. Executive Summary   2. Identity Risk   3. Action Plan
 *   4. Control & Governance 5. Compliance & Evidence 6. Risk Movement
 *
 * Uses inline styles (no Tailwind). Renders within the main app layout.
 * All data bound to tenantData schema — no hardcoded values in UI.
 *
 * v3.0.2: DrillableNumber enforcement (Rule 36), Preview Changes panel,
 *         Create Ticket integration, bug fixes (Rules 30-32),
 *         dead button elimination (Rules 33-35).
 * v3.0.5: MAJOR ARCHITECTURE FIX — removed identityStore, identityIds,
 *         changes[], affectedIdentityIds. Drill-downs navigate to
 *         /identities with filter params. Preview Changes fetches from
 *         remediation detail API. DrillDownPanel DEPRECATED.
 */
import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';
import {
  COLORS, getTierColor, getScoreColor, getPillarColor,
  getTier, getGrade, getSemanticColor,
  type TenantData, type Remediation, type ComplianceFramework,
} from '../constants/ciso';

// ─── Font Injection ──────────────────────────────────────────────

const FONT_LINK = 'https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap';

// ─── Typography Helpers ──────────────────────────────────────────

const FONT = {
  ui: "'DM Sans', sans-serif",
  mono: "'JetBrains Mono', monospace",
};

// ─── Reusable Components ─────────────────────────────────────────

function ScoreRing({ score, size = 96, strokeWidth = 6, color, displayValue }: {
  score: number; size?: number; strokeWidth?: number; color?: string; displayValue?: string;
}) {
  const c = color || getScoreColor(score);
  const r = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * r;
  const offset = circumference - (score / 100) * circumference;
  const fontSize = Math.min(32, Math.floor(size * 0.26));
  const grade = getGrade(score);
  const label = displayValue ?? score.toFixed(1);
  return (
    <svg width={size} height={size} style={{ display: 'block' }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none"
        stroke={COLORS.border} strokeWidth={strokeWidth} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none"
        stroke={c} strokeWidth={strokeWidth} strokeLinecap="round"
        strokeDasharray={circumference} strokeDashoffset={offset}
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
        style={{ transition: 'stroke-dashoffset 1.4s cubic-bezier(0.4,0,0.2,1)' }} />
      <text x={size / 2} y={size / 2 - 4} textAnchor="middle" dominantBaseline="central"
        fill={COLORS.text} fontFamily={FONT.mono} fontWeight={700} fontSize={fontSize}>
        {label}
      </text>
      <text x={size / 2} y={size / 2 + 18} textAnchor="middle" dominantBaseline="central"
        fill={COLORS.textMuted} fontFamily={FONT.mono} fontWeight={600} fontSize={10}>
        {grade}
      </text>
    </svg>
  );
}

function Sparkline({ data, width = 90, height = 22, color }: {
  data: number[]; width?: number; height?: number; color?: string;
}) {
  if (!data.length) return null;
  const c = color || COLORS.accent;
  const min = Math.min(...data);
  const max = Math.max(...data) || 1;
  const range = max - min || 1;
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = height - ((v - min) / range) * (height - 4) - 2;
    return `${x},${y}`;
  }).join(' ');
  const last = data[data.length - 1];
  const lx = width;
  const ly = height - ((last - min) / range) * (height - 4) - 2;
  const gradId = `sp-${Math.random().toString(36).slice(2, 8)}`;
  return (
    <svg width={width} height={height}>
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={c} stopOpacity={0.25} />
          <stop offset="100%" stopColor={c} stopOpacity={0} />
        </linearGradient>
      </defs>
      <polygon points={`0,${height} ${pts} ${width},${height}`} fill={`url(#${gradId})`} />
      <polyline points={pts} fill="none" stroke={c} strokeWidth={1.5} />
      <circle cx={lx} cy={ly} r={3} fill={c} />
    </svg>
  );
}

function CISOBadge({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      background: `${color}22`, border: `1px solid ${color}40`,
      padding: '2px 9px', borderRadius: 4,
      fontSize: 10, fontWeight: 600, letterSpacing: '0.08em',
      textTransform: 'uppercase' as const, color, fontFamily: FONT.ui,
    }}>
      <span style={{ width: 5, height: 5, borderRadius: '50%', background: color }} />
      {label}
    </span>
  );
}

function ProgressBar({ value, color, height = 6 }: { value: number; color: string; height?: number }) {
  return (
    <div style={{ background: COLORS.border, borderRadius: height / 2, height, width: '100%', overflow: 'hidden' }}>
      <div style={{
        width: `${Math.min(100, Math.max(0, value))}%`, height: '100%',
        background: color, borderRadius: height / 2,
        transition: 'width 1s ease',
      }} />
    </div>
  );
}

function StatBox({ label, value, color, sub }: {
  label: string; value: React.ReactNode; color: string; sub?: string;
}) {
  return (
    <div style={{
      background: `${color}14`, border: `1px solid ${color}2e`,
      borderRadius: 8, padding: '12px 16px', textAlign: 'center' as const,
    }}>
      <div style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase' as const, color: COLORS.textMuted, fontFamily: FONT.ui }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 700, color, fontFamily: FONT.mono, marginTop: 2 }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: COLORS.textMuted, marginTop: 2, fontFamily: FONT.ui }}>{sub}</div>}
    </div>
  );
}

function SectionTitle({ children, right, onRightClick }: { children: string; right?: string; onRightClick?: () => void }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
      <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.12em', color: COLORS.textMuted, fontFamily: FONT.ui }}>{children}</span>
      {right && <span onClick={onRightClick} style={{ fontSize: 10, color: COLORS.accent, cursor: onRightClick ? 'pointer' : 'default', fontFamily: FONT.ui }}>{right}</span>}
    </div>
  );
}

function CISOCard({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <div style={{
      background: COLORS.surface, border: `1px solid ${COLORS.border}`,
      borderRadius: 12, padding: '18px 20px', ...style,
    }}>
      {children}
    </div>
  );
}

function MiniComplianceCard({ fw, onClick }: { fw: ComplianceFramework; onClick?: () => void }) {
  const c = getScoreColor(fw.score);
  return (
    <div onClick={onClick} style={{
      background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
      borderRadius: 8, padding: '10px 12px', cursor: onClick ? 'pointer' : 'default',
      display: 'flex', alignItems: 'center', gap: 10,
      transition: 'border-color 0.15s ease',
    }}
      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = COLORS.borderAccent; }}
      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = COLORS.border; }}
    >
      <ScoreRing score={fw.score} size={36} strokeWidth={3} color={c} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const }}>{fw.name}</div>
        <div style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.ui }}>{fw.failedControls} failures · {fw.totalControls} controls</div>
      </div>
      {fw.trend !== 0 && (
        <span style={{ fontSize: 10, color: fw.trend > 0 ? COLORS.success : COLORS.danger, fontFamily: FONT.mono }}>
          {fw.trend > 0 ? '↑' : '↓'}
        </span>
      )}
    </div>
  );
}

function Gauge({ value, marks, max = 100 }: {
  value: number; marks: { label: string; value: number; color: string }[]; max?: number;
}) {
  return (
    <div style={{ position: 'relative', padding: '24px 0 8px' }}>
      <div style={{
        height: 6, borderRadius: 3, width: '100%',
        background: `linear-gradient(to right, ${COLORS.danger}59, ${COLORS.warning}59, ${COLORS.success}59)`,
      }} />
      {marks.map((m, i) => (
        <div key={i} style={{
          position: 'absolute', left: `${(m.value / max) * 100}%`,
          top: 0, transform: 'translateX(-50%)', textAlign: 'center' as const,
        }}>
          <div style={{ fontSize: 8, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' as const, color: m.color, fontFamily: FONT.mono, marginBottom: 4 }}>{m.label}</div>
          <div style={{ width: 1, height: 20, background: m.color, margin: '0 auto' }} />
        </div>
      ))}
      <div style={{
        position: 'absolute', left: `${(value / max) * 100}%`,
        top: 18, transform: 'translateX(-50%)',
        width: 14, height: 14, borderRadius: '50%',
        background: getScoreColor(value),
        boxShadow: `0 0 8px ${getScoreColor(value)}80`,
      }} />
    </div>
  );
}

// ─── DrillableNumber (v3.0.5: navigation model) ─────────────────

/** Wraps a countable number with dashed underline + pointer.
 *  v3.0.5: navigates to /identities with filter params (Section 3.1).
 *  Non-identity numbers use tooltip prop instead of navigateTo. */
function DN({ children, navigateTo, tooltip }: { children: React.ReactNode; navigateTo?: string; tooltip?: string }) {
  const navigate = useNavigate();
  if (!navigateTo) {
    return <span title={tooltip}>{children}</span>;
  }
  return (
    <span
      onClick={(e) => { e.stopPropagation(); navigate(navigateTo); }}
      title={tooltip || `Click to view details`}
      style={{
        textDecoration: 'underline', textDecorationStyle: 'dashed' as const,
        textUnderlineOffset: '3px', cursor: 'pointer',
      }}
    >
      {children}
    </span>
  );
}

// ─── PreviewChangesPanel (640px, v3.0.5: API fetch model) ────────

function PreviewChangesPanel({ rem, data, onClose }: { rem: Remediation; data: TenantData; onClose: () => void }) {
  const navigate = useNavigate();
  const { withConnection } = useConnection();
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState<any>(null);
  const [error, setError] = useState(false);

  // v3.0.5 Rule 39: Fetch from remediation detail API on click
  useEffect(() => {
    setLoading(true);
    setError(false);
    fetch(withConnection(`/api/identities/${rem.id}/remediations`))
      .then(r => r.ok ? r.json() : null)
      .then(d => { setDetail(d); setLoading(false); })
      .catch(() => { setError(true); setLoading(false); });
  }, [rem.id, withConnection]);

  const riskColor = (level: string) =>
    level === 'critical' ? COLORS.danger :
    level === 'high' ? COLORS.elevated :
    level === 'medium' ? COLORS.warning : COLORS.success;

  // Determine whether we have detailed identity-level data
  const hasDetail = detail?.playbooks?.length > 0 || detail?.affected_identities?.length > 0;

  return (
    <>
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 60 }} />
      <div style={{
        position: 'fixed', top: 0, right: 0, bottom: 0, width: 640,
        background: COLORS.surface, borderLeft: `1px solid ${COLORS.border}`,
        zIndex: 61, display: 'flex', flexDirection: 'column',
        boxShadow: '-8px 0 32px rgba(0,0,0,0.3)',
      }}>
        {/* Header */}
        <div style={{ padding: '16px 20px', borderBottom: `1px solid ${COLORS.border}` }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui }}>Preview Changes</div>
              <div style={{ fontSize: 11, color: COLORS.textMuted, fontFamily: FONT.ui, marginTop: 2 }}>{rem.title}</div>
            </div>
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: COLORS.textMuted, cursor: 'pointer', fontSize: 20, fontFamily: FONT.ui }}>×</button>
          </div>
          {/* Score impact bar — always shown from tenantData */}
          <div style={{
            marginTop: 12, padding: '10px 14px', borderRadius: 8,
            background: COLORS.successSoft, border: `1px solid ${COLORS.success}2e`,
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          }}>
            <span style={{ fontSize: 11, color: COLORS.textMuted, fontFamily: FONT.ui }}>Score impact</span>
            <span style={{ fontSize: 16, fontWeight: 700, color: COLORS.success, fontFamily: FONT.mono }}>
              {data.riskScore.current.toFixed(1)} → {rem.projectedScore} (+{rem.gain} pts)
            </span>
          </div>
        </div>

        {/* Content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '12px 20px' }}>
          {loading ? (
            /* Skeleton while API responds */
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {[1, 2, 3].map(i => (
                <div key={i} style={{
                  background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
                  borderRadius: 8, padding: '16px 14px', height: 60,
                }}>
                  <div style={{ width: `${60 + i * 10}%`, height: 10, borderRadius: 4, background: COLORS.border, marginBottom: 8 }} />
                  <div style={{ width: `${40 + i * 5}%`, height: 8, borderRadius: 4, background: COLORS.border }} />
                </div>
              ))}
              <div style={{ textAlign: 'center' as const, fontSize: 11, color: COLORS.textMuted, fontFamily: FONT.ui, marginTop: 8 }}>
                Loading affected identities...
              </div>
            </div>
          ) : hasDetail ? (
            /* Loaded — API returned data */
            <>
              <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textMuted, fontFamily: FONT.ui, marginBottom: 12 }}>
                Remediation Details
              </div>
              {(detail.playbooks || []).map((pb: any, i: number) => (
                <div key={i} style={{
                  background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
                  borderRadius: 8, padding: '12px 14px', marginBottom: 8,
                }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui }}>{pb.title || pb.name}</div>
                  <div style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.ui, marginTop: 4 }}>{pb.description || pb.subtitle}</div>
                  {pb.risk_level && <CISOBadge label={pb.risk_level} color={riskColor(pb.risk_level)} />}
                </div>
              ))}
            </>
          ) : (
            /* Fallback — show existing remediation data + View Affected Identities link (Rule 39) */
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textMuted, fontFamily: FONT.ui }}>
                Remediation Summary
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div style={{ background: COLORS.surfaceAlt, borderRadius: 8, padding: '10px 12px' }}>
                  <div style={{ fontSize: 9, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Affected</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{rem.affected}</div>
                </div>
                <div style={{ background: COLORS.surfaceAlt, borderRadius: 8, padding: '10px 12px' }}>
                  <div style={{ fontSize: 9, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Est. Effort</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{rem.effort}</div>
                </div>
                <div style={{ background: COLORS.surfaceAlt, borderRadius: 8, padding: '10px 12px' }}>
                  <div style={{ fontSize: 9, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Rollback</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: rem.rollbackRisk === 'safe' ? COLORS.success : COLORS.danger, fontFamily: FONT.mono, marginTop: 4 }}>{rem.rollback}</div>
                </div>
                <div style={{ background: COLORS.surfaceAlt, borderRadius: 8, padding: '10px 12px' }}>
                  <div style={{ fontSize: 9, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Confidence</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{rem.confidence}%</div>
                </div>
              </div>
              <div style={{ background: COLORS.surfaceAlt, borderRadius: 8, padding: '10px 12px' }}>
                <div style={{ fontSize: 9, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Compliance</div>
                <div style={{ fontSize: 12, color: COLORS.text, fontFamily: FONT.ui, marginTop: 4 }}>{rem.compliance}</div>
              </div>
              {/* Navigate to All Identities with remediation filter */}
              <button onClick={() => { navigate(`/identities?remediation=${rem.id}`); onClose(); }} style={{
                width: '100%', padding: '10px', borderRadius: 6, fontSize: 11, fontWeight: 600,
                background: COLORS.accentSoft, color: COLORS.accent, border: `1px solid ${COLORS.accent}30`,
                cursor: 'pointer', fontFamily: FONT.ui, marginTop: 4,
              }}>View Affected Identities →</button>
            </div>
          )}
        </div>

        {/* Footer */}
        <div style={{ padding: '14px 20px', borderTop: `1px solid ${COLORS.border}`, display: 'flex', gap: 8 }}>
          <button style={{
            flex: 1, padding: '8px', borderRadius: 6, fontSize: 11, fontWeight: 600,
            background: `linear-gradient(135deg, ${COLORS.accent}, ${COLORS.purple})`,
            color: '#fff', border: 'none', cursor: 'pointer', fontFamily: FONT.ui,
          }}>Apply Changes</button>
          <button onClick={onClose} style={{
            padding: '8px 16px', borderRadius: 6, fontSize: 11, fontWeight: 600,
            background: 'transparent', color: COLORS.textMuted,
            border: `1px solid ${COLORS.border}`, cursor: 'pointer', fontFamily: FONT.ui,
          }}>Cancel</button>
        </div>
        {/* Rule 40: Data source attribution */}
        <div style={{
          padding: '8px 20px', borderTop: `1px solid ${COLORS.border}`,
          fontSize: 10, color: COLORS.textDim, fontFamily: FONT.ui,
          display: 'flex', alignItems: 'center', gap: 6,
        }}>
          <span style={{ width: 4, height: 4, borderRadius: '50%', background: COLORS.success, flexShrink: 0 }} />
          Source: Azure RBAC scan · Entra ID · Last updated: {new Date(data.tenant.lastScan).toLocaleString()}
        </div>
      </div>
    </>
  );
}

// ─── CreateTicketModal (v3.0.2 §6.1.2) ──────────────────────────

function CreateTicketModal({ rem, data, onClose }: { rem: Remediation; data: TenantData; onClose: () => void }) {
  const navigate = useNavigate();
  const configured = data.ticketingIntegration.configured;
  const provider = data.ticketingIntegration.provider || 'Not configured';
  const [title, setTitle] = useState(`[AuditGraph] ${rem.title}`);
  const [priority, setPriority] = useState(rem.risk === 'HIGH' ? 'high' : 'medium');
  const [submitted, setSubmitted] = useState(false);

  if (!configured) {
    return (
      <>
        <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 60 }} />
        <div style={{
          position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%, -50%)',
          width: 420, background: COLORS.surface, border: `1px solid ${COLORS.border}`,
          borderRadius: 12, padding: '28px 24px', zIndex: 61,
          boxShadow: '0 16px 48px rgba(0,0,0,0.4)',
        }}>
          <div style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui, marginBottom: 8 }}>Ticketing Not Configured</div>
          <div style={{ fontSize: 12, color: COLORS.textMuted, fontFamily: FONT.ui, lineHeight: 1.6, marginBottom: 16 }}>
            Connect Jira, ServiceNow, or Azure DevOps in Settings to create tickets directly from remediation actions.
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => { navigate('/settings/integrations#ticketing'); onClose(); }} style={{
              flex: 1, padding: '8px', borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: COLORS.accent, color: '#fff', border: 'none', cursor: 'pointer', fontFamily: FONT.ui,
            }}>Configure in Settings</button>
            <button onClick={onClose} style={{
              padding: '8px 16px', borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: 'transparent', color: COLORS.textMuted,
              border: `1px solid ${COLORS.border}`, cursor: 'pointer', fontFamily: FONT.ui,
            }}>Cancel</button>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 60 }} />
      <div style={{
        position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%, -50%)',
        width: 500, background: COLORS.surface, border: `1px solid ${COLORS.border}`,
        borderRadius: 12, padding: '24px', zIndex: 61,
        boxShadow: '0 16px 48px rgba(0,0,0,0.4)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui }}>Create Ticket</div>
          <CISOBadge label={provider} color={COLORS.accent} />
        </div>

        {submitted ? (
          <div style={{ textAlign: 'center' as const, padding: '24px 0' }}>
            <div style={{ fontSize: 32, marginBottom: 8 }}>✓</div>
            <div style={{ fontSize: 14, fontWeight: 600, color: COLORS.success, fontFamily: FONT.ui }}>Ticket Created</div>
            <div style={{ fontSize: 11, color: COLORS.textMuted, fontFamily: FONT.ui, marginTop: 4 }}>
              {provider.toUpperCase()}-{Math.floor(Math.random() * 9000 + 1000)}
            </div>
            <button onClick={onClose} style={{
              marginTop: 16, padding: '8px 24px', borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: COLORS.accent, color: '#fff', border: 'none', cursor: 'pointer', fontFamily: FONT.ui,
            }}>Done</button>
          </div>
        ) : (
          <>
            {/* Title */}
            <div style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textMuted, fontFamily: FONT.ui }}>Title</label>
              <input value={title} onChange={e => setTitle(e.target.value)} style={{
                width: '100%', padding: '8px 12px', borderRadius: 6, marginTop: 4,
                background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
                color: COLORS.text, fontSize: 12, fontFamily: FONT.ui, outline: 'none',
                boxSizing: 'border-box' as const,
              }} />
            </div>
            {/* Description */}
            <div style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textMuted, fontFamily: FONT.ui }}>Description</label>
              <textarea defaultValue={`${rem.subtitle}\n\nAffected: ${rem.affected}\nEffort: ${rem.effort}\nCompliance: ${rem.compliance}\nConfidence: ${rem.confidence}%`} style={{
                width: '100%', padding: '8px 12px', borderRadius: 6, marginTop: 4, minHeight: 80, resize: 'vertical' as const,
                background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
                color: COLORS.text, fontSize: 12, fontFamily: FONT.ui, outline: 'none',
                boxSizing: 'border-box' as const,
              }} />
            </div>
            {/* Priority */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textMuted, fontFamily: FONT.ui }}>Priority</label>
              <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
                {['critical', 'high', 'medium', 'low'].map(p => (
                  <button key={p} onClick={() => setPriority(p)} style={{
                    padding: '4px 12px', borderRadius: 4, fontSize: 10, fontWeight: 600,
                    background: priority === p ? COLORS.accentSoft : 'transparent',
                    color: priority === p ? COLORS.accent : COLORS.textMuted,
                    border: `1px solid ${priority === p ? `${COLORS.accent}40` : COLORS.border}`,
                    cursor: 'pointer', fontFamily: FONT.ui, textTransform: 'capitalize' as const,
                  }}>{p}</button>
                ))}
              </div>
            </div>
            {/* Actions */}
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={() => setSubmitted(true)} style={{
                flex: 1, padding: '8px', borderRadius: 6, fontSize: 11, fontWeight: 600,
                background: COLORS.accent, color: '#fff', border: 'none', cursor: 'pointer', fontFamily: FONT.ui,
              }}>Create Ticket</button>
              <button onClick={onClose} style={{
                padding: '8px 16px', borderRadius: 6, fontSize: 11, fontWeight: 600,
                background: 'transparent', color: COLORS.textMuted,
                border: `1px solid ${COLORS.border}`, cursor: 'pointer', fontFamily: FONT.ui,
              }}>Cancel</button>
            </div>
          </>
        )}
      </div>
    </>
  );
}

// ─── Remediation Card ────────────────────────────────────────────

function RemediationCard({ item, index, onPreview, onTicket }: {
  item: Remediation; index: number;
  onPreview?: (r: Remediation) => void;
  onTicket?: (r: Remediation) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const c = getSemanticColor(item.color) || COLORS.accent;
  return (
    <div
      onClick={() => setExpanded(!expanded)}
      style={{
        background: expanded ? COLORS.surfaceHover : COLORS.surfaceAlt,
        border: `1px solid ${expanded ? COLORS.borderAccent : COLORS.border}`,
        borderRadius: 10, padding: '14px 18px', cursor: 'pointer',
        transition: 'all 0.2s ease',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{
          width: 34, height: 34, borderRadius: 7,
          background: `${c}1f`, border: `1px solid ${c}40`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontFamily: FONT.mono, fontSize: 13, fontWeight: 700, color: c,
          flexShrink: 0,
        }}>#{index + 1}</div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui }}>{item.title}</div>
          <div style={{ fontSize: 11, color: COLORS.textMuted, fontFamily: FONT.ui, marginTop: 1 }}>{item.subtitle}</div>
        </div>
        <div style={{ textAlign: 'right' as const, flexShrink: 0 }}>
          <div style={{ fontSize: 18, fontWeight: 700, color: COLORS.success, fontFamily: FONT.mono }}>+{item.gain}</div>
          <div style={{ fontSize: 9, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>→ {item.projectedScore}</div>
        </div>
        <CISOBadge label={item.risk} color={item.risk === 'HIGH' ? COLORS.danger : COLORS.success} />
        <CISOBadge label={item.automation} color={item.automation === 'Auto' ? COLORS.accent : COLORS.textMuted} />
        <span style={{ fontSize: 12, color: COLORS.textMuted, marginLeft: 4, transform: expanded ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }}>▾</span>
      </div>
      {expanded && (
        <div style={{ borderTop: `1px solid ${COLORS.border}`, marginTop: 14, paddingTop: 14 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
            <div>
              <div style={{ fontSize: 9, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Affected</div>
              <div style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{item.affected}</div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Est. Effort</div>
              <div style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{item.effort}</div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Rollback</div>
              <div style={{ fontSize: 11, color: item.rollbackRisk === 'safe' ? COLORS.success : COLORS.danger, fontFamily: FONT.mono, marginTop: 4 }}>{item.rollback}</div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Compliance</div>
              <div style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{item.compliance}</div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Confidence</div>
              <div style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{item.confidence}%</div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
            <button onClick={(e) => { e.stopPropagation(); onPreview?.(item); }} style={{
              padding: '6px 14px', borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: `linear-gradient(135deg, ${COLORS.accent}, ${COLORS.purple})`,
              color: '#fff', border: 'none', cursor: 'pointer', fontFamily: FONT.ui,
            }}>Preview Changes →</button>
            <button onClick={(e) => { e.stopPropagation(); onTicket?.(item); }} style={{
              padding: '6px 14px', borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: 'transparent', color: COLORS.textMuted,
              border: `1px solid ${COLORS.border}`, cursor: 'pointer', fontFamily: FONT.ui,
            }}>Create Ticket</button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Sample Tenant Data ──────────────────────────────────────────

function buildSampleData(): TenantData {
  return {
    tenant: {
      id: 'sample-tenant',
      name: 'NexgenixLabs',
      organizationName: 'NexgenixLabs',
      organizationLogo: null,
      cloud: 'Azure',
      subscriptions: 5,
      identityCount: 57,
      lastScan: new Date().toISOString(),
      scanDuration: 65,
      scanCompleteness: 100,
      scanConfidence: 'High',
      sources: ['Azure RBAC', 'Entra ID', 'Graph API'],
      isolationGuarantee: 'Isolated dataset • No cross-tenant visibility',
    },
    riskScore: {
      current: 50.2, previous: 48.2, delta: 2.0,
      tier: 'ELEVATED', grade: 'D',
      industry: 69, target: 90, potentialGain: 150,
      trend: [42, 44, 45, 43, 46, 48, 47, 49, 48, 50, 50.2],
    },
    projection: {
      noAction: { score: 47.2, tier: 'ELEVATED', consequences: [
        '2 privileged HRIs remain without review',
        '4 dormant privileged accounts retain active roles',
        '3 disabled accounts retain active RBAC roles (ghost accounts)',
        '3 RBAC modifiers continue unscreened',
        'Ownership gap at 96% — 44 SPNs unowned',
        '53 dormant accounts with active roles unresolved',
      ], breachImpact: 'Moderate-High' },
      remediated: { score: 95.0, tier: 'RESILIENT', actions: [
        'Over-privileged identities scoped down',
        'Dormant privileged accounts disabled',
        'Ghost account roles revoked',
        'All SPNs assigned owners',
      ], breachImpact: 'Low' },
    },
    ghostAccounts: {
      total: 3,
      privileged: 1,
      nonPrivileged: 2,
      roles: [
        { role: 'Contributor', scope: '/subscriptions/prod-sub-001', count: 1 },
        { role: 'Reader', scope: '/subscriptions/dev-sub-002', count: 2 },
      ],
      complianceImpact: ['SOC2 CC6.1', 'HIPAA', 'NIST AC-2', 'SOX'],
      lastDetected: new Date().toISOString(),
    },
    deltaChanges: [
      { icon: '👤', label: 'Dormant', value: '+3', color: 'danger' },
      { icon: '🔑', label: 'Over-priv', value: '6', color: 'warning' },
      { icon: '👻', label: 'Ghost Roles', value: '3', color: 'danger' },
      { icon: '🤖', label: 'Unowned SPs', value: '44', color: 'elevated' },
      { icon: '🌐', label: 'Ext exposure', value: '4', color: 'accent' },
    ],
    identityBreakdown: [
      { type: 'Human Users', count: 8, percentage: 14, color: 'accent' },
      { type: 'Workload Identities', count: 46, percentage: 80.7, color: 'warning' },
      { type: 'Guest Users', count: 3, percentage: 5.3, color: 'textDim' },
    ],
    pillars: [
      { name: 'Effective Privilege', score: 38, weight: 30, detail: '4 IDs over-privileged', identityCount: 4, subMetrics: [{ name: 'Tenant/Sub Owner', value: 2, max: 10 }, { name: 'High-priv roles', value: 6, max: 20 }] },
      { name: 'Credential Risk', score: 22, weight: 20, detail: '3 expired credentials', identityCount: 3, subMetrics: [{ name: 'Expired certs', value: 2, max: 10 }, { name: 'No MFA', value: 1, max: 8 }] },
      { name: 'Trust & Federation', score: 15, weight: 20, detail: '2 external trusts', identityCount: 2, subMetrics: [{ name: 'External apps', value: 2, max: 5 }] },
      { name: 'Usage Dormancy', score: 100, weight: 10, detail: '53 dormant identities', identityCount: 53, subMetrics: [{ name: 'Dormant privl', value: 4, max: 4 }, { name: 'Dormant all', value: 53, max: 57 }] },
      { name: 'Ownership Governance', score: 96, weight: 10, detail: '44 unowned SPNs', identityCount: 44, subMetrics: [{ name: 'Unowned', value: 44, max: 46 }] },
      { name: 'External Exposure', score: 28, weight: 10, detail: '4 externally exposed', identityCount: 4, subMetrics: [{ name: 'Multi-tenant apps', value: 3, max: 10 }, { name: 'Guest access', value: 1, max: 3 }] },
    ],
    blastRadius: {
      highRisk: 12.8, lowRisk: 0, orphaned: 44, productionWorkloads: 46,
      categories: [
        { name: 'Privilege', score: 0.4, color: COLORS.danger },
        { name: 'Credential', score: 0.1, color: COLORS.warning },
        { name: 'Exposure', score: 0.2, color: COLORS.elevated },
        { name: 'Lifecycle', score: 9.9, color: COLORS.accent },
        { name: 'Visibility', score: 2.1, color: COLORS.purple },
      ],
    },
    kpis: {
      privilegedRoles: { value: 2, subtitle: '80% from machines' },
      dormantPrivileged: { value: 4, subtitle: 'Active roles retained' },
      ghostAccounts: { value: 3, subtitle: 'Disabled + active RBAC' },
      subscriptionAccess: { value: 5, subtitle: '3 cross-sub identities' },
      rbacModifiers: { value: 3, subtitle: 'Custom role defs' },
    },
    remediations: [
      { id: 'r1', type: 'identity-remediation', title: 'Reduce over-privileged identities', subtitle: '6 ids hold TO/TI privileges across 5 subscriptions', gain: 79, projectedScore: '~76', status: 'new', automation: 'Manual', risk: 'HIGH', color: 'danger', affected: '6 ids · 5 subs · 46 wklds', effort: '~14 days', rollback: 'Safe to rollback', rollbackRisk: 'safe', compliance: 'SOC 2, HIPAA, NIST', confidence: 92, productionImpact: true, riskPerDay: 0.3 },
      { id: 'r2', type: 'identity-remediation', title: 'Remediate dormant privileged accounts', subtitle: '4 dormant accounts with active privileged roles', gain: 42, projectedScore: '~68', status: 'new', automation: 'Auto', risk: 'LOW', color: 'warning', affected: '4 ids · 2 subs · 0 wklds', effort: '~2 days', rollback: 'Safe to rollback', rollbackRisk: 'safe', compliance: 'HIPAA, SOC 2', confidence: 98, productionImpact: false, riskPerDay: 0.1 },
      { id: 'r2b', type: 'identity-remediation', title: 'Revoke roles from disabled accounts', subtitle: '3 accounts are disabled in Entra ID but retain active RBAC assignments — immediate security risk', gain: 35, projectedScore: '~70', status: 'new', automation: 'Auto', risk: 'HIGH', color: 'danger', affected: '3 ids · 2 subs · 0 wklds', effort: '~1 day', rollback: 'Safe to rollback', rollbackRisk: 'safe', compliance: 'SOC2 CC6.1, HIPAA, NIST AC-2, SOX', confidence: 99, productionImpact: false, riskPerDay: 0.5 },
      { id: 'r3', type: 'identity-remediation', title: 'Assign ownership to unowned SPNs', subtitle: '44 service principals without designated owners', gain: 29, projectedScore: '~62', status: 'new', automation: 'Manual', risk: 'LOW', color: 'elevated', affected: '44 ids · 0 subs · 0 wklds', effort: '~7 days', rollback: 'Safe to rollback', rollbackRisk: 'safe', compliance: 'SOC 2, ISO 27001', confidence: 95, productionImpact: false, riskPerDay: 0.05 },
    ],
    governance: {
      effectivenessScore: 1, effectivenessTier: 'CRITICAL', maturityLevel: 'Ad-Hoc',
      metrics: [
        { label: 'Ownership Coverage', value: '4%', target: '80%', status: 'critical', icon: '👤' },
        { label: 'PIM Enforcement', value: '—', target: '100%', status: 'not-configured', icon: '🔐' },
        { label: 'Access Reviews', value: '—', target: 'quarterly', status: 'not-configured', icon: '📋' },
        { label: 'Privileged Monitoring', value: '—', target: 'active', status: 'not-configured', icon: '📡' },
      ],
      controlFailures: [
        { type: 'PREVENTIVE FAILURES', items: [
          { label: 'Privilege outside PIM', count: 2, color: COLORS.danger },
          { label: 'Disabled accounts retain active RBAC roles', count: 3, color: COLORS.danger },
        ] },
        { type: 'OPERATIONAL GAPS', items: [
          { label: 'Ownership coverage at 4%', count: 44, color: COLORS.warning },
          { label: 'Dormant privileged accounts active', count: 4, color: COLORS.warning },
        ] },
      ],
      setupCompletion: { configured: 1, total: 4 },
    },
    compliance: {
      frameworks: [
        { id: 'hipaa', name: 'HIPAA', type: 'Industry', score: 26, totalControls: 167, failedControls: 8, status: 'Initial', trend: 0, identityImpactCount: 12, controls: [] },
        { id: 'soc2', name: 'SOC 2 Type II', type: 'Industry', score: 26, totalControls: 200, failedControls: 8, status: 'Initial', trend: 0, identityImpactCount: 10, controls: [] },
        { id: 'gdpr', name: 'GDPR', type: 'Industry', score: 26, totalControls: 159, failedControls: 8, status: 'Initial', trend: 0, identityImpactCount: 8, controls: [] },
        { id: 'ccpa', name: 'CCPA', type: 'Industry', score: 26, totalControls: 174, failedControls: 8, status: 'Initial', trend: 0, identityImpactCount: 6, controls: [] },
        { id: 'pci', name: 'PCI DSS', type: 'Industry', score: 26, totalControls: 180, failedControls: 8, status: 'Initial', trend: 0, identityImpactCount: 9, controls: [] },
        { id: 'cis', name: 'CIS Benchmark', type: 'Benchmark', score: 26, totalControls: 150, failedControls: 8, status: 'Initial', trend: 0, identityImpactCount: 11, controls: [] },
        { id: 'nist', name: 'NIST 800-53', type: 'Benchmark', score: 26, totalControls: 200, failedControls: 8, status: 'Initial', trend: 0, identityImpactCount: 14, controls: [] },
        { id: 'iso27001', name: 'ISO 27001', type: 'Core Governance', score: 26, totalControls: 93, failedControls: 8, status: 'Initial', trend: 0, identityImpactCount: 7, controls: [] },
        { id: 'csf', name: 'NIST CSF', type: 'Core Governance', score: 26, totalControls: 108, failedControls: 8, status: 'Initial', trend: 0, identityImpactCount: 10, controls: [] },
      ],
      maturity: { preventive: 0, detective: 0, compensating: 0, missing: 0 },
      progress: { remediation: 26, iaGovernance: 4.5 },
    },
    riskMovement: {
      trajectory: [42, 44, 45, 43, 46, 48, 47, 49, 48, 50, 50.2],
      changes: [
        { label: 'Critical Identities', before: 0, after: 1, direction: 'up' },
        { label: 'High-Risk Identities', before: 0, after: 0, direction: 'flat' },
        { label: 'Ghost Accounts', before: 0, after: 3, direction: 'up' },
        { label: 'Total Identities', before: 0, after: 57, direction: 'up' },
        { label: 'New Identities', before: 0, after: 0, direction: 'flat' },
        { label: 'Removed', before: 0, after: 0, direction: 'flat' },
      ],
      mostChanged: { name: 'Usage Dormancy', score: 100, category: 'Lifecycle' },
      scanMeta: { frequency: 'High', lastRun: new Date().toISOString(), sources: 'Azure RBAC, Entra ID, Graph API', duration: '1m 5s', completeness: '100%' },
    },
    ticketingIntegration: { configured: false, provider: null, projectKey: null, defaultAssignee: null, jira: null },
  };
}

// ─── Data Hook ───────────────────────────────────────────────────

function useCISOData(): { data: TenantData; loading: boolean } {
  const { withConnection, selectedConnectionId } = useConnection();
  const { activeTenantId } = useAuth();
  const [data, setData] = useState<TenantData>(buildSampleData);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        const [statsRes, postureRes, summaryRes, compRes] = await Promise.all([
          fetch(withConnection('/api/stats')).catch(() => null),
          fetch(withConnection('/api/dashboard/posture')).catch(() => null),
          fetch(withConnection('/api/identity-summary')).catch(() => null),
          fetch(withConnection('/api/dashboard/compliance')).catch(() => null),
        ]);
        const stats = statsRes?.ok ? await statsRes.json() : null;
        const posture = postureRes?.ok ? await postureRes.json() : null;
        const summary = summaryRes?.ok ? await summaryRes.json() : null;
        const comp = compRes?.ok ? await compRes.json() : null;

        if (cancelled) return;
        const base = buildSampleData();

        // Overlay real data where available
        if (stats?.latest_run) {
          base.tenant.identityCount = stats.latest_run.total_identities || base.tenant.identityCount;
          if (stats.latest_run.completed_at) base.tenant.lastScan = stats.latest_run.completed_at;
        }
        if (posture) {
          const ps = posture.posture_score ?? base.riskScore.current;
          const prev = posture.previous_posture_score ?? base.riskScore.previous;
          base.riskScore.current = ps;
          base.riskScore.previous = prev;
          base.riskScore.delta = ps - prev;
          base.riskScore.tier = getTier(ps);
          base.riskScore.grade = getGrade(ps);
        }
        if (summary?.categories) {
          const cats = summary.categories as Record<string, { total: number }>;
          const humanCount = (cats.human_user?.total || 0) + (cats.guest?.total || 0);
          const workloadCount = (cats.service_principal?.total || 0) + (cats.managed_identity_system?.total || 0) + (cats.managed_identity_user?.total || 0);
          const guestCount = cats.guest?.total || 0;
          const total = humanCount + workloadCount;
          if (total > 0) {
            base.identityBreakdown = [
              { type: 'Human Users', count: humanCount - guestCount, percentage: Math.round(((humanCount - guestCount) / total) * 100), color: 'accent' },
              { type: 'Workload Identities', count: workloadCount, percentage: Math.round((workloadCount / total) * 100), color: 'warning' },
              { type: 'Guest Users', count: guestCount, percentage: Math.round((guestCount / total) * 100), color: 'textDim' },
            ];
          }
        }

        setData(base);
      } catch {
        // Keep sample data
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [selectedConnectionId, activeTenantId]);

  return { data, loading };
}

// ─── Tab Components ──────────────────────────────────────────────

// ─── Navigation Helpers (v3.0.5 Section 3.1) ─────────────────────

function pillarNav(name: string): string {
  // Map pillars with direct filter equivalents to real filter params
  const n = name.toLowerCase();
  if (n.includes('usage') || n.includes('dormancy')) return '/identities?dormant=true';
  if (n.includes('ownership') || n.includes('governance')) return '/identities?owner=none';
  if (n.includes('privilege')) return '/identities?privileged=true';
  if (n.includes('credential')) return '/identities?credential_status=expired';
  // For others, use the pillar banner
  const slug = n.replace(/\s+&\s+/g, '-').replace(/\s+/g, '-');
  return `/identities?pillar=${slug}`;
}

// ── Tab 1: Executive Summary ──

function ExecSummaryTab({ d, onPreview, onTicket }: { d: TenantData; onPreview: (r: Remediation) => void; onTicket: (r: Remediation) => void }) {
  const identityRemediations = d.remediations.filter(r => r.type === 'identity-remediation' && r.gain > 0);
  const top3 = identityRemediations.sort((a, b) => b.gain - a.gain).slice(0, 3);
  const totalGain = top3.reduce((s, r) => s + r.gain, 0);
  const worstFrameworks = [...d.compliance.frameworks].sort((a, b) => a.score - b.score).slice(0, 6);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* Zone 1 — Status at a Glance */}
      <CISOCard>
        <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr auto', gap: 24, alignItems: 'center' }}>
          {/* Left: Score */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <ScoreRing score={d.riskScore.current} size={96} strokeWidth={6} />
            <div>
              <div style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui }}>{d.tenant.organizationName}</div>
              <CISOBadge label={d.riskScore.tier} color={getTierColor(d.riskScore.tier)} />
              <div style={{ fontSize: 11, color: COLORS.textMuted, marginTop: 6, fontFamily: FONT.ui }}>
                <DN navigateTo="/identities">{d.tenant.identityCount}</DN> ids · {d.tenant.subscriptions} subs
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
                <span style={{ fontSize: 12, fontWeight: 700, fontFamily: FONT.mono, color: d.riskScore.delta >= 0 ? COLORS.success : COLORS.danger }}>
                  {d.riskScore.delta >= 0 ? '+' : ''}{d.riskScore.delta.toFixed(1)} pts
                </span>
                <span style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.ui }}>vs 30d</span>
              </div>
              <Sparkline data={d.riskScore.trend} width={90} height={22} color={getTierColor(d.riskScore.tier)} />
            </div>
          </div>
          {/* Center: Benchmark Gauge */}
          <div>
            <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase' as const, color: COLORS.textMuted, marginBottom: 8, fontFamily: FONT.ui }}>Score Position</div>
            <Gauge value={d.riskScore.current} marks={[
              { label: `You (${d.riskScore.current})`, value: d.riskScore.current, color: getTierColor(d.riskScore.tier) },
              { label: `Industry (${d.riskScore.industry})`, value: d.riskScore.industry, color: COLORS.textDim },
              { label: `Target (${d.riskScore.target})`, value: d.riskScore.target, color: COLORS.success },
            ]} />
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8, fontSize: 10, fontFamily: FONT.ui }}>
              <span style={{ color: COLORS.textMuted }}>{Math.round(d.riskScore.industry - d.riskScore.current)} pts below industry</span>
              <span style={{ color: COLORS.textMuted }}>Potential +{d.riskScore.potentialGain}</span>
            </div>
          </div>
          {/* Right: Projection */}
          <div style={{ display: 'flex', gap: 10 }}>
            <StatBox label="No Action" value={d.projection.noAction.score.toFixed(1)} color={COLORS.danger} sub="in 10d" />
            <StatBox label="Remediated" value={d.projection.remediated.score.toFixed(1)} color={COLORS.success} sub="if fixed" />
          </div>
        </div>
        {/* Delta Changes Bar */}
        <div style={{ borderTop: `1px solid ${COLORS.border}`, marginTop: 16, paddingTop: 12, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' as const }}>
          <span style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.ui }}>Since last scan:</span>
          {d.deltaChanges.map((dc, i) => {
            const c = getSemanticColor(dc.color);
            return (
              <span key={i} style={{
                display: 'inline-flex', alignItems: 'center', gap: 5,
                background: `${c}14`, border: `1px solid ${c}2e`,
                padding: '3px 8px', borderRadius: 4,
                fontSize: 10, fontFamily: FONT.ui,
              }}>
                <span>{dc.icon}</span>
                <span style={{ color: COLORS.textMuted }}>{dc.label}</span>
                <DN navigateTo={
                  dc.label === 'Dormant' ? '/identities?dormant=true' :
                  dc.label === 'Over-priv' ? '/identities?privileged=true' :
                  dc.label === 'Ghost Roles' ? '/identities?status=disabled&hasRoles=true' :
                  dc.label === 'Unowned SPs' ? '/identities?category=service_principal&owner=none' :
                  dc.label === 'Ext exposure' ? '/identities?pillar=external-exposure' :
                  '/identities'
                }>
                  <span style={{ fontFamily: FONT.mono, fontWeight: 600, color: c }}>{dc.value}</span>
                </DN>
              </span>
            );
          })}
        </div>
      </CISOCard>

      {/* Zone 2 — Risk + Remediation */}
      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 18 }}>
        {/* Left: Three stacked cards */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          {/* Card A: Top Risk Drivers */}
          <CISOCard>
            <SectionTitle>Top Risk Drivers</SectionTitle>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
              {d.pillars.map((p, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0', borderBottom: i < d.pillars.length - 1 ? `1px solid ${COLORS.border}` : 'none' }}>
                  <div style={{ width: 7, height: 7, borderRadius: 2, background: getPillarColor(p.score), flexShrink: 0 }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui }}>{p.name}</div>
                    <div style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.ui }}>
                      <DN navigateTo={pillarNav(p.name)}>{p.identityCount} identities</DN>
                    </div>
                  </div>
                  <div style={{ width: 50, flexShrink: 0 }}>
                    <ProgressBar value={p.score} color={getPillarColor(p.score)} height={4} />
                  </div>
                  <span style={{ fontSize: 11, fontWeight: 600, fontFamily: FONT.mono, color: getPillarColor(p.score), width: 28, textAlign: 'right' as const }}>{p.score}</span>
                </div>
              ))}
            </div>
          </CISOCard>

          {/* Card B: Blast Radius Preview */}
          <CISOCard>
            <SectionTitle right="Deep Dive →">Blast Radius Preview</SectionTitle>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, marginBottom: 12 }}>
              <StatBox label="High" value={<DN navigateTo="/identities?risk=high,critical">{d.blastRadius.highRisk}</DN>} color={COLORS.danger} />
              <StatBox label="Low" value={<DN navigateTo="/identities?risk=low,medium">{d.blastRadius.lowRisk}</DN>} color={COLORS.success} />
              <StatBox label="Orphan" value={<DN navigateTo="/identities?owner=none">{d.blastRadius.orphaned}</DN>} color={COLORS.warning} />
            </div>
            <div style={{ display: 'flex', height: 6, borderRadius: 3, overflow: 'hidden', background: COLORS.border }}>
              <div style={{ width: `${Math.max(3, (d.blastRadius.highRisk / (d.blastRadius.highRisk + d.blastRadius.lowRisk + 1)) * 100)}%`, background: COLORS.danger }} />
              <div style={{ flex: 1, background: COLORS.success }} />
            </div>
            <div style={{ fontSize: 10, color: COLORS.textMuted, marginTop: 8, fontFamily: FONT.ui }}>
              <DN navigateTo="/identities?category=service_principal">{d.blastRadius.productionWorkloads}</DN> production workloads affected
            </div>
          </CISOCard>

          {/* Card C: Identity Breakdown */}
          <CISOCard>
            <SectionTitle>Identity Breakdown</SectionTitle>
            <div style={{ display: 'flex', height: 8, borderRadius: 4, overflow: 'hidden', marginBottom: 10 }}>
              {d.identityBreakdown.map((ib, i) => (
                <div key={i} style={{ width: `${ib.percentage}%`, background: getSemanticColor(ib.color) }} />
              ))}
            </div>
            {d.identityBreakdown.map((ib, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0' }}>
                <div style={{ width: 6, height: 6, borderRadius: '50%', background: getSemanticColor(ib.color), flexShrink: 0 }} />
                <span style={{ flex: 1, fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>{ib.type}</span>
                <DN navigateTo={
                  ib.type === 'Human Users' ? '/identities?identity_category=human_user' :
                  ib.type === 'Guest Users' ? '/identities?identity_category=guest' :
                  '/identities?workload=true'
                }>
                  <span style={{ fontSize: 11, fontFamily: FONT.mono, fontWeight: 600, color: COLORS.text }}>{ib.count}</span>
                </DN>
                <span style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.mono }}>({ib.percentage}%)</span>
              </div>
            ))}
          </CISOCard>
        </div>

        {/* Right: Immediate Actions */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <SectionTitle right="View full Action Plan →">Immediate Actions — Top 3</SectionTitle>
          {/* Score Math Explainer */}
          <div style={{
            background: COLORS.accentSoft, border: `1px solid ${COLORS.accent}2e`,
            borderRadius: 8, padding: '10px 14px', fontSize: 11, color: COLORS.textMuted, fontFamily: FONT.ui,
            lineHeight: 1.5,
          }}>
            Points = improvement toward target {d.riskScore.target}. Current {d.riskScore.current} → Fix #1 alone → {top3[0]?.projectedScore || '—'}.
            Cumulative when combined.
          </div>
          {top3.map((r, i) => <RemediationCard key={r.id} item={r} index={i} onPreview={onPreview} onTicket={onTicket} />)}
          {/* Total bar */}
          <div style={{
            background: COLORS.successSoft, border: `1px solid ${COLORS.success}2e`,
            borderRadius: 8, padding: '10px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          }}>
            <span style={{ fontSize: 11, color: COLORS.textMuted, fontFamily: FONT.ui }}>Total potential from top 3</span>
            <span style={{ fontSize: 16, fontWeight: 700, color: COLORS.success, fontFamily: FONT.mono }}>+{totalGain} pts</span>
          </div>
        </div>
      </div>

      {/* Zone 3 — Compliance + Governance */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 }}>
        {/* Compliance Snapshot */}
        <CISOCard>
          <SectionTitle right={`View all ${d.compliance.frameworks.length} →`}>Compliance Posture — Worst Performing</SectionTitle>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
            {worstFrameworks.map(fw => <MiniComplianceCard key={fw.id} fw={fw} />)}
          </div>
        </CISOCard>

        {/* Governance Effectiveness */}
        <CISOCard>
          <SectionTitle>Governance Effectiveness</SectionTitle>
          <div style={{ display: 'flex', gap: 16 }}>
            <div style={{
              background: COLORS.dangerSoft, border: `1px solid ${COLORS.danger}2e`,
              borderRadius: 10, padding: '16px 20px', textAlign: 'center' as const, minWidth: 90,
            }}>
              {/* Rule 31 fix: show raw score, not *10 */}
              <div style={{ fontSize: 32, fontWeight: 700, color: COLORS.danger, fontFamily: FONT.mono }}>{d.governance.effectivenessScore}</div>
              <div style={{ fontSize: 11, color: COLORS.textMuted, fontFamily: FONT.ui }}>/10</div>
              <CISOBadge label={d.governance.effectivenessTier} color={getTierColor(d.governance.effectivenessTier)} />
            </div>
            <div style={{ flex: 1 }}>
              {d.governance.metrics.map((m, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: i < d.governance.metrics.length - 1 ? `1px solid ${COLORS.border}` : 'none' }}>
                  <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>{m.icon} {m.label}</span>
                  <span style={{
                    fontSize: 11, fontFamily: FONT.mono, fontWeight: 600,
                    color: m.status === 'not-configured' ? COLORS.textDim : m.status === 'critical' ? COLORS.danger : COLORS.success,
                  }}>{m.value} / {m.target}</span>
                </div>
              ))}
            </div>
          </div>
          {/* Setup completion */}
          <div style={{ borderTop: `1px solid ${COLORS.border}`, marginTop: 12, paddingTop: 12 }}>
            <div style={{ fontSize: 10, color: COLORS.textMuted, marginBottom: 6, fontFamily: FONT.ui }}>
              Complete setup for full governance | {d.governance.setupCompletion.configured} of {d.governance.setupCompletion.total} configured
            </div>
            <ProgressBar value={(d.governance.setupCompletion.configured / d.governance.setupCompletion.total) * 100} color={COLORS.accent} height={4} />
          </div>
        </CISOCard>
      </div>
    </div>
  );
}

// ── Tab 2: Identity Risk ──

function IdentityRiskTab({ d }: { d: TenantData }) {
  const [expandedPillar, setExpandedPillar] = useState<number | null>(null);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* Pillar Breakdown */}
      <CISOCard>
        <SectionTitle>Risk Pillars</SectionTitle>
        <div style={{ fontSize: 10, color: COLORS.textMuted, marginBottom: 12, fontFamily: FONT.ui }}>Score scale: 0 = no risk · 100 = maximum risk</div>
        {d.pillars.map((p, i) => (
          <div key={i}>
            <div onClick={() => setExpandedPillar(expandedPillar === i ? null : i)} style={{
              display: 'grid', gridTemplateColumns: '200px 1fr 80px 120px', alignItems: 'center',
              padding: '10px 0', borderBottom: `1px solid ${COLORS.border}`, cursor: 'pointer',
            }}>
              <span style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui }}>{p.name}</span>
              <ProgressBar value={p.score} color={getPillarColor(p.score)} height={8} />
              <span style={{ fontSize: 16, fontWeight: 700, fontFamily: FONT.mono, color: getPillarColor(p.score), textAlign: 'center' as const }}>{p.score}</span>
              <span style={{ fontSize: 11, color: COLORS.textMuted, fontFamily: FONT.mono, textAlign: 'right' as const }}>
                <DN navigateTo={pillarNav(p.name)}>{p.identityCount} identities</DN>
              </span>
            </div>
            {expandedPillar === i && p.subMetrics.length > 0 && (
              <div style={{ background: COLORS.surfaceAlt, padding: '10px 16px', borderBottom: `1px solid ${COLORS.border}` }}>
                {p.subMetrics.map((sm, j) => {
                  const smNav = sm.name.toLowerCase().includes('dormant') ? '/identities?dormant=true' :
                    sm.name.toLowerCase().includes('unowned') || sm.name.toLowerCase().includes('ownership') ? '/identities?owner=none' :
                    sm.name.toLowerCase().includes('owner') || sm.name.toLowerCase().includes('tenant') ? '/identities?privileged=true' :
                    sm.name.toLowerCase().includes('priv') || sm.name.toLowerCase().includes('high-priv') ? '/identities?privileged=true' :
                    sm.name.toLowerCase().includes('expired') || sm.name.toLowerCase().includes('cert') ? '/identities?credential_status=expired' :
                    sm.name.toLowerCase().includes('mfa') ? '/identities?pillar=mfa-enforcement' :
                    sm.name.toLowerCase().includes('external') || sm.name.toLowerCase().includes('multi-tenant') ? '/identities?category=service_principal' :
                    sm.name.toLowerCase().includes('guest') ? '/identities?category=guest' :
                    pillarNav(p.name);
                  return (
                  <div key={j} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '4px 0' }}>
                    <span style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.ui, width: 120 }}>{sm.name}</span>
                    <div style={{ flex: 1 }}><ProgressBar value={(sm.value / sm.max) * 100} color={COLORS.accent} height={4} /></div>
                    <DN navigateTo={smNav}><span style={{ fontSize: 10, fontFamily: FONT.mono, color: COLORS.text }}>{sm.value}</span></DN>
                    <span style={{ fontSize: 10, fontFamily: FONT.mono, color: COLORS.textDim }}>/{sm.max}</span>
                  </div>
                  );
                })}
              </div>
            )}
          </div>
        ))}
      </CISOCard>

      {/* KPI Cards — 5 columns per v3.0.1 */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 14 }}>
        {Object.entries(d.kpis).map(([key, kpi]) => {
          const isGhost = key === 'ghostAccounts';
          const valueColor = isGhost && kpi.value > 0 ? COLORS.danger : COLORS.text;
          const navTo = key === 'privilegedRoles' ? '/identities?privileged=true' :
            key === 'dormantPrivileged' ? '/identities?privileged=true&dormant=true' :
            key === 'ghostAccounts' ? '/identities?status=disabled&hasRoles=true' :
            key === 'subscriptionAccess' ? '/identities?pillar=subscription-access' :
            key === 'rbacModifiers' ? '/identities?pillar=rbac-modifiers' :
            '/identities';
          return (
            <CISOCard key={key} style={isGhost && kpi.value > 0 ? { borderColor: `${COLORS.danger}40` } : undefined}>
              <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textMuted, fontFamily: FONT.ui }}>
                {key.replace(/([A-Z])/g, ' $1').trim()}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
                <DN navigateTo={navTo}>
                  <span style={{ fontSize: 32, fontWeight: 700, fontFamily: FONT.mono, color: valueColor }}>{kpi.value}</span>
                </DN>
                {isGhost && kpi.value > 0 && (
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: COLORS.danger, animation: 'pulse 2s infinite' }} />
                )}
              </div>
              <div style={{ fontSize: 11, color: COLORS.textMuted, fontFamily: FONT.ui, marginTop: 2 }}>{kpi.subtitle}</div>
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
          <StatBox label="Risk" value={<DN navigateTo="/identities?risk=high,critical">{d.blastRadius.highRisk}</DN>} color={COLORS.danger} />
          <StatBox label="Low" value={<DN navigateTo="/identities?risk=low,medium">{d.blastRadius.lowRisk}</DN>} color={COLORS.success} />
          <StatBox label="Orphaned" value={<DN navigateTo="/identities?owner=none">{d.blastRadius.orphaned}</DN>} color={COLORS.warning} />
        </div>
        <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textMuted, marginBottom: 10, fontFamily: FONT.ui }}>Category Scores</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
          {d.blastRadius.categories.map((cat, i) => (
            <div key={i} style={{ textAlign: 'center' as const }}>
              <div style={{ fontSize: 11, color: COLORS.textMuted, fontFamily: FONT.ui, marginBottom: 4 }}>{cat.name}</div>
              <ProgressBar value={cat.score * 10} color={cat.color} height={4} />
              <div style={{ fontSize: 13, fontWeight: 700, fontFamily: FONT.mono, color: cat.color, marginTop: 4 }}>{cat.score}</div>
            </div>
          ))}
        </div>
      </CISOCard>
    </div>
  );
}

// ── Tab 3: Action Plan ──
// Rule 30 fix: Removed duplicate "Run Discovery Scan" system-action from remediation list.
// The scan button is rendered once at the top bar only.

function ActionPlanTab({ d, onPreview, onTicket }: { d: TenantData; onPreview: (r: Remediation) => void; onTicket: (r: Remediation) => void }) {
  const { withConnection } = useConnection();
  const [filter, setFilter] = useState<string>('all');
  const identityRemediations = d.remediations.filter(r => r.type === 'identity-remediation');
  const filtered = filter === 'all' ? identityRemediations :
    filter === 'auto' ? identityRemediations.filter(r => r.automation === 'Auto') :
    filter === 'manual' ? identityRemediations.filter(r => r.automation === 'Manual') :
    identityRemediations.filter(r => r.status === 'in-progress');
  const totalGain = identityRemediations.reduce((s, r) => s + r.gain, 0);
  const stages = ['new', 'planned', 'in-progress', 'verified', 'closed'];
  const stageLabels = ['Detected', 'Planned', 'In Progress', 'Verified', 'Closed'];
  const stageColors = [COLORS.textDim, COLORS.accent, COLORS.warning, COLORS.success, COLORS.textDim];

  const handleScan = useCallback(() => {
    fetch(withConnection('/api/runs/trigger'), { method: 'POST' }).catch(() => {});
  }, [withConnection]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Top bar — Rule 30: single scan button, no system-action duplicates */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <button onClick={handleScan} style={{
          padding: '7px 16px', borderRadius: 6, fontSize: 11, fontWeight: 600,
          background: COLORS.accent, color: '#fff', border: 'none', cursor: 'pointer', fontFamily: FONT.ui,
        }}>Run Discovery Scan</button>
        <span style={{ fontSize: 10, color: COLORS.textMuted, marginLeft: 'auto', fontFamily: FONT.ui }}>
          Last scan: {new Date(d.tenant.lastScan).toLocaleString()}
        </span>
      </div>

      {/* Lifecycle legend */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        {stages.map((s, i) => (
          <React.Fragment key={s}>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10, color: stageColors[i], fontFamily: FONT.ui }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: stageColors[i], border: s === 'new' ? `2px solid ${COLORS.textDim}` : 'none' }} />
              {stageLabels[i]}
            </span>
            {i < stages.length - 1 && <span style={{ color: COLORS.textDim, fontSize: 10 }}>→</span>}
          </React.Fragment>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 6 }}>
        {['all', 'auto', 'manual', 'in-progress'].map(f => (
          <button key={f} onClick={() => setFilter(f)} style={{
            padding: '4px 12px', borderRadius: 4, fontSize: 10, fontWeight: 600,
            background: filter === f ? COLORS.accentSoft : 'transparent',
            color: filter === f ? COLORS.accent : COLORS.textMuted,
            border: `1px solid ${filter === f ? `${COLORS.accent}40` : COLORS.border}`,
            cursor: 'pointer', fontFamily: FONT.ui, textTransform: 'capitalize' as const,
          }}>{f === 'all' ? 'All' : f === 'auto' ? 'Auto Only' : f === 'manual' ? 'Manual Only' : 'In Progress'}</button>
        ))}
      </div>

      {/* Remediation cards */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {filtered.map((r, i) => <RemediationCard key={r.id} item={r} index={i} onPreview={onPreview} onTicket={onTicket} />)}
      </div>

      {/* Total bar */}
      <div style={{
        background: COLORS.successSoft, border: `1px solid ${COLORS.success}2e`,
        borderRadius: 8, padding: '12px 18px', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      }}>
        <span style={{ fontSize: 12, color: COLORS.textMuted, fontFamily: FONT.ui }}>Total potential gain</span>
        <span style={{ fontSize: 18, fontWeight: 700, color: COLORS.success, fontFamily: FONT.mono }}>
          +{totalGain} pts → {d.projection.remediated.score.toFixed(1)}
        </span>
      </div>
    </div>
  );
}

// ── Tab 4: Control & Governance ──
// Rule 31 fix: Governance ring displays raw effectivenessScore (e.g. "1"), not score*10.

function ControlGovernanceTab({ d }: { d: TenantData }) {
  const navigate = useNavigate();
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* Governance Metric Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
        {d.governance.metrics.map((m, i) => (
          <CISOCard key={i}>
            <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textMuted, fontFamily: FONT.ui }}>{m.icon} {m.label}</div>
            <div style={{
              fontSize: 28, fontWeight: 700, fontFamily: FONT.mono, marginTop: 6,
              color: m.status === 'not-configured' ? COLORS.textDim : m.status === 'critical' ? COLORS.danger : COLORS.success,
            }}>{m.value}</div>
            <div style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.ui, marginTop: 4 }}>Target: {m.target}</div>
            {m.status === 'not-configured' && (
              <button onClick={() => navigate('/settings/governance')} style={{
                marginTop: 8, padding: '4px 10px', borderRadius: 4, fontSize: 10,
                background: COLORS.accentSoft, color: COLORS.accent, border: `1px solid ${COLORS.accent}30`,
                cursor: 'pointer', fontFamily: FONT.ui,
              }}>Configure →</button>
            )}
          </CISOCard>
        ))}
      </div>

      {/* Two-column: Control Failures + Governance Ring */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 }}>
        <CISOCard>
          <SectionTitle>Control Failures</SectionTitle>
          {d.governance.controlFailures.map((group, gi) => (
            <div key={gi} style={{ marginBottom: 16 }}>
              <div style={{
                fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em',
                color: group.type.includes('PREVENTIVE') ? COLORS.danger : COLORS.warning,
                marginBottom: 8, fontFamily: FONT.ui,
              }}>▸ {group.type}</div>
              {group.items.map((item, ii) => {
                const cfNav = item.label.toLowerCase().includes('pim') || item.label.toLowerCase().includes('privilege outside') ? '/identities?privileged=true' :
                  item.label.toLowerCase().includes('disabled') || item.label.toLowerCase().includes('ghost') ? '/identities?status=disabled&hasRoles=true' :
                  item.label.toLowerCase().includes('ownership') || item.label.toLowerCase().includes('unowned') ? '/identities?owner=none' :
                  item.label.toLowerCase().includes('dormant') ? '/identities?privileged=true&dormant=true' :
                  item.label.toLowerCase().includes('credential') || item.label.toLowerCase().includes('expired') ? '/identities?credential_status=expired' :
                  '/identities';
                return (
                <div key={ii} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: `1px solid ${COLORS.border}` }}>
                  <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>● {item.label}</span>
                  <DN navigateTo={cfNav}>
                    <span style={{ fontSize: 11, fontWeight: 600, fontFamily: FONT.mono, color: item.color }}>{item.count}</span>
                  </DN>
                </div>);
              })}
            </div>
          ))}
        </CISOCard>

        <CISOCard>
          <SectionTitle>Governance Effectiveness</SectionTitle>
          <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
            {/* Rule 31 fix: Use effectivenessScore directly for display,
                ring arc uses score*10 for visual proportion but displayValue shows raw integer */}
            <ScoreRing
              score={d.governance.effectivenessScore * 10}
              size={80} strokeWidth={5}
              color={getTierColor(d.governance.effectivenessTier)}
              displayValue={String(d.governance.effectivenessScore)}
            />
            <div>
              <div style={{ fontSize: 24, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.text }}>{d.governance.effectivenessScore}/10</div>
              <CISOBadge label={d.governance.effectivenessTier} color={getTierColor(d.governance.effectivenessTier)} />
              <div style={{ marginTop: 6 }}>
                <CISOBadge label={d.governance.maturityLevel} color={COLORS.textMuted} />
              </div>
            </div>
          </div>
        </CISOCard>
      </div>
    </div>
  );
}

// ── Tab 5: Compliance & Evidence ──
// Rule 32 fix: informational note when all frameworks share the same score.
// Rule 35 fix: Export triggers CSV download, Details navigates to /compliance.

function ComplianceEvidenceTab({ d }: { d: TenantData }) {
  const navigate = useNavigate();
  const grouped = useMemo(() => {
    const groups: Record<string, ComplianceFramework[]> = {};
    d.compliance.frameworks.forEach(fw => {
      if (!groups[fw.type]) groups[fw.type] = [];
      groups[fw.type].push(fw);
    });
    return groups;
  }, [d.compliance.frameworks]);
  const typeIcons: Record<string, string> = { 'Industry': '🏢', 'Benchmark': '📐', 'Core Governance': '🛡️' };

  // Rule 32: detect if all frameworks have the same score
  const allScores = d.compliance.frameworks.map(fw => fw.score);
  const allSameScore = allScores.length > 1 && allScores.every(s => s === allScores[0]);

  // Rule 35: Export CSV handler
  const handleExportAll = useCallback(() => {
    const header = 'Framework,Type,Score,Total Controls,Failed Controls,Status,Trend\n';
    const rows = d.compliance.frameworks.map(fw =>
      `"${fw.name}","${fw.type}",${fw.score},${fw.totalControls},${fw.failedControls},"${fw.status}",${fw.trend}`
    ).join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'compliance_frameworks.csv'; a.click();
    URL.revokeObjectURL(url);
  }, [d.compliance.frameworks]);

  const handleExportSingle = useCallback((fw: ComplianceFramework) => {
    const header = 'Framework,Type,Score,Total Controls,Failed Controls,Status,Trend\n';
    const row = `"${fw.name}","${fw.type}",${fw.score},${fw.totalControls},${fw.failedControls},"${fw.status}",${fw.trend}`;
    const blob = new Blob([header + row], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `${fw.id}_compliance.csv`; a.click();
    URL.revokeObjectURL(url);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* Top bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <CISOBadge label="Identity Controls Only" color={COLORS.accent} />
        <span style={{ fontSize: 11, color: COLORS.textMuted, fontFamily: FONT.ui }}>{d.compliance.frameworks.length} frameworks · All initial assessment</span>
        <button onClick={handleExportAll} style={{
          marginLeft: 'auto', padding: '5px 12px', borderRadius: 5, fontSize: 10, fontWeight: 600,
          background: 'transparent', color: COLORS.textMuted, border: `1px solid ${COLORS.border}`,
          cursor: 'pointer', fontFamily: FONT.ui,
        }}>Export All</button>
      </div>

      {/* Rule 32: Informational note about identical scores */}
      {allSameScore && (
        <div style={{
          background: COLORS.accentSoft, border: `1px solid ${COLORS.accent}2e`,
          borderRadius: 8, padding: '10px 14px', fontSize: 11, color: COLORS.textMuted, fontFamily: FONT.ui,
          lineHeight: 1.5,
        }}>
          All frameworks currently share the same score ({allScores[0]}/100). This is expected for initial assessments — scores will diverge as framework-specific controls are evaluated over subsequent scans.
        </div>
      )}

      {/* Framework Groups */}
      {Object.entries(grouped).map(([type, frameworks]) => (
        <div key={type}>
          <div style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, marginBottom: 10, fontFamily: FONT.ui }}>
            {typeIcons[type] || '📋'} {type} ({frameworks.length})
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
            {frameworks.map(fw => (
              <CISOCard key={fw.id} style={{ padding: '14px 16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <ScoreRing score={fw.score} size={44} strokeWidth={3} color={getScoreColor(fw.score)} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui }}>{fw.name}</div>
                    <div style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.ui }}>
                      {fw.totalControls} controls · <DN navigateTo={`/identities?pillar=compliance-${fw.id}`}>{fw.failedControls}</DN> failures
                    </div>
                  </div>
                </div>
                <ProgressBar value={fw.score} color={getScoreColor(fw.score)} height={4} />
                <div style={{ display: 'flex', gap: 6, marginTop: 10 }}>
                  {/* Rule 35 fix: Export triggers CSV download */}
                  <button onClick={() => handleExportSingle(fw)} style={{
                    flex: 1, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 600,
                    background: 'transparent', color: COLORS.textMuted, border: `1px solid ${COLORS.border}`,
                    cursor: 'pointer', fontFamily: FONT.ui,
                  }}>Export</button>
                  {/* Rule 35 fix: Details navigates to compliance page */}
                  <button onClick={() => navigate('/compliance')} style={{
                    flex: 1, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 600,
                    background: COLORS.accentSoft, color: COLORS.accent, border: `1px solid ${COLORS.accent}30`,
                    cursor: 'pointer', fontFamily: FONT.ui,
                  }}>Details</button>
                </div>
              </CISOCard>
            ))}
          </div>
        </div>
      ))}

      {/* Bottom: Maturity + Progress */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 }}>
        <CISOCard>
          <SectionTitle>Control Maturity</SectionTitle>
          {Object.entries(d.compliance.maturity).map(([key, val]) => (
            <div key={key} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: `1px solid ${COLORS.border}` }}>
              <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>● {key.charAt(0).toUpperCase() + key.slice(1)}</span>
              <span style={{ fontSize: 11, fontWeight: 600, fontFamily: FONT.mono, color: COLORS.text }}>{val}</span>
            </div>
          ))}
        </CISOCard>
        <CISOCard>
          <SectionTitle>Progress</SectionTitle>
          <div style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>Remediation Progress</span>
              <span style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.text }}>{d.compliance.progress.remediation}%</span>
            </div>
            <ProgressBar value={d.compliance.progress.remediation} color={COLORS.accent} />
          </div>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>IA Governance</span>
              <span style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.text }}>{d.compliance.progress.iaGovernance}%</span>
            </div>
            <ProgressBar value={d.compliance.progress.iaGovernance} color={COLORS.warning} />
          </div>
        </CISOCard>
      </div>
    </div>
  );
}

// ── Tab 6: Risk Movement ──

function RiskMovementTab({ d }: { d: TenantData }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* Score Trajectory */}
      <CISOCard>
        <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
          <div>
            <div style={{ fontSize: 36, fontWeight: 700, fontFamily: FONT.mono, color: getTierColor(d.riskScore.tier) }}>{d.riskScore.current.toFixed(1)}</div>
            <CISOBadge label={d.riskScore.tier} color={getTierColor(d.riskScore.tier)} />
          </div>
          <div style={{ flex: 1 }}>
            <Sparkline data={d.riskMovement.trajectory} width={400} height={80} color={getTierColor(d.riskScore.tier)} />
          </div>
        </div>
      </CISOCard>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 }}>
        {/* Risk Movement Table */}
        <CISOCard>
          <SectionTitle>Risk Movement</SectionTitle>
          {d.riskMovement.changes.map((ch, i) => (
            <div key={i} style={{ display: 'grid', gridTemplateColumns: '1fr 60px 20px 60px 30px', alignItems: 'center', padding: '6px 0', borderBottom: `1px solid ${COLORS.border}` }}>
              <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>{ch.label}</span>
              <span style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.textMuted, textAlign: 'right' as const }}>{ch.before}</span>
              <span style={{ fontSize: 11, color: COLORS.textMuted, textAlign: 'center' as const }}>→</span>
              <DN navigateTo={
                ch.label === 'Critical Identities' ? '/identities?risk_level=critical' :
                ch.label === 'High-Risk Identities' ? '/identities?risk_level=high' :
                ch.label === 'Ghost Accounts' ? '/identities?status=disabled&hasRoles=true' :
                ch.label === 'New Identities' ? '/identities' :
                ch.label === 'Removed' ? '/identities?status=disabled' :
                ch.label === 'Total Identities' ? '/identities' :
                '/identities'
              }>
                <span style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.text }}>{ch.after}</span>
              </DN>
              <span style={{
                fontSize: 12, textAlign: 'right' as const,
                color: ch.direction === 'up' ? COLORS.danger : ch.direction === 'down' ? COLORS.success : COLORS.textMuted,
              }}>{ch.direction === 'up' ? '↑' : ch.direction === 'down' ? '↓' : '—'}</span>
            </div>
          ))}
        </CISOCard>

        {/* Consequence Panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Most Changed */}
          <CISOCard style={{ background: COLORS.dangerSoft, borderColor: `${COLORS.danger}30` }}>
            <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textMuted, fontFamily: FONT.ui }}>Most Changed Risk</div>
            <div style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui, marginTop: 4 }}>{d.riskMovement.mostChanged.name}</div>
            <div style={{ fontSize: 12, fontFamily: FONT.mono, color: COLORS.danger, marginTop: 2 }}>Score {d.riskMovement.mostChanged.score}/100</div>
          </CISOCard>

          {/* If No Action */}
          <CISOCard>
            <SectionTitle>If No Action Taken</SectionTitle>
            {d.projection.noAction.consequences.map((c, i) => (
              <div key={i} style={{ display: 'flex', gap: 6, padding: '4px 0', fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>
                <span style={{ color: COLORS.danger }}>▸</span>
                <span>{c}</span>
              </div>
            ))}
            <div style={{
              marginTop: 12, padding: '8px 12px', borderRadius: 6,
              background: COLORS.dangerSoft, border: `1px solid ${COLORS.danger}2e`,
              fontSize: 10, color: COLORS.danger, fontFamily: FONT.ui,
            }}>
              Estimated Breach Impact: {d.projection.noAction.breachImpact}
            </div>
          </CISOCard>
        </div>
      </div>

      {/* Scan Metadata */}
      <CISOCard style={{ padding: '10px 20px' }}>
        <div style={{ display: 'flex', gap: 24, justifyContent: 'center', flexWrap: 'wrap' as const }}>
          {Object.entries(d.riskMovement.scanMeta).map(([key, val]) => (
            <div key={key} style={{ textAlign: 'center' as const }}>
              <div style={{ fontSize: 9, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textMuted, fontFamily: FONT.ui }}>{key}</div>
              <div style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.text, marginTop: 2 }}>
                {key === 'lastRun' ? new Date(val).toLocaleString() : val}
              </div>
            </div>
          ))}
        </div>
      </CISOCard>
    </div>
  );
}

// ─── Tab Configuration ───────────────────────────────────────────

type CISOTab = 'exec' | 'risk' | 'action' | 'governance' | 'compliance' | 'movement';

const TAB_CONFIG: { id: CISOTab; label: string }[] = [
  { id: 'exec', label: 'Executive Summary' },
  { id: 'risk', label: 'Identity Risk' },
  { id: 'action', label: 'Action Plan' },
  { id: 'governance', label: 'Control & Governance' },
  { id: 'compliance', label: 'Compliance & Evidence' },
  { id: 'movement', label: 'Risk Movement' },
];

// ─── Main Dashboard Component ────────────────────────────────────

export default function CISODashboard() {
  const [activeTab, setActiveTab] = useState<CISOTab>('exec');
  const { data, loading } = useCISOData();

  // v3.0.5: Preview Changes + Create Ticket state (DrillDownPanel removed)
  const [previewRem, setPreviewRem] = useState<Remediation | null>(null);
  const [ticketRem, setTicketRem] = useState<Remediation | null>(null);

  // Tab content renderer
  const renderTab = () => {
    switch (activeTab) {
      case 'exec': return <ExecSummaryTab d={data} onPreview={setPreviewRem} onTicket={setTicketRem} />;
      case 'risk': return <IdentityRiskTab d={data} />;
      case 'action': return <ActionPlanTab d={data} onPreview={setPreviewRem} onTicket={setTicketRem} />;
      case 'governance': return <ControlGovernanceTab d={data} />;
      case 'compliance': return <ComplianceEvidenceTab d={data} />;
      case 'movement': return <RiskMovementTab d={data} />;
    }
  };

  if (loading) {
    return (
      <div style={{
        minHeight: 'calc(100vh - 56px)', background: COLORS.bg,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        borderRadius: '12px 0 0 0',
      }}>
        <div style={{ textAlign: 'center' as const }}>
          <div style={{
            width: 40, height: 40, borderRadius: '50%',
            border: `3px solid ${COLORS.border}`, borderTopColor: COLORS.accent,
            animation: 'spin 1s linear infinite', margin: '0 auto 12px',
          }} />
          <div style={{ fontSize: 12, color: COLORS.textMuted, fontFamily: FONT.ui }}>Loading Executive Summary...</div>
        </div>
        <style>{`@keyframes spin { to { transform: rotate(360deg) } } @keyframes pulse { 0%, 100% { opacity: 1 } 50% { opacity: 0.4 } }`}</style>
      </div>
    );
  }

  return (
    <div style={{ minHeight: 'calc(100vh - 56px)', background: COLORS.bg, fontFamily: FONT.ui, borderRadius: '12px 0 0 0' }}>
      {/* Font import */}
      <link rel="stylesheet" href={FONT_LINK} />
      <style>{`@keyframes spin { to { transform: rotate(360deg) } } @keyframes pulse { 0%, 100% { opacity: 1 } 50% { opacity: 0.4 } }`}</style>

      {/* Tab Bar */}
      <div style={{
        borderBottom: `1px solid ${COLORS.border}`, display: 'flex', padding: '0 24px',
        background: COLORS.surface, borderRadius: '12px 0 0 0',
      }}>
        {TAB_CONFIG.map(t => (
          <div key={t.id} onClick={() => setActiveTab(t.id)} style={{
            padding: '12px 18px', cursor: 'pointer', fontSize: 12, fontFamily: FONT.ui,
            color: activeTab === t.id ? COLORS.accent : COLORS.textMuted,
            fontWeight: activeTab === t.id ? 600 : 400,
            borderBottom: `2px solid ${activeTab === t.id ? COLORS.accent : 'transparent'}`,
            transition: 'all 0.15s ease',
          }}>
            {t.label}
          </div>
        ))}

        {/* Scan status indicator */}
        <div style={{
          marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8,
          fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.ui,
        }}>
          <span>Updated {new Date(data.tenant.lastScan).toLocaleTimeString()}</span>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: COLORS.success, animation: 'pulse 2s infinite' }} />
        </div>
      </div>

      {/* Tab Content */}
      <div style={{ padding: 24 }}>
        {renderTab()}
      </div>

      {/* v3.0.5 Panels */}
      {previewRem && <PreviewChangesPanel rem={previewRem} data={data} onClose={() => setPreviewRem(null)} />}
      {ticketRem && <CreateTicketModal rem={ticketRem} data={data} onClose={() => setTicketRem(null)} />}
    </div>
  );
}
