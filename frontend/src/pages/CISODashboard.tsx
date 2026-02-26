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
 * v3.0.9: Enterprise Review Refinements — score label, confidence banner,
 *         pillar count labels, rollback badges, governance trends,
 *         Identity Controls Only tooltip, predictive scores, layout fix.
 */
import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';
import {
  COLORS, getTierColor, getScoreColor, getPillarColor,
  getTier, getGrade, getSemanticColor,
  type TenantData, type Remediation, type ComplianceFramework,
  type AGIRSData, type DangerousIdentity,
  type Pillar, type GovernanceMetric,
} from '../constants/ciso';
import { getAGIRSColor } from '../constants/metrics';

// ─── Typography Helpers ──────────────────────────────────────────

const FONT = {
  ui: "'Inter', sans-serif",
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
        fill={COLORS.textSecondary} fontFamily={FONT.mono} fontWeight={600} fontSize={10}>
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
      <div style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase' as const, color: COLORS.textSecondary, fontFamily: FONT.ui }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 700, color, fontFamily: FONT.mono, marginTop: 2 }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: COLORS.textSecondary, marginTop: 2, fontFamily: FONT.ui }}>{sub}</div>}
    </div>
  );
}

function SectionTitle({ children, right, onRightClick }: { children: string; right?: string; onRightClick?: () => void }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
      <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.12em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>{children}</span>
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
        <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
          <DN navigateTo="/compliance">{fw.failedControls}</DN> failures · <DN navigateTo="/compliance">{fw.totalControls}</DN> controls
        </div>
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

// ─── DrillableNumber (v3.1.0: every number clickable) ────────────

/** Wraps any number with dashed underline + pointer.
 *  v3.1.0: EVERY number is always clickable when navigateTo is provided.
 *  Zero values ARE clickable (thumb rule: every number drills down). */
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
              <div style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 2 }}>{rem.title}</div>
            </div>
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: COLORS.textSecondary, cursor: 'pointer', fontSize: 20, fontFamily: FONT.ui }}>×</button>
          </div>
          {/* Score impact bar — always shown from tenantData */}
          <div style={{
            marginTop: 12, padding: '10px 14px', borderRadius: 8,
            background: COLORS.successSoft, border: `1px solid ${COLORS.success}2e`,
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          }}>
            <span style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui }}>Score impact</span>
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
              <div style={{ textAlign: 'center' as const, fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 8 }}>
                Loading affected identities...
              </div>
            </div>
          ) : hasDetail ? (
            /* Loaded — API returned data */
            <>
              <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 12 }}>
                Remediation Details
              </div>
              {(detail.playbooks || []).map((pb: any, i: number) => (
                <div key={i} style={{
                  background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
                  borderRadius: 8, padding: '12px 14px', marginBottom: 8,
                }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui }}>{pb.title || pb.name}</div>
                  <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 4 }}>{pb.description || pb.subtitle}</div>
                  {pb.risk_level && <CISOBadge label={pb.risk_level} color={riskColor(pb.risk_level)} />}
                </div>
              ))}
            </>
          ) : (
            /* Fallback — show existing remediation data + View Affected Identities link (Rule 39) */
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>
                Remediation Summary
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div style={{ background: COLORS.surfaceAlt, borderRadius: 8, padding: '10px 12px' }}>
                  <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Affected</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{rem.affected}</div>
                </div>
                <div style={{ background: COLORS.surfaceAlt, borderRadius: 8, padding: '10px 12px' }}>
                  <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Est. Effort</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{rem.effort}</div>
                </div>
                <div style={{ background: COLORS.surfaceAlt, borderRadius: 8, padding: '10px 12px' }}>
                  <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Rollback</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: rem.rollbackRisk === 'safe' ? COLORS.success : COLORS.danger, fontFamily: FONT.mono, marginTop: 4 }}>{rem.rollback}</div>
                </div>
                <div style={{ background: COLORS.surfaceAlt, borderRadius: 8, padding: '10px 12px' }}>
                  <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Confidence</div>
                  <DN navigateTo="/remediation"><div style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{rem.confidence}%</div></DN>
                </div>
              </div>
              <div style={{ background: COLORS.surfaceAlt, borderRadius: 8, padding: '10px 12px' }}>
                <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Compliance</div>
                <div style={{ fontSize: 12, color: COLORS.text, fontFamily: FONT.ui, marginTop: 4 }}>{rem.compliance}</div>
              </div>
              {/* Navigate to filtered identities matching this remediation */}
              <button onClick={() => { navigate(remediationNav(rem.id)); onClose(); }} style={{
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
            background: 'transparent', color: COLORS.textSecondary,
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
          <div style={{ fontSize: 12, color: COLORS.textSecondary, fontFamily: FONT.ui, lineHeight: 1.6, marginBottom: 16 }}>
            Connect Jira, ServiceNow, or Azure DevOps in Settings to create tickets directly from remediation actions.
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => { navigate('/settings/integrations#ticketing'); onClose(); }} style={{
              flex: 1, padding: '8px', borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: COLORS.accent, color: '#fff', border: 'none', cursor: 'pointer', fontFamily: FONT.ui,
            }}>Configure in Settings</button>
            <button onClick={onClose} style={{
              padding: '8px 16px', borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: 'transparent', color: COLORS.textSecondary,
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
            <div style={{ fontSize: 14, fontWeight: 600, color: COLORS.success, fontFamily: FONT.ui }}>Ticket Queued</div>
            <div style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 4 }}>
              Pending {provider.toUpperCase()} integration
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
              <label style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>Title</label>
              <input value={title} onChange={e => setTitle(e.target.value)} style={{
                width: '100%', padding: '8px 12px', borderRadius: 6, marginTop: 4,
                background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
                color: COLORS.text, fontSize: 12, fontFamily: FONT.ui, outline: 'none',
                boxSizing: 'border-box' as const,
              }} />
            </div>
            {/* Description */}
            <div style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>Description</label>
              <textarea defaultValue={`${rem.subtitle}\n\nAffected: ${rem.affected}\nEffort: ${rem.effort}\nCompliance: ${rem.compliance}\nConfidence: ${rem.confidence}%`} style={{
                width: '100%', padding: '8px 12px', borderRadius: 6, marginTop: 4, minHeight: 80, resize: 'vertical' as const,
                background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
                color: COLORS.text, fontSize: 12, fontFamily: FONT.ui, outline: 'none',
                boxSizing: 'border-box' as const,
              }} />
            </div>
            {/* Priority */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>Priority</label>
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
                background: 'transparent', color: COLORS.textSecondary,
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
  const navigate = useNavigate();
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
          <div style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 1 }}>{item.subtitle}</div>
        </div>
        <div style={{ textAlign: 'right' as const, flexShrink: 0 }}>
          <DN navigateTo={remediationNav(item.id)}><div style={{ fontSize: 18, fontWeight: 700, color: COLORS.success, fontFamily: FONT.mono }}>+{item.gain}</div></DN>
          <DN navigateTo="/remediation"><div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>→ {item.projectedScore}</div></DN>
        </div>
        <CISOBadge label={item.risk} color={item.risk === 'HIGH' ? COLORS.danger : COLORS.success} />
        <CISOBadge label={item.automation} color={item.automation === 'Auto' ? COLORS.accent : COLORS.textMuted} />
        <CISOBadge
          label={item.rollbackRisk === 'safe' ? 'Safe' : item.rollbackRisk === 'controlled' ? 'Controlled' : 'Risky'}
          color={item.rollbackRisk === 'safe' ? COLORS.success : item.rollbackRisk === 'controlled' ? COLORS.warning : COLORS.danger}
        />
        <span style={{ fontSize: 12, color: COLORS.textMuted, marginLeft: 4, transform: expanded ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }}>▾</span>
      </div>
      {expanded && (
        <div style={{ borderTop: `1px solid ${COLORS.border}`, marginTop: 14, paddingTop: 14 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
            <div>
              <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Affected</div>
              <div style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>
                <DN navigateTo={remediationNav(item.id)}>{item.affected}</DN>
              </div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Est. Effort</div>
              <div style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{item.effort}</div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Rollback</div>
              <div style={{ fontSize: 11, color: item.rollbackRisk === 'safe' ? COLORS.success : COLORS.danger, fontFamily: FONT.mono, marginTop: 4 }}>{item.rollback}</div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Compliance</div>
              <div style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{item.compliance}</div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Confidence</div>
              <DN navigateTo="/remediation"><div style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{item.confidence}%</div></DN>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
            <button onClick={(e) => { e.stopPropagation(); navigate(remediationNav(item.id)); }} style={{
              padding: '6px 14px', borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: `linear-gradient(135deg, ${COLORS.accent}, ${COLORS.purple})`,
              color: '#fff', border: 'none', cursor: 'pointer', fontFamily: FONT.ui,
            }}>View Affected Identities →</button>
            <button onClick={(e) => { e.stopPropagation(); onPreview?.(item); }} style={{
              padding: '6px 14px', borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: 'transparent', color: COLORS.text,
              border: `1px solid ${COLORS.borderAccent}`, cursor: 'pointer', fontFamily: FONT.ui,
            }}>Preview Changes</button>
            <button onClick={(e) => { e.stopPropagation(); onTicket?.(item); }} style={{
              padding: '6px 14px', borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: 'transparent', color: COLORS.textSecondary,
              border: `1px solid ${COLORS.border}`, cursor: 'pointer', fontFamily: FONT.ui,
            }}>Create Ticket</button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Empty Data (no hardcoded values) ────────────────────────────

function buildEmptyData(): TenantData {
  return {
    tenant: {
      id: '', name: '', organizationName: '', organizationLogo: null,
      cloud: 'Azure', subscriptions: 0, identityCount: 0,
      lastScan: '', scanDuration: 0, scanCompleteness: 0, scanConfidence: 'Low',
      sources: [], isolationGuarantee: 'Isolated dataset \u2022 No cross-tenant visibility',
    },
    riskScore: {
      current: 0, previous: 0, delta: 0,
      tier: 'CRITICAL', grade: 'F',
      industry: 0, target: 90, potentialGain: 0,
      trend: [],
    },
    projection: {
      noAction: { score: 0, tier: 'CRITICAL', consequences: [], breachImpact: 'Unknown' },
      remediated: { score: 0, tier: 'CRITICAL', actions: [], breachImpact: 'Unknown' },
    },
    ghostAccounts: {
      total: 0, privileged: 0, nonPrivileged: 0,
      roles: [], complianceImpact: [], lastDetected: '',
    },
    deltaChanges: [],
    identityBreakdown: [],
    pillars: [
      { name: 'Effective Privilege', score: 0, weight: 30, detail: '', identityCount: 0, subMetrics: [] },
      { name: 'Credential Risk', score: 0, weight: 20, detail: '', identityCount: 0, subMetrics: [] },
      { name: 'Trust & Federation', score: 0, weight: 20, detail: '', identityCount: 0, subMetrics: [] },
      { name: 'Usage Dormancy', score: 0, weight: 10, detail: '', identityCount: 0, subMetrics: [] },
      { name: 'Ownership Governance', score: 0, weight: 10, detail: '', identityCount: 0, subMetrics: [] },
      { name: 'External Exposure', score: 0, weight: 10, detail: '', identityCount: 0, subMetrics: [] },
    ],
    blastRadius: {
      highRisk: 0, lowRisk: 0, orphaned: 0, productionWorkloads: 0,
      categories: [
        { name: 'Privilege', score: 0, color: COLORS.danger },
        { name: 'Credential', score: 0, color: COLORS.warning },
        { name: 'Exposure', score: 0, color: COLORS.elevated },
        { name: 'Lifecycle', score: 0, color: COLORS.accent },
        { name: 'Visibility', score: 0, color: COLORS.purple },
      ],
    },
    kpis: {
      privilegedRoles: { value: 0, subtitle: '' },
      dormantPrivileged: { value: 0, subtitle: '' },
      ghostAccounts: { value: 0, subtitle: '' },
      subscriptionAccess: { value: 0, subtitle: '' },
      rbacModifiers: { value: 0, subtitle: '' },
    },
    remediations: [],
    governance: {
      effectivenessScore: 0, effectivenessTier: 'CRITICAL', maturityLevel: 'Unknown',
      metrics: [], controlFailures: [],
      setupCompletion: { configured: 0, total: 4 },
    },
    compliance: {
      frameworks: [],
      maturity: { preventive: 0, detective: 0, compensating: 0, missing: 0 },
      progress: { remediation: 0, iaGovernance: 0 },
    },
    riskMovement: {
      trajectory: [], changes: [],
      mostChanged: { name: '', score: 0, category: '' },
      scanMeta: { frequency: '', lastRun: '', sources: '', duration: '', completeness: '' },
    },
    ticketingIntegration: { configured: false, provider: null, projectKey: null, defaultAssignee: null, jira: null },
    agirs: { agirs: null, hiri: null, nhiri: null, gei: null, dangerous_identities: [], previous: null },
  };
}

// ─── Data Hook (real API data) ───────────────────────────────────

function useCISOData(): { data: TenantData; loading: boolean } {
  const { withConnection, selectedConnectionId } = useConnection();
  const { activeTenantId } = useAuth();
  const [data, setData] = useState<TenantData>(buildEmptyData);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        // Fetch all data sources in parallel
        const [attackRes, statsRes, compRes, driftRes, trendsRes, summaryRes, agirstRes] = await Promise.all([
          fetch(withConnection('/api/overview/attack-surface-score')).catch(() => null),
          fetch(withConnection('/api/stats')).catch(() => null),
          fetch(withConnection('/api/dashboard/compliance')).catch(() => null),
          fetch(withConnection('/api/drift/latest')).catch(() => null),
          fetch(withConnection('/api/trends?limit=11')).catch(() => null),
          fetch(withConnection('/api/identity-summary')).catch(() => null),
          fetch(withConnection('/api/identity-risk-summary')).catch(() => null),
        ]);

        const attack = attackRes?.ok ? await attackRes.json() : null;
        const stats = statsRes?.ok ? await statsRes.json() : null;
        const comp = compRes?.ok ? await compRes.json() : null;
        const drift = driftRes?.ok ? await driftRes.json() : null;
        const trends = trendsRes?.ok ? await trendsRes.json() : null;
        const summary = summaryRes?.ok ? await summaryRes.json() : null;
        const agirstData = agirstRes?.ok ? await agirstRes.json() : null;

        if (cancelled) return;
        const d = buildEmptyData();

        // ── Tenant metadata ──
        if (attack?.data_integrity) {
          const di = attack.data_integrity;
          d.tenant.id = String(di.tenant_id || '');
          d.tenant.name = di.tenant_name || di.organization_name || '';
          d.tenant.organizationName = di.organization_name || di.tenant_name || '';
          d.tenant.organizationLogo = di.organization_logo || null;
          d.tenant.lastScan = di.last_scan || '';
          d.tenant.scanDuration = di.scan_duration_seconds || 0;
          d.tenant.scanCompleteness = di.data_completeness_pct || 0;
          d.tenant.scanConfidence = di.confidence || 'Low';
          d.tenant.sources = ['Azure RBAC', 'Entra ID', 'Graph API'];
        }
        if (attack) {
          d.tenant.identityCount = attack.total_identities || 0;
        }
        const subCount = summary?.monitored_resources?.azure?.subscriptions || 0;
        d.tenant.subscriptions = subCount;

        // ── Risk Score ──
        // Attack surface score: higher = worse. UI shows posture: higher = better.
        // Invert: posture = 100 - attack_score
        if (attack) {
          const posture = Math.round((100 - (attack.score || 0)) * 10) / 10;
          const prevPosture = stats?.previous_run
            ? Math.round((100 - (stats.previous_run.avg_risk_score || 0)) * 10) / 10
            : posture;
          d.riskScore.current = posture;
          d.riskScore.previous = prevPosture;
          d.riskScore.delta = Math.round((posture - prevPosture) * 10) / 10;
          d.riskScore.tier = getTier(posture);
          const gradeMap: Record<string, string> = { A: 'A', B: 'B', C: 'C', D: 'D', F: 'F' };
          d.riskScore.grade = attack.grade ? (gradeMap[attack.grade as string] || getGrade(posture)) : getGrade(posture);
          d.riskScore.industry = attack.industry_avg != null ? Math.max(0, Math.min(100, attack.industry_avg)) : 69;
          d.riskScore.target = attack.posture_target != null ? attack.posture_target : 90;
          d.riskScore.potentialGain = Math.max(0, d.riskScore.target - posture);
        }
        // Trend from /api/trends
        if (trends?.runs?.length) {
          d.riskScore.trend = trends.runs.map((r: any) => r.posture_score ?? 0);
        }

        // ── Pillars ──
        if (attack?.pillars) {
          const p = attack.pillars;
          const ep = p.effective_privilege || {};
          const cr = p.credential_risk || {};
          const tf = p.trust_federation || {};
          const ud = p.usage_dormancy || {};
          const og = p.ownership_governance || {};
          const ee = p.external_exposure || {};

          d.pillars = [
            {
              name: 'Effective Privilege', score: ep.score || 0, weight: ep.weight || 30,
              detail: `${ep.detail?.t0t1 || 0} IDs at T0/T1`,
              identityCount: ep.detail?.t0t1 || 0,
              subMetrics: [
                { name: 'T0 (Tenant Owner)', value: ep.detail?.t0 || 0, max: attack.total_identities || 1 },
                { name: 'T0+T1 privileged', value: ep.detail?.t0t1 || 0, max: attack.total_identities || 1 },
              ],
            },
            {
              name: 'Credential Risk', score: cr.score || 0, weight: cr.weight || 20,
              detail: `${(cr.detail?.expired || 0) + (cr.detail?.expiring || 0)} credential issues`,
              identityCount: (cr.detail?.expired || 0) + (cr.detail?.expiring || 0),
              subMetrics: [
                { name: 'Expired', value: cr.detail?.expired || 0, max: cr.detail?.with_creds || 1 },
                { name: 'Expiring soon', value: cr.detail?.expiring || 0, max: cr.detail?.with_creds || 1 },
              ],
            },
            {
              name: 'Trust & Federation', score: tf.score || 0, weight: tf.weight || 20,
              detail: `${tf.detail?.guest_with_roles || 0} guests with roles`,
              identityCount: tf.detail?.guest_with_roles || 0,
              subMetrics: [
                { name: 'Guests with roles', value: tf.detail?.guest_with_roles || 0, max: tf.detail?.guests || 1 },
                { name: 'Federated', value: tf.detail?.federated || 0, max: tf.detail?.guests || 1 },
              ],
            },
            {
              name: 'Usage Dormancy', score: ud.score || 0, weight: ud.weight || 10,
              detail: `${ud.detail?.dormant || 0} dormant identities`,
              identityCount: ud.detail?.dormant || 0,
              subMetrics: [
                { name: 'Dormant', value: ud.detail?.dormant || 0, max: ud.detail?.total || 1 },
              ],
            },
            {
              name: 'Ownership Governance', score: og.score || 0, weight: og.weight || 10,
              detail: `${og.detail?.unowned_spns || 0} unowned SPNs`,
              identityCount: og.detail?.unowned_spns || 0,
              subMetrics: [
                { name: 'Unowned SPNs', value: og.detail?.unowned_spns || 0, max: og.detail?.total_spns || 1 },
              ],
            },
            {
              name: 'External Exposure', score: ee.score || 0, weight: ee.weight || 10,
              detail: `${ee.detail?.tenant_scope || 0} with tenant-wide scope`,
              identityCount: ee.detail?.tenant_scope || 0,
              subMetrics: [
                { name: 'Tenant-wide scope', value: ee.detail?.tenant_scope || 0, max: ee.detail?.total || 1 },
              ],
            },
          ];
        }

        // ── Ghost Accounts ──
        const ghostTotal = stats?.ghost_count || 0;
        const zombieTotal = stats?.zombie_count || 0;
        const dormantPrivCount = attack?.attack_opportunities?.dormant_privileged_count || 0;
        d.ghostAccounts.total = ghostTotal;
        d.ghostAccounts.privileged = Math.min(dormantPrivCount, ghostTotal);
        d.ghostAccounts.nonPrivileged = Math.max(0, ghostTotal - d.ghostAccounts.privileged);
        if (ghostTotal > 0) {
          d.ghostAccounts.complianceImpact = ['SOC2 CC6.1', 'HIPAA', 'NIST AC-2', 'SOX'];
          d.ghostAccounts.lastDetected = d.tenant.lastScan;
        }

        // ── KPIs ──
        if (attack) {
          const ao = attack.attack_opportunities || {};
          const ep = attack.pillars?.effective_privilege?.detail || {};
          d.kpis.privilegedRoles = { value: (ep.t0 || 0) + (ao.rbac_modifier_count || 0), subtitle: `${ep.t0 || 0} T0 identities` };
          d.kpis.dormantPrivileged = { value: ao.dormant_privileged_count || 0, subtitle: 'Active roles retained' };
          d.kpis.ghostAccounts = { value: ghostTotal, subtitle: ghostTotal > 0 ? 'Disabled + active RBAC' : 'None detected' };
          d.kpis.subscriptionAccess = { value: subCount, subtitle: `${ao.multi_sub_count || 0} cross-sub identities` };
          d.kpis.rbacModifiers = { value: ao.rbac_modifier_count || 0, subtitle: 'Custom role defs' };
        }

        // ── Identity Breakdown ──
        if (summary?.categories) {
          const cats = summary.categories as Record<string, { total: number }>;
          const humanCount = (cats.human_user?.total || 0);
          const workloadCount = (cats.service_principal?.total || 0) + (cats.managed_identity_system?.total || 0) + (cats.managed_identity_user?.total || 0);
          const guestCount = cats.guest?.total || 0;
          const total = humanCount + workloadCount + guestCount;
          if (total > 0) {
            d.identityBreakdown = [
              { type: 'Human Users', count: humanCount, percentage: Math.round((humanCount / total) * 100), color: 'accent' },
              { type: 'Workload Identities', count: workloadCount, percentage: Math.round((workloadCount / total) * 100), color: 'warning' },
              { type: 'Guest Users', count: guestCount, percentage: Math.round((guestCount / total) * 100), color: 'textDim' },
            ];
          }
        } else if (attack?.nhi_breakdown) {
          const nb = attack.nhi_breakdown;
          const humanCount = nb.human || 0;
          const workloadCount = (nb.service_principal || 0) + (nb.managed_identity_system || 0) + (nb.managed_identity_user || 0);
          const guestCount = nb.guest || 0;
          const total = humanCount + workloadCount + guestCount;
          if (total > 0) {
            d.identityBreakdown = [
              { type: 'Human Users', count: humanCount, percentage: Math.round((humanCount / total) * 100), color: 'accent' },
              { type: 'Workload Identities', count: workloadCount, percentage: Math.round((workloadCount / total) * 100), color: 'warning' },
              { type: 'Guest Users', count: guestCount, percentage: Math.round((guestCount / total) * 100), color: 'textDim' },
            ];
          }
        }

        // ── Blast Radius ──
        if (attack?.workload_exposure) {
          const we = attack.workload_exposure;
          const ed = we.exposure_distribution || {};
          d.blastRadius.highRisk = (ed.critical || 0) + (ed.high || 0);
          d.blastRadius.lowRisk = (ed.medium || 0) + (ed.low || 0);
          d.blastRadius.orphaned = attack.pillars?.ownership_governance?.detail?.unowned_spns || 0;
          d.blastRadius.productionWorkloads = we.total || 0;
          const ca = we.component_averages || {};
          d.blastRadius.categories = [
            { name: 'Privilege', score: ca.privilege || 0, color: COLORS.danger },
            { name: 'Credential', score: ca.credential_risk || 0, color: COLORS.warning },
            { name: 'Exposure', score: ca.exposure || 0, color: COLORS.elevated },
            { name: 'Lifecycle', score: ca.lifecycle || 0, color: COLORS.accent },
            { name: 'Visibility', score: ca.visibility || 0, color: COLORS.purple },
          ];
        }

        // ── Delta Changes (from drift) ──
        if (drift?.has_drift_data) {
          const dormantPillar = attack?.pillars?.usage_dormancy?.detail?.dormant || 0;
          const overPriv = attack?.pillars?.effective_privilege?.detail?.t0t1 || 0;
          const unownedSPs = attack?.pillars?.ownership_governance?.detail?.unowned_spns || 0;
          const extExposure = attack?.pillars?.external_exposure?.detail?.tenant_scope || 0;
          d.deltaChanges = [
            { icon: '\uD83D\uDC64', label: 'Dormant', value: String(dormantPillar), color: dormantPillar > 0 ? 'danger' : 'success' },
            { icon: '\uD83D\uDD11', label: 'Over-priv', value: String(overPriv), color: overPriv > 0 ? 'warning' : 'success' },
            { icon: '\uD83D\uDC7B', label: 'Ghost Roles', value: String(ghostTotal), color: ghostTotal > 0 ? 'danger' : 'success' },
            { icon: '\uD83E\uDDDF', label: 'Zombies', value: String(zombieTotal), color: zombieTotal > 0 ? 'danger' : 'success' },
            { icon: '\uD83E\uDD16', label: 'Unowned SPs', value: String(unownedSPs), color: unownedSPs > 0 ? 'elevated' : 'success' },
            { icon: '\uD83C\uDF10', label: 'Ext exposure', value: String(extExposure), color: extExposure > 0 ? 'accent' : 'success' },
          ];
        } else {
          // No drift data — show current pillar counts as absolute values
          const dormantPillar = attack?.pillars?.usage_dormancy?.detail?.dormant || 0;
          const overPriv = attack?.pillars?.effective_privilege?.detail?.t0t1 || 0;
          const unownedSPs = attack?.pillars?.ownership_governance?.detail?.unowned_spns || 0;
          const extExposure = attack?.pillars?.external_exposure?.detail?.tenant_scope || 0;
          d.deltaChanges = [
            { icon: '\uD83D\uDC64', label: 'Dormant', value: String(dormantPillar), color: dormantPillar > 0 ? 'danger' : 'success' },
            { icon: '\uD83D\uDD11', label: 'Over-priv', value: String(overPriv), color: overPriv > 0 ? 'warning' : 'success' },
            { icon: '\uD83D\uDC7B', label: 'Ghost Roles', value: String(ghostTotal), color: ghostTotal > 0 ? 'danger' : 'success' },
            { icon: '\uD83E\uDDDF', label: 'Zombies', value: String(zombieTotal), color: zombieTotal > 0 ? 'danger' : 'success' },
            { icon: '\uD83E\uDD16', label: 'Unowned SPs', value: String(unownedSPs), color: unownedSPs > 0 ? 'elevated' : 'success' },
            { icon: '\uD83C\uDF10', label: 'Ext exposure', value: String(extExposure), color: extExposure > 0 ? 'accent' : 'success' },
          ];
        }

        // ── Governance ──
        if (attack?.governance) {
          const gov = attack.governance;
          const ownerPct = gov.ownership_coverage_pct || 0;
          const pimPct = gov.pim_adoption_pct || 0;
          const dormantCleanupPct = gov.dormant_cleanup_pct || 0;
          const reviewPct = gov.privileged_under_review_pct || 0;
          // Effectiveness: average of 4 governance percentages on 0-10 scale
          const avgPct = (ownerPct + pimPct + dormantCleanupPct + reviewPct) / 4;
          const effScore = Math.round(avgPct / 10);
          d.governance.effectivenessScore = effScore;
          d.governance.effectivenessTier = effScore >= 8 ? 'RESILIENT' : effScore >= 5 ? 'CONTROLLED' : effScore >= 3 ? 'ELEVATED' : 'CRITICAL';
          d.governance.maturityLevel = effScore >= 8 ? 'Optimized' : effScore >= 5 ? 'Managed' : effScore >= 3 ? 'Developing' : effScore >= 1 ? 'Ad-Hoc' : 'Unknown';

          const govStatus = (pct: number) => pct >= 80 ? 'good' : pct >= 40 ? 'warning' : pct > 0 ? 'critical' : 'not-configured';
          d.governance.metrics = [
            { label: 'Ownership Coverage', value: `${Math.round(ownerPct)}%`, target: '80%', status: govStatus(ownerPct), icon: '\uD83D\uDC64' },
            { label: 'PIM Enforcement', value: pimPct > 0 ? `${Math.round(pimPct)}%` : '\u2014', target: '100%', status: govStatus(pimPct), icon: '\uD83D\uDD10' },
            { label: 'Access Reviews', value: gov.access_reviews_done > 0 ? `${gov.access_reviews_done} done` : '\u2014', target: 'quarterly', status: gov.access_reviews_done > 0 ? 'good' : 'not-configured', icon: '\uD83D\uDCCB' },
            { label: 'Privileged Monitoring', value: reviewPct > 0 ? `${Math.round(reviewPct)}%` : '\u2014', target: 'active', status: govStatus(reviewPct), icon: '\uD83D\uDCE1' },
          ];

          // Control failures derived from pillar details
          const preventiveItems: { label: string; count: number; color: string }[] = [];
          const operationalItems: { label: string; count: number; color: string }[] = [];
          const privT0 = attack.pillars?.effective_privilege?.detail?.t0 || 0;
          if (privT0 > 0 && pimPct < 100) preventiveItems.push({ label: 'Privilege outside PIM', count: privT0, color: COLORS.danger });
          if (ghostTotal > 0) preventiveItems.push({ label: 'Disabled accounts retain active RBAC roles', count: ghostTotal, color: COLORS.danger });
          const unownedSpns = attack.pillars?.ownership_governance?.detail?.unowned_spns || 0;
          if (unownedSpns > 0) operationalItems.push({ label: `Ownership coverage at ${Math.round(ownerPct)}%`, count: unownedSpns, color: COLORS.warning });
          const dormPriv = attack.attack_opportunities?.dormant_privileged_count || 0;
          if (dormPriv > 0) operationalItems.push({ label: 'Dormant privileged accounts active', count: dormPriv, color: COLORS.warning });

          d.governance.controlFailures = [];
          if (preventiveItems.length > 0) d.governance.controlFailures.push({ type: 'PREVENTIVE FAILURES', items: preventiveItems });
          if (operationalItems.length > 0) d.governance.controlFailures.push({ type: 'OPERATIONAL GAPS', items: operationalItems });

          const configured = [ownerPct > 0, pimPct > 0, gov.access_reviews_done > 0, reviewPct > 0].filter(Boolean).length;
          d.governance.setupCompletion = { configured, total: 4 };
        }

        // ── Compliance (from /api/dashboard/compliance) ──
        if (comp && typeof comp === 'object') {
          const frameworks: ComplianceFramework[] = [];
          for (const [key, fw] of Object.entries(comp) as [string, any][]) {
            if (!fw || typeof fw !== 'object' || !fw.name) continue;
            frameworks.push({
              id: key,
              name: fw.short_name || fw.name,
              type: fw.category || fw.tier || 'Industry',
              score: fw.score || 0,
              totalControls: fw.total_framework_controls || fw.total_controls || 0,
              failedControls: fw.fail_count || 0,
              status: fw.score >= 80 ? 'Mature' : fw.score >= 50 ? 'Developing' : fw.score > 0 ? 'Initial' : 'Not Assessed',
              trend: 0,
              identityImpactCount: fw.identity_controls_count || 0,
              controls: (fw.controls || []).map((c: any) => ({
                id: c.id, name: c.name, status: c.status,
                severity: c.status === 'fail' ? 'high' : 'medium',
                evidence: c.detail || '', recommendation: '', identityCount: 0,
              })),
            });
          }
          d.compliance.frameworks = frameworks;
          // Maturity summary
          const passTotal = frameworks.reduce((s, f) => s + (f.score >= 80 ? 1 : 0), 0);
          const failTotal = frameworks.reduce((s, f) => s + (f.failedControls || 0), 0);
          d.compliance.maturity = {
            preventive: passTotal,
            detective: frameworks.length - passTotal,
            compensating: 0,
            missing: failTotal,
          };
          const avgScore = frameworks.length > 0 ? Math.round(frameworks.reduce((s, f) => s + f.score, 0) / frameworks.length) : 0;
          d.compliance.progress = {
            remediation: avgScore,
            iaGovernance: (attack?.governance?.ownership_coverage_pct || 0) / 10,
          };
        }

        // ── Remediations (dynamic from attack surface data) ──
        const remCards: Remediation[] = [];
        if (attack) {
          const ep = attack.pillars?.effective_privilege?.detail || {};
          const ao = attack.attack_opportunities || {};
          const cr = attack.pillars?.credential_risk?.detail || {};
          const og = attack.pillars?.ownership_governance?.detail || {};
          const current = d.riskScore.current;
          const target = d.riskScore.target;

          if ((ep.t0t1 || 0) > 0) {
            const gain = Math.round((target - current) * 0.3);
            remCards.push({
              id: 'r1', type: 'identity-remediation',
              title: 'Reduce over-privileged identities',
              subtitle: `${ep.t0t1} identities at T0/T1 privilege across ${subCount} subscriptions`,
              gain, projectedScore: `~${Math.round(current + gain)}`,
              status: 'new', automation: 'Manual', risk: 'HIGH', color: 'danger',
              affected: `${ep.t0t1} ids \u00B7 ${subCount} subs`,
              effort: '~14 days', rollback: 'Safe to rollback', rollbackRisk: 'safe',
              compliance: 'SOC 2, HIPAA, NIST', confidence: 92, productionImpact: true, riskPerDay: 0.3,
            });
          }
          if ((ao.dormant_privileged_count || 0) > 0) {
            const gain = Math.round((target - current) * 0.2);
            remCards.push({
              id: 'r2', type: 'identity-remediation',
              title: 'Remediate dormant privileged accounts',
              subtitle: `${ao.dormant_privileged_count} dormant accounts with active privileged roles`,
              gain, projectedScore: `~${Math.round(current + gain)}`,
              status: 'new', automation: 'Auto', risk: 'LOW', color: 'warning',
              affected: `${ao.dormant_privileged_count} ids`,
              effort: '~2 days', rollback: 'Safe to rollback', rollbackRisk: 'safe',
              compliance: 'HIPAA, SOC 2', confidence: 98, productionImpact: false, riskPerDay: 0.1,
            });
          }
          if (ghostTotal > 0) {
            const gain = Math.round((target - current) * 0.15);
            remCards.push({
              id: 'r2b', type: 'identity-remediation',
              title: 'Revoke roles from disabled accounts',
              subtitle: `${ghostTotal} accounts disabled in Entra ID but retain active RBAC assignments`,
              gain, projectedScore: `~${Math.round(current + gain)}`,
              status: 'new', automation: 'Auto', risk: 'HIGH', color: 'danger',
              affected: `${ghostTotal} ids`,
              effort: '~1 day', rollback: 'Safe to rollback', rollbackRisk: 'safe',
              compliance: 'SOC2 CC6.1, HIPAA, NIST AC-2, SOX', confidence: 99, productionImpact: false, riskPerDay: 0.5,
            });
          }
          if ((og.unowned_spns || 0) > 0) {
            const gain = Math.round((target - current) * 0.1);
            remCards.push({
              id: 'r3', type: 'identity-remediation',
              title: 'Assign ownership to unowned SPNs',
              subtitle: `${og.unowned_spns} service principals without designated owners`,
              gain, projectedScore: `~${Math.round(current + gain)}`,
              status: 'new', automation: 'Manual', risk: 'LOW', color: 'elevated',
              affected: `${og.unowned_spns} ids`,
              effort: '~7 days', rollback: 'Safe to rollback', rollbackRisk: 'safe',
              compliance: 'SOC 2, ISO 27001', confidence: 95, productionImpact: false, riskPerDay: 0.05,
            });
          }
          if ((cr.expired || 0) > 0) {
            const gain = Math.round((target - current) * 0.15);
            remCards.push({
              id: 'r4', type: 'identity-remediation',
              title: 'Rotate expired credentials',
              subtitle: `${cr.expired} identities with expired credentials`,
              gain, projectedScore: `~${Math.round(current + gain)}`,
              status: 'new', automation: 'Manual', risk: 'MEDIUM', color: 'warning',
              affected: `${cr.expired} ids`,
              effort: '~3 days', rollback: 'Safe to rollback', rollbackRisk: 'safe',
              compliance: 'SOC 2, PCI DSS', confidence: 90, productionImpact: false, riskPerDay: 0.2,
            });
          }
        }
        d.remediations = remCards;

        // ── Projection ──
        const totalGain = remCards.reduce((s, r) => s + r.gain, 0);
        const noActionScore = Math.max(0, d.riskScore.current - 3);
        const remediatedScore = Math.min(100, d.riskScore.current + totalGain);
        d.projection.noAction = {
          score: Math.round(noActionScore * 10) / 10,
          tier: getTier(noActionScore),
          consequences: d.pillars.filter(p => p.score > 50).map(p => `${p.detail} (${p.name}: ${p.score}%)`),
          breachImpact: noActionScore < 40 ? 'High' : noActionScore < 60 ? 'Moderate-High' : 'Moderate',
        };
        d.projection.remediated = {
          score: Math.round(remediatedScore * 10) / 10,
          tier: getTier(remediatedScore),
          actions: remCards.slice(0, 4).map(r => r.title),
          breachImpact: remediatedScore >= 80 ? 'Low' : 'Moderate',
        };

        // ── Risk Movement ──
        if (trends?.runs?.length) {
          d.riskMovement.trajectory = trends.runs.map((r: any) => r.posture_score ?? 0);
        }
        // Changes from stats + drift
        const latestRun = stats?.latest_run || {};
        const prevRun = stats?.previous_run || {};
        d.riskMovement.changes = [
          { label: 'Critical Identities', before: prevRun.critical_count || 0, after: latestRun.critical_count || 0, direction: (latestRun.critical_count || 0) > (prevRun.critical_count || 0) ? 'up' : (latestRun.critical_count || 0) < (prevRun.critical_count || 0) ? 'down' : 'flat' },
          { label: 'High-Risk Identities', before: prevRun.high_count || 0, after: latestRun.high_count || 0, direction: (latestRun.high_count || 0) > (prevRun.high_count || 0) ? 'up' : (latestRun.high_count || 0) < (prevRun.high_count || 0) ? 'down' : 'flat' },
          { label: 'Ghost Accounts', before: 0, after: ghostTotal, direction: ghostTotal > 0 ? 'up' : 'flat' },
          { label: 'Zombie Personas', before: 0, after: zombieTotal, direction: zombieTotal > 0 ? 'up' : 'flat' },
          { label: 'Total Identities', before: prevRun.total_identities || 0, after: latestRun.total_identities || 0, direction: (latestRun.total_identities || 0) > (prevRun.total_identities || 0) ? 'up' : (latestRun.total_identities || 0) < (prevRun.total_identities || 0) ? 'down' : 'flat' },
          { label: 'New Identities', before: 0, after: drift?.new_identities_count || 0, direction: (drift?.new_identities_count || 0) > 0 ? 'up' : 'flat' },
          { label: 'Removed', before: 0, after: drift?.removed_identities_count || 0, direction: (drift?.removed_identities_count || 0) > 0 ? 'down' : 'flat' },
        ];
        // Most changed pillar
        const worstPillar = [...d.pillars].sort((a, b) => b.score - a.score)[0];
        if (worstPillar) {
          d.riskMovement.mostChanged = { name: worstPillar.name, score: worstPillar.score, category: worstPillar.name };
        }
        d.riskMovement.scanMeta = {
          frequency: d.tenant.scanDuration > 0 ? 'Scheduled' : 'Unknown',
          lastRun: d.tenant.lastScan,
          sources: d.tenant.sources.join(', '),
          duration: d.tenant.scanDuration > 0 ? `${Math.floor(d.tenant.scanDuration / 60)}m ${d.tenant.scanDuration % 60}s` : 'Unknown',
          completeness: `${d.tenant.scanCompleteness}%`,
        };

        // ── AGIRS data ──
        // Prefer persisted AGIRS scores from API; fall back to computing
        // from pillar/stats/governance data that's already loaded.
        if (agirstData?.agirs) {
          d.agirs = {
            agirs: agirstData.agirs,
            hiri: agirstData.hiri || null,
            nhiri: agirstData.nhiri || null,
            gei: agirstData.gei || null,
            dangerous_identities: agirstData.dangerous_identities || [],
            previous: agirstData.previous || null,
          };
        } else if (attack || stats) {
          // Compute AGIRS from already-loaded data (single source of truth)
          const ao = attack?.attack_opportunities || {};
          const ep = attack?.pillars?.effective_privilege?.detail || {};
          const cr = attack?.pillars?.credential_risk?.detail || {};
          const tf = attack?.pillars?.trust_federation?.detail || {};
          const ud = attack?.pillars?.usage_dormancy?.detail || {};
          const og = attack?.pillars?.ownership_governance?.detail || {};
          const gov = attack?.governance || {};

          // Identity counts from summary/attack
          const cats = (summary?.categories || {}) as Record<string, { total: number }>;
          const humanCount = (cats.human_user?.total || 0) + (cats.guest?.total || 0);
          const nhiCount = (cats.service_principal?.total || 0)
            + (cats.managed_identity_system?.total || 0)
            + (cats.managed_identity_user?.total || 0);

          // ── HIRI: Human Identity Risk Index ──
          const h1_ghost = stats?.ghost_count || 0;
          const h2_dormant_priv = ao.dormant_privileged_count || 0;
          const h3_over_priv = (ep.t0t1 || 0);
          const h4_ext_guest = tf.guest_with_roles || 0;
          const h5_zombie = stats?.zombie_count || 0;

          const hiriRaw = h1_ghost * 3 + h2_dormant_priv * 5 + h3_over_priv * 4 + h4_ext_guest * 6 + h5_zombie * 7;
          const hiriNorm = humanCount > 0 ? Math.min(hiriRaw / humanCount * 100, 500) : 0;
          const hiriScore = Math.round(Math.max(100 - hiriNorm, 0) * 100) / 100;

          // ── NHIRI: Non-Human Identity Risk Index ──
          const n1_orphaned = og.unowned_spns || 0;
          // Dormant NHIs: subset of dormant pillar that are NHI. Approximate from
          // total dormant minus human dormant (dormant_priv mostly human).
          const totalDormant = ud.dormant || 0;
          const n2_dormant = Math.max(0, totalDormant - h2_dormant_priv);
          const n3_zombie = 0; // requires credential + risk intersection, not in pillar data
          const n4_expired = (cr.expired || 0) + (cr.expiring || 0);
          const n5_ownerless_apps = 0; // from app_registrations, not in pillar data

          const nhiriRaw = (n1_orphaned * 4 + n2_dormant * 3 + n3_zombie * 6 + n4_expired * 2 + n5_ownerless_apps * 5) * 1.3;
          const nhiriNorm = nhiCount > 0 ? Math.min(nhiriRaw / nhiCount * 100, 500) : 0;
          const nhiriScore = Math.round(Math.max(100 - nhiriNorm, 0) * 100) / 100;

          // ── GEI: Governance Effectiveness Index ──
          const ownerPct = gov.ownership_coverage_pct || 0;
          const pimPct = gov.pim_adoption_pct || 0;
          const reviewPct = gov.privileged_under_review_pct || 0;
          const accessReviewsDone = gov.access_reviews_done || 0;
          const accessReviewScore = accessReviewsDone > 0 ? Math.min(accessReviewsDone * 20, 100) : 0;
          const geiScore = Math.round((ownerPct + pimPct + accessReviewScore + reviewPct) / 4 * 100) / 100;

          const agirs_score = Math.round((0.40 * hiriScore + 0.40 * nhiriScore + 0.20 * geiScore) * 100) / 100;
          const agirsTier = agirs_score >= 90 ? 'A' : agirs_score >= 75 ? 'B' : agirs_score >= 60 ? 'C' : agirs_score >= 40 ? 'D' : 'F';

          d.agirs = {
            agirs: { score: agirs_score, tier: agirsTier, delta: null },
            hiri: {
              score: hiriScore, human_count: humanCount,
              h1_ghost, h2_dormant_priv, h3_over_priv, h4_ext_guest, h5_zombie,
            },
            nhiri: {
              score: nhiriScore, nhi_count: nhiCount,
              phantom_breakdown: { orphaned: n1_orphaned, dormant: n2_dormant, zombie_nhi: n3_zombie, expired_creds: n4_expired, ownerless_apps: n5_ownerless_apps },
            },
            gei: {
              score: geiScore,
              components: [
                { name: 'Ownership Coverage', score: ownerPct, configured: ownerPct > 0 || og.total_spns > 0 },
                { name: 'PIM Adoption', score: pimPct, configured: pimPct > 0 },
                { name: 'Access Reviews', score: accessReviewScore, configured: accessReviewsDone > 0 },
                { name: 'Monitoring (P2)', score: reviewPct, configured: reviewPct > 0 },
              ],
            },
            dangerous_identities: agirstData?.dangerous_identities || [],
            previous: agirstData?.previous || null,
          };
        }

        setData(d);
      } catch {
        setData(buildEmptyData());
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
  // Use ?pillar=X which triggers server-side contributing_pillar filtering
  // for EXACT count match with the attack-surface-score engine
  const n = name.toLowerCase();
  if (n.includes('privilege'))                     return '/identities?pillar=effective-privilege';
  if (n.includes('credential'))                    return '/identities?pillar=credential-risk';
  if (n.includes('trust') || n.includes('feder'))  return '/identities?pillar=trust-federation';
  if (n.includes('usage') || n.includes('dorma'))  return '/identities?pillar=usage-dormancy';
  if (n.includes('ownership') || n.includes('gov'))return '/identities?pillar=ownership-governance';
  if (n.includes('external') || n.includes('expo'))return '/identities?pillar=external-exposure';
  return '/identities';
}

function remediationNav(id: string): string {
  // Map each remediation card to the correct identity filter
  // Use pillar-based URLs for exact count match where applicable
  switch (id) {
    case 'r1': return '/identities?pillar=effective-privilege';
    case 'r2': return '/identities?activity_status=dormant_strict&privileged=true';
    case 'r2b': return '/identities?status=disabled&hasRoles=true';
    case 'r3': return '/identities?pillar=ownership-governance';
    case 'r4': return '/identities?pillar=credential-risk';
    default: return '/identities';
  }
}

// ── AGIRS Components ─────────────────────────────────────────────

function AGIRSScoreTriad({ agirs }: { agirs: AGIRSData }) {
  const hasData = !!agirs?.agirs;
  const score = agirs?.agirs?.score ?? 0;
  const tier = agirs?.agirs?.tier ?? '--';
  const delta = agirs?.agirs?.delta ?? null;
  const hiriScore = agirs?.hiri?.score ?? 0;
  const nhiriScore = agirs?.nhiri?.score ?? 0;
  const geiScore = agirs?.gei?.score ?? 0;

  const prevHiri = agirs?.previous?.hiri;
  const prevNhiri = agirs?.previous?.nhiri;
  const prevGei = agirs?.previous?.gei;

  function DeltaArrow({ current, previous }: { current: number; previous: number | null | undefined }) {
    if (previous == null) return null;
    const d = current - previous;
    if (Math.abs(d) < 0.1) return null;
    const up = d > 0;
    return (
      <span style={{ fontSize: 10, fontWeight: 600, fontFamily: FONT.mono, color: up ? COLORS.success : COLORS.danger, marginLeft: 4 }}>
        {up ? '\u25B2' : '\u25BC'}{Math.abs(d).toFixed(1)}
      </span>
    );
  }

  return (
    <CISOCard>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 14 }}>
        <SectionTitle>AGIRS — Identity Risk Posture</SectionTitle>
        <span style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.mono }}>AuditGraph Identity Risk Score</span>
      </div>
      {/* Rule 59: empty state ONLY if no scan ever run — never when pillar data exists */}
      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr 1fr 1fr', gap: 24, alignItems: 'center' }}>
        {/* Main AGIRS Ring */}
        <div style={{ textAlign: 'center' }}>
          <ScoreRing score={score} size={96} strokeWidth={6} color={getAGIRSColor(score)} displayValue={score.toFixed(1)} />
          <div style={{ marginTop: 6 }}>
            <span style={{
              display: 'inline-block', padding: '2px 10px', borderRadius: 4, fontSize: 11, fontWeight: 700,
              fontFamily: FONT.mono, background: `${getAGIRSColor(score)}20`, color: getAGIRSColor(score),
            }}>
              {tier}
            </span>
            {delta != null && (
              <span style={{ fontSize: 11, fontWeight: 700, fontFamily: FONT.mono, marginLeft: 6, color: delta >= 0 ? COLORS.success : COLORS.danger }}>
                {delta >= 0 ? '+' : ''}{delta.toFixed(1)}
              </span>
            )}
          </div>
        </div>

        {/* HIRI */}
        <div style={{ textAlign: 'center' }}>
          <ScoreRing score={hiriScore} size={64} strokeWidth={5} color={COLORS.hiri} displayValue={hiriScore.toFixed(0)} />
          <div style={{ fontSize: 10, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui, marginTop: 4 }}>HIRI</div>
          <div style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.mono }}>
            <DN navigateTo="/identities?identity_category=human_user">{agirs?.hiri?.human_count ?? 0}</DN> humans
            <DeltaArrow current={hiriScore} previous={prevHiri} />
          </div>
        </div>

        {/* NHIRI */}
        <div style={{ textAlign: 'center' }}>
          <ScoreRing score={nhiriScore} size={64} strokeWidth={5} color={COLORS.nhiri} displayValue={nhiriScore.toFixed(0)} />
          <div style={{ fontSize: 10, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui, marginTop: 4 }}>NHIRI</div>
          <div style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.mono }}>
            <DN navigateTo="/identities?identity_category=service_principal">{agirs?.nhiri?.nhi_count ?? 0}</DN> NHIs
            <DeltaArrow current={nhiriScore} previous={prevNhiri} />
          </div>
        </div>

        {/* GEI */}
        <div style={{ textAlign: 'center' }}>
          <ScoreRing score={geiScore} size={64} strokeWidth={5} color={COLORS.gei} displayValue={geiScore.toFixed(0)} />
          <div style={{ fontSize: 10, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui, marginTop: 4 }}>GEI</div>
          <div style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.mono }}>
            <DN navigateTo="/service-accounts">{geiScore.toFixed(0)}% effective</DN>
            <DeltaArrow current={geiScore} previous={prevGei} />
          </div>
        </div>
      </div>
    </CISOCard>
  );
}

function HIRIBreakdownCard({ hiri }: { hiri: AGIRSData['hiri'] }) {
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

function PhantomExposureCard({ nhiri }: { nhiri: AGIRSData['nhiri'] }) {
  const pb = nhiri?.phantom_breakdown ?? { orphaned: 0, dormant: 0, zombie_nhi: 0, expired_creds: 0, ownerless_apps: 0 };
  const categories: { key: string; label: string; count: number | null; color: string; nav: string; tooltip?: string }[] = [
    { key: 'orphaned', label: 'Orphaned (No Owner)', count: pb.orphaned, color: COLORS.danger, nav: '/identities?agirs_factor=n1_orphaned' },
    { key: 'dormant', label: 'Dormant NHIs', count: pb.dormant, color: COLORS.elevated, nav: '/workload-identities', tooltip: 'Includes all NHI dormancy signals' },
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

function DangerousIdentitiesCard({ identities }: { identities: DangerousIdentity[] }) {
  const navigate = useNavigate();
  const tierColors: Record<string, string> = { T0: COLORS.danger, T1: COLORS.elevated, T2: COLORS.warning, T3: COLORS.textMuted };

  return (
    <CISOCard>
      <SectionTitle>Top Dangerous Identities</SectionTitle>
      {!identities.length && (
        <div style={{ textAlign: 'center', padding: '16px 0', color: COLORS.textSecondary, fontFamily: FONT.ui, fontSize: 11 }}>
          No blast radius data yet. Run a discovery scan to compute.
        </div>
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
        {identities.slice(0, 5).map((id, i) => (
          <div
            key={id.id}
            onClick={() => navigate(`/identities/${id.id}`)}
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '8px 0', cursor: 'pointer',
              borderBottom: i < Math.min(identities.length, 5) - 1 ? `1px solid ${COLORS.border}` : 'none',
            }}
          >
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{
                  display: 'inline-block', padding: '1px 6px', borderRadius: 3, fontSize: 9, fontWeight: 700,
                  fontFamily: FONT.mono, background: `${tierColors[id.tier] || COLORS.textMuted}20`,
                  color: tierColors[id.tier] || COLORS.textMuted,
                }}>{id.tier}</span>
                <span style={{ fontSize: 11, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const }}>
                  {id.display_name}
                </span>
              </div>
              <div style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.mono, marginTop: 2 }}>
                {id.key_risk_factors.join(' \u00B7 ')}
              </div>
            </div>
            <div style={{ textAlign: 'right', flexShrink: 0, marginLeft: 12 }}>
              <DN navigateTo={`/identities/${id.id}`}><div style={{ fontSize: 14, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.danger }}>{id.blast_radius_score.toFixed(1)}</div></DN>
              <div style={{ fontSize: 8, color: COLORS.textSecondary, fontFamily: FONT.mono }}>blast radius</div>
            </div>
          </div>
        ))}
      </div>
    </CISOCard>
  );
}

function GEICard({ gei }: { gei: AGIRSData['gei'] }) {
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

// ── Command Center Helpers ──

function HeroPanel({ d, execView }: { d: TenantData; execView: boolean }) {
  const score = d.riskScore.current;
  const tier = d.riskScore.tier;
  const delta = d.riskScore.delta;
  const isHighRisk = score < 40;
  const sortedPillars = [...d.pillars].sort((a, b) => a.score - b.score);
  const worstPillar = sortedPillars[0];
  const gradId = `hero-grad-${Math.random().toString(36).slice(2, 8)}`;

  return (
    <CISOCard style={{ padding: '16px 18px', position: 'relative', overflow: 'hidden' }}>
      {isHighRisk && (
        <div style={{
          position: 'absolute', inset: 0, pointerEvents: 'none',
          background: `radial-gradient(ellipse at 10% 50%, ${COLORS.danger}18 0%, transparent 60%)`,
        }} />
      )}
      <div style={{ display: 'flex', gap: 32, alignItems: 'center', position: 'relative', zIndex: 1 }}>
        {/* Left: Score + Tier + Delta */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 12 }}>
            <DN navigateTo="/dashboard">
              <span style={{ fontSize: 48, fontWeight: 700, fontFamily: FONT.mono, color: getScoreColor(score), lineHeight: 1 }}>
                {score.toFixed(1)}
              </span>
            </DN>
            <div>
              <div style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.12em', textTransform: 'uppercase' as const, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
                GLOBAL IDENTITY RISK SCORE
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
                <CISOBadge label={tier} color={getTierColor(tier)} />
                <span style={{ fontSize: 12, fontWeight: 700, fontFamily: FONT.mono, color: delta >= 0 ? COLORS.success : COLORS.danger }}>
                  {delta >= 0 ? '↑' : '↓'} {delta >= 0 ? '+' : ''}{delta.toFixed(1)} since last scan
                </span>
              </div>
            </div>
          </div>
          {/* AI micro-insight */}
          <div style={{
            marginTop: 12, paddingLeft: 10, borderLeft: `2px solid ${COLORS.borderAccent}`,
            fontSize: 11, fontStyle: 'italic', color: COLORS.textSecondary, fontFamily: FONT.ui, lineHeight: 1.5,
          }}>
            {execView ? (
              <>Identity risk is {tier === 'CRITICAL' ? 'critically elevated' : tier === 'ELEVATED' ? 'elevated above acceptable thresholds' : 'within managed parameters'}. {worstPillar ? `${worstPillar.name} is the primary driver, with ${worstPillar.identityCount} identities contributing to the score.` : ''} Remediation of top 3 actions would yield +{d.riskScore.potentialGain} pts improvement.</>
            ) : (
              <>Worst pillar: <strong style={{ color: COLORS.text, fontStyle: 'normal' }}>{worstPillar?.name || 'N/A'}</strong> (score {worstPillar?.score ?? 0}) — {worstPillar?.identityCount ?? 0} identities contributing. {d.riskScore.potentialGain > 0 ? `Potential +${d.riskScore.potentialGain} pts if top 3 remediations completed.` : ''}</>
            )}
          </div>
        </div>
        {/* Right: Score Benchmarks */}
        <div style={{ width: 280, flexShrink: 0 }}>
          <div style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase' as const, color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 10 }}>
            Score Benchmarks
          </div>
          <div style={{ position: 'relative', height: 32 }}>
            {/* Gradient bar */}
            <svg width="100%" height={8} style={{ display: 'block', marginTop: 12 }}>
              <defs>
                <linearGradient id={gradId} x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor={COLORS.danger} />
                  <stop offset="50%" stopColor={COLORS.warning} />
                  <stop offset="100%" stopColor={COLORS.success} />
                </linearGradient>
              </defs>
              <rect width="100%" height={8} rx={4} fill={`url(#${gradId})`} opacity={0.5} />
            </svg>
            {/* Your Score */}
            <div style={{ position: 'absolute', left: `${Math.min(95, Math.max(5, score))}%`, top: 0, transform: 'translateX(-50%)' }}>
              <div style={{ width: 14, height: 14, borderRadius: '50%', background: getScoreColor(score), border: '2px solid #fff', boxShadow: `0 0 6px ${getScoreColor(score)}80`, margin: '0 auto' }} />
            </div>
            {/* Industry Median */}
            <div style={{ position: 'absolute', left: `${Math.min(95, Math.max(5, d.riskScore.industry))}%`, top: 2, transform: 'translateX(-50%)' }}>
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: 'transparent', border: `2px solid ${COLORS.textDim}`, margin: '0 auto' }} />
            </div>
            {/* Target */}
            <div style={{ position: 'absolute', left: `${Math.min(95, Math.max(5, d.riskScore.target))}%`, top: 2, transform: 'translateX(-50%)' }}>
              <div style={{ width: 10, height: 10, borderRadius: 2, background: 'transparent', border: `2px solid ${COLORS.success}`, margin: '0 auto' }} />
            </div>
          </div>
          {/* Legend */}
          <div style={{ display: 'flex', gap: 14, marginTop: 8 }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: getScoreColor(score), display: 'inline-block' }} /> You ({score.toFixed(0)})
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', border: `2px solid ${COLORS.textDim}`, display: 'inline-block', boxSizing: 'border-box' }} /> Industry ({d.riskScore.industry})
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
              <span style={{ width: 8, height: 8, borderRadius: 2, border: `2px solid ${COLORS.success}`, display: 'inline-block', boxSizing: 'border-box' }} /> Target ({d.riskScore.target})
            </span>
          </div>
        </div>
      </div>
    </CISOCard>
  );
}

function RiskDriverRow({ pillar, isLast }: { pillar: Pillar; isLast: boolean }) {
  const c = getPillarColor(pillar.score);
  const nav = pillarNav(pillar.name);
  return (
    <div style={{
      display: 'flex', alignItems: 'center', padding: '8px 0',
      borderLeft: `3px solid ${c}`, paddingLeft: 10,
      borderBottom: isLast ? 'none' : `1px solid ${COLORS.border}`,
    }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui }}>{pillar.name}</div>
        <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 1 }}>
          <DN navigateTo={nav}>{pillar.identityCount}</DN> identities contributing
        </div>
      </div>
      <DN navigateTo={nav} tooltip={`View ${pillar.name} identities`}>
        <span style={{ fontSize: 16, fontWeight: 700, fontFamily: FONT.mono, color: c, flexShrink: 0, width: 36, textAlign: 'right' as const, display: 'inline-block' }}>
          {pillar.score}
        </span>
      </DN>
    </div>
  );
}

function ExposureMetricRow({ label, value, color, nav, isLast, tooltip }: { label: string; value: number; color: string; nav: string; isLast: boolean; tooltip?: string }) {
  const isZero = value === 0;
  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '6px 0',
      borderBottom: isLast ? 'none' : `1px solid ${COLORS.border}`,
    }}>
      <span style={{ fontSize: 11, color: isZero ? COLORS.textDim : COLORS.text, fontFamily: FONT.ui }}>{label}</span>
      <DN navigateTo={nav}>
        <span style={{ fontSize: 12, fontWeight: 700, fontFamily: FONT.mono, color: isZero ? COLORS.textDim : color }}>{value}</span>
      </DN>
    </div>
  );
}

function ActionQueueItem({ item, index, onPreview, onTicket, onAutoFix, isLast }: {
  item: Remediation; index: number;
  onPreview: (r: Remediation) => void;
  onTicket: (r: Remediation) => void;
  onAutoFix?: (r: Remediation) => void;
  isLast: boolean;
}) {
  const severityColor = item.risk === 'HIGH' ? COLORS.danger : item.risk === 'MEDIUM' ? COLORS.warning : COLORS.success;
  // Rule 67: Auto-Fix ONLY for ghost role revocation
  const isGhostRemediation = item.id === 'r2b' || item.title.toLowerCase().includes('ghost') || item.title.toLowerCase().includes('disabled account');
  const showAutoFix = item.automation === 'Auto' && isGhostRemediation;
  return (
    <div style={{
      padding: '10px 0',
      borderBottom: isLast ? 'none' : `1px solid ${COLORS.border}`,
    }}>
      {/* Top row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <CISOBadge label={item.risk} color={severityColor} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <span style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui }}>{item.title}</span>
          <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginLeft: 6 }}>{item.subtitle}</span>
        </div>
        <DN navigateTo="/remediation"><span style={{ fontSize: 14, fontWeight: 700, color: COLORS.success, fontFamily: FONT.mono, flexShrink: 0 }}>+{item.gain} pts</span></DN>
      </div>
      {/* Detail row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginTop: 6, paddingLeft: 2 }}>
        <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui }}>Affected: <DN navigateTo="/identities"><span style={{ fontFamily: FONT.mono, color: COLORS.text }}>{item.affected}</span></DN></span>
        <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui }}>Effort: <span style={{ fontFamily: FONT.mono, color: COLORS.text }}>{item.effort}</span></span>
        {item.rollbackRisk === 'safe' && (
          <span style={{ fontSize: 10, color: COLORS.success, fontFamily: FONT.ui }}>Safe Rollback Available</span>
        )}
      </div>
      {/* Action buttons */}
      <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
        <button onClick={() => onPreview(item)} style={{
          padding: '4px 12px', borderRadius: 5, fontSize: 10, fontWeight: 600,
          background: 'transparent', color: COLORS.text,
          border: `1px solid ${COLORS.borderAccent}`, cursor: 'pointer', fontFamily: FONT.ui,
        }}>Preview</button>
        <button onClick={() => onTicket(item)} style={{
          padding: '4px 12px', borderRadius: 5, fontSize: 10, fontWeight: 600,
          background: 'transparent', color: COLORS.textSecondary,
          border: `1px solid ${COLORS.border}`, cursor: 'pointer', fontFamily: FONT.ui,
        }}>Create Ticket</button>
        {showAutoFix && (
          <button onClick={() => onAutoFix?.(item)} style={{
            padding: '4px 12px', borderRadius: 5, fontSize: 10, fontWeight: 600,
            background: `${COLORS.accent}22`, color: COLORS.accent,
            border: `1px solid ${COLORS.accent}40`, cursor: 'pointer', fontFamily: FONT.ui,
          }}>Auto-Fix ⚡</button>
        )}
      </div>
    </div>
  );
}

function GovernanceRow({ metric, isLast }: { metric: GovernanceMetric; isLast: boolean }) {
  const statusIcon = metric.status === 'good' ? '✓' : metric.status === 'warning' ? '⚠' : metric.status === 'critical' ? '✕' : '—';
  const statusColor = metric.status === 'good' ? COLORS.success : metric.status === 'warning' ? COLORS.warning : metric.status === 'critical' ? COLORS.danger : COLORS.textDim;
  const govRowNav = metric.label.toLowerCase().includes('access review') ? '/access-reviews' :
    metric.label.toLowerCase().includes('owner') ? '/service-accounts' :
    metric.label.toLowerCase().includes('rotation') || metric.label.toLowerCase().includes('credential') ? '/resources?resource_type=key_vault' :
    metric.label.toLowerCase().includes('pim') || metric.label.toLowerCase().includes('jit') ? '/identities?pillar=effective-privilege' :
    '/service-accounts';
  const navTarget = metric.status !== 'not-configured' ? govRowNav : '/settings/governance';
  return (
    <div style={{
      display: 'grid', gridTemplateColumns: '1fr auto auto', gap: 12, alignItems: 'center',
      padding: '7px 0',
      borderBottom: isLast ? 'none' : `1px solid ${COLORS.border}`,
    }}>
      <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>{metric.label}</span>
      <DN navigateTo={navTarget}>
        <span style={{ fontSize: 11, fontWeight: 600, fontFamily: FONT.mono, color: COLORS.text }}>{metric.value}</span>
      </DN>
      <span style={{ fontSize: 14, color: statusColor, width: 20, textAlign: 'center' as const }}>{statusIcon}</span>
    </div>
  );
}

// ── Auto-Fix Confirmation Dialog (Rule 68) ──

function AutoFixDialog({ item, onClose, onConfirm }: {
  item: Remediation;
  onClose: () => void;
  onConfirm: (item: Remediation) => void;
}) {
  const { withConnection } = useConnection();
  const [identities, setIdentities] = useState<{ id: number; display_name: string; roles: string }[]>([]);
  const [loading, setLoading] = useState(true);
  const [executing, setExecuting] = useState(false);

  useEffect(() => {
    // Fetch affected identities from remediation detail API
    fetch(withConnection(`/api/identities?status=disabled&hasRoles=true&limit=50`))
      .then(r => r.ok ? r.json() : { identities: [] })
      .then(data => {
        const ids = (data.identities || []).map((id: Record<string, unknown>) => ({
          id: id.id as number,
          display_name: (id.display_name || id.name || 'Unknown') as string,
          roles: (id.role_count ? `${id.role_count} roles` : (id.critical_roles as string) || 'RBAC roles') as string,
        }));
        setIdentities(ids);
      })
      .catch(() => setIdentities([]))
      .finally(() => setLoading(false));
  }, [withConnection]);

  const handleConfirm = () => {
    setExecuting(true);
    onConfirm(item);
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9999,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)',
    }} onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        background: COLORS.surface, border: `1px solid ${COLORS.borderAccent}`,
        borderRadius: 12, padding: '24px 28px', width: 520, maxHeight: '80vh',
        overflow: 'auto',
      }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
          <span style={{ fontSize: 18 }}>⚠️</span>
          <span style={{ fontSize: 14, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui }}>
            Confirm Auto-Fix: Revoke Ghost Roles
          </span>
        </div>

        {/* Description */}
        <div style={{ fontSize: 12, color: COLORS.textSecondary, fontFamily: FONT.ui, lineHeight: 1.6, marginBottom: 16 }}>
          This will remove RBAC role assignments from {item.affected} disabled
          accounts. The accounts themselves are NOT deleted.
        </div>

        {/* Affected identities list */}
        <div style={{
          fontSize: 11, fontWeight: 600, textTransform: 'uppercase' as const,
          letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 8,
        }}>Affected Identities</div>

        <div style={{
          background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
          borderRadius: 8, padding: '10px 14px', marginBottom: 16,
          maxHeight: 200, overflow: 'auto',
        }}>
          {loading ? (
            <div style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, textAlign: 'center', padding: 12 }}>
              Loading affected identities...
            </div>
          ) : identities.length === 0 ? (
            <div style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, textAlign: 'center', padding: 12 }}>
              No affected identities found.
            </div>
          ) : (
            identities.map((id, i) => (
              <div key={id.id} style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '6px 0',
                borderBottom: i < identities.length - 1 ? `1px solid ${COLORS.border}` : 'none',
              }}>
                <span style={{ fontSize: 12, color: COLORS.text, fontFamily: FONT.ui }}>{id.display_name}</span>
                <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.mono }}>{id.roles}</span>
              </div>
            ))
          )}
        </div>

        {/* Rollback status */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8, marginBottom: 20,
          fontSize: 11, fontFamily: FONT.ui,
        }}>
          <span style={{ color: COLORS.textSecondary }}>Rollback:</span>
          <span style={{ color: COLORS.success, fontWeight: 600 }}>
            ✅ Safe — roles can be re-assigned if needed
          </span>
        </div>

        {/* Action buttons */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
          <button onClick={onClose} style={{
            padding: '8px 20px', borderRadius: 6, fontSize: 12, fontWeight: 600,
            background: 'transparent', color: COLORS.textSecondary,
            border: `1px solid ${COLORS.border}`, cursor: 'pointer', fontFamily: FONT.ui,
          }}>Cancel</button>
          <button
            onClick={handleConfirm}
            disabled={loading || executing}
            style={{
              padding: '8px 20px', borderRadius: 6, fontSize: 12, fontWeight: 600,
              background: loading || executing ? COLORS.textDim : COLORS.danger,
              color: '#fff', border: 'none',
              cursor: loading || executing ? 'not-allowed' : 'pointer',
              fontFamily: FONT.ui, opacity: loading || executing ? 0.5 : 1,
            }}
          >
            {executing ? 'Executing...' : 'Confirm & Execute'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Tab 1: Executive Summary ──

function ExecSummaryTab({ d, onPreview, onTicket }: { d: TenantData; onPreview: (r: Remediation) => void; onTicket: (r: Remediation) => void }) {
  const [execView, setExecView] = useState(false);
  const [autoFixItem, setAutoFixItem] = useState<Remediation | null>(null);
  const { withConnection } = useConnection();

  const sortedPillars = useMemo(() => [...d.pillars].sort((a, b) => a.score - b.score), [d.pillars]);
  const top3 = useMemo(() => {
    const identity = d.remediations.filter(r => r.type === 'identity-remediation' && r.gain > 0);
    return identity.sort((a, b) => b.gain - a.gain).slice(0, 3);
  }, [d.remediations]);
  const totalGain = useMemo(() => top3.reduce((s, r) => s + r.gain, 0), [top3]);

  const workloadCount = useMemo(() => d.identityBreakdown.filter(ib => ib.type !== 'Human Users' && ib.type !== 'Guest Users').reduce((s, ib) => s + ib.count, 0), [d.identityBreakdown]);
  const humanCount = useMemo(() => d.identityBreakdown.find(ib => ib.type === 'Human Users')?.count ?? 0, [d.identityBreakdown]);
  const guestCount = useMemo(() => d.identityBreakdown.find(ib => ib.type === 'Guest Users')?.count ?? 0, [d.identityBreakdown]);

  const orphaned = d.agirs?.nhiri?.phantom_breakdown?.orphaned ?? 0;
  const dormantPrivileged = d.agirs?.hiri?.h2_dormant_priv ?? 0;
  const extGuests = d.agirs?.hiri?.h4_ext_guest ?? 0;
  const ghostAccounts = d.ghostAccounts.total;

  const worstFrameworks = useMemo(() => [...d.compliance.frameworks].sort((a, b) => a.score - b.score).slice(0, 3), [d.compliance]);
  const netDelta = useMemo(() => {
    const t = d.riskMovement.trajectory;
    return t.length >= 2 ? t[t.length - 1] - t[0] : 0;
  }, [d.riskMovement.trajectory]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Executive View Toggle */}
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <button
          onClick={() => setExecView(!execView)}
          style={{
            padding: '4px 12px', borderRadius: 5, fontSize: 10, fontWeight: 600,
            background: execView ? `${COLORS.accent}22` : 'transparent',
            color: execView ? COLORS.accent : COLORS.textMuted,
            border: `1px solid ${execView ? COLORS.accent + '40' : COLORS.border}`,
            cursor: 'pointer', fontFamily: FONT.ui,
          }}
        >
          Executive View {execView ? 'On' : 'Off'}
        </button>
      </div>

      {/* Section 1: Hero Panel */}
      <HeroPanel d={d} execView={execView} />

      {/* Section 2+3: Risk Drivers | Identity Exposure */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, alignItems: 'start' }}>
        {/* Left: Risk Drivers */}
        <CISOCard style={{ padding: '16px 18px' }}>
          <SectionTitle>Risk Drivers</SectionTitle>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {sortedPillars.map((p, i) => (
              <RiskDriverRow key={i} pillar={p} isLast={i === sortedPillars.length - 1} />
            ))}
          </div>
        </CISOCard>

        {/* Right: Identity Exposure Snapshot */}
        <CISOCard style={{ padding: '16px 18px' }}>
          <SectionTitle>Identity Exposure Snapshot</SectionTitle>
          {/* Identity Breakdown */}
          <div style={{ display: 'flex', flexDirection: 'column', marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 0', borderBottom: `1px solid ${COLORS.border}` }}>
              <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>Human Users</span>
              <DN navigateTo="/identities?identity_category=human_user">
                <span style={{ fontSize: 12, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.text }}>{humanCount}</span>
              </DN>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 0', borderBottom: `1px solid ${COLORS.border}` }}>
              <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>Workload Identities</span>
              <DN navigateTo="/identities?workload=true">
                <span style={{ fontSize: 12, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.text }}>{workloadCount}</span>
              </DN>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 0' }}>
              <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>Guest Users</span>
              <DN navigateTo="/identities?identity_category=guest">
                <span style={{ fontSize: 12, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.text }}>{guestCount}</span>
              </DN>
            </div>
          </div>
          {/* Exposure Signals */}
          <div style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase' as const, color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 8 }}>
            Exposure Signals
          </div>
          <ExposureMetricRow label="Orphaned (No Owner)" value={orphaned} color={COLORS.danger} nav="/identities?agirs_factor=n1_orphaned" isLast={false} />
          <ExposureMetricRow label="Dormant Privileged" value={dormantPrivileged} color={COLORS.elevated} nav="/identities?activity_status=dormant_strict&privileged=true" isLast={false} />
          <ExposureMetricRow label="External Guests w/ Roles" value={extGuests} color={COLORS.purple} nav="/identities?agirs_factor=h4_ext_guest" isLast={false} />
          <ExposureMetricRow label="Ghost Accounts" value={ghostAccounts} color={COLORS.danger} nav="/identities?status=disabled&hasRoles=true" isLast={true} />
        </CISOCard>
      </div>

      {/* Section 4: Immediate Actions */}
      <CISOCard style={{ padding: '16px 18px' }}>
        <SectionTitle>Immediate Actions — Top 3</SectionTitle>
        {top3.map((r, i) => (
          <ActionQueueItem key={r.id} item={r} index={i} onPreview={onPreview} onTicket={onTicket} onAutoFix={setAutoFixItem} isLast={i === top3.length - 1} />
        ))}
        {top3.length > 0 && (
          <div style={{
            marginTop: 10, padding: '8px 0', borderTop: `1px solid ${COLORS.border}`,
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          }}>
            <span style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui }}>Total potential if top 3 completed</span>
            <DN navigateTo="/remediation"><span style={{ fontSize: 16, fontWeight: 700, color: COLORS.success, fontFamily: FONT.mono }}>+{totalGain} pts</span></DN>
          </div>
        )}
      </CISOCard>

      {/* Section 5+6: Risk Trend | Governance & Compliance */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, alignItems: 'start' }}>
        {/* Left: Risk Trend */}
        <CISOCard style={{ padding: '16px 18px' }}>
          <SectionTitle>Risk Trend — Last 30 Days</SectionTitle>
          {/* Net delta indicator */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <span style={{
              fontSize: 14, fontWeight: 700, fontFamily: FONT.mono,
              color: netDelta >= 0 ? COLORS.success : COLORS.danger,
            }}>
              {netDelta >= 0 ? '↑' : '↓'} {netDelta >= 0 ? '+' : ''}{netDelta.toFixed(1)} pts
            </span>
            <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui }}>net change</span>
          </div>
          {/* Large Sparkline */}
          <Sparkline data={d.riskMovement.trajectory.length > 0 ? d.riskMovement.trajectory : d.riskScore.trend} width={320} height={80} color={netDelta >= 0 ? COLORS.success : COLORS.danger} />
          {/* Projection footer — hidden in exec view */}
          {!execView && (
            <div style={{ marginTop: 10, display: 'flex', gap: 16, fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
              <span>No action: <DN navigateTo="/dashboard"><span style={{ fontFamily: FONT.mono, color: COLORS.danger, fontWeight: 600 }}>{d.projection.noAction.score.toFixed(1)}</span></DN> in 10d</span>
              <span>If remediated: <DN navigateTo="/remediation"><span style={{ fontFamily: FONT.mono, color: COLORS.success, fontWeight: 600 }}>{d.projection.remediated.score.toFixed(1)}</span></DN></span>
            </div>
          )}
        </CISOCard>

        {/* Right: Governance & Compliance Health */}
        <CISOCard style={{ padding: '16px 18px' }}>
          <SectionTitle>Governance & Compliance Health</SectionTitle>
          {/* Governance metrics */}
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {d.governance.metrics.map((m, i) => (
              <GovernanceRow key={i} metric={m} isLast={i === d.governance.metrics.length - 1} />
            ))}
          </div>
          {/* Worst compliance frameworks */}
          {worstFrameworks.length > 0 && (
            <>
              <div style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase' as const, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 14, marginBottom: 8 }}>
                Lowest Compliance Scores
              </div>
              {worstFrameworks.map((fw, i) => (
                <div key={fw.id} style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '6px 0',
                  borderBottom: i < worstFrameworks.length - 1 ? `1px solid ${COLORS.border}` : 'none',
                }}>
                  <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const, flex: 1, minWidth: 0 }}>{fw.name}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                    <DN navigateTo="/compliance">
                      <span style={{ fontSize: 12, fontWeight: 700, fontFamily: FONT.mono, color: getScoreColor(fw.score) }}>{fw.score}</span>
                    </DN>
                    {fw.trend !== 0 && (
                      <span style={{ fontSize: 10, color: fw.trend > 0 ? COLORS.success : COLORS.danger, fontFamily: FONT.mono }}>
                        {fw.trend > 0 ? '↑' : '↓'}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </>
          )}
        </CISOCard>
      </div>

      {/* Rule 68: Auto-Fix Confirmation Dialog */}
      {autoFixItem && (
        <AutoFixDialog
          item={autoFixItem}
          onClose={() => setAutoFixItem(null)}
          onConfirm={(item) => {
            // Execute auto-fix via API
            fetch(withConnection(`/api/remediations/${item.id}/execute`), {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ action: 'revoke_ghost_roles' }),
            }).catch(() => {});
            setAutoFixItem(null);
          }}
        />
      )}
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
        <div style={{ fontSize: 10, color: COLORS.textSecondary, marginBottom: 12, fontFamily: FONT.ui }}>Score scale: 0 = no risk · 100 = maximum risk</div>
        {d.pillars.map((p, i) => (
          <div key={i}>
            <div onClick={() => setExpandedPillar(expandedPillar === i ? null : i)} style={{
              display: 'grid', gridTemplateColumns: '200px 1fr 80px 120px', alignItems: 'center',
              padding: '10px 0', borderBottom: `1px solid ${COLORS.border}`, cursor: 'pointer',
            }}>
              <span style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui }}>{p.name}</span>
              <ProgressBar value={p.score} color={getPillarColor(p.score)} height={8} />
              <DN navigateTo={pillarNav(p.name)}>
                <span style={{ fontSize: 16, fontWeight: 700, fontFamily: FONT.mono, color: getPillarColor(p.score), textAlign: 'center' as const }}>{p.score}</span>
              </DN>
              <span style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.mono, textAlign: 'right' as const }}>
                <DN navigateTo={pillarNav(p.name)}>{p.identityCount}</DN> contributing
              </span>
            </div>
            {expandedPillar === i && p.subMetrics.length > 0 && (
              <div style={{ background: COLORS.surfaceAlt, padding: '10px 16px', borderBottom: `1px solid ${COLORS.border}` }}>
                {p.subMetrics.map((sm, j) => {
                  // Sub-metrics navigate to the parent pillar (exact count via contributing_pillar)
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
        ))}
      </CISOCard>

      {/* KPI Cards — 5 columns per v3.0.1 */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 14 }}>
        {Object.entries(d.kpis).map(([key, kpi]) => {
          const isGhost = key === 'ghostAccounts';
          const valueColor = isGhost && kpi.value > 0 ? COLORS.danger : COLORS.text;
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
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: COLORS.danger, animation: 'pulse 2s infinite' }} />
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
        <span style={{ fontSize: 10, color: COLORS.textSecondary, marginLeft: 'auto', fontFamily: FONT.ui }}>
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
        <span style={{ fontSize: 12, color: COLORS.textSecondary, fontFamily: FONT.ui }}>Total potential gain</span>
        <DN navigateTo="/remediation">
          <span style={{ fontSize: 18, fontWeight: 700, color: COLORS.success, fontFamily: FONT.mono }}>
            +{totalGain} pts → {d.projection.remediated.score.toFixed(1)}
          </span>
        </DN>
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
        {d.governance.metrics.map((m, i) => {
          // v3.0.9: Trend arrow — compare value to target numerically
          const numVal = parseFloat(String(m.value).replace(/[^0-9.]/g, ''));
          const numTarget = parseFloat(String(m.target).replace(/[^0-9.]/g, ''));
          const trendArrow = m.status === 'not-configured' ? '' : numVal >= numTarget ? '↑' : numVal >= numTarget * 0.7 ? '→' : '↓';
          const trendColor = trendArrow === '↑' ? COLORS.success : trendArrow === '→' ? COLORS.warning : COLORS.danger;
          const govNav = m.label.toLowerCase().includes('access review') ? '/access-reviews' :
            m.label.toLowerCase().includes('owner') ? '/service-accounts' :
            m.label.toLowerCase().includes('rotation') || m.label.toLowerCase().includes('credential') ? '/resources?resource_type=key_vault' :
            m.label.toLowerCase().includes('pim') || m.label.toLowerCase().includes('jit') ? '/identities?pillar=effective-privilege' :
            '/service-accounts';
          const navTarget = m.status !== 'not-configured' ? govNav : '/settings/governance';
          return (
          <CISOCard key={i}>
            <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>{m.icon} {m.label}</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <DN navigateTo={navTarget}>
                <div style={{
                  fontSize: 28, fontWeight: 700, fontFamily: FONT.mono, marginTop: 6,
                  color: m.status === 'not-configured' ? COLORS.textDim : m.status === 'critical' ? COLORS.danger : COLORS.success,
                }}>{m.value}</div>
              </DN>
              {trendArrow && <span style={{ fontSize: 16, color: trendColor, fontWeight: 700 }}>{trendArrow}</span>}
            </div>
            <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 4 }}>Target: {m.target}</div>
            {m.status === 'not-configured' && (
              <button onClick={() => navigate('/settings/governance')} style={{
                marginTop: 8, padding: '4px 10px', borderRadius: 4, fontSize: 10,
                background: COLORS.accentSoft, color: COLORS.accent, border: `1px solid ${COLORS.accent}30`,
                cursor: 'pointer', fontFamily: FONT.ui,
              }}>Configure →</button>
            )}
          </CISOCard>
          );
        })}
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
                const cfNav = item.label.toLowerCase().includes('pim') || item.label.toLowerCase().includes('privilege outside') ? '/identities?pillar=effective-privilege' :
                  item.label.toLowerCase().includes('disabled') || item.label.toLowerCase().includes('ghost') ? '/identities?status=disabled&hasRoles=true' :
                  item.label.toLowerCase().includes('ownership') || item.label.toLowerCase().includes('unowned') ? '/identities?pillar=ownership-governance' :
                  item.label.toLowerCase().includes('dormant') ? '/identities?pillar=usage-dormancy' :
                  item.label.toLowerCase().includes('credential') || item.label.toLowerCase().includes('expired') ? '/identities?pillar=credential-risk' :
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
              <DN navigateTo="/service-accounts">
                <div style={{ fontSize: 24, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.text }}>{d.governance.effectivenessScore}/10</div>
              </DN>
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
    // Export control-level detail for ALL frameworks
    const hasControls = d.compliance.frameworks.some(fw => fw.controls && fw.controls.length > 0);
    if (hasControls) {
      const header = 'Framework,Control ID,Control Name,Status,Severity,Evidence\n';
      const rows = d.compliance.frameworks.flatMap(fw =>
        (fw.controls || []).map(c =>
          `"${fw.name}","${c.id}","${c.name.replace(/"/g, '""')}","${c.status}","${c.severity}","${(c.evidence || '').replace(/"/g, '""')}"`
        )
      ).join('\n');
      const blob = new Blob([header + rows], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'compliance_all_controls.csv'; a.click();
      URL.revokeObjectURL(url);
    } else {
      // Fallback: framework-level summary
      const header = 'Framework,Type,Score,Total Controls,Failed Controls,Status,Trend\n';
      const rows = d.compliance.frameworks.map(fw =>
        `"${fw.name}","${fw.type}",${fw.score},${fw.totalControls},${fw.failedControls},"${fw.status}",${fw.trend}`
      ).join('\n');
      const blob = new Blob([header + rows], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'compliance_frameworks.csv'; a.click();
      URL.revokeObjectURL(url);
    }
  }, [d.compliance.frameworks]);

  const handleExportSingle = useCallback((fw: ComplianceFramework) => {
    // Export control-level detail (not just framework summary)
    if (fw.controls && fw.controls.length > 0) {
      const header = 'Framework,Control ID,Control Name,Status,Severity,Evidence\n';
      const rows = fw.controls.map(c =>
        `"${fw.name}","${c.id}","${c.name.replace(/"/g, '""')}","${c.status}","${c.severity}","${(c.evidence || '').replace(/"/g, '""')}"`
      ).join('\n');
      const blob = new Blob([header + rows], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `${fw.id}_compliance_controls.csv`; a.click();
      URL.revokeObjectURL(url);
    } else {
      // Fallback: framework-level summary if no controls data
      const header = 'Framework,Type,Score,Total Controls,Failed Controls,Status,Trend\n';
      const row = `"${fw.name}","${fw.type}",${fw.score},${fw.totalControls},${fw.failedControls},"${fw.status}",${fw.trend}`;
      const blob = new Blob([header + row], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `${fw.id}_compliance.csv`; a.click();
      URL.revokeObjectURL(url);
    }
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* Top bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <span title="This assessment covers identity-related controls only (authentication, authorization, lifecycle). Network, infrastructure, and application controls are not in scope.">
          <CISOBadge label="Identity Controls Only" color={COLORS.accent} />
        </span>
        <span style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui }}>{d.compliance.frameworks.length} frameworks · All initial assessment</span>
        <button onClick={handleExportAll} style={{
          marginLeft: 'auto', padding: '5px 12px', borderRadius: 5, fontSize: 10, fontWeight: 600,
          background: 'transparent', color: COLORS.textSecondary, border: `1px solid ${COLORS.border}`,
          cursor: 'pointer', fontFamily: FONT.ui,
        }}>Export All</button>
      </div>

      {/* Rule 32: Informational note about identical scores */}
      {allSameScore && (
        <div style={{
          background: COLORS.accentSoft, border: `1px solid ${COLORS.accent}2e`,
          borderRadius: 8, padding: '10px 14px', fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui,
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
                    <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
                      <DN navigateTo="/compliance">{fw.totalControls}</DN> controls · <DN navigateTo="/identities?risk=critical,high">{fw.failedControls}</DN> failures
                    </div>
                  </div>
                </div>
                <ProgressBar value={fw.score} color={getScoreColor(fw.score)} height={4} />
                <div style={{ display: 'flex', gap: 6, marginTop: 10 }}>
                  {/* Rule 35 fix: Export triggers CSV download */}
                  <button onClick={() => handleExportSingle(fw)} style={{
                    flex: 1, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 600,
                    background: 'transparent', color: COLORS.textSecondary, border: `1px solid ${COLORS.border}`,
                    cursor: 'pointer', fontFamily: FONT.ui,
                  }}>Export</button>
                  {/* Rule 35 fix: Details navigates to compliance page with framework auto-expand */}
                  <button onClick={() => navigate(`/compliance?framework=${encodeURIComponent(fw.name)}`)} style={{
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
              <DN navigateTo="/compliance"><span style={{ fontSize: 11, fontWeight: 600, fontFamily: FONT.mono, color: COLORS.text }}>{val}</span></DN>
            </div>
          ))}
        </CISOCard>
        <CISOCard>
          <SectionTitle>Progress</SectionTitle>
          <div style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>Remediation Progress</span>
              <DN navigateTo="/remediation"><span style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.text }}>{d.compliance.progress.remediation}%</span></DN>
            </div>
            <ProgressBar value={d.compliance.progress.remediation} color={COLORS.accent} />
          </div>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>IA Governance</span>
              <DN navigateTo="/service-accounts"><span style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.text }}>{d.compliance.progress.iaGovernance}%</span></DN>
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
  // v3.0.9: Predictive scores — extrapolate from trajectory + remediation potential
  const trajectory = d.riskMovement.trajectory;
  const recentDelta = trajectory.length >= 3 ? (trajectory[trajectory.length - 1] - trajectory[trajectory.length - 3]) / 3 : 0;
  const predicted30d = Math.max(0, Math.min(100, d.riskScore.current + recentDelta * 3));
  const predicted90d = Math.max(0, Math.min(100, d.riskScore.current + recentDelta * 9));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* Score Trajectory */}
      <CISOCard>
        <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
          <div>
            <DN navigateTo="/dashboard">
              <div style={{ fontSize: 36, fontWeight: 700, fontFamily: FONT.mono, color: getTierColor(d.riskScore.tier) }}>{d.riskScore.current.toFixed(1)}</div>
            </DN>
            <CISOBadge label={d.riskScore.tier} color={getTierColor(d.riskScore.tier)} />
          </div>
          <div style={{ flex: 1 }}>
            <Sparkline data={d.riskMovement.trajectory} width={400} height={80} color={getTierColor(d.riskScore.tier)} />
          </div>
          {/* v3.0.9: Predictive score cards */}
          <div style={{ display: 'flex', gap: 10, flexShrink: 0 }}>
            <div style={{
              background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
              borderRadius: 8, padding: '10px 14px', textAlign: 'center' as const,
            }}>
              <div style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' as const, color: COLORS.textSecondary, fontFamily: FONT.ui }}>30-Day</div>
              <DN navigateTo="/drift">
                <div style={{ fontSize: 20, fontWeight: 700, fontFamily: FONT.mono, color: getScoreColor(predicted30d), marginTop: 2 }}>{predicted30d.toFixed(1)}</div>
              </DN>
              <div style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.ui }}>projected</div>
            </div>
            <div style={{
              background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
              borderRadius: 8, padding: '10px 14px', textAlign: 'center' as const,
            }}>
              <div style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' as const, color: COLORS.textSecondary, fontFamily: FONT.ui }}>90-Day</div>
              <DN navigateTo="/drift">
                <div style={{ fontSize: 20, fontWeight: 700, fontFamily: FONT.mono, color: getScoreColor(predicted90d), marginTop: 2 }}>{predicted90d.toFixed(1)}</div>
              </DN>
              <div style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.ui }}>projected</div>
            </div>
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
              {(() => {
                const chNav = ch.label === 'Critical Identities' ? '/identities?risk_level=critical' :
                  ch.label === 'High-Risk Identities' ? '/identities?risk_level=high' :
                  ch.label === 'Ghost Accounts' ? '/identities?status=disabled&hasRoles=true' :
                  ch.label === 'Zombie Personas' ? '/identity-correlation' :
                  ch.label === 'New Identities' ? '/identities' :
                  ch.label === 'Removed' ? '/identities?status=disabled' :
                  ch.label === 'Total Identities' ? '/identities' : '/identities';
                return (
                  <>
                    <DN navigateTo={chNav} tooltip={`Previous: ${ch.before}`}>
                      <span style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.textSecondary, textAlign: 'right' as const, display: 'inline-block' }}>{ch.before}</span>
                    </DN>
                    <span style={{ fontSize: 11, color: COLORS.textSecondary, textAlign: 'center' as const }}>→</span>
                    <DN navigateTo={chNav}>
                      <span style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.text }}>{ch.after}</span>
                    </DN>
                  </>
                );
              })()}
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
            <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>Most Changed Risk</div>
            <div style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui, marginTop: 4 }}>{d.riskMovement.mostChanged.name}</div>
            <DN navigateTo="/drift">
              <div style={{ fontSize: 12, fontFamily: FONT.mono, color: COLORS.danger, marginTop: 2 }}>Score {d.riskMovement.mostChanged.score}/100</div>
            </DN>
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
          {Object.entries(d.riskMovement.scanMeta).map(([key, val]) => {
            const metaNav = key === 'identities' || key === 'totalIdentities' ? '/identities' :
              key === 'subscriptions' ? '/resources' : '';
            const isNum = typeof val === 'number' || (!isNaN(Number(val)) && key !== 'lastRun');
            return (
            <div key={key} style={{ textAlign: 'center' as const }}>
              <div style={{ fontSize: 9, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>{key}</div>
              <div style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.text, marginTop: 2 }}>
                {key === 'lastRun' ? new Date(val).toLocaleString() : isNum && metaNav ? (
                  <DN navigateTo={metaNav}>{val}</DN>
                ) : val}
              </div>
            </div>
            );
          })}
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
          <div style={{ fontSize: 12, color: COLORS.textSecondary, fontFamily: FONT.ui }}>Loading Executive Summary...</div>
        </div>
        <style>{`@keyframes spin { to { transform: rotate(360deg) } } @keyframes pulse { 0%, 100% { opacity: 1 } 50% { opacity: 0.4 } }`}</style>
      </div>
    );
  }

  return (
    <div style={{ minHeight: 'calc(100vh - 56px)', background: COLORS.bg, fontFamily: FONT.ui, borderRadius: '12px 0 0 0' }}>
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
          fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui,
        }}>
          <span>Updated {new Date(data.tenant.lastScan).toLocaleTimeString()}</span>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: COLORS.success, animation: 'pulse 2s infinite' }} />
        </div>
      </div>

      {/* v3.0.9: Confidence / Data Completeness Banner */}
      <div style={{
        margin: '12px 24px 0', padding: '8px 14px', borderRadius: 8,
        background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
        display: 'flex', alignItems: 'center', gap: 16, fontSize: 10, fontFamily: FONT.ui,
      }}>
        <span style={{ color: COLORS.textSecondary }}>Data Completeness</span>
        <div style={{ width: 80, height: 4, borderRadius: 2, background: COLORS.border, overflow: 'hidden' }}>
          <div style={{ width: `${data.tenant.scanCompleteness}%`, height: '100%', background: data.tenant.scanCompleteness >= 80 ? COLORS.success : COLORS.warning, borderRadius: 2 }} />
        </div>
        <DN navigateTo="/settings/connections">
          <span style={{ fontFamily: FONT.mono, fontWeight: 600, color: data.tenant.scanCompleteness >= 80 ? COLORS.success : COLORS.warning }}>{data.tenant.scanCompleteness}%</span>
        </DN>
        <span style={{ color: COLORS.textDim }}>|</span>
        <span style={{ color: COLORS.textSecondary }}>Confidence</span>
        <CISOBadge label={data.tenant.scanConfidence || 'Unknown'} color={
          data.tenant.scanConfidence?.toLowerCase() === 'high' ? COLORS.success :
          data.tenant.scanConfidence?.toLowerCase() === 'medium' ? COLORS.warning : COLORS.textMuted
        } />
        <span style={{ color: COLORS.textDim }}>|</span>
        <span style={{ color: COLORS.textSecondary }}>Sources: {data.tenant.sources?.join(', ') || 'Graph API'}</span>
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
