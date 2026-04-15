/**
 * Shared presentational helpers for CISO Dashboard components.
 * Extracted from CISODashboard.tsx for modularization — zero behavioral change.
 */
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { COLORS, getScoreColor, getGrade } from '../../constants/ciso';
import { useIdentityDrawer, type IdentityPrefill } from '../../contexts/IdentityDrawerContext';

// ─── Typography Helpers ──────────────────────────────────────────

export const FONT = {
  ui: "'Inter', sans-serif",
  mono: "'JetBrains Mono', monospace",
};

// ─── Reusable Components ─────────────────────────────────────────

export function ScoreRing({ score, size = 96, strokeWidth = 6, color, displayValue }: {
  score: number; size?: number; strokeWidth?: number; color?: string; displayValue?: string;
}) {
  const isNoData = score === 0 && !displayValue;
  const c = isNoData ? COLORS.textDim : (color || getScoreColor(score));
  const r = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * r;
  const offset = isNoData ? circumference : circumference - (score / 100) * circumference;
  const fontSize = Math.min(32, Math.floor(size * 0.26));
  const grade = isNoData ? '' : getGrade(score);
  const label = isNoData ? 'N/A' : (displayValue ?? score.toFixed(1));
  return (
    <svg width={size} height={size} style={{ display: 'block' }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none"
        stroke={COLORS.border} strokeWidth={strokeWidth} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none"
        stroke={c} strokeWidth={strokeWidth} strokeLinecap="round"
        strokeDasharray={circumference} strokeDashoffset={offset}
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
        style={{ transition: 'stroke-dashoffset 1.4s cubic-bezier(0.4,0,0.2,1)' }} />
      <text x={size / 2} y={isNoData ? size / 2 : size / 2 - 4} textAnchor="middle" dominantBaseline="central"
        fill={isNoData ? COLORS.textMuted : COLORS.text} fontFamily={FONT.mono} fontWeight={isNoData ? 600 : 700} fontSize={isNoData ? Math.floor(fontSize * 0.7) : fontSize}>
        {label}
      </text>
      {!isNoData && (
        <text x={size / 2} y={size / 2 + 18} textAnchor="middle" dominantBaseline="central"
          fill={COLORS.textSecondary} fontFamily={FONT.mono} fontWeight={600} fontSize={10}>
          {grade}
        </text>
      )}
    </svg>
  );
}

export function Sparkline({ data, width = 90, height = 22, color }: {
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
  return (
    <svg width={width} height={height}>
      <polygon points={`0,${height} ${pts} ${width},${height}`} fill={c} opacity={0.15} />
      <polyline points={pts} fill="none" stroke={c} strokeWidth={1.5} />
      <circle cx={lx} cy={ly} r={3} fill={c} />
    </svg>
  );
}

export function CISOBadge({ label, color }: { label: string; color: string }) {
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

export function ProgressBar({ value, color, height = 6 }: { value: number; color: string; height?: number }) {
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

export function StatBox({ label, value, color, sub }: {
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

export function SectionTitle({ children, right, onRightClick }: { children: string; right?: string; onRightClick?: () => void }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
      <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.12em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>{children}</span>
      {right && <span onClick={onRightClick} style={{ fontSize: 10, color: COLORS.accent, cursor: onRightClick ? 'pointer' : 'default', fontFamily: FONT.ui }}>{right}</span>}
    </div>
  );
}

export function CISOCard({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <div style={{
      background: COLORS.surface, border: `1px solid ${COLORS.border}`,
      borderRadius: 12, padding: '18px 20px', ...style,
    }}>
      {children}
    </div>
  );
}

// ─── DrillableNumber (v3.1.0: every number clickable) ────────────

export function DN({ children, navigateTo, tooltip, prefill }: {
  children: React.ReactNode; navigateTo?: string; tooltip?: string;
  /** Pre-populated identity metadata shown immediately while detail loads. */
  prefill?: IdentityPrefill;
}) {
  const navigate = useNavigate();
  const drawerCtx = useIdentityDrawer();
  if (!navigateTo) {
    return <span title={tooltip}>{children}</span>;
  }
  return (
    <span
      onClick={(e) => {
        e.stopPropagation();
        if (drawerCtx && navigateTo.startsWith('/identities')) {
          // Direct identity link: /identities/123 or /identities/uuid → open detail view
          const idMatch = navigateTo.match(/^\/identities\/([^?/]+)$/);
          if (idMatch) {
            const raw = idMatch[1];
            if (raw === 'undefined' || raw === 'null' || !raw) return; // guard against bad IDs
            const numVal = parseInt(raw, 10);
            // Accept both numeric DB ids and UUID identity_ids
            drawerCtx.openIdentity(!isNaN(numVal) && String(numVal) === raw ? numVal : raw, prefill);
          } else {
            // Filtered list: /identities?filter=X → open list view
            drawerCtx.openDrawer(navigateTo);
          }
        } else {
          navigate(navigateTo);
        }
      }}
      title={tooltip || `Click to view details`}
      style={{
        cursor: 'pointer',
      }}
    >
      {children}
    </span>
  );
}

// ─── InsightSentence ─────────────────────────────────────────────

export function InsightSentence({ children, icon }: { children: React.ReactNode; icon?: string }) {
  return (
    <div className="flex items-start gap-2 py-1.5">
      <span className="text-[11px] flex-shrink-0 mt-0.5">{icon || '→'}</span>
      <span className="text-[11.5px] text-[#8fa3bf] leading-relaxed">{children}</span>
    </div>
  );
}

// ─── SeverityPill ────────────────────────────────────────────────

const PILL_CLS: Record<string, string> = {
  critical: 'bg-[rgba(232,70,90,0.15)] text-[#e8465a]',
  high: 'bg-[rgba(255,114,22,0.15)] text-[#FF7216]',
  medium: 'bg-[rgba(245,158,11,0.12)] text-[#f59e0b]',
  low: 'bg-[rgba(34,197,94,0.12)] text-[#22c55e]',
};

export function SeverityPill({ severity }: { severity: string }) {
  const cls = PILL_CLS[severity] || PILL_CLS.medium;
  return (
    <span className={`inline-block text-[9px] font-semibold uppercase tracking-[0.5px] px-2 py-[2px] rounded-full ${cls}`}>
      {severity}
    </span>
  );
}

// ─── Navigation Helpers ──────────────────────────────────────────

export function pillarNav(name: string): string {
  const n = name.toLowerCase();
  if (n.includes('privilege'))                     return '/identities?pillar=effective-privilege';
  if (n.includes('credential'))                    return '/identities?pillar=credential-risk';
  if (n.includes('trust') || n.includes('feder'))  return '/identities?pillar=trust-federation';
  if (n.includes('usage') || n.includes('dorma'))  return '/identities?pillar=usage-dormancy';
  if (n.includes('ownership') || n.includes('gov'))return '/identities?pillar=ownership-governance';
  if (n.includes('external') || n.includes('expo'))return '/identities?pillar=external-exposure';
  return '/identities';
}
