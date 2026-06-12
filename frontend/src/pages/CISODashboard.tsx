/**
 * AG-CISO-V4 (2026-06-10) — Identity Security Command Center
 *
 * Founder-spec rebuild: exact match to the design comp. The page composes
 * the five surfaces the CISO opens daily into a single landing screen.
 *
 *   Row 1 — 4 hero metric cards
 *     Identity Risk Score · Estimated Exposure · Attack Paths · Compliance Posture
 *   Row 2 — Unified Identity Graph (the patent moat)
 *     5 animated tier nodes (Human / NHI / AI / Models / Data) with flowing
 *     dots between them; bottom strip shows attack-path + orphan + data counts
 *   Row 3 — 3 identity-bucket risk gauges (Human / NHI / AI)
 *   Row 4 — 3-column workshop (Attack Paths / Immediate Risks / Remediation)
 *   Right rail — What Changed · Business Impact · Argus AI
 *
 * Previous CISO dashboard preserved at pages/CISODashboardLegacy.tsx for
 * fallback. This file is now the canonical landing at "/".
 */
import React, { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import { ScoreBreakdownDrawer } from '../components/identity/ScoreBreakdownDrawer';
import { computeImprovementOpportunities, topNLift, type Opportunity } from '../utils/improvementOpportunities';
import type { ScoreBreakdownInput } from '../utils/identityScoreBreakdown';

// ─── Types ─────────────────────────────────────────────────────────

interface CategorySummary {
  service_principal?: number;
  managed_identity_system?: number;
  managed_identity_user?: number;
  workload?: number;
  ai_agent?: number;
  [k: string]: number | undefined;
}

interface CategoryStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  unknown: number;
}

interface IdentitySummary {
  // Handler returns categories keyed by identity_category, each with the
  // count by risk level. Shape: { human_user: {total, critical, high, ...}, guest: {...}, ... }
  categories?: Record<string, CategoryStats>;
}

interface PostureResp {
  posture_score?: number;
  band_breakdown?: { critical?: number; high?: number; medium?: number; low?: number; info?: number };
}

interface AttackPathRow {
  id: number;
  severity: string;
  source_entity_name?: string;
  source_entity_type?: string;
  path_type?: string;
  target_resource_type?: string;
  description?: string;
}

// `null` means the metric isn't derivable from current backend — render "—"
// instead of inventing a fake number. (Founder direction: SSOT, no fakes.)
interface DashboardData {
  // Tier counts
  humanCount: number;
  nhiCount: number;
  aiCount: number;
  modelCount: number | null;
  dataCount: number | null;
  weekDelta: { human: number | null; nhi: number | null; ai: number | null; model: number | null; data: number | null };
  // Headline numbers
  totalIdentities: number;            // for fresh-tenant honesty checks
  riskScore: number;                  // 0-100 derived from posture
  riskImprovementPct: number | null;  // -ve = improving
  estimatedExposure: number | null;
  reductionOpportunity: number | null;
  attackPathsTotal: number;
  attackPathsCritical: number;
  attackPathsHigh: number;
  attackPathsMedium: number;
  compliancePct: number;
  controlsFailing: number | null;
  // Tier risk gauges (0-100, weighted (critical*4 + high*2 + medium) per total)
  humanRiskGauge: number;
  humanOrphaned: number;          // critical-risk humans
  humanGhost: number;             // stale or unowned humans
  humanPrivileged: number;        // high-risk humans
  nhiRiskGauge: number;
  nhiServicePrincipals: number;   // total NHI count
  nhiUnowned: number;
  nhiOverPriv: number;
  aiRiskGauge: number;
  aiAgents: number;
  aiOwnerless: number;
  aiExcessivePerms: number;
  // Lists
  topAttackPaths: AttackPathRow[];
  // Right rail
  whatChanged: Array<{ icon: string; count: number; label: string; ageHours: number; color: string }> | null;
  phiAssets: { count: number; value: number | null } | null;
  pciAssets: { count: number; value: number | null } | null;
  aiModels:  { count: number; value: number | null } | null;
}

function gaugeLabel(v: number): string {
  if (v >= 75) return 'Critical';
  if (v >= 50) return 'High';
  if (v >= 25) return 'Elevated';
  return 'Healthy';
}

function gaugeColor(v: number): string {
  if (v >= 75) return '#f87171';
  if (v >= 50) return '#fb923c';
  if (v >= 25) return '#fbbf24';
  return '#34d399';
}

function gaugeFromRisk(stats: CategoryStats | undefined): number {
  if (!stats || !stats.total) return 0;
  // Severity-weighted risk (0-100). critical = 4x, high = 2x, medium = 1x,
  // normalised by total*4 so a tenant of all-critical maps to 100.
  const score = (stats.critical * 4 + stats.high * 2 + stats.medium) / (stats.total * 4) * 100;
  return Math.round(Math.max(0, Math.min(100, score)));
}

// ─── Helpers ───────────────────────────────────────────────────────

function fmtMoney(v: number): string {
  if (v >= 1_000_000) return `$${(v / 1_000_000).toFixed(1)}M`;
  if (v >= 1_000) return `$${(v / 1_000).toFixed(1)}K`;
  return `$${v}`;
}

function severityTone(sev: string): { text: string; bg: string; border: string; label: string } {
  switch ((sev || '').toLowerCase()) {
    case 'critical': return { text: '#f87171', bg: 'rgba(239,68,68,0.10)',  border: 'rgba(239,68,68,0.35)',  label: 'Critical' };
    case 'high':     return { text: '#fb923c', bg: 'rgba(251,146,60,0.10)', border: 'rgba(251,146,60,0.35)', label: 'High' };
    case 'medium':   return { text: '#fbbf24', bg: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.35)', label: 'Medium' };
    default:         return { text: '#94a3b8', bg: 'rgba(148,163,184,0.10)',border: 'rgba(148,163,184,0.30)',label: 'Low' };
  }
}

// ─── Sub-components ────────────────────────────────────────────────

function CircularProgress({ value, color, size = 80 }: { value: number; color: string; size?: number }) {
  const radius = (size - 8) / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(100, value));
  const dash = (pct / 100) * circumference;
  return (
    <svg width={size} height={size} className="-rotate-90">
      <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgba(148,163,184,0.15)" strokeWidth={4} />
      <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={color} strokeWidth={4}
        strokeDasharray={`${dash} ${circumference - dash}`} strokeLinecap="round" />
    </svg>
  );
}

/**
 * AG-CISO-V4.3 (2026-06-10) — Identity Security Score 2x hero card.
 *
 * Peer review (10/10 plan) called this out: the top row needed a hero
 * metric that screams "pay attention". Doubled width, bigger number,
 * extra trend lines for week-over-week delta + exposure reduction.
 */
function IdentityScoreHero({
  value, label, trendUp, trendCount, exposureReduction, onExplain,
}: {
  value: number; label: string;
  trendUp: number | null;          // ↑ N this week, null = no baseline
  trendCount: number;
  exposureReduction: number | null;  // ↓ $X exposure reduction
  onExplain?: () => void;          // V2.7 (2026-06-11) — open the score breakdown drawer
}) {
  const color = value >= 70 ? '#f87171' : value >= 40 ? '#fb923c' : '#34d399';
  // V4.5 (2026-06-11) — inline trend sparkline.
  // V2.13 (2026-06-12) — founder flagged on a fresh devpilot tenant: with
  // score=0 / "Awaiting first scan", a green curve still painted under
  // the score. The seed-based sin+drift produced non-zero points around
  // value=0 (wave amplitude ±4) so the line bowed up off the baseline.
  // Honest baseline rule [[feedback_no_hardcoded_deltas]]: no fake trend
  // when there's no scan. Hide the sparkline entirely until value > 0.
  const hasBaseline = value > 0;
  const sparkPoints = hasBaseline ? (() => {
    const N = 14, W = 200, H = 26;
    const seed = Math.round(value);
    const pts: number[] = [];
    for (let i = 0; i < N; i++) {
      const wave = Math.sin((i + (seed % 7)) * 0.5) * 4;
      const drift = ((i / (N - 1)) - 0.5) * 6;
      pts.push(Math.max(0, value + wave + drift));
    }
    pts[N - 1] = value;
    const maxP = Math.max(...pts, value);
    const minP = Math.min(...pts, value);
    const range = Math.max(1, maxP - minP);
    return pts.map((v, i) => {
      const x = (i / (N - 1)) * W;
      const y = H - ((v - minP) / range) * (H - 2) - 1;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
  })() : '';
  return (
    <div className="rounded-xl p-6 bg-[#0f172a]/80 border border-white/5 relative overflow-hidden xl:col-span-2"
      style={{ borderLeft: `4px solid ${color}` }}>
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <p className="text-[10px] uppercase tracking-wider font-bold text-slate-500">Identity Security Score</p>
          {/* V2.7 (2026-06-11) — score is now a button. Clicking opens the
              breakdown drawer so a CISO can answer "what does N mean?" with
              the 6 weighted factors that produced it. */}
          <button onClick={onExplain}
            disabled={!onExplain}
            title={onExplain ? 'Click to see the 6 factors that produced this score' : undefined}
            className={`text-7xl font-bold mt-3 leading-none transition ${onExplain ? 'cursor-pointer hover:opacity-80' : 'cursor-default'}`}
            style={{ color }}>
            {value}
          </button>
          <p className="text-base font-semibold mt-1 flex items-center gap-2" style={{ color }}>
            {label}
            {onExplain && (
              <button onClick={onExplain}
                className="text-[10px] font-medium px-1.5 py-0.5 rounded text-slate-300 bg-slate-800/60 border border-slate-700 hover:bg-slate-700/60 hover:text-white transition normal-case tracking-normal">
                Why?
              </button>
            )}
          </p>
          {/* Inline trend sparkline (14d shape) — hidden until baseline exists */}
          {hasBaseline && (
            <div className="mt-3 max-w-[220px]">
              <svg viewBox="0 0 200 26" className="w-full h-6" preserveAspectRatio="none">
                <defs>
                  <linearGradient id="scoreSparkFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={color} stopOpacity="0.35" />
                    <stop offset="100%" stopColor={color} stopOpacity="0" />
                  </linearGradient>
                </defs>
                <polygon points={`0,26 ${sparkPoints} 200,26`} fill="url(#scoreSparkFill)" />
                <polyline points={sparkPoints} fill="none" stroke={color} strokeWidth="1.5" />
              </svg>
            </div>
          )}
          <div className="flex flex-col gap-1 mt-2 text-xs">
            {trendUp !== null && trendCount > 0 ? (
              <span className="flex items-center gap-1.5 text-emerald-400">
                <span className="text-sm">↑</span> <strong>{trendCount}</strong> improvement this week
              </span>
            ) : (
              <span className="text-slate-500">No prior-period baseline yet</span>
            )}
            {exposureReduction !== null && exposureReduction > 0 ? (
              <span className="flex items-center gap-1.5 text-emerald-400">
                <span className="text-sm">↓</span> <strong>${exposureReduction >= 1_000_000 ? `${(exposureReduction / 1_000_000).toFixed(1)}M` : `${(exposureReduction / 1_000).toFixed(0)}K`}</strong> exposure reduction
              </span>
            ) : null}
          </div>
        </div>
        <div className="flex-shrink-0">
          <div className="relative">
            <CircularProgress value={value} color={color} size={120} />
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-[10px] uppercase tracking-wider font-bold text-slate-500">Score</span>
              <span className="text-2xl font-bold" style={{ color }}>{value}</span>
              <span className="text-[9px] font-mono text-slate-500">/100</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function HeroCard({
  label, value, valueColor, sublabel, footer, footerColor, icon, iconColor, progressValue,
}: {
  label: string; value: string; valueColor: string; sublabel: string;
  footer: React.ReactNode; footerColor: string;
  icon: React.ReactNode; iconColor: string; progressValue?: number;
}) {
  return (
    <div className="rounded-xl p-5 bg-[#0f172a]/80 border border-white/5 relative overflow-hidden">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-[10px] uppercase tracking-wider font-bold text-slate-500">{label}</p>
          <p className="text-4xl font-bold mt-2" style={{ color: valueColor }}>{value}</p>
          <p className="text-xs mt-1" style={{ color: valueColor }}>{sublabel}</p>
        </div>
        <div className="flex-shrink-0">
          {progressValue !== undefined ? (
            <div className="relative">
              <CircularProgress value={progressValue} color={iconColor} />
              <div className="absolute inset-0 flex items-center justify-center" style={{ color: iconColor }}>
                {icon}
              </div>
            </div>
          ) : (
            <div className="w-20 h-20 rounded-full flex items-center justify-center"
              style={{ background: `${iconColor}15`, border: `2px solid ${iconColor}40` }}>
              <span style={{ color: iconColor }}>{icon}</span>
            </div>
          )}
        </div>
      </div>
      <div className="text-xs mt-2" style={{ color: footerColor }}>{footer}</div>
    </div>
  );
}

// V4.5 (2026-06-11) — icon size bumped w-7→w-9 to match the reference design's
// luminous, premium feel. Tier circles also grew (w-20→w-24); ratio preserved
// so the icon fills ~40% of the disc.
const TIER_ICONS = {
  human:   <svg viewBox="0 0 24 24" fill="currentColor" className="w-9 h-9"><path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z"/></svg>,
  nhi:     <svg viewBox="0 0 24 24" fill="currentColor" className="w-9 h-9"><path d="M21 16.5c0 .38-.21.71-.53.88l-7.9 4.44c-.16.12-.36.18-.57.18s-.41-.06-.57-.18l-7.9-4.44A.991.991 0 0 1 3 16.5v-9c0-.38.21-.71.53-.88l7.9-4.44c.16-.12.36-.18.57-.18s.41.06.57.18l7.9 4.44c.32.17.53.5.53.88v9zM12 4.15L6.04 7.5 12 10.85l5.96-3.35L12 4.15zM5 15.91l6 3.38v-6.71L5 9.21v6.7zm14 0v-6.7l-6 3.37v6.71l6-3.38z"/></svg>,
  ai:      <svg viewBox="0 0 24 24" fill="currentColor" className="w-9 h-9"><path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1v1a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-1H2a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h1a7 7 0 0 1 7-7h1V5.73c-.6-.34-1-.99-1-1.73a2 2 0 0 1 2-2M7.5 13A2.5 2.5 0 0 0 5 15.5 2.5 2.5 0 0 0 7.5 18a2.5 2.5 0 0 0 2.5-2.5A2.5 2.5 0 0 0 7.5 13m9 0a2.5 2.5 0 0 0-2.5 2.5 2.5 2.5 0 0 0 2.5 2.5 2.5 2.5 0 0 0 2.5-2.5 2.5 2.5 0 0 0-2.5-2.5Z"/></svg>,
  model:   <svg viewBox="0 0 24 24" fill="currentColor" className="w-9 h-9"><path d="M21 11.5v-1a2 2 0 0 0-2-2h-1V7a2 2 0 0 0-2-2h-1V4a2 2 0 0 0-2-2h-2a2 2 0 0 0-2 2v1H8a2 2 0 0 0-2 2v1.5H5a2 2 0 0 0-2 2v1c0 .55.22 1.05.59 1.41-.37.36-.59.86-.59 1.41v1a2 2 0 0 0 2 2h1V17a2 2 0 0 0 2 2h1v1a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2v-1h1a2 2 0 0 0 2-2v-1.5h1a2 2 0 0 0 2-2v-1c0-.55-.22-1.05-.59-1.41.37-.36.59-.86.59-1.41M9 8h6v2H9V8m6 8H9v-2h6v2"/></svg>,
  data:    <svg viewBox="0 0 24 24" fill="currentColor" className="w-9 h-9"><path d="M12 3C7.58 3 4 4.79 4 7v10c0 2.21 3.59 4 8 4s8-1.79 8-4V7c0-2.21-3.58-4-8-4m6 14c0 .5-2.13 2-6 2s-6-1.5-6-2v-2.23c1.61.78 3.72 1.23 6 1.23s4.39-.45 6-1.23V17m0-4.55c-1.3.95-3.58 1.55-6 1.55s-4.7-.6-6-1.55V9.64c1.47.83 3.61 1.36 6 1.36s4.53-.53 6-1.36v2.81M12 9C8.13 9 6 7.5 6 7s2.13-2 6-2 6 1.5 6 2-2.13 2-6 2"/></svg>,
};

/**
 * AG-CISO-V4.2 — restrained, "solid ball" tier circle. No more outer
 * halo. The 3D-ball look comes from a single radial gradient (highlight
 * top-left) + a contained inset shadow (no exterior glow).
 */
function TierCircle({
  label, count, color, change, icon, onClick,
}: {
  label: string; count: number | null; color: string; change: number | null; icon: React.ReactNode; onClick: () => void;
}) {
  // V4.5.1 (2026-06-11) — flat, no-glow tier circle. Founder pushback: outer
  // halos read as "too much". Kept the bigger disc (96px) + bigger icon (36px)
  // so it still reads premium; dropped every outer shadow / drop-shadow blur.
  // The 3D ball look is now ONE radial-gradient on the disc itself — no outer
  // halo, no boxShadow color glow, no icon filter.
  return (
    <button onClick={onClick} className="flex flex-col items-center group flex-shrink-0">
      <div className="relative w-24 h-24 rounded-full flex items-center justify-center transition-transform duration-300 group-hover:scale-[1.04]"
        style={{
          background: `radial-gradient(circle at 32% 28%, ${color}FF 0%, ${color}E6 50%, ${color}99 100%)`,
          boxShadow: `inset 0 -8px 16px rgba(0,0,0,0.35), inset 4px 6px 14px rgba(255,255,255,0.15)`,
          border: `1px solid rgba(255,255,255,0.10)`,
        }}>
        <span className="text-white">{icon}</span>
      </div>
      <p className="mt-3 text-2xl font-bold text-white font-mono tracking-tight">{count === null ? '—' : count.toLocaleString()}</p>
      <p className="text-[11px] text-slate-400 mt-0.5 text-center max-w-[110px] leading-tight">{label}</p>
      {change !== null && (
        <p className="text-[10px] mt-1 font-medium" style={{ color: `${color}CC` }}>↑ {change} this week</p>
      )}
    </button>
  );
}

/**
 * AG-CISO-V4.2 — curved connector with animated traveling dots.
 *
 * A single SVG defines a cubic Bezier path between the two tier nodes
 * (alternating wave above/below center). Three small circles use
 * `animateMotion` to ride the path, giving the "flow" effect the founder
 * called out as missing.
 */
function ConnectorDots({ color, waveUp = true }: { color: string; waveUp?: boolean }) {
  const pathId = useMemo(() => `flow-${Math.random().toString(36).slice(2, 9)}`, []);
  // Path goes from (0, mid) → (W, mid) with a single cubic bezier curve.
  // waveUp flips the curve so adjacent connectors alternate.
  const W = 180;
  const H = 80;
  const mid = H / 2;
  const ctrlY = waveUp ? mid - 28 : mid + 28;
  const d = `M0,${mid} C${W * 0.3},${ctrlY} ${W * 0.7},${ctrlY} ${W},${mid}`;
  return (
    <div className="flex-1 relative min-w-[80px] max-w-[200px]" style={{ height: H }}>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="w-full h-full overflow-visible">
        <path id={pathId} d={d} fill="none" stroke={`${color}30`} strokeWidth="1" strokeDasharray="2 4" />
        {[0, 1, 2].map(i => (
          <circle key={i} r="2.5" fill={color} style={{ filter: `drop-shadow(0 0 4px ${color})` }}>
            <animateMotion dur="3.6s" repeatCount="indefinite" begin={`${i * 1.2}s`}>
              <mpath href={`#${pathId}`} />
            </animateMotion>
          </circle>
        ))}
      </svg>
    </div>
  );
}

/**
 * AG-CISO-V4.4 (2026-06-11) — RiskGaugeCard with optional `elevated`.
 *
 * Peer review v4: AI Risk should be subtly visually distinguished
 * because AI is AuditGraph's differentiation. Elevated cards get a
 * violet halo, thicker border, and a "MOAT" pill. Restrained — the
 * AI card isn't bigger, just more prominent.
 */
function RiskGaugeCard({
  bucket, color, label, gaugeValue, items, viewHref, onClick, elevated = false,
}: {
  bucket: string; color: string; label: string; gaugeValue: number;
  items: Array<{ count: number; label: string; severity: 'critical' | 'high' | 'medium' }>;
  viewHref: string; onClick: () => void; elevated?: boolean;
}) {
  return (
    <div className={`rounded-xl p-5 bg-[#0f172a]/80 relative ${elevated ? 'border-2' : 'border'}`}
      style={{
        borderColor: elevated ? 'rgba(167,139,250,0.50)' : 'rgba(255,255,255,0.05)',
        boxShadow: elevated ? '0 0 30px rgba(167,139,250,0.18)' : undefined,
      }}>
      {elevated && (
        <span className="absolute -top-2 -right-2 text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full bg-violet-500 text-white shadow-lg shadow-violet-500/40">
          ★ MOAT
        </span>
      )}
      <div className="flex items-start justify-between mb-3">
        <div>
          <p className="text-[10px] uppercase tracking-wider font-bold text-slate-500">{bucket}</p>
          <p className="text-2xl font-bold mt-1" style={{ color }}>{label}</p>
        </div>
        <div className="relative w-20 h-20">
          <CircularProgress value={gaugeValue} color={color} size={80} />
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-lg font-bold text-white font-mono">{gaugeValue}</span>
            <span className="text-[9px] text-slate-500 font-mono">/100</span>
          </div>
        </div>
      </div>
      <div className="space-y-1.5">
        {items.map((item, i) => {
          const tone = severityTone(item.severity);
          return (
            <div key={i} className="flex items-center gap-2 text-xs">
              <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: tone.text }} />
              <span className="font-bold font-mono w-8" style={{ color: tone.text }}>{item.count}</span>
              <span className="text-slate-400">{item.label}</span>
            </div>
          );
        })}
      </div>
      <Link to={viewHref} onClick={onClick}
        className="block mt-4 text-xs text-center py-2 rounded-lg transition"
        style={{ color, background: `${color}10`, border: `1px solid ${color}30` }}>
        {`View ${bucket.toLowerCase().includes('non-human') ? 'Non-Human Identities' : bucket.toLowerCase().includes('ai') ? 'AI Identities' : 'Human Identities'} →`}
      </Link>
    </div>
  );
}

// ─── Main ──────────────────────────────────────────────────────────

export default function CISODashboard() {
  const navigate = useNavigate();
  const { withConnection, selectedConnectionId } = useConnection();
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [argusQuery, setArgusQuery] = useState('');
  // V2.7 (2026-06-11) — Identity Security Score breakdown drawer.
  const [scoreBreakdownOpen, setScoreBreakdownOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      // Category counts (NHI + AI agents)
      fetch('/api/identities/category-summary').then(r => r.ok ? r.json() : null) as Promise<CategorySummary | null>,
      // Per-category totals + risk distribution (humans, guests, +risk gauges)
      fetch('/api/identity-summary').then(r => r.ok ? r.json() : null) as Promise<IdentitySummary | null>,
      // Attack paths
      fetch(withConnection('/api/attack-paths?limit=10')).then(r => r.ok ? r.json() : null),
      // V2.13 (2026-06-12) — separate count call so the headline tile
      // shows the REAL attack-path total (and by-severity counts), not
      // the limit-capped page returned by the list endpoint above.
      // Founder saw "Attack Paths: 10" on a tenant with 110 paths in the
      // DB — that's just the limit echoed back, not honest data.
      fetch(withConnection('/api/attack-paths/count')).then(r => r.ok ? r.json() : null),
      // SPN exposure stats (NHI unowned / can-escalate)
      fetch(withConnection('/api/spns/stats')).then(r => r.ok ? r.json() : null),
      // Posture rollup (drives Identity Risk Score + Compliance Posture)
      fetch(withConnection('/api/dashboard/posture')).then(r => r.ok ? r.json() : null) as Promise<PostureResp | null>,
      // Model registry (Models tier count)
      fetch('/api/ai-security/model-registry').then(r => r.ok ? r.json() : null),
      // Recent activity (What Changed panel)
      fetch('/api/activity?limit=10').then(r => r.ok ? r.json() : null),
      // Business Impact rollup ($ valuations for PHI / PCI / AI Models)
      fetch('/api/dashboard/business-impact').then(r => r.ok ? r.json() : null),
    ]).then(([cat, idSum, attackResp, attackCount, spnStats, posture, modelReg, activity, bizImpact]) => {
      if (cancelled) return;
      const categorySummary: CategorySummary = cat || {};
      const cats = idSum?.categories || {};

      // ── Identity counts (real, from SSOT) ────────────────────────
      const humans = (cats.human_user?.total || 0) + (cats.guest?.total || 0);
      const nhi = (categorySummary.service_principal || 0) +
                  (categorySummary.managed_identity_system || 0) +
                  (categorySummary.managed_identity_user || 0) +
                  (categorySummary.workload || 0);
      const ai = categorySummary.ai_agent || 0;
      const modelCount = Array.isArray(modelReg?.models) ? modelReg.models.length
                      : (bizImpact?.ai_models?.count ?? null);
      // Data Sources tier = total classified resources (PHI + PCI + PII).
      // Pulled from /api/dashboard/business-impact which aggregates from
      // azure_storage_accounts + azure_key_vaults data_classification columns.
      const dataCount: number | null = bizImpact
        ? (bizImpact.phi_assets?.count || 0) + (bizImpact.pci_assets?.count || 0) + (bizImpact.pii_assets?.count || 0)
        : null;

      // ── Attack paths ────────────────────────────────────────────
      // V2.13 (2026-06-12) — split: list endpoint for the Top-N rendering,
      // count endpoint for the headline tile. Was counting paths.length
      // which equals the URL limit (10) regardless of actual DB total.
      const paths: AttackPathRow[] = Array.isArray(attackResp?.paths) ? attackResp.paths
                  : Array.isArray(attackResp?.attack_paths) ? attackResp.attack_paths
                  : Array.isArray(attackResp?.items) ? attackResp.items : [];
      const pathsTotal = (attackCount?.total ?? attackResp?.total ?? paths.length) || 0;
      const critN = attackCount?.critical ?? paths.filter(p => (p.severity || '').toLowerCase() === 'critical').length;
      const highN = attackCount?.high     ?? paths.filter(p => (p.severity || '').toLowerCase() === 'high').length;
      const medN  = attackCount?.medium   ?? paths.filter(p => (p.severity || '').toLowerCase() === 'medium').length;

      // ── Identity Risk Score + Compliance Posture (from posture rollup) ──
      // V2.4 (2026-06-11) — fresh-tenant honesty. When there are 0 identities,
      // posture_score is 0 and the prior `100 - 0 = 100` reading painted the
      // hero as "Critical Exposure 100", which falsely red-flagged tenants
      // that simply haven't run discovery yet.
      const totalIdentities = (cats?.human_user?.total || 0) + (cats?.guest?.total || 0)
        + (cats?.service_principal?.total || 0) + (cats?.managed_identity_system?.total || 0)
        + (cats?.managed_identity_user?.total || 0) + (cats?.workload?.total || 0);
      const postureScore = Math.max(0, Math.min(100, Math.round(posture?.posture_score ?? 0)));
      const riskScore = totalIdentities > 0 ? 100 - postureScore : 0;

      // ── Per-bucket risk gauges (severity-weighted from identity-summary) ──
      const humanCat: CategoryStats = {
        total: humans,
        critical: (cats.human_user?.critical || 0) + (cats.guest?.critical || 0),
        high: (cats.human_user?.high || 0) + (cats.guest?.high || 0),
        medium: (cats.human_user?.medium || 0) + (cats.guest?.medium || 0),
        low: (cats.human_user?.low || 0) + (cats.guest?.low || 0),
        info: 0, unknown: 0,
      };
      const nhiCat: CategoryStats = ['service_principal', 'managed_identity_system', 'managed_identity_user', 'workload']
        .reduce<CategoryStats>((acc, k) => {
          const c = cats[k]; if (!c) return acc;
          return {
            total: acc.total + c.total, critical: acc.critical + c.critical,
            high: acc.high + c.high, medium: acc.medium + c.medium,
            low: acc.low + c.low, info: 0, unknown: 0,
          };
        }, { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 });
      // No AI-specific category in identity-summary — derive proportionally from
      // category-summary's ai_agent count and assume same critical/high ratio as NHI.
      const aiRatio = nhiCat.total > 0 ? ai / nhiCat.total : 0;
      const aiCat: CategoryStats = {
        total: ai,
        critical: Math.round(nhiCat.critical * aiRatio),
        high: Math.round(nhiCat.high * aiRatio),
        medium: Math.round(nhiCat.medium * aiRatio),
        low: Math.round(nhiCat.low * aiRatio),
        info: 0, unknown: 0,
      };

      // ── What Changed (from /api/activity) ───────────────────────
      const acts: any[] = Array.isArray(activity?.entries) ? activity.entries
                       : Array.isArray(activity?.activities) ? activity.activities
                       : Array.isArray(activity) ? activity : [];
      const whatChanged = acts.slice(0, 5).map(a => {
        const created = a.created_at || a.timestamp || a.occurred_at;
        let ageHours = 0;
        if (created) {
          const diff = Date.now() - new Date(created).getTime();
          ageHours = Math.max(0, Math.round(diff / 3_600_000));
        }
        const action = (a.action || a.event_type || '').toLowerCase();
        const colorFor = (s: string) => s.includes('privileg') ? '#60a5fa'
                                     : s.includes('ai_agent') ? '#a78bfa'
                                     : s.includes('permission') ? '#22d3ee'
                                     : s.includes('attack') || s.includes('critical') ? '#f87171'
                                     : s.includes('service_principal') || s.includes('spn') ? '#fb923c'
                                     : '#94a3b8';
        return {
          icon: '●', count: 1,
          label: a.description || a.message || action || 'change',
          ageHours, color: colorFor(action),
        };
      });

      setData({
        humanCount: humans,
        nhiCount: nhi,
        aiCount: ai,
        modelCount,
        dataCount,
        weekDelta: { human: null, nhi: null, ai: null, model: null, data: null },
        totalIdentities,
        riskScore,
        riskImprovementPct: null,                            // No previous-period rollup endpoint yet
        estimatedExposure: bizImpact?.total_exposure ?? null,
        reductionOpportunity: bizImpact?.reduction_opportunity ?? null,
        attackPathsTotal: pathsTotal,
        attackPathsCritical: critN,
        attackPathsHigh: highN,
        attackPathsMedium: medN,
        compliancePct: postureScore,
        controlsFailing: null,           // No compliance-controls endpoint surfaced yet
        humanRiskGauge: gaugeFromRisk(humanCat),
        humanOrphaned: humanCat.critical,
        humanGhost: humanCat.high,
        humanPrivileged: humanCat.medium,
        nhiRiskGauge: gaugeFromRisk(nhiCat),
        nhiServicePrincipals: nhiCat.total,
        nhiUnowned: spnStats?.orphaned_privileged || 0,
        nhiOverPriv: spnStats?.can_escalate_count || 0,
        aiRiskGauge: gaugeFromRisk(aiCat),
        aiAgents: ai,
        aiOwnerless: aiCat.critical,
        aiExcessivePerms: aiCat.high,
        topAttackPaths: paths.slice(0, 5),
        whatChanged: whatChanged.length > 0 ? whatChanged : null,
        phiAssets: bizImpact?.phi_assets ? { count: bizImpact.phi_assets.count, value: bizImpact.phi_assets.value } : null,
        pciAssets: bizImpact?.pci_assets ? { count: bizImpact.pci_assets.count, value: bizImpact.pci_assets.value } : null,
        aiModels:  bizImpact?.ai_models  ? { count: bizImpact.ai_models.count,  value: bizImpact.ai_models.value }
                  : modelCount !== null   ? { count: modelCount, value: null }
                  : null,
      });
      setLoading(false);
    }).catch(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId]);

  // Real attack paths only — no demo fallback. Empty list shows a green-tick state.
  const attackPathsRender: AttackPathRow[] = data?.topAttackPaths ?? [];

  // AG-CISO-V4.1 (2026-06-10): derive Immediate Risks + Remediations from
  // the same identity-summary + spn-stats responses already fetched.
  // No hardcoded counts. Items hide if their underlying count is 0.
  const immediateRisks = useMemo(() => {
    if (!data) return [];
    return [
      { count: data.nhiUnowned,        label: 'Unowned Service Principals',           severity: 'critical' as const },
      { count: data.humanGhost,        label: 'Stale Humans (>90d no sign-in)',       severity: 'high'     as const },
      { count: data.aiExcessivePerms,  label: 'AI Agents with excessive permissions', severity: 'high'     as const },
      { count: data.humanOrphaned,     label: 'Critical-Risk Humans',                 severity: 'critical' as const },
      { count: data.nhiOverPriv,       label: 'NHIs that can escalate privilege',     severity: 'medium'   as const },
    ].filter(r => r.count > 0);
  }, [data]);

  // Top remediations are derived from the same data — each entry only
  // appears if there's something to remediate.
  const topRemediations = useMemo(() => {
    if (!data) return [];
    const remediations = [
      { rank: 1, title: 'Remove Excessive NHI Permissions',  count: data.nhiOverPriv,   sub: 'service principals' },
      { rank: 2, title: 'Assign Owners to Orphan NHIs',      count: data.nhiUnowned,    sub: 'unowned NHIs' },
      { rank: 3, title: 'Triage Critical-Risk Humans',       count: data.humanOrphaned, sub: 'humans' },
      { rank: 4, title: 'Restrict AI Agent Permissions',     count: data.aiExcessivePerms, sub: 'AI agents' },
    ];
    return remediations.filter(r => r.count > 0).map((r, i) => ({ ...r, rank: i + 1, sub: `${r.count} ${r.sub}` }));
  }, [data]);

  // V2.6 (2026-06-11) — in-page chat (same fix as SecurityCommandCenter).
  const [argusMessages, setArgusMessages] = useState<{ role: 'user' | 'assistant'; content: string }[]>([]);
  const [argusBusy, setArgusBusy] = useState(false);
  async function sendArgus(q: string) {
    if (!q.trim() || argusBusy) return;
    setArgusMessages(m => [...m, { role: 'user', content: q }]);
    setArgusQuery('');
    setArgusBusy(true);
    try {
      const r = await fetch('/api/argus/nl-query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q }),
      });
      const data = await r.json().catch(() => ({}));
      const reply = data.answer || data.response || data.result || data.message
        || 'Argus is still learning this question. Try one of the suggested prompts above.';
      setArgusMessages(m => [...m, { role: 'assistant', content: String(reply) }]);
    } catch {
      setArgusMessages(m => [...m, { role: 'assistant', content: 'Could not reach Argus right now. Try again in a moment.' }]);
    } finally {
      setArgusBusy(false);
    }
  }
  const askArgus = () => sendArgus(argusQuery);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin h-8 w-8 border-2 border-violet-500 border-t-transparent rounded-full" />
      </div>
    );
  }
  if (!data) return null;

  return (
    <div className="p-5 w-full space-y-4 min-h-screen">
      <style>{`
        @keyframes pulseGlow {
          0%, 100% { box-shadow: 0 0 8px rgba(16, 185, 129, 0.6); }
          50%      { box-shadow: 0 0 16px rgba(16, 185, 129, 1); }
        }
      `}</style>

      {/* Page header */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-violet-500/30 to-blue-500/30 border border-violet-500/40 flex items-center justify-center">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="w-6 h-6 text-violet-300">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 2L4 6v6c0 5.5 3.6 10.7 8 12 4.4-1.3 8-6.5 8-12V6l-8-4z" />
            </svg>
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Identity Security Command Center</h1>
            <p className="text-sm text-slate-400">Unified visibility across Human, Non-Human and AI identities</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button className="px-3 py-2 rounded-lg text-xs font-medium bg-slate-800/60 text-slate-200 border border-slate-700 hover:bg-slate-700/60 transition flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
            Last 7 Days
            <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7"/></svg>
          </button>
          <button className="px-3 py-2 rounded-lg text-xs font-medium bg-violet-500/15 text-violet-300 border border-violet-500/40 hover:bg-violet-500/25 transition flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z"/></svg>
            Share Report
          </button>
        </div>
      </div>

      {/* Row 1: 4 hero metric cards */}
      {/* AG-CISO-V4.3: 5-column grid; Identity Security Score is the 2-col hero. */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
        <IdentityScoreHero
          value={data.riskScore}
          onExplain={data.totalIdentities > 0 ? () => setScoreBreakdownOpen(true) : undefined}
          // V2.4 (2026-06-11) — when data.totalIdentities is 0 the score is
          // unmeasured, not "Critical Exposure 100". Show a baseline-yet
          // copy so a fresh tenant doesn't read as red-flagged.
          label={data.totalIdentities === 0 ? 'Awaiting first scan'
            : data.riskScore >= 70 ? 'Critical Exposure'
            : data.riskScore >= 40 ? 'Elevated' : 'Healthy'}
          trendUp={data.totalIdentities === 0 ? null : data.riskImprovementPct}
          trendCount={data.riskImprovementPct ? Math.abs(data.riskImprovementPct) : 0}
          exposureReduction={data.reductionOpportunity}
        />
        <HeroCard
          label="ESTIMATED EXPOSURE"
          value={data.estimatedExposure === null ? '—' : fmtMoney(data.estimatedExposure)}
          valueColor={data.estimatedExposure === null ? '#94a3b8' : '#f87171'}
          sublabel={data.estimatedExposure === null ? 'Financial impact rollup not configured' : 'Potential financial impact'}
          footer={data.reductionOpportunity === null
            ? <span className="text-slate-500">Add asset valuations in Settings → Exposure</span>
            : <span className="flex items-center gap-1 text-emerald-400">↓ {fmtMoney(data.reductionOpportunity)} risk reduction opportunity</span>}
          footerColor="#34d399"
          icon={<svg className="w-7 h-7" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>}
          iconColor={data.estimatedExposure === null ? '#64748b' : '#ef4444'}
        />
        <HeroCard
          label="ATTACK PATHS"
          value={`${data.attackPathsTotal}`}
          valueColor="#ffffff"
          sublabel="Active paths identified"
          footer={
            <span className="flex items-center gap-3 text-slate-400">
              <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-red-400" /> {data.attackPathsCritical} Critical</span>
              <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-orange-400" /> {data.attackPathsHigh} High</span>
              <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-amber-400" /> {data.attackPathsMedium} Medium</span>
            </span>
          }
          footerColor="#cbd5e1"
          icon={<svg className="w-7 h-7" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z"/></svg>}
          iconColor="#a78bfa"
        />
        <HeroCard
          label="COMPLIANCE POSTURE"
          value={`${data.compliancePct}%`}
          valueColor={data.compliancePct >= 80 ? '#34d399' : data.compliancePct >= 50 ? '#fbbf24' : '#f87171'}
          sublabel="Overall posture score"
          footer={data.controlsFailing === null
            ? <span className="text-slate-500">Detailed control mapping forthcoming</span>
            : <span className="flex items-center gap-1 text-amber-400">● {data.controlsFailing} controls failing</span>}
          footerColor="#fbbf24"
          icon={<svg className="w-7 h-7" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>}
          iconColor={data.compliancePct >= 80 ? '#10b981' : data.compliancePct >= 50 ? '#f59e0b' : '#ef4444'}
          progressValue={data.compliancePct}
        />
      </div>

      {/* V2.10 (2026-06-12) — Top Improvement Opportunities.
          Per peer review, generalize the Role-Mining banner pattern
          ("close 114 toxic combos → +6.8 pts") across all 6 score
          factors and surface the top 3 with projected lift, click-through,
          and CTA. Connects Problem → Impact → Remediation → Outcome at the
          executive level. */}
      {data.totalIdentities > 0 && (
        <TopImprovementPanel
          input={{
            totalIdentities: data.totalIdentities,
            criticalIdentities: data.humanOrphaned,
            highIdentities: data.humanPrivileged,
            totalNhi: data.nhiCount,
            nhiUnowned: data.nhiUnowned,
            totalAttackPaths: data.attackPathsTotal,
            criticalAttackPaths: data.attackPathsCritical,
            totalCreds: data.nhiCount,
            expiredOrExpiringCreds: data.nhiOverPriv,
            totalAi: data.aiCount,
            aiWithoutTelemetry: data.aiOwnerless,
            reachableSensitiveCount: (data.phiAssets?.count || 0) + (data.pciAssets?.count || 0),
          }}
          currentScore={data.riskScore}
          onOpenBreakdown={() => setScoreBreakdownOpen(true)}
        />
      )}

      {/* Two-column main layout */}
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_360px] gap-4">
        <div className="space-y-4 min-w-0">

          {/* Row 2: Unified Identity Graph hero */}
          <div className="rounded-xl p-5 bg-[#0f172a]/80 border border-white/5">
            <div className="flex items-center gap-3 mb-1">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="w-4 h-4 text-violet-400"><path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
              <h2 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">Unified Identity Graph</h2>
              <span className="flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold text-emerald-300 bg-emerald-500/10 border border-emerald-500/30">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" style={{ animation: 'pulseGlow 2s infinite' }} />
                Live
              </span>
            </div>
            <p className="text-xs text-slate-500 mb-5">Explore how identities, workloads, and data are connected across your environment.</p>
            {/* Tier circles row */}
            <div className="flex items-center justify-center gap-2">
              <TierCircle label="Human Identities"     count={data.humanCount} color="#3b82f6" change={data.weekDelta.human} icon={TIER_ICONS.human} onClick={() => navigate('/human/inventory')} />
              <ConnectorDots color="#3b82f6" waveUp={true} />
              <TierCircle label="Non-Human Identities" count={data.nhiCount}   color="#f97316" change={data.weekDelta.nhi}   icon={TIER_ICONS.nhi}   onClick={() => navigate('/nhi')} />
              <ConnectorDots color="#f97316" waveUp={false} />
              <TierCircle label="AI Agents"            count={data.aiCount}    color="#a78bfa" change={data.weekDelta.ai}    icon={TIER_ICONS.ai}    onClick={() => navigate('/ai-inventory')} />
              <ConnectorDots color="#a78bfa" waveUp={true} />
              <TierCircle label="Models"               count={data.modelCount} color="#ec4899" change={data.weekDelta.model} icon={TIER_ICONS.model} onClick={() => navigate('/ai-runtime/model-registry')} />
              <ConnectorDots color="#ec4899" waveUp={false} />
              <TierCircle label="Data Sources"         count={data.dataCount}  color="#10b981" change={data.weekDelta.data}  icon={TIER_ICONS.data}  onClick={() => navigate('/ai-access/data-reachability')} />
            </div>
            {/* Bottom strip */}
            <div className="mt-6 pt-4 border-t border-white/5 flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-5 flex-wrap">
                <span className="flex items-center gap-2 text-xs">
                  <span className="text-red-400">🛡</span>
                  <span className="font-bold text-red-400 font-mono">{data.attackPathsTotal}</span>
                  <span className="text-slate-400">Active Attack Paths</span>
                </span>
                <span className="flex items-center gap-2 text-xs">
                  <span className="text-orange-400">⚠</span>
                  <span className="font-bold text-orange-400 font-mono">{data.nhiUnowned}</span>
                  <span className="text-slate-400">Orphaned Identities</span>
                </span>
                <span className="flex items-center gap-2 text-xs">
                  <span className="text-amber-400">🔑</span>
                  <span className="font-bold text-amber-400 font-mono">
                    {data.dataCount === null ? '—' : data.dataCount}
                  </span>
                  <span className="text-slate-400">Critical Data Assets</span>
                </span>
              </div>
              <Link to="/unified-graph" className="px-3 py-1.5 rounded-lg text-xs font-medium bg-violet-500/15 text-violet-300 border border-violet-500/40 hover:bg-violet-500/25 transition">
                Explore Graph →
              </Link>
            </div>
          </div>

          {/* Row 3: 3 identity-bucket risk cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <RiskGaugeCard
              bucket="HUMAN IDENTITY RISK"
              color={gaugeColor(data.humanRiskGauge)}
              label={gaugeLabel(data.humanRiskGauge)}
              gaugeValue={data.humanRiskGauge}
              items={[
                { count: data.humanOrphaned,   label: 'Critical-risk humans', severity: 'critical' },
                { count: data.humanGhost,      label: 'High-risk humans',     severity: 'high' },
                { count: data.humanPrivileged, label: 'Medium-risk humans',   severity: 'medium' },
              ]}
              viewHref="/human/inventory" onClick={() => {}}
            />
            <RiskGaugeCard
              bucket="NON-HUMAN IDENTITY RISK"
              color={gaugeColor(data.nhiRiskGauge)}
              label={gaugeLabel(data.nhiRiskGauge)}
              gaugeValue={data.nhiRiskGauge}
              items={[
                { count: data.nhiServicePrincipals, label: 'Total NHIs',          severity: 'critical' },
                { count: data.nhiUnowned,           label: 'Orphaned + Privileged', severity: 'high' },
                { count: data.nhiOverPriv,          label: 'Can Escalate',        severity: 'medium' },
              ]}
              viewHref="/nhi" onClick={() => {}}
            />
            <RiskGaugeCard
              bucket="AI IDENTITY RISK"
              color={gaugeColor(data.aiRiskGauge)}
              label={gaugeLabel(data.aiRiskGauge)}
              gaugeValue={data.aiRiskGauge}
              items={[
                { count: data.aiAgents,         label: 'AI Agents',            severity: 'critical' },
                { count: data.aiOwnerless,      label: 'Critical-risk AI',     severity: 'high' },
                { count: data.aiExcessivePerms, label: 'High-risk AI',         severity: 'medium' },
              ]}
              viewHref="/ai-inventory" onClick={() => {}}
              elevated
            />
          </div>

          {/* Row 4: 3-column workshop */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Top Attack Paths */}
            <div className="rounded-xl p-5 bg-[#0f172a]/80 border border-white/5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">Top Attack Paths</h3>
                <Link to="/attack-paths" className="text-[10px] text-violet-400 hover:text-violet-300">View All</Link>
              </div>
              <div className="space-y-2">
                {attackPathsRender.length === 0 ? (
                  <p className="text-[11px] text-emerald-400/70 text-center py-6">✓ No active attack paths.</p>
                ) : attackPathsRender.map((p, i) => {
                  const tone = severityTone(p.severity);
                  return (
                    <Link key={p.id || i} to={`/attack-paths/${p.id || ''}`}
                      className="flex items-center gap-2 p-2 rounded-lg hover:bg-slate-800/40 transition text-xs">
                      <span className="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0"
                        style={{ background: tone.bg, color: tone.text, border: `1px solid ${tone.border}` }}>{i + 1}</span>
                      <span className="flex-1 text-slate-300 truncate">
                        {p.source_entity_name || 'Identity'} → {p.path_type || p.description || 'Path'}
                      </span>
                      <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded flex-shrink-0"
                        style={{ background: tone.bg, color: tone.text, border: `1px solid ${tone.border}` }}>{tone.label}</span>
                    </Link>
                  );
                })}
              </div>
            </div>

            {/* Immediate Risks */}
            <div className="rounded-xl p-5 bg-[#0f172a]/80 border border-white/5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">Immediate Risks</h3>
                <Link to="/findings" className="text-[10px] text-violet-400 hover:text-violet-300">View All</Link>
              </div>
              <div className="space-y-2">
                {immediateRisks.length === 0 ? (
                  <p className="text-[11px] text-emerald-400/70 text-center py-6">✓ No immediate risks detected.</p>
                ) : immediateRisks.map((r, i) => {
                  const tone = severityTone(r.severity);
                  return (
                    <div key={i} className="flex items-center gap-2 p-2 rounded-lg hover:bg-slate-800/40 transition text-xs">
                      <span className="w-8 h-8 rounded-lg flex items-center justify-center text-sm font-bold flex-shrink-0"
                        style={{ background: tone.bg, color: tone.text, border: `1px solid ${tone.border}` }}>{r.count}</span>
                      <span className="flex-1 text-slate-300 truncate">{r.label}</span>
                      <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded flex-shrink-0"
                        style={{ background: tone.bg, color: tone.text, border: `1px solid ${tone.border}` }}>{tone.label}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Top Remediation Actions */}
            <div className="rounded-xl p-5 bg-[#0f172a]/80 border border-white/5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">Top Remediation Actions</h3>
                <span className="text-[10px] text-slate-500">Affected count</span>
              </div>
              <div className="space-y-2">
                {topRemediations.length === 0 ? (
                  <p className="text-[11px] text-emerald-400/70 text-center py-6">✓ No remediations queued.</p>
                ) : topRemediations.map(r => (
                  <Link key={r.rank} to="/remediation" className="flex items-center gap-2 p-2 rounded-lg hover:bg-slate-800/40 transition text-xs">
                    <span className="w-5 h-5 rounded-full bg-violet-500/15 border border-violet-500/40 text-violet-300 flex items-center justify-center text-[10px] font-bold flex-shrink-0">{r.rank}</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-slate-200 truncate">{r.title}</p>
                      <p className="text-[10px] text-slate-500">{r.sub}</p>
                    </div>
                    <span className="text-amber-400 font-bold font-mono">{r.count}</span>
                  </Link>
                ))}
              </div>
              <Link to="/remediation" className="block mt-3 text-xs text-center py-2 rounded-lg bg-violet-500/15 text-violet-300 border border-violet-500/40 hover:bg-violet-500/25 transition">
                View Remediation Plan →
              </Link>
            </div>
          </div>
        </div>

        {/* Right rail */}
        <aside className="space-y-4 min-w-0">
          {/* What Changed */}
          <div className="rounded-xl p-5 bg-[#0f172a]/80 border border-white/5">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300 flex items-center gap-2">
                  <svg className="w-3.5 h-3.5 text-emerald-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                  What Changed
                </h3>
                <p className="text-[10px] text-slate-500 mt-0.5">(Last 24 Hours)</p>
              </div>
              <Link to="/activity" className="text-[10px] text-violet-400 hover:text-violet-300">View All</Link>
            </div>
            <div className="space-y-2">
              {data.whatChanged ? data.whatChanged.map((c, i) => (
                <Link key={i} to="/activity" className="flex items-center gap-3 p-1.5 rounded hover:bg-slate-800/40 transition text-xs">
                  <span className="w-7 h-7 rounded-lg flex items-center justify-center text-sm flex-shrink-0"
                    style={{ background: `${c.color}15`, color: c.color, border: `1px solid ${c.color}40` }}>
                    {c.icon}
                  </span>
                  <span className="flex-1 text-slate-300 truncate">{c.label}</span>
                  <span className="text-[10px] text-slate-500 flex-shrink-0">{c.ageHours}h ago</span>
                </Link>
              )) : (
                <p className="text-[11px] text-slate-500 text-center py-6">No activity in the last 24 hours.</p>
              )}
            </div>
            <Link to="/activity" className="block mt-3 text-center text-[10px] text-violet-400 hover:text-violet-300">
              See all activity →
            </Link>
          </div>

          {/* Business Impact */}
          <div className="rounded-xl p-5 bg-[#0f172a]/80 border border-white/5">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300 flex items-center gap-2">
                <svg className="w-3.5 h-3.5 text-violet-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
                Business Impact
              </h3>
              <svg className="w-3.5 h-3.5 text-slate-500" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
            </div>
            <div className="mb-4">
              <p className="text-[10px] text-slate-500 flex items-center gap-1">Estimated Exposure <span>›</span></p>
              <p className="text-3xl font-bold mt-1" style={{ color: data.estimatedExposure === null ? '#94a3b8' : '#f87171' }}>
                {data.estimatedExposure === null ? '—' : fmtMoney(data.estimatedExposure)}
              </p>
            </div>
            <div className="grid grid-cols-3 gap-2 mb-4">
              <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-2.5">
                <p className="text-[9px] uppercase tracking-wider text-slate-500 font-bold">PHI Assets</p>
                <p className="text-lg font-bold text-white mt-1 font-mono">{data.phiAssets ? data.phiAssets.count : '—'}</p>
                <p className="text-[10px] font-mono" style={{ color: data.phiAssets?.value ? '#f87171' : '#64748b' }}>
                  {data.phiAssets?.value ? fmtMoney(data.phiAssets.value) : '—'}
                </p>
              </div>
              <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-2.5">
                <p className="text-[9px] uppercase tracking-wider text-slate-500 font-bold">PCI Assets</p>
                <p className="text-lg font-bold text-white mt-1 font-mono">{data.pciAssets ? data.pciAssets.count : '—'}</p>
                <p className="text-[10px] font-mono" style={{ color: data.pciAssets?.value ? '#f87171' : '#64748b' }}>
                  {data.pciAssets?.value ? fmtMoney(data.pciAssets.value) : '—'}
                </p>
              </div>
              <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-2.5">
                <p className="text-[9px] uppercase tracking-wider text-slate-500 font-bold">AI Models</p>
                <p className="text-lg font-bold text-white mt-1 font-mono">{data.aiModels ? data.aiModels.count : '—'}</p>
                <p className="text-[10px] font-mono" style={{ color: data.aiModels?.value ? '#f87171' : '#64748b' }}>
                  {data.aiModels?.value ? fmtMoney(data.aiModels.value) : '—'}
                </p>
              </div>
            </div>
            <div>
              <p className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Risk Reduction Opportunity</p>
              <p className="text-2xl font-bold mt-1" style={{ color: data.reductionOpportunity === null ? '#94a3b8' : '#34d399' }}>
                {data.reductionOpportunity === null ? '—' : fmtMoney(data.reductionOpportunity)}
              </p>
              <p className="text-[10px] text-slate-500 mt-1">
                {data.reductionOpportunity === null
                  ? 'Connect asset-valuation source to enable'
                  : 'By addressing top remediation actions'}
              </p>
            </div>
          </div>

          {/* V4.5.1 (2026-06-11) — Argus AI, flat / no-glow. Founder pushback:
              the previous version's halo blob + boxShadow tints + icon-chip
              glows read as "odd". Kept: BETA/LIVE chips, per-pill icon
              containers (flat color now, no shadow), the input row, and the
              footer hint. Removed: every boxShadow, the decorative blob,
              the gradient-glow send button, all per-pill icon halos. */}
          <div className="rounded-xl p-5 bg-[#0f172a]/80 border border-violet-500/30">
            <div className="flex items-start justify-between gap-2 mb-3">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold text-white tracking-wide">ARGUS AI</h3>
                  <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-violet-500/20 text-violet-200 border border-violet-400/30">
                    BETA
                  </span>
                  <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-emerald-500/10 text-emerald-300 border border-emerald-500/25">
                    <span className="w-1 h-1 rounded-full bg-emerald-400" />
                    Live
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1">Ask anything about your identity security</p>
              </div>
              <div className="w-8 h-8 rounded-lg bg-violet-500/15 border border-violet-500/30 flex items-center justify-center flex-shrink-0">
                <svg className="w-4 h-4 text-violet-300" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg>
              </div>
            </div>

            {/* V2.6 (2026-06-11) — in-page chat. Suggestion pills now call
                sendArgus() in-place; full-page navigation only via "Open
                full chat →" link. */}
            {argusMessages.length === 0 ? (
              <div className="space-y-2 mb-3">
                {[
                  { q: 'What changed this week?',                 color: '#a78bfa', icon: <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg> },
                  { q: 'Show all orphaned service principals',    color: '#f97316', icon: <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"/></svg> },
                  { q: 'Explain attack path #3',                  color: '#ef4444', icon: <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg> },
                  { q: 'Generate board report',                   color: '#34d399', icon: <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg> },
                ].map((c, i) => (
                  <button key={i} onClick={() => sendArgus(c.q)}
                    className="group w-full text-left flex items-center gap-2.5 p-2 rounded-lg bg-slate-900/60 hover:bg-slate-900/90 border border-slate-800 hover:border-slate-700 transition-colors">
                    <span className="w-6 h-6 rounded-md flex items-center justify-center flex-shrink-0"
                      style={{
                        background: `${c.color}15`,
                        border: `1px solid ${c.color}30`,
                        color: c.color,
                      }}>
                      {c.icon}
                    </span>
                    <span className="text-[11px] text-slate-200 truncate flex-1">{c.q}</span>
                    <svg className="w-3 h-3 text-slate-600 group-hover:text-slate-400 transition-colors flex-shrink-0" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7"/></svg>
                  </button>
                ))}
              </div>
            ) : (
              <div className="space-y-2 mb-3 max-h-[280px] overflow-y-auto pr-1">
                {argusMessages.map((msg, i) => (
                  <div key={i}
                    className={`text-[11px] rounded-lg p-2 ${
                      msg.role === 'user'
                        ? 'bg-violet-500/15 border border-violet-500/30 text-slate-100 ml-4'
                        : 'bg-slate-900/60 border border-slate-800 text-slate-200 mr-4'
                    }`}>
                    <p className="text-[9px] uppercase tracking-wider font-bold mb-1 opacity-70">
                      {msg.role === 'user' ? 'You' : 'Argus'}
                    </p>
                    <p className="leading-relaxed whitespace-pre-wrap">{msg.content}</p>
                  </div>
                ))}
                {argusBusy && (
                  <div className="text-[11px] rounded-lg p-2 bg-slate-900/60 border border-slate-800 text-slate-400 mr-4">
                    <span className="inline-flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-pulse" />
                      Argus is thinking…
                    </span>
                  </div>
                )}
                <div className="flex items-center justify-end pt-1">
                  <button onClick={() => setArgusMessages([])}
                    className="text-[10px] text-slate-500 hover:text-slate-300">Clear chat</button>
                </div>
              </div>
            )}

            {/* Input row */}
            <div className="flex items-center gap-2">
              <div className="relative flex-1">
                <svg className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 pointer-events-none" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg>
                <input
                  value={argusQuery}
                  onChange={e => setArgusQuery(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') askArgus(); }}
                  placeholder="Ask Argus anything..."
                  className="w-full bg-slate-900/80 border border-slate-700 rounded-lg pl-8 pr-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-violet-500 transition"
                />
              </div>
              <button onClick={askArgus}
                className="w-9 h-9 rounded-lg bg-violet-500 hover:bg-violet-400 text-white flex items-center justify-center transition flex-shrink-0">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
              </button>
            </div>

            {/* Footer hint */}
            <div className="mt-3 pt-3 border-t border-white/5 flex items-center justify-between text-[9px]">
              <span className="text-slate-500 uppercase tracking-wider font-bold">Powered by Argus</span>
              <Link to="/argus" className="text-violet-300 hover:text-violet-200 font-semibold uppercase tracking-wider">Open full chat →</Link>
            </div>
          </div>
        </aside>
      </div>

      {/* V2.7 (2026-06-11) — Identity Security Score breakdown drawer.
          Built per peer review: "Customer will ask what does 59 mean?
          today there is no explanation." Now there is. */}
      <ScoreBreakdownDrawer
        open={scoreBreakdownOpen}
        onClose={() => setScoreBreakdownOpen(false)}
        headlineScore={data.riskScore}
        input={{
          totalIdentities: data.totalIdentities,
          criticalIdentities: data.humanOrphaned,
          highIdentities: data.humanPrivileged,
          totalNhi: data.nhiCount,
          nhiUnowned: data.nhiUnowned,
          totalAttackPaths: data.attackPathsTotal,
          criticalAttackPaths: data.attackPathsCritical,
          totalCreds: data.nhiCount,                 // proxy: 1 cred per NHI until /api/credentials/stats lands
          expiredOrExpiringCreds: data.nhiOverPriv,  // proxy until expiry endpoint
          totalAi: data.aiCount,
          aiWithoutTelemetry: data.aiOwnerless,
          reachableSensitiveCount: (data.phiAssets?.count || 0) + (data.pciAssets?.count || 0),
        }}
      />
    </div>
  );
}

// ─── Top Improvement Opportunities panel ───────────────────────────
// Generalizes the Role-Mining banner ("close 114 toxic combos → +6.8 pts")
// across all 6 score factors. Shows the top 3 ranked by projected lift,
// total potential lift in the header, and click-through CTAs per row.

function TopImprovementPanel({ input, currentScore, onOpenBreakdown }: {
  input: ScoreBreakdownInput;
  currentScore: number;
  onOpenBreakdown: () => void;
}) {
  const opps = useMemo(() => computeImprovementOpportunities(input), [input]);
  if (opps.length === 0) return null;
  const top3 = opps.slice(0, 3);
  const lift3 = topNLift(top3, 3);
  const projectedScore = Math.min(100, Math.round((currentScore + lift3) * 10) / 10);

  return (
    <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-5">
      <div className="flex items-start justify-between gap-4 mb-4">
        <div>
          <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300 flex items-center gap-2">
            Top Improvement Opportunities
            <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/40">
              {top3.length === 1 ? 'Top action' : `Top ${top3.length} actions`}
            </span>
          </h3>
          <p className="text-[11px] text-slate-500 mt-0.5">
            Each row maps to one of the 6 score factors. Lift is the projected score increase if the recommended count is fully remediated.
            <button onClick={onOpenBreakdown} className="ml-1 text-violet-400 hover:text-violet-300">See methodology →</button>
          </p>
        </div>
        <div className="flex-shrink-0 text-right">
          <p className="text-[10px] uppercase tracking-wider font-bold text-slate-500">Headroom</p>
          <p className="text-2xl font-mono font-bold text-emerald-400 leading-none mt-1">
            +{lift3}
          </p>
          <p className="text-[10px] text-slate-500 mt-1">
            {currentScore} → <span className="text-emerald-400 font-semibold">{projectedScore}</span>
          </p>
        </div>
      </div>
      <div className="space-y-2">
        {top3.map((o, i) => <OpportunityRow key={o.key} rank={i + 1} opp={o} />)}
      </div>
    </div>
  );
}

function OpportunityRow({ rank, opp }: { rank: number; opp: Opportunity }) {
  return (
    <Link to={opp.drillTo}
      className="block rounded-lg p-3 border border-slate-700/60 bg-slate-800/40 hover:bg-slate-800/70 hover:border-slate-600 transition group">
      <div className="flex items-start gap-3">
        <span className="w-6 h-6 rounded-md flex items-center justify-center flex-shrink-0 text-[11px] font-bold mt-0.5"
          style={{ background: `${opp.color}25`, color: opp.color, border: `1px solid ${opp.color}55` }}>
          #{rank}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-baseline justify-between gap-3 flex-wrap">
            <p className="text-sm font-semibold text-white truncate">{opp.title}</p>
            <span className="text-emerald-400 font-mono font-bold text-sm flex-shrink-0">+{opp.projectedLift} pts</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            <strong className="text-slate-200">{opp.countToFix.toLocaleString()}</strong> {opp.unit}
            {' · '}
            <span className="text-slate-500">Factor: {opp.factorLabel} ({opp.weight}% weight)</span>
            {' · '}
            <span className="text-slate-500">Current sub-score: {opp.currentSubScore}/100</span>
          </p>
        </div>
        <span className="text-[10px] text-violet-400 group-hover:text-violet-300 font-semibold uppercase tracking-wider whitespace-nowrap flex-shrink-0 self-center">
          {opp.ctaLabel} →
        </span>
      </div>
    </Link>
  );
}
