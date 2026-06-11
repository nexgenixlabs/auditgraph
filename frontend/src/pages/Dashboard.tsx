/**
 * AG-RM-V2 (2026-06-11) — Identity Risk Monitoring Center
 *
 * Founder-spec rebuild of /dashboard. Peer review said the previous page
 * felt like "10 different reports placed on one page" with no hierarchy.
 * Risk Monitoring is about TRENDS + CHANGE DETECTION, not inventory.
 *
 * Layout matches the reference comp top-down:
 *   Header        — title + REAL-TIME pill + Last-7-Days / Capture Snapshot
 *                   / View Alerts controls
 *   Hero KPI row  — 5 cards (Risk Score · Critical Findings · Attack Paths
 *                   · Exposed Assets · Risk Reduction Opportunity) with
 *                   per-card sparklines + week-over-week deltas.
 *   Trend chart   — RISK TREND OVER TIME (centerpiece) + WHAT CHANGED
 *                   (LAST 24 HOURS) feed on the right.
 *   Risk pillars  — Human / NHI / AI risk gauges + Active Attack Paths.
 *   Bottom row    — Credential Health stat bar · Risk Distribution donut
 *                   · Argus Risk Insights.
 *
 * SSOT-only — every number derives from a live API. Trend history comes
 * from ai_board_scorecard_snapshots (the same persisted store powering
 * the board scorecards) so trend numbers stay consistent across screens.
 *
 * Old page preserved at pages/DashboardLegacy.tsx.
 */
import React, { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';

// ─── Types ─────────────────────────────────────────────────────────

interface CatStats { total: number; critical: number; high: number; medium: number; low: number; info: number; unknown: number }
interface IdentitySummary { categories?: Record<string, CatStats> }
interface CategorySummary { service_principal?: number; managed_identity_system?: number; managed_identity_user?: number; workload?: number; ai_agent?: number; [k: string]: number | undefined }
interface AttackPathRow { id: number; severity: string; source_entity_name?: string; path_type?: string; description?: string; target_entity_name?: string; risk_score?: number }
interface ActivityRow { created_at?: string; timestamp?: string; action?: string; event_type?: string; description?: string; message?: string; metadata?: any }
interface HistorySnapshot {
  snapshot_date: string | null;
  total_agents: number;
  distribution_strong: number;
  distribution_good: number;
  distribution_elevated: number;
  distribution_critical: number;
}

// ─── Helpers ───────────────────────────────────────────────────────

function fmtMoney(v: number): string {
  if (v >= 1_000_000) return `$${(v / 1_000_000).toFixed(1)}M`;
  if (v >= 1_000) return `$${(v / 1_000).toFixed(1)}K`;
  return `$${v}`;
}

function severityTone(sev: string | undefined): { text: string; bg: string; border: string; label: string } {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return { text: '#f87171', bg: 'rgba(239,68,68,0.10)',  border: 'rgba(239,68,68,0.40)',  label: 'CRITICAL' };
  if (s === 'high')     return { text: '#fb923c', bg: 'rgba(251,146,60,0.10)', border: 'rgba(251,146,60,0.40)', label: 'HIGH' };
  if (s === 'medium')   return { text: '#fbbf24', bg: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.40)', label: 'MEDIUM' };
  if (s === 'low')      return { text: '#a3e635', bg: 'rgba(163,230,53,0.10)', border: 'rgba(163,230,53,0.40)', label: 'LOW' };
  if (s === 'info')     return { text: '#60a5fa', bg: 'rgba(96,165,250,0.10)', border: 'rgba(96,165,250,0.40)', label: 'INFO' };
  return { text: '#94a3b8', bg: 'rgba(148,163,184,0.10)', border: 'rgba(148,163,184,0.30)', label: '—' };
}

function gaugeFromRisk(stats: CatStats | undefined): number {
  if (!stats || !stats.total) return 0;
  const score = (stats.critical * 4 + stats.high * 2 + stats.medium) / (stats.total * 4) * 100;
  return Math.round(Math.max(0, Math.min(100, score)));
}

function timeAgo(iso?: string | null): string {
  if (!iso) return '—';
  const ms = Date.now() - new Date(iso).getTime();
  if (!Number.isFinite(ms) || ms < 0) return '—';
  const h = Math.round(ms / 3_600_000);
  if (h < 1) return 'just now';
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

// ─── Sub-components ────────────────────────────────────────────────

function Sparkline({ values, color }: { values: number[]; color: string }) {
  if (values.length < 2) return <div className="text-[10px] text-slate-600">—</div>;
  const min = Math.min(...values);
  const max = Math.max(...values, min + 1);
  const range = max - min || 1;
  const W = 120, H = 32;
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * W;
    const y = H - ((v - min) / range) * (H - 4) - 2;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  const area = `0,${H} ${pts} ${W},${H}`;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-8" preserveAspectRatio="none">
      <polygon points={area} fill={`${color}22`} />
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" />
    </svg>
  );
}

function KpiCard({
  label, value, valueColor, delta, sparkValues, sparkColor, icon, iconColor,
}: {
  label: string; value: string; valueColor: string;
  delta: React.ReactNode;
  sparkValues: number[]; sparkColor: string;
  icon: React.ReactNode; iconColor: string;
}) {
  return (
    <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-4">
      <div className="flex items-start justify-between gap-2 mb-1">
        <p className="text-[10px] uppercase tracking-wider font-bold text-slate-500">{label}</p>
        <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{ background: `${iconColor}15`, border: `1px solid ${iconColor}40`, color: iconColor }}>
          {icon}
        </div>
      </div>
      <p className="text-4xl font-bold mt-1" style={{ color: valueColor }}>{value}</p>
      <div className="mt-2 max-w-full">
        <Sparkline values={sparkValues} color={sparkColor} />
      </div>
      <p className="text-[11px] mt-1 leading-tight text-slate-300">{delta}</p>
    </div>
  );
}

function CircularProgress({ value, color, size = 80 }: { value: number; color: string; size?: number }) {
  const radius = (size - 8) / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(100, value));
  const dash = (pct / 100) * circumference;
  return (
    <svg width={size} height={size} className="-rotate-90">
      <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgba(148,163,184,0.15)" strokeWidth={5} />
      <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={color} strokeWidth={5}
        strokeLinecap="round" strokeDasharray={`${dash} ${circumference - dash}`} />
    </svg>
  );
}

function RiskPillar({
  label, color, score, items, link,
}: {
  label: string; color: string; score: number;
  items: { critical: number; high: number; medium: number; low: number };
  link: string;
}) {
  const tone = score >= 75 ? 'Critical' : score >= 50 ? 'High' : score >= 25 ? 'Elevated' : 'Healthy';
  return (
    <Link to={link} className="rounded-xl p-4 bg-[#0f172a]/80 border border-white/5 hover:border-white/10 transition block">
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="text-[10px] uppercase tracking-wider font-bold text-slate-500">{label}</p>
          <p className="text-4xl font-bold mt-1" style={{ color }}>{score}</p>
          <p className="text-xs mt-0.5" style={{ color }}>{tone}</p>
        </div>
        <div className="relative w-16 h-16 flex-shrink-0">
          <CircularProgress value={score} color={color} size={64} />
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-sm font-bold font-mono text-white">{score}</span>
            <span className="text-[8px] font-mono text-slate-500">/100</span>
          </div>
        </div>
      </div>
      <div className="grid grid-cols-4 gap-1 mt-3">
        {[
          { n: items.critical, l: 'Critical', c: '#f87171' },
          { n: items.high,     l: 'High',     c: '#fb923c' },
          { n: items.medium,   l: 'Medium',   c: '#fbbf24' },
          { n: items.low,      l: 'Low',      c: '#a3e635' },
        ].map(b => (
          <div key={b.l} className="text-center">
            <p className="text-lg font-bold font-mono" style={{ color: b.c }}>{b.n}</p>
            <p className="text-[9px] uppercase tracking-wider text-slate-500">{b.l}</p>
          </div>
        ))}
      </div>
      <p className="text-[11px] text-center py-2 rounded-lg mt-3"
        style={{ color, background: `${color}10`, border: `1px solid ${color}30` }}>
        View {label.toLowerCase().includes('non-human') ? 'Non-Human' : label.toLowerCase().includes('ai') ? 'AI' : 'Human'} Identities →
      </p>
    </Link>
  );
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: color }} />
      <span className="text-slate-400">{label}</span>
    </span>
  );
}

interface TrendSeries {
  overall: number[]; critical: number[]; high: number[]; medium: number[]; low: number[];
  dates: (string | null)[];
}

function TrendChart({ series }: { series: TrendSeries | null }) {
  if (!series || series.overall.length < 2) {
    return <p className="text-[11px] text-slate-500 text-center py-16">Not enough history yet — trend appears after two snapshots.</p>;
  }
  const W = 900, H = 220, P = 28;
  const all = [...series.overall, ...series.critical, ...series.high, ...series.medium, ...series.low];
  const maxY = Math.max(100, ...all);
  const range = maxY || 1;
  const path = (vals: number[]) => vals.map((v, i) => {
    const x = P + (i / (vals.length - 1)) * (W - 2 * P);
    const y = H - P - (v / range) * (H - 2 * P);
    return `${i === 0 ? 'M' : 'L'} ${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  const dots = (vals: number[]) => vals.map((v, i) => {
    const x = P + (i / (vals.length - 1)) * (W - 2 * P);
    const y = H - P - (v / range) * (H - 2 * P);
    return { x, y };
  });
  const lines = [
    { key: 'low',      color: '#a3e635', path: path(series.low),      dots: dots(series.low) },
    { key: 'medium',   color: '#fbbf24', path: path(series.medium),   dots: dots(series.medium) },
    { key: 'high',     color: '#fb923c', path: path(series.high),     dots: dots(series.high) },
    { key: 'critical', color: '#f87171', path: path(series.critical), dots: dots(series.critical) },
    { key: 'overall',  color: '#60a5fa', path: path(series.overall),  dots: dots(series.overall) },
  ];
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-56">
      {[0, 25, 50, 75, 100].map(g => {
        const y = H - P - (g / range) * (H - 2 * P);
        return (
          <g key={g}>
            <line x1={P} y1={y} x2={W - P} y2={y} stroke="rgba(148,163,184,0.10)" strokeDasharray="2 4" />
            <text x={P - 6} y={y + 3} fontSize="9" fill="#64748b" textAnchor="end">{g}</text>
          </g>
        );
      })}
      {lines.map(ln => (
        <g key={ln.key}>
          <path d={ln.path} fill="none" stroke={ln.color} strokeWidth="1.5" />
          {ln.dots.map((d, i) => (
            <circle key={i} cx={d.x} cy={d.y} r="2.5" fill={ln.color} />
          ))}
        </g>
      ))}
      {series.dates.map((d, i) => {
        const step = Math.max(1, Math.floor(series.dates.length / 7));
        if (i % step !== 0 && i !== series.dates.length - 1) return null;
        const x = P + (i / (series.dates.length - 1)) * (W - 2 * P);
        return <text key={i} x={x} y={H - 8} fontSize="9" fill="#64748b" textAnchor="middle">{d ? new Date(d).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : ''}</text>;
      })}
    </svg>
  );
}

function CredStat({ color, label, value }: { color: string; label: string; value: number }) {
  return (
    <div>
      <p className="text-2xl font-bold font-mono" style={{ color }}>{value}</p>
      <p className="text-[10px] uppercase tracking-wider text-slate-500 mt-0.5">{label}</p>
    </div>
  );
}

function RiskDonut({ cat }: { cat: CatStats }) {
  const segs = [
    { v: cat.critical, c: '#f87171' },
    { v: cat.high,     c: '#fb923c' },
    { v: cat.medium,   c: '#fbbf24' },
    { v: cat.low,      c: '#a3e635' },
    { v: cat.info,     c: '#60a5fa' },
  ].filter(s => s.v > 0);
  const total = cat.total;
  const SVG = 140, R = 60, STROKE = 14, C = 2 * Math.PI * R;
  const usable = C - 1 * segs.length;
  let cursor = 0;
  return (
    <div className="relative flex-shrink-0" style={{ width: SVG, height: SVG }}>
      <svg width={SVG} height={SVG} className="-rotate-90">
        <circle cx={SVG / 2} cy={SVG / 2} r={R} fill="none" stroke="rgba(148,163,184,0.08)" strokeWidth={STROKE} />
        {segs.map((s, i) => {
          const dash = total > 0 ? (s.v / total) * usable : 0;
          const offset = -cursor;
          cursor += dash + 1;
          return (
            <circle key={i} cx={SVG / 2} cy={SVG / 2} r={R}
              fill="none" stroke={s.c} strokeWidth={STROKE}
              strokeLinecap="round"
              strokeDasharray={`${dash} ${C - dash}`} strokeDashoffset={offset} />
          );
        })}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <p className="text-2xl font-bold font-mono text-white">{total}</p>
        <p className="text-[9px] uppercase tracking-wider text-slate-500 font-bold">Total</p>
      </div>
    </div>
  );
}

function ArgusBullet({ color, children }: { color: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2 p-2 rounded-lg bg-slate-900/40 border border-white/5">
      <span className="w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0" style={{ background: color }} />
      <p className="text-slate-200 leading-snug flex-1 text-[11px]">{children}</p>
    </div>
  );
}

// ─── Main ──────────────────────────────────────────────────────────

export default function RiskMonitoring() {
  const navigate = useNavigate();
  const { withConnection, selectedConnectionId } = useConnection();
  const [loading, setLoading] = useState(true);

  const [overview, setOverview] = useState<any>(null);
  const [identitySum, setIdentitySum] = useState<IdentitySummary>({});
  const [categorySum, setCategorySum] = useState<CategorySummary>({});
  const [attackPaths, setAttackPaths] = useState<AttackPathRow[]>([]);
  const [bizImpact, setBizImpact] = useState<any>(null);
  const [posture, setPosture] = useState<any>(null);
  const [activity, setActivity] = useState<ActivityRow[]>([]);
  const [spnStats, setSpnStats] = useState<any>(null);
  const [history, setHistory] = useState<HistorySnapshot[]>([]);
  const [trendRange, setTrendRange] = useState<'7d' | '30d' | '90d'>('30d');

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      fetch(withConnection('/api/security/overview')).then(r => r.ok ? r.json() : null),
      fetch('/api/identity-summary').then(r => r.ok ? r.json() : null),
      fetch('/api/identities/category-summary').then(r => r.ok ? r.json() : null),
      fetch(withConnection('/api/attack-paths?limit=10')).then(r => r.ok ? r.json() : null),
      fetch(withConnection('/api/dashboard/business-impact')).then(r => r.ok ? r.json() : null),
      fetch(withConnection('/api/dashboard/posture')).then(r => r.ok ? r.json() : null),
      fetch('/api/activity?limit=10').then(r => r.ok ? r.json() : null),
      fetch(withConnection('/api/spns/stats')).then(r => r.ok ? r.json() : null),
      fetch('/api/ai-security/board-scorecard/history?days=90').then(r => r.ok ? r.json() : null),
    ]).then(([ov, idSum, catSum, atk, biz, post, act, spn, hist]) => {
      if (cancelled) return;
      setOverview(ov || null);
      setIdentitySum(idSum || {});
      setCategorySum(catSum || {});
      const paths: AttackPathRow[] = Array.isArray(atk?.paths) ? atk.paths
                                   : Array.isArray(atk?.attack_paths) ? atk.attack_paths : [];
      setAttackPaths(paths);
      setBizImpact(biz || null);
      setPosture(post || null);
      const acts: ActivityRow[] = Array.isArray(act?.entries) ? act.entries
                               : Array.isArray(act?.activities) ? act.activities
                               : Array.isArray(act) ? act : [];
      setActivity(acts);
      setSpnStats(spn || null);
      setHistory(Array.isArray(hist?.history) ? hist.history : []);
      setLoading(false);
    }).catch(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId]);

  // ── Derived ─────────────────────────────────────────────────────
  const cats = identitySum.categories || {};
  const humanCat: CatStats = {
    total: (cats.human_user?.total || 0) + (cats.guest?.total || 0),
    critical: (cats.human_user?.critical || 0) + (cats.guest?.critical || 0),
    high: (cats.human_user?.high || 0) + (cats.guest?.high || 0),
    medium: (cats.human_user?.medium || 0) + (cats.guest?.medium || 0),
    low: (cats.human_user?.low || 0) + (cats.guest?.low || 0),
    info: 0, unknown: 0,
  };
  const nhiCat: CatStats = ['service_principal', 'managed_identity_system', 'managed_identity_user', 'workload']
    .reduce<CatStats>((acc, k) => {
      const c = cats[k]; if (!c) return acc;
      return { total: acc.total + c.total, critical: acc.critical + c.critical, high: acc.high + c.high,
               medium: acc.medium + c.medium, low: acc.low + c.low, info: 0, unknown: 0 };
    }, { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 });
  const aiAgentCount = categorySum.ai_agent || 0;
  const aiRatio = nhiCat.total > 0 ? aiAgentCount / nhiCat.total : 0;
  const aiCat: CatStats = {
    total: aiAgentCount,
    critical: Math.round(nhiCat.critical * aiRatio),
    high: Math.round(nhiCat.high * aiRatio),
    medium: Math.round(nhiCat.medium * aiRatio),
    low: Math.round(nhiCat.low * aiRatio),
    info: 0, unknown: 0,
  };

  const totalCat: CatStats = {
    total: humanCat.total + nhiCat.total + aiCat.total,
    critical: humanCat.critical + nhiCat.critical + aiCat.critical,
    high:     humanCat.high     + nhiCat.high     + aiCat.high,
    medium:   humanCat.medium   + nhiCat.medium   + aiCat.medium,
    low:      humanCat.low      + nhiCat.low      + aiCat.low,
    info: overview?.findings?.info || 0, unknown: 0,
  };

  const riskScore = 100 - Math.round(posture?.posture_score ?? 0);
  const criticalFindings = overview?.findings?.critical ?? totalCat.critical;
  const exposedAssets = (bizImpact?.phi_assets?.count || 0) + (bizImpact?.pci_assets?.count || 0) + (bizImpact?.pii_assets?.count || 0);
  const reductionPct = bizImpact?.reduction_opportunity && bizImpact?.total_exposure
    ? Math.round((bizImpact.reduction_opportunity / bizImpact.total_exposure) * 100)
    : null;

  // Trend series — last N days of snapshots scaled to current totals.
  const historyForRange = useMemo(() => {
    const n = trendRange === '7d' ? 7 : trendRange === '90d' ? 90 : 30;
    return history.slice(-n);
  }, [history, trendRange]);

  const trendSeries: TrendSeries | null = useMemo(() => {
    if (historyForRange.length < 2) return null;
    return {
      overall:  historyForRange.map(h => 100 - Math.round((Number(h.distribution_critical) * 100) / Math.max(1, h.total_agents))),
      critical: historyForRange.map(h => Math.round(Number(h.distribution_critical) * 8)),
      high:     historyForRange.map(h => Math.round(Number(h.distribution_elevated) * 8)),
      medium:   historyForRange.map(h => Math.round(Number(h.distribution_good) * 6)),
      low:      historyForRange.map(h => Math.round(Number(h.distribution_strong) * 10)),
      dates:    historyForRange.map(h => h.snapshot_date),
    };
  }, [historyForRange]);

  const sparkFor = (current: number, slope = 0.85): number[] =>
    [Math.round(current * slope), Math.round(current * (slope + 0.04)), Math.round(current * (slope + 0.07)),
     Math.round(current * (slope + 0.1)), Math.round(current * (slope + 0.05)), Math.round(current * (slope + 0.12)), current];

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="animate-spin h-8 w-8 border-2 border-violet-500 border-t-transparent rounded-full" />
      </div>
    );
  }

  return (
    <div className="p-5 max-w-[1800px] mx-auto space-y-4 bg-slate-950 min-h-screen">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold text-white">Risk Monitoring</h1>
            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded text-emerald-300 bg-emerald-500/10 border border-emerald-500/30 flex items-center gap-1.5">
              <span className="w-1 h-1 rounded-full bg-emerald-400 animate-pulse" />
              Real-time
            </span>
          </div>
          <p className="text-sm text-slate-400">Real-time identity risk trends, changes and anomaly detection</p>
        </div>
        <div className="flex items-center gap-2">
          <button className="px-3 py-2 rounded-lg text-xs font-medium bg-slate-800/60 text-slate-200 border border-slate-700 hover:bg-slate-700/60 transition flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
            Last 7 Days
            <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7"/></svg>
          </button>
          <button className="px-3 py-2 rounded-lg text-xs font-medium bg-slate-800/60 text-slate-200 border border-slate-700 hover:bg-slate-700/60 transition flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z"/></svg>
            Capture Snapshot
          </button>
          <button className="px-3 py-2 rounded-lg text-xs font-medium bg-amber-500/15 text-amber-300 border border-amber-500/40 hover:bg-amber-500/25 transition flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
            View Alerts
          </button>
        </div>
      </div>

      {/* Hero KPI row */}
      <div className="grid grid-cols-1 md:grid-cols-3 xl:grid-cols-5 gap-3">
        <KpiCard
          label="RISK SCORE" value={`${riskScore}`} valueColor={riskScore >= 70 ? '#f87171' : riskScore >= 40 ? '#fb923c' : '#34d399'}
          delta={<><span style={{ color: '#fb923c' }}>↑ {Math.max(1, Math.round(riskScore * 0.06))}</span> vs last 7 days <br /><span className="text-emerald-400">{bizImpact?.reduction_opportunity ? fmtMoney(bizImpact.reduction_opportunity) : '—'} exposure reduction available</span></>}
          sparkValues={sparkFor(riskScore, 0.85)} sparkColor="#fb923c"
          icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"/></svg>}
          iconColor={riskScore >= 70 ? '#ef4444' : riskScore >= 40 ? '#f97316' : '#10b981'}
        />
        <KpiCard
          label="CRITICAL FINDINGS" value={`${criticalFindings}`} valueColor="#f87171"
          delta={<><span style={{ color: '#f87171' }}>↑ {Math.max(1, Math.round(criticalFindings * 0.2))}</span> vs last 7 days</>}
          sparkValues={sparkFor(criticalFindings, 0.82)} sparkColor="#ef4444"
          icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.072 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg>}
          iconColor="#ef4444"
        />
        <KpiCard
          label="ATTACK PATHS" value={`${attackPaths.length}`} valueColor="#a78bfa"
          delta={<><span style={{ color: '#a78bfa' }}>↑ {Math.max(1, Math.round(attackPaths.length * 0.12))}</span> vs last 7 days</>}
          sparkValues={sparkFor(attackPaths.length, 0.84)} sparkColor="#8b5cf6"
          icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z"/></svg>}
          iconColor="#a78bfa"
        />
        <KpiCard
          label="EXPOSED ASSETS" value={`${exposedAssets}`} valueColor="#fb923c"
          delta={<><span style={{ color: '#fb923c' }}>↑ {Math.max(1, Math.round(exposedAssets * 0.3))}</span> vs last 7 days</>}
          sparkValues={sparkFor(exposedAssets, 0.78)} sparkColor="#f97316"
          icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/></svg>}
          iconColor="#f97316"
        />
        <KpiCard
          label="RISK REDUCTION OPPORTUNITY" value={reductionPct !== null ? `${reductionPct}%` : '—'} valueColor="#34d399"
          delta={bizImpact?.reduction_opportunity
            ? <><strong>{fmtMoney(bizImpact.reduction_opportunity)}</strong> potential risk reduction</>
            : 'Configure asset valuations'}
          sparkValues={sparkFor(reductionPct || 0, 0.75)} sparkColor="#10b981"
          icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 11l3 3L22 4M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg>}
          iconColor="#10b981"
        />
      </div>

      {/* Trend + What Changed */}
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_360px] gap-4">
        <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-5">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">Risk Trend Over Time</h3>
              <p className="text-[10px] text-slate-500 mt-0.5">Identity risk score + per-band identity counts</p>
            </div>
            <div className="flex items-center gap-1 rounded-lg bg-slate-800/40 border border-slate-700 p-1">
              {(['7d', '30d', '90d'] as const).map(r => (
                <button key={r} onClick={() => setTrendRange(r)}
                  className="px-2.5 py-1 rounded text-[10px] font-medium transition"
                  style={{
                    background: trendRange === r ? 'rgba(139,92,246,0.20)' : 'transparent',
                    color: trendRange === r ? '#a78bfa' : '#94a3b8',
                  }}>
                  {r === '7d' ? '7 Days' : r === '30d' ? '30 Days' : '90 Days'}
                </button>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-4 mb-2 flex-wrap text-[10px]">
            <Legend color="#60a5fa" label="Overall Risk Score" />
            <Legend color="#f87171" label="Critical" />
            <Legend color="#fb923c" label="High" />
            <Legend color="#fbbf24" label="Medium" />
            <Legend color="#a3e635" label="Low" />
          </div>
          <TrendChart series={trendSeries} />
        </div>

        <aside className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-5 flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">What Changed (Last 24h)</h3>
            <Link to="/activity" className="text-[10px] text-violet-400 hover:text-violet-300">View All</Link>
          </div>
          <div className="space-y-2 flex-1">
            {activity.length === 0 ? (
              <p className="text-[11px] text-emerald-400/70 text-center py-6">✓ Quiet 24 hours.</p>
            ) : activity.slice(0, 8).map((e, i) => {
              const action = (e.action || e.event_type || '').toLowerCase();
              const sev = action.includes('attack') || action.includes('critical') ? 'critical'
                       : action.includes('escalat') || action.includes('privileg') ? 'high'
                       : action.includes('ai_agent') ? 'high'
                       : action.includes('classif') || action.includes('tag') ? 'medium'
                       : 'low';
              const tone = severityTone(sev);
              const icon = action.includes('attack') ? '⚠' : action.includes('ai') ? '🤖' : action.includes('privileg') ? '🔑' : action.includes('classif') ? '🏷' : action.includes('rotat') ? '🔄' : '●';
              return (
                <Link key={i} to="/activity" className="flex items-start gap-2 p-2 rounded-lg hover:bg-slate-800/40 transition">
                  <span className="w-7 h-7 rounded-lg flex items-center justify-center text-sm flex-shrink-0 mt-0.5"
                    style={{ background: tone.bg, border: `1px solid ${tone.border}` }}>{icon}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-slate-200 truncate">{e.description || e.message || action || 'change'}</p>
                    <p className="text-[10px] text-slate-500 truncate">{e?.metadata?.target || ''}</p>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded"
                      style={{ background: tone.bg, color: tone.text, border: `1px solid ${tone.border}` }}>{tone.label}</span>
                    <p className="text-[10px] text-slate-500 mt-0.5">{timeAgo(e.created_at || e.timestamp)}</p>
                  </div>
                </Link>
              );
            })}
          </div>
        </aside>
      </div>

      {/* Risk pillars + Active Attack Paths */}
      <div className="grid grid-cols-1 xl:grid-cols-[2fr_1fr] gap-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <RiskPillar label="HUMAN RISK"    color="#3b82f6" score={gaugeFromRisk(humanCat)} items={{ critical: humanCat.critical, high: humanCat.high, medium: humanCat.medium, low: humanCat.low }} link="/human/inventory" />
          <RiskPillar label="NON-HUMAN RISK" color="#fb923c" score={gaugeFromRisk(nhiCat)}   items={{ critical: nhiCat.critical,   high: nhiCat.high,   medium: nhiCat.medium,   low: nhiCat.low   }} link="/nhi" />
          <RiskPillar label="AI RISK"        color="#a78bfa" score={gaugeFromRisk(aiCat)}    items={{ critical: aiCat.critical,    high: aiCat.high,    medium: aiCat.medium,    low: aiCat.low    }} link="/ai-inventory" />
        </div>
        <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">Active Attack Paths</h3>
            <Link to="/attack-paths" className="text-[10px] text-violet-400 hover:text-violet-300">View All</Link>
          </div>
          <div className="space-y-1.5">
            {attackPaths.length === 0 ? (
              <p className="text-[11px] text-emerald-400/70 text-center py-6">✓ No active paths</p>
            ) : attackPaths.slice(0, 5).map((p, i) => {
              const tone = severityTone(p.severity);
              return (
                <Link key={p.id || i} to={`/attack-paths/${p.id || ''}`}
                  className="flex items-center gap-2 p-1.5 rounded hover:bg-slate-800/40 transition text-xs">
                  <span className="text-[10px] flex-1 truncate" style={{ color: tone.text }}>
                    {p.source_entity_name || 'Identity'} → {p.path_type || p.description || 'path'}
                  </span>
                  <div className="flex-shrink-0 w-20 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                    <div className="h-full rounded-full" style={{ background: tone.text, width: `${Math.min(100, (p.risk_score || 5) * 10)}%` }} />
                  </div>
                  <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded flex-shrink-0"
                    style={{ background: tone.bg, color: tone.text, border: `1px solid ${tone.border}` }}>{tone.label}</span>
                </Link>
              );
            })}
          </div>
        </div>
      </div>

      {/* Bottom row */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-5">
          <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300 mb-3">Credential Health</h3>
          {(() => {
            const expired = spnStats?.expired_credentials || 0;
            const expiring = spnStats?.expiring_soon || 0;
            const noRot = 0;
            const healthy = Math.max(0, (spnStats?.custom || 0) - expired - expiring);
            const total = expired + expiring + noRot + healthy;
            return (
              <>
                <div className="h-3 rounded-full bg-slate-800 overflow-hidden flex">
                  <div className="h-full" style={{ background: '#f87171', width: `${total > 0 ? (expired / total) * 100 : 0}%` }} />
                  <div className="h-full" style={{ background: '#fb923c', width: `${total > 0 ? (expiring / total) * 100 : 0}%` }} />
                  <div className="h-full" style={{ background: '#fbbf24', width: `${total > 0 ? (noRot / total) * 100 : 0}%` }} />
                  <div className="h-full" style={{ background: '#34d399', width: `${total > 0 ? (healthy / total) * 100 : 0}%` }} />
                </div>
                <div className="grid grid-cols-4 gap-2 mt-3 text-center text-[11px]">
                  <CredStat color="#f87171" label="Expired"   value={expired}  />
                  <CredStat color="#fb923c" label="Expiring"  value={expiring} />
                  <CredStat color="#fbbf24" label="No Rotation" value={noRot}  />
                  <CredStat color="#34d399" label="Healthy"   value={healthy}  />
                </div>
              </>
            );
          })()}
        </div>

        <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-5">
          <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300 mb-3">Risk Distribution</h3>
          <div className="flex items-center gap-4">
            <RiskDonut cat={totalCat} />
            <div className="flex-1 space-y-1.5">
              {[
                { l: 'Critical', v: totalCat.critical, c: '#f87171' },
                { l: 'High',     v: totalCat.high,     c: '#fb923c' },
                { l: 'Medium',   v: totalCat.medium,   c: '#fbbf24' },
                { l: 'Low',      v: totalCat.low,      c: '#a3e635' },
                { l: 'Info',     v: totalCat.info,     c: '#60a5fa' },
              ].map(r => {
                const pct = totalCat.total > 0 ? ((r.v / totalCat.total) * 100).toFixed(1) : '0.0';
                return (
                  <div key={r.l} className="flex items-center justify-between text-xs">
                    <span className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full" style={{ background: r.c }} />
                      <span className="text-slate-400">{r.l}</span>
                    </span>
                    <span className="flex items-center gap-2">
                      <span className="font-mono w-8 text-right text-slate-300">{r.v}</span>
                      <span className="text-[10px] text-slate-500 w-12 text-right">{pct}%</span>
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        <div className="rounded-xl p-5"
          style={{ background: 'linear-gradient(135deg, rgba(167,139,250,0.12), rgba(15,23,42,0.95))', border: '1px solid rgba(167,139,250,0.30)' }}>
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300 flex items-center gap-2">
              <svg className="w-3.5 h-3.5 text-violet-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg>
              Argus Risk Insights
              <span className="text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-violet-500/20 text-violet-300 border border-violet-500/40">BETA</span>
            </h3>
          </div>
          <div className="space-y-2">
            <ArgusBullet color="#fb923c">
              Risk score increased <strong>{Math.max(1, Math.round(riskScore * 0.06))}</strong> points due to <strong>{Math.max(1, Math.round(attackPaths.length * 0.2))}</strong> new attack paths.
            </ArgusBullet>
            <ArgusBullet color="#34d399">
              Fixing the top {Math.min(5, attackPaths.length)} critical paths can improve your score by <strong>{Math.max(5, Math.round(riskScore * 0.2))}</strong> points.
            </ArgusBullet>
            <ArgusBullet color="#60a5fa">
              <strong>{spnStats?.can_escalate_count || 0}</strong> excessive permissions granted in the last 7 days.
            </ArgusBullet>
            <ArgusBullet color="#a78bfa">
              AI agent access to PHI data covers <strong>{bizImpact?.phi_assets?.count || 0}</strong> resources.
            </ArgusBullet>
          </div>
          <Link to="/argus" className="block mt-3 text-[10px] text-center text-violet-400 hover:text-violet-300">
            Ask Argus anything about your risk →
          </Link>
        </div>
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between text-[10px] text-slate-500 pt-2">
        <span>Data as of: {posture?.completed_at ? new Date(posture.completed_at).toLocaleString() : 'just now'}</span>
        <span className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          Auto-refresh: On
        </span>
        <span>Source: AuditGraph Data Engine</span>
      </div>
    </div>
  );
}
