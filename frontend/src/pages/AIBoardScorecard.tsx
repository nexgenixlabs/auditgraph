/**
 * AG-BOARD-V2 (2026-06-10) — AI Board Scorecard
 *
 * Founder-spec rebuild to match the design comp. SSOT-driven — every
 * number derives from /api/ai-security/board-scorecard (live KPIs,
 * distribution, top-10 worst) + /api/ai-security/board-scorecard/history
 * (trend chart). No hardcoded fallbacks.
 *
 * Layout (matches reference top-down):
 *   Header       — title + Snapshot pill + Last-7-Days / Download Board Pack
 *   Row 1        — 5 KPI cards (With Owner / Telemetry / Private Network /
 *                  Least Privilege / Policy Compliant) each with sparkline +
 *                  framework citation (NIST AI RMF / ISO 42001) + tone icon
 *   Row 2        — 3 panels (Posture Distribution donut · Trend Over Time
 *                  line chart · KPI Snapshots empty-or-history)
 *   Row 3        — search + 3 filter dropdowns + Filters
 *   Row 4        — agents table (id, display name, owner, trust, top failing
 *                  dimension, posture mini-bars, last seen) + Insights right
 *                  rail (Critical / Elevated / Ownership Gaps / Compliant ratio
 *                  + View Remediation Plan)
 *
 * Previous page preserved at AIBoardScorecardLegacy.tsx.
 */
import React, { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

// ─── Types ─────────────────────────────────────────────────────────

interface BoardScorecard {
  total_agents: number;
  with_owner_pct: number;
  with_telemetry_pct: number;
  private_network_pct: number;
  least_privilege_pct: number;
  policy_compliant_pct: number;
  distribution: { strong: number; good: number; elevated: number; critical: number };
  top_10_worst: Array<{
    identity_id: string;
    display_name: string;
    trust_score: number;
    top_dimension_fail: string | null;
    owner?: string | null;
    last_seen?: string | null;
  }>;
  exceptions_pending: number;
}

interface HistorySnapshot {
  snapshot_date: string | null;
  total_agents: number;
  with_owner_pct: number;
  with_telemetry_pct: number;
  private_network_pct: number;
  least_privilege_pct: number;
  policy_compliant_pct: number;
  distribution_strong: number;
  distribution_good: number;
  distribution_elevated: number;
  distribution_critical: number;
  exceptions_pending: number;
}

// ─── Helpers ───────────────────────────────────────────────────────

function trustTone(score: number): { text: string; bg: string; border: string; label: string } {
  if (score >= 80) return { text: '#34d399', bg: 'rgba(52,211,153,0.10)',  border: 'rgba(52,211,153,0.40)',  label: 'Strong' };
  if (score >= 60) return { text: '#a3e635', bg: 'rgba(163,230,53,0.10)',  border: 'rgba(163,230,53,0.40)',  label: 'Good' };
  if (score >= 40) return { text: '#fb923c', bg: 'rgba(251,146,60,0.10)',  border: 'rgba(251,146,60,0.40)',  label: 'Elevated' };
  return                { text: '#f87171', bg: 'rgba(248,113,113,0.10)', border: 'rgba(248,113,113,0.40)', label: 'Critical' };
}

function pctTone(value: number, healthyMin: number = 80, borderlineMin: number = 50):
  { text: string; bg: string; border: string; spark: string } {
  if (value >= healthyMin) return { text: '#34d399', bg: 'rgba(52,211,153,0.08)',  border: 'rgba(52,211,153,0.30)',  spark: '#10b981' };
  if (value >= borderlineMin) return { text: '#fbbf24', bg: 'rgba(251,191,36,0.08)', border: 'rgba(251,191,36,0.30)', spark: '#f59e0b' };
  return                       { text: '#f87171', bg: 'rgba(248,113,113,0.08)', border: 'rgba(248,113,113,0.30)', spark: '#ef4444' };
}

function timeAgo(iso?: string | null): string {
  if (!iso) return '—';
  const ms = Date.now() - new Date(iso).getTime();
  if (!Number.isFinite(ms) || ms < 0) return '—';
  const h = Math.round(ms / 3_600_000);
  if (h < 1) return 'just now';
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  return `${d}d ago`;
}

function ownerInitials(name?: string | null): string {
  if (!name) return '—';
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '—';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

function ownerColor(name?: string | null): string {
  if (!name) return '#475569';
  // Deterministic color per owner — same initials always same hue.
  let hash = 0;
  for (let i = 0; i < name.length; i++) hash = (hash * 31 + name.charCodeAt(i)) >>> 0;
  const palette = ['#3b82f6', '#a78bfa', '#f97316', '#10b981', '#f43f5e', '#22d3ee', '#fbbf24', '#ec4899'];
  return palette[hash % palette.length];
}

function dimensionLabel(k: string | null | undefined): { name: string; framework: string } {
  switch ((k || '').toLowerCase()) {
    case 'secrets':       return { name: 'secrets',       framework: 'ISO 42001 · 4.1.4' };
    case 'ownership':     return { name: 'ownership',     framework: 'NIST AI RMF · Manage 2.1' };
    case 'egress':        return { name: 'egress',        framework: 'NIST AI RMF · Govern 3.2' };
    case 'telemetry':     return { name: 'telemetry',     framework: 'NIST AI RMF · Measure 2.1' };
    case 'oversight':     return { name: 'oversight',     framework: 'NIST AI RMF · Manage 2.3' };
    case 'data_access':   return { name: 'data access',   framework: 'ISO 42001 · A.6.2' };
    case 'network':       return { name: 'network',       framework: 'ISO 42001 · 4.1.4' };
    case 'model_exposure':return { name: 'model exposure',framework: 'NIST AI RMF · Manage 2.3' };
    case 'supply_chain':  return { name: 'supply chain',  framework: 'NIST AI RMF · Govern 2.1' };
    default:              return { name: '—',             framework: '' };
  }
}

// ─── Sub-components ────────────────────────────────────────────────

function Sparkline({ values, color }: { values: number[]; color: string }) {
  if (values.length < 2) {
    return <div className="text-[10px]" style={{ color: 'var(--text-muted)' }}>no history</div>;
  }
  const min = Math.min(...values);
  const max = Math.max(...values, min + 1);
  const range = max - min || 1;
  const W = 80, H = 24;
  const points = values.map((v, i) => {
    const x = (i / (values.length - 1)) * W;
    const y = H - ((v - min) / range) * H;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  const area = `0,${H} ${points} ${W},${H}`;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-20 h-6">
      <polygon points={area} fill={`${color}22`} />
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.5" />
    </svg>
  );
}

function KpiCard({
  label, value, citation, sparkValues, icon,
}: {
  label: string; value: number; citation: string; sparkValues: number[]; icon: React.ReactNode;
}) {
  const tone = pctTone(value);
  return (
    <div className="rounded-xl p-4 bg-[#0f172a]/80"
      style={{ border: `1px solid ${tone.border}` }}>
      <div className="flex items-start justify-between gap-2 mb-2">
        <p className="text-[10px] uppercase tracking-wider font-bold text-slate-500">{label}</p>
        <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{ background: tone.bg, color: tone.text, border: `1px solid ${tone.border}` }}>
          {icon}
        </div>
      </div>
      <p className="text-3xl font-bold" style={{ color: tone.text }}>{Math.round(value)}%</p>
      <div className="flex items-end justify-between mt-2">
        <p className="text-[10px] text-slate-500 leading-tight">{citation}</p>
        <Sparkline values={sparkValues} color={tone.spark} />
      </div>
    </div>
  );
}

function PostureDonut({ dist, total }: { dist: BoardScorecard['distribution']; total: number }) {
  const segs = [
    { key: 'strong',   color: '#34d399', value: dist.strong,   label: 'Strong (≥80)' },
    { key: 'good',     color: '#a3e635', value: dist.good,     label: 'Good (60–79)' },
    { key: 'elevated', color: '#fb923c', value: dist.elevated, label: 'Elevated (40–59)' },
    { key: 'critical', color: '#f87171', value: dist.critical, label: 'Critical (<40)' },
  ];
  // Thinner stroke + smaller radius = clean smooth ring, not chunky pinwheel.
  // SVG_SIZE = 160; R = 65; STROKE = 14 produces a balanced donut.
  const SVG_SIZE = 160;
  const R = 65;
  const STROKE = 14;
  const C = 2 * Math.PI * R;
  // Insert a tiny gap between each non-zero segment so they read as separate
  // arcs rather than blurring into one band.
  const visibleSegs = segs.filter(s => s.value > 0);
  const GAP = visibleSegs.length > 1 ? 1.5 : 0;  // px of stroke
  const usable = C - GAP * visibleSegs.length;
  let cursor = 0;
  return (
    <div className="flex items-center gap-6">
      <div className="relative flex-shrink-0" style={{ width: SVG_SIZE, height: SVG_SIZE }}>
        <svg width={SVG_SIZE} height={SVG_SIZE} viewBox={`0 0 ${SVG_SIZE} ${SVG_SIZE}`} className="-rotate-90">
          {/* track */}
          <circle cx={SVG_SIZE / 2} cy={SVG_SIZE / 2} r={R}
            fill="none" stroke="rgba(148,163,184,0.08)" strokeWidth={STROKE} />
          {visibleSegs.map(s => {
            const dash = (s.value / total) * usable;
            const offset = -cursor;
            cursor += dash + GAP;
            return (
              <circle key={s.key} cx={SVG_SIZE / 2} cy={SVG_SIZE / 2} r={R}
                fill="none" stroke={s.color} strokeWidth={STROKE}
                strokeLinecap="round"
                strokeDasharray={`${dash} ${C - dash}`} strokeDashoffset={offset} />
            );
          })}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <p className="text-3xl font-bold text-white font-mono">{total}</p>
          <p className="text-[10px] uppercase tracking-wider text-slate-500 font-bold">Total Agents</p>
        </div>
      </div>
      <div className="flex-1 space-y-2 min-w-0">
        {segs.map(s => {
          const pct = total > 0 ? Math.round((s.value / total) * 100) : 0;
          return (
            <div key={s.key} className="flex items-center gap-2 text-xs">
              <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: s.color }} />
              <span className="text-slate-300 flex-1 truncate">{s.label}</span>
              <div className="w-20 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                <div className="h-full rounded-full" style={{ background: s.color, width: `${pct}%`, opacity: 0.7 }} />
              </div>
              <span className="font-mono text-slate-400 w-16 text-right">{s.value} ({pct}%)</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function TrendChart({ history }: { history: HistorySnapshot[] }) {
  if (history.length < 2) {
    return (
      <div className="h-44 flex flex-col items-center justify-center text-center">
        <p className="text-xs text-slate-400">Not enough history yet — trend appears after two snapshots.</p>
        <p className="text-[10px] text-slate-500 mt-1">Snapshots are persisted automatically after each discovery run.</p>
      </div>
    );
  }
  const W = 520, H = 180, P = 24;
  const maxY = Math.max(15, ...history.map(s => Math.max(s.distribution_strong, s.distribution_good, s.distribution_elevated, s.distribution_critical)));
  const lineFor = (key: keyof HistorySnapshot, color: string) => {
    const points = history.map((s, i) => {
      const x = P + (i / (history.length - 1)) * (W - 2 * P);
      const v = (s[key] as number) || 0;
      const y = H - P - (v / maxY) * (H - 2 * P);
      return { x, y, v };
    });
    const path = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
    return { path, points, color };
  };
  const lines = [
    lineFor('distribution_strong',   '#34d399'),
    lineFor('distribution_good',     '#a3e635'),
    lineFor('distribution_elevated', '#fb923c'),
    lineFor('distribution_critical', '#f87171'),
  ];
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-44">
      {[0, 5, 10, 15].map(g => {
        const y = H - P - (g / maxY) * (H - 2 * P);
        return (
          <g key={g}>
            <line x1={P} y1={y} x2={W - P} y2={y} stroke="rgba(148,163,184,0.10)" strokeDasharray="2 4" />
            <text x={P - 6} y={y + 3} fontSize="9" fill="#64748b" textAnchor="end">{g}</text>
          </g>
        );
      })}
      {lines.map((l, i) => (
        <g key={i}>
          <path d={l.path} fill="none" stroke={l.color} strokeWidth="1.5" />
          {l.points.map((p, j) => (
            <circle key={j} cx={p.x} cy={p.y} r="2.5" fill={l.color} />
          ))}
        </g>
      ))}
      {history.map((s, i) => {
        const step = Math.max(1, Math.floor(history.length / 6));
        if (i % step !== 0 && i !== history.length - 1) return null;
        const x = P + (i / (history.length - 1)) * (W - 2 * P);
        const label = s.snapshot_date ? new Date(s.snapshot_date).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : '';
        return (
          <text key={i} x={x} y={H - 6} fontSize="9" fill="#64748b" textAnchor="middle">{label}</text>
        );
      })}
    </svg>
  );
}

function PostureBars({ score }: { score: number }) {
  const tone = trustTone(score);
  const filled = Math.max(1, Math.min(5, Math.round((score / 100) * 5)));
  return (
    <div className="flex items-center gap-0.5">
      {[1, 2, 3, 4, 5].map(i => (
        <span key={i} className="block w-2 h-1.5 rounded-sm"
          style={{ background: i <= filled ? tone.text : 'rgba(148,163,184,0.15)' }} />
      ))}
    </div>
  );
}

function InsightRow({ color, big, title, sub }: { color: string; big: React.ReactNode; title: string; sub: string }) {
  return (
    <div className="flex items-center gap-3">
      <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 font-bold font-mono text-sm"
        style={{ background: `${color}15`, color, border: `1px solid ${color}40` }}>
        {big}
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-xs font-medium text-slate-200">{title}</p>
        <p className="text-[10px] text-slate-500">{sub}</p>
      </div>
    </div>
  );
}

// ─── Main ──────────────────────────────────────────────────────────

export default function AIBoardScorecard() {
  const navigate = useNavigate();
  const [data, setData] = useState<BoardScorecard | null>(null);
  const [history, setHistory] = useState<HistorySnapshot[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [dimensionFilter, setDimensionFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [ownerFilter, setOwnerFilter] = useState('');

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      fetch('/api/ai-security/board-scorecard').then(r => r.ok ? r.json() : null),
      fetch('/api/ai-security/board-scorecard/history?days=30').then(r => r.ok ? r.json() : null),
    ]).then(([sc, hist]) => {
      if (cancelled) return;
      setData(sc || null);
      setHistory(Array.isArray(hist?.history) ? hist.history : []);
      setLoading(false);
    }).catch(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  const sparkSeries = useMemo(() => {
    const keys: Array<keyof HistorySnapshot> = [
      'with_owner_pct', 'with_telemetry_pct', 'private_network_pct',
      'least_privilege_pct', 'policy_compliant_pct',
    ];
    const out: Record<string, number[]> = {};
    keys.forEach(k => { out[k as string] = history.map(h => (h[k] as number) || 0); });
    return out;
  }, [history]);

  const insights = useMemo(() => {
    if (!data) return null;
    const ownershipGaps = data.top_10_worst.filter(a => (a.top_dimension_fail || '') === 'ownership').length;
    const critical = data.distribution.critical;
    const elevated = data.distribution.elevated;
    const compliant = data.distribution.strong + data.distribution.good;
    return { critical, elevated, ownershipGaps, compliant, total: data.total_agents };
  }, [data]);

  const filteredAgents = useMemo(() => {
    if (!data) return [];
    const q = search.trim().toLowerCase();
    return data.top_10_worst.filter(a => {
      if (q && !(a.display_name.toLowerCase().includes(q) || a.identity_id.toLowerCase().includes(q))) return false;
      if (dimensionFilter && (a.top_dimension_fail || '') !== dimensionFilter) return false;
      if (statusFilter) {
        const label = trustTone(a.trust_score).label.toLowerCase();
        if (label !== statusFilter) return false;
      }
      return true;
    });
  }, [data, search, dimensionFilter, statusFilter, ownerFilter]);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="animate-spin h-8 w-8 border-2 border-violet-500 border-t-transparent rounded-full" />
      </div>
    );
  }

  if (!data || data.total_agents === 0) {
    return (
      <div className="p-6 max-w-[1800px] mx-auto bg-slate-950 min-h-screen">
        <div className="rounded-xl border border-white/5 bg-[#0f172a] p-10 text-center">
          <h1 className="text-2xl font-bold text-white">AI Board Scorecard</h1>
          <p className="text-sm text-slate-400 mt-2">No AI agents discovered yet. Run a discovery scan to populate the scorecard.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-5 max-w-[1800px] mx-auto space-y-4 bg-slate-950 min-h-screen">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-violet-500/30 to-blue-500/30 border border-violet-500/40 flex items-center justify-center">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="w-6 h-6 text-violet-300">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 2L4 6v6c0 5.5 3.6 10.7 8 12 4.4-1.3 8-6.5 8-12V6l-8-4z" />
            </svg>
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">AI Board Scorecard</h1>
            <p className="text-sm text-slate-400">Board-ready view of your AI agent posture across NIST AI RMF + ISO 42001 dimensions.</p>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-xs text-slate-500">Snapshot — {data.total_agents} AI agents in scope</span>
              <span className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold text-emerald-300 bg-emerald-500/10 border border-emerald-500/30">
                <span className="w-1 h-1 rounded-full bg-emerald-400" />
                Real-time
              </span>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button className="px-3 py-2 rounded-lg text-xs font-medium bg-slate-800/60 text-slate-200 border border-slate-700 hover:bg-slate-700/60 transition flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
            Last 7 Days
            <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7"/></svg>
          </button>
          <button className="px-3 py-2 rounded-lg text-xs font-medium bg-violet-500/15 text-violet-300 border border-violet-500/40 hover:bg-violet-500/25 transition flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
            Download Board Pack
          </button>
        </div>
      </div>

      {/* Row 1: 5 KPI cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 xl:grid-cols-5 gap-3">
        <KpiCard
          label="WITH OWNER" value={data.with_owner_pct}
          citation={`Total Agents: ${data.total_agents}`}
          sparkValues={sparkSeries.with_owner_pct}
          icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>}
        />
        <KpiCard
          label="WITH TELEMETRY" value={data.with_telemetry_pct}
          citation="NIST AI RMF · Measure 2.1"
          sparkValues={sparkSeries.with_telemetry_pct}
          icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M8.288 15.038a5.25 5.25 0 017.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0M12.53 18.22l-.53.53-.53-.53a.75.75 0 011.06 0z"/></svg>}
        />
        <KpiCard
          label="PRIVATE NETWORK" value={data.private_network_pct}
          citation="ISO 42001 · 4.1.4"
          sparkValues={sparkSeries.private_network_pct}
          icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>}
        />
        <KpiCard
          label="LEAST PRIVILEGE" value={data.least_privilege_pct}
          citation="NIST AI RMF · Manage 2.3"
          sparkValues={sparkSeries.least_privilege_pct}
          icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>}
        />
        <KpiCard
          label="POLICY COMPLIANT" value={data.policy_compliant_pct}
          citation="ISO 42001 · 4.6.2"
          sparkValues={sparkSeries.policy_compliant_pct}
          icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/></svg>}
        />
      </div>

      {/* Row 2: 3 panels — Posture Distribution / Trend / KPI Snapshots */}
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_1fr_360px] gap-4">
        <div className="rounded-xl p-5 bg-[#0f172a]/80 border border-white/5">
          <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300 mb-1">Posture Distribution</h3>
          <p className="text-[10px] text-slate-500 mb-4">Strong (≥80) · Good (60–79) · Elevated (40–59) · Critical (&lt;40)</p>
          <PostureDonut dist={data.distribution} total={data.total_agents} />
          <Link to="/identities?category=ai_agent" className="block mt-4 text-center text-[11px] text-violet-400 hover:text-violet-300">
            View all agents →
          </Link>
        </div>

        <div className="rounded-xl p-5 bg-[#0f172a]/80 border border-white/5">
          <div className="flex items-center justify-between mb-1">
            <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">Trend Over Time</h3>
            <span className="text-[10px] text-slate-500">Last 30 days</span>
          </div>
          <div className="flex items-center gap-4 mb-3 text-[10px]">
            <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /><span className="text-slate-400">Strong</span></span>
            <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-lime-400" /><span className="text-slate-400">Good</span></span>
            <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-orange-400" /><span className="text-slate-400">Elevated</span></span>
            <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-red-400" /><span className="text-slate-400">Critical</span></span>
          </div>
          <TrendChart history={history} />
        </div>

        <div className="rounded-xl p-5 bg-[#0f172a]/80 border border-white/5">
          <div className="flex items-center justify-between mb-1">
            <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">KPI Snapshots</h3>
            <span className="text-[10px] text-slate-500">{history.length} captured</span>
          </div>
          {history.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <div className="w-10 h-10 rounded-lg bg-slate-800/60 border border-slate-700 flex items-center justify-center mb-3">
                <svg className="w-5 h-5 text-slate-500" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>
              </div>
              <p className="text-xs font-medium text-slate-300">Not enough history yet —</p>
              <p className="text-[11px] text-slate-500 mt-1">trend appears after two snapshots.</p>
              <div className="mt-4 pt-3 border-t border-white/5 w-full">
                <div className="flex items-center gap-2 text-[10px] text-slate-400">
                  <svg className="w-3 h-3 text-slate-500" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                  Next snapshot
                </div>
                <p className="text-[10px] text-slate-500 mt-1">Persisted automatically after the next scan</p>
              </div>
            </div>
          ) : (
            <div className="space-y-2 mt-3">
              {history.slice(-5).reverse().map((h, i) => (
                <div key={i} className="flex items-center justify-between text-xs">
                  <span className="text-slate-400">{h.snapshot_date ? new Date(h.snapshot_date).toLocaleDateString() : '—'}</span>
                  <span className="text-slate-200 font-mono">{h.total_agents} agents · {Math.round(h.with_owner_pct)}% owned</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Row 3: Filter / Search */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex-1 relative min-w-[260px]">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search agents, names, IDs..."
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-[#0f172a]/80 border border-white/5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-violet-500/40" />
        </div>
        <select value={dimensionFilter} onChange={e => setDimensionFilter(e.target.value)}
          className="px-3 py-2 rounded-lg bg-[#0f172a]/80 border border-white/5 text-xs text-slate-200 focus:outline-none focus:border-violet-500/40">
          <option value="">All Dimensions</option>
          <option value="ownership">Ownership</option>
          <option value="secrets">Secrets</option>
          <option value="egress">Egress</option>
          <option value="telemetry">Telemetry</option>
          <option value="oversight">Oversight</option>
        </select>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
          className="px-3 py-2 rounded-lg bg-[#0f172a]/80 border border-white/5 text-xs text-slate-200 focus:outline-none focus:border-violet-500/40">
          <option value="">All Status</option>
          <option value="strong">Strong</option>
          <option value="good">Good</option>
          <option value="elevated">Elevated</option>
          <option value="critical">Critical</option>
        </select>
        <select value={ownerFilter} onChange={e => setOwnerFilter(e.target.value)}
          className="px-3 py-2 rounded-lg bg-[#0f172a]/80 border border-white/5 text-xs text-slate-200 focus:outline-none focus:border-violet-500/40">
          <option value="">All Owners</option>
        </select>
        <button className="px-3 py-2 rounded-lg text-xs font-medium bg-violet-500/15 text-violet-300 border border-violet-500/40 hover:bg-violet-500/25 transition flex items-center gap-1.5">
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z"/></svg>
          Filters
        </button>
      </div>

      {/* Row 4: Agents table + Insights right rail */}
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_320px] gap-4">
        <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 overflow-hidden">
          {/*
            Columns (matches reference comp):
              [ ☐ ] [ 🤖 ] [ AGENT id ] [ status chip ] [ display name + sub ]
              [ owner avatar + name ] [ trust score chip ] [ top failing dim ]
              [ posture bars ] [ last seen ] [ ⋯ ]
          */}
          <div className="grid grid-cols-[24px_30px_1.4fr_85px_1.5fr_1.1fr_70px_1.4fr_70px_70px_24px] gap-2 px-4 py-2.5 text-[10px] uppercase tracking-wider font-bold text-slate-500 border-b border-white/5 items-center">
            <span></span>
            <span></span>
            <span>Agent</span>
            <span></span>
            <span>Display Name</span>
            <span>Owner</span>
            <span>Trust Score</span>
            <span>Top Failing Dimension</span>
            <span>Posture</span>
            <span>Last Seen</span>
            <span></span>
          </div>
          {filteredAgents.length === 0 ? (
            <p className="text-xs text-slate-500 text-center py-10">No agents match the current filter.</p>
          ) : filteredAgents.map(a => {
            const tone = trustTone(a.trust_score);
            const dim = dimensionLabel(a.top_dimension_fail);
            const rowBg = tone.label === 'Critical' ? 'bg-red-950/20 border-l-2 border-l-red-500/60' : '';
            const ownerName = a.owner ?? null;
            return (
              <Link key={a.identity_id}
                to={`/identities/${a.identity_id}`}
                className={`grid grid-cols-[24px_30px_1.4fr_85px_1.5fr_1.1fr_70px_1.4fr_70px_70px_24px] gap-2 px-4 py-2.5 items-center text-xs hover:bg-slate-800/30 transition border-b border-white/5 last:border-b-0 ${rowBg}`}>
                {/* checkbox */}
                <input type="checkbox" onClick={e => e.stopPropagation()}
                  className="w-3.5 h-3.5 rounded border-slate-600 bg-slate-800 accent-violet-500" />
                {/* robot icon */}
                <span className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
                  style={{ background: `${tone.text}15`, color: tone.text, border: `1px solid ${tone.border}` }}>
                  <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1v1a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-1H2a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h1a7 7 0 0 1 7-7h1V5.73c-.6-.34-1-.99-1-1.73a2 2 0 0 1 2-2M7.5 13A2.5 2.5 0 0 0 5 15.5 2.5 2.5 0 0 0 7.5 18a2.5 2.5 0 0 0 2.5-2.5A2.5 2.5 0 0 0 7.5 13m9 0a2.5 2.5 0 0 0-2.5 2.5 2.5 2.5 0 0 0 2.5 2.5 2.5 2.5 0 0 0 2.5-2.5 2.5 2.5 0 0 0-2.5-2.5Z"/></svg>
                </span>
                {/* agent id (truncated) */}
                <span className="font-mono text-slate-400 truncate" title={a.identity_id}>{a.identity_id}</span>
                {/* status chip */}
                <span className="font-bold px-1.5 py-0.5 rounded text-[10px] text-center"
                  style={{ background: tone.bg, color: tone.text, border: `1px solid ${tone.border}` }}>
                  {tone.label}
                </span>
                {/* display name + subline (the underlying identity_type) */}
                <span className="flex flex-col min-w-0">
                  <span className="text-slate-200 truncate">{a.display_name}</span>
                  <span className="text-[10px] text-slate-500 truncate">AI Agent</span>
                </span>
                {/* owner avatar + name */}
                <span className="flex items-center gap-1.5 min-w-0">
                  {ownerName ? (
                    <span className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0"
                      style={{ background: ownerColor(ownerName), color: '#fff' }}>
                      {ownerInitials(ownerName)}
                    </span>
                  ) : (
                    <span className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] flex-shrink-0 bg-slate-800 text-slate-500 border border-slate-700">—</span>
                  )}
                  <span className="text-slate-300 truncate text-[11px]">{ownerName || 'Unowned'}</span>
                </span>
                {/* trust score chip */}
                <span className="font-mono font-bold px-2 py-0.5 rounded text-center"
                  style={{ background: tone.bg, color: tone.text, border: `1px solid ${tone.border}` }}>
                  {a.trust_score}
                </span>
                {/* top failing dimension + framework citation */}
                <span className="flex flex-col min-w-0">
                  <span className="truncate text-slate-300">{dim.name}</span>
                  <span className="text-[10px] text-slate-500 truncate">{dim.framework}</span>
                </span>
                {/* posture bars */}
                <PostureBars score={a.trust_score} />
                {/* last seen */}
                <span className="text-slate-400 text-[11px]">{timeAgo(a.last_seen)}</span>
                {/* row menu */}
                <button onClick={e => { e.preventDefault(); e.stopPropagation(); }}
                  className="text-slate-500 hover:text-slate-300 transition flex items-center justify-center">
                  <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z"/></svg>
                </button>
              </Link>
            );
          })}
          <div className="px-4 py-2 border-t border-white/5 text-[10px] text-slate-500 flex items-center justify-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            Auto refreshed just now
          </div>
        </div>

        {/* Insights right rail */}
        <aside className="space-y-3">
          <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-4">
            <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300 mb-3 flex items-center gap-1.5">
              <svg className="w-3.5 h-3.5 text-violet-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg>
              Insights
            </h3>
            {insights && (
              <div className="space-y-3">
                <InsightRow color="#f87171" big={insights.critical}
                  title={`${insights.critical} Critical Risk${insights.critical === 1 ? '' : 's'}`}
                  sub={`${insights.critical} agent${insights.critical === 1 ? '' : 's'} ha${insights.critical === 1 ? 's' : 've'} critical issues`} />
                <InsightRow color="#fb923c" big={insights.elevated}
                  title={`${insights.elevated} Elevated Risk${insights.elevated === 1 ? '' : 's'}`}
                  sub="Require immediate attention" />
                <InsightRow color="#fbbf24" big={insights.ownershipGaps}
                  title={`${insights.ownershipGaps} Ownership Gap${insights.ownershipGaps === 1 ? '' : 's'}`}
                  sub="Agents without assigned owner" />
                <InsightRow color="#34d399" big={`${insights.compliant}/${insights.total}`}
                  title="Agents Compliant" sub="Meeting all policy requirements" />
              </div>
            )}
            <Link to="/remediation" className="block mt-4 text-xs text-center py-2 rounded-lg bg-violet-500/15 text-violet-300 border border-violet-500/40 hover:bg-violet-500/25 transition">
              View Remediation Plan →
            </Link>
          </div>
          <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-3 text-[10px] text-slate-500 leading-relaxed">
            Architecture-derived signals · No telemetry required · NIST AI RMF + ISO 42001
          </div>
        </aside>
      </div>
    </div>
  );
}
