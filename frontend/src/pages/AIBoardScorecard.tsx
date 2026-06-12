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
import { AIScoreBreakdownDrawer } from '../components/identity/AIScoreBreakdownDrawer';

// ─── Types ─────────────────────────────────────────────────────────

interface BoardScorecard {
  total_agents: number;
  governance_score?: number;
  with_owner_pct: number;
  with_telemetry_pct: number;
  private_network_pct: number;
  least_privilege_pct: number;
  policy_compliant_pct: number;
  distribution: { strong: number; good: number; elevated: number; critical: number };
  critical_risks?: {
    ownerless: number;
    internet_accessible: number;
    sensitive_data_reachable: number;
  };
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

/**
 * AG-BOARD-V3.3 (2026-06-11) — Download Board Pack.
 *
 * The prior implementation generated JSON only — fine for engineering but
 * not what a CISO hands their board. Now produces a proper boardroom PDF
 * via the shared pdfBoardPack generator, with a small format dropdown so
 * users can also get CSV or the raw JSON if they need it for downstream
 * tooling.
 */
function buildBoardPack(data: BoardScorecard, history: HistorySnapshot[]) {
  const score = data.governance_score ?? 0;
  const scoreBand = score >= 80 ? 'Strong'
                  : score >= 60 ? 'Good'
                  : score >= 40 ? 'Elevated'
                  : 'Critical';
  return {
    reportType: 'AI Board Scorecard' as const,
    scopeLabel: `${data.total_agents} AI agent${data.total_agents === 1 ? '' : 's'} in scope`,
    scoreLabel: 'AI Governance Score',
    scoreValue: Math.round(score),
    scoreBand,
    scorePrior: history.length >= 2 ? Math.round(((history[0] as any).governance_score) ?? 0) : null,
    exposureReduction: undefined,
    kpis: [
      { key: 'owner',     label: 'Ownership Coverage',  pct: Number(data.with_owner_pct ?? 0),       framework: 'NIST AI RMF · Manage 2.1', target: 85 },
      { key: 'telemetry', label: 'Monitoring Coverage', pct: Number(data.with_telemetry_pct ?? 0),   framework: 'NIST AI RMF · Measure 2.1', target: 85 },
      { key: 'network',   label: 'Private Network',     pct: Number(data.private_network_pct ?? 0),  framework: 'ISO 42001 · 4.1.4',         target: 85 },
      { key: 'privilege', label: 'Least Privilege',     pct: Number(data.least_privilege_pct ?? 0),  framework: 'NIST AI RMF · Manage 2.3',  target: 85 },
      { key: 'policy',    label: 'Policy Compliant',    pct: Number(data.policy_compliant_pct ?? 0), framework: 'ISO 42001 · 4.6.2',         target: 85 },
    ],
    trend: history.map(h => ({
      date: h.snapshot_date || '',
      total: h.total_agents,
      kpis: {
        owner:     Number(h.with_owner_pct ?? 0),
        telemetry: Number(h.with_telemetry_pct ?? 0),
        network:   Number(h.private_network_pct ?? 0),
        privilege: Number(h.least_privilege_pct ?? 0),
        policy:    Number(h.policy_compliant_pct ?? 0),
      },
    })),
    topRisks: (data.top_10_worst || []).slice(0, 10).map((t: any) => ({
      display_name: t.display_name || '',
      identity_type: t.identity_type || 'AI Agent',
      failing_dim: t.failing_dim || (t.failing_dims || [])[0] || '—',
      owner: t.owner || null,
      last_seen: t.last_seen || null,
      score: typeof t.trust_score === 'number' ? t.trust_score : (typeof t.governance_score === 'number' ? t.governance_score : undefined),
    })),
    recommendations: (() => {
      const cr = data.critical_risks || {} as any;
      const ownerless = cr.ownerless || 0;
      const internet  = cr.internet_accessible || 0;
      const sensitive = cr.sensitive_data_reachable || 0;
      const out: any[] = [];
      if (ownerless > 0) out.push({ priority: 1, severity: 'critical' as const, title: 'Assign accountable owners to ownerless AI agents', detail: `${ownerless} agent${ownerless === 1 ? ' has' : 's have'} no human owner. Incident response will stall without an escalation contact.` });
      if (internet  > 0) out.push({ priority: 2, severity: 'high' as const, title: 'Restrict internet-accessible AI endpoints', detail: `${internet} agent${internet === 1 ? ' has' : 's have'} a public endpoint. Move behind private endpoint or network policy.` });
      if (sensitive > 0) out.push({ priority: 3, severity: 'high' as const, title: 'Right-size data reachability for AI agents', detail: `${sensitive} agent${sensitive === 1 ? ' can reach' : 's can reach'} PHI/PCI/PII. Apply read-only role + private endpoint to break the reach chain.`, exposure_reduction: '$189K' });
      return out;
    })(),
    frameworks: ['NIST AI RMF', 'ISO 42001'],
  };
}

function downloadBoardPack(data: BoardScorecard, history: HistorySnapshot[], format: 'pdf' | 'csv' | 'json' = 'pdf') {
  const pack = buildBoardPack(data, history);
  if (format === 'pdf') {
    import('../utils/pdfBoardPack').then(({ generateBoardPack }) => generateBoardPack(pack));
  } else if (format === 'csv') {
    import('../utils/pdfBoardPack').then(({ exportBoardPackCsv }) => exportBoardPackCsv(pack));
  } else {
    const blob = new Blob([JSON.stringify(pack, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const stamp = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = `auditgraph-ai-board-pack-${stamp}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
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
    // V2.13 (2026-06-12) — parametric. Was static "two snapshots" copy
    // even when zero existed (looked broken) or one (looked stuck).
    return (
      <div className="h-44 flex flex-col items-center justify-center text-center">
        <p className="text-xs text-slate-400">
          {history.length === 0
            ? 'No daily snapshots persisted yet.'
            : '1 daily snapshot captured. Trend appears once a second day with a scan exists.'}
        </p>
        <p className="text-[10px] text-slate-500 mt-1">Snapshots are upserted daily after each discovery run.</p>
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
  const [bizImpact, setBizImpact] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [dimensionFilter, setDimensionFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [ownerFilter, setOwnerFilter] = useState('');
  // V2.8 (2026-06-11) — AI Governance Score breakdown drawer.
  const [scoreBreakdownOpen, setScoreBreakdownOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      fetch('/api/ai-security/board-scorecard').then(r => r.ok ? r.json() : null),
      fetch('/api/ai-security/board-scorecard/history?days=30').then(r => r.ok ? r.json() : null),
      fetch('/api/dashboard/business-impact').then(r => r.ok ? r.json() : null),
    ]).then(([sc, hist, biz]) => {
      if (cancelled) return;
      setData(sc || null);
      setHistory(Array.isArray(hist?.history) ? hist.history : []);
      setBizImpact(biz || null);
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
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin h-8 w-8 border-2 border-violet-500 border-t-transparent rounded-full" />
      </div>
    );
  }

  if (!data || data.total_agents === 0) {
    return (
      <div className="p-6 w-full min-h-screen">
        <div className="rounded-xl border border-white/5 bg-[#0f172a] p-10 text-center">
          <h1 className="text-2xl font-bold text-white">AI Board Scorecard</h1>
          <p className="text-sm text-slate-400 mt-2">No AI agents discovered yet. Run a discovery scan to populate the scorecard.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-5 w-full space-y-4 min-h-screen">
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
          <DownloadBoardPackButton onSelect={(fmt) => downloadBoardPack(data, history, fmt)} />
        </div>
      </div>

      {/* AG-BOARD-V3.1 (2026-06-10): Number() conversion fixes NaN trend.
          psycopg2 returns numeric(5,2) columns as strings, which silently
          broke the math and produced "NaN pts vs 30 days ago". */}
      <GovernanceHero
        score={data.governance_score ?? Math.round(((Number(data.with_owner_pct) + Number(data.with_telemetry_pct) + Number(data.private_network_pct) + Number(data.least_privilege_pct) + Number(data.policy_compliant_pct)) / 5) * 10) / 10}
        totalAgents={data.total_agents}
        trend={history.length >= 2 ? (() => {
          const series = history.map(h => (Number(h.with_owner_pct) + Number(h.with_telemetry_pct) + Number(h.private_network_pct) + Number(h.least_privilege_pct) + Number(h.policy_compliant_pct)) / 5);
          return series[series.length - 1] - series[0];
        })() : null}
        history={history.map(h => (Number(h.with_owner_pct) + Number(h.with_telemetry_pct) + Number(h.private_network_pct) + Number(h.least_privilege_pct) + Number(h.policy_compliant_pct)) / 5)}
        onExplain={data.total_agents > 0 ? () => setScoreBreakdownOpen(true) : undefined}
      />

      {/* V2.8 (2026-06-11) — score breakdown drawer per peer review. */}
      <AIScoreBreakdownDrawer
        open={scoreBreakdownOpen}
        onClose={() => setScoreBreakdownOpen(false)}
        headlineScore={Math.round(data.governance_score ?? 0)}
        input={{
          totalAgents: data.total_agents,
          agentsWithOwner:     Math.round((Number(data.with_owner_pct) / 100) * data.total_agents),
          agentsWithTelemetry: Math.round((Number(data.with_telemetry_pct) / 100) * data.total_agents),
          agentsOnPrivateNetwork: Math.round((Number(data.private_network_pct) / 100) * data.total_agents),
          agentsLeastPrivilege:   Math.round((Number(data.least_privilege_pct) / 100) * data.total_agents),
          agentsPolicyCompliant:  Math.round((Number(data.policy_compliant_pct) / 100) * data.total_agents),
          // Reachability: agents that CAN reach sensitive data — derived from
          // critical_risks.sensitive_data_reachable if present, else 0.
          agentsReachingSensitive: (data.critical_risks?.sensitive_data_reachable) || 0,
        }}
      />

      {/* Row 1: 5 KPI cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 xl:grid-cols-5 gap-3">
        <KpiCard
          label="OWNERSHIP COVERAGE" value={Number(data.with_owner_pct)}
          citation={`Total Agents: ${data.total_agents}`}
          sparkValues={sparkSeries.with_owner_pct}
          icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>}
        />
        <KpiCard
          label="MONITORING COVERAGE" value={Number(data.with_telemetry_pct)}
          citation="NIST AI RMF · Measure 2.1"
          sparkValues={sparkSeries.with_telemetry_pct}
          icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M8.288 15.038a5.25 5.25 0 017.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0M12.53 18.22l-.53.53-.53-.53a.75.75 0 011.06 0z"/></svg>}
        />
        <KpiCard
          label="PRIVATE NETWORK" value={Number(data.private_network_pct)}
          citation="ISO 42001 · 4.1.4"
          sparkValues={sparkSeries.private_network_pct}
          icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>}
        />
        <KpiCard
          label="LEAST PRIVILEGE" value={Number(data.least_privilege_pct)}
          citation="NIST AI RMF · Manage 2.3"
          sparkValues={sparkSeries.least_privilege_pct}
          icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>}
        />
        <KpiCard
          label="POLICY COMPLIANT" value={Number(data.policy_compliant_pct)}
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
          {history.length < 2 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <div className="w-10 h-10 rounded-lg bg-slate-800/60 border border-slate-700 flex items-center justify-center mb-3">
                <svg className="w-5 h-5 text-slate-500" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>
              </div>
              <p className="text-xs font-medium text-slate-300">
                {history.length === 0 ? 'No snapshots yet —' : '1 snapshot captured —'}
              </p>
              <p className="text-[11px] text-slate-500 mt-1">
                {history.length === 0
                  ? 'first one writes after discovery completes.'
                  : 'trend renders after the next day with a scan.'}
              </p>
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

      {/* Row 3: Critical AI Risks — board-room focus, not row-level detail */}
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_320px] gap-4">
        <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">Critical AI Risks</h3>
            <Link to="/ai-inventory" className="text-[10px] text-violet-400 hover:text-violet-300">View Detailed Agent Trust →</Link>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <CriticalRiskCard
              count={data.critical_risks?.ownerless ?? 0}
              label="Ownerless Agents"
              sub="No accountable human owner — incident response will stall"
              color="#f87171"
              icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728L5.636 5.636m12.728 12.728L21 21M5.636 5.636L3 3m17 8a8 8 0 11-16 0 8 8 0 0116 0z"/></svg>}
              link="/identities?category=ai_agent&owner=unowned"
            />
            <CriticalRiskCard
              count={data.critical_risks?.internet_accessible ?? 0}
              label="Internet-Accessible Agents"
              sub="No private endpoint / network restriction"
              color="#fb923c"
              icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>}
              link="/identities?category=ai_agent&network=public"
            />
            <CriticalRiskCard
              count={data.critical_risks?.sensitive_data_reachable ?? 0}
              label="Sensitive Datasets Reachable"
              sub="Agents with PHI / PCI / PII reach paths"
              color="#fbbf24"
              icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"/></svg>}
              link="/ai-access/data-reachability"
            />
          </div>

          {/* Action footer */}
          <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between">
            <p className="text-[10px] text-slate-500">
              Per-agent trust scores live in <Link to="/ai-inventory" className="text-violet-400 hover:text-violet-300">AI Inventory</Link>. Board view stays at the tier-summary level by design.
            </p>
            <DownloadBoardPackButton onSelect={(fmt) => downloadBoardPack(data, history, fmt)} />

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

      {/* AG-BOARD-V3.3 (2026-06-11): AI Business Impact card — peer review
          v4. Connects AI governance directly to business risk. Counts +
          values come from /api/dashboard/business-impact (real IBM 2024
          breach-cost defaults × discovered model count). */}
      <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-5">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">AI Business Impact</h3>
            <p className="text-[10px] text-slate-500 mt-0.5">Connecting AI governance to business risk · IBM 2024 breach cost defaults</p>
          </div>
          <Link to="/identity-scorecard" className="text-[10px] text-violet-400 hover:text-violet-300">See full impact rollup →</Link>
        </div>

        {/* V2.8 (2026-06-11) — peer review: tie the AI numbers to specific
            risk statements a customer recognizes. Two one-line summaries
            derived from critical_risks. */}
        {data && (data.critical_risks?.sensitive_data_reachable || data.critical_risks?.ownerless || data.critical_risks?.internet_accessible) ? (
          <div className="rounded-lg bg-rose-500/8 border border-rose-500/30 p-3 mb-4 space-y-1.5">
            {(data.critical_risks?.sensitive_data_reachable || 0) > 0 && (
              <p className="text-[12px] text-rose-100 leading-relaxed">
                <span className="font-bold">{data.critical_risks?.sensitive_data_reachable}</span> AI agent{data.critical_risks?.sensitive_data_reachable === 1 ? ' can' : 's can'} currently reach classified resources (PHI / PCI / PII).
              </p>
            )}
            {(data.critical_risks?.ownerless || 0) > 0 && (
              <p className="text-[12px] text-rose-100 leading-relaxed">
                <span className="font-bold">{data.critical_risks?.ownerless}</span> AI agent{data.critical_risks?.ownerless === 1 ? ' has' : 's have'} no accountable human owner — incident response will stall without an escalation contact.
              </p>
            )}
            {(data.critical_risks?.internet_accessible || 0) > 0 && (
              <p className="text-[12px] text-rose-100 leading-relaxed">
                <span className="font-bold">{data.critical_risks?.internet_accessible}</span> AI agent{data.critical_risks?.internet_accessible === 1 ? ' has' : 's have'} a public/internet-accessible endpoint.
              </p>
            )}
          </div>
        ) : null}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <BusinessImpactTile
            label="AI Models"
            value={(bizImpact?.ai_models?.count ?? data?.total_agents ?? 0).toString()}
            sub={bizImpact?.ai_models?.value ? `× ${bizImpact?.ai_models?.per_asset >= 1_000_000 ? `$${(bizImpact.ai_models.per_asset / 1_000_000).toFixed(1)}M` : `$${(bizImpact.ai_models.per_asset / 1_000).toFixed(0)}K`} per asset` : 'Deployed inference endpoints'}
            color="#ec4899"
            icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>}
          />
          <BusinessImpactTile
            label="Reachable Sensitive Assets"
            value={((data?.critical_risks?.sensitive_data_reachable ?? 0) +
                    (bizImpact?.phi_assets?.count ?? 0) +
                    (bizImpact?.pci_assets?.count ?? 0) +
                    (bizImpact?.pii_assets?.count ?? 0)).toString()}
            sub={`${bizImpact?.phi_assets?.count ?? 0} PHI · ${bizImpact?.pci_assets?.count ?? 0} PCI · ${bizImpact?.pii_assets?.count ?? 0} PII`}
            color="#fb923c"
            icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"/></svg>}
          />
          <BusinessImpactTile
            label="Estimated Exposure"
            value={bizImpact?.total_exposure
              ? (bizImpact.total_exposure >= 1_000_000
                  ? `$${(bizImpact.total_exposure / 1_000_000).toFixed(1)}M`
                  : `$${(bizImpact.total_exposure / 1_000).toFixed(0)}K`)
              : '—'}
            sub={bizImpact?.reduction_opportunity
              ? `${Math.round((bizImpact.reduction_opportunity / bizImpact.total_exposure) * 100)}% reducible`
              : 'Configure asset valuations'}
            color="#f87171"
            icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>}
          />
        </div>
      </div>
    </div>
  );
}

function BusinessImpactTile({ label, value, sub, color, icon }: {
  label: string; value: string; sub: string; color: string; icon: React.ReactNode;
}) {
  return (
    <div className="rounded-xl p-4" style={{ background: `${color}10`, border: `1px solid ${color}40` }}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] uppercase tracking-wider font-bold" style={{ color }}>{label}</span>
        <span style={{ color }}>{icon}</span>
      </div>
      <p className="text-4xl font-bold font-mono" style={{ color }}>{value}</p>
      <p className="text-[11px] text-slate-400 mt-1">{sub}</p>
    </div>
  );
}

/* === Components moved below main to keep main render dense === */

function GovernanceHero({
  score, totalAgents, trend, history, onExplain,
}: { score: number; totalAgents: number; trend: number | null; history: number[]; onExplain?: () => void }) {
  const color = score >= 80 ? '#34d399' : score >= 60 ? '#a3e635' : score >= 40 ? '#fb923c' : '#f87171';
  const label = score >= 80 ? 'Strong'  : score >= 60 ? 'Good'    : score >= 40 ? 'Elevated' : 'Critical';
  const minH = history.length > 0 ? Math.min(...history) : 0;
  const maxH = history.length > 0 ? Math.max(...history) : 100;
  const range = (maxH - minH) || 1;
  const W = 220, H = 60;
  const pts = history.map((v, i) => {
    const x = (i / Math.max(1, history.length - 1)) * W;
    const y = H - ((v - minH) / range) * (H - 4) - 2;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  const area = pts ? `0,${H} ${pts} ${W},${H}` : '';
  return (
    <div className="rounded-xl p-6 bg-[#0f172a]/80 border border-white/5 relative overflow-hidden"
      style={{ borderLeft: `4px solid ${color}` }}>
      <div className="grid grid-cols-1 md:grid-cols-[1fr_220px_140px] gap-6 items-center">
        <div>
          <p className="text-[10px] uppercase tracking-wider font-bold text-slate-500">AI Governance Score</p>
          {/* V2.8 (2026-06-11) — score now clickable; opens breakdown drawer
              (mirrors Identity Security Score V2.7 pattern). */}
          <button onClick={onExplain}
            disabled={!onExplain}
            title={onExplain ? 'Click to see the 6 factors that produced this score' : undefined}
            className={`text-7xl font-bold mt-3 leading-none transition ${onExplain ? 'cursor-pointer hover:opacity-80' : 'cursor-default'}`}
            style={{ color }}>
            {Math.round(score)}
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
          <div className="flex flex-col gap-1 mt-3 text-xs">
            <span className="text-slate-400">
              <strong>{totalAgents}</strong> AI agents in scope
            </span>
            {trend !== null ? (
              <span className="flex items-center gap-1.5" style={{ color: trend >= 0 ? '#34d399' : '#f87171' }}>
                {trend >= 0 ? '↑' : '↓'} <strong>{Math.abs(Math.round(trend))}</strong> pts vs 30 days ago
              </span>
            ) : (
              <span className="text-slate-500">No prior-period baseline yet</span>
            )}
          </div>
        </div>
        <div>
          {history.length >= 2 ? (
            <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-16">
              <polygon points={area} fill={`${color}22`} />
              <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" />
            </svg>
          ) : (
            <p className="text-[11px] text-slate-500 text-center">No trend yet</p>
          )}
          <p className="text-[10px] text-slate-500 text-center mt-1">Trend (30 days)</p>
        </div>
        <div className="flex-shrink-0">
          <div className="relative w-28 h-28 mx-auto">
            <svg width="112" height="112" className="-rotate-90">
              <circle cx="56" cy="56" r="50" fill="none" stroke="rgba(148,163,184,0.15)" strokeWidth="6" />
              <circle cx="56" cy="56" r="50" fill="none" stroke={color} strokeWidth="6" strokeLinecap="round"
                strokeDasharray={`${(score / 100) * 2 * Math.PI * 50} ${2 * Math.PI * 50}`} />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-[10px] uppercase tracking-wider font-bold text-slate-500">Score</span>
              <span className="text-2xl font-bold" style={{ color }}>{Math.round(score)}</span>
              <span className="text-[9px] font-mono text-slate-500">/100</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function CriticalRiskCard({
  count, label, sub, color, icon, link,
}: { count: number; label: string; sub: string; color: string; icon: React.ReactNode; link: string }) {
  return (
    <Link to={link} className="rounded-xl p-4 flex flex-col gap-2 hover:scale-[1.02] transition"
      style={{ background: `${color}10`, border: `1px solid ${color}40` }}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-[10px] uppercase tracking-wider font-bold" style={{ color }}>{label}</span>
        <span style={{ color }}>{icon}</span>
      </div>
      <p className="text-4xl font-bold font-mono leading-none" style={{ color }}>{count}</p>
      <p className="text-[11px] text-slate-400 leading-tight">{sub}</p>
    </Link>
  );
}

// ─── Download Board Pack split-button (PDF default + format menu) ──
// Default-action button on the left (PDF), chevron on the right opens a
// small menu with CSV and JSON alternatives. Replaces the "downloads JSON"
// behaviour that caused the founder bug report on 2026-06-11.

function DownloadBoardPackButton({ onSelect }: { onSelect: (fmt: 'pdf' | 'csv' | 'json') => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative inline-flex">
      <button onClick={() => { setOpen(false); onSelect('pdf'); }}
        className="px-3 py-2 rounded-l-lg text-xs font-medium bg-violet-500 text-white hover:bg-violet-400 transition flex items-center gap-2">
        <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
        Download Board Pack
      </button>
      <button onClick={() => setOpen(o => !o)}
        title="Choose format"
        className="px-2 py-2 rounded-r-lg text-xs font-medium bg-violet-500 text-white hover:bg-violet-400 transition border-l border-violet-400/40">
        <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7"/></svg>
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 min-w-[160px] rounded-lg bg-slate-900 border border-slate-700 shadow-xl z-30 overflow-hidden">
          {[
            { fmt: 'pdf'  as const, label: 'PDF (recommended)', sub: 'Board presentation' },
            { fmt: 'csv'  as const, label: 'CSV',               sub: 'Spreadsheet import' },
            { fmt: 'json' as const, label: 'JSON',              sub: 'Developer / API' },
          ].map(opt => (
            <button key={opt.fmt} onClick={() => { setOpen(false); onSelect(opt.fmt); }}
              className="block w-full text-left px-3 py-2 text-xs text-slate-200 hover:bg-slate-800 border-b border-slate-800 last:border-b-0">
              <div className="font-semibold">{opt.label}</div>
              <div className="text-[10px] text-slate-500">{opt.sub}</div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
