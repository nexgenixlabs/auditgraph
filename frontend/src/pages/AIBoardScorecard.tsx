/**
 * AI Board Scorecard — executive, board-ready view of AI agent posture.
 *
 * Mounted at /board-scorecard. Pairs with /api/ai-security/board-scorecard
 * (current snapshot) and /api/ai-security/board-scorecard/history?days=180
 * (trend). Renders 5 hero KPIs mapped to NIST AI RMF + ISO 42001 dimensions,
 * a Strong / Good / Elevated / Critical distribution histogram, the 10 worst
 * agents with one-click pivot to /identities/<id>, and a single inline SVG
 * sparkline showing the 5-KPI average over time.
 *
 * No fake data: if total_agents=0, we render an empty-state explaining that
 * the scorecard populates once a discovery includes AI agent classification.
 *
 * "Download Board Pack" is stubbed for this sprint — the future hook lives in
 * utils/pdfGenerator.ts (see TODO inside handleDownload).
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import { BoardScorecard } from '../types/security_events';

// ── KPI configuration ─────────────────────────────────────────────────────

interface KpiDef {
  key:
    | 'with_owner_pct'
    | 'with_telemetry_pct'
    | 'private_network_pct'
    | 'least_privilege_pct'
    | 'policy_compliant_pct';
  label: string;
  caption: string;
}

const KPIS: KpiDef[] = [
  { key: 'with_owner_pct',       label: 'With Owner',        caption: 'NIST AI RMF · Govern 1.2' },
  { key: 'with_telemetry_pct',   label: 'With Telemetry',    caption: 'NIST AI RMF · Measure 2.1' },
  { key: 'private_network_pct',  label: 'Private Network',   caption: 'ISO 42001 · A.7.4' },
  { key: 'least_privilege_pct',  label: 'Least Privilege',   caption: 'NIST AI RMF · Manage 2.3' },
  { key: 'policy_compliant_pct', label: 'Policy Compliant',  caption: 'ISO 42001 · A.6.2' },
];

// ── Helpers ───────────────────────────────────────────────────────────────

/** Border-left accent color based on percentage threshold. */
function pctColor(pct: number): string {
  if (pct >= 80) return '#22c55e'; // green
  if (pct >= 50) return '#f59e0b'; // amber
  return '#ef4444';                 // red
}

function pctBg(pct: number): string {
  if (pct >= 80) return 'rgba(34,197,94,0.08)';
  if (pct >= 50) return 'rgba(245,158,11,0.08)';
  return 'rgba(239,68,68,0.08)';
}

function trustBadgeColor(score: number): { text: string; bg: string; border: string } {
  if (score >= 80) return { text: '#16a34a', bg: 'rgba(34,197,94,0.10)',  border: 'rgba(34,197,94,0.35)' };
  if (score >= 50) return { text: '#d97706', bg: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.35)' };
  return                  { text: '#dc2626', bg: 'rgba(239,68,68,0.10)',  border: 'rgba(239,68,68,0.35)' };
}

function fmtDate(iso?: string | null): string {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  } catch { return iso; }
}

function truncId(id: string, n = 12): string {
  if (!id) return '';
  if (id.length <= n) return id;
  return `${id.slice(0, n)}…`;
}

/** cubic-out easing — matches the RAF animation pattern used elsewhere. */
function easeOutCubic(t: number): number {
  return 1 - Math.pow(1 - t, 3);
}

// ── Component ─────────────────────────────────────────────────────────────

export default function AIBoardScorecard() {
  const navigate = useNavigate();
  const { withConnection, selectedConnectionId } = useConnection();

  const [scorecard, setScorecard]   = useState<BoardScorecard | null>(null);
  const [history,   setHistory]     = useState<BoardScorecard[]>([]);
  const [loading,   setLoading]     = useState(true);
  const [error,     setError]       = useState<string | null>(null);

  // Animated percentages for hero KPIs (RAF count-up on mount).
  const [animPct, setAnimPct] = useState<Record<KpiDef['key'], number>>({
    with_owner_pct:       0,
    with_telemetry_pct:   0,
    private_network_pct:  0,
    least_privilege_pct:  0,
    policy_compliant_pct: 0,
  });

  // ── Fetch on mount + connection change ────────────────────────────────

  useEffect(() => {
    let cancelled = false;
    const startedAt = Date.now();

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const [snapRes, histRes] = await Promise.all([
          fetch(withConnection('/api/ai-security/board-scorecard')),
          fetch(withConnection('/api/ai-security/board-scorecard/history?days=180')),
        ]);

        if (!snapRes.ok) throw new Error(`Scorecard API error: ${snapRes.status}`);
        const snapJson: BoardScorecard = await snapRes.json();

        let histJson: { history: BoardScorecard[] } = { history: [] };
        if (histRes.ok) {
          try { histJson = await histRes.json(); } catch { /* keep empty */ }
        }

        // Enforce a ~600ms minimum skeleton so the loading state never flashes.
        const elapsed = Date.now() - startedAt;
        if (elapsed < 600) {
          await new Promise(r => setTimeout(r, 600 - elapsed));
        }

        if (!cancelled) {
          setScorecard(snapJson);
          setHistory(Array.isArray(histJson.history) ? histJson.history : []);
        }
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load board scorecard');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => { cancelled = true; };
  }, [selectedConnectionId, withConnection]);

  // ── Hero KPI count-up animation (RAF, cubic-out, 600ms) ───────────────

  useEffect(() => {
    if (!scorecard) return;
    const targets: Record<KpiDef['key'], number> = {
      with_owner_pct:       scorecard.with_owner_pct       ?? 0,
      with_telemetry_pct:   scorecard.with_telemetry_pct   ?? 0,
      private_network_pct:  scorecard.private_network_pct  ?? 0,
      least_privilege_pct:  scorecard.least_privilege_pct  ?? 0,
      policy_compliant_pct: scorecard.policy_compliant_pct ?? 0,
    };
    const duration = 600;
    const start = performance.now();
    let raf = 0;

    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      const e = easeOutCubic(t);
      setAnimPct({
        with_owner_pct:       targets.with_owner_pct       * e,
        with_telemetry_pct:   targets.with_telemetry_pct   * e,
        private_network_pct:  targets.private_network_pct  * e,
        least_privilege_pct:  targets.least_privilege_pct  * e,
        policy_compliant_pct: targets.policy_compliant_pct * e,
      });
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [scorecard]);

  // ── Derived: 5-KPI average per history snapshot for the sparkline ─────

  const trendSeries = useMemo(() => {
    if (!history.length) return [] as Array<{ date: string; avg: number }>;
    return history.map(h => {
      const avg =
        ((h.with_owner_pct ?? 0) +
          (h.with_telemetry_pct ?? 0) +
          (h.private_network_pct ?? 0) +
          (h.least_privilege_pct ?? 0) +
          (h.policy_compliant_pct ?? 0)) /
        5;
      return { date: h.snapshot_date, avg };
    });
  }, [history]);

  const currentAvg = useMemo(() => {
    if (!scorecard) return 0;
    return (
      ((scorecard.with_owner_pct ?? 0) +
        (scorecard.with_telemetry_pct ?? 0) +
        (scorecard.private_network_pct ?? 0) +
        (scorecard.least_privilege_pct ?? 0) +
        (scorecard.policy_compliant_pct ?? 0)) /
      5
    );
  }, [scorecard]);

  // ── Download Board Pack handler (stub for this sprint) ────────────────

  const handleDownload = useCallback(() => {
    // TODO: wire to utils/pdfGenerator.ts — add generateBoardPack(scorecard, history)
    // that mirrors the cover / exec-summary / KPIs / worst-10 / trend layout.
    // For now, stub until the next sprint.
    alert('Board pack PDF — coming in next sprint');
  }, []);

  // ── Render ────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="p-6 max-w-[1400px] mx-auto space-y-6">
        <div className="animate-pulse">
          <div className="h-8 w-72 rounded bg-slate-200 mb-2" />
          <div className="h-4 w-[520px] rounded bg-slate-200" />
        </div>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 animate-pulse">
          {[0, 1, 2, 3, 4].map(i => (
            <div key={i} className="h-32 rounded-xl bg-slate-200" />
          ))}
        </div>
        <div className="animate-pulse h-40 rounded-xl bg-slate-200" />
        <div className="animate-pulse h-72 rounded-xl bg-slate-200" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 max-w-[1400px] mx-auto">
        <div className="rounded-xl border border-red-200 bg-red-50 p-5 text-sm text-red-700">
          {error}
        </div>
      </div>
    );
  }

  if (!scorecard || scorecard.total_agents === 0) {
    return (
      <div className="p-6 max-w-[1400px] mx-auto space-y-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-slate-900">AI Board Scorecard</h1>
            <p className="text-sm text-slate-600 mt-1 max-w-2xl">
              Board-ready view of your AI agent posture across NIST AI RMF + ISO 42001 dimensions.
            </p>
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-10 text-center">
          <p className="text-sm text-slate-700 max-w-xl mx-auto">
            No AI agents discovered yet — board scorecard will populate after the
            first discovery includes AI agent classification.
          </p>
        </div>
      </div>
    );
  }

  // Histogram bars: Strong / Good / Elevated / Critical.
  const dist = scorecard.distribution;
  const distMax = Math.max(dist.strong, dist.good, dist.elevated, dist.critical, 1);
  const distBars: Array<{ key: string; label: string; count: number; color: string }> = [
    { key: 'strong',   label: 'Strong',   count: dist.strong,   color: '#16a34a' },
    { key: 'good',     label: 'Good',     count: dist.good,     color: '#84cc16' },
    { key: 'elevated', label: 'Elevated', count: dist.elevated, color: '#f59e0b' },
    { key: 'critical', label: 'Critical', count: dist.critical, color: '#ef4444' },
  ];

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-2xl font-bold text-slate-900">AI Board Scorecard</h1>
            {scorecard.exceptions_pending > 0 && (
              <span
                className="text-[10px] font-bold uppercase px-2 py-0.5 rounded-full border"
                style={{
                  color: '#d97706',
                  backgroundColor: 'rgba(245,158,11,0.10)',
                  borderColor: 'rgba(245,158,11,0.35)',
                }}
              >
                {scorecard.exceptions_pending} Exception{scorecard.exceptions_pending === 1 ? '' : 's'} Pending
              </span>
            )}
          </div>
          <p className="text-sm text-slate-600 mt-1 max-w-2xl">
            Board-ready view of your AI agent posture across NIST AI RMF + ISO 42001 dimensions.
          </p>
          <p className="text-xs text-slate-500 mt-0.5">
            Snapshot {fmtDate(scorecard.snapshot_date)} · {scorecard.total_agents} AI agent
            {scorecard.total_agents === 1 ? '' : 's'} in scope
          </p>
        </div>
        <button
          onClick={handleDownload}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg border transition text-white hover:opacity-90"
          style={{ backgroundColor: '#24A2A1', borderColor: '#24A2A1' }}
        >
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M7 10l5 5 5-5M12 15V3" />
          </svg>
          Download Board Pack
        </button>
      </div>

      {/* Hero KPI cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {KPIS.map((kpi, idx) => {
          const target = scorecard[kpi.key] ?? 0;
          const animated = animPct[kpi.key] ?? 0;
          const color = pctColor(target);
          const bg = pctBg(target);
          return (
            <div
              key={kpi.key}
              className="rounded-xl border bg-white p-4 transition"
              style={{
                borderColor: 'rgba(15,23,42,0.10)',
                borderLeftWidth: 4,
                borderLeftColor: color,
                backgroundColor: bg,
              }}
            >
              <p
                className="text-[10px] uppercase tracking-wider font-semibold text-slate-500"
                title={kpi.caption}
              >
                {kpi.label}
              </p>
              <p
                className="text-3xl font-bold font-mono mt-1"
                style={{ color, fontFamily: "'JetBrains Mono', monospace" }}
              >
                {Math.round(animated)}%
              </p>
              {idx === 0 ? (
                <p className="text-[10px] mt-1 text-slate-500">
                  Total Agents: <span className="font-semibold text-slate-700">{scorecard.total_agents}</span>
                </p>
              ) : (
                <p className="text-[10px] mt-1 text-slate-400">{kpi.caption}</p>
              )}
            </div>
          );
        })}
      </div>

      {/* Distribution histogram + trend sparkline (side-by-side on md+) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Histogram */}
        <div className="md:col-span-2 rounded-xl border bg-white p-5" style={{ borderColor: 'rgba(15,23,42,0.10)' }}>
          <div className="flex items-center justify-between mb-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">Agent Trust Distribution</h3>
              <p className="text-[11px] text-slate-500">Strong (≥80) · Good (60–79) · Elevated (40–59) · Critical (&lt;40)</p>
            </div>
            <span className="text-[10px] font-mono text-slate-400">
              {scorecard.total_agents} agents
            </span>
          </div>
          <div className="flex items-end gap-4 h-44">
            {distBars.map(b => {
              const heightPct = (b.count / distMax) * 100;
              return (
                <div key={b.key} className="flex-1 flex flex-col items-center justify-end">
                  <span
                    className="text-xs font-mono font-semibold mb-1"
                    style={{ color: b.color }}
                  >
                    {b.count}
                  </span>
                  <div
                    className="w-full rounded-t-md transition-all"
                    style={{
                      height: `${Math.max(heightPct, 2)}%`,
                      backgroundColor: b.color,
                      minHeight: 4,
                    }}
                    title={`${b.label}: ${b.count}`}
                  />
                  <span className="text-[11px] text-slate-600 font-medium mt-1.5">{b.label}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Trend sparkline */}
        <div className="rounded-xl border bg-white p-5" style={{ borderColor: 'rgba(15,23,42,0.10)' }}>
          <div className="mb-2">
            <h3 className="text-sm font-semibold text-slate-900">Posture Trend</h3>
            <p className="text-[11px] text-slate-500">
              5-KPI average · last {trendSeries.length || 0} snapshot{trendSeries.length === 1 ? '' : 's'}
            </p>
          </div>
          <TrendSparkline data={trendSeries} currentAvg={currentAvg} />
          <p className="text-[10px] text-slate-400 mt-2">
            Now: <span className="font-mono font-semibold text-slate-700">{currentAvg.toFixed(1)}%</span>
          </p>
        </div>
      </div>

      {/* Worst-10 agents */}
      <div className="rounded-xl border bg-white" style={{ borderColor: 'rgba(15,23,42,0.10)' }}>
        <div className="px-4 py-3 border-b" style={{ borderColor: 'rgba(15,23,42,0.06)' }}>
          <h3 className="text-sm font-semibold text-slate-900">Worst 10 Agents</h3>
          <p className="text-[11px] text-slate-500">
            Lowest trust scores · click a row to investigate
          </p>
        </div>
        {scorecard.top_10_worst.length === 0 ? (
          <p className="px-4 py-8 text-center text-xs text-slate-500">
            No agents at elevated risk — nice work.
          </p>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-slate-500">
                <th className="px-4 py-2 font-semibold uppercase text-[10px]">Identity ID</th>
                <th className="px-4 py-2 font-semibold uppercase text-[10px]">Display Name</th>
                <th className="px-4 py-2 font-semibold uppercase text-[10px]">Trust Score</th>
                <th className="px-4 py-2 font-semibold uppercase text-[10px]">Top Failing Dimension</th>
              </tr>
            </thead>
            <tbody className="divide-y" style={{ borderColor: 'rgba(15,23,42,0.06)' }}>
              {scorecard.top_10_worst.map(a => {
                const badge = trustBadgeColor(a.trust_score);
                return (
                  <tr
                    key={a.identity_id}
                    onClick={() => navigate(`/identities/${a.identity_id}`)}
                    className="cursor-pointer hover:bg-slate-50 transition"
                  >
                    <td
                      className="px-4 py-2 font-mono text-[11px] text-slate-600"
                      title={a.identity_id}
                    >
                      {truncId(a.identity_id, 14)}
                    </td>
                    <td className="px-4 py-2 text-slate-800">{a.display_name || '—'}</td>
                    <td className="px-4 py-2">
                      <span
                        className="inline-block text-[11px] font-bold font-mono px-2 py-0.5 rounded border"
                        style={{
                          color: badge.text,
                          backgroundColor: badge.bg,
                          borderColor: badge.border,
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {a.trust_score}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-slate-700">{a.top_dimension_fail || '—'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Footer note */}
      <p className="text-[10px] text-slate-400 text-center">
        Architecture-derived signals · No telemetry required · NIST AI RMF + ISO 42001
      </p>
    </div>
  );
}

// ── Inline SVG sparkline (no chart library) ─────────────────────────────

interface TrendSparklineProps {
  data: Array<{ date: string; avg: number }>;
  currentAvg: number;
}

function TrendSparkline({ data, currentAvg }: TrendSparklineProps) {
  // Fall back gracefully when we don't have enough points to draw a line.
  if (data.length < 2) {
    return (
      <div className="h-20 flex items-center justify-center text-[11px] text-slate-400">
        Not enough history yet — trend appears after two snapshots.
      </div>
    );
  }

  const W = 280;
  const H = 80;
  const padX = 4;
  const padY = 6;

  const xs = data.map((_, i) => padX + (i * (W - 2 * padX)) / (data.length - 1));
  // Lock the y-axis to 0-100 so the line is comparable across renders.
  const ys = data.map(d => H - padY - (Math.max(0, Math.min(100, d.avg)) / 100) * (H - 2 * padY));
  const pts = xs.map((x, i) => `${x.toFixed(1)},${ys[i].toFixed(1)}`).join(' ');

  // Area fill: same line, closed off at the bottom.
  const areaPath =
    `M ${xs[0].toFixed(1)},${(H - padY).toFixed(1)} ` +
    xs.map((x, i) => `L ${x.toFixed(1)},${ys[i].toFixed(1)}`).join(' ') +
    ` L ${xs[xs.length - 1].toFixed(1)},${(H - padY).toFixed(1)} Z`;

  const lineColor = pctColor(currentAvg);
  const fillColor = pctColor(currentAvg);

  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="block">
      {/* 50% gridline */}
      <line
        x1={padX}
        x2={W - padX}
        y1={H - padY - 0.5 * (H - 2 * padY)}
        y2={H - padY - 0.5 * (H - 2 * padY)}
        stroke="rgba(15,23,42,0.06)"
        strokeDasharray="2 2"
      />
      <path d={areaPath} fill={fillColor} opacity={0.12} />
      <polyline points={pts} fill="none" stroke={lineColor} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
      {/* End-point marker */}
      <circle cx={xs[xs.length - 1]} cy={ys[ys.length - 1]} r={3} fill={lineColor} />
    </svg>
  );
}
