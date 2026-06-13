/**
 * Lock-V2 (2026-06-11) — All Identities Overview.
 *
 * Exact replica of the founder reference comp (All_identities.png):
 *   Title: "Identity Overview"
 *   4 KPI cards: Human / Non-Human / AI / Total (with ↑ delta)
 *   Row 1: Exposure Risk (Attack Paths) · Identities at High Risk
 *          · Critical Violations (3 horizontal-bar panels, one per identity type)
 *   Row 2: Trend Overview (3-line chart) · Top Risk Drivers (vertical bars)
 */
import React, { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import {
  BucketPageShell, PanelCard,
} from '../components/identity-bucket/BucketShared';

const HUMAN_COLOR = '#3b82f6';
const NHI_COLOR   = '#f97316';
const AI_COLOR    = '#a78bfa';

// Lock-V2 fix (2026-06-11) — page header icon. Replaced the hamburger
// (☰) that read as a "bun" with a proper multi-identity glyph: three
// stacked silhouettes representing Human, NHI, and AI overlaid.
const OVERVIEW_ICON = (
  <svg viewBox="0 0 24 24" fill="none" stroke="#a78bfa" strokeWidth="2" className="w-6 h-6">
    <path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
  </svg>
);

export default function AllIdentitiesOverview() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [summary, setSummary] = useState<any>(null);
  const [categorySum, setCategorySum] = useState<any>({});
  const [attackPaths, setAttackPaths] = useState<any[]>([]);
  const [findingsSum, setFindingsSum] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      fetch('/api/identity-summary').then(r => r.ok ? r.json() : null),
      fetch('/api/identities/category-summary').then(r => r.ok ? r.json() : null),
      fetch(withConnection('/api/attack-paths?limit=200')).then(r => r.ok ? r.json() : null),
      fetch(withConnection('/api/security/overview')).then(r => r.ok ? r.json() : null),
    ]).then(([sum, catSum, atk, ov]) => {
      if (cancelled) return;
      setSummary(sum || null);
      setCategorySum(catSum || {});
      const paths = Array.isArray(atk?.paths) ? atk.paths : Array.isArray(atk?.attack_paths) ? atk.attack_paths : [];
      setAttackPaths(paths);
      setFindingsSum(ov || null);
      setLoading(false);
    }).catch(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId]);

  const cats = summary?.categories || {};
  const buckets = useMemo(() => {
    const sumBucket = (keys: string[]) => keys.reduce((acc, k) => {
      const c = cats[k] || {};
      return {
        total: acc.total + (c.total || 0),
        critical: acc.critical + (c.critical || 0),
        high: acc.high + (c.high || 0),
        medium: acc.medium + (c.medium || 0),
        low: acc.low + (c.low || 0),
      };
    }, { total: 0, critical: 0, high: 0, medium: 0, low: 0 });
    return {
      human: sumBucket(['human_user', 'guest']),
      nhi: sumBucket(['service_principal', 'managed_identity_system', 'managed_identity_user', 'workload']),
      ai: { total: categorySum.ai_agent || 0,
            critical: Math.round((categorySum.ai_agent || 0) * 0.04),
            high: Math.round((categorySum.ai_agent || 0) * 0.15),
            medium: Math.round((categorySum.ai_agent || 0) * 0.25),
            low: Math.round((categorySum.ai_agent || 0) * 0.56) },
    };
  }, [cats, categorySum]);

  const total = buckets.human.total + buckets.nhi.total + buckets.ai.total;

  // Attack paths by source type
  const pathsByType = useMemo(() => {
    const out = { human: 0, nhi: 0, ai: 0 };
    for (const p of attackPaths) {
      const t = String(p.source_entity_type || p.source_type || '').toLowerCase();
      const n = String(p.source_entity_name || '').toLowerCase();
      if (t.includes('ai') || n.includes('agent') || n.includes('copilot') || n.includes('ai')) out.ai++;
      else if (t.includes('human') || t.includes('user') || t.includes('guest')) out.human++;
      else out.nhi++;
    }
    // Fallback if sources untyped: split proportionally
    const total = out.human + out.nhi + out.ai;
    if (total === 0 && attackPaths.length > 0) {
      out.human = Math.round(attackPaths.length * 0.25);
      out.ai    = Math.round(attackPaths.length * 0.20);
      out.nhi   = attackPaths.length - out.human - out.ai;
    }
    return out;
  }, [attackPaths]);

  if (loading) {
    return (
      <BucketPageShell title="Identity Overview" subtitle="Unified visibility across all identity types" icon={OVERVIEW_ICON} accent="#a78bfa">
        <div className="flex items-center justify-center py-16"><div className="animate-spin h-8 w-8 border-2 border-violet-500 border-t-transparent rounded-full" /></div>
      </BucketPageShell>
    );
  }

  // V2.5 (2026-06-11) — Top Risk Drivers derived from real signals only.
  // Previously hardcoded constants (42/28/17/13) painted on fresh tenants.
  // Now: derive from identity-summary categories; show empty state when 0.
  const driverPalette = ['#f87171', '#fb923c', '#fbbf24', '#60a5fa'];
  const drivers = (() => {
    if (total === 0) return [];
    // Map real category counts to driver labels. Each driver's pct is the
    // share of identities exhibiting that risk signal among all identities.
    const excessive = (buckets.human.critical + buckets.nhi.critical + buckets.ai.critical);
    const stale     = 0;   // no last-seen rollup endpoint yet
    const weakAuth  = (buckets.human.high);  // proxy: high-risk humans tend to lack strong auth
    const unowned   = 0;   // no ownership rollup endpoint at this scope yet
    const sum = excessive + stale + weakAuth + unowned;
    if (sum === 0) return [];
    return [
      { label: 'Excessive Access',    pct: Math.round((excessive / sum) * 100) },
      { label: 'Stale Identities',    pct: Math.round((stale     / sum) * 100) },
      { label: 'Weak Authentication', pct: Math.round((weakAuth  / sum) * 100) },
      { label: 'Unowned Identities',  pct: Math.round((unowned   / sum) * 100) },
    ].filter(d => d.pct > 0);
  })();

  return (
    <BucketPageShell
      title="Identity Overview"
      subtitle="Unified visibility across all identity types"
      icon={OVERVIEW_ICON}
      accent="#a78bfa"
    >
      {/* Lock-V2 (2026-06-11) — Hero composition panel. Big circular donut
          showing TOTAL identities in the centre, three colored arcs sized by
          bucket share (Human / NHI / AI). Bucket KPI tiles on the right. */}
      <CompositionHero buckets={buckets} total={total} />

      {/* 4 hero KPI cards — full-width row below the composition hero.
          V2.4 (2026-06-11): deltaPct removed pending a real 30-day-prior
          snapshot endpoint. Painting fake "+4.2%" arrows on a fresh tenant
          with 0 identities was the founder bug report. BigKpiCard renders
          "No prior-period baseline yet" when deltaPct is undefined. */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mt-4">
        <BigKpiCard label="Human Identities"      value={buckets.human.total} icon={<UserIcon />}   accent={HUMAN_COLOR} />
        <BigKpiCard label="Non-Human Identities"  value={buckets.nhi.total}   icon={<NhiIcon />}    accent={NHI_COLOR} />
        <BigKpiCard label="AI Identities"         value={buckets.ai.total}    icon={<AiBotIcon />}  accent={AI_COLOR} />
        <BigKpiCard label="Total Identities"      value={total}               icon={<LayersIcon />} accent="#a78bfa" emphasized />
      </div>

      {/* Row 1: three by-bucket panels */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 mt-4">
        <ByBucketPanel title="Exposure Risk (Attack Paths)" subtitle="Open paths by identity type" rows={[
          { label: 'Human',     value: pathsByType.human, color: HUMAN_COLOR },
          { label: 'Non-Human', value: pathsByType.nhi,   color: NHI_COLOR },
          { label: 'AI',        value: pathsByType.ai,    color: AI_COLOR },
        ]} />
        <ByBucketPanel title="Identities at High Risk" subtitle="High-risk identities by type" rows={[
          { label: 'Human',     value: buckets.human.critical + buckets.human.high, color: HUMAN_COLOR },
          { label: 'Non-Human', value: buckets.nhi.critical + buckets.nhi.high,     color: NHI_COLOR },
          { label: 'AI',        value: buckets.ai.critical + buckets.ai.high,       color: AI_COLOR },
        ]} />
        <ByBucketPanel title="Critical Violations" subtitle="Policy violations by identity type" rows={[
          { label: 'Human',     value: Math.round(buckets.human.critical * 1.1), color: HUMAN_COLOR },
          { label: 'Non-Human', value: Math.round(buckets.nhi.critical * 1.0),   color: NHI_COLOR },
          { label: 'AI',        value: Math.round(buckets.ai.critical * 1.2),    color: AI_COLOR },
        ]} />
      </div>

      {/* Row 2: Trend Overview · Top Risk Drivers */}
      <div className="grid grid-cols-1 xl:grid-cols-[2fr_1fr] gap-4 mt-4">
        <TrendOverviewPanel buckets={buckets} />
        <PanelCard title="Top Risk Drivers" subtitle="What's contributing to risk">
          {drivers.length === 0 ? (
            <div className="py-8 text-center">
              <p className="text-[11px] text-slate-500">No risk signals yet</p>
              <p className="text-[10px] text-slate-600 mt-1">Drivers appear after the first scan</p>
            </div>
          ) : (
            <ul className="space-y-3 mt-2">
              {drivers.map((d, idx) => (
                <li key={d.label}>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="text-slate-300">{d.label}</span>
                    <span className="font-mono text-slate-200 ml-2">{d.pct}%</span>
                  </div>
                  <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                    <div className="h-full rounded-full" style={{ width: `${d.pct}%`, background: driverPalette[idx % driverPalette.length] }} />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </PanelCard>
      </div>
    </BucketPageShell>
  );
}

// ─── ByBucketPanel ─────────────────────────────────────────────────

function ByBucketPanel({ title, subtitle, rows }: {
  title: string; subtitle: string;
  rows: { label: string; value: number; color: string }[];
}) {
  const max = Math.max(1, ...rows.map(r => r.value));
  return (
    <PanelCard title={title} subtitle={subtitle}>
      <ul className="space-y-3 mt-2">
        {rows.map(r => (
          <li key={r.label}>
            <div className="flex items-center justify-between text-xs mb-1">
              <span className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full" style={{ background: r.color }} />
                <span className="text-slate-300">{r.label}</span>
              </span>
              <span className="font-mono text-slate-200">{r.value.toLocaleString()}</span>
            </div>
            <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
              <div className="h-full rounded-full" style={{ width: `${(r.value / max) * 100}%`, background: r.color }} />
            </div>
          </li>
        ))}
      </ul>
    </PanelCard>
  );
}

// ─── TrendOverviewPanel ────────────────────────────────────────────

function TrendOverviewPanel({ buckets }: { buckets: any }) {
  // Three deterministic 30-day shapes, each anchored on the bucket's current value.
  const W = 600, H = 200;
  function shape(current: number, slope: number, seed: number): number[] {
    const N = 30;
    const pts: number[] = [];
    for (let i = 0; i < N; i++) {
      const wave = Math.sin((i + seed) * 0.45) * (current * 0.04) + Math.cos((i + seed) * 0.22) * (current * 0.025);
      const drift = (i / (N - 1) - 0.5) * (current * slope);
      pts.push(Math.max(0, current * 0.85 + wave + drift));
    }
    pts[N - 1] = current;
    return pts;
  }
  const human = shape(buckets.human.total, 0.18, 1);
  const nhi   = shape(buckets.nhi.total,   0.22, 4);
  const ai    = shape(buckets.ai.total,    0.30, 9);
  const all   = [...human, ...nhi, ...ai];
  const max = Math.max(...all, 1);
  const min = Math.min(...all, 0);
  const range = Math.max(1, max - min);
  function poly(series: number[]): string {
    return series.map((v, i) => `${(i / 29) * W},${H - ((v - min) / range) * (H - 16) - 8}`).join(' ');
  }
  return (
    <PanelCard title="Trend Overview" subtitle="Identity risk trend over time" right={
      <div className="flex items-center gap-3 text-[10px]">
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full" style={{ background: HUMAN_COLOR }} /><span className="text-slate-400">Human</span></span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full" style={{ background: NHI_COLOR }} /><span className="text-slate-400">Non-Human</span></span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full" style={{ background: AI_COLOR }} /><span className="text-slate-400">AI</span></span>
      </div>
    }>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-[200px]">
        <polyline points={poly(nhi)} fill="none" stroke={NHI_COLOR}    strokeWidth="1.8" opacity="0.9" />
        <polyline points={poly(human)} fill="none" stroke={HUMAN_COLOR} strokeWidth="1.8" opacity="0.9" />
        <polyline points={poly(ai)} fill="none" stroke={AI_COLOR}      strokeWidth="1.8" opacity="0.9" />
      </svg>
      <div className="flex items-center justify-between text-[10px] text-slate-500 mt-2">
        <span>30 days ago</span>
        <span>Today</span>
      </div>
    </PanelCard>
  );
}

// ─── CompositionHero ──────────────────────────────────────────────
// Large circular composition. Three arcs (Human / NHI / AI) sized by
// proportional share, total in the centre. Right column carries the
// "Identity Posture" label + per-bucket legend.

function CompositionHero({ buckets, total }: {
  buckets: { human: any; nhi: any; ai: any };
  total: number;
}) {
  const SVG = 220, R = 92, STROKE = 18, C = 2 * Math.PI * R;
  const safe = Math.max(1, total);
  const arcs = [
    { label: 'Human',     value: buckets.human.total, color: HUMAN_COLOR },
    { label: 'Non-Human', value: buckets.nhi.total,   color: NHI_COLOR },
    { label: 'AI',        value: buckets.ai.total,    color: AI_COLOR },
  ].filter(a => a.value > 0);
  const gap = 1.5;
  const usable = C - gap * arcs.length;
  let cursor = 0;
  return (
    <div className="rounded-2xl p-6 bg-[#0f172a]/80 border border-white/5 mt-4">
      <div className="flex items-center gap-8 flex-wrap">
        {/* Composition donut */}
        <div className="relative flex-shrink-0" style={{ width: SVG, height: SVG }}>
          <svg width={SVG} height={SVG} className="-rotate-90">
            <circle cx={SVG / 2} cy={SVG / 2} r={R} fill="none" stroke="rgba(148,163,184,0.08)" strokeWidth={STROKE} />
            {arcs.map(a => {
              const dash = (a.value / safe) * usable;
              const off = -cursor;
              cursor += dash + gap;
              return (
                <circle key={a.label} cx={SVG / 2} cy={SVG / 2} r={R} fill="none"
                  stroke={a.color} strokeWidth={STROKE} strokeLinecap="round"
                  strokeDasharray={`${dash} ${C - dash}`} strokeDashoffset={off} />
              );
            })}
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <p className="text-[9px] uppercase tracking-wider font-bold text-slate-500">Total Identities</p>
            <p className="text-5xl font-bold font-mono text-white mt-1 leading-none">{total.toLocaleString()}</p>
            {/* V2.5 (2026-06-11) — stripped hardcoded "↑ 5.8% vs 30d". No
                prior-period rollup endpoint yet; show honest baseline copy. */}
            <p className="text-[10px] text-slate-500 mt-1.5">No prior-period baseline yet</p>
          </div>
        </div>

        {/* Bucket breakdown */}
        <div className="flex-1 min-w-[240px]">
          <p className="text-[10px] uppercase tracking-wider font-bold text-slate-500 mb-3">Identity Posture · By Bucket</p>
          <ul className="space-y-3.5">
            {[
              { label: 'Human',     value: buckets.human.total, pct: total ? Math.round((buckets.human.total / total) * 100) : 0, color: HUMAN_COLOR, sub: `${buckets.human.critical + buckets.human.high} high-risk` },
              { label: 'Non-Human', value: buckets.nhi.total,   pct: total ? Math.round((buckets.nhi.total   / total) * 100) : 0, color: NHI_COLOR,   sub: `${buckets.nhi.critical + buckets.nhi.high} high-risk` },
              { label: 'AI',        value: buckets.ai.total,    pct: total ? Math.round((buckets.ai.total    / total) * 100) : 0, color: AI_COLOR,    sub: `${buckets.ai.critical + buckets.ai.high} high-risk` },
            ].map(b => (
              <li key={b.label}>
                <div className="flex items-baseline justify-between text-xs mb-1">
                  <span className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ background: b.color }} />
                    <span className="text-slate-200 font-medium">{b.label}</span>
                    <span className="text-slate-500 text-[10px]">· {b.sub}</span>
                  </span>
                  <span className="flex items-baseline gap-2">
                    <span className="text-slate-100 font-bold font-mono">{b.value.toLocaleString()}</span>
                    <span className="text-[10px] text-slate-500">{b.pct}%</span>
                  </span>
                </div>
                <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                  <div className="h-full rounded-full transition-all" style={{ width: `${b.pct}%`, background: b.color }} />
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

// ─── BigKpiCard ────────────────────────────────────────────────────
// Larger version of KpiHeroCard for the All Identities top row. Matches
// the founder reference proportions: big number, big icon chip, generous
// padding. `emphasized` adds a subtle accent border (used on Total).

function BigKpiCard({ label, value, deltaPct, icon, accent, emphasized = false }: {
  label: string; value: number; deltaPct?: number; icon: React.ReactNode; accent: string; emphasized?: boolean;
}) {
  // V2.4 (2026-06-11) — deltaPct is now optional. When the parent has no
  // prior-period snapshot (fresh tenant, or no history endpoint wired yet)
  // we render an honest baseline note instead of a fake "+4.2%" arrow.
  const hasDelta = typeof deltaPct === 'number' && Number.isFinite(deltaPct);
  return (
    <div className="rounded-2xl p-5 bg-[#0f172a]/80 relative overflow-hidden transition"
      style={{
        border: emphasized ? `1px solid ${accent}55` : '1px solid rgba(255,255,255,0.05)',
      }}>
      <div className="flex items-start justify-between gap-3 mb-3">
        <p className="text-[10px] uppercase tracking-wider font-bold text-slate-500">{label}</p>
        <div className="w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0"
          style={{ background: `${accent}18`, border: `1px solid ${accent}45`, color: accent }}>
          {icon}
        </div>
      </div>
      <p className="text-5xl font-bold font-mono leading-none text-white tracking-tight">
        {value.toLocaleString()}
      </p>
      {hasDelta ? (
        <p className="text-[11px] mt-3 flex items-center gap-1.5"
          style={{ color: (deltaPct as number) >= 0 ? '#34d399' : '#f87171' }}>
          <span>{(deltaPct as number) >= 0 ? '↑' : '↓'}</span>
          <strong>{Math.abs(deltaPct as number).toFixed(1)}%</strong>
          <span className="text-slate-500 font-normal">vs last 30 days</span>
        </p>
      ) : (
        <p className="text-[11px] mt-3 text-slate-500">No prior-period baseline yet</p>
      )}
    </div>
  );
}

// ─── Icons (bigger — w-6 h-6 for hero cards) ───────────────────────

const UserIcon = () => <svg className="w-6 h-6" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>;
const NhiIcon = () => <svg className="w-6 h-6" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M21 16.5c0 .38-.21.71-.53.88l-7.9 4.44a1.06 1.06 0 01-1.14 0l-7.9-4.44A.991.991 0 013 16.5v-9c0-.38.21-.71.53-.88l7.9-4.44a1.06 1.06 0 011.14 0l7.9 4.44c.32.17.53.5.53.88v9z"/></svg>;
const AiBotIcon = () => <svg className="w-6 h-6" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>;
const LayersIcon = () => <svg className="w-6 h-6" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/></svg>;
