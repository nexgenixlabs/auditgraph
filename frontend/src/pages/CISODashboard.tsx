/**
 * AuditGraph — CISO Executive Posture Dashboard
 *
 * Layout matches the ciso-dashboard.html artifact:
 *   Page Header → Hero Banner → Composition Bar → 5 Metric Cards →
 *   Content Grid (Findings Table + Right Column) → Remediation Queue
 */
import React, { useState, useEffect, useMemo } from 'react';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';
import { buildCISOViewModel, buildEmptyCISOViewModel, fmtPct, type CISOViewModel } from '../utils/cisoViewModel';
import { DN } from '../components/dashboard/ciso-shared';
import { IdentityDrawerProvider } from '../contexts/IdentityDrawerContext';
import { IdentityContextDrawer } from '../components/dashboard/IdentityContextDrawer';

// ─── Data Hook ───────────────────────────────────────────────

function useCISOViewModel(): { vm: CISOViewModel; loading: boolean } {
  const { withConnection, selectedConnectionId } = useConnection();
  const { activeOrgId } = useAuth();
  const [vm, setVm] = useState<CISOViewModel>(buildEmptyCISOViewModel);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        const [summaryRes, attackRes] = await Promise.all([
          fetch(withConnection('/api/risk/summary/full')).catch(() => null),
          fetch(withConnection('/api/overview/attack-surface-score')).catch(() => null),
        ]);
        const riskData = summaryRes?.ok ? await summaryRes.json() : null;
        const attackData = attackRes?.ok ? await attackRes.json() : null;
        if (!cancelled) setVm(buildCISOViewModel(riskData, attackData));
      } catch {
        if (!cancelled) setVm(buildEmptyCISOViewModel());
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId, activeOrgId]);

  return { vm, loading };
}

// ─── Color Maps ──────────────────────────────────────────────

const STATUS_DOT: Record<string, string> = {
  critical: '#e8465a', high: '#FF7216', moderate: '#f59e0b', low: '#22c55e', no_data: '#4a6080',
};
const STATUS_TEXT_CLS: Record<string, string> = {
  critical: 'text-[#e8465a]', high: 'text-[#FF7216]', moderate: 'text-[#f59e0b]', low: 'text-[#22c55e]', no_data: 'text-[#4a6080]',
};
const STATUS_LABEL: Record<string, string> = {
  critical: 'CRITICAL RISK', high: 'HIGH RISK', moderate: 'MODERATE RISK', low: 'LOW RISK', no_data: 'NO DATA',
};

const EXPOSURE_TAG_CLS: Record<string, string> = {
  critical: 'bg-[rgba(232,70,90,0.15)] text-[#e8465a]',
  high: 'bg-[rgba(255,114,22,0.15)] text-[#FF7216]',
  moderate: 'bg-[rgba(245,158,11,0.15)] text-[#f59e0b]',
  low: 'bg-[rgba(34,197,94,0.15)] text-[#22c55e]',
};

const VERDICT_CLS: Record<string, string> = {
  red: 'bg-[rgba(232,70,90,0.15)] text-[#e8465a]',
  orange: 'bg-[rgba(255,114,22,0.15)] text-[#FF7216]',
  amber: 'bg-[rgba(245,158,11,0.15)] text-[#f59e0b]',
  purple: 'bg-[rgba(120,100,200,0.15)] text-[#a78bfa]',
  teal: 'bg-[rgba(36,162,161,0.12)] text-[#24A2A1]',
  green: 'bg-[rgba(34,197,94,0.12)] text-[#22c55e]',
};

const TAG_CLS: Record<string, string> = {
  red: 'bg-[rgba(232,70,90,0.15)] text-[#e8465a]',
  orange: 'bg-[rgba(255,114,22,0.15)] text-[#FF7216]',
  green: 'bg-[rgba(34,197,94,0.15)] text-[#22c55e]',
  teal: 'bg-[rgba(36,162,161,0.15)] text-[#24A2A1]',
};

const RISK_BAR_COLOR: Record<string, string> = {
  critical: '#e8465a', high: '#FF7216', medium: '#f59e0b', low: '#22c55e',
};

const CONFIDENCE_CLS: Record<string, string> = {
  high: 'text-[#24A2A1]', medium: 'text-[#f59e0b]', low: 'text-[#4a6080]',
};

const BLAST_SEVERITY_CLS: Record<string, string> = {
  critical: 'bg-[rgba(232,70,90,0.15)] text-[#e8465a]',
  high: 'bg-[rgba(232,70,90,0.15)] text-[#e8465a]',
  medium: 'bg-[rgba(245,158,11,0.12)] text-[#f59e0b]',
  low: 'bg-[rgba(36,162,161,0.12)] text-[#24A2A1]',
};

// ─── Helpers ─────────────────────────────────────────────────

function splitActionVerb(text: string): { verb: string; rest: string } {
  const match = text.match(/^(\S+)\s(.+)$/);
  if (!match) return { verb: text.toUpperCase(), rest: '' };
  return { verb: match[1].toUpperCase(), rest: match[2] };
}

function buildConicGradient(cats: CISOViewModel['identity_categories']): string {
  const total = cats.reduce((s, c) => s + c.count, 0);
  if (total === 0) return '#1c2d4a';
  let cumDeg = 0;
  const stops = cats.map(c => {
    const start = cumDeg;
    cumDeg += (c.count / total) * 360;
    return `${c.chart_color} ${start}deg ${cumDeg}deg`;
  });
  return `conic-gradient(${stops.join(', ')})`;
}

// ─── Component ───────────────────────────────────────────────

export default function CISODashboard() {
  const { vm, loading } = useCISOViewModel();

  const cats = vm.identity_categories;
  const total = vm.total_identities;
  const donutCats = useMemo(() => {
    const human = cats.find(c => c.label === 'Human Identities');
    const guest = cats.find(c => c.label === 'Guest Users');
    const nhiLabels = new Set(['Non-Human / SPNs', 'System MSIs', 'User-Assigned MSIs']);
    const nhiItems = cats.filter(c => nhiLabels.has(c.label));
    const nhiCount = nhiItems.reduce((s, c) => s + c.count, 0);
    const result: typeof cats = [];
    if (human) result.push(human);
    if (nhiCount > 0) {
      const nhiPct = total > 0 ? Math.round((nhiCount / total) * 1000) / 10 : 0;
      result.push({
        label: 'Non-Human Identities',
        count: nhiCount,
        pct: nhiPct,
        issues: [`${nhiCount} non-human identities`],
        tag: nhiItems[0]?.tag || { text: 'Tracked', variant: 'teal' },
        accent: '#24A2A1',
        chart_color: '#24A2A1',
        nav: '/identities?workload=true',
      });
    }
    if (guest) result.push(guest);
    return result;
  }, [cats, total]);

  if (loading) {
    return (
      <IdentityDrawerProvider>
        <div className="min-h-[calc(100vh-56px)] bg-[#0d1829] rounded-tl-card flex items-center justify-center">
          <div className="flex items-center gap-3">
            <div className="w-5 h-5 border-2 border-[#24A2A1] border-t-transparent rounded-full animate-spin" />
            <span className="text-xs text-[#4a6080] tracking-wide">Loading executive briefing…</span>
          </div>
        </div>
        <IdentityContextDrawer />
      </IdentityDrawerProvider>
    );
  }

  const hasData = vm.data_origin !== 'no_data' || vm.monitored.identities > 0;
  const dist = vm.snapshot.risk_distribution;
  const agirsScore = vm.agirs_display.score;

  return (
    <IdentityDrawerProvider>
      <div className="min-h-[calc(100vh-56px)] bg-[#0d1829] rounded-tl-card overflow-auto">

        {/* ── Empty State ── */}
        {!hasData && (
          <div className="max-w-[700px] mx-auto px-8 py-20">
            <div className="bg-[#111f35] border border-[rgba(36,162,161,0.15)] rounded-[14px] px-8 py-20 text-center">
              <div className="w-14 h-14 mx-auto mb-5 rounded-full bg-[#162540] flex items-center justify-center">
                <svg className="w-7 h-7 text-[#4a6080]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold text-[#e8eef8] mb-2">No identities discovered yet</h3>
              <p className="text-sm text-[#4a6080] max-w-md mx-auto mb-8 leading-relaxed">
                Connect your Azure tenant and run discovery to populate this view.
              </p>
              <DN navigateTo="/settings">
                <span className="inline-flex items-center px-5 py-2.5 rounded-lg bg-[#24A2A1] text-white text-sm font-semibold cursor-pointer hover:brightness-110 transition">
                  Configure Connection
                </span>
              </DN>
            </div>
          </div>
        )}

        {hasData && (
          <div className="p-6 flex flex-col gap-5">

            {/* ━━━ 1. PAGE HEADER ━━━ */}
            <header className="flex items-start justify-between">
              <div>
                <h1 className="text-[19px] font-semibold text-[#e8eef8]" style={{ letterSpacing: '-0.4px' }}>
                  Executive Posture
                </h1>
                <p className="text-xs text-[#4a6080] mt-1">
                  Identity attack surface · Last scan {vm.last_updated} · {vm.monitored.subscriptions} subscription{vm.monitored.subscriptions !== 1 ? 's' : ''} monitored
                </p>
              </div>
              <div className="flex gap-2 flex-shrink-0">
                <button className="px-3.5 py-[7px] rounded-lg text-xs font-medium text-[#8fa3bf] bg-[#162540] border border-[rgba(36,162,161,0.15)] flex items-center gap-1.5 hover:border-[rgba(36,162,161,0.35)] transition">
                  ⬇ Export CISO Report
                </button>
                <button className="px-3.5 py-[7px] rounded-lg text-xs font-medium text-[#8fa3bf] bg-[#162540] border border-[rgba(36,162,161,0.15)] flex items-center gap-1.5 hover:border-[rgba(36,162,161,0.35)] transition">
                  ⟳ Rescan
                </button>
                <DN navigateTo="/remediation">
                  <button className="px-3.5 py-[7px] rounded-lg text-xs font-medium text-white bg-[#24A2A1] border border-transparent flex items-center gap-1.5 cursor-pointer">
                    + Remediation
                  </button>
                </DN>
              </div>
            </header>

            {/* ━━━ 2. RISK HERO BANNER ━━━ */}
            <section className="relative bg-[#111f35] border border-[rgba(36,162,161,0.15)] rounded-[14px] px-6 py-5 overflow-hidden">
              {/* Top gradient accent */}
              <div className="absolute top-0 inset-x-0 h-0.5 bg-gradient-to-r from-[#24A2A1] to-[#1e3f8a]" />

              <div className="grid items-center gap-6" style={{ gridTemplateColumns: '1fr 1fr 1fr auto' }}>

                {/* Block 1: Overall Posture */}
                <div>
                  <div className="text-[10px] font-medium uppercase tracking-[1.2px] text-[#4a6080] mb-2">Overall Posture</div>
                  <div className="flex items-center gap-2.5">
                    {/* Pulse dot */}
                    <span className="relative flex h-2.5 w-2.5 flex-shrink-0">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75" style={{ backgroundColor: STATUS_DOT[vm.status] || '#4a6080' }} />
                      <span className="relative inline-flex rounded-full h-2.5 w-2.5" style={{ backgroundColor: STATUS_DOT[vm.status] || '#4a6080' }} />
                    </span>
                    <span className={`text-[26px] font-semibold leading-none ${STATUS_TEXT_CLS[vm.status] || 'text-[#4a6080]'}`} style={{ letterSpacing: '-1px' }}>
                      {STATUS_LABEL[vm.status] || 'UNKNOWN'}
                    </span>
                  </div>
                  <p className="text-[11.5px] text-[#8fa3bf] leading-relaxed mt-2">
                    {vm.status_reason}
                  </p>
                </div>

                {/* Block 2: Risk Exposure Rate */}
                <div className="border-l border-[rgba(36,162,161,0.15)] pl-6">
                  <div className="text-[10px] font-medium uppercase tracking-[1.2px] text-[#4a6080] mb-2">Risk Exposure Rate</div>
                  <DN navigateTo={vm.risk_exposure.nav}>
                    <div className="flex items-baseline gap-0.5">
                      <span className="text-[28px] font-semibold text-[#e8eef8] leading-none" style={{ letterSpacing: '-1px' }}>
                        {vm.risk_exposure.pct > 0 ? vm.risk_exposure.pct.toFixed(1) : '0'}
                      </span>
                      <span className="text-sm text-[#4a6080]">%</span>
                    </div>
                  </DN>
                  <DN navigateTo={vm.total_identities_nav}>
                    <div className="text-[11px] text-[#4a6080] mt-1.5">of {total.toLocaleString()} total identities</div>
                  </DN>
                  <span className={`inline-block mt-2 text-[10px] font-medium px-2 py-0.5 rounded-full ${EXPOSURE_TAG_CLS[vm.risk_exposure.level] || EXPOSURE_TAG_CLS.low}`}>
                    {vm.risk_exposure.level === 'low' ? '↓ Within threshold' : vm.risk_exposure.level === 'moderate' ? '→ Approaching threshold' : '↑ Above threshold'}
                  </span>
                </div>

                {/* Block 3: Assessment Confidence */}
                <div className="border-l border-[rgba(36,162,161,0.15)] pl-6">
                  <div className="text-[10px] font-medium uppercase tracking-[1.2px] text-[#4a6080] mb-2">Assessment Confidence</div>
                  <div className={`text-[28px] font-semibold leading-none ${CONFIDENCE_CLS[vm.data_confidence] || 'text-[#4a6080]'}`} style={{ letterSpacing: '-1px' }}>
                    {vm.data_confidence.charAt(0).toUpperCase() + vm.data_confidence.slice(1)}
                  </div>
                  <div className="text-[11px] text-[#4a6080] mt-1.5">Static lineage · No log dependency</div>
                  <span className="inline-block mt-2 text-[10px] font-medium px-2 py-0.5 rounded-full bg-[rgba(36,162,161,0.15)] text-[#24A2A1]">
                    Architecture-derived
                  </span>
                </div>

                {/* Block 4: AGIRS Badge */}
                {agirsScore != null && (
                  <DN navigateTo={vm.agirs_display.nav}>
                    <div className="min-w-[120px] bg-[rgba(36,162,161,0.1)] border border-[rgba(36,162,161,0.35)] rounded-[10px] px-5 py-3 text-center">
                      <div className="font-mono text-[32px] font-medium text-[#24A2A1] leading-tight" style={{ letterSpacing: '-1px' }}>
                        {agirsScore.toFixed(agirsScore % 1 === 0 ? 0 : 1)}
                      </div>
                      <div className="text-[9px] font-medium uppercase tracking-[1.5px] text-[#1a7a79] mt-1">AGIRS Score</div>
                      <div className="text-[9px] font-mono text-[#4a6080] mt-1.5 leading-snug">
                        0.40×HIRI + 0.40×NHIRI<br />+ 0.20×GEI
                      </div>
                    </div>
                  </DN>
                )}
              </div>
            </section>

            {/* ━━━ 3. RISK COMPOSITION BAR ━━━ */}
            {dist.length > 0 && (
              <section className="bg-[#111f35] border border-[rgba(36,162,161,0.15)] rounded-xl px-5 py-4">
                <div className="flex justify-between items-center mb-3">
                  <span className="text-[10px] font-medium uppercase tracking-[1.2px] text-[#4a6080]">
                    Risk Composition · {total.toLocaleString()} Identities
                  </span>
                  <span className="text-[11px] font-mono text-[#4a6080]">
                    {dist.map(d => `${d.level.toUpperCase()} ${d.count}`).join(' · ')}
                  </span>
                </div>
                {/* Track */}
                <div className="flex h-2 rounded bg-[#1c2d4a] overflow-hidden gap-px">
                  {dist.map(d => (
                    <DN key={d.level} navigateTo={d.nav}>
                      <div style={{
                        flex: d.pct || 0.3,
                        backgroundColor: RISK_BAR_COLOR[d.level] || '#22c55e',
                        minWidth: d.count > 0 ? '2px' : '0',
                        height: '8px',
                      }} />
                    </DN>
                  ))}
                </div>
                {/* Legend */}
                <div className="flex gap-4 mt-2.5">
                  {dist.map(d => (
                    <DN key={d.level} navigateTo={d.nav}>
                      <div className="flex items-center gap-1.5 text-[11px] text-[#8fa3bf]">
                        <span className="w-2 h-2 rounded-sm flex-shrink-0" style={{ backgroundColor: RISK_BAR_COLOR[d.level] || '#22c55e' }} />
                        <span className="capitalize">{d.level}</span>
                        <span className="font-mono">{d.count}</span>
                      </div>
                    </DN>
                  ))}
                </div>
              </section>
            )}

            {/* ━━━ 4. METRIC CARDS ━━━ */}
            {cats.length > 0 && (
              <div className="grid gap-3" style={{ gridTemplateColumns: `repeat(${Math.min(cats.length, 5)}, 1fr)` }}>
                {cats.map(c => (
                  <DN key={c.label} navigateTo={c.nav}>
                    <div className="relative bg-[#111f35] border border-[rgba(36,162,161,0.15)] rounded-xl p-4 overflow-hidden hover:border-[rgba(36,162,161,0.35)] transition cursor-pointer">
                      <div className="text-[10px] uppercase tracking-[0.8px] text-[#4a6080] mb-2">{c.label}</div>
                      <div className="text-[28px] font-semibold text-[#e8eef8] leading-none" style={{ letterSpacing: '-1.5px' }}>{c.count}</div>
                      <div className="text-[11px] text-[#4a6080] leading-snug mt-2">
                        {c.issues.map((line, i) => <React.Fragment key={i}>{i > 0 && <br />}{line}</React.Fragment>)}
                      </div>
                      <span className={`inline-block mt-2 text-[10px] font-medium px-2 py-0.5 rounded-full ${TAG_CLS[c.tag.variant] || TAG_CLS.teal}`}>
                        {c.tag.text}
                      </span>
                      {/* Bottom accent */}
                      <div className="absolute bottom-0 inset-x-0 h-0.5 rounded-b-xl" style={{ backgroundColor: c.accent }} />
                    </div>
                  </DN>
                ))}
              </div>
            )}

            {/* ━━━ 5. CONTENT GRID ━━━ */}
            <div className="grid gap-4" style={{ gridTemplateColumns: '1fr 340px' }}>

              {/* ── LEFT: Findings Table ── */}
              <div className="bg-[#111f35] border border-[rgba(36,162,161,0.15)] rounded-[14px] overflow-hidden">
                <div className="px-5 py-4 border-b border-[rgba(36,162,161,0.15)] flex justify-between items-center">
                  <span className="text-[13px] font-semibold text-[#e8eef8]">Key Risk Findings</span>
                  <DN navigateTo="/identity-exposures">
                    <span className="text-[11px] font-medium text-[#24A2A1] cursor-pointer">View all →</span>
                  </DN>
                </div>

                {vm.findings.length === 0 && (
                  <div className="px-5 py-10 text-center text-[11px] text-[#4a6080]">
                    No high-risk identities detected
                  </div>
                )}

                {vm.findings.map((f, i) => (
                  <DN key={f.name + i} navigateTo={f.nav} prefill={f.prefill}>
                    <div className="grid items-center gap-3 px-5 py-3 border-b border-[rgba(36,162,161,0.07)] hover:bg-[#162540] transition cursor-pointer"
                         style={{ gridTemplateColumns: '24px 1fr 90px 90px 70px' }}>
                      <span className="font-mono text-[10px] text-[#4a6080]">
                        {String(i + 1).padStart(2, '0')}
                      </span>
                      <div className="min-w-0">
                        <div className="text-[12.5px] font-medium text-[#e8eef8] truncate">{f.name}</div>
                        <div className="text-[11px] text-[#4a6080] mt-0.5 truncate">{f.sub}</div>
                      </div>
                      <span className={`font-mono text-[9.5px] font-semibold uppercase tracking-[0.5px] px-2 py-[3px] rounded-full text-center whitespace-nowrap ${VERDICT_CLS[f.verdict_variant] || VERDICT_CLS.teal}`}>
                        {f.verdict}
                      </span>
                      <div className="flex flex-col gap-1">
                        <div className="h-1 rounded bg-[#1c2d4a] overflow-hidden">
                          <div className="h-full rounded" style={{ width: `${f.blast_pct}%`, backgroundColor: f.blast_color }} />
                        </div>
                        <span className="font-mono text-[10px] text-[#4a6080]">{f.blast_label}</span>
                      </div>
                      <span className="text-[9.5px] font-semibold px-2.5 py-1 rounded-md bg-[rgba(36,162,161,0.1)] text-[#24A2A1] border border-[rgba(36,162,161,0.15)] text-center">
                        {f.action_label}
                      </span>
                    </div>
                  </DN>
                ))}
              </div>

              {/* ── RIGHT COLUMN ── */}
              <div className="flex flex-col gap-3.5">

                {/* Panel A: Identity Composition */}
                {donutCats.length > 0 && (
                  <div className="bg-[#111f35] border border-[rgba(36,162,161,0.15)] rounded-xl overflow-hidden">
                    <div className="px-4 py-3.5 border-b border-[rgba(36,162,161,0.15)] flex justify-between items-center">
                      <span className="text-[13px] font-semibold text-[#e8eef8]">Identity Composition</span>
                      <DN navigateTo={vm.total_identities_nav}>
                        <span className="text-[11px] font-mono text-[#4a6080]">{total.toLocaleString()} total</span>
                      </DN>
                    </div>
                    {/* Donut via conic-gradient */}
                    <div className="px-4 py-4 flex justify-center">
                      <div className="relative w-[140px] h-[140px]">
                        <div className="absolute inset-0 rounded-full" style={{
                          background: buildConicGradient(donutCats),
                        }} />
                        <div className="absolute rounded-full bg-[#111f35]" style={{ inset: '20%' }} />
                        <div className="absolute inset-0 flex flex-col items-center justify-center" style={{ pointerEvents: 'none' }}>
                          <DN navigateTo={vm.total_identities_nav}>
                            <span className="text-[22px] font-semibold text-[#e8eef8] leading-none" style={{ pointerEvents: 'auto' }}>{total.toLocaleString()}</span>
                          </DN>
                          <span className="text-[10px] text-[#4a6080] mt-0.5">identities</span>
                        </div>
                      </div>
                    </div>
                    {/* Identity list */}
                    <div className="px-0 pb-1">
                      {donutCats.map(c => (
                        <DN key={c.label} navigateTo={c.nav}>
                          <div className="flex items-center gap-2 px-4 py-[7px] border-b border-[rgba(36,162,161,0.06)] last:border-0 hover:bg-[#162540] transition cursor-pointer">
                            <span className="w-2 h-2 rounded-sm flex-shrink-0" style={{ backgroundColor: c.chart_color }} />
                            <span className="text-[11.5px] text-[#8fa3bf] flex-1">{c.label}</span>
                            <span className="text-[11px] font-mono text-[#e8eef8]">{c.count}</span>
                            <span className="text-[10px] text-[#4a6080] w-8 text-right">{fmtPct(c.pct)}</span>
                          </div>
                        </DN>
                      ))}
                    </div>
                  </div>
                )}

                {/* Panel B: Worst-Case Blast Radius */}
                {vm.blast_radius.identity_name && (
                  <div className="bg-[#111f35] border border-[rgba(36,162,161,0.15)] rounded-xl overflow-hidden">
                    <div className="px-4 py-3.5 border-b border-[rgba(36,162,161,0.15)] flex justify-between items-center">
                      <span className="text-[13px] font-semibold text-[#e8eef8]">Worst-Case Blast Radius</span>
                      <span className={`text-[9.5px] font-mono font-semibold px-2 py-0.5 rounded ${BLAST_SEVERITY_CLS[vm.blast_radius.level] || BLAST_SEVERITY_CLS.low}`}>
                        IMPACT: {vm.blast_radius.level.toUpperCase()}
                      </span>
                    </div>
                    {/* Blast identity */}
                    <div className="flex gap-3 px-4 py-3 border-b border-[rgba(36,162,161,0.07)] items-start">
                      <div className="w-8 h-8 rounded-lg bg-[#1c2d4a] flex items-center justify-center text-[13px] flex-shrink-0">⛓</div>
                      <div className="flex-1 min-w-0">
                        <DN navigateTo={`/identities/${vm.blast_radius.identity_string_id || vm.blast_radius.identity_id}`}>
                          <div className="text-xs font-medium text-[#e8eef8] cursor-pointer hover:text-[#24A2A1] transition truncate">
                            {vm.blast_radius.identity_name} compromised
                          </div>
                        </DN>
                        <div className="text-[10.5px] text-[#4a6080] mt-0.5">{vm.blast_radius.summary}</div>
                      </div>
                      <span className={`text-[10px] font-mono font-semibold px-2 py-[3px] rounded flex-shrink-0 ${BLAST_SEVERITY_CLS[vm.blast_radius.level] || BLAST_SEVERITY_CLS.low}`}>
                        {vm.blast_radius.level === 'critical' ? 'CRIT' : vm.blast_radius.level.toUpperCase()}
                      </span>
                    </div>
                    {/* Consequences */}
                    {vm.blast_radius.consequences.map((line, i) => (
                      <div key={i} className="flex gap-3 px-4 py-2.5 border-b border-[rgba(36,162,161,0.07)] last:border-0 items-start">
                        <div className="w-8 h-8 rounded-lg bg-[#1c2d4a] flex items-center justify-center text-[13px] flex-shrink-0">
                          {i === 0 ? '⚡' : '◌'}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="text-xs font-medium text-[#e8eef8]">{line}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* ━━━ 6. REMEDIATION QUEUE ━━━ */}
            {vm.immediate_actions.length > 0 && (
              <section className="bg-[#111f35] border border-[rgba(36,162,161,0.15)] rounded-[14px] overflow-hidden">
                <div className="px-5 py-4 border-b border-[rgba(36,162,161,0.15)] flex justify-between items-center">
                  <span className="text-[13px] font-semibold text-[#e8eef8]">Recommended Remediation · Priority Queue</span>
                  <DN navigateTo="/remediation">
                    <span className="text-[11px] font-medium text-[#24A2A1] cursor-pointer">View full plan →</span>
                  </DN>
                </div>
                {vm.immediate_actions.map((action, i) => {
                  const { verb, rest } = splitActionVerb(action.action);
                  return (
                    <DN key={action.action} navigateTo={action.nav}>
                      <div className="flex items-start gap-2.5 px-4 py-3 border-b border-[rgba(36,162,161,0.07)] last:border-0 hover:bg-[#162540] transition cursor-pointer">
                        <span className="w-5 h-5 rounded-full bg-[rgba(36,162,161,0.12)] text-[#24A2A1] text-[10px] font-semibold font-mono flex items-center justify-center flex-shrink-0 mt-0.5">
                          {i + 1}
                        </span>
                        <div className="flex-1 min-w-0">
                          <div className="text-xs font-medium text-[#e8eef8] leading-snug">
                            <span className="font-bold text-[#FF7216]">{verb}</span> {rest}
                          </div>
                          <div className="text-[10.5px] text-[#4a6080] mt-0.5 leading-snug">
                            {action.detail}
                          </div>
                        </div>
                        <span className="text-[9px] uppercase tracking-[0.5px] text-[#4a6080] flex-shrink-0 whitespace-nowrap self-center">
                          {i === 0 ? '15 MIN' : i === 1 ? '30 MIN' : i === 2 ? '20 MIN' : '45 MIN'}
                        </span>
                      </div>
                    </DN>
                  );
                })}
              </section>
            )}

          </div>
        )}
      </div>
      <IdentityContextDrawer />
    </IdentityDrawerProvider>
  );
}
