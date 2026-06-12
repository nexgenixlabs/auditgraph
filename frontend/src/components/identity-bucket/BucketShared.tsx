/**
 * Lock-V2 (2026-06-11) — Identity Bucket Shared Components.
 *
 * Single source of truth for the 4 identity bucket pages (Human, NHI, AI,
 * All Identities). Every page composes from these primitives so they look
 * identical and tabs swap cleanly without per-page reinvention.
 *
 * Layout primitives:
 *   BucketPageShell    — header + subtitle + period selector + filters button
 *   BucketTabs         — top tab strip with ?tab=X URL state
 *   KpiHeroCard        — single big-number card with delta hint
 *   RiskDistributionDonut — Risk Distribution donut + legend
 *   TopRiskReasonsBar  — horizontal bars: each reason + % bar
 *   RecentlyRiskyTable — generic risky-identities table with Investigate CTA
 *   PanelCard          — generic dark panel wrapper
 *
 * SSOT only — these components don't fetch data. Pages own the fetches and
 * pass cooked data in via props.
 */
import React, { useMemo } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';

// ─── PanelCard ─────────────────────────────────────────────────────

export function PanelCard({
  title, subtitle, right, children, className = '',
}: {
  title?: string; subtitle?: string;
  right?: React.ReactNode; children: React.ReactNode; className?: string;
}) {
  return (
    <div className={`rounded-xl p-5 bg-[#0f172a]/80 border border-white/5 ${className}`}>
      {(title || right) && (
        <div className="flex items-center justify-between mb-3 gap-2">
          <div className="min-w-0">
            {title && <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">{title}</h3>}
            {subtitle && <p className="text-[10px] text-slate-500 mt-0.5">{subtitle}</p>}
          </div>
          {right && <div className="flex-shrink-0">{right}</div>}
        </div>
      )}
      {children}
    </div>
  );
}

// ─── BucketPageShell ───────────────────────────────────────────────

export function BucketPageShell({
  title, subtitle, icon, accent, periodLabel = 'Last 30 Days', periodOptions, period, onPeriodChange,
  filtersOpen, onFiltersToggle, children,
}: {
  title: string; subtitle: string; icon?: React.ReactNode; accent: string;
  periodLabel?: string;
  periodOptions?: { label: string; value: string }[];
  period?: string;
  onPeriodChange?: (value: string) => void;
  filtersOpen?: boolean; onFiltersToggle?: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="p-5 w-full space-y-4 min-h-screen">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-3">
          {icon && (
            <div className="w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0"
              style={{ background: `${accent}25`, border: `1px solid ${accent}55` }}>
              {icon}
            </div>
          )}
          <div>
            <h1 className="text-2xl font-bold text-white">{title}</h1>
            <p className="text-sm text-slate-400 mt-0.5">{subtitle}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <PeriodDropdown label={periodLabel} options={periodOptions} value={period} onChange={onPeriodChange} />
          <button
            onClick={onFiltersToggle}
            className="px-3 py-2 rounded-lg text-xs font-medium transition flex items-center gap-2"
            style={{
              background: filtersOpen ? `${accent}25` : 'rgba(30,41,59,0.6)',
              color: filtersOpen ? accent : '#e2e8f0',
              border: `1px solid ${filtersOpen ? `${accent}55` : 'rgba(51,65,85,0.6)'}`,
            }}>
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z"/></svg>
            Filters
          </button>
        </div>
      </div>

      {children}
    </div>
  );
}

function PeriodDropdown({
  label, options, value, onChange,
}: {
  label: string;
  options?: { label: string; value: string }[];
  value?: string;
  onChange?: (v: string) => void;
}) {
  const opts = options || [
    { label: 'Last 7 Days', value: '7d' },
    { label: 'Last 30 Days', value: '30d' },
    { label: 'Last 90 Days', value: '90d' },
  ];
  const current = opts.find(o => o.value === value)?.label || label;
  return (
    <div className="relative group">
      <button className="px-3 py-2 rounded-lg text-xs font-medium bg-slate-800/60 text-slate-200 border border-slate-700 hover:bg-slate-700/60 transition flex items-center gap-2">
        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
        {current}
        <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7"/></svg>
      </button>
      {onChange && (
        <div className="absolute right-0 top-full mt-1 hidden group-hover:block z-30 min-w-[140px] rounded-lg bg-slate-900 border border-slate-700 shadow-xl">
          {opts.map(o => (
            <button key={o.value} onClick={() => onChange(o.value)}
              className="block w-full text-left px-3 py-2 text-xs text-slate-200 hover:bg-slate-800 first:rounded-t-lg last:rounded-b-lg">
              {o.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── BucketTabs (URL-driven via ?tab=X) ────────────────────────────

export interface BucketTab {
  key: string;
  label: string;
  count?: number;
}

export function BucketTabs({ tabs, defaultTab = 'overview', accent }: {
  tabs: BucketTab[];
  defaultTab?: string;
  accent: string;
}): { activeTab: string; tabStrip: React.ReactNode } {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = searchParams.get('tab') || defaultTab;

  const tabStrip = (
    <div className="border-b border-slate-800/80">
      <nav className="flex overflow-x-auto -mb-px scrollbar-thin">
        {tabs.map(t => {
          const isActive = activeTab === t.key;
          return (
            <button
              key={t.key}
              onClick={() => {
                const next = new URLSearchParams(searchParams);
                if (t.key === defaultTab) next.delete('tab'); else next.set('tab', t.key);
                setSearchParams(next, { replace: true });
              }}
              className="px-4 py-2.5 text-[13px] font-medium border-b-2 transition whitespace-nowrap flex items-center gap-2"
              style={{
                borderColor: isActive ? accent : 'transparent',
                color: isActive ? accent : '#94a3b8',
              }}>
              {t.label}
              {typeof t.count === 'number' && t.count > 0 && (
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                  style={{
                    background: isActive ? `${accent}20` : 'rgba(148,163,184,0.10)',
                    color: isActive ? accent : '#94a3b8',
                  }}>{t.count}</span>
              )}
            </button>
          );
        })}
      </nav>
    </div>
  );

  return { activeTab, tabStrip };
}

// ─── KpiHeroCard ───────────────────────────────────────────────────

export function KpiHeroCard({
  label, value, deltaPct, deltaPositive, sublabel, icon, iconColor, valueColor, onClick,
}: {
  label: string;
  value: string | number;
  deltaPct?: number | null;     // ↑ +4.2 / null = no baseline
  deltaPositive?: boolean;       // for color signal (green up vs red up depends on KPI)
  sublabel?: string;             // e.g., "vs last 30 days"
  icon?: React.ReactNode;
  iconColor?: string;
  valueColor?: string;
  // V2.8 (2026-06-11) — peer review: KPI tiles must drill-in.
  onClick?: () => void;
}) {
  const finalIconColor = iconColor || '#94a3b8';
  const interactive = !!onClick;
  return (
    <div onClick={onClick}
      role={interactive ? 'button' : undefined}
      tabIndex={interactive ? 0 : undefined}
      onKeyDown={interactive ? (e) => { if (e.key === 'Enter' || e.key === ' ') onClick!(); } : undefined}
      className={`rounded-xl p-4 bg-[#0f172a]/80 border border-white/5 relative overflow-hidden ${
        interactive ? 'cursor-pointer hover:border-slate-600 hover:bg-[#0f172a] transition group' : ''
      }`}>
      <div className="flex items-start justify-between gap-3 mb-2">
        <p className="text-[10px] uppercase tracking-wider font-bold text-slate-500">{label}</p>
        {icon && (
          <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: `${finalIconColor}15`, border: `1px solid ${finalIconColor}40`, color: finalIconColor }}>
            {icon}
          </div>
        )}
      </div>
      <p className="text-3xl font-bold font-mono leading-tight" style={{ color: valueColor || '#e2e8f0' }}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </p>
      {deltaPct != null && (
        <p className="text-[11px] mt-1.5 flex items-center gap-1"
          style={{ color: deltaPositive ? '#34d399' : '#f87171' }}>
          <span>{deltaPositive ? '↑' : '↓'}</span>
          <strong>{Math.abs(deltaPct).toFixed(1)}%</strong>
          <span className="text-slate-500 font-normal">{sublabel || 'vs last 30 days'}</span>
        </p>
      )}
      {deltaPct == null && sublabel && (
        <p className="text-[11px] mt-1.5 text-slate-500">{sublabel}</p>
      )}
      {/* V2.4 (2026-06-11): honest baseline copy when neither delta nor
          sublabel is set. Prior versions silently rendered nothing here,
          which on a fresh tenant left the card with no caption at all. */}
      {deltaPct == null && !sublabel && (
        <p className="text-[11px] mt-1.5 text-slate-500">No prior-period baseline yet</p>
      )}
    </div>
  );
}

// ─── RiskDistributionDonut ─────────────────────────────────────────

export interface RiskDistEntry { label: string; value: number; color: string }

export function RiskDistributionDonut({ entries, total, title = 'Risk Distribution', subtitle = 'By risk level', explainer }: {
  entries: RiskDistEntry[];
  total: number;
  title?: string;
  subtitle?: string;
  // V2.8 (2026-06-11) — optional explainer banner under the donut for
  // pages where the distribution looks counter-intuitive without context.
  // Peer review flagged NHI showing "100% critical" as a trust-breaker
  // until the customer learns it's an intentional default-to-critical
  // posture per CSA NHI Risk Framework.
  explainer?: React.ReactNode;
}) {
  const SVG = 168, R = 68, STROKE = 16, C = 2 * Math.PI * R;
  const visible = entries.filter(e => e.value > 0);
  const totalSafe = Math.max(1, total);
  const usable = C - 1.5 * Math.max(1, visible.length);
  let cursor = 0;
  return (
    <PanelCard title={title} subtitle={subtitle}>
      <div className="flex items-center gap-5">
        <div className="relative flex-shrink-0" style={{ width: SVG, height: SVG }}>
          <svg width={SVG} height={SVG} className="-rotate-90">
            <circle cx={SVG / 2} cy={SVG / 2} r={R} fill="none" stroke="rgba(148,163,184,0.08)" strokeWidth={STROKE} />
            {visible.map(e => {
              const dash = (e.value / totalSafe) * usable;
              const offset = -cursor;
              cursor += dash + 1.5;
              return (
                <circle key={e.label} cx={SVG / 2} cy={SVG / 2} r={R} fill="none"
                  stroke={e.color} strokeWidth={STROKE} strokeLinecap="round"
                  strokeDasharray={`${dash} ${C - dash}`} strokeDashoffset={offset} />
              );
            })}
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <p className="text-3xl font-bold font-mono text-white leading-none">{total.toLocaleString()}</p>
            <p className="text-[9px] uppercase tracking-wider text-slate-500 font-bold mt-1">Total</p>
          </div>
        </div>
        <ul className="flex-1 space-y-2 min-w-0">
          {entries.map(e => {
            const pct = total > 0 ? Math.round((e.value / total) * 100) : 0;
            return (
              <li key={e.label} className="flex items-center justify-between gap-3 text-xs">
                <span className="flex items-center gap-2 min-w-0">
                  <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: e.color }} />
                  <span className="text-slate-300 truncate">{e.label}</span>
                </span>
                <span className="flex items-center gap-2 flex-shrink-0">
                  <span className="font-mono text-slate-200">{e.value.toLocaleString()}</span>
                  <span className="text-[10px] text-slate-500">({pct}%)</span>
                </span>
              </li>
            );
          })}
        </ul>
      </div>
      {explainer && (
        <div className="mt-3 pt-3 border-t border-slate-700/60 text-[10px] text-slate-400 leading-relaxed">
          {explainer}
        </div>
      )}
    </PanelCard>
  );
}

// ─── TopRiskReasonsBar ─────────────────────────────────────────────

export interface RiskReasonEntry { label: string; value: number; color?: string }

export function TopRiskReasonsBar({ entries, total, title = 'Top Risk Reasons', subtitle = 'Why identities are at risk' }: {
  entries: RiskReasonEntry[];
  total: number;
  title?: string;
  subtitle?: string;
}) {
  const max = Math.max(1, ...entries.map(e => e.value));
  return (
    <PanelCard title={title} subtitle={subtitle}>
      {entries.length === 0 ? (
        <p className="text-[11px] text-slate-500 text-center py-8">No risk reasons logged.</p>
      ) : (
        <ul className="space-y-3">
          {entries.map(e => {
            const pct = total > 0 ? Math.round((e.value / total) * 100) : 0;
            const barPct = (e.value / max) * 100;
            const color = e.color || '#60a5fa';
            return (
              <li key={e.label}>
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="text-slate-300 truncate flex-1">{e.label}</span>
                  <span className="font-mono text-slate-200 ml-2">{pct}%</span>
                </div>
                <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                  <div className="h-full rounded-full transition-all duration-300"
                    style={{ width: `${barPct}%`, background: color }} />
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </PanelCard>
  );
}

// ─── RecentlyRiskyTable ────────────────────────────────────────────

export interface RecentlyRiskyRow {
  identity_id: string;
  display_name: string;
  secondary?: string;          // department (Human) / type (NHI, AI)
  risk_level: string;           // critical / high / medium / low
  risk_reasons?: string;        // joined risk reasons text
  last_seen?: string | null;
  last_label?: string;          // "Last Seen" (Human) / "Last Used" (NHI) / "Last Active" (AI)
}

export function RecentlyRiskyTable({
  rows, secondaryHeader, lastHeader, title = 'Recently Risky Identities',
}: {
  rows: RecentlyRiskyRow[];
  secondaryHeader: string;       // "Department" / "Type"
  lastHeader: string;            // "Last Seen" / "Last Used" / "Last Active"
  title?: string;
}) {
  const navigate = useNavigate();
  return (
    <PanelCard title={title} subtitle={`${rows.length} identit${rows.length === 1 ? 'y' : 'ies'} requiring attention`}>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left text-[10px] uppercase tracking-wider font-bold text-slate-500 border-b border-slate-800">
              <th className="px-2 py-2">Identity</th>
              <th className="px-2 py-2">{secondaryHeader}</th>
              <th className="px-2 py-2">Risk Level</th>
              <th className="px-2 py-2">Risk Reasons</th>
              <th className="px-2 py-2">{lastHeader}</th>
              <th className="px-2 py-2 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={6} className="text-center py-6 text-slate-500 text-[11px]">
                  ✓ No risky identities in this window.
                </td>
              </tr>
            ) : rows.map(r => (
              <tr key={r.identity_id} className="border-b border-slate-800/60 hover:bg-slate-800/30 transition">
                <td className="px-2 py-2.5">
                  <Link to={`/identities/${encodeURIComponent(r.identity_id)}`}
                    className="text-slate-100 font-medium hover:text-violet-300 transition">
                    {r.display_name}
                  </Link>
                </td>
                <td className="px-2 py-2.5 text-slate-300 truncate max-w-[140px]">{r.secondary || '—'}</td>
                <td className="px-2 py-2.5">
                  <RiskChip level={r.risk_level} />
                </td>
                <td className="px-2 py-2.5 text-slate-300 truncate max-w-[280px]" title={r.risk_reasons || ''}>
                  {r.risk_reasons || '—'}
                </td>
                <td className="px-2 py-2.5 text-slate-400">{formatLast(r.last_seen)}</td>
                <td className="px-2 py-2.5 text-right">
                  <button
                    onClick={() => navigate(`/identities/${encodeURIComponent(r.identity_id)}`)}
                    className="px-2.5 py-1 rounded text-[11px] font-semibold text-emerald-300 bg-emerald-500/10 border border-emerald-500/30 hover:bg-emerald-500/20 transition">
                    Investigate
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </PanelCard>
  );
}

function RiskChip({ level }: { level: string }) {
  const k = (level || '').toLowerCase();
  const tone = k === 'critical' ? { bg: 'rgba(239,68,68,0.15)', fg: '#f87171', border: 'rgba(239,68,68,0.40)', label: 'Critical' }
            : k === 'high'     ? { bg: 'rgba(251,146,60,0.15)', fg: '#fb923c', border: 'rgba(251,146,60,0.40)', label: 'High' }
            : k === 'medium'   ? { bg: 'rgba(251,191,36,0.15)', fg: '#fbbf24', border: 'rgba(251,191,36,0.40)', label: 'Medium' }
            : k === 'low'      ? { bg: 'rgba(163,230,53,0.15)', fg: '#a3e635', border: 'rgba(163,230,53,0.40)', label: 'Low' }
            :                    { bg: 'rgba(148,163,184,0.10)', fg: '#94a3b8', border: 'rgba(148,163,184,0.30)', label: '—' };
  return (
    <span className="inline-flex px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
      style={{ background: tone.bg, color: tone.fg, border: `1px solid ${tone.border}` }}>
      {tone.label}
    </span>
  );
}

function formatLast(iso: string | null | undefined): string {
  if (!iso) return '—';
  const ms = Date.now() - new Date(iso).getTime();
  if (!Number.isFinite(ms) || ms < 0) return '—';
  const days = Math.floor(ms / 86_400_000);
  if (days < 1) {
    const h = Math.floor(ms / 3_600_000);
    return h <= 1 ? 'just now' : `${h}h ago`;
  }
  if (days === 1) return '1 day ago';
  if (days < 30) return `${days} days ago`;
  if (days < 365) return `${Math.floor(days / 30)} months ago`;
  return `${Math.floor(days / 365)} years ago`;
}

// ─── derived helpers shared by all 4 pages ─────────────────────────

export function deriveRiskDistribution(cat: { critical: number; high: number; medium: number; low: number; info?: number } | undefined): RiskDistEntry[] {
  const c = cat || { critical: 0, high: 0, medium: 0, low: 0 };
  return [
    { label: 'Critical', value: c.critical, color: '#ef4444' },
    { label: 'High',     value: c.high,     color: '#fb923c' },
    { label: 'Medium',   value: c.medium,   color: '#fbbf24' },
    { label: 'Low',      value: c.low,      color: '#a3e635' },
  ];
}

export function deriveRiskReasons(identities: any[], topN = 5): RiskReasonEntry[] {
  // Aggregate top reason strings across identities (uses risk_reasons[] when
  // present, falls back to risk_factors[].description). Returns the top N.
  const tally = new Map<string, number>();
  for (const i of identities) {
    const reasons: string[] = Array.isArray(i.risk_reasons) ? i.risk_reasons
                            : typeof i.risk_reasons === 'string' ? i.risk_reasons.split(/[,;]\s*/)
                            : Array.isArray(i.risk_factors) ? i.risk_factors.map((f: any) => f.description).filter(Boolean)
                            : [];
    for (const r of reasons) {
      const clean = String(r).replace(/\s*\(\+\d+\)\s*$/, '').trim();
      if (!clean) continue;
      tally.set(clean, (tally.get(clean) || 0) + 1);
    }
  }
  // V2.8 (2026-06-11) — peer review: panel should never be empty when there
  // are identities. When `risk_reasons` isn't populated yet, derive
  // categorical reasons from raw flags on each identity. These map to the
  // top architectural risk categories every CISO recognizes:
  //   - Excessive Privilege   (risk_level critical|high)
  //   - Dormant Account       (activity_status stale|dormant|never_used)
  //   - MFA Missing           (mfa_status=none / mfa_methods empty)
  //   - Privileged Role       (privilege_level Highly Privileged|Privileged)
  //   - Attack Path Participation (has_direct_rbac_path or risk_score >= 80)
  // V2.12 (2026-06-12) — category-aware fallback. Two bugs the founder
  // flagged on the NHI Overview's Top Risk Reasons:
  //
  //   1. "MFA Missing 100%" was firing for every NHI because NHIs don't
  //      have an mfa_status column, so the empty-check matched everything.
  //      NHIs literally cannot have MFA. Skip this tag for non-human.
  //
  //   2. "Excessive Privilege 100%" was firing for every critical NHI
  //      because NHIs default to CRITICAL per the CSA NHI Risk Framework
  //      (see [[feedback_nhi_default_critical]]). The customer reads the
  //      same 100% as "every NHI has excessive privilege" — that's a lie.
  //      For NHIs, surface the actual reason: ownership gap, expired creds,
  //      no recent activity, ungated auth. These come from risk_reasons
  //      when available; otherwise we tag by detected condition.
  if (tally.size === 0 && identities.length > 0) {
    // Detect whether the identities are non-human (no MFA concept).
    const isNhiBucket = identities.length > 0 && identities.every(i => {
      const c = String(i.identity_category || '').toLowerCase();
      return c === 'service_principal' || c === 'managed_identity_system'
          || c === 'managed_identity_user' || c === 'workload';
    });

    for (const i of identities) {
      const risk = String(i.risk_level || '').toLowerCase();
      const isCritOrHigh = risk === 'critical' || risk === 'high';

      // Excessive Privilege is only honest when the identity ACTUALLY holds
      // a privileged role. For NHIs flagged critical-by-default we use the
      // specific failed-check tags instead (see below).
      const priv = String(i.privilege_level || '').toLowerCase();
      const isPrivileged = priv.includes('privileged');
      if (isCritOrHigh && isPrivileged) {
        tally.set('Excessive Privilege', (tally.get('Excessive Privilege') || 0) + 1);
      }
      if (isPrivileged) {
        tally.set('Privileged Role', (tally.get('Privileged Role') || 0) + 1);
      }

      const act = String(i.activity_status || '').toLowerCase();
      if (act === 'stale' || act === 'dormant' || act === 'never_used' || i.is_dormant) {
        tally.set('Dormant Account', (tally.get('Dormant Account') || 0) + 1);
      }

      // MFA Missing is a HUMAN concept. NHIs cannot have MFA.
      if (!isNhiBucket) {
        const mfa = String(i.mfa_status || '').toLowerCase();
        const noMfa = mfa === 'none' || mfa === 'disabled' || (Array.isArray(i.mfa_methods) && i.mfa_methods.length === 0);
        if (noMfa) tally.set('MFA Missing', (tally.get('MFA Missing') || 0) + 1);
      }

      if (i.has_direct_rbac_path || (i.risk_score || 0) >= 80) {
        tally.set('Attack Path Participation', (tally.get('Attack Path Participation') || 0) + 1);
      }

      // NHI-specific failure tags. Read from risk_reasons when present
      // (discovery engine emits a "NHI default = CRITICAL (failed: X, Y)"
      // string per identity); otherwise infer from raw flags.
      if (isNhiBucket && isCritOrHigh) {
        const reasonsStr = Array.isArray(i.risk_reasons) ? i.risk_reasons.join(' ')
                       : typeof i.risk_reasons === 'string' ? i.risk_reasons : '';
        const reasonsLower = reasonsStr.toLowerCase();

        const owned = (i.owner_count || 0) > 0
                   || !!i.owner_display_name
                   || !!i.app_reg_owner_display_name;
        if (!owned || reasonsLower.includes('no owner')) {
          tally.set('No Owner', (tally.get('No Owner') || 0) + 1);
        }

        if (reasonsLower.includes('expired') || reasonsLower.includes('expiring')
            || i.secret_expiry_status === 'expired' || i.secret_expiry_status === 'expiring') {
          tally.set('Expired Credentials', (tally.get('Expired Credentials') || 0) + 1);
        }

        if (reasonsLower.includes('no recent activity') || reasonsLower.includes('dormant')) {
          tally.set('No Recent Activity', (tally.get('No Recent Activity') || 0) + 1);
        }

        if (reasonsLower.includes('ungated') || reasonsLower.includes('long-lived')) {
          tally.set('Ungated Auth (long-lived secrets)', (tally.get('Ungated Auth (long-lived secrets)') || 0) + 1);
        }
      }
    }
  }
  const palette = ['#ef4444', '#fb923c', '#fbbf24', '#60a5fa', '#a78bfa', '#34d399'];
  return Array.from(tally.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, topN)
    .map(([label, value], idx) => ({ label, value, color: palette[idx % palette.length] }));
}
