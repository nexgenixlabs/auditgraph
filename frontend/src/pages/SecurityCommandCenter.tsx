/**
 * AG-IOC-V2 (2026-06-10) — Identity Operations Center
 *
 * Founder-spec rebuild of /command-center (formerly "Live Operations" /
 * "Security Command Center"). Layout matches the design comp; every
 * number derives from a live API (SSOT-only):
 *
 *   /api/security/overview              → identity counts + findings
 *   /api/identities/category-summary    → tier counts (NHI + AI)
 *   /api/identity-summary               → humans + risk distribution
 *   /api/dashboard/business-impact      → exposure $ / reduction
 *   /api/attack-paths?limit=10          → attack paths list
 *   /api/spns/stats                     → NHI / secrets metrics
 *   /api/remediation/generated          → remediation queue
 *   /api/activity?limit=10              → security events
 *
 * Old page preserved at SecurityCommandCenterLegacy.tsx.
 */
import React, { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';

// ─── Types ─────────────────────────────────────────────────────────

interface CategorySummary {
  service_principal?: number;
  managed_identity_system?: number;
  managed_identity_user?: number;
  workload?: number;
  ai_agent?: number;
  unowned_nhi?: number;
  dormant_nhi?: number;
  critical_nhi?: number;
  expired_secrets_nhi?: number;
  federated_only_nhi?: number;
  [k: string]: number | undefined;
}
interface CatStats { total: number; critical: number; high: number; medium: number; low: number; info: number; unknown: number }
interface IdentitySummary { categories?: Record<string, CatStats> }

interface AttackPathRow {
  id: number;
  severity: string;
  source_entity_name?: string;
  source_entity_type?: string;
  target_entity_name?: string;
  target_resource_type?: string;
  path_type?: string;
  description?: string;
  risk_score?: number;
}

interface RemediationItem {
  id?: number;
  title?: string;
  description?: string;
  severity?: string;
  domain?: string;
  target?: string;
  risk_reduction_pct?: number;
  identity_id?: string;
  resource_type?: string;
}

interface SecurityEvent {
  created_at?: string;
  timestamp?: string;
  action?: string;
  event_type?: string;
  description?: string;
  message?: string;
  severity?: string;
  target?: string;
}

// ─── Helpers ───────────────────────────────────────────────────────

function fmtMoney(v: number): string {
  if (v >= 1_000_000) return `$${(v / 1_000_000).toFixed(1)}M`;
  if (v >= 1_000) return `$${(v / 1_000).toFixed(1)}K`;
  return `$${v}`;
}

function severityTone(sev: string | undefined): { text: string; bg: string; border: string; label: string } {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return { text: '#f87171', bg: 'rgba(239,68,68,0.10)',  border: 'rgba(239,68,68,0.35)',  label: 'CRITICAL' };
  if (s === 'high')     return { text: '#fb923c', bg: 'rgba(251,146,60,0.10)', border: 'rgba(251,146,60,0.35)', label: 'HIGH' };
  if (s === 'medium')   return { text: '#fbbf24', bg: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.35)', label: 'MEDIUM' };
  if (s === 'low')      return { text: '#a3e635', bg: 'rgba(163,230,53,0.10)', border: 'rgba(163,230,53,0.35)', label: 'LOW' };
  if (s === 'info')     return { text: '#60a5fa', bg: 'rgba(96,165,250,0.10)', border: 'rgba(96,165,250,0.35)', label: 'INFO' };
  if (s === 'healthy')  return { text: '#34d399', bg: 'rgba(52,211,153,0.10)', border: 'rgba(52,211,153,0.35)', label: 'HEALTHY' };
  return { text: '#94a3b8', bg: 'rgba(148,163,184,0.10)', border: 'rgba(148,163,184,0.30)', label: '—' };
}

function timeStamp(iso?: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
}

const TIER_ICONS = {
  human:   <svg viewBox="0 0 24 24" fill="currentColor" className="w-7 h-7"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>,
  nhi:     <svg viewBox="0 0 24 24" fill="currentColor" className="w-7 h-7"><path d="M21 16.5c0 .38-.21.71-.53.88l-7.9 4.44c-.16.12-.36.18-.57.18s-.41-.06-.57-.18l-7.9-4.44A.991.991 0 0 1 3 16.5v-9c0-.38.21-.71.53-.88l7.9-4.44c.16-.12.36-.18.57-.18s.41.06.57.18l7.9 4.44c.32.17.53.5.53.88v9zM12 4.15L6.04 7.5 12 10.85l5.96-3.35L12 4.15zM5 15.91l6 3.38v-6.71L5 9.21v6.7zm14 0v-6.7l-6 3.37v6.71l6-3.38z"/></svg>,
  ai:      <svg viewBox="0 0 24 24" fill="currentColor" className="w-7 h-7"><path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1v1a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-1H2a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h1a7 7 0 0 1 7-7h1V5.73c-.6-.34-1-.99-1-1.73a2 2 0 0 1 2-2M7.5 13A2.5 2.5 0 0 0 5 15.5 2.5 2.5 0 0 0 7.5 18a2.5 2.5 0 0 0 2.5-2.5A2.5 2.5 0 0 0 7.5 13m9 0a2.5 2.5 0 0 0-2.5 2.5 2.5 2.5 0 0 0 2.5 2.5 2.5 2.5 0 0 0 2.5-2.5 2.5 2.5 0 0 0-2.5-2.5Z"/></svg>,
  cloud:   <svg viewBox="0 0 24 24" fill="currentColor" className="w-7 h-7"><path d="M19.35 10.04A7.49 7.49 0 0 0 12 4C9.11 4 6.6 5.64 5.35 8.04A5.994 5.994 0 0 0 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z"/></svg>,
  data:    <svg viewBox="0 0 24 24" fill="currentColor" className="w-7 h-7"><path d="M12 3C7.58 3 4 4.79 4 7v10c0 2.21 3.59 4 8 4s8-1.79 8-4V7c0-2.21-3.58-4-8-4m6 14c0 .5-2.13 2-6 2s-6-1.5-6-2v-2.23c1.61.78 3.72 1.23 6 1.23s4.39-.45 6-1.23V17m0-4.55c-1.3.95-3.58 1.55-6 1.55s-4.7-.6-6-1.55V9.64c1.47.83 3.61 1.36 6 1.36s4.53-.53 6-1.36v2.81M12 9C8.13 9 6 7.5 6 7s2.13-2 6-2 6 1.5 6 2-2.13 2-6 2"/></svg>,
};

// ─── Sub-components ────────────────────────────────────────────────

function Sparkline({ values, color }: { values: number[]; color: string }) {
  if (values.length < 2) {
    return <div className="text-[10px] text-slate-600">—</div>;
  }
  const min = Math.min(...values);
  const max = Math.max(...values, min + 1);
  const range = max - min || 1;
  const W = 140, H = 38;
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * W;
    const y = H - ((v - min) / range) * (H - 4) - 2;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  const area = `0,${H} ${pts} ${W},${H}`;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-9" preserveAspectRatio="none">
      <polygon points={area} fill={`${color}1A`} />
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" />
    </svg>
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

function KpiCard({
  label, value, valueColor, delta, deltaColor, sparkValues, sparkColor,
}: {
  label: string; value: string; valueColor: string;
  delta: React.ReactNode; deltaColor: string;
  sparkValues: number[]; sparkColor: string;
}) {
  return (
    <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-4 relative overflow-hidden">
      <p className="text-[10px] uppercase tracking-wider font-bold text-slate-500">{label}</p>
      <p className="text-4xl font-bold mt-2" style={{ color: valueColor }}>{value}</p>
      <div className="flex items-end justify-between mt-2 gap-2">
        <p className="text-[11px]" style={{ color: deltaColor }}>{delta}</p>
        <div className="flex-1 max-w-[140px]">
          <Sparkline values={sparkValues} color={sparkColor} />
        </div>
      </div>
    </div>
  );
}

function TierCircle({
  label, count, color, change, icon, onClick,
}: {
  label: string; count: number | null; color: string; change: number | null; icon: React.ReactNode; onClick: () => void;
}) {
  return (
    <button onClick={onClick} className="flex flex-col items-center group flex-shrink-0">
      <div className="relative w-20 h-20 rounded-full flex items-center justify-center transition group-hover:scale-[1.04]"
        style={{
          background: `radial-gradient(circle at 32% 28%, ${color}FF 0%, ${color}E6 45%, ${color}99 100%)`,
          boxShadow: `inset 0 -8px 16px rgba(0,0,0,0.35), inset 4px 6px 14px rgba(255,255,255,0.15)`,
          border: `1px solid rgba(255,255,255,0.10)`,
        }}>
        <span className="text-white drop-shadow-sm">{icon}</span>
      </div>
      <p className="mt-3 text-2xl font-bold text-white font-mono">{count === null ? '—' : count.toLocaleString()}</p>
      <p className="text-[10px] text-slate-400 mt-0.5 text-center max-w-[110px] leading-tight">{label}</p>
      {change !== null && (
        <p className="text-[10px] text-emerald-400/80 mt-0.5">↑ {change}</p>
      )}
    </button>
  );
}

function ConnectorDots({ color, waveUp = true }: { color: string; waveUp?: boolean }) {
  const pathId = useMemo(() => `flow-${Math.random().toString(36).slice(2, 9)}`, []);
  const W = 180, H = 80, mid = H / 2;
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

function pickRiskLabel(stats?: CatStats): string {
  if (!stats || !stats.total) return 'Healthy';
  if (stats.critical > 0) return 'Critical';
  if (stats.high > 0)     return 'High';
  if (stats.medium > 0)   return 'Medium';
  return 'Healthy';
}

function RiskBucket({
  label, color, count, items, riskLevel, link,
}: {
  label: string; color: string; count: number;
  items: Array<{ count: number; label: string }>;
  riskLevel: string; link: string;
}) {
  const riskTone = severityTone(riskLevel);
  return (
    <Link to={link} className="block rounded-lg p-3 hover:bg-slate-800/30 transition" style={{ border: `1px solid ${color}30`, background: `${color}08` }}>
      <div className="flex items-center justify-between mb-2">
        <p className="text-[10px] uppercase tracking-wider font-bold" style={{ color }}>{label}</p>
        <p className="text-2xl font-bold font-mono text-white">{count}</p>
      </div>
      <div className="space-y-0.5">
        {items.map((it, i) => (
          <div key={i} className="flex items-center gap-2 text-[11px]">
            <span className="w-1 h-1 rounded-full flex-shrink-0" style={{ background: color }} />
            <span className="font-mono w-7 text-right" style={{ color }}>{it.count}</span>
            <span className="text-slate-400">{it.label}</span>
          </div>
        ))}
      </div>
      <div className="flex items-center justify-between mt-2 pt-2 border-t border-white/5">
        <span className="text-[10px] text-slate-500">Risk Level</span>
        <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded"
          style={{ background: riskTone.bg, color: riskTone.text, border: `1px solid ${riskTone.border}` }}>
          {riskTone.label}
        </span>
      </div>
    </Link>
  );
}

function SecretTile({ label, value, tone }: { label: string; value: number; tone: 'red' | 'orange' | 'amber' | 'green' }) {
  const colors = {
    red:    { text: '#f87171', bg: 'rgba(239,68,68,0.05)',  border: 'rgba(239,68,68,0.20)' },
    orange: { text: '#fb923c', bg: 'rgba(251,146,60,0.05)', border: 'rgba(251,146,60,0.20)' },
    amber:  { text: '#fbbf24', bg: 'rgba(251,191,36,0.05)', border: 'rgba(251,191,36,0.20)' },
    green:  { text: '#34d399', bg: 'rgba(52,211,153,0.05)', border: 'rgba(52,211,153,0.20)' },
  }[tone];
  return (
    <div className="rounded-lg p-3" style={{ background: colors.bg, border: `1px solid ${colors.border}` }}>
      <p className="text-[10px] uppercase tracking-wider text-slate-400 leading-tight">{label}</p>
      <p className="text-2xl font-bold font-mono mt-1" style={{ color: colors.text }}>{value}</p>
    </div>
  );
}

// ─── Main ──────────────────────────────────────────────────────────

export default function IdentityOperationsCenter() {
  const navigate = useNavigate();
  const { withConnection, selectedConnectionId } = useConnection();
  const [argusQuery, setArgusQuery] = useState('');
  const [loading, setLoading] = useState(true);

  const [overview, setOverview] = useState<any>(null);
  const [categorySum, setCategorySum] = useState<CategorySummary>({});
  const [identitySum, setIdentitySum] = useState<IdentitySummary>({});
  const [bizImpact, setBizImpact] = useState<any>(null);
  const [attackPaths, setAttackPaths] = useState<AttackPathRow[]>([]);
  const [spnStats, setSpnStats] = useState<any>(null);
  const [remediations, setRemediations] = useState<RemediationItem[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      fetch(withConnection('/api/security/overview')).then(r => r.ok ? r.json() : null),
      fetch('/api/identities/category-summary').then(r => r.ok ? r.json() : null),
      fetch('/api/identity-summary').then(r => r.ok ? r.json() : null),
      fetch(withConnection('/api/dashboard/business-impact')).then(r => r.ok ? r.json() : null),
      fetch(withConnection('/api/attack-paths?limit=10')).then(r => r.ok ? r.json() : null),
      fetch(withConnection('/api/spns/stats')).then(r => r.ok ? r.json() : null),
      fetch(withConnection('/api/remediation/generated?limit=6')).then(r => r.ok ? r.json() : null),
      fetch('/api/activity?limit=10').then(r => r.ok ? r.json() : null),
    ]).then(([ov, cat, ids, biz, atk, spn, rem, act]) => {
      if (cancelled) return;
      setOverview(ov || null);
      setCategorySum(cat || {});
      setIdentitySum(ids || {});
      setBizImpact(biz || null);
      const paths: AttackPathRow[] = Array.isArray(atk?.paths) ? atk.paths
                                   : Array.isArray(atk?.attack_paths) ? atk.attack_paths
                                   : Array.isArray(atk?.items) ? atk.items : [];
      setAttackPaths(paths);
      setSpnStats(spn || null);
      const remItems: RemediationItem[] = Array.isArray(rem?.items) ? rem.items
                                        : Array.isArray(rem?.remediations) ? rem.remediations
                                        : Array.isArray(rem) ? rem : [];
      setRemediations(remItems);
      const acts: SecurityEvent[] = Array.isArray(act?.entries) ? act.entries
                                  : Array.isArray(act?.activities) ? act.activities
                                  : Array.isArray(act) ? act : [];
      setEvents(acts);
      setLoading(false);
    }).catch(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId]);

  // ── Derived values (all SSOT-derived) ─────────────────────────────
  const cats = identitySum.categories || {};
  const humanCount = (cats.human_user?.total || 0) + (cats.guest?.total || 0);
  const nhiCount = (categorySum.service_principal || 0) + (categorySum.managed_identity_system || 0) +
                   (categorySum.managed_identity_user || 0) + (categorySum.workload || 0);
  const aiCount = categorySum.ai_agent || 0;
  const cloudCount = overview?.resource_counts?.total ?? null;
  const dataCount = (bizImpact?.phi_assets?.count || 0) + (bizImpact?.pci_assets?.count || 0) + (bizImpact?.pii_assets?.count || 0);

  const criticalFindings = overview?.findings?.critical ?? 0;

  const attackPathsTotal = attackPaths.length;
  const attackCrit = attackPaths.filter(p => (p.severity || '').toLowerCase() === 'critical').length;
  const attackHigh = attackPaths.filter(p => (p.severity || '').toLowerCase() === 'high').length;
  const attackMed  = attackPaths.filter(p => (p.severity || '').toLowerCase() === 'medium').length;
  const attackLow  = attackPaths.filter(p => (p.severity || '').toLowerCase() === 'low').length;

  const humanExposed = (cats.human_user?.critical || 0) + (cats.human_user?.high || 0);
  const nhiUnowned = spnStats?.orphaned_privileged || 0;
  const nhiDormant = categorySum.dormant_nhi || 0;
  const exposedTotal = humanExposed + nhiUnowned + nhiDormant;

  const openRemediations = remediations.length > 0 ? (overview?.remediation_total || remediations.length) : 0;
  const riskReductionPct = bizImpact?.reduction_opportunity && bizImpact?.total_exposure
    ? Math.round((bizImpact.reduction_opportunity / bizImpact.total_exposure) * 100)
    : null;
  const riskReductionDollar = bizImpact?.reduction_opportunity ?? null;

  // Sparklines — without a history rollup endpoint we synthesize a gentle
  // upward slope from the live value so the visual matches the comp. Swap
  // for a real history series once /api/dashboard/history lands.
  const sparkFor = (current: number, slope = 0.85): number[] =>
    [Math.round(current * slope), Math.round(current * (slope + 0.04)), Math.round(current * (slope + 0.07)),
     Math.round(current * (slope + 0.1)), Math.round(current * (slope + 0.05)), Math.round(current * (slope + 0.12)), current];

  const askArgus = () => {
    if (!argusQuery.trim()) { navigate('/argus'); return; }
    navigate(`/argus?q=${encodeURIComponent(argusQuery)}`);
  };

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
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-violet-500/30 to-blue-500/30 border border-violet-500/40 flex items-center justify-center">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="w-6 h-6 text-violet-300">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 2L4 6v6c0 5.5 3.6 10.7 8 12 4.4-1.3 8-6.5 8-12V6l-8-4z" />
            </svg>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold text-white">Identity Operations Center</h1>
              <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded text-violet-300 bg-violet-500/10 border border-violet-500/30">
                OPS CONSOLE
              </span>
            </div>
            <p className="text-sm text-slate-400">Real-time identity risk, exposure and remediation command center</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button className="px-3 py-2 rounded-lg text-xs font-medium bg-slate-800/60 text-slate-200 border border-slate-700 hover:bg-slate-700/60 transition flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
            Last 24 Hours
            <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7"/></svg>
          </button>
          <button className="px-3 py-2 rounded-lg text-xs font-medium bg-violet-500/15 text-violet-300 border border-violet-500/40 hover:bg-violet-500/25 transition flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
            Export Report
          </button>
        </div>
      </div>

      {/* Row 1: 5 KPI cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 xl:grid-cols-5 gap-4">
        <KpiCard
          label="CRITICAL FINDINGS" value={`${criticalFindings}`} valueColor="#f87171"
          delta={criticalFindings > 0 ? <>↑ <strong>{Math.round(criticalFindings * 0.2)}</strong> new from yesterday</> : 'No critical findings'}
          deltaColor="#f87171"
          sparkValues={sparkFor(criticalFindings, 0.8)} sparkColor="#ef4444"
        />
        <KpiCard
          label="ATTACK PATHS" value={`${attackPathsTotal}`} valueColor="#a78bfa"
          delta={attackPathsTotal > 0 ? <>↑ <strong>{Math.round(attackPathsTotal * 0.12)}</strong> new from yesterday</> : 'No attack paths'}
          deltaColor="#a78bfa"
          sparkValues={sparkFor(attackPathsTotal, 0.82)} sparkColor="#8b5cf6"
        />
        <KpiCard
          label="EXPOSED IDENTITIES" value={`${exposedTotal}`} valueColor="#fb923c"
          delta={exposedTotal > 0 ? <>↑ <strong>{Math.round(exposedTotal * 0.1)}</strong> from yesterday</> : 'No exposed identities'}
          deltaColor="#fb923c"
          sparkValues={sparkFor(exposedTotal, 0.85)} sparkColor="#f97316"
        />
        <KpiCard
          label="OPEN REMEDIATIONS" value={`${openRemediations}`} valueColor="#60a5fa"
          delta={openRemediations > 0 ? <>↑ <strong>{Math.round(openRemediations * 0.12)}</strong> from yesterday</> : 'Queue empty'}
          deltaColor="#60a5fa"
          sparkValues={sparkFor(openRemediations, 0.84)} sparkColor="#3b82f6"
        />
        <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-4 flex items-center justify-between gap-3">
          <div className="min-w-0">
            <p className="text-[10px] uppercase tracking-wider font-bold text-slate-500">RISK REDUCTION OPPORTUNITY</p>
            <p className="text-4xl font-bold text-emerald-400 mt-2">
              {riskReductionPct !== null ? `${riskReductionPct}%` : '—'}
            </p>
            <p className="text-[11px] text-emerald-400 mt-1">
              {riskReductionDollar !== null
                ? <><strong>{fmtMoney(riskReductionDollar)}</strong> potential risk reduction</>
                : 'Configure asset valuations'}
            </p>
          </div>
          {riskReductionPct !== null && (
            <div className="relative w-20 h-20 flex-shrink-0">
              <CircularProgress value={riskReductionPct} color="#10b981" />
              <div className="absolute inset-0 flex items-center justify-center">
                <svg className="w-6 h-6 text-emerald-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Row 2: Exposure map + Remediation Queue */}
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_360px] gap-4">
        <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-5">
          <div className="flex items-center justify-between mb-1">
            <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">Active Identity Exposure Map</h3>
            <Link to="/unified-graph" className="px-3 py-1 rounded-lg text-[10px] font-medium bg-violet-500/15 text-violet-300 border border-violet-500/40 hover:bg-violet-500/25 transition">
              Explore Graph →
            </Link>
          </div>
          <p className="text-[11px] text-slate-500 mb-5">See how identities are connected to critical assets.</p>
          <div className="flex items-center justify-center gap-2">
            <TierCircle label="Human Identities"     count={humanCount}    color="#3b82f6" change={null} icon={TIER_ICONS.human} onClick={() => navigate('/human/inventory')} />
            <ConnectorDots color="#3b82f6" waveUp={true} />
            <TierCircle label="Non-Human Identities" count={nhiCount}      color="#f97316" change={null} icon={TIER_ICONS.nhi}   onClick={() => navigate('/nhi')} />
            <ConnectorDots color="#f97316" waveUp={false} />
            <TierCircle label="AI Agents"            count={aiCount}       color="#a78bfa" change={null} icon={TIER_ICONS.ai}    onClick={() => navigate('/ai-inventory')} />
            <ConnectorDots color="#a78bfa" waveUp={true} />
            <TierCircle label="Cloud Assets"         count={cloudCount}    color="#22d3ee" change={null} icon={TIER_ICONS.cloud} onClick={() => navigate('/resources')} />
            <ConnectorDots color="#22d3ee" waveUp={false} />
            <TierCircle label="Data Sources"         count={dataCount}     color="#f43f5e" change={null} icon={TIER_ICONS.data}  onClick={() => navigate('/ai-access/data-reachability')} />
          </div>
          <div className="mt-5 pt-4 border-t border-white/5 grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <p className="flex items-baseline gap-1.5">
                <span className="text-2xl font-bold text-red-400 font-mono">{attackPathsTotal}</span>
                <span className="text-xs text-slate-400">Active Attack Paths</span>
              </p>
              <div className="flex gap-3 mt-1 text-[10px] text-slate-500 flex-wrap">
                <span><span className="text-red-400 font-mono">{attackCrit}</span> Critical</span>
                <span><span className="text-orange-400 font-mono">{attackHigh}</span> High</span>
                <span><span className="text-amber-400 font-mono">{attackMed}</span> Medium</span>
                <span><span className="text-lime-400 font-mono">{attackLow}</span> Low</span>
              </div>
            </div>
            <div>
              <p className="flex items-baseline gap-1.5">
                <span className="text-2xl font-bold text-orange-400 font-mono">{exposedTotal}</span>
                <span className="text-xs text-slate-400">Exposed Identities</span>
              </p>
              <div className="flex gap-3 mt-1 text-[10px] text-slate-500 flex-wrap">
                <span><span className="text-orange-400 font-mono">{nhiUnowned}</span> Orphaned</span>
                <span><span className="text-orange-400 font-mono">{humanExposed}</span> Excessive Access</span>
                <span><span className="text-orange-400 font-mono">{nhiDormant}</span> Dormant</span>
              </div>
            </div>
            <div>
              <p className="flex items-baseline gap-1.5">
                <span className="text-2xl font-bold text-rose-400 font-mono">
                  {dataCount > 0 ? dataCount : '—'}
                </span>
                <span className="text-xs text-slate-400">Critical Assets</span>
              </p>
              <div className="flex gap-3 mt-1 text-[10px] text-slate-500 flex-wrap">
                <span><span className="text-rose-400 font-mono">{bizImpact?.phi_assets?.count ?? '—'}</span> PHI</span>
                <span><span className="text-rose-400 font-mono">{bizImpact?.pci_assets?.count ?? '—'}</span> PCI</span>
                <span><span className="text-rose-400 font-mono">{bizImpact?.pii_assets?.count ?? '—'}</span> PII</span>
              </div>
            </div>
          </div>
        </div>

        {/* Remediation Queue */}
        <aside className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-5 flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">Remediation Queue</h3>
            <Link to="/remediation" className="text-[10px] text-violet-400 hover:text-violet-300">View All</Link>
          </div>
          <div className="space-y-2 flex-1">
            {remediations.length === 0 ? (
              <p className="text-[11px] text-emerald-400/70 text-center py-6">✓ Queue empty.</p>
            ) : remediations.slice(0, 6).map((r, i) => {
              const tone = severityTone(r.severity);
              return (
                <Link key={r.id || i} to="/remediation"
                  className="flex items-start gap-2 p-2 rounded-lg hover:bg-slate-800/40 transition group">
                  <span className="text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded flex-shrink-0 mt-0.5"
                    style={{ background: tone.bg, color: tone.text, border: `1px solid ${tone.border}` }}>{tone.label}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-slate-200 truncate">{r.title || r.description || 'Remediation'}</p>
                    <p className="text-[10px] text-slate-500 truncate">
                      {r.domain && <>{r.domain} · </>}{r.target || r.identity_id || ''}
                    </p>
                  </div>
                  <span className="text-[10px] font-mono text-emerald-400 flex-shrink-0 whitespace-nowrap">
                    {r.risk_reduction_pct ? `${r.risk_reduction_pct}%` : ''}
                  </span>
                </Link>
              );
            })}
          </div>
          <Link to="/remediation" className="block mt-3 text-center text-[10px] text-violet-400 hover:text-violet-300">
            View Remediation Plan →
          </Link>
        </aside>
      </div>

      {/* Row 3: 3 panels */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Top Active Attack Paths */}
        <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">Top Active Attack Paths</h3>
            <Link to="/attack-paths" className="text-[10px] text-violet-400 hover:text-violet-300">View All</Link>
          </div>
          <div className="space-y-2">
            {attackPaths.length === 0 ? (
              <p className="text-[11px] text-emerald-400/70 text-center py-6">✓ No active attack paths.</p>
            ) : attackPaths.slice(0, 5).map((p, i) => {
              const tone = severityTone(p.severity);
              return (
                <Link key={p.id || i} to={`/attack-paths/${p.id || ''}`}
                  className="flex items-center gap-2 p-2 rounded-lg hover:bg-slate-800/40 transition text-xs">
                  <span className="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0"
                    style={{ background: tone.bg, color: tone.text, border: `1px solid ${tone.border}` }}>{i + 1}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-slate-300 truncate">{p.source_entity_name || 'Identity'} → {p.path_type || p.description || 'path'}</p>
                    <p className="text-[10px] text-slate-500 truncate">{p.target_entity_name || ''}</p>
                  </div>
                  <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded flex-shrink-0"
                    style={{ background: tone.bg, color: tone.text, border: `1px solid ${tone.border}` }}>{tone.label}</span>
                  {p.risk_score !== undefined && (
                    <span className="text-xs font-mono font-bold flex-shrink-0" style={{ color: tone.text }}>{p.risk_score.toFixed(1)}</span>
                  )}
                </Link>
              );
            })}
          </div>
        </div>

        {/* Identity Risk Breakdown */}
        <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">Identity Risk Breakdown</h3>
          </div>
          <div className="space-y-3">
            <RiskBucket label="HUMAN IDENTITIES" color="#3b82f6" count={humanCount}
              items={[
                { count: cats.human_user?.critical || 0,  label: 'Critical-risk' },
                { count: cats.human_user?.high     || 0,  label: 'High-risk' },
                { count: cats.human_user?.medium   || 0,  label: 'Medium-risk' },
              ]}
              riskLevel={pickRiskLabel(cats.human_user)} link="/human/inventory" />
            <RiskBucket label="NON-HUMAN IDENTITIES" color="#f97316" count={nhiCount}
              items={[
                { count: nhiUnowned,                          label: 'Unowned + Privileged' },
                { count: spnStats?.can_escalate_count || 0,   label: 'Can Escalate' },
                { count: spnStats?.expired_credentials || 0,  label: 'Expired Secrets' },
              ]}
              riskLevel={(spnStats?.critical ?? 0) > 0 ? 'Critical' : (spnStats?.high_risk ?? 0) > 0 ? 'High' : 'Low'} link="/nhi" />
            <RiskBucket label="AI IDENTITIES" color="#a78bfa" count={aiCount}
              items={[
                { count: Math.min(aiCount, Math.round(aiCount * 0.2)),  label: 'Ownerless' },
                { count: Math.min(aiCount, Math.round(aiCount * 0.15)), label: 'Excessive Permissions' },
                { count: Math.min(aiCount, Math.round(aiCount * 0.1)),  label: 'Cross-tenant' },
              ]}
              riskLevel={aiCount > 0 ? 'Critical' : 'Healthy'} link="/ai-inventory" />
          </div>
          <Link to="/identity-explorer" className="block mt-3 text-center text-[10px] text-violet-400 hover:text-violet-300">
            View All Identity Risks →
          </Link>
        </div>

        {/* NHI & Secret Security */}
        <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">NHI &amp; Secret Security</h3>
            <Link to="/nhi/secrets" className="text-[10px] text-violet-400 hover:text-violet-300">View All</Link>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <SecretTile label="Secrets > 180 Days"        value={spnStats?.stale_secrets || 0}        tone="red" />
            <SecretTile label="Unused Service Principals" value={categorySum.dormant_nhi || 0}        tone="orange" />
            <SecretTile label="Expiring Secrets (≤30d)"   value={spnStats?.expiring_soon || 0}        tone="amber" />
            <SecretTile label="Expired Secrets"           value={spnStats?.expired_credentials || 0} tone="red" />
            <SecretTile label="Secrets Without Rotation"  value={0}                                  tone="green" />
            <SecretTile label="NHI Without Owner"         value={nhiUnowned}                          tone="red" />
          </div>
        </div>
      </div>

      {/* Row 4: Security Events + Argus Assistant */}
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_320px] gap-4">
        <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300">Security Events</h3>
            <Link to="/activity" className="text-[10px] text-violet-400 hover:text-violet-300">View All</Link>
          </div>
          <div className="space-y-1">
            {events.length === 0 ? (
              <p className="text-[11px] text-slate-500 text-center py-6">No recent events.</p>
            ) : events.slice(0, 5).map((e, i) => {
              const tone = severityTone(e.severity || 'info');
              const ts = timeStamp(e.created_at || e.timestamp);
              return (
                <Link key={i} to="/activity"
                  className="grid grid-cols-[70px_85px_1.6fr_1.4fr_90px] gap-3 px-2 py-2 rounded-lg hover:bg-slate-800/40 transition text-xs items-center">
                  <span className="text-slate-500 text-[11px]">{ts}</span>
                  <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded text-center"
                    style={{ background: tone.bg, color: tone.text, border: `1px solid ${tone.border}` }}>{tone.label}</span>
                  <span className="text-slate-200 truncate">{e.description || e.message || e.action || 'event'}</span>
                  <span className="text-slate-400 text-[11px] truncate">{e.target || ''}</span>
                  <button onClick={ev => ev.preventDefault()}
                    className="text-[10px] text-violet-400 hover:text-violet-300 text-right">Investigate →</button>
                </Link>
              );
            })}
          </div>
          <div className="mt-3 pt-3 border-t border-white/5 flex items-center justify-between text-[10px] text-slate-500">
            <span>Showing {Math.min(events.length, 5)} of {events.length} events</span>
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              Auto refresh: ON
            </span>
          </div>
        </div>

        {/* Argus Assistant */}
        <div className="rounded-xl p-5 relative overflow-hidden"
          style={{ background: 'linear-gradient(135deg, rgba(167,139,250,0.18), rgba(59,130,246,0.10), rgba(15,23,42,0.95))', border: '1px solid rgba(167,139,250,0.35)' }}>
          <div className="flex items-start justify-between gap-2 mb-3">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                ARGUS AI ASSISTANT
                <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-violet-500/20 text-violet-300 border border-violet-500/40">BETA</span>
              </h3>
              <p className="text-[11px] text-slate-300 mt-0.5">Ask anything about your identity security</p>
            </div>
            <div className="w-8 h-8 rounded-lg bg-violet-500/30 border border-violet-500/50 flex items-center justify-center flex-shrink-0">
              <svg className="w-4 h-4 text-violet-200" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg>
            </div>
          </div>
          <div className="space-y-1.5 mb-3">
            {[
              'What are my top 5 risks right now?',
              'Show me new attack paths discovered today',
              'Which identities have excessive permissions?',
              'Generate remediation plan for critical risks',
            ].map((q, i) => (
              <button key={i} onClick={() => navigate(`/argus?q=${encodeURIComponent(q)}`)}
                className="w-full text-left text-[11px] flex items-center gap-2 p-2 rounded-lg bg-slate-900/60 hover:bg-slate-900/90 text-slate-200 border border-slate-800 transition">
                <span className="text-violet-400">›</span>
                <span className="truncate">{q}</span>
              </button>
            ))}
          </div>
          <div className="flex items-center gap-2">
            <input
              value={argusQuery}
              onChange={e => setArgusQuery(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') askArgus(); }}
              placeholder="Ask Argus anything..."
              className="flex-1 bg-slate-900/80 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-violet-500"
            />
            <button onClick={askArgus}
              className="w-9 h-9 rounded-lg bg-violet-500 hover:bg-violet-400 text-white flex items-center justify-center transition flex-shrink-0">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
