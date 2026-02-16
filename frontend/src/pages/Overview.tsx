import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { COLORS, RISK_COLORS, scoreToColor, scoreToGrade } from '../constants/design';
import { ComplianceBadgeGroup } from '../components/ComplianceBadge';
import { getFrameworkNames } from '../utils/complianceMapping';
import StaleDataBanner from '../components/StaleDataBanner';

// ── Types ──────────────────────────────────────────────────────────

interface StatsResponse {
  total_discovery_runs: number;
  latest_run: {
    id: number;
    completed_at: string | null;
    total_identities: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
  } | null;
  previous_run?: {
    id: number;
    total_identities: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
  } | null;
}

interface InsightsData {
  privilege_tiers?: { t0: number; t1: number; t2: number; t3: number; total: number; identities?: any[] };
  action_items?: { dormant_privileged: number; expiring_credentials: number; unowned_spns: number };
  dormant_count?: number;
  no_owner_count?: number;
}

interface TrendRun {
  run_id: number;
  date: string | null;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface PillarData {
  score: number;
  weight: number;
  detail: Record<string, number>;
}

interface AttackSurfaceData {
  score: number;
  grade: string;
  severity: string;
  pillars: {
    effective_privilege: PillarData;
    credential_risk: PillarData;
    trust_federation: PillarData;
    usage_dormancy: PillarData;
    ownership_governance: PillarData;
    external_exposure: PillarData;
  };
  total_identities: number;
}

// ── Component ──────────────────────────────────────────────────────

export default function Overview() {
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [insights, setInsights] = useState<InsightsData | null>(null);
  const [trends, setTrends] = useState<TrendRun[]>([]);
  const [posture, setPosture] = useState<any>(null);
  const [attackSurface, setAttackSurface] = useState<AttackSurfaceData | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const [statsRes, insightsRes] = await Promise.all([
          fetch('/api/stats'),
          fetch('/api/overview/insights'),
        ]);
        if (!statsRes.ok) throw new Error(`Stats API error: ${statsRes.status}`);
        const statsJson = await statsRes.json();
        const insightsJson = insightsRes.ok ? await insightsRes.json() : null;

        let trendsJson: TrendRun[] = [];
        try { const r = await fetch('/api/trends'); if (r.ok) { const d = await r.json(); trendsJson = d.runs || []; } } catch {}

        let postureJson = null;
        try { const r = await fetch('/api/dashboard/posture'); if (r.ok) postureJson = await r.json(); } catch {}

        let asJson: AttackSurfaceData | null = null;
        try { const r = await fetch('/api/overview/attack-surface-score'); if (r.ok) asJson = await r.json(); } catch {}

        if (!cancelled) {
          setStats(statsJson);
          setInsights(insightsJson);
          setTrends(trendsJson);
          setPosture(postureJson);
          setAttackSurface(asJson);
        }
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load overview');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  const latest = stats?.latest_run;
  const prev = stats?.previous_run;

  // ── Derived: Top 3 risk drivers ────────────────────────────────

  const riskDrivers = useMemo(() => {
    if (!insights) return [];
    const drivers: { title: string; affected: number; severity: string; category: string }[] = [];
    const ai = insights.action_items;

    if (ai) {
      if ((ai.unowned_spns ?? 0) > 0) drivers.push({ title: 'Unowned High-Privilege Service Principals', affected: ai.unowned_spns, severity: 'critical', category: 'unowned_spns' });
      if ((ai.dormant_privileged ?? 0) > 0) drivers.push({ title: 'Dormant Privileged Identities', affected: ai.dormant_privileged, severity: 'high', category: 'dormant_privileged' });
      if ((ai.expiring_credentials ?? 0) > 0) drivers.push({ title: 'Expiring Credentials', affected: ai.expiring_credentials, severity: 'medium', category: 'expiring_credentials' });
    }
    if (drivers.length < 3 && (insights.no_owner_count ?? 0) > 0) {
      drivers.push({ title: 'Identities Without Owner', affected: insights.no_owner_count ?? 0, severity: 'high', category: 'no_owner_assigned' });
    }
    return drivers.slice(0, 3);
  }, [insights]);

  // ── Derived: High privilege surface ────────────────────────────

  const privilegeSurface = useMemo(() => {
    const pt = insights?.privilege_tiers;
    if (!pt) return { t0t1: 0, total: 0, pct: 0 };
    const t0t1 = (pt.t0 ?? 0) + (pt.t1 ?? 0);
    const total = pt.total ?? 1;
    return { t0t1, total, pct: total > 0 ? Math.round((t0t1 / total) * 100) : 0 };
  }, [insights]);

  // ── Derived: Credential snapshot ───────────────────────────────

  const credSnapshot = useMemo(() => {
    const ch = posture?.credential_health;
    return {
      expired: ch?.expired ?? 0,
      expiring: ch?.expiring_soon ?? 0,
      healthy: ch?.healthy ?? 0,
      none: ch?.no_credentials ?? 0,
    };
  }, [posture]);

  // ── Loading / Error ────────────────────────────────────────────

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8" style={{ fontFamily: "'DM Sans', sans-serif" }}>
        <div className="animate-pulse space-y-5">
          <div className="h-[180px] rounded-2xl" style={{ backgroundColor: '#1E293B' }} />
          <div className="grid grid-cols-3 gap-4">
            {[1, 2, 3].map(i => <div key={i} className="h-28 rounded-xl" style={{ backgroundColor: COLORS.borderLight }} />)}
          </div>
          <div className="grid grid-cols-3 gap-4">
            {[1, 2, 3].map(i => <div key={i} className="h-32 rounded-xl" style={{ backgroundColor: COLORS.borderLight }} />)}
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8" style={{ fontFamily: "'DM Sans', sans-serif" }}>
        <div className="rounded-xl p-6" style={{ backgroundColor: RISK_COLORS.critical.bg, border: `1px solid ${COLORS.border}` }}>
          <div className="font-semibold" style={{ color: RISK_COLORS.critical.color }}>Error loading overview</div>
          <div className="text-sm mt-1" style={{ color: COLORS.textSecondary }}>{error}</div>
          <button onClick={() => window.location.reload()} className="mt-3 px-4 py-1.5 text-sm font-medium text-white rounded-lg" style={{ backgroundColor: COLORS.brandLight }}>Retry</button>
        </div>
      </div>
    );
  }

  const severityBorder = (s: string) =>
    s === 'critical' ? RISK_COLORS.critical.color : s === 'high' ? RISK_COLORS.high.color : RISK_COLORS.medium.color;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6" style={{ fontFamily: "'DM Sans', sans-serif" }}>

      {/* Page Header */}
      <div className="flex items-start justify-between mb-5">
        <div>
          <h2 className="text-[22px] font-extrabold tracking-tight" style={{ color: COLORS.textPrimary }}>Identity Attack Surface</h2>
          <p className="text-sm" style={{ color: COLORS.textSecondary }}>Executive risk snapshot across all cloud environments</p>
        </div>
        <div className="text-xs" style={{ color: COLORS.textMuted }}>
          {latest?.completed_at ? `Updated ${new Date(latest.completed_at).toLocaleString()}` : 'No data yet'}
        </div>
      </div>

      <StaleDataBanner completedAt={latest?.completed_at} />

      {/* ── Block 1: Attack Surface Score Hero ─────────────────────── */}
      <div
        className="rounded-2xl p-8 mb-5 flex items-center gap-10"
        style={{ background: 'linear-gradient(135deg, #0F172A 0%, #1E293B 50%, #1E3A5F 100%)', minHeight: 180 }}
      >
        {/* Arc Gauge */}
        <div className="flex-shrink-0">
          <ArcGauge score={attackSurface?.score ?? null} grade={attackSurface?.grade ?? null} />
        </div>
        <div className="flex-1">
          <div className="text-lg font-bold text-white mb-1">Identity Attack Surface Score</div>
          <p className="text-xs text-slate-400 mb-4 max-w-xl leading-relaxed">
            6-pillar weighted score: effective privilege, credential exposure, trust relationships, usage dormancy, ownership governance, and external exposure.
          </p>
          <div className="flex items-center gap-8">
            <div>
              <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-0.5">Identities</div>
              <div className="text-xl font-bold text-white">{latest?.total_identities ?? 0}</div>
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-0.5">Critical</div>
              <div className="text-xl font-bold" style={{ color: RISK_COLORS.critical.color }}>{latest?.critical_count ?? 0}</div>
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-0.5">High</div>
              <div className="text-xl font-bold" style={{ color: RISK_COLORS.high.color }}>{latest?.high_count ?? 0}</div>
            </div>
            {prev && (
              <div>
                <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-0.5">30-Day Trend</div>
                <div className="flex items-center gap-1 text-sm font-semibold">
                  {(() => {
                    const delta = (latest?.critical_count ?? 0) - (prev.critical_count ?? 0);
                    if (delta > 0) return <span style={{ color: RISK_COLORS.critical.color }}>↑ +{delta} critical</span>;
                    if (delta < 0) return <span style={{ color: RISK_COLORS.low.color }}>↓ {delta} critical</span>;
                    return <span className="text-slate-400">→ No change</span>;
                  })()}
                </div>
              </div>
            )}
          </div>
          {/* Pillar mini-bars */}
          {attackSurface && (
            <div className="flex items-center gap-4 mt-4">
              {PILLAR_LABELS.map(p => {
                const pillar = attackSurface.pillars[p.key as keyof typeof attackSurface.pillars];
                return (
                  <div key={p.key} className="flex-1">
                    <div className="flex items-center justify-between mb-0.5">
                      <span className="text-[9px] uppercase tracking-wider text-slate-500">{p.short}</span>
                      <span className="text-[10px] font-bold" style={{ color: scoreToColor(pillar.score) }}>{Math.round(pillar.score)}</span>
                    </div>
                    <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: '#334155' }}>
                      <div className="h-full rounded-full transition-all duration-700" style={{ width: `${Math.min(pillar.score, 100)}%`, backgroundColor: scoreToColor(pillar.score) }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* ── Block 2: Top 3 Risk Drivers ───────────────────────────── */}
      {riskDrivers.length > 0 && (
        <div className="mb-5">
          <div className="text-[14px] font-bold mb-3" style={{ color: COLORS.textPrimary }}>Top Risk Drivers</div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
            {riskDrivers.map((d, i) => (
              <div
                key={i}
                className="bg-white rounded-xl p-4"
                style={{ border: `1px solid ${COLORS.border}`, borderLeft: `4px solid ${severityBorder(d.severity)}` }}
              >
                <div className="text-[13px] font-bold mb-2 line-clamp-2" style={{ color: COLORS.textPrimary }}>{d.title}</div>
                <div className="flex items-center gap-5 mb-2">
                  <div>
                    <div className="text-[10px] uppercase tracking-wider" style={{ color: COLORS.textMuted }}>Affected</div>
                    <div className="text-lg font-bold" style={{ color: COLORS.textPrimary }}>{d.affected}</div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase tracking-wider" style={{ color: COLORS.textMuted }}>Severity</div>
                    <span className="inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase"
                      style={{ color: severityBorder(d.severity), backgroundColor: `${severityBorder(d.severity)}14` }}>
                      {d.severity}
                    </span>
                  </div>
                </div>
                <ComplianceBadgeGroup frameworks={getFrameworkNames(d.category)} />
                <button onClick={() => navigate(`/identities`)} className="mt-2 text-[12px] font-medium" style={{ color: COLORS.brandLight }}>
                  View Details →
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Blocks 3, 4, 5: Three-column grid ────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5 mb-5">

        {/* Block 3: High Privilege Surface */}
        <div className="bg-white rounded-xl p-5" style={{ border: `1px solid ${COLORS.border}` }}>
          <div className="text-[14px] font-bold mb-3" style={{ color: COLORS.textPrimary }}>High Privilege Surface</div>
          <div className="text-4xl font-extrabold mb-1" style={{ color: privilegeSurface.pct > 5 ? RISK_COLORS.critical.color : privilegeSurface.pct > 1 ? RISK_COLORS.high.color : RISK_COLORS.low.color }}>
            {privilegeSurface.pct}%
          </div>
          <div className="text-[12px] mb-2" style={{ color: COLORS.textSecondary }}>
            {privilegeSurface.t0t1} of {privilegeSurface.total} identities are T0 or T1
          </div>
          <div className="text-[11px] px-2 py-1 rounded inline-block" style={{ color: COLORS.textMuted, backgroundColor: COLORS.borderLight }}>
            Recommended: &lt;1%
          </div>
        </div>

        {/* Block 4: Credential Exposure Snapshot */}
        <div className="bg-white rounded-xl p-5" style={{ border: `1px solid ${COLORS.border}` }}>
          <div className="text-[14px] font-bold mb-3" style={{ color: COLORS.textPrimary }}>Credential Exposure</div>
          <div className="space-y-2.5">
            <MetricRow label="Expired Secrets" value={credSnapshot.expired} color={credSnapshot.expired > 0 ? RISK_COLORS.critical.color : RISK_COLORS.low.color} />
            <MetricRow label="Expiring <30 Days" value={credSnapshot.expiring} color={credSnapshot.expiring > 0 ? RISK_COLORS.high.color : RISK_COLORS.low.color} />
            <MetricRow label="Healthy Credentials" value={credSnapshot.healthy} color={RISK_COLORS.low.color} />
            <MetricRow label="No Credentials" value={credSnapshot.none} color={COLORS.textMuted} />
          </div>
          {/* Stacked bar */}
          {(credSnapshot.expired + credSnapshot.expiring + credSnapshot.healthy + credSnapshot.none) > 0 && (
            <div className="flex h-2 rounded-full overflow-hidden mt-3">
              {credSnapshot.expired > 0 && <div style={{ flex: credSnapshot.expired, backgroundColor: RISK_COLORS.critical.color }} />}
              {credSnapshot.expiring > 0 && <div style={{ flex: credSnapshot.expiring, backgroundColor: RISK_COLORS.high.color }} />}
              {credSnapshot.healthy > 0 && <div style={{ flex: credSnapshot.healthy, backgroundColor: RISK_COLORS.low.color }} />}
              {credSnapshot.none > 0 && <div style={{ flex: credSnapshot.none, backgroundColor: '#E2E8F0' }} />}
            </div>
          )}
        </div>

        {/* Block 5: Trust & Ownership */}
        <div className="bg-white rounded-xl p-5" style={{ border: `1px solid ${COLORS.border}` }}>
          <div className="text-[14px] font-bold mb-3" style={{ color: COLORS.textPrimary }}>Trust & Ownership</div>
          {attackSurface ? (() => {
            const tp = attackSurface.pillars.trust_federation.detail;
            const op = attackSurface.pillars.ownership_governance.detail;
            const ownedPct = op.total_spns > 0 ? Math.round(((op.total_spns - op.unowned_spns) / op.total_spns) * 100) : 100;
            return (
              <div className="space-y-2.5">
                <MetricRow label="Guest Identities" value={tp.guests ?? 0} color={tp.guests > 0 ? RISK_COLORS.medium.color : COLORS.textMuted} />
                <MetricRow label="Guests with Roles" value={tp.guest_with_roles ?? 0} color={tp.guest_with_roles > 0 ? RISK_COLORS.high.color : COLORS.textMuted} />
                <MetricRow label="Federated Identities" value={tp.federated ?? 0} color={tp.federated > 0 ? RISK_COLORS.medium.color : COLORS.textMuted} />
                <MetricRow label="Unowned SPNs" value={op.unowned_spns ?? 0} color={op.unowned_spns > 0 ? RISK_COLORS.high.color : RISK_COLORS.low.color} />
                <div className="pt-1 mt-1" style={{ borderTop: `1px solid ${COLORS.borderLight}` }}>
                  <div className="flex items-center justify-between">
                    <span className="text-[11px]" style={{ color: COLORS.textSecondary }}>Ownership Coverage</span>
                    <span className="text-[14px] font-bold" style={{
                      color: ownedPct >= 90 ? RISK_COLORS.low.color : ownedPct >= 70 ? RISK_COLORS.medium.color : RISK_COLORS.critical.color
                    }}>{ownedPct}%</span>
                  </div>
                </div>
              </div>
            );
          })() : (
            <div className="space-y-2.5">
              <MetricRow label="Guest Identities" value={0} color={COLORS.textMuted} />
              <MetricRow label="Unowned SPNs" value={0} color={COLORS.textMuted} />
            </div>
          )}
        </div>
      </div>

      {/* ── Block 6: 30-Day Trend Snapshot ────────────────────────── */}
      <div className="bg-white rounded-xl p-4" style={{ border: `1px solid ${COLORS.border}` }}>
        <div className="text-[14px] font-bold mb-2" style={{ color: COLORS.textPrimary }}>30-Day Trend</div>
        {trends.length >= 2 ? (
          <div className="flex items-center gap-6">
            {/* Mini inline bar chart */}
            <div className="flex items-end gap-1 h-[50px]">
              {trends.slice(-8).map((t, i) => {
                const maxTotal = Math.max(...trends.slice(-8).map(r => r.total), 1);
                return (
                  <div key={i} className="flex flex-col items-center gap-0.5">
                    <div
                      className="w-5 rounded-sm"
                      style={{
                        height: `${Math.max((t.total / maxTotal) * 40, 4)}px`,
                        backgroundColor: t.critical > 0 ? RISK_COLORS.critical.color : t.high > 0 ? RISK_COLORS.high.color : RISK_COLORS.low.color,
                        opacity: 0.7 + (i / 8) * 0.3,
                      }}
                    />
                    <div className="text-[8px]" style={{ color: COLORS.textMuted }}>
                      {t.date ? new Date(t.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : ''}
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="flex items-center gap-6 text-sm">
              <TrendDelta label="Critical" current={latest?.critical_count ?? 0} previous={prev?.critical_count} invertColor />
              <TrendDelta label="High" current={latest?.high_count ?? 0} previous={prev?.high_count} invertColor />
              <TrendDelta label="Total" current={latest?.total_identities ?? 0} previous={prev?.total_identities} />
            </div>
          </div>
        ) : (
          <div className="text-[12px] py-2" style={{ color: COLORS.textMuted }}>Need at least 2 discovery runs for trend data</div>
        )}
      </div>
    </div>
  );
}

// ── Constants ─────────────────────────────────────────────────────

const PILLAR_LABELS = [
  { key: 'effective_privilege', short: 'Privilege' },
  { key: 'credential_risk', short: 'Creds' },
  { key: 'trust_federation', short: 'Trust' },
  { key: 'usage_dormancy', short: 'Usage' },
  { key: 'ownership_governance', short: 'Ownership' },
  { key: 'external_exposure', short: 'Exposure' },
];

// ── Sub-components ─────────────────────────────────────────────────

function ArcGauge({ score, grade }: { score: number | null; grade: string | null }) {
  const size = 170;
  const cx = size / 2;
  const cy = size / 2;
  const r = 65;
  const startAngle = 135;       // bottom-left
  const endAngle = 405;         // bottom-right (270 deg arc)
  const arcLen = endAngle - startAngle; // 270 degrees

  const pct = score != null ? Math.min(score, 100) / 100 : 0;
  const color = score != null ? scoreToColor(score) : '#475569';
  const gradeLabel = grade ?? '—';

  // Convert angle to radians for SVG arc
  function angleToXY(angle: number) {
    const rad = (angle * Math.PI) / 180;
    return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
  }

  // Build arc path
  function arcPath(start: number, sweep: number) {
    const s = angleToXY(start);
    const e = angleToXY(start + sweep);
    const largeArc = sweep > 180 ? 1 : 0;
    return `M ${s.x} ${s.y} A ${r} ${r} 0 ${largeArc} 1 ${e.x} ${e.y}`;
  }

  const bgPath = arcPath(startAngle, arcLen);
  const fgPath = arcPath(startAngle, arcLen * pct);

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      {/* Background track */}
      <path d={bgPath} stroke="#334155" strokeWidth="12" fill="none" strokeLinecap="round" />
      {/* Filled arc */}
      {score != null && pct > 0 && (
        <path d={fgPath} stroke={color} strokeWidth="12" fill="none" strokeLinecap="round"
          style={{ transition: 'all 1s ease-in-out' }} />
      )}
      {/* Score number */}
      <text x={cx} y={cy - 6} textAnchor="middle" fill={score != null ? color : '#94A3B8'} fontSize="36" fontWeight="800">
        {score != null ? Math.round(score) : '—'}
      </text>
      {/* Grade label */}
      <text x={cx} y={cy + 18} textAnchor="middle" fill="#94A3B8" fontSize="14" fontWeight="600">
        {score != null ? `Grade ${gradeLabel}` : 'No Data'}
      </text>
      {/* Scale labels */}
      <text x={cx - 58} y={cy + 52} textAnchor="middle" fill="#475569" fontSize="9">0</text>
      <text x={cx + 58} y={cy + 52} textAnchor="middle" fill="#475569" fontSize="9">100</text>
    </svg>
  );
}

function MetricRow({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-[12px]" style={{ color: COLORS.textSecondary }}>{label}</span>
      <span className="text-[14px] font-bold" style={{ color }}>{value}</span>
    </div>
  );
}

function TrendDelta({ label, current, previous, invertColor }: { label: string; current: number; previous?: number; invertColor?: boolean }) {
  const delta = previous != null ? current - previous : undefined;
  let color: string = COLORS.textMuted;
  let arrow = '→';
  if (delta != null && delta > 0) { arrow = '↑'; color = invertColor ? RISK_COLORS.critical.color : COLORS.textMuted; }
  if (delta != null && delta < 0) { arrow = '↓'; color = invertColor ? RISK_COLORS.low.color : COLORS.textMuted; }

  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: COLORS.textMuted }}>{label}</div>
      <div className="flex items-center gap-1">
        <span className="font-bold" style={{ color: COLORS.textPrimary }}>{current}</span>
        {delta != null && (
          <span className="text-[11px] font-medium" style={{ color }}>
            {arrow} {delta > 0 ? '+' : ''}{delta}
          </span>
        )}
      </div>
    </div>
  );
}
