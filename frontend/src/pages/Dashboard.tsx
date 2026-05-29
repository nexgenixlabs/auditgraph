/**
 * AuditGraph — Risk Monitoring Dashboard
 *
 * Single scrollable page with 7 sections:
 *   1. Header (Risk Monitoring + SOC badge + Capture Snapshot + View Alerts)
 *   2. Active Identity Alerts (AnomalyAlerts)
 *   3. Risk Trend + Velocity (side-by-side)
 *   4. Identity Risk Heat Map + Distribution (side-by-side)
 *   5. Snapshot Drift Analysis (RecentChanges)
 *   6. Machine Identity Exposure (inline)
 *   7. Credential Intelligence (CredentialHealth + CredentialIntelligence)
 *
 * No tabs. No metric overlap with / (Executive Posture).
 * All data from 8 API calls — no compliance, governance, or AGIRS data.
 */
import React, { useEffect, useMemo, useState, useCallback } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { EXPOSURE_LEVEL_CONFIG, getCategoriesForClouds } from '../constants/metrics';
import { COLORS } from '../constants/design';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';
import { formatDate } from '../utils/displayHelpers';
import { DiscoveryProgressModal } from '../components/settings/DiscoveryProgressModal';

import {
  RiskHeatMap, RiskDonutChart, CredentialHealth,
  RecentChanges, RiskTrendChart,
  AnomalyAlerts, RiskVelocityChart,
} from '../components/dashboard';
import { COLORS as CISO_COLORS, getScoreColor, getTierColor } from '../constants/ciso';
import { FONT, Sparkline, CISOBadge } from '../components/dashboard/ciso-shared';
import CredentialIntelligence from '../components/dashboard/CredentialIntelligence';
import AttackSurfaceTile from '../components/dashboard/AttackSurfaceTile';
import RemediationTile from '../components/dashboard/RemediationTile';
import StaleDataBanner from '../components/StaleDataBanner';
import AudienceBadge from '../components/AudienceBadge';
import { useToast } from '../components/ToastProvider';


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
  ghost_count?: number;
  disabled_count?: number;
  deleted_count?: number;
  customer_count?: number;
  microsoft_count?: number;
  total_including_microsoft?: number;
  workload_exposure?: {
    total: number; critical: number; orphaned: number;
    can_escalate: number; anomalies_unresolved: number;
    exposure_distribution?: { critical: number; high: number; medium: number; low: number };
    blind_count?: number; avg_exposure_score?: number;
  };
}

interface IdentitySummaryResponse {
  run_id: number;
  completed_at: string | null;
  categories: Record<
    string,
    { total: number; critical: number; high: number; medium: number; low: number; info: number; unknown: number }
  >;
  monitored_resources?: {
    azure: { subscriptions: number; subscription_ids: string[] };
    aws: { accounts: number; account_ids: string[] };
    gcp: { projects: number; project_ids: string[] };
  };
}

interface PostureResponse {
  current_run: {
    id: number;
    completed_at: string | null;
    total_identities: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
  };
  previous_run: {
    id: number;
    completed_at: string | null;
    total_identities: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
  } | null;
  posture_score: number;
  previous_posture_score: number | null;
  credential_health: {
    expired: number;
    expiring_soon: number;
    healthy: number;
    no_credentials: number;
  };
  dormant_count: number;
  no_owner_count: number;
  expiring_credentials_count: number;
}

// ── Component ──────────────────────────────────────────────────────

export default function Dashboard() {
  const navigate = useNavigate();
  const { addToast } = useToast();
  const { connections, withConnection, selectedConnectionId } = useConnection();
  const { activeOrgId } = useAuth();

  // Connection scope label for header
  const scopeLabel = selectedConnectionId
    ? connections.find(c => c.id === selectedConnectionId)?.label || `Connection ${selectedConnectionId}`
    : connections.length > 1 ? 'All Connections' : connections[0]?.label || '';

  // Data state
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [summary, setSummary] = useState<IdentitySummaryResponse | null>(null);
  const [posture, setPosture] = useState<PostureResponse | null>(null);
  const [anomalyData, setAnomalyData] = useState<{ anomalies: any[]; unresolved_count: number } | null>(null);
  const [driftData, setDriftData] = useState<any>(null);
  const [trends, setTrends] = useState<Array<{ run_id: number; date: string | null; total: number; critical: number; high: number; medium: number; low: number; dormant: number }>>([]);
  const [velocityData, setVelocityData] = useState<{
    transitions: Array<{
      run_id: number; date: string | null; prev_run_id: number;
      inflow: Record<string, number>; outflow: Record<string, number>; net: Record<string, number>;
    }>;
    retention: Record<string, { retained: number; total: number; rate: number }>;
  } | null>(null);
  const [enabledClouds, setEnabledClouds] = useState<string[]>([]);
  const [snapshotRunning, setSnapshotRunning] = useState(false);
  const [agirsSummary, setAgirsSummary] = useState<{ score: number; tier: string } | null>(null);
  const [agirsTrend, setAgirsTrend] = useState<number[]>([]);

  // ── Data Fetching (8 API calls) ─────────────────────────────────

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const [statsRes, summaryRes, postureRes] = await Promise.all([
          fetch(withConnection('/api/stats')),
          fetch(withConnection('/api/identity-summary')),
          fetch(withConnection('/api/dashboard/posture')),
        ]);

        if (!statsRes.ok) throw new Error(`Stats API error: ${statsRes.status}`);
        if (!summaryRes.ok) throw new Error(`Summary API error: ${summaryRes.status}`);

        const [statsJson, summaryJson] = await Promise.all([
          statsRes.json().catch(() => ({})),
          summaryRes.json().catch(() => ({})),
        ]);

        let postureJson: PostureResponse | null = null;
        if (postureRes.ok) postureJson = await postureRes.json().catch(() => null);

        let anomalyJson = null;
        try { const r = await fetch(withConnection('/api/dashboard/anomalies')); if (r.ok) anomalyJson = await r.json(); } catch {}

        let driftJson = null;
        try { const r = await fetch(withConnection('/api/drift/latest')); if (r.ok) driftJson = await r.json(); } catch {}

        let trendsJson: typeof trends = [];
        try { const r = await fetch(withConnection('/api/trends')); if (r.ok) { const d = await r.json(); trendsJson = d.runs || []; } } catch {}

        let velocityJson = null;
        try { const r = await fetch(withConnection('/api/trends/velocity')); if (r.ok) velocityJson = await r.json(); } catch {}

        let cloudCfg: string[] = [];
        try {
          const r = await fetch('/api/tenant/config');
          if (r.ok) {
            const cfg = await r.json();
            cloudCfg = ['azure', 'aws', 'gcp'].filter(k => cfg?.cloud_providers?.[k]?.enabled);
          }
        } catch {}

        // AGIRS summary for compact widget
        let agirsData: { score: number; tier: string } | null = null;
        try {
          const r = await fetch(withConnection('/api/identity-risk-summary'));
          if (r.ok) {
            const d = await r.json();
            if (d?.agirs) {
              agirsData = { score: d.agirs.score ?? 0, tier: d.agirs.tier ?? 'Unknown' };
            }
          }
        } catch {}

        if (!cancelled) {
          setStats(statsJson);
          setSummary(summaryJson);
          setPosture(postureJson);
          setAnomalyData(anomalyJson);
          setDriftData(driftJson);
          setTrends(trendsJson);
          setVelocityData(velocityJson);
          setEnabledClouds(cloudCfg);
          setAgirsSummary(agirsData);
          setAgirsTrend(trendsJson.map((r: any) => r.posture_score ?? r.total ?? 0).filter((v: number) => v > 0));
        }
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load dashboard');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => { cancelled = true; };
  }, [selectedConnectionId, activeOrgId]);

  // ── Derived Data ───────────────────────────────────────────────

  const latest = stats?.latest_run;

  const categoryCards = useMemo(() => {
    const categories = summary?.categories || {};
    const displayOrder = getCategoriesForClouds(enabledClouds);
    return displayOrder.map((key) => {
      const v = categories[key] || { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
      return { key, ...v };
    });
  }, [summary, enabledClouds]);

  const riskCounts = useMemo(() => {
    const cats = summary?.categories || {};
    let critical = 0, high = 0, medium = 0, low = 0, info = 0, total = 0;
    Object.values(cats).forEach((cat: any) => {
      critical += cat.critical || 0;
      high += cat.high || 0;
      medium += cat.medium || 0;
      low += cat.low || 0;
      info += cat.info || 0;
      total += cat.total || 0;
    });
    return { critical, high, medium, low, info, total };
  }, [summary]);

  const handleSegmentClick = (level: string) => {
    navigate(`/identities?risk_level=${level}`);
  };

  // ── Snapshot Trigger + Progress Modal ──────────────────────

  const [showProgressModal, setShowProgressModal] = useState(false);

  const triggerSnapshot = useCallback(async () => {
    if (snapshotRunning) {
      // Already running — just re-open modal
      setShowProgressModal(true);
      return;
    }
    setSnapshotRunning(true);
    try {
      const connId = selectedConnectionId || undefined;
      const payload: Record<string, unknown> = {};
      if (connId) payload.connection_id = connId;
      const res = await fetch('/api/runs/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok && res.status !== 409) throw new Error('Trigger failed');
    } catch (e: any) {
      addToast(e?.message || 'Failed to trigger snapshot', 'error');
      setSnapshotRunning(false);
      return;
    }
    // Always open modal
    setShowProgressModal(true);
  }, [addToast, snapshotRunning, selectedConnectionId]);

  // ── Render ─────────────────────────────────────────────────────

  return (
    <div className="w-full px-4 sm:px-5 lg:px-6 py-6" style={{ fontFamily: "'Inter', sans-serif" }}>
      {/* Section 1: Header */}
      <div className="flex items-start justify-between gap-4 mb-5">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-[22px] font-extrabold tracking-tight" style={{ color: COLORS.textPrimary }}>Risk Monitoring</h2>
            <AudienceBadge label="SOC / IAM OPS" variant="blue" />
            {scopeLabel && (
              <span className="text-[9px] font-semibold px-1.5 py-0.5 rounded" style={{
                background: selectedConnectionId ? `${COLORS.accentPrimary}18` : `${COLORS.textMuted}15`,
                color: selectedConnectionId ? COLORS.accentPrimary : COLORS.textMuted,
                border: `1px solid ${selectedConnectionId ? COLORS.accentPrimary : COLORS.textMuted}30`,
                fontFamily: "'JetBrains Mono', monospace",
              }}>{scopeLabel}</span>
            )}
          </div>
          <p className="text-sm" style={{ color: COLORS.textSecondary }}>
            Operational identity risk monitoring — What happened?
          </p>
          {latest?.completed_at && (
            <div className="flex items-center gap-2 mt-0.5 flex-wrap">
              <p className="text-xs" style={{ color: COLORS.textMuted }}>
                Data as of {formatDate(latest.completed_at, 'No data')} · Snapshot #{stats?.latest_run?.id}
              </p>
              {stats?.customer_count != null && (
                <span className="text-[10px]" style={{ color: COLORS.textMuted }}>
                  {stats.latest_run?.total_identities} total &middot; {stats.customer_count} customer &middot; {stats.microsoft_count} Microsoft
                </span>
              )}
              <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-700 text-[9px] font-semibold uppercase tracking-wide" title="Snapshot data is immutable">
                <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
                Immutable
              </span>
              <button onClick={() => navigate('/drift')} className="text-[10px] text-blue-500 hover:text-blue-700 font-medium">
                Compare Snapshots →
              </button>
            </div>
          )}
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={triggerSnapshot}
            className={`inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg border transition ${
              snapshotRunning
                ? 'bg-blue-50 text-blue-600 cursor-pointer border-blue-200 hover:bg-blue-100'
                : 'text-white hover:opacity-90 border-transparent'
            }`}
            style={snapshotRunning ? {} : { backgroundColor: COLORS.brand }}
          >
            {snapshotRunning ? (
              <>
                <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg>
                Running... (view)
              </>
            ) : (
              <>
                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
                Capture Snapshot
              </>
            )}
          </button>
          <button
            onClick={() => document.getElementById('anomaly-alerts')?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-sm font-medium rounded-lg border transition"
            style={{ borderColor: '#f59e0b', color: '#f59e0b' }}
            onMouseEnter={e => { (e.currentTarget as any).style.backgroundColor = 'rgba(245,158,11,0.08)'; }}
            onMouseLeave={e => { (e.currentTarget as any).style.backgroundColor = 'transparent'; }}
          >
            View Alerts
            {(anomalyData?.unresolved_count ?? 0) > 0 && (
              <span className="inline-flex items-center justify-center px-1.5 py-0.5 text-xs font-bold rounded-full" style={{ backgroundColor: 'rgba(245,158,11,0.15)', color: '#f59e0b', minWidth: 20 }}>
                {anomalyData?.unresolved_count}
              </span>
            )}
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
          </button>
        </div>
      </div>

      <StaleDataBanner completedAt={latest?.completed_at} />

      {loading ? (
        <div className="animate-pulse space-y-4">
          <div className="grid grid-cols-3 gap-4">
            {[1, 2, 3].map(i => <div key={i} className="h-48 rounded-xl" style={{ backgroundColor: COLORS.borderLight }} />)}
          </div>
        </div>
      ) : error ? (
        <div className="bg-white rounded-xl p-6 text-red-600" style={{ border: `1px solid ${COLORS.border}` }}>{error}</div>
      ) : (
        <div className="space-y-6">
          {/* Sticky section nav — Risk Monitoring is intentionally section-rich
              (the SOC needs all of these views), so instead of hiding sections
              we give the operator one-click navigation. Sticks below the global
              header (56px) so it's always reachable while scrolling. */}
          <nav
            className="sticky z-20 -mx-4 sm:-mx-5 lg:-mx-6 px-4 sm:px-5 lg:px-6 py-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs font-medium border-y bg-white/95 backdrop-blur"
            style={{ top: 'var(--header-height, 56px)', borderColor: COLORS.border }}
            aria-label="Risk Monitoring sections"
          >
            <span style={{ color: COLORS.textMuted }}>Jump to:</span>
            <a href="#anomaly-alerts" className="text-blue-600 hover:underline">Alerts</a>
            <a href="#risk-trend" className="text-blue-600 hover:underline">Trend</a>
            <a href="#risk-heatmap" className="text-blue-600 hover:underline">Heat Map</a>
            <a href="#drift-analysis" className="text-blue-600 hover:underline">Drift</a>
            <a href="#attack-surface" className="text-blue-600 hover:underline">Attack Surface</a>
            <a href="#machine-identity" className="text-blue-600 hover:underline">Machine ID</a>
            <a href="#credentials" className="text-blue-600 hover:underline">Credentials</a>
          </nav>

          {/* Section 2: Active Identity Alerts */}
          <div id="anomaly-alerts" className="scroll-mt-24">
            <AnomalyAlerts anomalies={anomalyData?.anomalies ?? []} unresolvedCount={anomalyData?.unresolved_count ?? 0} loading={loading} />
          </div>

          {/* Section 3: Risk Trend + Velocity */}
          <div id="risk-trend" className="scroll-mt-24 grid grid-cols-1 md:grid-cols-2 gap-6">
            {trends.length >= 2 && <RiskTrendChart data={trends} />}
            {velocityData && velocityData.transitions.length > 0 && (
              <RiskVelocityChart transitions={velocityData.transitions} retention={velocityData.retention} />
            )}
          </div>

          {/* Section 4: Identity Risk Heat Map + Distribution */}
          <div id="risk-heatmap" className="scroll-mt-24 grid grid-cols-1 md:grid-cols-2 gap-6">
            <RiskHeatMap categories={categoryCards} />
            <RiskDonutChart counts={riskCounts} onSegmentClick={handleSegmentClick}
              cloudSources={summary?.monitored_resources ? Object.entries(summary.monitored_resources).filter(([, v]) => (v as any)?.subscriptions > 0 || (v as any)?.accounts > 0 || (v as any)?.projects > 0).map(([k]) => k) : undefined} />
          </div>

          {/* Section 5: Snapshot Drift Analysis */}
          <div id="drift-analysis" className="scroll-mt-24">
            <RecentChanges hasData={driftData?.has_drift_data ?? false} currentRunId={driftData?.current_run_id} previousRunId={driftData?.previous_run_id}
              newIdentities={driftData?.new_identities_count ?? 0} removedIdentities={driftData?.removed_identities_count ?? 0}
              permissionChanges={driftData?.permission_changes_count ?? 0} riskChanges={driftData?.risk_changes_count ?? 0}
              credentialChanges={driftData?.credential_changes_count ?? 0} totalChanges={driftData?.total_changes ?? 0} createdAt={driftData?.created_at} />
          </div>

          {/* Section 5b: Attack Surface + Remediation */}
          <div id="attack-surface" className="scroll-mt-24 grid grid-cols-1 md:grid-cols-2 gap-4">
            <AttackSurfaceTile />
            <RemediationTile />
          </div>

          {/* Section 6: Machine Identity Exposure */}
          {stats?.workload_exposure && stats.workload_exposure.total > 0 && (
            <div id="machine-identity" className="scroll-mt-24 bg-white rounded-xl p-5" style={{ border: `1px solid ${COLORS.border}` }}>
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold" style={{ color: COLORS.textPrimary }}>
                  Machine Identity Exposure
                </h3>
                <Link to="/workload-identities" className="text-xs font-medium hover:underline"
                  style={{ color: COLORS.brand }}>View All →</Link>
              </div>
              {stats.workload_exposure.exposure_distribution && (
                <ExposureDistributionBar distribution={stats.workload_exposure.exposure_distribution} total={stats.workload_exposure.total}
                  onSegmentClick={k => navigate(`/workload-identities?exposure=${k}`)} />
              )}
              <div className="grid grid-cols-4 gap-3 mt-3">
                <MiniStat label="Total" value={stats.workload_exposure.total}
                  onClick={() => navigate('/workload-identities')} title="View all workload identities" />
                <MiniStat label="Avg Score" value={stats.workload_exposure.avg_exposure_score ?? '\u2014'} warn={(stats.workload_exposure.avg_exposure_score ?? 0) >= 50}
                  onClick={() => navigate('/workload-identities')} title="View workload identities" />
                <MiniStat label="Orphaned" value={stats.workload_exposure.orphaned} warn={stats.workload_exposure.orphaned > 0}
                  onClick={() => navigate('/workload-identities?owner=orphaned')} title="View orphaned identities" />
                <MiniStat label="Can Escalate" value={stats.workload_exposure.can_escalate} warn={stats.workload_exposure.can_escalate > 0}
                  onClick={() => navigate('/workload-identities?escalate=true')} title="View identities that can escalate" />
              </div>
            </div>
          )}

          {/* Section 7: Credential Intelligence */}
          <div id="credentials" className="scroll-mt-24 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {posture && (
                <CredentialHealth expired={posture.credential_health.expired} expiringSoon={posture.credential_health.expiring_soon}
                  healthy={posture.credential_health.healthy} noCredentials={posture.credential_health.no_credentials} />
              )}
            </div>
            <CredentialIntelligence />
          </div>

          {/* Posture Trend (compact) */}
          {agirsSummary && (
            <div className="bg-white rounded-xl p-4" style={{ border: `1px solid ${COLORS.border}` }}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div>
                    <div className="text-[10px] font-semibold uppercase tracking-wider flex items-center gap-1" style={{ color: COLORS.textMuted }}>
                      Posture Score
                      <span className="relative group">
                        <span className="cursor-help" style={{ fontSize: 14, color: COLORS.textMuted, opacity: 0.6 }}>{'\u24D8'}</span>
                        <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1.5 hidden group-hover:block text-[10px] px-2.5 py-1.5 rounded-md max-w-[280px] whitespace-normal z-50 shadow-lg pointer-events-none leading-relaxed" style={{ background: '#0f172a', border: `1px solid ${COLORS.border}`, color: '#e2e8f0' }}>
                          Identity Posture Score — measures your identity attack surface across 7 pillars: privilege, dormancy, credentials, ownership, trust, federation, and external exposure. Score of 100 = zero identity risk.
                        </span>
                      </span>
                    </div>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-2xl font-bold" style={{ fontFamily: FONT.mono, color: getScoreColor(agirsSummary.score) }}>{agirsSummary.score.toFixed(1)}</span>
                      <CISOBadge label={agirsSummary.tier} color={getTierColor(agirsSummary.tier)} />
                    </div>
                  </div>
                  {agirsTrend.length >= 2 && (
                    <Sparkline data={agirsTrend} width={200} height={50} color={getScoreColor(agirsSummary.score)} />
                  )}
                </div>
                <Link to="/" className="text-xs font-medium hover:underline" style={{ color: COLORS.brand }}>
                  Executive Posture {'\u2192'}
                </Link>
              </div>
            </div>
          )}

          {/* Data Integrity Footer */}
          <div className="flex items-center justify-between px-4 py-3 rounded-lg" style={{ backgroundColor: '#F8FAFC', border: `1px solid ${COLORS.border}` }}>
            <div className="flex items-center gap-2">
              <svg className="w-3.5 h-3.5 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              <span className="text-[10px]" style={{ color: COLORS.textSecondary }}>
                Snapshot-only data {'\u2022'} Tenant-isolated {'\u2022'} No cross-org visibility
              </span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-[10px]" style={{ color: COLORS.textMuted }}>
                Snapshot: <span className="font-semibold" style={{ color: COLORS.textPrimary }}>#{stats?.latest_run?.id || '\u2014'}</span>
              </span>
              <span className="text-[10px]" style={{ color: COLORS.textMuted }}>
                Identities: <span className="font-semibold" style={{ color: COLORS.textPrimary }}>{riskCounts.total}</span>
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Discovery Progress Modal */}
      {showProgressModal && (
        <DiscoveryProgressModal
          connectionId={selectedConnectionId || undefined}
          connectionLabel={selectedConnectionId
            ? connections.find(c => c.id === selectedConnectionId)?.label || 'Connection'
            : 'All Connections'}
          connectionCloud="azure"
          onClose={() => setShowProgressModal(false)}
          onComplete={() => {
            setShowProgressModal(false);
            setSnapshotRunning(false);
            window.location.reload();
          }}
        />
      )}
    </div>
  );
}

// ── Inline helpers for workload exposure ─────────────────────────────

function ExposureDistributionBar({ distribution, total, onSegmentClick }: { distribution: { critical: number; high: number; medium: number; low: number }; total: number; onSegmentClick?: (key: string) => void }) {
  const segments = [
    { key: 'critical', count: distribution.critical },
    { key: 'high', count: distribution.high },
    { key: 'medium', count: distribution.medium },
    { key: 'low', count: distribution.low },
  ];
  return (
    <div>
      <div className="flex h-5 rounded-md overflow-hidden" style={{ backgroundColor: COLORS.borderLight }}>
        {segments.filter(s => s.count > 0).map(s => {
          const cfg = EXPOSURE_LEVEL_CONFIG[s.key];
          const w = total > 0 ? (s.count / total) * 100 : 0;
          return (
            <div key={s.key} style={{ width: `${w}%`, backgroundColor: cfg.color, transition: 'width 0.8s ease', cursor: onSegmentClick ? 'pointer' : undefined }}
              className="flex items-center justify-center" title={`${cfg.label}: ${s.count}${onSegmentClick ? ' — Click to filter' : ''}`}
              onClick={onSegmentClick ? () => onSegmentClick(s.key) : undefined}>
              {w > 14 && <span className="text-[9px] font-bold text-white">{s.count}</span>}
            </div>
          );
        })}
      </div>
      <div className="flex gap-3 mt-1.5">
        {segments.map(s => {
          const cfg = EXPOSURE_LEVEL_CONFIG[s.key];
          return (
            <span key={s.key} className="text-[10px] flex items-center gap-1" style={{ color: COLORS.textSecondary, cursor: onSegmentClick ? 'pointer' : undefined }}
              onClick={onSegmentClick ? () => onSegmentClick(s.key) : undefined}>
              <span className="inline-block w-2 h-2 rounded-full" style={{ backgroundColor: cfg.color }} />
              {cfg.label} {s.count}
            </span>
          );
        })}
      </div>
    </div>
  );
}

function MiniStat({ label, value, warn, onClick, title }: { label: string; value: number | string; warn?: boolean; onClick?: () => void; title?: string }) {
  return (
    <div className={`text-center p-2 rounded-lg${onClick ? ' cursor-pointer hover:ring-1 hover:ring-blue-300 dark:hover:ring-blue-700 transition-shadow' : ''}`}
      style={{ backgroundColor: warn ? '#FEF2F2' : '#F8FAFC', border: `1px solid ${warn ? '#FECACA' : COLORS.border}` }}
      onClick={onClick} title={title}>
      <div className="text-lg font-extrabold" style={{ color: warn ? '#EF4444' : COLORS.textPrimary }}>{value}</div>
      <div className="text-[10px] uppercase tracking-wider" style={{ color: COLORS.textMuted }}>{label}</div>
    </div>
  );
}
