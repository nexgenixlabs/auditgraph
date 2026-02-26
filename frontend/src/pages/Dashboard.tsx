import React, { useEffect, useMemo, useState, useCallback } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { CATEGORY_DISPLAY_ORDER, EXPOSURE_LEVEL_CONFIG } from '../constants/metrics';
import { DASHBOARD_TABS, type DashboardTab, COLORS } from '../constants/design';
import { useConnection } from '../contexts/ConnectionContext';
import { formatDate } from '../utils/displayHelpers';

import StatsCard from '../components/StatsCard';
import ViewAllButton from '../components/ViewAllButton';
import RiskMethodology from '../components/RiskMethodology';
import {
  RiskHeatMap, QuickActions, RiskDonutChart, CredentialHealth,
  ComplianceScorecard, ConditionalAccessCard, CloudContextBanner,
  RecentChanges, RemediationProgress, RiskTrendChart, RoleUsageChart,
  AnomalyAlerts, RiskVelocityChart, SOARActivity, ServiceAccountGovernance,
  PlatformHealth, CustomizePanel, IdentityCorrelationWidget,
} from '../components/dashboard';
import ExpiryTracker from '../components/dashboard/ExpiryTracker';
import ResourceOverview from '../components/dashboard/ResourceOverview';
import CredentialIntelligence from '../components/dashboard/CredentialIntelligence';
import TrustAccessPanel from '../components/dashboard/TrustAccessPanel';
import Sparkline from '../components/Sparkline';
import StaleDataBanner from '../components/StaleDataBanner';
import AudienceBadge from '../components/AudienceBadge';
import { useToast } from '../components/ToastProvider';
import DrillableNumber from '../components/DrillableNumber';
import { useDashboardPreferences } from '../hooks/useDashboardPreferences';

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
  workload_exposure?: {
    total: number; critical: number; orphaned: number;
    can_escalate: number; anomalies_unresolved: number;
    exposure_distribution?: { critical: number; high: number; medium: number; low: number };
    blind_count?: number; avg_exposure_score?: number;
  };
}

interface MonitoredResources {
  azure: { subscriptions: number; subscription_ids: string[] };
  aws: { accounts: number; account_ids: string[] };
  gcp: { projects: number; project_ids: string[] };
}

interface IdentitySummaryResponse {
  run_id: number;
  completed_at: string | null;
  categories: Record<
    string,
    { total: number; critical: number; high: number; medium: number; low: number; info: number; unknown: number }
  >;
  monitored_resources?: MonitoredResources;
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
  const [searchParams, setSearchParams] = useSearchParams();
  const { addToast } = useToast();
  const { withConnection, selectedConnectionId } = useConnection();

  // Tab state from URL
  const activeTab = (searchParams.get('tab') as DashboardTab) || 'exposure';
  const setActiveTab = useCallback((tab: DashboardTab) => {
    setSearchParams({ tab }, { replace: true });
  }, [setSearchParams]);

  // Data state
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [summary, setSummary] = useState<IdentitySummaryResponse | null>(null);
  const [posture, setPosture] = useState<PostureResponse | null>(null);
  const [compliance, setCompliance] = useState<any>(null);
  const [caData, setCaData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [discoveryRunning, setDiscoveryRunning] = useState(false);
  const [schedulerInfo, setSchedulerInfo] = useState<{ scheduler: string; next_run: string | null; interval_hours: number } | null>(null);
  const [showRuns, setShowRuns] = useState(false);
  const [runs, setRuns] = useState<any[]>([]);
  const [driftData, setDriftData] = useState<any>(null);
  const [trends, setTrends] = useState<Array<{ run_id: number; date: string | null; total: number; critical: number; high: number; medium: number; low: number; dormant: number }>>([]);
  const [remediationSummary, setRemediationSummary] = useState<{ open: number; acknowledged: number; completed: number; skipped: number; total: number; completion_pct: number } | null>(null);
  const [roleUsage, setRoleUsage] = useState<{ statuses: Record<string, number>; by_risk: Record<string, number>; total: number } | null>(null);
  const [anomalyData, setAnomalyData] = useState<{ anomalies: any[]; unresolved_count: number } | null>(null);
  const [velocityData, setVelocityData] = useState<{
    transitions: Array<{
      run_id: number; date: string | null; prev_run_id: number;
      inflow: Record<string, number>; outflow: Record<string, number>; net: Record<string, number>;
    }>;
    retention: Record<string, { retained: number; total: number; rate: number }>;
  } | null>(null);

  // Dashboard customization (Phase 44)
  const [customizeOpen, setCustomizeOpen] = useState(false);
  const { widgets: widgetPrefs, saving: prefsSaving, dirty: prefsDirty, toggleWidget, moveWidget, save: savePrefs, reset: resetPrefs } = useDashboardPreferences();

  // ── Data Fetching ──────────────────────────────────────────────

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const [statsRes, summaryRes, postureRes, complianceRes, caRes] = await Promise.all([
          fetch(withConnection('/api/stats')),
          fetch(withConnection('/api/identity-summary')),
          fetch(withConnection('/api/dashboard/posture')),
          fetch(withConnection('/api/dashboard/compliance')),
          fetch(withConnection('/api/dashboard/conditional-access')),
        ]);

        if (!statsRes.ok) throw new Error(`Stats API error: ${statsRes.status}`);
        if (!summaryRes.ok) throw new Error(`Summary API error: ${summaryRes.status}`);

        const [statsJson, summaryJson] = await Promise.all([
          statsRes.json(),
          summaryRes.json(),
        ]);

        let postureJson: PostureResponse | null = null;
        if (postureRes.ok) postureJson = await postureRes.json();

        const complianceJson = complianceRes.ok ? await complianceRes.json() : null;
        const caJson = caRes.ok ? await caRes.json() : null;

        let schedJson = null;
        try { const r = await fetch(withConnection('/api/scheduler')); if (r.ok) schedJson = await r.json(); } catch {}

        let driftJson = null;
        try { const r = await fetch(withConnection('/api/drift/latest')); if (r.ok) driftJson = await r.json(); } catch {}

        let trendsJson: typeof trends = [];
        try { const r = await fetch(withConnection('/api/trends')); if (r.ok) { const d = await r.json(); trendsJson = d.runs || []; } } catch {}

        let remSummaryJson = null;
        try { const r = await fetch(withConnection('/api/remediation-summary')); if (r.ok) remSummaryJson = await r.json(); } catch {}

        let roleUsageJson = null;
        try { const r = await fetch(withConnection('/api/dashboard/role-usage')); if (r.ok) roleUsageJson = await r.json(); } catch {}

        let anomalyJson = null;
        try { const r = await fetch(withConnection('/api/dashboard/anomalies')); if (r.ok) anomalyJson = await r.json(); } catch {}

        let velocityJson = null;
        try { const r = await fetch(withConnection('/api/trends/velocity')); if (r.ok) velocityJson = await r.json(); } catch {}

        if (!cancelled) {
          setStats(statsJson);
          setSummary(summaryJson);
          setPosture(postureJson);
          setCompliance(complianceJson);
          setCaData(caJson);
          setSchedulerInfo(schedJson);
          setDriftData(driftJson);
          setTrends(trendsJson);
          setRemediationSummary(remSummaryJson);
          setRoleUsage(roleUsageJson);
          setAnomalyData(anomalyJson);
          setVelocityData(velocityJson);
        }
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load dashboard');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => { cancelled = true; };
  }, [selectedConnectionId]);

  useEffect(() => {
    if (!showRuns) return;
    fetch('/api/runs')
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data?.runs) setRuns(data.runs); })
      .catch(() => {});
  }, [showRuns]);

  // ── Derived Data ───────────────────────────────────────────────

  const latest = stats?.latest_run;
  const prev = stats?.previous_run;

  function trendDir(current: number, previous: number | undefined): 'up' | 'down' | 'neutral' | undefined {
    if (previous == null) return undefined;
    if (current > previous) return 'up';
    if (current < previous) return 'down';
    return 'neutral';
  }

  function trendSeries(key: 'total' | 'critical' | 'high' | 'medium' | 'low' | 'dormant'): number[] {
    return trends.map(t => t[key] ?? 0);
  }

  const categoryCards = useMemo(() => {
    const categories = summary?.categories || {};
    return CATEGORY_DISPLAY_ORDER.map((key) => {
      const v = categories[key] || { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
      return { key, ...v };
    });
  }, [summary]);

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

  // ── Discovery Run Trigger ──────────────────────────────────────

  const triggerDiscovery = useCallback(async () => {
    setDiscoveryRunning(true);
    try {
      const res = await fetch('/api/runs/trigger', { method: 'POST' });
      if (!res.ok) throw new Error('Trigger failed');
      addToast('Discovery run started', 'success');
      const poll = setInterval(async () => {
        const runsRes = await fetch('/api/runs');
        if (runsRes.ok) {
          const runsJson = await runsRes.json();
          const latest = runsJson?.runs?.[0];
          if (latest?.status === 'completed') {
            clearInterval(poll);
            setDiscoveryRunning(false);
            addToast('Discovery completed! Refreshing...', 'success');
            window.location.reload();
          }
        }
      }, 5000);
      setTimeout(() => { clearInterval(poll); setDiscoveryRunning(false); addToast('Discovery timed out. Check runs panel for status.', 'error'); }, 600000);
    } catch (e: any) {
      addToast(e?.message || 'Failed to trigger discovery run', 'error');
      setDiscoveryRunning(false);
    }
  }, [addToast]);

  // ── Render ─────────────────────────────────────────────────────

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6" style={{ fontFamily: "'Inter', sans-serif" }}>
      {/* Page Header */}
      <div className="flex items-start justify-between gap-4 mb-5">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-[22px] font-extrabold tracking-tight" style={{ color: COLORS.textPrimary }}>Risk Monitoring</h2>
            <AudienceBadge label="SOC / IAM OPS" variant="blue" />
          </div>
          <p className="text-sm" style={{ color: COLORS.textSecondary }}>
            Operational identity risk monitoring — What happened?
          </p>
          {latest?.completed_at && (
            <p className="text-xs mt-0.5" style={{ color: COLORS.textMuted }}>
              Data as of {formatDate(latest.completed_at, 'No data')} · Run #{stats?.latest_run?.id}
            </p>
          )}
        </div>
        <div className="flex items-center gap-3">
          <button
            disabled={discoveryRunning}
            onClick={triggerDiscovery}
            className={`inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg border transition ${
              discoveryRunning
                ? 'bg-gray-100 text-gray-400 cursor-not-allowed border-gray-200'
                : 'text-white hover:opacity-90 border-transparent'
            }`}
            style={discoveryRunning ? {} : { backgroundColor: COLORS.brand }}
          >
            {discoveryRunning ? (
              <>
                <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg>
                Running...
              </>
            ) : (
              <>
                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
                Run Discovery
              </>
            )}
          </button>
          <button
            onClick={() => { setActiveTab('exposure'); setTimeout(() => document.getElementById('anomaly-alerts')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100); }}
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
          {schedulerInfo && (
            <span className="text-xs" style={{ color: COLORS.textMuted }} title={`Interval: every ${schedulerInfo.interval_hours}h`}>
              Next: {formatDate(schedulerInfo.next_run, 'N/A')}
            </span>
          )}
          <ViewAllButton />
          <button
            onClick={() => setCustomizeOpen(true)}
            className="p-2 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition"
            title="Customize dashboard"
          >
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
          </button>
        </div>
      </div>

      <StaleDataBanner completedAt={latest?.completed_at} />
      <RiskMethodology />

      {loading ? (
        <div className="animate-pulse space-y-4">
          <div className="grid grid-cols-4 gap-4">
            {[1, 2, 3, 4].map(i => <div key={i} className="h-24 rounded-xl" style={{ backgroundColor: COLORS.borderLight }} />)}
          </div>
          <div className="h-10 rounded-lg mt-4" style={{ backgroundColor: COLORS.borderLight }} />
          <div className="grid grid-cols-3 gap-4 mt-4">
            {[1, 2, 3].map(i => <div key={i} className="h-48 rounded-xl" style={{ backgroundColor: COLORS.borderLight }} />)}
          </div>
        </div>
      ) : error ? (
        <div className="bg-white rounded-xl p-6 text-red-600" style={{ border: `1px solid ${COLORS.border}` }}>{error}</div>
      ) : (
        <>
          {/* ── Persistent Summary Cards ─────────────────────────── */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div>
              <StatsCard title="Total Identities" value={latest?.total_identities ?? 0} icon="🧩" color="blue"
                trend={trendDir(latest?.total_identities ?? 0, prev?.total_identities)}
                trendDelta={prev ? (latest?.total_identities ?? 0) - prev.total_identities : undefined}
                trendNeutral onClick={() => navigate('/identities')} />
              {trends.length >= 2 && <div className="mt-1 px-3"><Sparkline data={trendSeries('total')} color="#3b82f6" width={200} height={28} /></div>}
            </div>
            <div>
              <StatsCard title="Critical" value={latest?.critical_count ?? 0} icon="🔴" color="red"
                trend={trendDir(latest?.critical_count ?? 0, prev?.critical_count)}
                trendDelta={prev ? (latest?.critical_count ?? 0) - prev.critical_count : undefined}
                onClick={() => navigate('/identities?risk_level=critical')} />
              {trends.length >= 2 && <div className="mt-1 px-3"><Sparkline data={trendSeries('critical')} color="#ef4444" width={200} height={28} /></div>}
            </div>
            <div>
              <StatsCard title="High" value={latest?.high_count ?? 0} icon="🟠" color="yellow"
                trend={trendDir(latest?.high_count ?? 0, prev?.high_count)}
                trendDelta={prev ? (latest?.high_count ?? 0) - prev.high_count : undefined}
                onClick={() => navigate('/identities?risk_level=high')} />
              {trends.length >= 2 && <div className="mt-1 px-3"><Sparkline data={trendSeries('high')} color="#f97316" width={200} height={28} /></div>}
            </div>
            <div>
              <StatsCard title="Discovery Runs" value={stats?.total_discovery_runs ?? 0} icon="🔄" color="gray"
                onClick={() => setShowRuns(!showRuns)} />
              {trends.length >= 2 && (
                <div className="mt-1 px-3">
                  <Sparkline data={trendSeries('dormant')} color="#6b7280" width={200} height={28} />
                  <div className="text-[10px] mt-0.5" style={{ color: COLORS.textMuted }}>Dormant trend</div>
                </div>
              )}
            </div>
          </div>

          {/* ── Tab Navigation ───────────────────────────────────── */}
          <div className="flex items-center gap-0 border-b mb-6" style={{ borderColor: COLORS.border }}>
            {DASHBOARD_TABS.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className="relative px-4 py-2.5 text-[13px] font-semibold transition-colors whitespace-nowrap"
                style={{
                  color: activeTab === tab.id ? COLORS.brand : COLORS.textSecondary,
                }}
              >
                {tab.label}
                {activeTab === tab.id && (
                  <span
                    className="absolute bottom-0 left-0 right-0 h-[2px] rounded-t"
                    style={{ backgroundColor: COLORS.brand }}
                  />
                )}
              </button>
            ))}
          </div>

          {/* ── Tab Content ──────────────────────────────────────── */}

          {/* Tab 1: Exposure & Risk */}
          {activeTab === 'exposure' && (
            <div className="space-y-6">
              {/* Row 1: Anomaly Alerts (full width — promoted to top) */}
              <div id="anomaly-alerts">
                <AnomalyAlerts anomalies={anomalyData?.anomalies ?? []} unresolvedCount={anomalyData?.unresolved_count ?? 0} loading={loading} />
              </div>
              {/* Row 2: Trend + Escalation Tracker (2 col) */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {trends.length >= 2 && <RiskTrendChart data={trends} />}
                {velocityData && velocityData.transitions.length > 0 && (
                  <RiskVelocityChart transitions={velocityData.transitions} retention={velocityData.retention} />
                )}
              </div>
              {/* Workload Exposure Summary */}
              {stats?.workload_exposure && stats.workload_exposure.total > 0 && (
                <div className="bg-white rounded-xl p-5" style={{ border: `1px solid ${COLORS.border}` }}>
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-sm font-semibold" style={{ color: COLORS.textPrimary }}>
                      Workload Identity Exposure
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
                    <MiniStat label="Avg Score" value={stats.workload_exposure.avg_exposure_score ?? '—'} warn={(stats.workload_exposure.avg_exposure_score ?? 0) >= 50}
                      onClick={() => navigate('/workload-identities')} title="View workload identities" />
                    <MiniStat label="Orphaned" value={stats.workload_exposure.orphaned} warn={stats.workload_exposure.orphaned > 0}
                      onClick={() => navigate('/workload-identities?owner=orphaned')} title="View orphaned identities" />
                    <MiniStat label="Can Escalate" value={stats.workload_exposure.can_escalate} warn={stats.workload_exposure.can_escalate > 0}
                      onClick={() => navigate('/workload-identities?escalate=true')} title="View identities that can escalate" />
                  </div>
                </div>
              )}
              {/* Row 3: Heat Map + Donut (2 col) */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <RiskHeatMap categories={categoryCards} />
                <RiskDonutChart counts={riskCounts} onSegmentClick={handleSegmentClick}
                  cloudSources={summary?.monitored_resources ? Object.entries(summary.monitored_resources).filter(([, v]) => (v as any)?.subscriptions > 0 || (v as any)?.accounts > 0 || (v as any)?.projects > 0).map(([k]) => k) : undefined} />
              </div>
              {/* Row 4: Recent Changes (full width) */}
              <RecentChanges hasData={driftData?.has_drift_data ?? false} currentRunId={driftData?.current_run_id} previousRunId={driftData?.previous_run_id}
                newIdentities={driftData?.new_identities_count ?? 0} removedIdentities={driftData?.removed_identities_count ?? 0}
                permissionChanges={driftData?.permission_changes_count ?? 0} riskChanges={driftData?.risk_changes_count ?? 0}
                credentialChanges={driftData?.credential_changes_count ?? 0} totalChanges={driftData?.total_changes ?? 0} createdAt={driftData?.created_at} />
            </div>
          )}

          {/* Tab 2: Credential Intelligence */}
          {activeTab === 'credential' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {posture && (
                  <CredentialHealth expired={posture.credential_health.expired} expiringSoon={posture.credential_health.expiring_soon}
                    healthy={posture.credential_health.healthy} noCredentials={posture.credential_health.no_credentials} />
                )}
                <ExpiryTracker />
              </div>
              <CredentialIntelligence />
            </div>
          )}

          {/* Tab 3: Trust & Access */}
          {activeTab === 'trust' && (
            <div>
              <TrustAccessPanel />
              {!loading && !stats?.latest_run && (
                <div className="bg-white rounded-xl p-8 text-center" style={{ border: `1px solid ${COLORS.border}` }}>
                  <div className="text-sm font-medium mb-2" style={{ color: COLORS.textSecondary }}>No trust & access data available</div>
                  <p className="text-xs mb-4" style={{ color: COLORS.textMuted }}>Run a discovery scan to populate trust and access relationships.</p>
                  <button onClick={triggerDiscovery} disabled={discoveryRunning}
                    className="px-4 py-2 text-sm font-medium text-white rounded-lg transition hover:opacity-90"
                    style={{ backgroundColor: COLORS.brand }}>
                    Run Discovery
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Tab 4: Usage & Optimization */}
          {activeTab === 'usage' && (
            <div className="space-y-6">
              {/* Usage summary cards */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="bg-white rounded-xl p-4 cursor-pointer hover:ring-1 hover:ring-orange-300 transition-shadow" style={{ border: `1px solid ${COLORS.border}` }}
                  onClick={() => navigate('/workload-identities?lifecycle=likely_dormant')} title="View dormant identities">
                  <div className="text-[11px] uppercase tracking-wider mb-1" style={{ color: COLORS.textMuted }}>Dormant Identities</div>
                  <div className="text-2xl font-extrabold"><DrillableNumber value={posture?.dormant_count ?? 0} to="/workload-identities?lifecycle=likely_dormant" color={(posture?.dormant_count ?? 0) > 0 ? '#F97316' : '#22C55E'} className="text-2xl font-extrabold" /></div>
                  <div className="text-[10px]" style={{ color: COLORS.textSecondary }}>Stale &gt;90 days</div>
                </div>
                <div className="bg-white rounded-xl p-4 cursor-pointer hover:ring-1 hover:ring-orange-300 transition-shadow" style={{ border: `1px solid ${COLORS.border}` }}
                  onClick={() => navigate('/workload-identities?owner=orphaned')} title="View unowned SPNs">
                  <div className="text-[11px] uppercase tracking-wider mb-1" style={{ color: COLORS.textMuted }}>Unowned SPNs</div>
                  <div className="text-2xl font-extrabold"><DrillableNumber value={posture?.no_owner_count ?? 0} to="/workload-identities?owner=orphaned" color={(posture?.no_owner_count ?? 0) > 0 ? '#F97316' : '#22C55E'} className="text-2xl font-extrabold" /></div>
                  <div className="text-[10px]" style={{ color: COLORS.textSecondary }}>No assigned owner</div>
                </div>
                <div className="bg-white rounded-xl p-4 cursor-pointer hover:ring-1 hover:ring-red-300 transition-shadow" style={{ border: `1px solid ${COLORS.border}` }}
                  onClick={() => navigate('/workload-identities?exposure=critical')} title="View expiring credentials">
                  <div className="text-[11px] uppercase tracking-wider mb-1" style={{ color: COLORS.textMuted }}>Expiring Credentials</div>
                  <div className="text-2xl font-extrabold"><DrillableNumber value={posture?.expiring_credentials_count ?? 0} to="/workload-identities?exposure=critical" color={(posture?.expiring_credentials_count ?? 0) > 0 ? '#EF4444' : '#22C55E'} className="text-2xl font-extrabold" /></div>
                  <div className="text-[10px]" style={{ color: COLORS.textSecondary }}>Within 30 days</div>
                </div>
                <div className="bg-white rounded-xl p-4 cursor-pointer hover:ring-1 hover:ring-blue-300 transition-shadow" style={{ border: `1px solid ${COLORS.border}` }}
                  onClick={() => navigate('/identities')} title="View active identities">
                  <div className="text-[11px] uppercase tracking-wider mb-1" style={{ color: COLORS.textMuted }}>Active Identities</div>
                  <div className="text-2xl font-extrabold"><DrillableNumber value={Math.max((latest?.total_identities ?? 0) - (posture?.dormant_count ?? 0), 0)} to="/identities" color={COLORS.brandLight} className="text-2xl font-extrabold" /></div>
                  <div className="text-[10px]" style={{ color: COLORS.textSecondary }}>Used within 90 days</div>
                </div>
                <div className="bg-white rounded-xl p-4 cursor-pointer hover:ring-1 hover:ring-blue-300 transition-shadow" style={{ border: `1px solid ${COLORS.border}` }}
                  onClick={() => navigate('/workload-identities')} title="View workload identities">
                  <div className="text-[11px] uppercase tracking-wider mb-1" style={{ color: COLORS.textMuted }}>Avg Exposure</div>
                  <div className="text-2xl font-extrabold">
                    <DrillableNumber value={stats?.workload_exposure?.avg_exposure_score ?? '—'} to="/workload-identities" color={(stats?.workload_exposure?.avg_exposure_score ?? 0) >= 50 ? '#EF4444' : '#22C55E'} className="text-2xl font-extrabold" format={false} />
                  </div>
                  <div className="text-[10px]" style={{ color: COLORS.textSecondary }}>Workload identities</div>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <RoleUsageChart statuses={roleUsage?.statuses || {}} byRisk={roleUsage?.by_risk || {}} total={roleUsage?.total || 0} />
                <QuickActions criticalCount={latest?.critical_count ?? 0} expiringCount={posture?.expiring_credentials_count ?? 0} dormantCount={posture?.dormant_count ?? 0} ghostCount={stats?.ghost_count ?? 0} />
              </div>
            </div>
          )}

          {/* Tab 5: Governance & Compliance */}
          {activeTab === 'governance' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <ComplianceScorecard data={compliance} loading={loading} />
                <ConditionalAccessCard data={caData} loading={loading} />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {remediationSummary && <RemediationProgress {...remediationSummary} />}
                <ServiceAccountGovernance />
              </div>
            </div>
          )}

          {/* Tab 6: Platform & Discovery */}
          {activeTab === 'platform' && (
            <div className="space-y-6">
              {summary?.monitored_resources && (
                <CloudContextBanner monitoredResources={summary.monitored_resources} />
              )}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <SOARActivity />
                <PlatformHealth />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <IdentityCorrelationWidget />
              </div>
              <ResourceOverview />
            </div>
          )}

          {/* Discovery Runs Panel (toggled, not part of tab system) */}
          {showRuns && (
            <div className="bg-white rounded-xl overflow-hidden mt-6" style={{ border: `1px solid ${COLORS.border}` }}>
              <div className="px-5 py-3 border-b flex items-center justify-between" style={{ backgroundColor: COLORS.borderLight, borderColor: COLORS.border }}>
                <h3 className="text-sm font-semibold" style={{ color: COLORS.textPrimary }}>Discovery Run History</h3>
                <button onClick={() => setShowRuns(false)} className="text-xs hover:opacity-70 transition" style={{ color: COLORS.textMuted }}>Close</button>
              </div>
              {runs.length === 0 ? (
                <div className="p-6 text-sm text-center" style={{ color: COLORS.textMuted }}>No discovery runs found</div>
              ) : (
                <div className="divide-y max-h-64 overflow-y-auto">
                  {runs.slice(0, 10).map((run: any, idx: number) => (
                    <div key={run.id || idx} className="px-5 py-3 flex items-center justify-between text-sm">
                      <div className="flex items-center gap-3">
                        <span className={`w-2 h-2 rounded-full ${run.status === 'completed' ? 'bg-green-500' : run.status === 'running' ? 'bg-yellow-500 animate-pulse' : 'bg-red-500'}`} />
                        <span className="font-medium" style={{ color: COLORS.textPrimary }}>Run #{run.id}</span>
                        <span className="text-xs" style={{ color: COLORS.textSecondary }}>
                          {formatDate(run.completed_at, '') || formatDate(run.started_at, '') || '—'}
                        </span>
                      </div>
                      <div className="flex items-center gap-4 text-xs">
                        <span style={{ color: COLORS.textSecondary }}>{run.total_identities ?? '—'} identities</span>
                        {(run.critical_count ?? 0) > 0 && <span className="px-1.5 py-0.5 rounded bg-red-100 text-red-700 font-semibold">{run.critical_count} critical</span>}
                        {(run.high_count ?? 0) > 0 && <span className="px-1.5 py-0.5 rounded bg-orange-100 text-orange-700 font-semibold">{run.high_count} high</span>}
                        <span className={`px-1.5 py-0.5 rounded font-medium ${run.status === 'completed' ? 'bg-green-100 text-green-700' : run.status === 'running' ? 'bg-yellow-100 text-yellow-700' : 'bg-gray-100 text-gray-600'}`}>
                          {run.status || 'unknown'}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Customize Panel */}
      <CustomizePanel
        open={customizeOpen}
        onClose={() => setCustomizeOpen(false)}
        widgets={widgetPrefs}
        toggleWidget={toggleWidget}
        moveWidget={moveWidget}
        save={savePrefs}
        reset={resetPrefs}
        saving={prefsSaving}
        dirty={prefsDirty}
      />
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
