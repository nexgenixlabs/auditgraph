import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { CATEGORY_DISPLAY_ORDER } from '../constants/metrics';

import StatsCard from '../components/StatsCard';
import ViewAllButton from '../components/ViewAllButton';
import RiskMethodology from '../components/RiskMethodology';
import { RiskHeatMap, QuickActions, RiskDonutChart, PostureScore, CredentialHealth, ComplianceScorecard, ConditionalAccessCard, CloudContextBanner, RecentChanges, RemediationProgress, RiskTrendChart, RoleUsageChart, AnomalyAlerts, RiskVelocityChart, SOARActivity, ServiceAccountGovernance, PlatformHealth, CustomizePanel } from '../components/dashboard';
import ExpiryTracker from '../components/dashboard/ExpiryTracker';
import ResourceOverview from '../components/dashboard/ResourceOverview';
import Sparkline from '../components/Sparkline';
import StaleDataBanner from '../components/StaleDataBanner';
import { useToast } from '../components/ToastProvider';
import { useDashboardPreferences } from '../hooks/useDashboardPreferences';
import { getWidgetMeta } from '../components/dashboard/widgetRegistry';

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

export default function Dashboard() {
  const navigate = useNavigate();
  const { addToast } = useToast();

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

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const [statsRes, summaryRes, postureRes, complianceRes, caRes] = await Promise.all([
          fetch('/api/stats'),
          fetch('/api/identity-summary'),
          fetch('/api/dashboard/posture'),
          fetch('/api/dashboard/compliance'),
          fetch('/api/dashboard/conditional-access'),
        ]);

        if (!statsRes.ok) throw new Error(`Stats API error: ${statsRes.status}`);
        if (!summaryRes.ok) throw new Error(`Summary API error: ${summaryRes.status}`);

        const [statsJson, summaryJson] = await Promise.all([
          statsRes.json(),
          summaryRes.json(),
        ]);

        // Posture endpoint is optional - don't fail if unavailable
        let postureJson: PostureResponse | null = null;
        if (postureRes.ok) {
          postureJson = await postureRes.json();
        }

        const complianceJson = complianceRes.ok ? await complianceRes.json() : null;
        const caJson = caRes.ok ? await caRes.json() : null;

        // Fetch scheduler status (non-blocking)
        let schedJson = null;
        try {
          const schedRes = await fetch('/api/scheduler');
          if (schedRes.ok) schedJson = await schedRes.json();
        } catch { /* ignore */ }

        // Fetch drift data (non-blocking)
        let driftJson = null;
        try {
          const driftRes = await fetch('/api/drift/latest');
          if (driftRes.ok) driftJson = await driftRes.json();
        } catch { /* ignore */ }

        // Fetch trend data for sparklines (non-blocking)
        let trendsJson: typeof trends = [];
        try {
          const trendsRes = await fetch('/api/trends');
          if (trendsRes.ok) {
            const trendsData = await trendsRes.json();
            trendsJson = trendsData.runs || [];
          }
        } catch { /* ignore */ }

        // Fetch remediation summary (non-blocking)
        let remSummaryJson = null;
        try {
          const remRes = await fetch('/api/remediation-summary');
          if (remRes.ok) remSummaryJson = await remRes.json();
        } catch { /* ignore */ }

        // Fetch role usage stats (non-blocking)
        let roleUsageJson = null;
        try {
          const ruRes = await fetch('/api/dashboard/role-usage');
          if (ruRes.ok) roleUsageJson = await ruRes.json();
        } catch { /* ignore */ }

        // Fetch anomaly alerts (non-blocking)
        let anomalyJson = null;
        try {
          const anomRes = await fetch('/api/dashboard/anomalies');
          if (anomRes.ok) anomalyJson = await anomRes.json();
        } catch { /* ignore */ }

        // Fetch risk velocity (non-blocking)
        let velocityJson = null;
        try {
          const velRes = await fetch('/api/trends/velocity');
          if (velRes.ok) velocityJson = await velRes.json();
        } catch { /* ignore */ }

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
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!showRuns) return;
    fetch('/api/runs')
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data?.runs) setRuns(data.runs); })
      .catch(() => {});
  }, [showRuns]);

  const latest = stats?.latest_run;
  const prev = stats?.previous_run;

  // Trend helpers (Pillar 6)
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
    const ordered = CATEGORY_DISPLAY_ORDER;

    return ordered.map((key) => {
      const v = categories[key] || { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
      return { key, ...v };
    });
  }, [summary]);

  // Calculate overall risk counts for donut chart
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

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
      <div className="flex items-start justify-between gap-4 mb-5">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Dashboard</h2>
          <p className="text-sm text-gray-600">
            Posture view from the latest discovery run. Use the category blocks to drill down.
          </p>
          {latest?.completed_at && (
            <p className="text-xs text-gray-400 mt-0.5">
              Data as of {new Date(latest.completed_at).toLocaleString()}
              {' · '}Run #{stats?.latest_run?.id}
            </p>
          )}
        </div>
        <div className="flex items-center gap-3">
          <button
            disabled={discoveryRunning}
            onClick={async () => {
              setDiscoveryRunning(true);
              try {
                const res = await fetch('/api/runs/trigger', { method: 'POST' });
                if (!res.ok) throw new Error('Trigger failed');
                addToast('Discovery run started', 'success');
                // Poll for completion
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
                // Safety timeout: stop polling after 10 minutes
                setTimeout(() => { clearInterval(poll); setDiscoveryRunning(false); addToast('Discovery timed out. Check runs panel for status.', 'error'); }, 600000);
              } catch (e: any) {
                addToast(e?.message || 'Failed to trigger discovery run', 'error');
                setDiscoveryRunning(false);
              }
            }}
            className={`inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg border transition ${
              discoveryRunning
                ? 'bg-gray-100 text-gray-400 cursor-not-allowed border-gray-200'
                : 'bg-indigo-600 text-white hover:bg-indigo-700 border-indigo-600'
            }`}
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
          {schedulerInfo && (
            <span className="text-xs text-gray-400" title={`Interval: every ${schedulerInfo.interval_hours}h`}>
              Next: {schedulerInfo.next_run ? new Date(schedulerInfo.next_run).toLocaleString() : 'N/A'}
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

      {/* Stale Data Warning */}
      <StaleDataBanner completedAt={latest?.completed_at} />

      {/* Methodology panel */}
      <RiskMethodology />

      {loading ? (
        <div className="animate-pulse space-y-4">
          <div className="grid grid-cols-4 gap-4">
            {[1, 2, 3, 4].map(i => <div key={i} className="h-24 bg-gray-100 rounded-xl" />)}
          </div>
          <div className="grid grid-cols-3 gap-4">
            {[1, 2, 3].map(i => <div key={i} className="h-48 bg-gray-100 rounded-xl" />)}
          </div>
        </div>
      ) : error ? (
        <div className="bg-white border rounded-2xl p-6 text-red-600">{error}</div>
      ) : (
        <>
          {/* Widget renderers — map each widget ID to its JSX */}
          {(() => {
            const widgetRenderers: Record<string, () => React.ReactNode | null> = {
              stats_cards: () => (
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
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
                        <div className="text-[10px] text-gray-400 mt-0.5">Dormant trend</div>
                      </div>
                    )}
                  </div>
                </div>
              ),
              risk_trend_chart: () => trends.length >= 2 ? <RiskTrendChart data={trends} /> : null,
              role_usage_chart: () => <RoleUsageChart statuses={roleUsage?.statuses || {}} byRisk={roleUsage?.by_risk || {}} total={roleUsage?.total || 0} />,
              risk_velocity_chart: () => velocityData && velocityData.transitions.length > 0 ? (
                <RiskVelocityChart transitions={velocityData.transitions} retention={velocityData.retention} />
              ) : null,
              cloud_context_banner: () => summary?.monitored_resources ? (
                <CloudContextBanner monitoredResources={summary.monitored_resources} />
              ) : null,
              posture_score: () => posture ? (
                <PostureScore score={posture.posture_score} previousScore={posture.previous_posture_score} />
              ) : null,
              credential_health: () => posture ? (
                <CredentialHealth expired={posture.credential_health.expired} expiringSoon={posture.credential_health.expiring_soon}
                  healthy={posture.credential_health.healthy} noCredentials={posture.credential_health.no_credentials} />
              ) : null,
              quick_actions: () => (
                <QuickActions criticalCount={latest?.critical_count ?? 0} expiringCount={posture?.expiring_credentials_count ?? 0} dormantCount={posture?.dormant_count ?? 0} />
              ),
              recent_changes: () => (
                <RecentChanges hasData={driftData?.has_drift_data ?? false} currentRunId={driftData?.current_run_id} previousRunId={driftData?.previous_run_id}
                  newIdentities={driftData?.new_identities_count ?? 0} removedIdentities={driftData?.removed_identities_count ?? 0}
                  permissionChanges={driftData?.permission_changes_count ?? 0} riskChanges={driftData?.risk_changes_count ?? 0}
                  credentialChanges={driftData?.credential_changes_count ?? 0} totalChanges={driftData?.total_changes ?? 0} createdAt={driftData?.created_at} />
              ),
              anomaly_alerts: () => (
                <AnomalyAlerts anomalies={anomalyData?.anomalies ?? []} unresolvedCount={anomalyData?.unresolved_count ?? 0} loading={loading} />
              ),
              soar_activity: () => <SOARActivity />,
              sa_governance: () => <ServiceAccountGovernance />,
              platform_health: () => <PlatformHealth />,
              expiry_tracker: () => <ExpiryTracker />,
              resource_overview: () => <ResourceOverview />,
              risk_heat_map: () => <RiskHeatMap categories={categoryCards} />,
              risk_donut_chart: () => (
                <RiskDonutChart counts={riskCounts} onSegmentClick={handleSegmentClick}
                  cloudSources={summary?.monitored_resources ? Object.entries(summary.monitored_resources).filter(([, v]) => (v as any)?.subscriptions > 0 || (v as any)?.accounts > 0 || (v as any)?.projects > 0).map(([k]) => k) : undefined} />
              ),
              compliance_scorecard: () => <ComplianceScorecard data={compliance} loading={loading} />,
              conditional_access: () => <ConditionalAccessCard data={caData} loading={loading} />,
              remediation_progress: () => remediationSummary ? <RemediationProgress {...remediationSummary} /> : null,
            };

            // Pack visible widgets into rows using colSpan metadata
            const visibleWidgets = widgetPrefs.filter(w => w.visible);
            const rows: Array<Array<{ id: string; colSpan: number }>> = [];
            let currentRow: Array<{ id: string; colSpan: number }> = [];
            let currentSpan = 0;

            for (const w of visibleWidgets) {
              const meta = getWidgetMeta(w.id);
              const colSpan = meta?.colSpan ?? 1;

              if (colSpan === 3 || currentSpan + colSpan > 3) {
                if (currentRow.length > 0) {
                  rows.push(currentRow);
                  currentRow = [];
                  currentSpan = 0;
                }
              }

              if (colSpan === 3) {
                rows.push([{ id: w.id, colSpan: 3 }]);
              } else {
                currentRow.push({ id: w.id, colSpan });
                currentSpan += colSpan;
                if (currentSpan >= 3) {
                  rows.push(currentRow);
                  currentRow = [];
                  currentSpan = 0;
                }
              }
            }
            if (currentRow.length > 0) rows.push(currentRow);

            return (
              <>
                {rows.map((row, rowIdx) => {
                  // Full-width widget
                  if (row.length === 1 && row[0].colSpan === 3) {
                    const renderer = widgetRenderers[row[0].id];
                    const content = renderer?.();
                    if (!content) return null;
                    return <div key={rowIdx} className="mb-6">{content}</div>;
                  }

                  // Multi-widget row
                  return (
                    <div key={rowIdx} className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                      {row.map(({ id, colSpan }) => {
                        const renderer = widgetRenderers[id];
                        const content = renderer?.();
                        if (!content) return null;
                        return (
                          <div key={id} className={colSpan === 2 ? 'md:col-span-2' : ''}>
                            {content}
                          </div>
                        );
                      })}
                    </div>
                  );
                })}

                {/* Discovery Runs Panel (toggled, not part of widget system) */}
                {showRuns && (
                  <div className="bg-white border rounded-xl overflow-hidden mb-6">
                    <div className="px-5 py-3 border-b bg-gray-50 flex items-center justify-between">
                      <h3 className="text-sm font-semibold text-gray-900">Discovery Run History</h3>
                      <button onClick={() => setShowRuns(false)} className="text-xs text-gray-400 hover:text-gray-600">Close</button>
                    </div>
                    {runs.length === 0 ? (
                      <div className="p-6 text-sm text-gray-400 text-center">No discovery runs found</div>
                    ) : (
                      <div className="divide-y max-h-64 overflow-y-auto">
                        {runs.slice(0, 10).map((run: any, idx: number) => (
                          <div key={run.id || idx} className="px-5 py-3 flex items-center justify-between text-sm">
                            <div className="flex items-center gap-3">
                              <span className={`w-2 h-2 rounded-full ${run.status === 'completed' ? 'bg-green-500' : run.status === 'running' ? 'bg-yellow-500 animate-pulse' : 'bg-red-500'}`} />
                              <span className="font-medium text-gray-900">Run #{run.id}</span>
                              <span className="text-xs text-gray-500">
                                {run.completed_at ? new Date(run.completed_at).toLocaleString() : run.started_at ? new Date(run.started_at).toLocaleString() : '—'}
                              </span>
                            </div>
                            <div className="flex items-center gap-4 text-xs">
                              <span className="text-gray-600">{run.total_identities ?? '—'} identities</span>
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
            );
          })()}
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
