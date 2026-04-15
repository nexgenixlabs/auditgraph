import React, { useEffect, useState } from 'react';
import { api } from '../../services/apiClient';
import { TIME_MS } from '../../constants/metrics';

interface TenantMetric {
  id: number;
  name: string;
  slug: string;
  plan: string;
  enabled: boolean;
  user_count: number;
  total_runs: number;
  last_discovery: string | null;
}

interface HealthCheck {
  name: string;
  status: string;
  latency_ms?: number;
  error?: string;
  next_run?: string;
  pid?: number;
  uptime?: string;
  memory_mb?: number;
  cpu_percent?: number;
}

interface PlatformHealth {
  status: string;
  checks: HealthCheck[];
}

interface SystemMetrics {
  uptime: string;
  total_requests: number;
  total_errors: number;
  avg_latency_ms: number;
  p95_latency_ms: number;
  error_rate: number;
  status_codes: Record<string, number>;
}

interface LoginSession {
  user_id: number | null;
  username: string;
  display_name: string;
  role: string;
  org_name: string;
  organization_id: number | null;
  login_at: string | null;
  logout_at: string | null;
  duration_minutes: number | null;
  ip_address: string;
  user_agent: string;
  status: 'active' | 'ended';
  portal: 'admin' | 'client';
}

interface PlatformHealthExtended {
  status: string;
  tenants: { total: number; healthy: number; warning: number; critical: number; stale: number; integrity_warnings: number };
  jobs: { recent_total: number; failed: number; running: number; failure_rate_24h: number };
  job_queue: { queued: number; running: number };
  snapshot_stats: { total: number; completed: number; failed: number; success_rate: number };
  discovery_stats: { total: number; completed: number; failed: number; avg_duration_ms: number; success_rate: number };
  snapshot_run_stats: { total: number; completed: number; failed: number; running: number; avg_duration_seconds: number; success_rate: number; total_identities: number; total_spns: number };
  alert_counts: { total: number; critical: number; warning: number; info: number };
  worker_health: { scheduler_running: boolean; active_jobs_count: number };
}

interface AlertItem {
  type?: string;
  alert_source?: string;
  severity?: string;
  org_name?: string;
  organization_name?: string;
  error?: string | null;
  message?: string;
  created_at: string;
  job_type?: string;
  alert_type?: string;
  id?: string;
}

interface SnapshotRun {
  id: string;
  organization_id: number;
  organization_name?: string;
  status: string;
  scan_mode: string;
  started_at: string;
  completed_at: string | null;
  duration_seconds: number | null;
  identities_found: number;
  spns_found: number;
  connections_total: number;
  connections_completed: number;
  connections_failed: number;
  triggered_by: string;
}

export default function AdminMonitoring() {
  const [metrics, setMetrics] = useState<TenantMetric[]>([]);
  const [health, setHealth] = useState<PlatformHealth | null>(null);
  const [system, setSystem] = useState<SystemMetrics | null>(null);
  const [sessions, setSessions] = useState<LoginSession[]>([]);
  const [platformHealth, setPlatformHealth] = useState<PlatformHealthExtended | null>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [snapshotRuns, setSnapshotRuns] = useState<SnapshotRun[]>([]);
  const [portalFilter, setPortalFilter] = useState<'' | 'admin' | 'client'>('admin');
  const [orgFilter, setOrgFilter] = useState<number | ''>('');
  const [alertTypeFilter, setAlertTypeFilter] = useState<string>('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const sessionParams = new URLSearchParams({ limit: '50' });
    if (portalFilter) sessionParams.set('portal', portalFilter);
    if (orgFilter) sessionParams.set('organization_id', String(orgFilter));
    Promise.all([
      api.get('/analytics/clients').catch(() => ({ tenants: [] })),
      api.get('/health').catch(() => null),
      api.get('/system/health').catch(() => null),
      api.get(`/analytics/login-sessions?${sessionParams}`).catch(() => ({ sessions: [] })),
      api.get('/admin/alerts').catch(() => ({ alerts: [] })),
      api.get('/admin/snapshot-runs?limit=20').catch(() => ({ runs: [] })),
    ]).then(([analytics, healthData, systemData, sessionData, alertData, runData]: any[]) => {
      setMetrics(analytics.tenants || []);
      setHealth(healthData);
      if (systemData?.api) setSystem(systemData.api);
      if (systemData?.job_queue) setPlatformHealth(systemData as PlatformHealthExtended);
      setSessions(sessionData.sessions || []);
      setAlerts(alertData.alerts || []);
      setSnapshotRuns(runData.runs || []);
    }).finally(() => setLoading(false));
  }, [portalFilter, orgFilter]);

  if (loading) return <div className="flex items-center justify-center h-64 text-gray-400">Loading monitoring data...</div>;

  const overallStatus = health?.status || 'unknown';
  const activeSessions = sessions.filter(s => s.status === 'active').length;
  const filteredAlerts = alertTypeFilter
    ? alerts.filter(a => (a.alert_source || a.type) === alertTypeFilter)
    : alerts;

  const ph = platformHealth;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900">Platform Monitoring</h2>
          <p className="text-sm text-gray-500 mt-0.5">Snapshot pipeline, infrastructure health, and login activity</p>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-500 font-medium">Tenant:</label>
          <select
            value={orgFilter}
            onChange={e => setOrgFilter(e.target.value ? parseInt(e.target.value) : '')}
            className="text-xs border border-gray-200 rounded px-2 py-1.5"
          >
            <option value="">All Tenants</option>
            {metrics.map(t => (
              <option key={t.id} value={t.id}>{t.name}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Snapshot Pipeline Metrics (Phase 7) */}
      {ph && (
        <div className="grid grid-cols-6 gap-3">
          <MetricCard
            label="Snapshots Today"
            value={ph.snapshot_run_stats?.total ?? 0}
            sub={`${ph.snapshot_run_stats?.completed ?? 0} completed`}
            color="blue"
          />
          <MetricCard
            label="Failed Snapshots"
            value={ph.snapshot_run_stats?.failed ?? 0}
            color={ph.snapshot_run_stats?.failed > 0 ? 'red' : 'green'}
          />
          <MetricCard
            label="Critical Health"
            value={ph.tenants.critical ?? 0}
            sub={`of ${ph.tenants.total} tenants`}
            color={ph.tenants.critical > 0 ? 'red' : 'green'}
          />
          <MetricCard
            label="Warning Health"
            value={ph.tenants.warning ?? 0}
            sub={`of ${ph.tenants.total} tenants`}
            color={ph.tenants.warning > 0 ? 'yellow' : 'green'}
          />
          <MetricCard
            label="Queue Depth"
            value={ph.job_queue.queued + ph.job_queue.running}
            sub={`${ph.job_queue.queued} queued, ${ph.job_queue.running} running`}
            color="blue"
          />
          <MetricCard
            label="Active Alerts"
            value={ph.alert_counts?.total ?? 0}
            sub={ph.alert_counts?.critical > 0 ? `${ph.alert_counts.critical} critical` : undefined}
            color={ph.alert_counts?.critical > 0 ? 'red' : ph.alert_counts?.total > 0 ? 'yellow' : 'green'}
          />
        </div>
      )}

      {/* Platform Health Cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className={`border rounded-lg p-4 ${
          overallStatus === 'healthy' ? 'bg-green-50 border-green-200' :
          overallStatus === 'degraded' ? 'bg-yellow-50 border-yellow-200' :
          'bg-red-50 border-red-200'
        }`}>
          <div className="flex items-center gap-2 mb-1">
            <div className={`w-2.5 h-2.5 rounded-full ${
              overallStatus === 'healthy' ? 'bg-green-500' :
              overallStatus === 'degraded' ? 'bg-yellow-500' :
              'bg-red-500'
            }`} />
            <span className="text-xs font-semibold text-gray-600 uppercase tracking-wider">Platform</span>
          </div>
          <div className={`text-lg font-bold capitalize ${
            overallStatus === 'healthy' ? 'text-green-700' :
            overallStatus === 'degraded' ? 'text-yellow-700' :
            'text-red-700'
          }`}>{overallStatus}</div>
        </div>

        {system ? (
          <>
            <div className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">API Uptime</div>
              <div className="text-lg font-bold text-gray-900">{system.uptime}</div>
            </div>
            <div className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Avg Latency</div>
              <div className="text-lg font-bold text-gray-900">{system.avg_latency_ms}ms</div>
              <div className="text-[10px] text-gray-400">P95: {system.p95_latency_ms}ms</div>
            </div>
            <div className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Error Rate</div>
              <div className={`text-lg font-bold ${system.error_rate > 5 ? 'text-red-600' : system.error_rate > 1 ? 'text-yellow-600' : 'text-green-700'}`}>
                {system.error_rate.toFixed(1)}%
              </div>
              <div className="text-[10px] text-gray-400">{system.total_requests.toLocaleString()} requests</div>
            </div>
          </>
        ) : (
          <>
            <div className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="text-xs text-gray-400">API metrics unavailable</div>
            </div>
            <div className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="text-xs text-gray-400">Latency unavailable</div>
            </div>
            <div className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="text-xs text-gray-400">Error rate unavailable</div>
            </div>
          </>
        )}
      </div>

      {/* Job Queue & Worker Health + Success Rate Cards */}
      {ph && (
        <div className="grid grid-cols-2 gap-4">
          {/* Job Queue & Worker Health */}
          <div className="bg-white border border-gray-200 rounded-lg p-5">
            <h3 className="text-sm font-semibold text-gray-800 mb-4">Job Queue & Worker Health</h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-700">{ph.job_queue.queued}</div>
                <div className="text-[10px] text-gray-500 mt-1">Queued</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-700">{ph.job_queue.running}</div>
                <div className="text-[10px] text-gray-500 mt-1">Running</div>
              </div>
            </div>
            <div className="mt-4 pt-3 border-t border-gray-100 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${ph.worker_health.scheduler_running ? 'bg-green-500' : 'bg-red-500'}`} />
                <span className="text-xs text-gray-600">
                  Scheduler: <span className={`font-semibold ${ph.worker_health.scheduler_running ? 'text-green-700' : 'text-red-700'}`}>
                    {ph.worker_health.scheduler_running ? 'Running' : 'Stopped'}
                  </span>
                </span>
              </div>
              <span className="text-xs text-gray-500">{ph.worker_health.active_jobs_count} scheduled jobs</span>
            </div>
          </div>

          {/* Success Rate Cards */}
          <div className="bg-white border border-gray-200 rounded-lg p-5">
            <h3 className="text-sm font-semibold text-gray-800 mb-4">Success Rates (24h)</h3>
            <div className="space-y-4">
              <SuccessBar
                label="Snapshot Runs"
                completed={ph.snapshot_run_stats?.completed ?? 0}
                total={ph.snapshot_run_stats?.total ?? 0}
                successRate={ph.snapshot_run_stats?.success_rate ?? 100}
                failed={ph.snapshot_run_stats?.failed ?? 0}
                sub={ph.snapshot_run_stats?.avg_duration_seconds > 0
                  ? `Avg: ${ph.snapshot_run_stats.avg_duration_seconds}s`
                  : undefined}
              />
              <SuccessBar
                label="Discovery Runs"
                completed={ph.discovery_stats.completed}
                total={ph.discovery_stats.total}
                successRate={ph.discovery_stats.success_rate}
                failed={ph.discovery_stats.failed}
                sub={ph.discovery_stats.avg_duration_ms > 0
                  ? `Avg: ${Math.round(ph.discovery_stats.avg_duration_ms / 1000)}s`
                  : undefined}
              />
            </div>
          </div>
        </div>
      )}

      {/* Snapshot Runs Table (Phase 7) */}
      {snapshotRuns.length > 0 && (
        <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-200">
            <h3 className="text-sm font-semibold text-gray-800">Recent Snapshot Runs</h3>
            <p className="text-[10px] text-gray-500 mt-0.5">Organization-level snapshot pipeline executions</p>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-xs">
              <thead className="bg-gray-50 border-b border-gray-200 text-gray-600 uppercase tracking-wider font-medium">
                <tr>
                  <th className="px-4 py-2.5">Tenant</th>
                  <th className="px-4 py-2.5">Status</th>
                  <th className="px-4 py-2.5">Mode</th>
                  <th className="px-4 py-2.5">Connections</th>
                  <th className="px-4 py-2.5">Identities</th>
                  <th className="px-4 py-2.5">SPNs</th>
                  <th className="px-4 py-2.5">Duration</th>
                  <th className="px-4 py-2.5">Triggered</th>
                  <th className="px-4 py-2.5">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {snapshotRuns.map(r => (
                  <tr key={r.id} className="hover:bg-gray-50">
                    <td className="px-4 py-2.5 text-xs font-medium text-gray-800">
                      {r.organization_name || `Org #${r.organization_id}`}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                        r.status === 'completed' ? 'bg-green-100 text-green-700' :
                        r.status === 'running' ? 'bg-blue-100 text-blue-700' :
                        'bg-red-100 text-red-700'
                      }`}>{r.status}</span>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-gray-600 capitalize">{r.scan_mode}</td>
                    <td className="px-4 py-2.5 text-xs">
                      <span className="text-green-600">{r.connections_completed}</span>
                      {r.connections_failed > 0 && (
                        <span className="text-red-500 ml-1">/ {r.connections_failed} fail</span>
                      )}
                      <span className="text-gray-400 ml-1">of {r.connections_total}</span>
                    </td>
                    <td className="px-4 py-2.5 text-xs font-medium text-gray-800">{r.identities_found}</td>
                    <td className="px-4 py-2.5 text-xs text-gray-600">{r.spns_found}</td>
                    <td className="px-4 py-2.5 text-xs text-gray-600">
                      {r.duration_seconds != null ? `${r.duration_seconds}s` : '\u2014'}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                        r.triggered_by === 'scheduler' ? 'bg-gray-100 text-gray-600' : 'bg-blue-100 text-blue-700'
                      }`}>{r.triggered_by}</span>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-gray-500 font-mono">
                      {r.started_at ? formatTimeAgo(r.started_at) : '\u2014'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Infrastructure Health Checks */}
      {health?.checks && health.checks.length > 0 && (
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-800 mb-3">Infrastructure</h3>
          <div className="grid grid-cols-3 gap-4">
            {health.checks.map(check => (
              <div key={check.name} className={`border rounded-lg p-3 ${
                check.status === 'healthy' || check.status === 'running' ? 'border-green-200 bg-green-50/50' :
                check.status === 'degraded' || check.status === 'stopped' ? 'border-yellow-200 bg-yellow-50/50' :
                'border-red-200 bg-red-50/50'
              }`}>
                <div className="flex items-center gap-2 mb-2">
                  <div className={`w-2 h-2 rounded-full ${
                    check.status === 'healthy' || check.status === 'running' ? 'bg-green-500' :
                    check.status === 'degraded' || check.status === 'stopped' ? 'bg-yellow-500' :
                    'bg-red-500'
                  }`} />
                  <span className="text-xs font-bold text-gray-700 capitalize">{check.name}</span>
                  <span className={`ml-auto text-[10px] font-semibold capitalize ${
                    check.status === 'healthy' || check.status === 'running' ? 'text-green-600' :
                    check.status === 'degraded' || check.status === 'stopped' ? 'text-yellow-600' :
                    'text-red-600'
                  }`}>{check.status}</span>
                </div>
                <div className="space-y-0.5 text-[11px] text-gray-500">
                  {check.latency_ms !== undefined && <div>Latency: {check.latency_ms}ms</div>}
                  {check.next_run && <div>Next snapshot: {formatTimeAgo(check.next_run, true)}</div>}
                  {check.memory_mb !== undefined && <div>Memory: {check.memory_mb}MB</div>}
                  {check.cpu_percent !== undefined && <div>CPU: {check.cpu_percent}%</div>}
                  {check.error && <div className="text-red-500 truncate">{check.error}</div>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Alerts Panel (Phase 7 Enhanced) */}
      <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-200 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-gray-800">Recent Alerts</h3>
            <p className="text-[10px] text-gray-500 mt-0.5">Snapshot failures, connection errors, and health alerts</p>
          </div>
          <div className="flex items-center gap-2">
            {[
              { key: '', label: 'All' },
              { key: 'failure', label: 'Failures' },
              { key: 'snapshot_alert', label: 'Alerts' },
            ].map(f => (
              <button
                key={f.key}
                onClick={() => setAlertTypeFilter(f.key)}
                className={`px-2.5 py-1 rounded text-[10px] font-semibold transition ${
                  alertTypeFilter === f.key
                    ? 'bg-red-600 text-white'
                    : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                }`}
              >
                {f.label}
              </button>
            ))}
            {alerts.length > 0 && (
              <span className="px-2 py-1 bg-red-100 text-red-700 rounded-full text-[10px] font-bold ml-1">
                {alerts.length}
              </span>
            )}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-xs">
            <thead className="bg-gray-50 border-b border-gray-200 text-gray-600 uppercase tracking-wider font-medium">
              <tr>
                <th className="px-4 py-2.5">Severity</th>
                <th className="px-4 py-2.5">Type</th>
                <th className="px-4 py-2.5">Tenant</th>
                <th className="px-4 py-2.5">Message</th>
                <th className="px-4 py-2.5">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {filteredAlerts.slice(0, 20).map((a, i) => (
                <tr key={i} className="hover:bg-gray-50">
                  <td className="px-4 py-2.5">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                      a.severity === 'critical' ? 'bg-red-100 text-red-700' :
                      a.severity === 'warning' ? 'bg-yellow-100 text-yellow-700' :
                      'bg-blue-100 text-blue-700'
                    }`}>
                      {a.severity || 'warning'}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                      a.alert_type === 'snapshot_failure' || a.alert_type === 'connection_failure'
                        ? 'bg-red-50 text-red-600'
                        : a.alert_type === 'health_critical'
                        ? 'bg-orange-50 text-orange-600'
                        : a.type === 'job' ? 'bg-orange-100 text-orange-700'
                        : 'bg-gray-100 text-gray-600'
                    }`}>
                      {a.alert_type || a.type || 'failure'}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-gray-700">
                    {a.organization_name || a.org_name || '\u2014'}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-red-600 max-w-xs truncate">
                    {a.message || a.error || '\u2014'}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-gray-500 font-mono">
                    {a.created_at ? formatTimeAgo(a.created_at) : '\u2014'}
                  </td>
                </tr>
              ))}
              {filteredAlerts.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-sm text-gray-400">No alerts</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* API Status Codes */}
      {system?.status_codes && Object.keys(system.status_codes).length > 0 && (
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-800 mb-3">API Status Codes</h3>
          <div className="flex gap-4">
            {Object.entries(system.status_codes).sort(([a], [b]) => a.localeCompare(b)).map(([code, count]) => {
              const total = Object.values(system.status_codes).reduce((s, c) => s + c, 0);
              const pct = total > 0 ? Math.round((count / total) * 100) : 0;
              const color = code.startsWith('2') ? 'bg-green-500' :
                           code.startsWith('3') ? 'bg-blue-500' :
                           code.startsWith('4') ? 'bg-yellow-500' :
                           'bg-red-500';
              return (
                <div key={code} className="flex-1">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold text-gray-700">{code}</span>
                    <span className="text-xs text-gray-500">{count.toLocaleString()}</span>
                  </div>
                  <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
                  </div>
                  <div className="text-[10px] text-gray-400 mt-0.5">{pct}%</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Discovery Freshness */}
      <div className="bg-white border border-gray-200 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-800 mb-3">Snapshot Freshness</h3>
        <div className="space-y-2">
          {(orgFilter ? metrics.filter(t => t.id === orgFilter) : metrics).map(t => {
            const hours = t.last_discovery ? (Date.now() - new Date(t.last_discovery).getTime()) / TIME_MS.HOUR : Infinity;
            const stale = hours > 24;
            const critical = hours > 72;
            return (
              <div key={t.id} className="flex items-center justify-between py-2 border-b border-gray-50 last:border-0">
                <div className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${critical ? 'bg-red-500' : stale ? 'bg-yellow-500' : 'bg-green-500'}`} />
                  <span className="text-sm font-medium text-gray-800">{t.name}</span>
                  <span className="text-[10px] text-gray-400 font-mono">{t.slug}</span>
                </div>
                <div className="flex items-center gap-4 text-xs">
                  <span className="text-gray-500">{t.total_runs} runs</span>
                  <span className="text-gray-500">{t.user_count} users</span>
                  <span className={`font-medium ${critical ? 'text-red-600' : stale ? 'text-yellow-600' : 'text-green-600'}`}>
                    {t.last_discovery ? formatTimeAgo(t.last_discovery) : 'Never'}
                  </span>
                  {!t.enabled && <span className="px-1.5 py-0.5 bg-red-100 text-red-700 rounded text-[10px] font-semibold">Disabled</span>}
                </div>
              </div>
            );
          })}
          {metrics.length === 0 && <p className="text-sm text-gray-400 text-center py-4">No tenants found</p>}
        </div>
      </div>

      {/* Login Session Audit Trail */}
      <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-200 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-gray-800">Login Session Audit</h3>
            <p className="text-[10px] text-gray-500 mt-0.5">User login/logout tracking for compliance governance</p>
          </div>
          <div className="flex items-center gap-2">
            {(['', 'admin', 'client'] as const).map(f => (
              <button
                key={f}
                onClick={() => setPortalFilter(f)}
                className={`px-2.5 py-1 rounded text-[10px] font-semibold transition ${
                  portalFilter === f
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                }`}
              >
                {f === '' ? 'All' : f === 'admin' ? 'Admin Portal' : 'Client Portal'}
              </button>
            ))}
            {activeSessions > 0 && (
              <span className="px-2 py-1 bg-green-100 text-green-700 rounded-full text-[10px] font-bold ml-2">
                {activeSessions} active
              </span>
            )}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-xs">
            <thead className="bg-gray-50 border-b border-gray-200 text-gray-600 uppercase tracking-wider font-medium">
              <tr>
                <th className="px-4 py-2.5">User</th>
                <th className="px-4 py-2.5">Role</th>
                <th className="px-4 py-2.5">Portal</th>
                <th className="px-4 py-2.5">Tenant</th>
                <th className="px-4 py-2.5">Login Time</th>
                <th className="px-4 py-2.5">Logout Time</th>
                <th className="px-4 py-2.5">Duration</th>
                <th className="px-4 py-2.5">IP Address</th>
                <th className="px-4 py-2.5">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {sessions.map((s, i) => (
                <tr key={i} className="hover:bg-gray-50">
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <div className="w-6 h-6 rounded-full bg-blue-100 text-blue-600 flex items-center justify-center text-[9px] font-bold shrink-0">
                        {(s.display_name || s.username || '?').substring(0, 2).toUpperCase()}
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-gray-900">{s.display_name || s.username}</div>
                        {s.display_name && s.username && s.display_name !== s.username && (
                          <div className="text-[10px] text-gray-400">{s.username}</div>
                        )}
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold capitalize ${
                      s.role === 'admin' ? 'bg-purple-100 text-purple-700' :
                      s.role === 'auditor' ? 'bg-blue-100 text-blue-700' :
                      'bg-gray-100 text-gray-600'
                    }`}>{s.role || '\u2014'}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                      s.portal === 'admin' ? 'bg-gray-900 text-white' : 'bg-blue-100 text-blue-700'
                    }`}>{s.portal === 'admin' ? 'Admin' : 'Client'}</span>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-gray-600">{s.org_name || '\u2014'}</td>
                  <td className="px-4 py-2.5 text-xs text-gray-700 font-mono">{s.login_at ? fmtDateTime(s.login_at) : '\u2014'}</td>
                  <td className="px-4 py-2.5 text-xs text-gray-700 font-mono">{s.logout_at ? fmtDateTime(s.logout_at) : '\u2014'}</td>
                  <td className="px-4 py-2.5 text-xs text-gray-600">
                    {s.duration_minutes != null ? formatDuration(s.duration_minutes) : s.status === 'active' ? (
                      <span className="text-green-600 font-medium">In progress</span>
                    ) : '\u2014'}
                  </td>
                  <td className="px-4 py-2.5">
                    {s.ip_address ? (
                      <span className="text-xs text-gray-500 font-mono">{s.ip_address}</span>
                    ) : <span className="text-gray-400">&mdash;</span>}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                      s.status === 'active' ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600'
                    }`}>{s.status === 'active' ? 'Active' : 'Ended'}</span>
                  </td>
                </tr>
              ))}
              {sessions.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-4 py-8 text-center text-sm text-gray-400">No login sessions recorded</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ── Helper Components ────────────────────────────────────────────────

function MetricCard({ label, value, sub, color }: {
  label: string; value: number; sub?: string;
  color: 'blue' | 'green' | 'yellow' | 'red';
}) {
  const colors = {
    blue: 'bg-blue-50 border-blue-200 text-blue-700',
    green: 'bg-green-50 border-green-200 text-green-700',
    yellow: 'bg-yellow-50 border-yellow-200 text-yellow-700',
    red: 'bg-red-50 border-red-200 text-red-700',
  };
  return (
    <div className={`border rounded-lg p-3 ${colors[color]}`}>
      <div className="text-[10px] font-semibold uppercase tracking-wider opacity-70 mb-1">{label}</div>
      <div className="text-xl font-bold">{value}</div>
      {sub && <div className="text-[10px] opacity-60 mt-0.5">{sub}</div>}
    </div>
  );
}

function SuccessBar({ label, completed, total, successRate, failed, sub }: {
  label: string; completed: number; total: number; successRate: number;
  failed: number; sub?: string;
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-xs font-medium text-gray-600">{label}</span>
        <span className="text-xs font-bold text-gray-800">
          {completed}/{total}
          <span className={`ml-2 ${successRate >= 90 ? 'text-green-600' : successRate >= 70 ? 'text-yellow-600' : 'text-red-600'}`}>
            {successRate}%
          </span>
        </span>
      </div>
      <div className="h-2.5 bg-gray-100 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${successRate >= 90 ? 'bg-green-500' : successRate >= 70 ? 'bg-yellow-500' : 'bg-red-500'}`}
          style={{ width: `${successRate}%` }}
        />
      </div>
      {failed > 0 && <div className="text-[10px] text-red-500 mt-0.5">{failed} failed</div>}
      {sub && !failed && <div className="text-[10px] text-gray-400 mt-0.5">{sub}</div>}
    </div>
  );
}

// ── Helper Functions ─────────────────────────────────────────────────

function fmtDateTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  });
}

function formatDuration(minutes: number): string {
  if (minutes < 1) return '<1m';
  if (minutes < 60) return `${Math.round(minutes)}m`;
  const hours = Math.floor(minutes / 60);
  const mins = Math.round(minutes % 60);
  if (hours < 24) return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
  const days = Math.floor(hours / 24);
  const remHours = hours % 24;
  return remHours > 0 ? `${days}d ${remHours}h` : `${days}d`;
}

function formatTimeAgo(iso: string, future?: boolean): string {
  const diff = future
    ? new Date(iso).getTime() - Date.now()
    : Date.now() - new Date(iso).getTime();
  if (diff < 0 && future) return 'overdue';
  const minutes = Math.floor(Math.abs(diff) / 60000);
  if (minutes < 1) return future ? 'soon' : 'just now';
  if (minutes < 60) return `${minutes}m ${future ? '' : 'ago'}`.trim();
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${future ? '' : 'ago'}`.trim();
  const days = Math.floor(hours / 24);
  return `${days}d ${future ? '' : 'ago'}`.trim();
}
