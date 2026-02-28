import React, { useEffect, useState } from 'react';
import { api } from '../../services/apiClient';

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
  tenant_name: string;
  tenant_id: number | null;
  login_at: string | null;
  logout_at: string | null;
  duration_minutes: number | null;
  ip_address: string;
  user_agent: string;
  status: 'active' | 'ended';
  portal: 'admin' | 'client';
}

export default function AdminMonitoring() {
  const [metrics, setMetrics] = useState<TenantMetric[]>([]);
  const [health, setHealth] = useState<PlatformHealth | null>(null);
  const [system, setSystem] = useState<SystemMetrics | null>(null);
  const [sessions, setSessions] = useState<LoginSession[]>([]);
  const [portalFilter, setPortalFilter] = useState<'' | 'admin' | 'client'>('admin');
  const [tenantFilter, setTenantFilter] = useState<number | ''>('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const sessionParams = new URLSearchParams({ limit: '50' });
    if (portalFilter) sessionParams.set('portal', portalFilter);
    if (tenantFilter) sessionParams.set('tenant_id', String(tenantFilter));
    Promise.all([
      api.get('/analytics/clients').catch(() => ({ tenants: [] })),
      api.get('/health').catch(() => null),
      api.get('/system/health').catch(() => null),
      api.get(`/analytics/login-sessions?${sessionParams}`).catch(() => ({ sessions: [] })),
    ]).then(([analytics, healthData, systemData, sessionData]: any[]) => {
      setMetrics(analytics.tenants || []);
      setHealth(healthData);
      if (systemData?.api) setSystem(systemData.api);
      setSessions(sessionData.sessions || []);
    }).finally(() => setLoading(false));
  }, [portalFilter, tenantFilter]);

  if (loading) return <div className="flex items-center justify-center h-64 text-gray-400">Loading monitoring data...</div>;

  const overallStatus = health?.status || 'unknown';
  const activeSessions = sessions.filter(s => s.status === 'active').length;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900">Platform Monitoring</h2>
          <p className="text-sm text-gray-500 mt-0.5">Infrastructure health, snapshot status, and login activity</p>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-500 font-medium">Tenant:</label>
          <select
            value={tenantFilter}
            onChange={e => setTenantFilter(e.target.value ? parseInt(e.target.value) : '')}
            className="text-xs border border-gray-200 rounded px-2 py-1.5"
          >
            <option value="">All Tenants</option>
            {metrics.map(t => (
              <option key={t.id} value={t.id}>{t.name}</option>
            ))}
          </select>
        </div>
      </div>

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

        {system && (
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
        )}
        {!system && (
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
          {(tenantFilter ? metrics.filter(t => t.id === tenantFilter) : metrics).map(t => {
            const hours = t.last_discovery ? (Date.now() - new Date(t.last_discovery).getTime()) / 3600000 : Infinity;
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
            {/* Portal filter */}
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
                  <td className="px-4 py-2.5 text-xs text-gray-600">{s.tenant_name || '\u2014'}</td>
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
