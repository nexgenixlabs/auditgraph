import React, { useEffect, useState, useCallback } from 'react';
import { api as apiClient } from '../services/apiClient';

interface HealthResponse {
  service: string;
  status: string;
  timestamp: string;
  checks: {
    database: { status: string; latency_ms?: number; error?: string };
    scheduler: { status: string; next_run: string | null };
    system: { pid: number; uptime_seconds: number; memory_mb?: number; cpu_percent?: number };
  };
}

interface SystemHealthResponse {
  api: {
    uptime_seconds: number;
    total_requests: number;
    total_errors: number;
    error_rate: number;
    avg_latency_ms: number;
    p95_latency_ms: number;
    p99_latency_ms: number;
    status_codes: Record<string, number>;
  };
  top_endpoints: Array<{ endpoint: string; count: number; avg_ms: number }>;
  discovery_runs: Array<{
    id: number;
    started_at: string | null;
    completed_at: string | null;
    status: string;
    total_identities: number;
    critical_count: number;
    high_count: number;
    duration_sec: number | null;
  }>;
  database: { tables: Array<{ name: string; size_bytes: number; size_mb: number }> };
}

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function StatusDot({ status }: { status: string }) {
  const color =
    status === 'healthy' || status === 'running'
      ? 'bg-green-500'
      : status === 'degraded' || status === 'stopped'
      ? 'bg-yellow-500'
      : 'bg-red-500';
  return <span className={`inline-block w-2.5 h-2.5 rounded-full ${color}`} />;
}

export default function SystemHealth() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [detail, setDetail] = useState<SystemHealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

  const fetchData = useCallback(async () => {
    try {
      const [h, d] = await Promise.all([
        apiClient.get<HealthResponse>('/health').catch(() => null),
        apiClient.get<SystemHealthResponse>('/system/health').catch(() => null),
      ]);
      if (h) setHealth(h);
      if (d) setDetail(d);
      setLastRefresh(new Date());
    } catch {
      // silent
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [fetchData]);

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-gray-200 rounded w-48" />
          <div className="grid grid-cols-4 gap-4">
            {[1, 2, 3, 4].map(i => <div key={i} className="h-24 bg-gray-200 rounded-xl" />)}
          </div>
        </div>
      </div>
    );
  }

  const api = detail?.api;
  const checks = health?.checks;

  return (
    <div className="max-w-7xl mx-auto px-6 py-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">System Health</h1>
          <p className="text-sm text-gray-500 mt-1">
            Real-time platform monitoring and performance metrics
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-400">
            Last refresh: {lastRefresh.toLocaleTimeString()}
          </span>
          <button
            onClick={() => fetchData()}
            className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Status Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white border rounded-xl p-5">
          <div className="text-xs text-gray-500 mb-1">Overall Status</div>
          <div className="flex items-center gap-2">
            <StatusDot status={health?.status || 'unknown'} />
            <span className="text-lg font-bold text-gray-900 capitalize">{health?.status || 'Unknown'}</span>
          </div>
        </div>
        <div className="bg-white border rounded-xl p-5">
          <div className="text-xs text-gray-500 mb-1">Uptime</div>
          <div className="text-lg font-bold text-gray-900">
            {api ? formatUptime(api.uptime_seconds) : '--'}
          </div>
        </div>
        <div className="bg-white border rounded-xl p-5">
          <div className="text-xs text-gray-500 mb-1">Avg Latency</div>
          <div className="text-lg font-bold text-gray-900">
            {api ? `${api.avg_latency_ms}ms` : '--'}
          </div>
        </div>
        <div className="bg-white border rounded-xl p-5">
          <div className="text-xs text-gray-500 mb-1">Error Rate</div>
          <div className={`text-lg font-bold ${(api?.error_rate ?? 0) > 5 ? 'text-red-600' : 'text-gray-900'}`}>
            {api ? `${api.error_rate}%` : '--'}
          </div>
        </div>
      </div>

      {/* Health Checks */}
      <div className="bg-white border rounded-xl p-5">
        <h2 className="text-sm font-semibold text-gray-900 mb-4">Health Checks</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="border rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <StatusDot status={checks?.database?.status || 'unknown'} />
              <span className="text-sm font-medium text-gray-900">Database</span>
            </div>
            {checks?.database?.latency_ms != null && (
              <div className="text-xs text-gray-500">Latency: {checks.database.latency_ms}ms</div>
            )}
            {!!checks?.database?.error && (
              <div className="text-xs text-red-600 mt-1">{checks.database.error}</div>
            )}
          </div>
          <div className="border rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <StatusDot status={checks?.scheduler?.status === 'running' ? 'healthy' : 'degraded'} />
              <span className="text-sm font-medium text-gray-900">Scheduler</span>
            </div>
            <div className="text-xs text-gray-500 capitalize">Status: {checks?.scheduler?.status || 'unknown'}</div>
            {!!checks?.scheduler?.next_run && (
              <div className="text-xs text-gray-500 mt-1">
                Next run: {new Date(checks.scheduler.next_run).toLocaleString()}
              </div>
            )}
          </div>
          <div className="border rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <StatusDot status="healthy" />
              <span className="text-sm font-medium text-gray-900">System</span>
            </div>
            <div className="text-xs text-gray-500">PID: {checks?.system?.pid || '--'}</div>
            {checks?.system?.memory_mb != null && (
              <div className="text-xs text-gray-500">Memory: {checks.system.memory_mb} MB</div>
            )}
            {checks?.system?.cpu_percent != null && (
              <div className="text-xs text-gray-500">CPU: {checks.system.cpu_percent}%</div>
            )}
          </div>
        </div>
      </div>

      {/* API Performance */}
      <div className="bg-white border rounded-xl p-5">
        <h2 className="text-sm font-semibold text-gray-900 mb-4">API Performance</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
          <div>
            <div className="text-xs text-gray-500">Total Requests</div>
            <div className="text-lg font-bold text-gray-900">{api?.total_requests?.toLocaleString() ?? '--'}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Total Errors</div>
            <div className="text-lg font-bold text-red-600">{api?.total_errors?.toLocaleString() ?? '--'}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">P95 Latency</div>
            <div className="text-lg font-bold text-gray-900">{api ? `${api.p95_latency_ms}ms` : '--'}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">P99 Latency</div>
            <div className="text-lg font-bold text-gray-900">{api ? `${api.p99_latency_ms}ms` : '--'}</div>
          </div>
        </div>

        {/* Status code breakdown */}
        {api?.status_codes && Object.keys(api.status_codes).length > 0 && (
          <div>
            <div className="text-xs font-medium text-gray-500 mb-2">Status Codes</div>
            <div className="flex flex-wrap gap-2">
              {Object.entries(api.status_codes)
                .sort(([a], [b]) => Number(a) - Number(b))
                .map(([code, count]) => (
                  <span
                    key={code}
                    className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium ${
                      Number(code) >= 500
                        ? 'bg-red-100 text-red-700'
                        : Number(code) >= 400
                        ? 'bg-yellow-100 text-yellow-700'
                        : 'bg-green-100 text-green-700'
                    }`}
                  >
                    {code}: {count}
                  </span>
                ))}
            </div>
          </div>
        )}
      </div>

      {/* Top Endpoints */}
      {detail?.top_endpoints && detail.top_endpoints.length > 0 && (
        <div className="bg-white border rounded-xl p-5">
          <h2 className="text-sm font-semibold text-gray-900 mb-4">Top Endpoints</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-gray-500 border-b">
                  <th className="pb-2 pr-4">Endpoint</th>
                  <th className="pb-2 pr-4 text-right">Requests</th>
                  <th className="pb-2 text-right">Avg Latency</th>
                </tr>
              </thead>
              <tbody>
                {detail.top_endpoints.map((ep, i) => (
                  <tr key={i} className="border-b last:border-0">
                    <td className="py-2 pr-4 font-mono text-xs text-gray-700">{ep.endpoint}</td>
                    <td className="py-2 pr-4 text-right text-gray-900">{ep.count.toLocaleString()}</td>
                    <td className={`py-2 text-right ${ep.avg_ms > 500 ? 'text-red-600' : 'text-gray-900'}`}>
                      {ep.avg_ms}ms
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Discovery Runs */}
      {detail?.discovery_runs && detail.discovery_runs.length > 0 && (
        <div className="bg-white border rounded-xl p-5">
          <h2 className="text-sm font-semibold text-gray-900 mb-4">Recent Discovery Runs</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-gray-500 border-b">
                  <th className="pb-2 pr-4">Run ID</th>
                  <th className="pb-2 pr-4">Started</th>
                  <th className="pb-2 pr-4">Status</th>
                  <th className="pb-2 pr-4 text-right">Duration</th>
                  <th className="pb-2 pr-4 text-right">Identities</th>
                  <th className="pb-2 pr-4 text-right">Critical</th>
                  <th className="pb-2 text-right">High</th>
                </tr>
              </thead>
              <tbody>
                {detail.discovery_runs.map(run => (
                  <tr key={run.id} className="border-b last:border-0">
                    <td className="py-2 pr-4 text-gray-700">#{run.id}</td>
                    <td className="py-2 pr-4 text-xs text-gray-500">
                      {run.started_at ? new Date(run.started_at).toLocaleString() : '--'}
                    </td>
                    <td className="py-2 pr-4">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                        run.status === 'completed'
                          ? 'bg-green-100 text-green-700'
                          : run.status === 'running'
                          ? 'bg-blue-100 text-blue-700'
                          : 'bg-red-100 text-red-700'
                      }`}>
                        {run.status}
                      </span>
                    </td>
                    <td className="py-2 pr-4 text-right text-gray-700">
                      {run.duration_sec != null ? `${run.duration_sec}s` : '--'}
                    </td>
                    <td className="py-2 pr-4 text-right text-gray-900">{run.total_identities ?? '--'}</td>
                    <td className="py-2 pr-4 text-right text-red-600">{run.critical_count ?? 0}</td>
                    <td className="py-2 text-right text-orange-600">{run.high_count ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Database Tables */}
      {detail?.database?.tables && detail.database.tables.length > 0 && (
        <div className="bg-white border rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-gray-900">Database Tables (by size)</h2>
            <a href="/settings" className="text-xs text-blue-600 hover:underline">Retention Settings</a>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-gray-500 border-b">
                  <th className="pb-2 pr-4">Table</th>
                  <th className="pb-2 text-right">Size (MB)</th>
                </tr>
              </thead>
              <tbody>
                {detail.database.tables.map((t, i) => (
                  <tr key={i} className="border-b last:border-0">
                    <td className="py-2 pr-4 font-mono text-xs text-gray-700">{t.name}</td>
                    <td className="py-2 text-right text-gray-900">{t.size_mb}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
