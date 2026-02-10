import React, { useEffect, useState } from 'react';

interface TenantTrend {
  tenant_id: number;
  tenant_name: string;
  runs: Array<{
    id: number;
    started_at: string;
    completed_at: string | null;
    status: string;
    total_identities: number;
    critical_count: number;
  }>;
}

interface TenantMetric {
  id: number;
  name: string;
  slug: string;
  plan: string;
  enabled: boolean;
  user_count: number;
  total_runs: number;
  last_discovery: string | null;
  total_identities: number;
  critical_count: number;
  high_count: number;
}

export default function AdminMonitoring() {
  const [trends, setTrends] = useState<TenantTrend[]>([]);
  const [metrics, setMetrics] = useState<TenantMetric[]>([]);
  const [loading, setLoading] = useState(true);
  const [activity, setActivity] = useState<Array<Record<string, unknown>>>([]);

  useEffect(() => {
    Promise.all([
      fetch('/api/analytics/tenants').then(r => r.json()),
      fetch('/api/analytics/tenants/trends').then(r => r.json()).catch(() => ({ tenants: [] })),
      fetch('/api/activity?limit=20&type=auth_login').then(r => r.json()).catch(() => ({ activities: [] })),
    ]).then(([analytics, trendsData, activityData]) => {
      setMetrics(analytics.tenants || []);
      setTrends(trendsData.tenants || []);
      setActivity(activityData.activities || []);
    }).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="flex items-center justify-center h-64 text-gray-400">Loading monitoring data...</div>;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-gray-900">Monitoring</h2>
        <p className="text-sm text-gray-500 mt-0.5">Discovery health, usage, and login activity</p>
      </div>

      {/* Discovery Freshness */}
      <div className="bg-white border border-gray-200 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-800 mb-3">Discovery Freshness</h3>
        <div className="space-y-2">
          {metrics.map(t => {
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
                  <span className="text-gray-500">{t.total_identities} identities</span>
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

      {/* Discovery Timeline */}
      {trends.length > 0 && (
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-800 mb-3">Recent Discovery Runs</h3>
          <div className="space-y-1 max-h-64 overflow-y-auto">
            {trends.flatMap(t => t.runs.map(r => ({ ...r, tenant_name: t.tenant_name })))
              .sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime())
              .slice(0, 20)
              .map((r, i) => (
                <div key={i} className="flex items-center justify-between py-1.5 text-xs border-b border-gray-50 last:border-0">
                  <div className="flex items-center gap-2">
                    <span className={`w-1.5 h-1.5 rounded-full ${r.status === 'completed' ? 'bg-green-500' : r.status === 'running' ? 'bg-blue-500 animate-pulse' : 'bg-red-500'}`} />
                    <span className="font-medium text-gray-700">{r.tenant_name}</span>
                  </div>
                  <div className="flex items-center gap-3 text-gray-500">
                    <span>{r.total_identities} identities</span>
                    {r.critical_count > 0 && <span className="text-red-600 font-semibold">{r.critical_count} critical</span>}
                    <span>{formatTimeAgo(r.started_at)}</span>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Recent Login Activity */}
      <div className="bg-white border border-gray-200 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-800 mb-3">Recent Login Activity</h3>
        <div className="space-y-1 max-h-48 overflow-y-auto">
          {activity.map((a, i) => (
            <div key={i} className="flex items-center justify-between py-1.5 text-xs border-b border-gray-50 last:border-0">
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
                <span className="text-gray-700">{String(a.description || '')}</span>
              </div>
              <span className="text-gray-400">{a.created_at ? formatTimeAgo(String(a.created_at)) : '—'}</span>
            </div>
          ))}
          {activity.length === 0 && <p className="text-sm text-gray-400 text-center py-4">No recent login activity</p>}
        </div>
      </div>
    </div>
  );
}

function formatTimeAgo(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime();
  const minutes = Math.floor(ms / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
