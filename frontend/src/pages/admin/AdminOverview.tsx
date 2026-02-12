import React, { useEffect, useState } from 'react';

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
  risk_score: number;
}

interface GlobalMetrics {
  total_tenants: number;
  active_tenants: number;
  total_identities: number;
  total_critical: number;
  total_high: number;
  avg_risk_score: number;
}

interface AnalyticsData {
  global: GlobalMetrics;
  tenants: TenantMetric[];
}

function freshnessLabel(lastDiscovery: string | null): { text: string; color: string } {
  if (!lastDiscovery) return { text: 'Never', color: 'text-gray-400' };
  const hours = (Date.now() - new Date(lastDiscovery).getTime()) / 3600000;
  if (hours < 24) return { text: `${Math.round(hours)}h ago`, color: 'text-green-600' };
  if (hours < 72) return { text: `${Math.round(hours / 24)}d ago`, color: 'text-yellow-600' };
  return { text: `${Math.round(hours / 24)}d ago`, color: 'text-red-600' };
}

export default function AdminOverview() {
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/analytics/tenants')
      .then(r => {
        if (!r.ok) throw new Error('Forbidden');
        return r.json();
      })
      .then(setData)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="flex items-center justify-center h-64 text-gray-400">Loading platform data...</div>;
  if (!data) return <div className="text-gray-500 text-center py-8">Failed to load analytics data</div>;

  const { global: g, tenants } = data;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-gray-900">Platform Overview</h2>
        <p className="text-sm text-gray-500 mt-0.5">Cross-tenant health and activity summary</p>
      </div>

      {/* Global stats — 2 cards only per v3.0 spec */}
      <div className="grid grid-cols-2 gap-4">
        <StatCard label="Total Tenants" value={g.total_tenants} color="blue" />
        <StatCard label="Active Tenants" value={g.active_tenants} color="green" />
      </div>

      {/* Tenant health grid */}
      <div>
        <h3 className="text-sm font-semibold text-gray-800 mb-3">Tenant Health</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {tenants.map(t => {
            const fresh = freshnessLabel(t.last_discovery);
            return (
              <div key={t.id} className={`border rounded-lg p-4 ${t.enabled ? 'bg-white border-gray-200' : 'bg-gray-50 border-gray-200 opacity-60'}`}>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center text-xs font-bold">
                      {t.name.substring(0, 2).toUpperCase()}
                    </div>
                    <div>
                      <div className="text-sm font-semibold text-gray-900">{t.name}</div>
                      <div className="text-[10px] text-gray-500">{t.slug}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                      t.plan === 'enterprise' ? 'bg-purple-100 text-purple-700' :
                      t.plan === 'pro' ? 'bg-blue-100 text-blue-700' :
                      t.plan === 'trial' ? 'bg-amber-100 text-amber-700' :
                      'bg-gray-100 text-gray-600'
                    }`}>{t.plan}</span>
                    {!t.enabled && <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-100 text-red-700">Disabled</span>}
                  </div>
                </div>
                <div className="grid grid-cols-4 gap-2 text-center">
                  <div>
                    <div className="text-lg font-bold text-gray-800">{t.total_identities}</div>
                    <div className="text-[10px] text-gray-400">Identities</div>
                  </div>
                  <div>
                    <div className="text-lg font-bold text-gray-800">{t.user_count}</div>
                    <div className="text-[10px] text-gray-400">Users</div>
                  </div>
                  <div>
                    <div className={`text-lg font-bold ${t.critical_count > 0 ? 'text-red-600' : 'text-gray-800'}`}>{t.critical_count}</div>
                    <div className="text-[10px] text-gray-400">Critical</div>
                  </div>
                  <div>
                    <div className={`text-lg font-bold ${fresh.color}`}>{fresh.text}</div>
                    <div className="text-[10px] text-gray-400">Last Scan</div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  const colorMap: Record<string, string> = {
    blue: 'bg-blue-50 border-blue-200 text-blue-700',
    green: 'bg-green-50 border-green-200 text-green-700',
  };
  return (
    <div className={`border rounded-lg p-4 ${colorMap[color] || colorMap.blue}`}>
      <div className="text-3xl font-bold">{value}</div>
      <div className="text-xs font-medium opacity-80">{label}</div>
    </div>
  );
}
