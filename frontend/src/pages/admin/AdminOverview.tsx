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
  license_activated_at: string | null;
  license_expires_at: string | null;
  clouds_enabled: string[];
}

interface GlobalMetrics {
  total_tenants: number;
  active_tenants: number;
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

function licenseLabel(expiresAt: string | null): { text: string; color: string } {
  if (!expiresAt) return { text: '-', color: 'text-gray-400' };
  const days = (new Date(expiresAt).getTime() - Date.now()) / 86400000;
  if (days < 0) return { text: 'Expired', color: 'text-red-600' };
  if (days < 30) return { text: `${Math.round(days)}d left`, color: 'text-yellow-600' };
  return { text: `${Math.round(days)}d left`, color: 'text-green-600' };
}

function formatDate(d: string | null): string {
  if (!d) return '-';
  return new Date(d).toLocaleDateString();
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

      {/* Tenant health table */}
      <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-200">
          <h3 className="text-sm font-semibold text-gray-800">Tenant Health</h3>
        </div>
        <table className="min-w-full text-left text-xs">
          <thead className="bg-gray-50 border-b border-gray-200 text-gray-600 uppercase tracking-wider font-medium">
            <tr>
              <th className="px-4 py-2.5">Tenant</th>
              <th className="px-4 py-2.5">Users</th>
              <th className="px-4 py-2.5">License Model</th>
              <th className="px-4 py-2.5">Cloud Providers</th>
              <th className="px-4 py-2.5">Status</th>
              <th className="px-4 py-2.5">Last Scan</th>
              <th className="px-4 py-2.5">License Activated</th>
              <th className="px-4 py-2.5">License Expiry</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {tenants.map(t => {
              const fresh = freshnessLabel(t.last_discovery);
              const lic = licenseLabel(t.license_expires_at);
              return (
                <tr key={t.id} className={`hover:bg-gray-50 ${!t.enabled ? 'opacity-60' : ''}`}>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center text-[10px] font-bold shrink-0">
                        {t.name.substring(0, 2).toUpperCase()}
                      </div>
                      <div>
                        <div className="text-sm font-semibold text-gray-900">{t.name}</div>
                        <div className="text-[10px] text-gray-500">{t.slug}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-sm font-bold text-gray-800">{t.user_count}</td>
                  <td className="px-4 py-2.5">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold capitalize ${
                      t.plan === 'enterprise' ? 'bg-purple-100 text-purple-700' :
                      t.plan === 'pro' ? 'bg-blue-100 text-blue-700' :
                      t.plan === 'trial' ? 'bg-amber-100 text-amber-700' :
                      'bg-gray-100 text-gray-600'
                    }`}>{t.plan}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-0.5 flex-wrap">
                      {(t.clouds_enabled || []).length > 0 ? (t.clouds_enabled || []).map(c => (
                        <span key={c} className={`px-1 py-0.5 rounded text-[9px] font-bold ${
                          c === 'azure' ? 'bg-blue-100 text-blue-700' :
                          c === 'aws' ? 'bg-orange-100 text-orange-700' :
                          'bg-red-100 text-red-600'
                        }`}>{c.toUpperCase()}</span>
                      )) : <span className="text-[10px] text-gray-400">&mdash;</span>}
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                      t.enabled ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                    }`}>{t.enabled ? 'Active' : 'Disabled'}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`text-xs font-semibold ${fresh.color}`}>{fresh.text}</span>
                  </td>
                  <td className="px-4 py-2.5 text-gray-500">{formatDate(t.license_activated_at)}</td>
                  <td className="px-4 py-2.5">
                    <span className={`text-xs font-semibold ${lic.color}`}>{lic.text}</span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
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
