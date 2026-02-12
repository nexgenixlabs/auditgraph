import React, { useEffect, useState, useMemo } from 'react';
import {
  CLOUD_PRICING, ADDON_PRICING, CLOUD_LABELS, ANNUAL_DISCOUNT,
  ACCOUNT_TIER_LABELS, calculateMonthlyTotal, type CloudConfig,
} from '../../constants/pricing';

interface TenantBilling {
  id: number;
  name: string;
  slug: string;
  plan: string;
  enabled: boolean;
  user_count: number;
  license_activated_at: string | null;
  license_expires_at: string | null;
  settings?: Record<string, unknown>;
}

const PLAN_LABELS = ACCOUNT_TIER_LABELS;

function getTenantConfig(t: TenantBilling): CloudConfig {
  const settings = (t.settings || {}) as Record<string, unknown>;
  return {
    cloud_providers: (settings.cloud_providers || {
      azure: { enabled: true, plan: 'starter' },
      aws: { enabled: false, plan: null },
      gcp: { enabled: false, plan: null },
    }) as CloudConfig['cloud_providers'],
    addons: (settings.addons || {}) as CloudConfig['addons'],
  };
}

function getTenantMrr(t: TenantBilling): number {
  if (!t.enabled) return 0;
  return calculateMonthlyTotal(getTenantConfig(t));
}

function formatDate(iso: string | null): string {
  if (!iso) return '\u2014';
  return new Date(iso).toLocaleDateString();
}

function licenseLabel(t: TenantBilling): { text: string; color: string } {
  if (!t.license_activated_at) return { text: 'Not Activated', color: 'text-gray-400' };
  if (t.license_expires_at) {
    const days = Math.ceil((new Date(t.license_expires_at).getTime() - Date.now()) / 86400000);
    if (days < 0) return { text: 'Expired', color: 'text-red-600' };
    if (days < 30) return { text: `${days}d left`, color: 'text-yellow-600' };
  }
  return { text: 'Active', color: 'text-green-600' };
}

export default function AdminBilling() {
  const [tenants, setTenants] = useState<TenantBilling[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/tenants')
      .then(r => r.ok ? r.json() : { tenants: [] })
      .then(d => setTenants(d.tenants || []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const planCounts = tenants.reduce<Record<string, number>>((acc, t) => {
    acc[t.plan] = (acc[t.plan] || 0) + 1;
    return acc;
  }, {});

  const totalUsers = tenants.reduce((sum, t) => sum + t.user_count, 0);

  const totalMrr = useMemo(() => tenants.reduce((sum, t) => sum + getTenantMrr(t), 0), [tenants]);
  const projectedArr = totalMrr * 12 * (1 - ANNUAL_DISCOUNT);

  // Revenue by cloud provider
  const revenueByCloud = useMemo(() => {
    const result: Record<string, number> = { azure: 0, aws: 0, gcp: 0 };
    for (const t of tenants) {
      if (!t.enabled) continue;
      const cfg = getTenantConfig(t);
      for (const [provider, pCfg] of Object.entries(cfg.cloud_providers)) {
        if (pCfg.enabled && pCfg.plan && CLOUD_PRICING[provider]) {
          result[provider] = (result[provider] || 0) + (CLOUD_PRICING[provider][pCfg.plan] ?? 0);
        }
      }
    }
    return result;
  }, [tenants]);

  // Revenue by add-on
  const revenueByAddon = useMemo(() => {
    const result: Record<string, { revenue: number; count: number }> = {};
    for (const key of Object.keys(ADDON_PRICING)) {
      result[key] = { revenue: 0, count: 0 };
    }
    for (const t of tenants) {
      if (!t.enabled) continue;
      const cfg = getTenantConfig(t);
      for (const [addon, enabled] of Object.entries(cfg.addons)) {
        if (enabled && ADDON_PRICING[addon]) {
          result[addon] = {
            revenue: (result[addon]?.revenue || 0) + ADDON_PRICING[addon].price,
            count: (result[addon]?.count || 0) + 1,
          };
        }
      }
    }
    return result;
  }, [tenants]);

  if (loading) return <div className="flex items-center justify-center h-64 text-gray-400">Loading billing data...</div>;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-gray-900">Billing & Revenue</h2>
        <p className="text-sm text-gray-500 mt-0.5">Revenue tracking, plan distribution, and licensing</p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-6 gap-4">
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="text-2xl font-bold text-gray-900">{tenants.length}</div>
          <div className="text-xs text-gray-500 mt-1">Total Organizations</div>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="text-2xl font-bold text-gray-900">{totalUsers}</div>
          <div className="text-xs text-gray-500 mt-1">Total Users</div>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="text-2xl font-bold text-gray-900">{tenants.filter(t => t.enabled).length}</div>
          <div className="text-xs text-gray-500 mt-1">Active Tenants</div>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="text-2xl font-bold text-purple-700">{planCounts.enterprise || 0}</div>
          <div className="text-xs text-gray-500 mt-1">Enterprise Licenses</div>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="text-2xl font-bold text-green-700">${totalMrr.toLocaleString()}</div>
          <div className="text-xs text-gray-500 mt-1">Total MRR</div>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="text-2xl font-bold text-blue-700">${Math.round(projectedArr).toLocaleString()}</div>
          <div className="text-xs text-gray-500 mt-1">Projected ARR</div>
        </div>
      </div>

      {/* Plan distribution */}
      <div className="bg-white border border-gray-200 rounded-lg p-6">
        <h3 className="text-sm font-semibold text-gray-800 mb-4">Plan Distribution</h3>
        <div className="flex gap-6">
          {['free', 'trial', 'pro', 'enterprise'].map(plan => {
            const count = planCounts[plan] || 0;
            const pct = tenants.length > 0 ? Math.round((count / tenants.length) * 100) : 0;
            const cfg = PLAN_LABELS[plan] || PLAN_LABELS.free;
            const barColor = plan === 'enterprise' ? 'bg-purple-500' : plan === 'pro' ? 'bg-blue-500' : plan === 'trial' ? 'bg-amber-500' : 'bg-gray-400';
            return (
              <div key={plan} className="flex-1">
                <div className="flex items-center justify-between mb-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold ${cfg.bg} ${cfg.color}`}>{cfg.label}</span>
                  <span className="text-sm font-bold text-gray-900">{count}</span>
                </div>
                <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${barColor}`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <div className="text-[10px] text-gray-400 mt-1">{pct}% of tenants</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Active Users by Tenant */}
      <div className="bg-white border border-gray-200 rounded-lg p-6">
        <h3 className="text-sm font-semibold text-gray-800 mb-4">Active Users by Tenant</h3>
        <div className="space-y-2">
          {[...tenants].sort((a, b) => b.user_count - a.user_count).map(t => {
            const maxUsers = Math.max(...tenants.map(t2 => t2.user_count), 1);
            const pct = Math.round((t.user_count / maxUsers) * 100);
            const planCfg = PLAN_LABELS[t.plan] || PLAN_LABELS.free;
            return (
              <div key={t.id} className="flex items-center gap-3">
                <div className="w-32 text-xs font-medium text-gray-700 truncate">{t.name}</div>
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${planCfg.bg} ${planCfg.color}`}>{planCfg.label}</span>
                <div className="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-500 rounded-full transition-all"
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <span className="text-xs font-bold text-gray-800 w-8 text-right">{t.user_count}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Revenue breakdowns */}
      <div className="grid grid-cols-2 gap-4">
        {/* Revenue by Cloud */}
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <h3 className="text-sm font-semibold text-gray-800 mb-4">Revenue by Cloud Provider</h3>
          <div className="space-y-3">
            {Object.entries(CLOUD_LABELS).map(([key, meta]) => {
              const revenue = revenueByCloud[key] || 0;
              const pct = totalMrr > 0 ? Math.round((revenue / totalMrr) * 100) : 0;
              return (
                <div key={key}>
                  <div className="flex items-center justify-between mb-1">
                    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${meta.bg} ${meta.color}`}>{meta.label}</span>
                    <span className="text-sm font-bold text-gray-900">${revenue.toLocaleString()}/mo</span>
                  </div>
                  <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${key === 'azure' ? 'bg-blue-500' : key === 'aws' ? 'bg-orange-500' : 'bg-red-500'}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <div className="text-[10px] text-gray-400 mt-0.5">{pct}% of MRR</div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Revenue by Add-on */}
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <h3 className="text-sm font-semibold text-gray-800 mb-4">Add-on Revenue</h3>
          <div className="space-y-3">
            {Object.entries(ADDON_PRICING).map(([key, addon]) => {
              const data = revenueByAddon[key] || { revenue: 0, count: 0 };
              return (
                <div key={key} className="flex items-center justify-between">
                  <div>
                    <div className="text-xs font-medium text-gray-800">{addon.label}</div>
                    <div className="text-[10px] text-gray-400">{data.count} tenant{data.count !== 1 ? 's' : ''}</div>
                  </div>
                  <span className="text-sm font-bold text-gray-900">${data.revenue.toLocaleString()}/mo</span>
                </div>
              );
            })}
            <div className="border-t border-gray-200 pt-2 mt-2 flex items-center justify-between">
              <span className="text-xs font-semibold text-gray-700">Total Add-on Revenue</span>
              <span className="text-sm font-bold text-green-700">
                ${Object.values(revenueByAddon).reduce((s, d) => s + d.revenue, 0).toLocaleString()}/mo
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Organization Licenses table */}
      <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-200">
          <h3 className="text-sm font-semibold text-gray-800">Organization Licenses</h3>
        </div>
        <table className="min-w-full text-left text-xs">
          <thead className="bg-gray-50 border-b border-gray-200 text-gray-600 uppercase tracking-wider font-medium">
            <tr>
              <th className="px-4 py-2.5">Organization</th>
              <th className="px-4 py-2.5">Plan</th>
              <th className="px-4 py-2.5">Clouds</th>
              <th className="px-4 py-2.5">Add-ons</th>
              <th className="px-4 py-2.5">Users</th>
              <th className="px-4 py-2.5">License Status</th>
              <th className="px-4 py-2.5">Activated</th>
              <th className="px-4 py-2.5">Expires</th>
              <th className="px-4 py-2.5">Status</th>
              <th className="px-4 py-2.5 text-right">MRR</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {tenants.map(t => {
              const cfg = getTenantConfig(t);
              const enabledClouds = Object.entries(cfg.cloud_providers).filter(([, v]) => v.enabled).map(([k]) => k);
              const cloudsToShow = enabledClouds.length > 0 ? enabledClouds : ['azure'];
              const addonCount = Object.values(cfg.addons).filter(Boolean).length;
              const mrr = getTenantMrr(t);
              const planCfg = PLAN_LABELS[t.plan] || PLAN_LABELS.free;
              const ls = licenseLabel(t);
              return (
                <tr key={t.id} className="hover:bg-gray-50/60">
                  <td className="px-4 py-2.5 font-medium text-gray-900">{t.name}</td>
                  <td className="px-4 py-2.5">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${planCfg.bg} ${planCfg.color}`}>{planCfg.label}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex gap-1 flex-wrap">
                      {cloudsToShow.map(cloud => {
                        const meta = CLOUD_LABELS[cloud];
                        return meta ? (
                          <span key={cloud} className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${meta.bg} ${meta.color}`}>{meta.label}</span>
                        ) : null;
                      })}
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-gray-700">
                    {addonCount > 0 ? (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-green-100 text-green-700">{addonCount} add-on{addonCount !== 1 ? 's' : ''}</span>
                    ) : (
                      <span className="text-gray-400">&mdash;</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-gray-700">{t.user_count}</td>
                  <td className="px-4 py-2.5">
                    <span className={`text-[10px] font-semibold ${ls.color}`}>{ls.text}</span>
                  </td>
                  <td className="px-4 py-2.5 text-gray-500">{formatDate(t.license_activated_at)}</td>
                  <td className="px-4 py-2.5 text-gray-500">{formatDate(t.license_expires_at)}</td>
                  <td className="px-4 py-2.5">
                    <span className={`text-[10px] font-semibold ${t.enabled ? 'text-green-600' : 'text-red-500'}`}>
                      {t.enabled ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-right font-semibold text-gray-900">${mrr.toLocaleString()}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
