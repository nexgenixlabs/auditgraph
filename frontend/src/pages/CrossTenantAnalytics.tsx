import React, { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { api } from '../services/apiClient';
import { SnapshotContextHeader } from '../components/ui/SnapshotContextHeader';

// ── Types ──────────────────────────────────────────────────────

interface TenantMetrics {
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
  medium_count: number;
  low_count: number;
  prev_total: number | null;
  prev_critical: number | null;
  prev_high: number | null;
  risk_score: number;
}

interface GlobalMetrics {
  total_orgs: number;
  active_orgs: number;
  total_identities: number;
  total_critical: number;
  total_high: number;
  avg_risk_score: number;
}

interface AnalyticsResponse {
  organizations: TenantMetrics[];
  global: GlobalMetrics;
}

type SortKey = 'name' | 'plan' | 'user_count' | 'total_identities' | 'critical_count' | 'high_count' | 'risk_score' | 'last_discovery';

// ── Helpers ────────────────────────────────────────────────────

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return 'Never';
  const now = new Date();
  const date = new Date(dateStr);
  const hours = Math.floor((now.getTime() - date.getTime()) / 3600000);
  if (hours < 1) return 'Just now';
  if (hours < 24) return `${hours}h ago`;
  if (hours < 72) return `${Math.floor(hours / 24)}d ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function freshnessColor(dateStr: string | null): string {
  if (!dateStr) return 'text-gray-400';
  const hours = (Date.now() - new Date(dateStr).getTime()) / 3600000;
  if (hours < 24) return 'text-green-600';
  if (hours < 72) return 'text-yellow-600';
  return 'text-red-600';
}

function scoreColor(score: number): string {
  if (score >= 80) return 'text-green-700 bg-green-50';
  if (score >= 60) return 'text-yellow-700 bg-yellow-50';
  return 'text-red-700 bg-red-50';
}

function trendArrow(current: number, prev: number | null): React.ReactNode {
  if (prev === null || prev === undefined) return <span className="text-gray-400 text-xs">--</span>;
  const delta = current - prev;
  if (delta > 0) return <span className="text-red-600 text-xs font-medium">+{delta}</span>;
  if (delta < 0) return <span className="text-green-600 text-xs font-medium">{delta}</span>;
  return <span className="text-gray-400 text-xs">--</span>;
}

// ── Component ──────────────────────────────────────────────────

export default function CrossTenantAnalytics() {
  const navigate = useNavigate();
  const { isSuperAdmin, switchOrganization } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<AnalyticsResponse | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>('risk_score');
  const [sortAsc, setSortAsc] = useState(false);

  useEffect(() => {
    if (!isSuperAdmin) {
      setError('This page is only accessible to superadmins.');
      setLoading(false);
      return;
    }
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const json = await api.get('/analytics/clients');
        setData(json);
      } catch (e: any) {
        setError(e?.message || 'Failed to load analytics');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [isSuperAdmin]);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortAsc(!sortAsc);
    } else {
      setSortKey(key);
      setSortAsc(key === 'name');
    }
  };

  const sorted = useMemo(() => {
    if (!data?.organizations) return [];
    const items = [...data.organizations];
    items.sort((a, b) => {
      let av: any = a[sortKey];
      let bv: any = b[sortKey];
      if (sortKey === 'last_discovery') {
        av = av ? new Date(av).getTime() : 0;
        bv = bv ? new Date(bv).getTime() : 0;
      }
      if (typeof av === 'string') return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
      return sortAsc ? (av ?? 0) - (bv ?? 0) : (bv ?? 0) - (av ?? 0);
    });
    return items;
  }, [data, sortKey, sortAsc]);

  const handleTenantClick = (tenant: TenantMetrics) => {
    switchOrganization(tenant.id, tenant.name);
    navigate('/dashboard');
  };

  // ── Loading ──────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-gray-200 rounded w-64" />
          <div className="grid grid-cols-4 gap-4">
            {[1, 2, 3, 4].map(i => <div key={i} className="h-24 bg-gray-100 rounded-xl" />)}
          </div>
          <div className="h-96 bg-gray-100 rounded-xl" />
        </div>
      </div>
    );
  }

  // ── Error ────────────────────────────────────────────────────
  if (error) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-red-700">
          <div className="font-semibold">Error</div>
          <div className="text-sm mt-1">{error}</div>
        </div>
      </div>
    );
  }

  if (!data) return null;

  const g = data.global;

  const SortHeader = ({ label, field, className }: { label: string; field: SortKey; className?: string }) => (
    <th
      className={`px-4 py-3 font-medium text-gray-600 cursor-pointer hover:text-gray-900 select-none ${className || ''}`}
      onClick={() => handleSort(field)}
    >
      <span className="inline-flex items-center gap-1">
        {label}
        {sortKey === field && (
          <span className="text-blue-600">{sortAsc ? '\u25B2' : '\u25BC'}</span>
        )}
      </span>
    </th>
  );

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-4">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Cross-Client Analytics</h2>
        <p className="text-sm text-gray-600 mt-1">
          Aggregated risk posture across all clients
        </p>
        <SnapshotContextHeader />
      </div>

      {/* Global Stats Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-white border rounded-xl p-5">
          <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">Total Clients</div>
          <div className="text-3xl font-bold text-gray-900 mt-1">{g.total_orgs}</div>
        </div>
        <div className="bg-white border rounded-xl p-5">
          <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">Active Clients</div>
          <div className="text-3xl font-bold text-green-700 mt-1">{g.active_orgs}</div>
          <div className="text-xs text-gray-400 mt-0.5">with discovery data</div>
        </div>
        <div className="bg-white border rounded-xl p-5">
          <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">Total Identities</div>
          <div className="text-3xl font-bold text-gray-900 mt-1">{g.total_identities.toLocaleString()}</div>
        </div>
        <div className="bg-white border rounded-xl p-5">
          <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">Critical Identities</div>
          <div className="text-3xl font-bold text-red-700 mt-1">{g.total_critical}</div>
          <div className="text-xs text-gray-400 mt-0.5">{g.total_high} high risk</div>
        </div>
      </div>

      {/* Average Risk Score */}
      <div className="bg-white border rounded-xl p-5 flex items-center gap-4">
        <div>
          <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">Avg Risk Score</div>
          <div className={`text-4xl font-bold mt-1 px-3 py-1 rounded-lg inline-block ${scoreColor(g.avg_risk_score)}`}>
            {g.avg_risk_score}
          </div>
        </div>
        <div className="text-xs text-gray-500 max-w-sm">
          Weighted average across all tenants. Higher is better. Score = 100 - (critical x 15 + high x 5 + medium x 1), clamped 0-100.
        </div>
      </div>

      {/* Tenant Comparison Table */}
      <div className="bg-white border rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b bg-gray-50">
          <h3 className="text-sm font-semibold text-gray-700">Client Comparison</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-50 border-b text-left">
                <SortHeader label="Client" field="name" />
                <SortHeader label="Plan" field="plan" className="w-20" />
                <SortHeader label="Users" field="user_count" className="w-20 text-right" />
                <SortHeader label="Identities" field="total_identities" className="w-24 text-right" />
                <SortHeader label="Critical" field="critical_count" className="w-20 text-right" />
                <SortHeader label="High" field="high_count" className="w-20 text-right" />
                <SortHeader label="Score" field="risk_score" className="w-20 text-center" />
                <SortHeader label="Last Snapshot" field="last_discovery" className="w-36 text-right" />
                <th className="px-4 py-3 font-medium text-gray-600 w-20 text-right">Trend</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map(tenant => (
                <tr key={tenant.id} className="border-b hover:bg-gray-50 transition">
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleTenantClick(tenant)}
                      className="text-blue-600 hover:text-blue-800 font-medium hover:underline text-left"
                    >
                      {tenant.name}
                    </button>
                    <div className="text-[10px] text-gray-400">{tenant.slug}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                      tenant.plan === 'pro' ? 'bg-blue-50 text-blue-700' :
                      tenant.plan === 'trial' ? 'bg-amber-50 text-amber-700' :
                      'bg-gray-100 text-gray-600'
                    }`}>
                      {tenant.plan}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right text-gray-700">{tenant.user_count}</td>
                  <td className="px-4 py-3 text-right text-gray-700">
                    {tenant.total_identities}
                    {tenant.prev_total !== null && tenant.prev_total !== undefined && (
                      <span className="ml-1">{trendArrow(tenant.total_identities, tenant.prev_total)}</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <span className={tenant.critical_count > 0 ? 'text-red-700 font-semibold' : 'text-gray-400'}>
                      {tenant.critical_count}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <span className={tenant.high_count > 0 ? 'text-orange-700 font-medium' : 'text-gray-400'}>
                      {tenant.high_count}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-center">
                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${scoreColor(tenant.risk_score)}`}>
                      {tenant.risk_score}
                    </span>
                  </td>
                  <td className={`px-4 py-3 text-right text-xs ${freshnessColor(tenant.last_discovery)}`}>
                    {timeAgo(tenant.last_discovery)}
                    {tenant.last_discovery && (
                      <div className="text-[10px] text-gray-400">
                        {new Date(tenant.last_discovery).toLocaleDateString()}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {trendArrow(tenant.critical_count, tenant.prev_critical)}
                  </td>
                </tr>
              ))}
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-4 py-12 text-center text-gray-400">
                    No clients found. Create clients in Settings to see analytics.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Risk Distribution Bars */}
      {sorted.length > 0 && (
        <div className="bg-white border rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b bg-gray-50">
            <h3 className="text-sm font-semibold text-gray-700">Risk Distribution by Client</h3>
          </div>
          <div className="p-6 space-y-4">
            {sorted.map(tenant => {
              const total = tenant.critical_count + tenant.high_count + tenant.medium_count + tenant.low_count;
              if (total === 0) {
                return (
                  <div key={tenant.id} className="flex items-center gap-3">
                    <div className="w-28 text-xs font-medium text-gray-700 truncate">{tenant.name}</div>
                    <div className="flex-1 h-6 bg-gray-100 rounded-full overflow-hidden flex items-center justify-center">
                      <span className="text-[10px] text-gray-400">No data</span>
                    </div>
                    <div className="w-12 text-right text-xs text-gray-400">0</div>
                  </div>
                );
              }
              const pct = (v: number) => Math.max(v > 0 ? 2 : 0, (v / total) * 100);
              return (
                <div key={tenant.id} className="flex items-center gap-3">
                  <div className="w-28 text-xs font-medium text-gray-700 truncate" title={tenant.name}>{tenant.name}</div>
                  <div className="flex-1 h-6 bg-gray-100 rounded-full overflow-hidden flex">
                    {tenant.critical_count > 0 && (
                      <div
                        className="bg-red-500 h-full flex items-center justify-center text-[10px] text-white font-medium"
                        style={{ width: `${pct(tenant.critical_count)}%` }}
                        title={`Critical: ${tenant.critical_count}`}
                      >
                        {tenant.critical_count > 0 && pct(tenant.critical_count) > 8 ? tenant.critical_count : ''}
                      </div>
                    )}
                    {tenant.high_count > 0 && (
                      <div
                        className="bg-orange-400 h-full flex items-center justify-center text-[10px] text-white font-medium"
                        style={{ width: `${pct(tenant.high_count)}%` }}
                        title={`High: ${tenant.high_count}`}
                      >
                        {pct(tenant.high_count) > 8 ? tenant.high_count : ''}
                      </div>
                    )}
                    {tenant.medium_count > 0 && (
                      <div
                        className="bg-yellow-400 h-full flex items-center justify-center text-[10px] text-gray-700 font-medium"
                        style={{ width: `${pct(tenant.medium_count)}%` }}
                        title={`Medium: ${tenant.medium_count}`}
                      >
                        {pct(tenant.medium_count) > 8 ? tenant.medium_count : ''}
                      </div>
                    )}
                    {tenant.low_count > 0 && (
                      <div
                        className="bg-green-400 h-full flex items-center justify-center text-[10px] text-white font-medium"
                        style={{ width: `${pct(tenant.low_count)}%` }}
                        title={`Low: ${tenant.low_count}`}
                      >
                        {pct(tenant.low_count) > 8 ? tenant.low_count : ''}
                      </div>
                    )}
                  </div>
                  <div className="w-12 text-right text-xs text-gray-500">{total}</div>
                </div>
              );
            })}
            {/* Legend */}
            <div className="flex items-center gap-4 pt-2 border-t mt-2">
              <div className="flex items-center gap-1"><div className="w-3 h-3 rounded bg-red-500" /><span className="text-[10px] text-gray-500">Critical</span></div>
              <div className="flex items-center gap-1"><div className="w-3 h-3 rounded bg-orange-400" /><span className="text-[10px] text-gray-500">High</span></div>
              <div className="flex items-center gap-1"><div className="w-3 h-3 rounded bg-yellow-400" /><span className="text-[10px] text-gray-500">Medium</span></div>
              <div className="flex items-center gap-1"><div className="w-3 h-3 rounded bg-green-400" /><span className="text-[10px] text-gray-500">Low</span></div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
