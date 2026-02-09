import React, { useState, useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';

interface RoleMiningData {
  summary: {
    total_roles: number;
    unused: number;
    redundant: number;
    orphaned: number;
    overprivileged: number;
    optimization_pct: number;
  };
  findings: Finding[];
  role_frequency: RoleFrequency[];
  role_bundles: RoleBundle[];
}

interface Finding {
  identity_id: string;
  identity_name: string;
  identity_category: string;
  role_name: string;
  source: string;
  type: string;
  risk_level: string;
  days_since_assigned: number | null;
  scope: string | null;
  recommendation: string;
}

interface RoleFrequency {
  role_name: string;
  source: string;
  assignment_count: number;
}

interface RoleBundle {
  role_a: string;
  role_b: string;
  co_count: number;
}

const TYPE_CONFIG: Record<string, { label: string; bg: string; text: string }> = {
  definitely_unused: { label: 'Unused', bg: 'bg-red-50', text: 'text-red-700' },
  likely_unused: { label: 'Likely Unused', bg: 'bg-orange-50', text: 'text-orange-700' },
  redundant: { label: 'Redundant', bg: 'bg-yellow-50', text: 'text-yellow-700' },
  orphaned: { label: 'Orphaned', bg: 'bg-purple-50', text: 'text-purple-700' },
  overprivileged: { label: 'Over-Privileged', bg: 'bg-amber-50', text: 'text-amber-700' },
};

const RISK_COLORS: Record<string, string> = {
  critical: 'text-red-600 bg-red-50',
  high: 'text-orange-600 bg-orange-50',
  medium: 'text-yellow-700 bg-yellow-50',
  low: 'text-blue-600 bg-blue-50',
  unknown: 'text-gray-500 bg-gray-50',
};

const CATEGORY_LABELS: Record<string, string> = {
  service_principal: 'Service Principal',
  managed_identity_system: 'System MI',
  managed_identity_user: 'User MI',
  human_user: 'Human',
  guest: 'Guest',
  microsoft_internal: 'MS Internal',
};

export default function RoleMining() {
  const [data, setData] = useState<RoleMiningData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch('/api/role-mining');
        if (!res.ok) throw new Error(`API error: ${res.status}`);
        const json = await res.json();
        setData(json);
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : 'Failed to load');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const filtered = useMemo(() => {
    if (!data) return [];
    return data.findings.filter(f => {
      if (typeFilter && f.type !== typeFilter) return false;
      if (riskFilter && f.risk_level !== riskFilter) return false;
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        return f.identity_name.toLowerCase().includes(term) || f.role_name.toLowerCase().includes(term);
      }
      return true;
    });
  }, [data, typeFilter, riskFilter, searchTerm]);

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse space-y-6">
          <div className="h-8 bg-gray-200 rounded w-72" />
          <div className="grid grid-cols-5 gap-4">
            {[...Array(5)].map((_, i) => <div key={i} className="h-20 bg-gray-100 rounded-xl" />)}
          </div>
          <div className="h-96 bg-gray-100 rounded-xl" />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-red-700">
          <div className="font-semibold">Error loading role mining data</div>
          <div className="text-sm mt-1">{error}</div>
        </div>
      </div>
    );
  }

  if (!data) return null;
  const { summary, role_frequency, role_bundles } = data;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Role Mining & Optimization</h2>
        <p className="text-sm text-gray-600 mt-1">Analyze role assignments to find unused, redundant, and over-provisioned access</p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        <div className="bg-white border rounded-xl p-4">
          <div className="text-xs text-gray-500 font-medium">Total Roles</div>
          <div className="text-2xl font-bold text-gray-900 mt-1">{summary.total_roles}</div>
        </div>
        <div className="bg-red-50 border border-red-200 rounded-xl p-4">
          <div className="text-xs text-red-600 font-medium">Unused</div>
          <div className="text-2xl font-bold text-red-700 mt-1">{summary.unused}</div>
        </div>
        <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-4">
          <div className="text-xs text-yellow-700 font-medium">Redundant</div>
          <div className="text-2xl font-bold text-yellow-800 mt-1">{summary.redundant}</div>
        </div>
        <div className="bg-purple-50 border border-purple-200 rounded-xl p-4">
          <div className="text-xs text-purple-600 font-medium">Orphaned</div>
          <div className="text-2xl font-bold text-purple-700 mt-1">{summary.orphaned}</div>
        </div>
        <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
          <div className="text-xs text-blue-600 font-medium">Optimization</div>
          <div className="text-2xl font-bold text-blue-700 mt-1">{summary.optimization_pct}%</div>
          <div className="text-[10px] text-blue-500 mt-0.5">of roles actionable</div>
        </div>
      </div>

      {/* Findings Section */}
      <div className="bg-white border rounded-xl shadow-sm overflow-hidden">
        {/* Filter Bar */}
        <div className="px-6 py-4 border-b flex flex-wrap items-center gap-3">
          <input
            type="text"
            placeholder="Search identity or role..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="px-3 py-1.5 border rounded-lg text-sm w-56 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          />
          <select
            value={typeFilter}
            onChange={e => setTypeFilter(e.target.value)}
            className="px-3 py-1.5 border rounded-lg text-sm bg-white focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Types</option>
            {Object.entries(TYPE_CONFIG).map(([k, v]) => (
              <option key={k} value={k}>{v.label}</option>
            ))}
          </select>
          <select
            value={riskFilter}
            onChange={e => setRiskFilter(e.target.value)}
            className="px-3 py-1.5 border rounded-lg text-sm bg-white focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Risk Levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <span className="text-xs text-gray-500 ml-auto">{filtered.length} findings</span>
        </div>

        {/* Table */}
        {filtered.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <div className="text-gray-400 font-medium">No findings match your filters</div>
            <div className="text-sm text-gray-300 mt-1">Try adjusting the search or filter criteria</div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-gray-50 border-b text-left">
                  <th className="px-4 py-3 font-medium text-gray-600">Identity</th>
                  <th className="px-4 py-3 font-medium text-gray-600">Category</th>
                  <th className="px-4 py-3 font-medium text-gray-600">Role</th>
                  <th className="px-4 py-3 font-medium text-gray-600">Source</th>
                  <th className="px-4 py-3 font-medium text-gray-600">Type</th>
                  <th className="px-4 py-3 font-medium text-gray-600">Risk</th>
                  <th className="px-4 py-3 font-medium text-gray-600">Age</th>
                  <th className="px-4 py-3 font-medium text-gray-600">Recommendation</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((f, i) => {
                  const tc = TYPE_CONFIG[f.type] || { label: f.type, bg: 'bg-gray-50', text: 'text-gray-600' };
                  const rc = RISK_COLORS[f.risk_level] || 'text-gray-500 bg-gray-50';
                  return (
                    <tr key={i} className="border-b last:border-b-0 hover:bg-gray-50 transition">
                      <td className="px-4 py-3">
                        <Link to={`/identities/${f.identity_id}`} className="text-blue-600 hover:underline font-medium">
                          {f.identity_name}
                        </Link>
                      </td>
                      <td className="px-4 py-3 text-gray-600 text-xs">
                        {CATEGORY_LABELS[f.identity_category] || f.identity_category || '-'}
                      </td>
                      <td className="px-4 py-3 font-medium text-gray-900">{f.role_name}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                          f.source === 'entra' ? 'bg-indigo-50 text-indigo-600' : 'bg-sky-50 text-sky-600'
                        }`}>
                          {f.source}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${tc.bg} ${tc.text}`}>
                          {tc.label}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase ${rc}`}>
                          {f.risk_level}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-gray-500 text-xs">
                        {f.days_since_assigned != null ? `${f.days_since_assigned}d` : '-'}
                      </td>
                      <td className="px-4 py-3 text-gray-600 text-xs max-w-[250px]">{f.recommendation}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Bottom Grid: Frequency + Bundles */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Role Frequency */}
        <div className="bg-white border rounded-xl p-5">
          <h3 className="text-sm font-semibold text-gray-900 mb-3">Most Assigned Roles</h3>
          {role_frequency.length === 0 ? (
            <div className="text-sm text-gray-400 text-center py-6">No role data available</div>
          ) : (
            <div className="space-y-2">
              {role_frequency.map((r, i) => {
                const maxCount = role_frequency[0]?.assignment_count || 1;
                const pct = Math.round((r.assignment_count / maxCount) * 100);
                return (
                  <div key={i} className="flex items-center gap-3">
                    <div className="w-40 truncate text-xs text-gray-700 font-medium" title={r.role_name}>{r.role_name}</div>
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase ${
                      r.source === 'entra' ? 'bg-indigo-50 text-indigo-500' : 'bg-sky-50 text-sky-500'
                    }`}>{r.source}</span>
                    <div className="flex-1 bg-gray-100 rounded-full h-4 overflow-hidden">
                      <div className="bg-blue-500 h-full rounded-full transition-all" style={{ width: `${pct}%` }} />
                    </div>
                    <div className="text-xs font-semibold text-gray-600 w-8 text-right">{r.assignment_count}</div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Role Bundles */}
        <div className="bg-white border rounded-xl p-5">
          <h3 className="text-sm font-semibold text-gray-900 mb-1">Commonly Co-Assigned Roles</h3>
          <p className="text-xs text-gray-500 mb-3">Role pairs assigned together to 2+ identities</p>
          {role_bundles.length === 0 ? (
            <div className="text-sm text-gray-400 text-center py-6">No common bundles found</div>
          ) : (
            <div className="space-y-2">
              {role_bundles.map((b, i) => (
                <div key={i} className="flex items-center gap-2 p-2 bg-gray-50 rounded-lg">
                  <span className="px-2 py-0.5 text-xs font-medium bg-blue-100 text-blue-700 rounded truncate max-w-[180px]" title={b.role_a}>{b.role_a}</span>
                  <span className="text-gray-400 text-xs">+</span>
                  <span className="px-2 py-0.5 text-xs font-medium bg-blue-100 text-blue-700 rounded truncate max-w-[180px]" title={b.role_b}>{b.role_b}</span>
                  <span className="ml-auto text-xs text-gray-500 whitespace-nowrap">{b.co_count} identities</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
