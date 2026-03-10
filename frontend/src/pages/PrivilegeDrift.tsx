import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { RISK_BADGE, CLOUD_BADGE, safeLower } from '../constants/metrics';

interface DriftChange {
  identity_id: number;
  identity_name: string;
  identity_category: string;
  cloud: string;
  change_type: string;
  previous_role: string | null;
  current_role: string | null;
  is_privileged: boolean;
  severity: string;
  risk_level: string;
  timestamp: string | null;
}

interface DriftStats {
  role_added: number;
  role_removed: number;
  identity_added: number;
  identity_removed: number;
  risk_score_change: number;
  privileged_changes: number;
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-green-100 text-green-700',
  info: 'bg-gray-100 text-gray-500',
};

const CHANGE_CONFIG: Record<string, { label: string; icon: string; color: string }> = {
  role_added:         { label: 'Roles Added',      icon: 'M12 6v6m0 0v6m0-6h6m-6 0H6', color: 'text-red-500' },
  role_removed:       { label: 'Roles Removed',    icon: 'M20 12H4', color: 'text-green-500' },
  identity_added:     { label: 'New Identities',   icon: 'M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z', color: 'text-blue-500' },
  identity_removed:   { label: 'Removed Identities', icon: 'M13 7a4 4 0 11-8 0 4 4 0 018 0zM9 14a6 6 0 00-6 6v1h12v-1a6 6 0 00-6-6zM21 12h-6', color: 'text-gray-500' },
  risk_score_change:  { label: 'Risk Score Changes', icon: 'M13 7h8m0 0v8m0-8l-8 8-4-4-6 6', color: 'text-orange-500' },
};

export default function PrivilegeDrift() {
  const navigate = useNavigate();
  const [changes, setChanges] = useState<DriftChange[]>([]);
  const [stats, setStats] = useState<DriftStats | null>(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState('');
  const [typeFilter, setTypeFilter] = useState('');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (typeFilter) params.set('change_type', typeFilter);
      params.set('limit', '200');
      const res = await fetch(`/api/privilege-drift?${params}`);
      if (res.ok) {
        const data = await res.json();
        setChanges(data.changes || []);
        setStats(data.stats || null);
        setTotal(data.total || 0);
        setMessage(data.message || '');
      }
    } catch { /* ignore */ }
    setLoading(false);
  }, [typeFilter]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const privilegedCount = stats?.privileged_changes ?? 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Privilege Drift Detection</h1>
        <p className="text-sm text-gray-500 mt-1">
          Compares identity privileges between the latest two discovery snapshots to detect role escalations, removals, and risk score changes.
        </p>
      </div>

      {/* Alert banner for privileged changes */}
      {privilegedCount > 0 && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-red-50 border border-red-200">
          <svg className="w-5 h-5 text-red-600 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <div>
            <div className="text-xs font-bold text-red-800 uppercase">Privileged Changes Detected</div>
            <div className="text-sm text-gray-700">
              {privilegedCount} privileged role change{privilegedCount !== 1 ? 's' : ''} detected since last snapshot.
            </div>
          </div>
        </div>
      )}

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
        {Object.entries(CHANGE_CONFIG).map(([key, cfg]) => {
          const count = stats?.[key as keyof DriftStats] ?? 0;
          return (
            <button
              key={key}
              onClick={() => setTypeFilter(typeFilter === key ? '' : key)}
              className={`rounded-xl border p-3 text-left transition ${
                typeFilter === key ? 'border-indigo-300 bg-indigo-50 ring-1 ring-indigo-200' : 'border-gray-200 bg-white hover:bg-gray-50'
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                <svg className={`w-4 h-4 ${cfg.color}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={cfg.icon} />
                </svg>
                <span className="text-lg font-bold text-gray-900">{count}</span>
              </div>
              <div className="text-[10px] text-gray-500 font-medium">{cfg.label}</div>
            </button>
          );
        })}
      </div>

      {/* Table */}
      <div className="bg-white border rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-gray-400">Comparing snapshots...</div>
        ) : message ? (
          <div className="p-12 text-center">
            <svg className="w-10 h-10 text-gray-300 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div className="text-sm font-semibold text-gray-600">{message}</div>
          </div>
        ) : changes.length === 0 ? (
          <div className="p-12 text-center">
            <svg className="w-10 h-10 text-green-400 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <div className="text-sm font-semibold text-green-700">No Privilege Drift Detected</div>
            <div className="text-xs text-gray-500 mt-1">No role changes between the latest snapshots.</div>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b text-left text-xs text-gray-500 uppercase">
              <tr>
                <th className="px-4 py-3">Identity</th>
                <th className="px-4 py-3">Cloud</th>
                <th className="px-4 py-3">Change Type</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Previous</th>
                <th className="px-4 py-3">Current</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {changes.map((c, i) => (
                <tr key={`${c.identity_id}-${c.change_type}-${i}`} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <button
                      onClick={() => navigate(`/identities/${c.identity_id}`)}
                      className="text-blue-600 hover:underline font-medium text-left"
                    >
                      {c.identity_name}
                    </button>
                    <div className="text-[10px] text-gray-400">{c.identity_category}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${CLOUD_BADGE[safeLower(c.cloud)] || CLOUD_BADGE.azure}`}>
                      {c.cloud}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs font-medium text-gray-700">
                        {CHANGE_CONFIG[c.change_type]?.label || c.change_type}
                      </span>
                      {c.is_privileged && (
                        <span className="px-1 py-px rounded text-[9px] font-bold bg-red-100 text-red-700">PRIV</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEVERITY_BADGE[c.severity] || 'bg-gray-100 text-gray-600'}`}>
                      {c.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-600 max-w-[180px] truncate" title={c.previous_role || '—'}>
                    {c.previous_role || '—'}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-600 max-w-[180px] truncate" title={c.current_role || '—'}>
                    {c.current_role || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="text-xs text-gray-400 text-right">{total} total changes</div>
    </div>
  );
}
