import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { RISK_BADGE, CLOUD_BADGE, safeLower } from '../constants/metrics';

interface Exposure {
  id: number;
  identity_id: number;
  identity_name: string;
  identity_category: string;
  cloud: string;
  risk_level: string;
  risk_score: number;
  exposure_type: string;
  severity: string;
  description: string;
  status: string;
  roles?: string[];
  credential_status?: string;
  credential_count?: number;
  expired_credential_count?: number;
  role_count?: number;
  last_sign_in?: string | null;
  first_detected_at?: string;
  last_detected_at?: string;
  occurrence_count?: number;
}

interface ExposureStats {
  dormant_privileged: number;
  long_lived_credential: number;
  spn_secret_exposure: number;
  external_privileged: number;
  orphaned_identity: number;
  orphaned_privileged: number;
  disabled_with_access: number;
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
};

const STATUS_BADGE: Record<string, string> = {
  open: 'bg-red-500/20 text-red-400 border border-red-500/30',
  acknowledged: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
  resolved: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30',
};

const EXPOSURE_CONFIG: Record<string, { label: string; icon: string; color: string }> = {
  dormant_privileged:    { label: 'Dormant Privileged',   icon: 'M12 8v4m0 4h.01', color: 'text-red-400' },
  long_lived_credential: { label: 'Long-Lived Creds',     icon: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743', color: 'text-orange-400' },
  spn_secret_exposure:   { label: 'SPN Secret Exposure',  icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z', color: 'text-purple-400' },
  external_privileged:   { label: 'External Privileged',  icon: 'M17 20h5v-2a3 3 0 00-5.356-1.857', color: 'text-red-400' },
  orphaned_identity:     { label: 'Orphaned Identity',    icon: 'M18.364 18.364A9 9 0 005.636 5.636', color: 'text-amber-400' },
};

export default function IdentityExposures() {
  const navigate = useNavigate();
  const [exposures, setExposures] = useState<Exposure[]>([]);
  const [stats, setStats] = useState<ExposureStats | null>(null);
  const [bySeverity, setBySeverity] = useState<Record<string, number>>({});
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('open');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (typeFilter) params.set('exposure_type', typeFilter);
      if (severityFilter) params.set('severity', severityFilter);
      if (statusFilter) params.set('status', statusFilter);
      params.set('limit', '200');
      const res = await fetch(`/api/identity-exposures?${params}`);
      if (res.ok) {
        const data = await res.json();
        setExposures(data.exposures || []);
        setStats(data.stats || null);
        setBySeverity(data.by_severity || {});
        setTotal(data.total || 0);
      }
    } catch { /* ignore */ }
    setLoading(false);
  }, [typeFilter, severityFilter, statusFilter]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleAction = async (exposureId: number, action: 'acknowledge' | 'resolve') => {
    try {
      const res = await fetch(`/api/identity-exposures/${exposureId}/${action}`, { method: 'POST' });
      if (res.ok) fetchData();
    } catch (err) {
      console.error(`Failed to ${action} exposure:`, err);
    }
  };

  // Group exposures by severity for sectioned display
  const grouped = {
    critical: exposures.filter(e => e.severity === 'critical'),
    high: exposures.filter(e => e.severity === 'high'),
    medium: exposures.filter(e => e.severity === 'medium'),
    low: exposures.filter(e => e.severity === 'low'),
  };

  const severityLabel: Record<string, string> = {
    critical: 'Critical Exposures',
    high: 'High Exposures',
    medium: 'Medium Exposures',
    low: 'Low Exposures',
  };

  const severityHeaderColor: Record<string, string> = {
    critical: 'text-red-400',
    high: 'text-orange-400',
    medium: 'text-yellow-400',
    low: 'text-blue-400',
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Identity Exposures</h1>
        <p className="text-sm text-slate-400 mt-1">
          Continuous detection of identity risk patterns: dormant privileged accounts, credential exposure, and external access.
        </p>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
        {Object.entries(EXPOSURE_CONFIG).map(([key, cfg]) => {
          const count = stats?.[key as keyof ExposureStats] ?? 0;
          return (
            <button
              key={key}
              onClick={() => setTypeFilter(typeFilter === key ? '' : key)}
              className={`rounded-xl border p-3 text-left transition ${
                typeFilter === key
                  ? 'border-indigo-500/50 bg-indigo-500/10 ring-1 ring-indigo-500/30'
                  : 'border-slate-700/50 bg-slate-800/50 hover:bg-slate-700/30'
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                <svg className={`w-4 h-4 ${cfg.color}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={cfg.icon} />
                </svg>
                <span className="text-lg font-bold text-white">{count}</span>
              </div>
              <div className="text-[10px] text-slate-400 font-medium">{cfg.label}</div>
            </button>
          );
        })}
      </div>

      {/* Severity Summary + Status Filter */}
      <div className="flex items-center gap-4 text-sm flex-wrap">
        <span className="text-slate-400">By severity:</span>
        {['critical', 'high', 'medium', 'low'].map(sev => (
          <button
            key={sev}
            onClick={() => setSeverityFilter(severityFilter === sev ? '' : sev)}
            className={`px-2 py-0.5 rounded text-xs font-semibold transition ${
              severityFilter === sev ? 'ring-2 ring-offset-1 ring-offset-slate-900 ring-indigo-400' : ''
            } ${SEVERITY_BADGE[sev]}`}
          >
            {sev}: {bySeverity[sev] || 0}
          </button>
        ))}
        <span className="ml-auto text-xs text-slate-500">{total} total exposures</span>

        {/* Status filter */}
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="bg-slate-800 border border-slate-700 text-white text-sm rounded-lg px-3 py-1.5"
        >
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
          <option value="">All Statuses</option>
        </select>
      </div>

      {/* Grouped by Severity */}
      {loading ? (
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-12 text-center text-slate-400">
          Loading exposures...
        </div>
      ) : exposures.length === 0 ? (
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-12 text-center">
          <svg className="w-10 h-10 text-emerald-400 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <div className="text-sm font-semibold text-emerald-400">No Exposures Detected</div>
          <div className="text-xs text-slate-500 mt-1">All identities are within acceptable risk parameters.</div>
        </div>
      ) : (
        (['critical', 'high', 'medium', 'low'] as const).map(sev => {
          const items = grouped[sev];
          if (items.length === 0) return null;
          return (
            <div key={sev} className="space-y-2">
              <div className={`text-xs font-semibold uppercase tracking-wider ${severityHeaderColor[sev]}`}>
                {severityLabel[sev]} ({items.length})
              </div>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg overflow-hidden">
                <table className="w-full text-sm text-left">
                  <thead className="bg-slate-900/50 text-slate-400 uppercase text-xs tracking-wider">
                    <tr>
                      <th className="px-4 py-3">Identity</th>
                      <th className="px-4 py-3">Cloud</th>
                      <th className="px-4 py-3">Exposure Type</th>
                      <th className="px-4 py-3">Severity</th>
                      <th className="px-4 py-3">Risk</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Description</th>
                      <th className="px-4 py-3">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700/50">
                    {items.map((e, i) => (
                      <tr key={`${e.id || e.identity_id}-${e.exposure_type}-${i}`} className="hover:bg-slate-700/20">
                        <td className="px-4 py-3">
                          <button
                            onClick={() => navigate(`/identities/${e.identity_id}`)}
                            className="text-blue-400 hover:underline font-medium text-left"
                          >
                            {e.identity_name}
                          </button>
                          <div className="text-[10px] text-slate-500">{e.identity_category}</div>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${CLOUD_BADGE[safeLower(e.cloud)] || CLOUD_BADGE.azure}`}>
                            {e.cloud}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-xs font-medium text-slate-300">
                            {EXPOSURE_CONFIG[e.exposure_type]?.label || e.exposure_type}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_BADGE[e.severity] || ''}`}>
                            {e.severity}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${RISK_BADGE[safeLower(e.risk_level)] || 'bg-slate-700 text-slate-400'}`}>
                            {e.risk_level}
                          </span>
                          {e.risk_score > 0 && <span className="text-[10px] text-slate-500 ml-1 font-mono">{e.risk_score}</span>}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${STATUS_BADGE[e.status] || ''}`}>
                            {e.status}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-slate-400 max-w-xs truncate" title={e.description}>
                          {e.description}
                        </td>
                        <td className="px-4 py-3">
                          {e.status === 'open' && (
                            <div className="flex gap-2">
                              <button
                                onClick={() => handleAction(e.id, 'acknowledge')}
                                className="px-2 py-1 text-xs bg-yellow-500/20 text-yellow-400 rounded hover:bg-yellow-500/30"
                              >
                                Acknowledge
                              </button>
                              <button
                                onClick={() => handleAction(e.id, 'resolve')}
                                className="px-2 py-1 text-xs bg-emerald-500/20 text-emerald-400 rounded hover:bg-emerald-500/30"
                              >
                                Resolve
                              </button>
                            </div>
                          )}
                          {e.status === 'acknowledged' && (
                            <button
                              onClick={() => handleAction(e.id, 'resolve')}
                              className="px-2 py-1 text-xs bg-emerald-500/20 text-emerald-400 rounded hover:bg-emerald-500/30"
                            >
                              Resolve
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          );
        })
      )}
    </div>
  );
}
