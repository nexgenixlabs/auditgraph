import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { RISK_BADGE, CLOUD_BADGE, safeLower } from '../constants/metrics';

interface Exposure {
  identity_id: number;
  identity_name: string;
  identity_category: string;
  cloud: string;
  risk_level: string;
  risk_score: number;
  exposure_type: string;
  severity: string;
  description: string;
  roles?: string[];
  credential_status?: string;
  credential_count?: number;
  expired_credential_count?: number;
  role_count?: number;
  last_sign_in?: string | null;
}

interface ExposureStats {
  dormant_privileged: number;
  long_lived_credential: number;
  spn_secret_exposure: number;
  external_privileged: number;
  orphaned_privileged: number;
  disabled_with_access: number;
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-green-100 text-green-700',
};

const EXPOSURE_CONFIG: Record<string, { label: string; icon: string; color: string }> = {
  dormant_privileged:   { label: 'Dormant Privileged',   icon: 'M12 8v4m0 4h.01', color: 'text-red-500' },
  long_lived_credential:{ label: 'Long-Lived Creds',     icon: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743', color: 'text-orange-500' },
  spn_secret_exposure:  { label: 'SPN Secret Exposure',  icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z', color: 'text-purple-500' },
  external_privileged:  { label: 'External Privileged',  icon: 'M17 20h5v-2a3 3 0 00-5.356-1.857', color: 'text-red-500' },
  orphaned_privileged:  { label: 'Orphaned Privileged',  icon: 'M18.364 18.364A9 9 0 005.636 5.636', color: 'text-amber-500' },
  disabled_with_access: { label: 'Disabled with Access', icon: 'M18.364 18.364A9 9 0 005.636 5.636m12.728 0A9 9 0 015.636 18.364', color: 'text-gray-500' },
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

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (typeFilter) params.set('exposure_type', typeFilter);
      if (severityFilter) params.set('severity', severityFilter);
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
  }, [typeFilter, severityFilter]);

  useEffect(() => { fetchData(); }, [fetchData]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Identity Exposures</h1>
        <p className="text-sm text-gray-500 mt-1">
          Continuous detection of identity risk patterns: dormant privileged accounts, credential exposure, and external access.
        </p>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {Object.entries(EXPOSURE_CONFIG).map(([key, cfg]) => {
          const count = stats?.[key as keyof ExposureStats] ?? 0;
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

      {/* Severity Summary */}
      <div className="flex items-center gap-4 text-sm">
        <span className="text-gray-500">By severity:</span>
        {['critical', 'high', 'medium', 'low'].map(sev => (
          <button
            key={sev}
            onClick={() => setSeverityFilter(severityFilter === sev ? '' : sev)}
            className={`px-2 py-0.5 rounded text-xs font-semibold transition ${
              severityFilter === sev ? 'ring-2 ring-offset-1 ring-indigo-400' : ''
            } ${SEVERITY_BADGE[sev]}`}
          >
            {sev}: {bySeverity[sev] || 0}
          </button>
        ))}
        <span className="ml-auto text-xs text-gray-400">{total} total exposures</span>
      </div>

      {/* Table */}
      <div className="bg-white border rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-gray-400">Loading exposures...</div>
        ) : exposures.length === 0 ? (
          <div className="p-12 text-center">
            <svg className="w-10 h-10 text-green-400 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <div className="text-sm font-semibold text-green-700">No Exposures Detected</div>
            <div className="text-xs text-gray-500 mt-1">All identities are within acceptable risk parameters.</div>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b text-left text-xs text-gray-500 uppercase">
              <tr>
                <th className="px-4 py-3">Identity</th>
                <th className="px-4 py-3">Cloud</th>
                <th className="px-4 py-3">Exposure Type</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Risk</th>
                <th className="px-4 py-3">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {exposures.map((e, i) => (
                <tr key={`${e.identity_id}-${e.exposure_type}-${i}`} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <button
                      onClick={() => navigate(`/identities/${e.identity_id}`)}
                      className="text-blue-600 hover:underline font-medium text-left"
                    >
                      {e.identity_name}
                    </button>
                    <div className="text-[10px] text-gray-400">{e.identity_category}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${CLOUD_BADGE[safeLower(e.cloud)] || CLOUD_BADGE.azure}`}>
                      {e.cloud}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs font-medium text-gray-700">
                      {EXPOSURE_CONFIG[e.exposure_type]?.label || e.exposure_type}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEVERITY_BADGE[e.severity] || 'bg-gray-100 text-gray-600'}`}>
                      {e.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${RISK_BADGE[safeLower(e.risk_level)] || 'bg-gray-100 text-gray-600'}`}>
                      {e.risk_level}
                    </span>
                    {e.risk_score > 0 && <span className="text-[10px] text-gray-400 ml-1 font-mono">{e.risk_score}</span>}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-600 max-w-sm truncate" title={e.description}>
                    {e.description}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
