import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../../contexts/ConnectionContext';

interface SAGovStats {
  total: number;
  compliant: number;
  needs_attention: number;
  non_compliant: number;
  unowned: number;
  dormant: number;
  attestation_overdue: number;
  compliance_rate: number;
}

export default function ServiceAccountGovernance() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [stats, setStats] = useState<SAGovStats | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    fetch(withConnection('/api/service-accounts/stats'))
      .then(r => r.ok ? r.json() : null)
      .then(d => d && setStats(d))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [selectedConnectionId]);

  if (loading) {
    return (
      <div className="bg-white dark:bg-slate-800 border border-gray-200 dark:border-slate-700 rounded-xl p-5">
        <div className="text-sm font-semibold text-gray-900 dark:text-white mb-3">SA Governance</div>
        <div className="animate-pulse space-y-3">
          <div className="h-2.5 rounded-full bg-gray-200 dark:bg-slate-700" />
          <div className="grid grid-cols-2 gap-2">
            {[0,1,2,3].map(i => <div key={i} className="h-14 rounded-lg bg-gray-100 dark:bg-slate-700" />)}
          </div>
        </div>
      </div>
    );
  }

  if (!stats || stats.total === 0) {
    return (
      <div className="bg-white dark:bg-slate-800 border border-gray-200 dark:border-slate-700 rounded-xl p-5">
        <div className="text-sm font-semibold text-gray-900 dark:text-white mb-2">SA Governance</div>
        <p className="text-xs text-gray-400">No service accounts discovered</p>
      </div>
    );
  }

  const total = stats.total || 1;
  const segments = [
    { key: 'compliant', label: 'Compliant', count: stats.compliant, color: 'bg-green-500', textColor: 'text-green-700 dark:text-green-400', bgColor: 'bg-green-50 dark:bg-green-900/20' },
    { key: 'attention', label: 'Attention', count: stats.needs_attention, color: 'bg-yellow-400', textColor: 'text-yellow-700 dark:text-yellow-400', bgColor: 'bg-yellow-50 dark:bg-yellow-900/20' },
    { key: 'non_compliant', label: 'Non-Compliant', count: stats.non_compliant, color: 'bg-red-500', textColor: 'text-red-700 dark:text-red-400', bgColor: 'bg-red-50 dark:bg-red-900/20' },
  ];

  return (
    <div className="bg-white dark:bg-slate-800 border border-gray-200 dark:border-slate-700 rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="text-sm font-semibold text-gray-900 dark:text-white">SA Governance</div>
        <button onClick={() => navigate('/service-accounts')}
                className="text-[10px] text-blue-600 hover:underline">
          View All
        </button>
      </div>

      {/* Compliance bar */}
      <div className="flex rounded-full overflow-hidden h-2.5 mb-3">
        {segments.map(seg => (
          seg.count > 0 ? (
            <div key={seg.key} className={`${seg.color} transition-all duration-500`}
                 style={{ width: `${(seg.count / total) * 100}%` }}
                 title={`${seg.label}: ${seg.count}`} />
          ) : null
        ))}
      </div>

      {/* Rate */}
      <div className="text-center mb-3">
        <span className="text-lg font-bold text-gray-900 dark:text-white">{stats.compliance_rate}%</span>
        <span className="text-[10px] text-gray-400 ml-1">compliant</span>
      </div>

      {/* Legend */}
      <div className="grid grid-cols-2 gap-2">
        {segments.map(seg => (
          <button key={seg.key}
                  onClick={() => navigate('/service-accounts')}
                  className={`${seg.bgColor} rounded-lg p-2 text-left hover:opacity-80 transition`}>
            <div className="flex items-center gap-1.5">
              <div className={`w-2 h-2 rounded-full ${seg.color}`} />
              <span className="text-[10px] text-gray-500 dark:text-slate-400">{seg.label}</span>
            </div>
            <div className={`text-base font-bold ${seg.textColor} mt-0.5`}>{seg.count}</div>
          </button>
        ))}
        <button onClick={() => navigate('/service-accounts?filter=dormant')}
                className="bg-gray-50 dark:bg-slate-700/50 rounded-lg p-2 text-left hover:opacity-80 transition">
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-gray-400" />
            <span className="text-[10px] text-gray-500 dark:text-slate-400">Dormant</span>
          </div>
          <div className="text-base font-bold text-gray-600 dark:text-slate-300 mt-0.5">{stats.dormant}</div>
        </button>
      </div>
    </div>
  );
}
