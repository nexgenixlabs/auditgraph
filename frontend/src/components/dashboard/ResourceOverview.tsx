import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

interface ResourceStats {
  total: number;
  storage_accounts: number;
  key_vaults: number;
  by_risk: Record<string, number>;
  at_risk: number;
  rotation_compliance?: { total_storage: number; keys_stale: number; avg_key_age_days: number };
  expiry_summary?: {
    secrets: { total: number; expired: number; expiring_soon: number };
    keys: { total: number; expired: number; expiring_soon: number };
    certs: { total: number; expired: number; expiring_soon: number };
  };
}

interface ComplianceSummary {
  storage: { total_resources: number; score: number };
  key_vault: { total_resources: number; score: number };
}

const RISK_COLORS: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-400',
  low: 'bg-green-400',
  info: 'bg-blue-300',
};

export default function ResourceOverview() {
  const navigate = useNavigate();
  const [stats, setStats] = useState<ResourceStats | null>(null);
  const [compliance, setCompliance] = useState<ComplianceSummary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch('/api/resources/stats').then(r => r.json()),
      fetch('/api/resources/compliance-summary').then(r => r.json()).catch(() => null),
    ]).then(([s, c]) => {
      setStats(s);
      setCompliance(c);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <div className="animate-pulse h-32 bg-gray-100 dark:bg-gray-800 rounded" />
      </div>
    );
  }

  if (!stats || stats.total === 0) {
    return (
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <h3 className="text-sm font-semibold text-gray-800 dark:text-gray-200 mb-2">Azure Resources</h3>
        <p className="text-xs text-gray-500">No resources discovered yet. Run a discovery to populate.</p>
      </div>
    );
  }

  const totalExpired = stats.expiry_summary
    ? (stats.expiry_summary.secrets.expired + stats.expiry_summary.keys.expired + stats.expiry_summary.certs.expired)
    : 0;
  const totalExpiring = stats.expiry_summary
    ? (stats.expiry_summary.secrets.expiring_soon + stats.expiry_summary.keys.expiring_soon + stats.expiry_summary.certs.expiring_soon)
    : 0;

  // Risk bar widths
  const riskEntries = ['critical', 'high', 'medium', 'low', 'info']
    .map(level => ({ level, count: stats.by_risk[level] || 0 }))
    .filter(e => e.count > 0);

  return (
    <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
      <div className="flex items-center justify-between mb-3">
        <div>
          <h3 className="text-sm font-semibold text-gray-800 dark:text-gray-200">Azure Resources</h3>
          <p className="text-[10px] text-gray-500">Storage Accounts & Key Vaults</p>
        </div>
        <span className="text-2xl font-bold text-gray-800 dark:text-gray-200">{stats.total}</span>
      </div>

      {/* Resource type split */}
      <div className="grid grid-cols-2 gap-2 mb-3">
        <button
          onClick={() => navigate('/resources?resource_type=storage_account')}
          className="text-left p-2 rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 hover:shadow-sm transition"
        >
          <div className="text-lg font-bold text-blue-700 dark:text-blue-300">{stats.storage_accounts}</div>
          <div className="text-[10px] text-blue-600 dark:text-blue-400">Storage Accounts</div>
          {stats.rotation_compliance && stats.rotation_compliance.keys_stale > 0 && (
            <div className="text-[9px] text-orange-600 mt-0.5">{stats.rotation_compliance.keys_stale} keys stale</div>
          )}
        </button>
        <button
          onClick={() => navigate('/resources?resource_type=key_vault')}
          className="text-left p-2 rounded-lg bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 hover:shadow-sm transition"
        >
          <div className="text-lg font-bold text-purple-700 dark:text-purple-300">{stats.key_vaults}</div>
          <div className="text-[10px] text-purple-600 dark:text-purple-400">Key Vaults</div>
          {totalExpired > 0 && <div className="text-[9px] text-red-600 mt-0.5">{totalExpired} items expired</div>}
          {totalExpired === 0 && totalExpiring > 0 && <div className="text-[9px] text-orange-600 mt-0.5">{totalExpiring} expiring soon</div>}
        </button>
      </div>

      {/* Risk distribution bar */}
      {riskEntries.length > 0 && (
        <div className="mb-3">
          <div className="text-[10px] uppercase tracking-wider text-gray-500 font-medium mb-1">Risk Distribution</div>
          <div className="flex h-3 rounded-full overflow-hidden bg-gray-100 dark:bg-gray-700">
            {riskEntries.map(e => (
              <div
                key={e.level}
                className={`${RISK_COLORS[e.level]} transition-all`}
                style={{ width: `${(e.count / stats.total) * 100}%` }}
                title={`${e.level}: ${e.count}`}
              />
            ))}
          </div>
          <div className="flex gap-2 mt-1">
            {riskEntries.map(e => (
              <span key={e.level} className="text-[9px] text-gray-500">
                <span className={`inline-block w-1.5 h-1.5 rounded-full ${RISK_COLORS[e.level]} mr-0.5`} />
                {e.count} {e.level}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Compliance score */}
      {compliance && (compliance.storage?.total_resources > 0 || compliance.key_vault?.total_resources > 0) && (
        <div className="mb-2">
          <div className="text-[10px] uppercase tracking-wider text-gray-500 font-medium mb-1">Compliance Score</div>
          <div className="flex gap-3">
            {compliance.storage?.total_resources > 0 && (
              <div className="flex items-center gap-1.5">
                <div className="w-8 h-8 rounded-full flex items-center justify-center text-[10px] font-bold border-2" style={{
                  borderColor: compliance.storage.score >= 80 ? '#22c55e' : compliance.storage.score >= 50 ? '#eab308' : '#ef4444',
                  color: compliance.storage.score >= 80 ? '#16a34a' : compliance.storage.score >= 50 ? '#ca8a04' : '#dc2626',
                }}>
                  {compliance.storage.score}%
                </div>
                <span className="text-[10px] text-gray-500">Storage</span>
              </div>
            )}
            {compliance.key_vault?.total_resources > 0 && (
              <div className="flex items-center gap-1.5">
                <div className="w-8 h-8 rounded-full flex items-center justify-center text-[10px] font-bold border-2" style={{
                  borderColor: compliance.key_vault.score >= 80 ? '#22c55e' : compliance.key_vault.score >= 50 ? '#eab308' : '#ef4444',
                  color: compliance.key_vault.score >= 80 ? '#16a34a' : compliance.key_vault.score >= 50 ? '#ca8a04' : '#dc2626',
                }}>
                  {compliance.key_vault.score}%
                </div>
                <span className="text-[10px] text-gray-500">Key Vault</span>
              </div>
            )}
          </div>
        </div>
      )}

      <button
        onClick={() => navigate('/resources')}
        className="text-[10px] text-blue-600 hover:underline"
      >
        View all resources →
      </button>
    </div>
  );
}
