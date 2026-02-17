import React, { useEffect, useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { maskCredential } from '../utils/maskCredential';
import { ACCOUNT_PRICING, PLATFORM_FEE } from '../constants/pricing';

interface CloudSubscription {
  id: number;
  tenant_id: number;
  cloud: string;
  account_id: string;
  account_name: string | null;
  status: string;
  monitored: boolean;
  activated_at: string | null;
  created_at: string | null;
}

interface SubscriptionStats {
  total: number;
  active: number;
  discovered: number;
  clouds: number;
}

const CLOUD_BADGE: Record<string, { label: string; color: string; bg: string }> = {
  azure: { label: 'Azure', color: 'text-blue-700', bg: 'bg-blue-50' },
  aws: { label: 'AWS', color: 'text-orange-700', bg: 'bg-orange-50' },
  gcp: { label: 'GCP', color: 'text-red-600', bg: 'bg-red-50' },
};

export default function Subscriptions() {
  const { canActivateSubscriptions, canSeePricing } = useAuth();
  const [subs, setSubs] = useState<CloudSubscription[]>([]);
  const [stats, setStats] = useState<SubscriptionStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [activating, setActivating] = useState<number | null>(null);

  const fetchData = () => {
    Promise.all([
      fetch('/api/subscriptions').then(r => r.json()),
      fetch('/api/subscriptions/stats').then(r => r.json()),
    ])
      .then(([subsData, statsData]) => {
        setSubs(subsData.subscriptions || []);
        setStats(statsData);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleActivate = async (id: number) => {
    setActivating(id);
    try {
      const res = await fetch('/api/subscriptions/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id }),
      });
      if (res.ok) fetchData();
    } finally {
      setActivating(null);
    }
  };

  const handleDeactivate = async (id: number) => {
    setActivating(id);
    try {
      const res = await fetch(`/api/subscriptions/${id}/deactivate`, { method: 'PUT' });
      if (res.ok) fetchData();
    } finally {
      setActivating(null);
    }
  };

  const unmonitored = subs.filter(s => !s.monitored);
  const accountCost = (stats?.active || 0) * ACCOUNT_PRICING.direct;
  const platformFee = (stats?.active || 0) > 0 ? PLATFORM_FEE.direct : 0;
  const monthlyCost = accountCost + platformFee;

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Subscriptions</h1>
        <p className="text-sm text-gray-500 mt-1">Manage monitored cloud accounts across your organization</p>
      </div>

      {/* HIPAA Compliance Warning */}
      {unmonitored.length > 0 && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 flex items-start gap-3">
          <svg className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
          </svg>
          <div>
            <p className="text-sm font-medium text-amber-800">Compliance Gap Detected</p>
            <p className="text-xs text-amber-700 mt-0.5">
              {unmonitored.length} subscription{unmonitored.length !== 1 ? 's' : ''} discovered but not monitored.
              Unmonitored subscriptions may create HIPAA, SOC2, or PCI compliance gaps.
            </p>
          </div>
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white border rounded-xl p-4 shadow-sm">
          <div className="text-xs text-gray-500 uppercase tracking-wider font-medium">Active</div>
          <div className="text-2xl font-bold text-gray-900 mt-1">{stats?.active ?? '—'}</div>
        </div>
        <div className="bg-white border rounded-xl p-4 shadow-sm">
          <div className="text-xs text-gray-500 uppercase tracking-wider font-medium">Discovered</div>
          <div className="text-2xl font-bold text-gray-900 mt-1">{stats?.discovered ?? '—'}</div>
        </div>
        <div className="bg-white border rounded-xl p-4 shadow-sm">
          <div className="text-xs text-gray-500 uppercase tracking-wider font-medium">Cloud Providers</div>
          <div className="text-2xl font-bold text-gray-900 mt-1">{stats?.clouds ?? '—'}</div>
        </div>
        {canSeePricing && (
          <div className="bg-white border rounded-xl p-4 shadow-sm">
            <div className="text-xs text-gray-500 uppercase tracking-wider font-medium">Monthly Cost</div>
            <div className="text-2xl font-bold text-gray-900 mt-1">${monthlyCost.toLocaleString()}/mo</div>
            {platformFee > 0 && (
              <div className="text-[10px] text-gray-400 mt-0.5">
                ${PLATFORM_FEE.direct} platform + ${accountCost} ({stats?.active} x ${ACCOUNT_PRICING.direct})
              </div>
            )}
          </div>
        )}
      </div>

      {/* Platform fee notice */}
      {canSeePricing && (stats?.active || 0) === 0 && subs.length > 0 && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="text-sm font-semibold text-blue-800 mb-1">Pricing</div>
          <p className="text-xs text-blue-700">
            Platform base fee: <span className="font-semibold">${PLATFORM_FEE.direct}/mo</span> +{' '}
            <span className="font-semibold">${ACCOUNT_PRICING.direct}/mo</span> per monitored subscription.
            Activate subscriptions below to begin identity monitoring.
          </p>
        </div>
      )}

      {/* Info box */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 text-xs text-blue-700">
        No additional permissions needed — Graph API credentials operate at the Entra ID tenant level.
        All subscriptions discovered during scans appear here automatically.
      </div>

      {/* Table */}
      <div className="bg-white border rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 border-b">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Account ID</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Account Name</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Cloud</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Status</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {loading ? (
                <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-500">Loading...</td></tr>
              ) : subs.length === 0 ? (
                <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-500">No subscriptions discovered yet. Run a discovery scan to detect cloud accounts.</td></tr>
              ) : subs.map(sub => {
                const badge = CLOUD_BADGE[sub.cloud] || CLOUD_BADGE.azure;
                return (
                  <tr key={sub.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 font-mono text-xs text-gray-700">{maskCredential(sub.account_id)}</td>
                    <td className="px-4 py-3 text-gray-900">{sub.account_name || '—'}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${badge.color} ${badge.bg}`}>{badge.label}</span>
                    </td>
                    <td className="px-4 py-3">
                      {sub.monitored ? (
                        <span className="px-2 py-0.5 rounded text-xs font-medium text-green-700 bg-green-50">Active</span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-xs font-medium text-gray-600 bg-gray-100">Discovered</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {canActivateSubscriptions ? (
                        sub.monitored ? (
                          <button
                            onClick={() => handleDeactivate(sub.id)}
                            disabled={activating === sub.id}
                            className="px-3 py-1.5 text-xs font-medium text-red-700 bg-red-50 border border-red-200 rounded-lg hover:bg-red-100 transition disabled:opacity-50"
                          >
                            {activating === sub.id ? 'Processing...' : 'Deactivate'}
                          </button>
                        ) : (
                          <button
                            onClick={() => handleActivate(sub.id)}
                            disabled={activating === sub.id}
                            className="px-3 py-1.5 text-xs font-medium text-blue-700 bg-blue-50 border border-blue-200 rounded-lg hover:bg-blue-100 transition disabled:opacity-50"
                          >
                            {activating === sub.id ? 'Processing...' : canSeePricing ? `Activate — $${ACCOUNT_PRICING.direct}/mo` : 'Activate for Monitoring'}
                          </button>
                        )
                      ) : (
                        <span className="text-xs text-gray-400">Contact admin to activate</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
