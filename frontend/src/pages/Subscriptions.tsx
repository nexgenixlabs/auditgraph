import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useConnection } from '../contexts/ConnectionContext';
import { maskCredential } from '../utils/maskCredential';
import { formatCents, SUB_RATES_CENTS } from '../constants/pricing';

interface CloudSubscription {
  id: number;
  organization_id: number;
  cloud: string;
  account_id: string;
  account_name: string | null;
  status: string;
  monitored: boolean;
  activated_at: string | null;
  created_at: string | null;
  rate_cents?: number;
  connection_label?: string | null;
}

interface SubscriptionStats {
  total: number;
  active: number;
  discovered: number;
  clouds: number;
}

interface BillingBreakdown {
  platform_fee_cents: number;
  platform_fee_waiver_cents: number;
  trial_active: boolean;
  subscription_total_cents: number;
  gross_monthly_cents: number;
  discount_pct: number;
  net_monthly_cents: number;
  projected_arr_cents: number;
  active_count: number;
  line_items: Array<{ label: string; amount_cents: number; type: string }>;
}

const CLOUD_BADGE: Record<string, { label: string; color: string; bg: string }> = {
  azure: { label: 'Azure', color: 'text-blue-700', bg: 'bg-blue-50' },
  aws: { label: 'AWS', color: 'text-orange-700', bg: 'bg-orange-50' },
  gcp: { label: 'GCP', color: 'text-red-600', bg: 'bg-red-50' },
};

export default function Subscriptions() {
  const navigate = useNavigate();
  const { canActivateSubscriptions, canSeePricing } = useAuth();
  const { withConnection, selectedConnectionId } = useConnection();
  const [subs, setSubs] = useState<CloudSubscription[]>([]);
  const [stats, setStats] = useState<SubscriptionStats | null>(null);
  const [billing, setBilling] = useState<BillingBreakdown | null>(null);
  const [loading, setLoading] = useState(true);
  const [activating, setActivating] = useState<number | null>(null);
  const [activateError, setActivateError] = useState<string | null>(null);
  const [sortActiveFirst, setSortActiveFirst] = useState(true);

  const fetchData = () => {
    Promise.all([
      fetch(withConnection('/api/subscriptions')).then(r => r.ok ? r.json() : { subscriptions: [], billing: null }),
      fetch(withConnection('/api/subscriptions/stats')).then(r => r.ok ? r.json() : null),
    ])
      .then(([subsData, statsData]) => {
        setSubs(subsData.subscriptions || []);
        setBilling(subsData.billing || null);
        setStats(statsData);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchData(); }, [selectedConnectionId]);

  const handleActivate = async (id: number) => {
    setActivating(id);
    setActivateError(null);
    try {
      const res = await fetch(`/api/client/subscriptions/${id}/activate`, {
        method: 'POST',
      });
      if (res.ok) {
        fetchData();
      } else {
        const data = await res.json().catch(() => ({}));
        setActivateError(data.error || 'Activation failed');
      }
    } finally {
      setActivating(null);
    }
  };

  const handleDeactivate = async (id: number) => {
    setActivating(id);
    setActivateError(null);
    try {
      const res = await fetch(withConnection(`/api/subscriptions/${id}/deactivate`), { method: 'PUT' });
      if (res.ok) {
        fetchData();
      } else {
        const data = await res.json().catch(() => ({}));
        setActivateError(data.error || 'Deactivation failed');
      }
    } finally {
      setActivating(null);
    }
  };

  const sortedSubs = [...subs].sort((a, b) => {
    const aActive = a.monitored ? 1 : 0;
    const bActive = b.monitored ? 1 : 0;
    const statusCmp = sortActiveFirst ? bActive - aActive : aActive - bActive;
    if (statusCmp !== 0) return statusCmp;
    return (a.account_name || '').localeCompare(b.account_name || '');
  });
  const unmonitored = subs.filter(s => !s.monitored);
  const isTrial = billing?.trial_active ?? false;
  const netMonthlyCents = billing?.net_monthly_cents ?? 0;

  // Filter line items: hide platform fee + waiver on trial
  const displayLineItems = billing?.line_items.filter(li => {
    if (isTrial) return li.type !== 'platform' && li.type !== 'trial_waiver';
    return li.type !== 'trial_waiver';
  }) ?? [];

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-4">
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

      {/* Upgrade required error */}
      {!!activateError && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-start gap-3">
          <svg className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
          </svg>
          <div>
            <p className="text-sm font-medium text-red-800">Subscription Limit Reached</p>
            <p className="text-xs text-red-700 mt-0.5">{activateError}</p>
          </div>
          <button onClick={() => setActivateError(null)} className="ml-auto text-red-500 hover:text-red-700">&times;</button>
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white border rounded-xl p-4 shadow-sm">
          <div className="text-xs text-gray-500 uppercase tracking-wider font-medium">Active</div>
          <div className="text-2xl font-bold text-gray-900 mt-1">{stats?.active ?? '\u2014'}</div>
        </div>
        <div className="bg-white border rounded-xl p-4 shadow-sm">
          <div className="text-xs text-gray-500 uppercase tracking-wider font-medium">Discovered</div>
          <div className="text-2xl font-bold text-gray-900 mt-1">{stats?.discovered ?? '\u2014'}</div>
        </div>
        <div className="bg-white border rounded-xl p-4 shadow-sm">
          <div className="text-xs text-gray-500 uppercase tracking-wider font-medium">Cloud Providers</div>
          <div className="text-2xl font-bold text-gray-900 mt-1">{stats?.clouds ?? '\u2014'}</div>
        </div>
        {canSeePricing && (
          <div className="bg-white border rounded-xl p-4 shadow-sm">
            <div className="text-xs text-gray-500 uppercase tracking-wider font-medium">Monthly Cost</div>
            <div className="flex items-baseline gap-1.5 mt-1">
              <div className="text-2xl font-bold text-gray-900">{formatCents(netMonthlyCents)}/mo</div>
              {isTrial && <span className="text-[10px] text-gray-400">after trial</span>}
            </div>
            {!!billing && billing.active_count > 0 && !isTrial && (
              <div className="text-[10px] text-gray-400 mt-0.5">
                {formatCents(billing.platform_fee_cents)} platform + {formatCents(billing.subscription_total_cents)} ({billing.active_count} subs)
                {billing.discount_pct > 0 && <span className="text-green-600"> - {billing.discount_pct}% discount</span>}
              </div>
            )}
            {!!billing && billing.active_count > 0 && isTrial && (
              <div className="text-[10px] text-gray-400 mt-0.5">
                {formatCents(billing.subscription_total_cents)} ({billing.active_count} sub{billing.active_count !== 1 ? 's' : ''})
              </div>
            )}
          </div>
        )}
      </div>

      {/* Cost Breakdown — only show for paid plans with line items */}
      {canSeePricing && !!billing && displayLineItems.length > 0 && (
        <div className="bg-white border rounded-xl p-4 shadow-sm">
          <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Cost Breakdown</h3>
          <div className="space-y-1.5">
            {displayLineItems.map((item, i) => (
              <div key={i} className="flex items-center justify-between text-xs">
                <span className={item.amount_cents < 0 ? 'text-green-700' : 'text-gray-700'}>
                  {item.label}
                </span>
                <span className={`font-semibold ${item.amount_cents < 0 ? 'text-green-700' : 'text-gray-900'}`}>
                  {item.amount_cents < 0 ? '-' : ''}{formatCents(Math.abs(item.amount_cents))}/mo
                </span>
              </div>
            ))}
            <div className="border-t border-gray-200 pt-2 mt-2 flex items-center justify-between">
              <span className="text-xs font-semibold text-gray-700">
                {isTrial ? 'Projected Monthly' : 'Net Monthly'}
              </span>
              <div className="flex items-baseline gap-1.5">
                <span className="text-sm font-bold text-gray-900">{formatCents(billing.net_monthly_cents)}/mo</span>
                {isTrial && <span className="text-[10px] text-gray-400">after trial</span>}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Pricing notice — no active subs */}
      {canSeePricing && (stats?.active || 0) === 0 && subs.length > 0 && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="text-sm font-semibold text-blue-800 mb-1">Pricing</div>
          <p className="text-xs text-blue-700">
            {isTrial ? (
              <>Per-subscription rate: <span className="font-semibold">{formatCents(SUB_RATES_CENTS.azure)}/mo</span> per monitored account. No charges during trial.</>
            ) : (
              <>Platform base fee: <span className="font-semibold">{formatCents(billing?.platform_fee_cents ?? 50000)}/mo</span> + per-subscription rate: <span className="font-semibold">{formatCents(SUB_RATES_CENTS.azure)}/mo</span> per monitored account.</>
            )}
            {' '}Activate subscriptions below to begin identity monitoring.
          </p>
        </div>
      )}

      {/* Info box */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 text-xs text-blue-700">
        No additional permissions needed &mdash; Graph API credentials operate at the Entra ID tenant level.
        All subscriptions discovered during snapshots appear here automatically.
      </div>

      {/* Table */}
      <div className="bg-white border rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 border-b">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Account ID</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Account Name</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Connection</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Cloud</th>
                {canSeePricing && <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Rate</th>}
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase cursor-pointer select-none hover:text-gray-700" onClick={() => setSortActiveFirst(p => !p)}>Status {sortActiveFirst ? '\u2191' : '\u2193'}</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {loading ? (
                <tr><td colSpan={canSeePricing ? 7 : 6} className="px-4 py-8 text-center text-gray-500">Loading...</td></tr>
              ) : subs.length === 0 ? (
                <tr><td colSpan={canSeePricing ? 7 : 6} className="px-4 py-8 text-center text-gray-500">No subscriptions discovered yet. Capture a snapshot to detect cloud accounts.</td></tr>
              ) : sortedSubs.map(sub => {
                const badge = CLOUD_BADGE[sub.cloud] || CLOUD_BADGE.azure;
                const rateCents = sub.rate_cents ?? SUB_RATES_CENTS[sub.cloud] ?? SUB_RATES_CENTS.azure;
                return (
                  <tr key={sub.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 font-mono text-xs text-gray-700">{maskCredential(sub.account_id)}</td>
                    <td className="px-4 py-3 text-gray-900">{sub.account_name || '\u2014'}</td>
                    <td className="px-4 py-3 text-xs text-gray-600">{sub.connection_label || '\u2014'}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${badge.color} ${badge.bg}`}>{badge.label}</span>
                    </td>
                    {canSeePricing && (
                      <td className="px-4 py-3 text-xs font-medium text-gray-700">{formatCents(rateCents)}/mo</td>
                    )}
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
                            {activating === sub.id ? 'Processing...' : canSeePricing ? `Activate \u2014 ${formatCents(rateCents)}/mo` : 'Activate for Monitoring'}
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
