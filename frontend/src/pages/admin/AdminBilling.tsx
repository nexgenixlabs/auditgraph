import React, { useEffect, useState } from 'react';
import {
  CLOUD_LABELS,
  ACCOUNT_TIER_LABELS,
  getTermLabel,
  formatCents,
} from '../../constants/pricing';

interface BillingSummary {
  total_mrr_cents: number;
  projected_arr_cents: number;
  total_tenants: number;
  active_tenants: number;
  by_plan: Record<string, { count: number; mrr_cents: number }>;
  by_cloud: Record<string, { count: number; revenue_cents: number }>;
  tenants: Array<{
    tenant_id: number;
    tenant_name: string;
    plan: string;
    active_subs: number;
    net_monthly_cents: number;
  }>;
}

interface BillingEvent {
  id: number;
  tenant_id: number;
  tenant_name: string;
  event_type: string;
  field_changed: string | null;
  old_value: string | null;
  new_value: string | null;
  created_at: string;
}

interface TenantRow {
  id: number;
  name: string;
  slug: string;
  plan: string;
  enabled: boolean;
  user_count: number;
  license_activated_at: string | null;
  license_expires_at: string | null;
  subscription_term: number;
}

const PLAN_LABELS = ACCOUNT_TIER_LABELS;

function formatDate(iso: string | null): string {
  if (!iso) return '\u2014';
  return new Date(iso).toLocaleDateString();
}

function licenseLabel(t: TenantRow): { text: string; color: string } {
  if (!t.license_activated_at) return { text: 'Not Activated', color: 'text-gray-400' };
  if (t.license_expires_at) {
    const days = Math.ceil((new Date(t.license_expires_at).getTime() - Date.now()) / 86400000);
    if (days < 0) return { text: 'Expired', color: 'text-red-600' };
    if (days < 30) return { text: `${days}d left`, color: 'text-yellow-600' };
  }
  return { text: 'Active', color: 'text-green-600' };
}

function eventTypeLabel(type: string): { text: string; color: string; bg: string } {
  switch (type) {
    case 'plan_change': return { text: 'Plan Change', color: 'text-blue-700', bg: 'bg-blue-100' };
    case 'commitment_change': return { text: 'Commitment', color: 'text-purple-700', bg: 'bg-purple-100' };
    case 'platform_fee_override': return { text: 'Fee Override', color: 'text-orange-700', bg: 'bg-orange-100' };
    case 'rate_override': return { text: 'Rate Override', color: 'text-cyan-700', bg: 'bg-cyan-100' };
    default: return { text: type, color: 'text-gray-700', bg: 'bg-gray-100' };
  }
}

interface TenantBillingDetail {
  billing: {
    platform_fee_cents: number;
    subscription_total_cents: number;
    gross_monthly_cents: number;
    discount_pct: number;
    net_monthly_cents: number;
    active_count: number;
    subscriptions_by_cloud: Record<string, { count: number; revenue_cents: number }>;
    line_items: Array<{ label: string; amount_cents: number; type: string }>;
  };
}

export default function AdminBilling() {
  const [summary, setSummary] = useState<BillingSummary | null>(null);
  const [tenants, setTenants] = useState<TenantRow[]>([]);
  const [events, setEvents] = useState<BillingEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedTenant, setExpandedTenant] = useState<number | null>(null);
  const [expandedBilling, setExpandedBilling] = useState<TenantBillingDetail | null>(null);
  const [expandLoading, setExpandLoading] = useState(false);

  useEffect(() => {
    Promise.all([
      fetch('/api/admin/billing/summary').then(r => r.ok ? r.json() : null),
      fetch('/api/tenants').then(r => r.ok ? r.json() : { tenants: [] }),
      fetch('/api/admin/billing/events?limit=20').then(r => r.ok ? r.json() : { events: [] }),
    ])
      .then(([summaryData, tenantsData, eventsData]) => {
        if (summaryData) setSummary(summaryData);
        setTenants(tenantsData.tenants || []);
        setEvents(eventsData.events || []);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  function toggleTenantExpand(tenantId: number) {
    if (expandedTenant === tenantId) {
      setExpandedTenant(null);
      setExpandedBilling(null);
      return;
    }
    setExpandedTenant(tenantId);
    setExpandedBilling(null);
    setExpandLoading(true);
    fetch(`/api/admin/tenants/${tenantId}/billing`)
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data) setExpandedBilling(data); })
      .catch(() => {})
      .finally(() => setExpandLoading(false));
  }

  const totalMrr = summary?.total_mrr_cents ?? 0;
  const projectedArr = summary?.projected_arr_cents ?? 0;
  const totalUsers = tenants.reduce((sum, t) => sum + t.user_count, 0);

  const planCounts: Record<string, number> = {};
  for (const t of tenants) {
    planCounts[t.plan] = (planCounts[t.plan] || 0) + 1;
  }

  if (loading) return <div className="flex items-center justify-center h-64 text-gray-400">Loading billing data...</div>;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-gray-900">Billing & Revenue</h2>
        <p className="text-sm text-gray-500 mt-0.5">Per-subscription billing model &mdash; platform fee + per-sub rates</p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-6 gap-4">
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="text-2xl font-bold text-gray-900">{summary?.total_tenants ?? tenants.length}</div>
          <div className="text-xs text-gray-500 mt-1">Total Organizations</div>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="text-2xl font-bold text-gray-900">{totalUsers}</div>
          <div className="text-xs text-gray-500 mt-1">Total Users</div>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="text-2xl font-bold text-gray-900">{summary?.active_tenants ?? tenants.filter(t => t.enabled).length}</div>
          <div className="text-xs text-gray-500 mt-1">Active Tenants</div>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="text-2xl font-bold text-purple-700">{planCounts.enterprise || 0}</div>
          <div className="text-xs text-gray-500 mt-1">Enterprise Licenses</div>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="text-2xl font-bold text-green-700">{formatCents(totalMrr)}</div>
          <div className="text-xs text-gray-500 mt-1">Total MRR <span className="text-[10px] text-gray-400">excl. tax</span></div>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <div className="text-2xl font-bold text-blue-700">{formatCents(projectedArr)}</div>
          <div className="text-xs text-gray-500 mt-1">Projected ARR <span className="text-[10px] text-gray-400">excl. tax</span></div>
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
            const planMrr = summary?.by_plan?.[plan]?.mrr_cents ?? 0;
            return (
              <div key={plan} className="flex-1">
                <div className="flex items-center justify-between mb-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold ${cfg.bg} ${cfg.color}`}>{cfg.label}</span>
                  <span className="text-sm font-bold text-gray-900">{count}</span>
                </div>
                <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                  <div className={`h-full rounded-full transition-all ${barColor}`} style={{ width: `${pct}%` }} />
                </div>
                <div className="text-[10px] text-gray-400 mt-1">{pct}% of tenants &middot; {formatCents(planMrr)}/mo</div>
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
                  <div className="h-full bg-blue-500 rounded-full transition-all" style={{ width: `${pct}%` }} />
                </div>
                <span className="text-xs font-bold text-gray-800 w-8 text-right">{t.user_count}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Revenue by Cloud (per-subscription model) */}
      <div className="bg-white border border-gray-200 rounded-lg p-6">
        <h3 className="text-sm font-semibold text-gray-800 mb-4">Revenue by Cloud Provider</h3>
        <div className="space-y-3">
          {Object.entries(CLOUD_LABELS).map(([key, meta]) => {
            const cloudData = summary?.by_cloud?.[key];
            const revenue = cloudData?.revenue_cents ?? 0;
            const subCount = cloudData?.count ?? 0;
            const pct = totalMrr > 0 ? Math.round((revenue / totalMrr) * 100) : 0;
            return (
              <div key={key}>
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${meta.bg} ${meta.color}`}>{meta.label}</span>
                    <span className="text-[10px] text-gray-400">{subCount} sub{subCount !== 1 ? 's' : ''}</span>
                  </div>
                  <span className="text-sm font-bold text-gray-900">{formatCents(revenue)}/mo</span>
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
              <th className="px-4 py-2.5">Term</th>
              <th className="px-4 py-2.5">Active Subs</th>
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
              const tb = summary?.tenants?.find(tb => tb.tenant_id === t.id);
              const mrr = tb?.net_monthly_cents ?? 0;
              const activeSubs = tb?.active_subs ?? 0;
              const planCfg = PLAN_LABELS[t.plan] || PLAN_LABELS.free;
              const ls = licenseLabel(t);
              const isExpanded = expandedTenant === t.id;
              return (
                <React.Fragment key={t.id}>
                  <tr
                    className={`hover:bg-gray-50/60 cursor-pointer ${isExpanded ? 'bg-blue-50/40' : ''}`}
                    onClick={() => toggleTenantExpand(t.id)}
                  >
                    <td className="px-4 py-2.5 font-medium text-gray-900">
                      <div className="flex items-center gap-1.5">
                        <svg className={`w-3 h-3 text-gray-400 transition-transform ${isExpanded ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
                        {t.name}
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${planCfg.bg} ${planCfg.color}`}>{planCfg.label}</span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`text-[10px] font-semibold ${(t.subscription_term || 0) > 0 ? 'text-blue-600' : 'text-gray-400'}`}>
                        {getTermLabel(t.subscription_term || 0)}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-gray-700">{activeSubs}</td>
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
                    <td className="px-4 py-2.5 text-right font-semibold text-gray-900">{formatCents(mrr)}</td>
                  </tr>
                  {isExpanded && (
                    <tr>
                      <td colSpan={10} className="px-4 py-3 bg-gray-50/80 border-t border-b border-gray-200">
                        {expandLoading ? (
                          <div className="text-xs text-gray-400 py-2">Loading billing breakdown...</div>
                        ) : expandedBilling ? (
                          <div className="grid grid-cols-3 gap-4 max-w-2xl">
                            <div>
                              <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Breakdown</div>
                              <div className="space-y-1">
                                {expandedBilling.billing.line_items.map((item, i) => (
                                  <div key={i} className="flex items-center justify-between text-xs">
                                    <span className="text-gray-600">{item.label}</span>
                                    <span className={`font-semibold ${item.amount_cents < 0 ? 'text-green-700' : 'text-gray-900'}`}>
                                      {item.amount_cents < 0 ? '-' : ''}{formatCents(Math.abs(item.amount_cents))}
                                    </span>
                                  </div>
                                ))}
                                <div className="border-t border-gray-200 pt-1 mt-1 flex items-center justify-between text-xs">
                                  <span className="font-semibold text-gray-700">Net Monthly</span>
                                  <span className="font-bold text-gray-900">{formatCents(expandedBilling.billing.net_monthly_cents)}</span>
                                </div>
                              </div>
                            </div>
                            <div>
                              <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">By Cloud</div>
                              <div className="space-y-1">
                                {Object.entries(expandedBilling.billing.subscriptions_by_cloud).map(([cloud, data]) => {
                                  const meta = CLOUD_LABELS[cloud];
                                  return (
                                    <div key={cloud} className="flex items-center justify-between text-xs">
                                      <span className="flex items-center gap-1.5">
                                        {meta && <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${meta.bg} ${meta.color}`}>{meta.label}</span>}
                                        <span className="text-gray-500">{data.count} sub{data.count !== 1 ? 's' : ''}</span>
                                      </span>
                                      <span className="font-semibold text-gray-900">{formatCents(data.revenue_cents)}</span>
                                    </div>
                                  );
                                })}
                                {Object.keys(expandedBilling.billing.subscriptions_by_cloud).length === 0 && (
                                  <div className="text-[10px] text-gray-400">No active subscriptions</div>
                                )}
                              </div>
                            </div>
                            <div>
                              <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Summary</div>
                              <div className="space-y-1 text-xs">
                                <div className="flex justify-between"><span className="text-gray-500">Platform Fee</span><span className="text-gray-700">{formatCents(expandedBilling.billing.platform_fee_cents)}</span></div>
                                <div className="flex justify-between"><span className="text-gray-500">Sub Revenue</span><span className="text-gray-700">{formatCents(expandedBilling.billing.subscription_total_cents)}</span></div>
                                {expandedBilling.billing.discount_pct > 0 && (
                                  <div className="flex justify-between"><span className="text-gray-500">Discount</span><span className="text-green-600">-{expandedBilling.billing.discount_pct}%</span></div>
                                )}
                              </div>
                            </div>
                          </div>
                        ) : (
                          <div className="text-xs text-gray-400 py-2">Failed to load billing details</div>
                        )}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Billing Events */}
      {events.length > 0 && (
        <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-200">
            <h3 className="text-sm font-semibold text-gray-800">Recent Billing Events</h3>
          </div>
          <table className="min-w-full text-left text-xs">
            <thead className="bg-gray-50 border-b border-gray-200 text-gray-600 uppercase tracking-wider font-medium">
              <tr>
                <th className="px-4 py-2.5">Event</th>
                <th className="px-4 py-2.5">Organization</th>
                <th className="px-4 py-2.5">Field</th>
                <th className="px-4 py-2.5">Change</th>
                <th className="px-4 py-2.5">Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {events.map(ev => {
                const badge = eventTypeLabel(ev.event_type);
                return (
                  <tr key={ev.id} className="hover:bg-gray-50/60">
                    <td className="px-4 py-2.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${badge.bg} ${badge.color}`}>{badge.text}</span>
                    </td>
                    <td className="px-4 py-2.5 font-medium text-gray-900">{ev.tenant_name}</td>
                    <td className="px-4 py-2.5 text-gray-600 font-mono">{ev.field_changed || '\u2014'}</td>
                    <td className="px-4 py-2.5">
                      {ev.old_value || ev.new_value ? (
                        <span className="text-gray-700">
                          {ev.old_value && <span className="line-through text-red-500 mr-1">{ev.old_value}</span>}
                          {ev.new_value && <span className="text-green-700">{ev.new_value}</span>}
                        </span>
                      ) : '\u2014'}
                    </td>
                    <td className="px-4 py-2.5 text-gray-500">{formatDate(ev.created_at)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Tax disclaimer */}
      <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 text-xs text-gray-500">
        All prices are in USD and exclude applicable taxes (GST, VAT, Sales Tax, etc.). Taxes will be calculated based on the customer&apos;s billing address and applied to the invoice.
      </div>
    </div>
  );
}
