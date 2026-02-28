import React, { useEffect, useState } from 'react';
import { api } from '../services/apiClient';
import { formatCentsExact } from '../constants/pricing';
import { generateInvoicePdf, type Invoice } from '../utils/invoicePdfGenerator';

interface LineItem {
  label: string;
  amount_cents: number;
  type: string;
}

interface BillingPreview {
  period_start: string;
  period_end: string;
  plan: string;
  active_subscriptions: number;
  subscriptions_by_cloud: Record<string, number>;
  platform_fee_cents: number;
  subscription_total_cents: number;
  discount_pct: number;
  subtotal_cents: number;
  tax_label: string;
  tax_rate: number;
  tax_amount_cents: number;
  projected_total_cents: number;
  line_items: LineItem[];
  note: string;
}

interface InvoiceRow {
  id: number;
  invoice_number: string;
  period_start: string;
  period_end: string;
  total_cents: number;
  status: string;
  due_at: string | null;
  content_hash?: string;
}

interface VerifyResult {
  verified: boolean;
  content_hash?: string;
  computed_hash?: string;
  reason?: string;
  invoice_id: number;
}

interface SubStats {
  total: number;
  active: number;
}

const statusStyles: Record<string, string> = {
  draft: 'bg-gray-100 text-gray-600 dark:bg-slate-700 dark:text-gray-300',
  sent: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
  paid: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300',
  overdue: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
  void: 'bg-gray-100 text-gray-400 line-through dark:bg-slate-700 dark:text-gray-500',
};

const planColors: Record<string, string> = {
  free: 'bg-gray-100 text-gray-600 dark:bg-slate-700 dark:text-gray-300',
  trial: 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300',
  pro: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
  enterprise: 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300',
};

function formatDate(iso: string | null | undefined): string {
  if (!iso) return '-';
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function nextMonthFirst(): string {
  const now = new Date();
  const next = new Date(now.getFullYear(), now.getMonth() + 1, 1);
  return next.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

const ClientBilling: React.FC = () => {
  const [preview, setPreview] = useState<BillingPreview | null>(null);
  const [invoices, setInvoices] = useState<InvoiceRow[]>([]);
  const [subStats, setSubStats] = useState<SubStats>({ total: 0, active: 0 });
  const [loading, setLoading] = useState(true);
  const [verifyResults, setVerifyResults] = useState<Record<number, VerifyResult>>({});
  const [verifyingId, setVerifyingId] = useState<number | null>(null);

  useEffect(() => {
    Promise.all([
      api.get<BillingPreview>('/api/client/billing/preview').catch(() => null),
      api.get<{ invoices: InvoiceRow[] }>('/api/client/invoices').catch(() => ({ invoices: [] })),
      api.get<SubStats>('/api/subscriptions/stats').catch(() => ({ total: 0, active: 0 })),
    ]).then(([prev, inv, stats]) => {
      if (prev) setPreview(prev);
      setInvoices(inv.invoices || []);
      setSubStats(stats);
    }).finally(() => setLoading(false));
  }, []);

  const handleVerify = async (invoiceId: number) => {
    setVerifyingId(invoiceId);
    try {
      const result = await api.get<VerifyResult>(`/api/client/invoices/${invoiceId}/verify`);
      setVerifyResults(prev => ({ ...prev, [invoiceId]: result }));
    } catch {
      setVerifyResults(prev => ({ ...prev, [invoiceId]: { verified: false, reason: 'Verification failed', invoice_id: invoiceId } }));
    } finally {
      setVerifyingId(null);
    }
  };

  const handleDownloadPdf = async (invoiceId: number) => {
    try {
      const resp = await api.get<{ invoice: Invoice }>(`/api/client/invoices/${invoiceId}`);
      if (resp.invoice) generateInvoicePdf(resp.invoice);
    } catch { /* silent */ }
  };

  const outstandingBalance = invoices
    .filter(i => i.status === 'sent' || i.status === 'overdue')
    .reduce((sum, i) => sum + i.total_cents, 0);

  if (loading) {
    return (
      <div className="p-6 max-w-6xl mx-auto">
        <p className="text-sm text-gray-500 dark:text-gray-400">Loading billing...</p>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-gray-900 dark:text-white">Billing Overview</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-0.5">
          Subscription billing, projected charges, and invoice history
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <SummaryCard label="Active Subscriptions" value={String(subStats.active)} />
        <SummaryCard label="Projected Monthly Cost" value={preview ? formatCentsExact(preview.projected_total_cents) : '$0.00'} />
        <SummaryCard label="Next Invoice" value={nextMonthFirst()} />
        <SummaryCard label="Outstanding Balance" value={formatCentsExact(outstandingBalance)}
          accent={outstandingBalance > 0 ? 'text-red-600 dark:text-red-400' : undefined} />
      </div>

      {/* Projected Charges */}
      {preview && (
        <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-gray-900 dark:text-white">Projected Charges</h2>
              <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
                {formatDate(preview.period_start)} &mdash; {formatDate(preview.period_end)}
              </p>
            </div>
            <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${planColors[preview.plan] || planColors.free}`}>
              {preview.plan}
            </span>
          </div>

          {/* Cloud breakdown */}
          {Object.keys(preview.subscriptions_by_cloud).length > 0 && (
            <div className="flex gap-3 mb-4">
              {Object.entries(preview.subscriptions_by_cloud).map(([cloud, count]) => (
                <span key={cloud} className="text-[11px] text-gray-600 dark:text-gray-400">
                  {cloud.toUpperCase()}: {count} sub{count !== 1 ? 's' : ''}
                </span>
              ))}
            </div>
          )}

          {/* Line items */}
          <div className="divide-y divide-gray-100 dark:divide-slate-800">
            {preview.line_items.map((li, idx) => (
              <div key={idx} className="flex justify-between py-2 text-xs">
                <span className={`${li.type === 'discount' ? 'text-emerald-600 dark:text-emerald-400' : 'text-gray-700 dark:text-gray-300'}`}>
                  {li.label}
                </span>
                <span className={`font-medium ${li.type === 'discount' ? 'text-emerald-600 dark:text-emerald-400' : 'text-gray-900 dark:text-white'}`}>
                  {li.amount_cents < 0 ? '-' : ''}{formatCentsExact(Math.abs(li.amount_cents))}
                </span>
              </div>
            ))}
          </div>

          {/* Total */}
          <div className="flex justify-between pt-3 mt-2 border-t border-gray-200 dark:border-slate-700">
            <span className="text-sm font-semibold text-gray-900 dark:text-white">Projected Total</span>
            <span className="text-sm font-bold text-gray-900 dark:text-white">
              {formatCentsExact(preview.projected_total_cents)}
            </span>
          </div>
        </div>
      )}

      {/* Invoice History */}
      <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700">
        <div className="px-5 py-4 border-b border-gray-200 dark:border-slate-700">
          <h2 className="text-sm font-semibold text-gray-900 dark:text-white">Invoice History</h2>
        </div>
        {invoices.length === 0 ? (
          <div className="px-5 py-8 text-center text-xs text-gray-500 dark:text-gray-400">
            No invoices yet
          </div>
        ) : (
          <table className="min-w-full text-left text-xs">
            <thead>
              <tr className="bg-gray-50 dark:bg-slate-800 text-[10px] uppercase tracking-wider font-medium text-gray-500 dark:text-gray-400">
                <th className="px-4 py-2.5">Invoice #</th>
                <th className="px-4 py-2.5">Period</th>
                <th className="px-4 py-2.5 text-right">Total</th>
                <th className="px-4 py-2.5">Status</th>
                <th className="px-4 py-2.5">Due Date</th>
                <th className="px-4 py-2.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-slate-800">
              {invoices.map(inv => {
                const vr = verifyResults[inv.id];
                return (
                  <tr key={inv.id} className="hover:bg-gray-50/60 dark:hover:bg-slate-800/60">
                    <td className="px-4 py-2.5 font-medium text-gray-900 dark:text-white">{inv.invoice_number}</td>
                    <td className="px-4 py-2.5 text-gray-600 dark:text-gray-400">
                      {formatDate(inv.period_start)} &mdash; {formatDate(inv.period_end)}
                    </td>
                    <td className="px-4 py-2.5 text-right font-medium text-gray-900 dark:text-white">
                      {formatCentsExact(inv.total_cents)}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${statusStyles[inv.status] || statusStyles.draft}`}>
                        {inv.status}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-gray-600 dark:text-gray-400">{formatDate(inv.due_at)}</td>
                    <td className="px-4 py-2.5 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleDownloadPdf(inv.id)}
                          className="text-[10px] text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium"
                        >
                          PDF
                        </button>
                        <button
                          onClick={() => handleVerify(inv.id)}
                          disabled={verifyingId === inv.id}
                          className="text-[10px] text-gray-600 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-300 font-medium disabled:opacity-50"
                        >
                          {verifyingId === inv.id ? 'Verifying...' : 'Verify'}
                        </button>
                        {vr && (
                          <span className={`text-[10px] font-semibold ${vr.verified ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400'}`}>
                            {vr.verified ? '\u2713 Valid' : '\u2717 ' + (vr.reason || 'Mismatch')}
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Server-side calculation notice */}
      <p className="text-[10px] text-gray-400 dark:text-gray-500 text-center">
        All billing calculations are computed server-side. Amounts shown are projections based on current subscription configuration.
      </p>
    </div>
  );
};

const SummaryCard: React.FC<{ label: string; value: string; accent?: string }> = ({ label, value, accent }) => (
  <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-4">
    <p className="text-[11px] text-gray-500 dark:text-gray-400 font-medium">{label}</p>
    <p className={`text-lg font-bold mt-1 ${accent || 'text-gray-900 dark:text-white'}`}>{value}</p>
  </div>
);

export default ClientBilling;
