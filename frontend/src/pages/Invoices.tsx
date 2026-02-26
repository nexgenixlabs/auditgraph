import React, { useEffect, useState } from 'react';
import { formatCentsExact } from '../constants/pricing';
import { generateInvoicePdf, type Invoice } from '../utils/invoicePdfGenerator';
import { api } from '../services/apiClient';

function formatDate(iso: string | null | undefined): string {
  if (!iso) return '\u2014';
  return new Date(iso).toLocaleDateString();
}

export default function Invoices() {
  const [invoices, setInvoices] = useState<Invoice[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<number | null>(null);

  useEffect(() => {
    api.get<{ invoices: Invoice[] }>('/client/invoices')
      .then(d => setInvoices(d.invoices || []))
      .catch(() => setInvoices([]))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-gray-400">Loading invoices...</div>;
  }

  const statusStyles: Record<string, string> = {
    sent: 'bg-blue-100 text-blue-700',
    paid: 'bg-green-100 text-green-700',
    overdue: 'bg-red-100 text-red-700',
    void: 'bg-gray-100 text-gray-500 line-through',
  };

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-900 dark:text-white">Invoices</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-0.5">View and download your billing invoices</p>
      </div>

      {invoices.length === 0 ? (
        <div className="bg-white dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-lg p-12 text-center">
          <div className="text-gray-400 dark:text-gray-500 text-sm">No invoices available yet.</div>
        </div>
      ) : (
        <div className="bg-white dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-lg overflow-hidden">
          <table className="min-w-full text-left text-xs">
            <thead className="bg-gray-50 dark:bg-slate-800 border-b border-gray-200 dark:border-slate-700 text-gray-600 dark:text-gray-400 uppercase tracking-wider font-medium">
              <tr>
                <th className="px-4 py-2.5">Invoice #</th>
                <th className="px-4 py-2.5">Period</th>
                <th className="px-4 py-2.5 text-right">Total</th>
                <th className="px-4 py-2.5">Status</th>
                <th className="px-4 py-2.5">Due Date</th>
                <th className="px-4 py-2.5">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-slate-800">
              {invoices.map(inv => {
                const isExpanded = expanded === inv.id;
                return (
                  <React.Fragment key={inv.id}>
                    <tr
                      className={`hover:bg-gray-50/60 dark:hover:bg-slate-800/60 cursor-pointer ${isExpanded ? 'bg-blue-50/40 dark:bg-blue-900/10' : ''}`}
                      onClick={() => setExpanded(isExpanded ? null : inv.id)}
                    >
                      <td className="px-4 py-2.5 font-mono font-medium text-gray-900 dark:text-white">
                        <div className="flex items-center gap-1.5">
                          <svg className={`w-3 h-3 text-gray-400 transition-transform ${isExpanded ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                          </svg>
                          {inv.invoice_number}
                        </div>
                      </td>
                      <td className="px-4 py-2.5 text-gray-600 dark:text-gray-400">
                        {formatDate(inv.period_start)} — {formatDate(inv.period_end)}
                      </td>
                      <td className="px-4 py-2.5 text-right font-semibold text-gray-900 dark:text-white">
                        {formatCentsExact(inv.total_cents)}
                      </td>
                      <td className="px-4 py-2.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${statusStyles[inv.status] || 'bg-gray-100 text-gray-600'}`}>
                          {inv.status.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-gray-500 dark:text-gray-400">{formatDate(inv.due_at)}</td>
                      <td className="px-4 py-2.5">
                        <button
                          onClick={e => { e.stopPropagation(); generateInvoicePdf(inv); }}
                          className="text-[10px] text-blue-600 hover:text-blue-800 font-semibold"
                        >
                          Download PDF
                        </button>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr>
                        <td colSpan={6} className="px-4 py-3 bg-gray-50/80 dark:bg-slate-800/50 border-t border-b border-gray-200 dark:border-slate-700">
                          <div className="max-w-lg">
                            <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-2">Line Items</div>
                            <div className="space-y-1">
                              {inv.line_items.filter(li => li.type !== 'tax').map((li, i) => (
                                <div key={i} className="flex items-center justify-between text-xs">
                                  <span className="text-gray-600 dark:text-gray-400">{li.label}</span>
                                  <span className={`font-semibold ${li.amount_cents < 0 ? 'text-green-700' : 'text-gray-900 dark:text-white'}`}>
                                    {li.amount_cents < 0 ? '-' : ''}{formatCentsExact(Math.abs(li.amount_cents))}
                                  </span>
                                </div>
                              ))}
                              <div className="border-t border-gray-200 dark:border-slate-700 pt-1 mt-1 flex items-center justify-between text-xs">
                                <span className="text-gray-500">Subtotal</span>
                                <span className="font-semibold text-gray-900 dark:text-white">{formatCentsExact(inv.subtotal_cents)}</span>
                              </div>
                              {inv.tax_amount_cents > 0 && (
                                <div className="flex items-center justify-between text-xs">
                                  <span className="text-gray-500">{inv.tax_label || 'Tax'} ({inv.tax_rate}%)</span>
                                  <span className="font-semibold text-gray-900 dark:text-white">{formatCentsExact(inv.tax_amount_cents)}</span>
                                </div>
                              )}
                              <div className="border-t border-gray-200 dark:border-slate-700 pt-1 mt-1 flex items-center justify-between text-xs">
                                <span className="font-bold text-gray-700 dark:text-gray-300">Total</span>
                                <span className="font-bold text-gray-900 dark:text-white">{formatCentsExact(inv.total_cents)}</span>
                              </div>
                            </div>
                            {inv.notes && (
                              <div className="mt-3 text-xs text-gray-500 dark:text-gray-400">
                                <span className="font-semibold">Notes:</span> {inv.notes}
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
