import React, { useEffect, useState } from 'react';
import { api } from '../../services/apiClient';

interface ActionEvent {
  id: number;
  action_type: string;
  source: 'admin_audit' | 'billing';
  admin_user_id: number | null;
  admin_username: string | null;
  target_tenant_id: number | null;
  target_tenant_name: string | null;
  details: Record<string, unknown> | null;
  ip_address: string | null;
  created_at: string;
}

const ACTION_BADGE: Record<string, { text: string; color: string; bg: string }> = {
  plan_change:           { text: 'Plan Change',     color: 'text-blue-700',   bg: 'bg-blue-100' },
  password_reset:        { text: 'Password Reset',  color: 'text-red-700',    bg: 'bg-red-100' },
  platform_fee_override: { text: 'Fee Override',     color: 'text-orange-700', bg: 'bg-orange-100' },
  rate_override:         { text: 'Rate Override',    color: 'text-cyan-700',   bg: 'bg-cyan-100' },
  commitment_change:     { text: 'Commitment',       color: 'text-purple-700', bg: 'bg-purple-100' },
  invoice_generated:     { text: 'Invoice',          color: 'text-green-700',  bg: 'bg-green-100' },
  invoice_sent:          { text: 'Sent',             color: 'text-blue-700',   bg: 'bg-blue-100' },
  invoice_paid:          { text: 'Paid',             color: 'text-green-700',  bg: 'bg-green-100' },
  invoice_void:          { text: 'Voided',           color: 'text-red-700',    bg: 'bg-red-100' },
  invoice_emailed:       { text: 'Emailed',          color: 'text-indigo-700', bg: 'bg-indigo-100' },
  tenant_updated:        { text: 'Tenant Updated',   color: 'text-gray-700',   bg: 'bg-gray-100' },
  tenant_root_created:   { text: 'Root User',        color: 'text-amber-700',  bg: 'bg-amber-100' },
};

const SOURCE_BADGE: Record<string, { text: string; color: string; bg: string }> = {
  admin_audit: { text: 'Admin', color: 'text-purple-700', bg: 'bg-purple-100' },
  billing:     { text: 'Billing', color: 'text-green-700', bg: 'bg-green-100' },
};

function fmtDateTime(iso: string): string {
  return new Date(iso).toLocaleDateString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  });
}

function summarizeDetails(details: Record<string, unknown> | null): string {
  if (!details) return '\u2014';
  const parts: string[] = [];
  if (details.old_plan && details.new_plan) parts.push(`${details.old_plan} \u2192 ${details.new_plan}`);
  if (details.old_fee !== undefined && details.new_fee !== undefined) parts.push(`fee: ${details.old_fee} \u2192 ${details.new_fee}`);
  if (details.old_term !== undefined && details.new_term !== undefined) parts.push(`term: ${details.old_term}yr \u2192 ${details.new_term}yr`);
  if (details.discount_pct) parts.push(`discount: ${details.discount_pct}%`);
  if (details.cloud) parts.push(`cloud: ${String(details.cloud).toUpperCase()}`);
  if (details.rate_cents) parts.push(`rate: ${details.rate_cents}c`);
  if (details.updated_count) parts.push(`${details.updated_count} subs`);
  if (details.fields_changed) parts.push(`fields: ${(details.fields_changed as string[]).join(', ')}`);
  // billing event sub-fields
  if (details.field_changed) parts.push(String(details.field_changed));
  if (details.old_value && details.new_value) parts.push(`${details.old_value} \u2192 ${details.new_value}`);
  return parts.length > 0 ? parts.join(' | ') : '\u2014';
}

type SourceFilter = 'all' | 'admin_audit' | 'billing';

export default function AdminActionLog() {
  const [events, setEvents] = useState<ActionEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>('all');
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const LIMIT = 50;

  function fetchEvents(reset: boolean) {
    const newOffset = reset ? 0 : offset;
    setLoading(true);
    const params = new URLSearchParams({ limit: String(LIMIT), offset: String(newOffset) });
    if (sourceFilter !== 'all') params.set('source', sourceFilter);
    api.get<{ events: ActionEvent[] }>(`/admin/action-log?${params}`)
      .then(data => {
        const rows = data.events || [];
        if (reset) {
          setEvents(rows);
        } else {
          setEvents(prev => [...prev, ...rows]);
        }
        setHasMore(rows.length >= LIMIT);
        setOffset(newOffset + rows.length);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    fetchEvents(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sourceFilter]);

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-xl font-bold text-gray-900">Admin Action Log</h2>
        <p className="text-sm text-gray-500 mt-0.5">Unified audit trail of administrative and billing actions</p>
      </div>

      <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-200 flex items-center justify-between">
          <div className="flex items-center gap-2">
            {(['all', 'admin_audit', 'billing'] as SourceFilter[]).map(f => (
              <button
                key={f}
                onClick={() => setSourceFilter(f)}
                className={`px-2.5 py-1 rounded text-[10px] font-semibold transition ${
                  sourceFilter === f
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                }`}
              >
                {f === 'all' ? 'All Events' : f === 'admin_audit' ? 'Admin' : 'Billing'}
              </button>
            ))}
          </div>
          <span className="text-[10px] text-gray-400">{events.length} events loaded</span>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-xs">
            <thead className="bg-gray-50 border-b border-gray-200 text-gray-600 uppercase tracking-wider font-medium">
              <tr>
                <th className="px-4 py-2.5">Timestamp</th>
                <th className="px-4 py-2.5">Admin User</th>
                <th className="px-4 py-2.5">Action</th>
                <th className="px-4 py-2.5">Source</th>
                <th className="px-4 py-2.5">Target Tenant</th>
                <th className="px-4 py-2.5">Details</th>
                <th className="px-4 py-2.5">IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {events.map((ev, i) => {
                const actionBadge = ACTION_BADGE[ev.action_type] || { text: ev.action_type, color: 'text-gray-700', bg: 'bg-gray-100' };
                const srcBadge = SOURCE_BADGE[ev.source] || SOURCE_BADGE.admin_audit;
                return (
                  <tr key={`${ev.source}-${ev.id}-${i}`} className="hover:bg-gray-50">
                    <td className="px-4 py-2.5 text-xs text-gray-700 font-mono whitespace-nowrap">
                      {fmtDateTime(ev.created_at)}
                    </td>
                    <td className="px-4 py-2.5 text-xs font-medium text-gray-900">
                      {ev.admin_username || '\u2014'}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${actionBadge.bg} ${actionBadge.color}`}>
                        {actionBadge.text}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${srcBadge.bg} ${srcBadge.color}`}>
                        {srcBadge.text}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-gray-600">
                      {ev.target_tenant_name || '\u2014'}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-gray-600 max-w-xs truncate" title={JSON.stringify(ev.details)}>
                      {summarizeDetails(ev.details)}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-gray-500 font-mono">
                      {ev.ip_address || '\u2014'}
                    </td>
                  </tr>
                );
              })}
              {events.length === 0 && !loading && (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-sm text-gray-400">No events found</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {hasMore && (
          <div className="px-4 py-3 border-t border-gray-100 text-center">
            <button
              onClick={() => fetchEvents(false)}
              disabled={loading}
              className="px-4 py-1.5 bg-gray-100 text-gray-700 text-xs font-semibold rounded hover:bg-gray-200 disabled:opacity-50 transition"
            >
              {loading ? 'Loading...' : 'Load More'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
