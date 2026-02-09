import React, { useEffect, useState } from 'react';
import { useToast } from '../components/ToastProvider';

// ── Types ──────────────────────────────────────────────────────

interface ActivityEntry {
  id: number;
  action_type: string;
  description: string;
  metadata: Record<string, any> | null;
  created_at: string;
}

// ── Action type display config ─────────────────────────────────

const ACTION_CONFIG: Record<string, { label: string; color: string; bg: string; icon: string }> = {
  discovery_triggered: { label: 'Discovery Triggered', color: 'text-blue-700', bg: 'bg-blue-50', icon: '>' },
  discovery_completed: { label: 'Discovery Completed', color: 'text-green-700', bg: 'bg-green-50', icon: 'V' },
  settings_updated: { label: 'Settings Updated', color: 'text-purple-700', bg: 'bg-purple-50', icon: '*' },
  report_generated: { label: 'Report Generated', color: 'text-orange-700', bg: 'bg-orange-50', icon: 'D' },
  drift_reviewed: { label: 'Drift Reviewed', color: 'text-yellow-700', bg: 'bg-yellow-50', icon: '~' },
  test_email_sent: { label: 'Test Email Sent', color: 'text-teal-700', bg: 'bg-teal-50', icon: '@' },
  test_email_failed: { label: 'Test Email Failed', color: 'text-red-700', bg: 'bg-red-50', icon: 'X' },
  report_emailed: { label: 'Report Emailed', color: 'text-green-700', bg: 'bg-green-50', icon: '@' },
  report_email_failed: { label: 'Report Email Failed', color: 'text-red-700', bg: 'bg-red-50', icon: 'X' },
  remediation_updated: { label: 'Remediation Updated', color: 'text-indigo-700', bg: 'bg-indigo-50', icon: 'R' },
};

function getActionConfig(type: string) {
  return ACTION_CONFIG[type] || { label: type, color: 'text-gray-700', bg: 'bg-gray-50', icon: '?' };
}

function timeAgo(dateStr: string): string {
  const now = new Date();
  const date = new Date(dateStr);
  const seconds = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
  return date.toLocaleDateString();
}

// ── Component ──────────────────────────────────────────────────

export default function ActivityLog() {
  const { addToast } = useToast();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [entries, setEntries] = useState<ActivityEntry[]>([]);
  const [filter, setFilter] = useState<string>('');

  useEffect(() => {
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const url = filter
          ? `/api/activity?limit=100&type=${encodeURIComponent(filter)}`
          : '/api/activity?limit=100';
        const res = await fetch(url);
        if (!res.ok) throw new Error(`API error: ${res.status}`);
        const data = await res.json();
        setEntries(data.entries || []);
      } catch (e: any) {
        setError(e?.message || 'Failed to load activity log');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [filter]);

  // ── Loading ────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse space-y-6">
          <div className="h-8 bg-gray-200 rounded w-48" />
          <div className="h-12 bg-gray-100 rounded-xl" />
          <div className="h-96 bg-gray-100 rounded-xl" />
        </div>
      </div>
    );
  }

  // ── Error ──────────────────────────────────────────────────
  if (error) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-red-700">
          <div className="font-semibold">Error loading activity log</div>
          <div className="text-sm mt-1">{error}</div>
        </div>
      </div>
    );
  }

  const actionTypes = Object.keys(ACTION_CONFIG);

  function exportCsv() {
    const header = ['ID', 'Action Type', 'Description', 'Metadata', 'Timestamp'];
    const rows = entries.map(e => [
      e.id,
      getActionConfig(e.action_type).label,
      e.description,
      e.metadata ? JSON.stringify(e.metadata) : '',
      new Date(e.created_at).toISOString(),
    ]);
    const csv = [header, ...rows].map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `activity-log-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    addToast(`Exported ${entries.length} entries to CSV`, 'success');
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Activity Log</h2>
        <p className="text-sm text-gray-600 mt-1">
          Audit trail of system and user actions
        </p>
      </div>

      {/* Summary + Filter bar */}
      <div className="flex items-center justify-between bg-white border rounded-xl px-6 py-4">
        <div>
          <div className="text-2xl font-bold text-gray-900">{entries.length}</div>
          <div className="text-xs text-gray-500">
            {filter ? `Filtered entries` : 'Recent entries'}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={exportCsv}
            disabled={entries.length === 0}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-gray-100 text-gray-700 hover:bg-gray-200 transition disabled:opacity-40 disabled:cursor-not-allowed mr-2"
          >
            Export CSV
          </button>
          <span className="text-xs text-gray-500 mr-1">Filter:</span>
          <button
            onClick={() => setFilter('')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              !filter ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            All
          </button>
          {actionTypes.map(type => {
            const cfg = getActionConfig(type);
            return (
              <button
                key={type}
                onClick={() => setFilter(type)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                  filter === type ? 'bg-blue-600 text-white' : `${cfg.bg} ${cfg.color} hover:opacity-80`
                }`}
              >
                {cfg.label.split(' ')[0]}
              </button>
            );
          })}
        </div>
      </div>

      {/* Empty state */}
      {entries.length === 0 ? (
        <div className="bg-white border rounded-xl p-12 text-center">
          <svg className="w-12 h-12 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
          </svg>
          <div className="text-gray-500 font-medium">No activity recorded yet</div>
          <div className="text-sm text-gray-400 mt-1">
            Actions like discovery runs, settings changes, and report generation will appear here
          </div>
        </div>
      ) : (
        /* Activity table */
        <div className="bg-white border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-50 border-b text-left">
                <th className="px-4 py-3 font-medium text-gray-600 w-48">Action</th>
                <th className="px-4 py-3 font-medium text-gray-600">Description</th>
                <th className="px-4 py-3 font-medium text-gray-600 w-44 text-right">Time</th>
              </tr>
            </thead>
            <tbody>
              {entries.map(entry => {
                const cfg = getActionConfig(entry.action_type);
                return (
                  <tr key={entry.id} className="border-b hover:bg-gray-50 transition">
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${cfg.bg} ${cfg.color}`}>
                        <span className="font-mono">{cfg.icon}</span>
                        {cfg.label}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-700">
                      {entry.description}
                      {entry.metadata && Object.keys(entry.metadata).length > 0 && (
                        <span className="ml-2 text-[10px] text-gray-400 font-mono">
                          {Object.entries(entry.metadata)
                            .filter(([, v]) => v !== null && v !== undefined)
                            .slice(0, 3)
                            .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`)
                            .join(' ')}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="text-xs text-gray-500">{timeAgo(entry.created_at)}</div>
                      <div className="text-[10px] text-gray-400">
                        {new Date(entry.created_at).toLocaleString()}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
