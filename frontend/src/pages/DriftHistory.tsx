import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useToast } from '../components/ToastProvider';
import { useConnection } from '../contexts/ConnectionContext';
import { SEVERITY_COLORS, DRIFT_EVENT_LABELS } from '../constants/metrics';

// ── Types ──────────────────────────────────────────────────────

interface DriftReport {
  id: number;
  current_run_id: number;
  previous_run_id: number;
  new_identities_count: number;
  removed_identities_count: number;
  permission_changes_count: number;
  risk_changes_count: number;
  credential_changes_count: number;
  total_changes: number;
  created_at: string;
  run_completed_at: string | null;
  max_severity?: string | null;
  privilege_escalation_count?: number;
  attack_path_created_count?: number;
  identity_resurrection_count?: number;
}

interface IdentityData {
  identity_id: string;
  display_name: string;
  identity_type: string;
  identity_category: string;
  risk_level: string;
  credential_status: string;
  change_reason?: string;
}

interface DriftEvent {
  event_type: string;
  severity: string;
  identity_id: string;
  display_name: string;
  description: string;
  details: Record<string, unknown>;
  timestamp: string;
}

interface FullDriftReport {
  current_run_id: number;
  previous_run_id: number;
  total_changes: number;
  events?: DriftEvent[];
  max_severity?: string;
  privilege_escalation_count?: number;
  attack_path_created_count?: number;
  identity_resurrection_count?: number;
  changes: {
    new_identities: IdentityData[];
    removed_identities: IdentityData[];
    microsoft_removed_identities?: IdentityData[];
    permission_changes: Array<{
      identity: IdentityData;
      added_roles: string[];
      removed_roles: string[];
      role_deltas?: Array<{
        change_type: 'added' | 'removed' | 'modified';
        previous_role?: string;
        new_role?: string;
        scope_type: string;
        scope: string;
      }>;
      change_reason?: string;
    }>;
    risk_changes: Array<{
      identity: IdentityData;
      previous_risk: string;
      current_risk: string;
      previous_score?: number;
      current_score?: number;
      severity: 'escalation' | 'de-escalation' | 'unchanged';
      change_reason?: string;
    }>;
    credential_changes: Array<{
      identity: IdentityData;
      previous_status: string;
      current_status: string;
      change_reason?: string;
    }>;
    classification_changes?: Array<{
      change_type: string;
      resource_id: string;
      resource_name: string;
      resource_type: string;
      new_classification: string | null;
      previous_classification: string | null;
    }>;
  };
}

// ── Helpers ─────────────────────────────────────────────────────

const RISK_COLORS: Record<string, string> = {
  critical: 'text-red-600 bg-red-50',
  high: 'text-orange-600 bg-orange-50',
  medium: 'text-yellow-700 bg-yellow-50',
  low: 'text-blue-600 bg-blue-50',
  info: 'text-gray-500 bg-gray-50',
};

function riskBadge(level: string) {
  const colors = RISK_COLORS[level?.toLowerCase()] || 'text-gray-500 bg-gray-50';
  return (
    <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase ${colors}`}>
      {level || 'unknown'}
    </span>
  );
}

function categoryLabel(cat: string) {
  return (cat || 'unknown').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// ── Component ──────────────────────────────────────────────────

export default function DriftHistory() {
  const { addToast } = useToast();
  const { withConnection, selectedConnectionId } = useConnection();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reports, setReports] = useState<DriftReport[]>([]);

  // Expanded row state
  const [expandedSnapshotId, setExpandedSnapshotId] = useState<number | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [detail, setDetail] = useState<FullDriftReport | null>(null);

  // Snapshot comparison
  const [showCompare, setShowCompare] = useState(false);
  const [compareFrom, setCompareFrom] = useState('');
  const [compareTo, setCompareTo] = useState('');
  const [compareLoading, setCompareLoading] = useState(false);
  const [compareResult, setCompareResult] = useState<any>(null);

  // Collapsible sections in detail view
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
    new_identities: true,
    removed_identities: true,
    microsoft_removed_identities: false,
    permission_changes: true,
    risk_changes: true,
    credential_changes: true,
    classification_changes: true,
  });

  useEffect(() => {
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(withConnection('/api/drift/history?limit=50'));
        if (!res.ok) throw new Error(`API error: ${res.status}`);
        const data = await res.json();
        setReports(data.reports || []);
      } catch (e: any) {
        setError(e?.message || 'Failed to load drift history');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [selectedConnectionId]);

  async function toggleSnapshot(snapshotId: number) {
    if (expandedSnapshotId === snapshotId) {
      setExpandedSnapshotId(null);
      setDetail(null);
      return;
    }

    setExpandedSnapshotId(snapshotId);
    setDetailLoading(true);
    setDetailError(null);
    setDetail(null);

    try {
      const res = await fetch(withConnection(`/api/runs/${snapshotId}/drift`));
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      const data = await res.json();
      setDetail(data);
    } catch (e: any) {
      setDetailError(e?.message || 'Failed to load drift details');
    } finally {
      setDetailLoading(false);
    }
  }

  function toggleSection(key: string) {
    setOpenSections(prev => ({ ...prev, [key]: !prev[key] }));
  }

  const runCompare = useCallback(async () => {
    if (!compareFrom || !compareTo) {
      addToast('Select both dates', 'error');
      return;
    }
    setCompareLoading(true);
    setCompareResult(null);
    try {
      const res = await fetch(withConnection(`/api/snapshots/compare?from=${compareFrom}&to=${compareTo}`));
      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        throw new Error(errData?.error || `Compare failed (${res.status})`);
      }
      setCompareResult(await res.json());
    } catch (e: any) {
      addToast(e?.message || 'Comparison failed', 'error');
    } finally {
      setCompareLoading(false);
    }
  }, [compareFrom, compareTo, withConnection, addToast]);

  // Summary stats
  const totalReports = reports.length;
  const totalChanges = reports.reduce((sum, r) => sum + r.total_changes, 0);

  function exportCsv() {
    const header = ['Report ID', 'Current Snapshot', 'Previous Snapshot', 'Date', 'Total Changes', 'New', 'Removed', 'Permissions', 'Risk', 'Credentials'];
    const rows = reports.map(r => [
      r.id,
      r.current_run_id,
      r.previous_run_id,
      r.run_completed_at ? new Date(r.run_completed_at).toISOString() : new Date(r.created_at).toISOString(),
      r.total_changes,
      r.new_identities_count,
      r.removed_identities_count,
      r.permission_changes_count,
      r.risk_changes_count,
      r.credential_changes_count,
    ]);
    const csv = [header, ...rows].map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `drift-history-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    addToast(`Exported ${reports.length} drift reports to CSV`, 'success');
  }

  // ── Loading ────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-gray-200 rounded w-64" />
          <div className="h-16 bg-gray-100 rounded-xl" />
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
          <div className="font-semibold">Error loading drift history</div>
          <div className="text-sm mt-1">{error}</div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Drift History</h2>
          <div className="flex items-center gap-2 mt-1">
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
              All identity and permission changes
            </p>
            {reports.length > 0 && (
              <>
                <span className="text-xs px-1.5 py-0.5 rounded font-medium" style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border-default)' }}>
                  {reports.length} snapshots
                </span>
                <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-700 text-[9px] font-semibold uppercase tracking-wide" title="Snapshot data is immutable — it reflects the state at capture time">
                  <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
                  Immutable
                </span>
              </>
            )}
          </div>
        </div>
        <button
          onClick={() => setShowCompare(!showCompare)}
          className={`px-4 py-2 rounded-lg text-sm font-medium border transition ${
            showCompare
              ? 'bg-blue-600 text-white border-blue-600'
              : 'text-blue-600 border-blue-300 hover:bg-blue-50'
          }`}
        >
          {showCompare ? 'Hide Compare' : 'Compare Snapshots'}
        </button>
      </div>

      {/* Snapshot Comparison Panel */}
      {showCompare && (
        <div className="rounded-xl border p-5 space-y-4" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-default)' }}>
          <div className="flex items-end gap-4 flex-wrap">
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>From Date</label>
              <input
                type="date"
                value={compareFrom}
                onChange={e => setCompareFrom(e.target.value)}
                className="px-3 py-2 rounded-lg border text-sm"
                style={{ backgroundColor: 'var(--bg-primary)', borderColor: 'var(--border-default)', color: 'var(--text-primary)' }}
              />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>To Date</label>
              <input
                type="date"
                value={compareTo}
                onChange={e => setCompareTo(e.target.value)}
                className="px-3 py-2 rounded-lg border text-sm"
                style={{ backgroundColor: 'var(--bg-primary)', borderColor: 'var(--border-default)', color: 'var(--text-primary)' }}
              />
            </div>
            <button
              onClick={runCompare}
              disabled={compareLoading || !compareFrom || !compareTo}
              className="px-4 py-2 rounded-lg text-sm font-medium bg-blue-600 text-white hover:bg-blue-700 transition disabled:opacity-50"
            >
              {compareLoading ? 'Comparing...' : 'Compare'}
            </button>
          </div>

          {/* Comparison results */}
          {compareResult && (
            <div className="space-y-4">
              {/* Summary cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <CompareCard label="From" sublabel={compareResult.from_run?.completed_at ? new Date(compareResult.from_run.completed_at).toLocaleDateString() : compareResult.from_date} value={String(compareResult.from_run?.total_identities ?? 0)} detail={`Snapshot #${compareResult.from_run?.run_id}`} />
                <CompareCard label="To" sublabel={compareResult.to_run?.completed_at ? new Date(compareResult.to_run.completed_at).toLocaleDateString() : compareResult.to_date} value={String(compareResult.to_run?.total_identities ?? 0)} detail={`Snapshot #${compareResult.to_run?.run_id}`} />
                <CompareCard label="Added" sublabel="New identities" value={`+${compareResult.summary?.added_count ?? 0}`} detail="" color="text-green-600" />
                <CompareCard label="Removed" sublabel="Removed identities" value={`-${compareResult.summary?.removed_count ?? 0}`} detail="" color="text-red-600" />
              </div>

              {/* Risk distribution comparison */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <RiskDistCard title="From" dist={compareResult.from_risk_distribution} />
                <RiskDistCard title="To" dist={compareResult.to_risk_distribution} />
              </div>

              {/* Risk changes */}
              {compareResult.risk_changes?.length > 0 && (
                <div className="rounded-lg border overflow-hidden" style={{ borderColor: 'var(--border-default)' }}>
                  <div className="px-4 py-2 text-sm font-semibold" style={{ backgroundColor: 'var(--bg-tertiary, var(--bg-secondary))', color: 'var(--text-primary)' }}>
                    Risk Changes ({compareResult.risk_changes.length})
                  </div>
                  <div className="divide-y" style={{ borderColor: 'var(--border-default)' }}>
                    {compareResult.risk_changes.slice(0, 20).map((rc: any, i: number) => (
                      <div key={i} className="px-4 py-2 flex items-center gap-3 text-sm" style={{ color: 'var(--text-primary)' }}>
                        <Link to={`/identities/${rc.identity_id}`} className="text-blue-600 hover:underline font-medium">
                          {rc.display_name}
                        </Link>
                        {riskBadge(rc.old_risk_level)}
                        <span style={{ color: 'var(--text-secondary)' }}>{'\u2192'}</span>
                        {riskBadge(rc.new_risk_level)}
                        <span className={`text-xs font-mono ${rc.score_delta > 0 ? 'text-red-500' : 'text-green-500'}`}>
                          {rc.score_delta > 0 ? '+' : ''}{rc.score_delta}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Added identities (truncated) */}
              {compareResult.added_identities?.length > 0 && (
                <div className="rounded-lg border overflow-hidden" style={{ borderColor: 'var(--border-default)' }}>
                  <div className="px-4 py-2 text-sm font-semibold text-green-700" style={{ backgroundColor: 'rgba(34,197,94,0.08)' }}>
                    Added Identities ({compareResult.summary?.added_count})
                  </div>
                  <div className="divide-y" style={{ borderColor: 'var(--border-default)' }}>
                    {compareResult.added_identities.slice(0, 15).map((a: any, i: number) => (
                      <div key={i} className="px-4 py-1.5 flex items-center gap-3 text-sm" style={{ color: 'var(--text-primary)' }}>
                        <span className="text-green-600 font-mono">+</span>
                        <span className="font-medium">{a.display_name}</span>
                        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{(a.identity_category || '').replace(/_/g, ' ')}</span>
                        {riskBadge(a.risk_level)}
                      </div>
                    ))}
                    {compareResult.summary?.added_count > 15 && (
                      <div className="px-4 py-1.5 text-xs" style={{ color: 'var(--text-secondary)' }}>
                        ...and {compareResult.summary.added_count - 15} more
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Removed identities (truncated) */}
              {compareResult.removed_identities?.length > 0 && (
                <div className="rounded-lg border overflow-hidden" style={{ borderColor: 'var(--border-default)' }}>
                  <div className="px-4 py-2 text-sm font-semibold text-red-700" style={{ backgroundColor: 'rgba(239,68,68,0.08)' }}>
                    Removed Identities ({compareResult.summary?.removed_count})
                  </div>
                  <div className="divide-y" style={{ borderColor: 'var(--border-default)' }}>
                    {compareResult.removed_identities.slice(0, 15).map((r: any, i: number) => (
                      <div key={i} className="px-4 py-1.5 flex items-center gap-3 text-sm" style={{ color: 'var(--text-primary)' }}>
                        <span className="text-red-600 font-mono">-</span>
                        <span className="font-medium">{r.display_name}</span>
                        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{(r.identity_category || '').replace(/_/g, ' ')}</span>
                      </div>
                    ))}
                    {compareResult.summary?.removed_count > 15 && (
                      <div className="px-4 py-1.5 text-xs" style={{ color: 'var(--text-secondary)' }}>
                        ...and {compareResult.summary.removed_count - 15} more
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Empty state */}
      {reports.length === 0 ? (
        <div className="bg-white border rounded-xl p-12 text-center">
          <svg className="w-12 h-12 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          <div className="text-gray-500 font-medium">No drift reports yet</div>
          <div className="text-sm text-gray-400 mt-1">
            Drift data becomes available after 2+ snapshots
          </div>
        </div>
      ) : (
        <>
          {/* Summary bar */}
          <div className="flex items-center gap-6 bg-white border rounded-xl px-6 py-4">
            <div>
              <div className="text-2xl font-bold text-gray-900">{totalReports}</div>
              <div className="text-xs text-gray-500">Reports</div>
            </div>
            <div className="w-px h-10 bg-gray-200" />
            <div>
              <div className="text-2xl font-bold text-gray-900">{totalChanges}</div>
              <div className="text-xs text-gray-500">Total Changes</div>
            </div>
            <div className="w-px h-10 bg-gray-200" />
            <button
              onClick={exportCsv}
              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-gray-100 text-gray-700 hover:bg-gray-200 transition"
            >
              Export CSV
            </button>
            <div className="w-px h-10 bg-gray-200" />
            <div className="flex items-center gap-4 text-xs text-gray-500">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-green-500" /> New</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500" /> Removed</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-orange-500" /> Permissions</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-purple-500" /> Risk</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-yellow-500" /> Credentials</span>
            </div>
          </div>

          {/* Timeline table */}
          <div className="bg-white border rounded-xl overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-gray-50 border-b text-left">
                  <th className="px-3 py-2.5 font-medium uppercase text-gray-600 w-8" />
                  <th className="px-3 py-2.5 font-medium uppercase text-gray-600">Snapshot Comparison</th>
                  <th className="px-3 py-2.5 font-medium uppercase text-gray-600">Date</th>
                  <th className="px-3 py-2.5 font-medium uppercase text-gray-600 text-center">Total</th>
                  <th className="px-3 py-2.5 font-medium uppercase text-gray-600 text-center">Severity</th>
                  <th className="px-3 py-2.5 font-medium uppercase text-green-700 text-center">New</th>
                  <th className="px-3 py-2.5 font-medium uppercase text-red-700 text-center">Removed</th>
                  <th className="px-3 py-2.5 font-medium uppercase text-orange-700 text-center">Perms</th>
                  <th className="px-3 py-2.5 font-medium uppercase text-purple-700 text-center">Risk</th>
                  <th className="px-3 py-2.5 font-medium uppercase text-yellow-700 text-center">Creds</th>
                </tr>
              </thead>
              <tbody>
                {reports.map(report => (
                  <React.Fragment key={report.id}>
                    <tr
                      onClick={() => toggleSnapshot(report.current_run_id)}
                      className={`border-b cursor-pointer transition hover:bg-gray-50 ${
                        expandedSnapshotId === report.current_run_id ? 'bg-blue-50' : ''
                      }`}
                    >
                      <td className="px-3 py-2 text-gray-400">
                        <svg
                          className={`w-4 h-4 transition-transform ${
                            expandedSnapshotId === report.current_run_id ? 'rotate-90' : ''
                          }`}
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
                      </td>
                      <td className="px-3 py-2">
                        <span className="font-mono text-xs text-gray-700">
                          Snapshot #{report.current_run_id} vs #{report.previous_run_id}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-gray-600">
                        {report.run_completed_at
                          ? new Date(report.run_completed_at).toLocaleString()
                          : new Date(report.created_at).toLocaleString()}
                      </td>
                      <td className="px-3 py-2 text-center">
                        {report.total_changes === 0 ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-green-50 text-green-700 rounded-full text-xs font-medium">
                            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                            </svg>
                            Stable
                          </span>
                        ) : (
                          <span className="font-bold text-gray-900">{report.total_changes}</span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-center">
                        {report.max_severity ? (
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEVERITY_COLORS[report.max_severity] || 'bg-gray-100 text-gray-500'}`}>
                            {report.max_severity}
                          </span>
                        ) : (
                          <span className="text-gray-300">—</span>
                        )}
                      </td>
                      <CountCell count={report.new_identities_count} color="text-green-600" />
                      <CountCell count={report.removed_identities_count} color="text-red-600" />
                      <CountCell count={report.permission_changes_count} color="text-orange-600" />
                      <CountCell count={report.risk_changes_count} color="text-purple-600" />
                      <CountCell count={report.credential_changes_count} color="text-yellow-700" />
                    </tr>

                    {/* Expanded detail row */}
                    {expandedSnapshotId === report.current_run_id && (
                      <tr>
                        <td colSpan={10} className="bg-gray-50 px-3 py-2">
                          {detailLoading && (
                            <div className="flex items-center gap-2 text-sm text-gray-500">
                              <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                              </svg>
                              Loading change details...
                            </div>
                          )}
                          {detailError && (
                            <div className="text-sm text-red-600">{detailError}</div>
                          )}
                          {detail && (
                            <DetailView
                              detail={detail}
                              openSections={openSections}
                              onToggleSection={toggleSection}
                            />
                          )}
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

// ── Count Cell ──────────────────────────────────────────────

function CountCell({ count, color }: { count: number; color: string }) {
  return (
    <td className="px-3 py-2 text-center">
      {count > 0 ? (
        <span className={`font-semibold ${color}`}>{count}</span>
      ) : (
        <span className="text-gray-300">—</span>
      )}
    </td>
  );
}

// ── Detail View ─────────────────────────────────────────────

function DetailView({
  detail,
  openSections,
  onToggleSection,
}: {
  detail: FullDriftReport;
  openSections: Record<string, boolean>;
  onToggleSection: (key: string) => void;
}) {
  const sections = [
    {
      key: 'new_identities',
      label: 'New Identities',
      count: detail.changes.new_identities?.length || 0,
      color: 'text-green-700',
      bgHeader: 'bg-green-50',
      icon: '+',
    },
    {
      key: 'removed_identities',
      label: 'Removed Identities',
      count: detail.changes.removed_identities?.length || 0,
      color: 'text-red-700',
      bgHeader: 'bg-red-50',
      icon: '-',
    },
    {
      key: 'microsoft_removed_identities',
      label: 'Microsoft Removed',
      count: detail.changes.microsoft_removed_identities?.length || 0,
      color: 'text-gray-600',
      bgHeader: 'bg-gray-100',
      icon: 'M',
    },
    {
      key: 'permission_changes',
      label: 'Permission Changes',
      count: detail.changes.permission_changes?.length || 0,
      color: 'text-orange-700',
      bgHeader: 'bg-orange-50',
      icon: '~',
    },
    {
      key: 'risk_changes',
      label: 'Risk Changes',
      count: detail.changes.risk_changes?.length || 0,
      color: 'text-purple-700',
      bgHeader: 'bg-purple-50',
      icon: '!',
    },
    {
      key: 'credential_changes',
      label: 'Credential Changes',
      count: detail.changes.credential_changes?.length || 0,
      color: 'text-yellow-700',
      bgHeader: 'bg-yellow-50',
      icon: '*',
    },
    {
      key: 'classification_changes',
      label: 'Classification Changes',
      count: detail.changes.classification_changes?.length || 0,
      color: 'text-cyan-700',
      bgHeader: 'bg-cyan-50',
      icon: '\u25C9',
    },
  ];

  const nonEmpty = sections.filter(s => s.count > 0);

  // Build event lookup by identity_id for section-level badges
  // (must be called unconditionally — React hooks rules)
  const eventsByIdentity = useMemo(() => {
    const map: Record<string, DriftEvent[]> = {};
    for (const e of (detail.events || [])) {
      const id = e.identity_id;
      if (id) {
        if (!map[id]) map[id] = [];
        map[id].push(e);
      }
    }
    return map;
  }, [detail.events]);

  const hasIntel = !!(detail.max_severity || (detail.events?.length ?? 0) > 0);

  if (nonEmpty.length === 0) {
    return (
      <div className="flex items-center gap-2 p-3 bg-green-50 rounded-lg">
        <svg className="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <span className="text-sm text-green-700 font-medium">Environment stable — no changes detected</span>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Security Intelligence summary panel */}
      {hasIntel && (
        <div className="rounded-lg border p-4 mb-3 bg-gray-50">
          <div className="text-xs font-semibold uppercase tracking-wide mb-2 text-gray-500">
            Security Intelligence
          </div>
          <div className="flex items-center gap-4 flex-wrap">
            <IntelCard
              label="Max Severity"
              value={detail.max_severity || 'low'}
              badgeClass={SEVERITY_COLORS[detail.max_severity || 'low'] || 'bg-gray-100 text-gray-500'}
              isBadge
            />
            <IntelCard
              label="Privilege Escalations"
              value={detail.privilege_escalation_count || 0}
              badgeClass={detail.privilege_escalation_count ? 'bg-red-50 text-red-700' : 'bg-gray-50 text-gray-400'}
            />
            <IntelCard
              label="New Attack Paths"
              value={detail.attack_path_created_count || 0}
              badgeClass={detail.attack_path_created_count ? 'bg-red-50 text-red-700' : 'bg-gray-50 text-gray-400'}
            />
            <IntelCard
              label="Resurrections"
              value={detail.identity_resurrection_count || 0}
              badgeClass={detail.identity_resurrection_count ? 'bg-orange-50 text-orange-700' : 'bg-gray-50 text-gray-400'}
            />
            <IntelCard
              label="Events"
              value={detail.events?.length || 0}
              badgeClass="bg-blue-50 text-blue-700"
            />
          </div>
        </div>
      )}

      {nonEmpty.map(section => (
        <div key={section.key} className="border rounded-lg bg-white overflow-hidden">
          {/* Section header */}
          <button
            onClick={(e) => { e.stopPropagation(); onToggleSection(section.key); }}
            className={`w-full flex items-center justify-between px-4 py-2.5 ${section.bgHeader} hover:opacity-90 transition`}
          >
            <div className="flex items-center gap-2">
              <span className={`font-mono font-bold text-sm ${section.color}`}>{section.icon}</span>
              <span className={`text-sm font-semibold ${section.color}`}>{section.label}</span>
              <span className={`text-xs font-medium ${section.color} opacity-70`}>({section.count})</span>
            </div>
            <svg
              className={`w-4 h-4 text-gray-500 transition-transform ${openSections[section.key] ? 'rotate-180' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>

          {/* Section content */}
          {openSections[section.key] && (
            <div className="px-4 py-3">
              {section.key === 'new_identities' && (
                <NewIdentitiesSection items={detail.changes.new_identities} eventsByIdentity={eventsByIdentity} />
              )}
              {section.key === 'removed_identities' && (
                <RemovedIdentitiesSection items={detail.changes.removed_identities} />
              )}
              {section.key === 'microsoft_removed_identities' && (
                <MicrosoftRemovedSection items={detail.changes.microsoft_removed_identities || []} />
              )}
              {section.key === 'permission_changes' && (
                <PermissionChangesSection items={detail.changes.permission_changes} eventsByIdentity={eventsByIdentity} />
              )}
              {section.key === 'risk_changes' && (
                <RiskChangesSection items={detail.changes.risk_changes} />
              )}
              {section.key === 'credential_changes' && (
                <CredentialChangesSection items={detail.changes.credential_changes} />
              )}
              {section.key === 'classification_changes' && (
                <ClassificationChangesSection items={detail.changes.classification_changes || []} />
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Section Components ──────────────────────────────────────

function IdentityLink({ identity }: { identity: IdentityData }) {
  return (
    <Link
      to={`/identities/${identity.identity_id}`}
      className="text-blue-600 hover:text-blue-800 hover:underline font-medium"
      onClick={e => e.stopPropagation()}
    >
      {identity.display_name || identity.identity_id}
    </Link>
  );
}

const NEW_REASON_TOOLTIPS: Record<string, string> = {
  'Created in Entra ID': 'This identity was newly created in Entra ID between the two scans.',
  'First discovered': 'This identity existed before AuditGraph monitoring began and is appearing for the first time.',
  'Moved into monitored scope': 'This identity already existed but was assigned RBAC roles on a monitored subscription.',
};

const DRIFT_REASON_TOOLTIPS: Record<string, string> = {
  'Disabled': 'This identity was explicitly disabled in Entra ID between snapshots.',
  'Service principal removed': 'The service principal was deleted but its app registration still exists. This may indicate a deployment reset or manual cleanup.',
  'Removed from monitored scope': 'This identity still exists in Entra ID but no longer has RBAC role assignments on any monitored subscription.',
  'Not observed in latest scan': 'This identity was not found in the latest discovery scan. It may have been deleted from Entra ID, or an API error prevented its discovery.',
};

function reasonTooltip(reason: string | undefined, tooltips: Record<string, string>): string | undefined {
  if (!reason) return undefined;
  return Object.entries(tooltips).find(([k]) => reason.startsWith(k))?.[1];
}

function NewIdentitiesSection({ items, eventsByIdentity }: { items: IdentityData[]; eventsByIdentity?: Record<string, DriftEvent[]> }) {
  return (
    <div className="space-y-2">
      {items.map((item, i) => {
        const matchingEvent = eventsByIdentity?.[item.identity_id]?.find(
          e => e.event_type === 'identity_added' || e.event_type === 'identity_resurrection'
        );
        const br = matchingEvent?.details?.blast_radius as Record<string, unknown> | undefined;
        return (
          <div key={item.identity_id || i}>
            <div className="flex items-center gap-2 text-sm flex-wrap">
              <span className="text-green-600 font-mono font-bold">+</span>
              <IdentityLink identity={item} />
              <span className="text-gray-400">·</span>
              <span className="text-xs text-gray-500">{categoryLabel(item.identity_category)}</span>
              {riskBadge(item.risk_level)}
              {matchingEvent?.severity && (
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEVERITY_COLORS[matchingEvent.severity] || ''}`}>
                  {matchingEvent.severity}
                </span>
              )}
              {matchingEvent?.event_type && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-600">
                  {DRIFT_EVENT_LABELS[matchingEvent.event_type] || matchingEvent.event_type}
                </span>
              )}
              {br && Number(br.resource_count) > 0 && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-50 text-purple-600">
                  {String(br.resource_count)} resources at risk
                </span>
              )}
            </div>
            {!!item.change_reason && (
              <div className="ml-5 mt-0.5 text-xs text-gray-500 italic cursor-help" title={reasonTooltip(item.change_reason, NEW_REASON_TOOLTIPS)}>{item.change_reason}</div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function RemovedIdentitiesSection({ items }: { items: IdentityData[] }) {
  return (
    <div className="space-y-2">
      {items.map((item, i) => (
        <div key={item.identity_id || i}>
          <div className="flex items-center gap-3 text-sm">
            <span className="text-red-600 font-mono font-bold">-</span>
            <span className="font-medium text-gray-700">{item.display_name || item.identity_id}</span>
            <span className="text-gray-400">·</span>
            <span className="text-xs text-gray-500">{categoryLabel(item.identity_category)}</span>
          </div>
          {!!item.change_reason && (
            <div className="ml-5 mt-0.5 text-xs text-gray-500 italic cursor-help" title={reasonTooltip(item.change_reason, DRIFT_REASON_TOOLTIPS)}>{item.change_reason}</div>
          )}
        </div>
      ))}
    </div>
  );
}

function MicrosoftRemovedSection({ items }: { items: IdentityData[] }) {
  return (
    <div className="space-y-2">
      <div className="text-xs text-gray-500 mb-2">
        Microsoft first-party identities removed from tenant. These are typically managed by Microsoft and are informational only.
      </div>
      {items.map((item, i) => (
        <div key={item.identity_id || i} className="flex items-center gap-3 text-sm">
          <span className="text-gray-400 font-mono font-bold">M</span>
          <Link
            to={`/identities?hide_microsoft=false&search=${encodeURIComponent(item.display_name || '')}`}
            className="text-gray-600 hover:text-blue-600 hover:underline"
            onClick={e => e.stopPropagation()}
          >
            {item.display_name || item.identity_id}
          </Link>
          <span className="text-gray-300">·</span>
          <span className="text-xs text-gray-400">{categoryLabel(item.identity_category)}</span>
        </div>
      ))}
    </div>
  );
}

type RoleDelta = {
  change_type: 'added' | 'removed' | 'modified';
  previous_role?: string;
  new_role?: string;
  scope_type: string;
  scope: string;
};

/** Parse legacy role signature "RoleName:scope_type:/scope/path" into a RoleDelta */
function parseRoleSignature(sig: string, changeType: 'added' | 'removed'): RoleDelta {
  const parts = sig.split(':');
  const roleName = parts[0] || '';
  const scopeType = parts[1] || '';
  const scope = parts.slice(2).join(':');
  return {
    change_type: changeType,
    ...(changeType === 'added' ? { new_role: roleName } : { previous_role: roleName }),
    scope_type: scopeType,
    scope,
  };
}

/** Build deltas from legacy added/removed strings when role_deltas is absent */
function buildFallbackDeltas(addedRoles: string[], removedRoles: string[]): RoleDelta[] {
  const added = addedRoles.map(s => parseRoleSignature(s, 'added'));
  const removed = removedRoles.map(s => parseRoleSignature(s, 'removed'));

  // Try to match added+removed on same scope as "modified"
  const deltas: RoleDelta[] = [];
  const usedRemoved = new Set<number>();
  for (const a of added) {
    const matchIdx = removed.findIndex(
      (r, idx) => !usedRemoved.has(idx) && r.scope_type === a.scope_type && r.scope === a.scope
    );
    if (matchIdx >= 0) {
      usedRemoved.add(matchIdx);
      deltas.push({
        change_type: 'modified',
        previous_role: removed[matchIdx].previous_role,
        new_role: a.new_role,
        scope_type: a.scope_type,
        scope: a.scope,
      });
    } else {
      deltas.push(a);
    }
  }
  removed.forEach((r, idx) => { if (!usedRemoved.has(idx)) deltas.push(r); });
  return deltas;
}

const CHANGE_TYPE_STYLES: Record<string, { label: string; badge: string }> = {
  added:    { label: 'Role Added',    badge: 'bg-green-100 text-green-700 border-green-200' },
  removed:  { label: 'Role Removed',  badge: 'bg-red-100 text-red-700 border-red-200' },
  modified: { label: 'Role Modified', badge: 'bg-orange-100 text-orange-700 border-orange-200' },
};

function PermissionChangesSection({ items, eventsByIdentity }: { items: FullDriftReport['changes']['permission_changes']; eventsByIdentity?: Record<string, DriftEvent[]> }) {
  return (
    <div className="space-y-4">
      {items.map((item, i) => {
        const deltas: RoleDelta[] = item.role_deltas && item.role_deltas.length > 0
          ? item.role_deltas
          : buildFallbackDeltas(item.added_roles, item.removed_roles);

        const matchingEvent = eventsByIdentity?.[item.identity?.identity_id]?.find(
          e => ['role_assigned', 'role_removed', 'privilege_escalated', 'privilege_deescalated'].includes(e.event_type)
        );
        const br = matchingEvent?.details?.blast_radius as Record<string, unknown> | undefined;

        return (
          <div key={item.identity?.identity_id || i} className="space-y-2">
            {deltas.map((delta, j) => {
              const style = CHANGE_TYPE_STYLES[delta.change_type] || CHANGE_TYPE_STYLES.added;
              return (
                <div
                  key={j}
                  className="rounded-lg border p-3 text-sm"
                  style={{ backgroundColor: 'var(--bg-primary)', borderColor: 'var(--border-default)' }}
                >
                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                    <IdentityLink identity={item.identity} />
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase border ${style.badge}`}>
                      {style.label}
                    </span>
                    {matchingEvent?.severity && (
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEVERITY_COLORS[matchingEvent.severity] || ''}`}>
                        {matchingEvent.severity}
                      </span>
                    )}
                    {br && Number(br.resource_count) > 0 && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-50 text-purple-600">
                        {String(br.resource_count)} resources at risk
                      </span>
                    )}
                  </div>
                  <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 ml-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
                    {delta.change_type === 'modified' && (
                      <>
                        <span className="font-medium" style={{ color: 'var(--text-primary)' }}>Previous Role</span>
                        <span className="text-red-600 font-medium">{delta.previous_role}</span>
                        <span className="font-medium" style={{ color: 'var(--text-primary)' }}>New Role</span>
                        <span className="text-green-600 font-medium">{delta.new_role}</span>
                      </>
                    )}
                    {delta.change_type === 'added' && (
                      <>
                        <span className="font-medium" style={{ color: 'var(--text-primary)' }}>New Role</span>
                        <span className="text-green-600 font-medium">{delta.new_role}</span>
                      </>
                    )}
                    {delta.change_type === 'removed' && (
                      <>
                        <span className="font-medium" style={{ color: 'var(--text-primary)' }}>Previous Role</span>
                        <span className="text-red-600 font-medium">{delta.previous_role}</span>
                      </>
                    )}
                    <span className="font-medium" style={{ color: 'var(--text-primary)' }}>Scope</span>
                    <span className="font-mono text-[11px] truncate" title={delta.scope}>{delta.scope || 'N/A'}</span>
                    {delta.scope_type && (
                      <>
                        <span className="font-medium" style={{ color: 'var(--text-primary)' }}>Scope Type</span>
                        <span>{delta.scope_type.replace(/_/g, ' ')}</span>
                      </>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        );
      })}
    </div>
  );
}

function RiskChangesSection({ items }: { items: FullDriftReport['changes']['risk_changes'] }) {
  return (
    <div className="space-y-2">
      {items.map((item, i) => (
        <div key={item.identity?.identity_id || i}>
          <div className="flex items-center gap-3 text-sm">
            <span className={item.severity === 'escalation' ? 'text-red-500' : 'text-green-500'}>
              {item.severity === 'escalation' ? '\u2191' : '\u2193'}
            </span>
            <IdentityLink identity={item.identity} />
            {riskBadge(item.previous_risk)}
            <span className="text-gray-400">{'\u2192'}</span>
            {riskBadge(item.current_risk)}
          </div>
          {!!item.change_reason && (
            <div className="ml-5 mt-0.5 text-xs text-gray-500 italic">{item.change_reason}</div>
          )}
        </div>
      ))}
    </div>
  );
}

function CredentialChangesSection({ items }: { items: FullDriftReport['changes']['credential_changes'] }) {
  return (
    <div className="space-y-2">
      {items.map((item, i) => (
        <div key={item.identity?.identity_id || i}>
          <div className="flex items-center gap-3 text-sm">
            <span className="text-yellow-600">*</span>
            <IdentityLink identity={item.identity} />
            <span className="text-xs text-gray-500">{item.previous_status}</span>
            <span className="text-gray-400">{'\u2192'}</span>
            <span className="text-xs font-medium text-yellow-700">{item.current_status}</span>
          </div>
          {!!item.change_reason && (
            <div className="ml-5 mt-0.5 text-xs text-gray-500 italic">{item.change_reason}</div>
          )}
        </div>
      ))}
    </div>
  );
}

function ClassificationChangesSection({ items }: { items: NonNullable<FullDriftReport['changes']['classification_changes']> }) {
  const CLASS_COLORS: Record<string, string> = {
    PHI: 'text-red-600 bg-red-50',
    PCI: 'text-amber-600 bg-amber-50',
    PII: 'text-blue-600 bg-blue-50',
  };
  return (
    <div className="space-y-2">
      {items.map((item, i) => (
        <div key={item.resource_id || i} className="flex items-center gap-3 text-sm">
          <span className={`font-mono font-bold ${
            item.change_type === 'classified' ? 'text-cyan-600' :
            item.change_type === 'declassified' ? 'text-gray-500' : 'text-cyan-700'
          }`}>
            {item.change_type === 'classified' ? '+' : item.change_type === 'declassified' ? '-' : '~'}
          </span>
          <span className="font-medium" style={{ color: 'var(--text-primary)' }}>{item.resource_name}</span>
          <span className="text-xs px-1.5 py-0.5 rounded bg-gray-100 text-gray-600">
            {(item.resource_type || '').replace(/_/g, ' ')}
          </span>
          {item.previous_classification && (
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${CLASS_COLORS[item.previous_classification] || 'text-gray-500 bg-gray-50'}`}>
              {item.previous_classification}
            </span>
          )}
          {item.previous_classification && item.new_classification && (
            <span style={{ color: 'var(--text-secondary)' }}>{'\u2192'}</span>
          )}
          {item.new_classification && (
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${CLASS_COLORS[item.new_classification] || 'text-gray-500 bg-gray-50'}`}>
              {item.new_classification}
            </span>
          )}
          {!item.new_classification && item.change_type === 'declassified' && (
            <span className="text-xs text-gray-400 italic">removed</span>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Intel Card ──────────────────────────────────────────────

function IntelCard({ label, value, badgeClass, isBadge }: {
  label: string;
  value: string | number;
  badgeClass: string;
  isBadge?: boolean;
}) {
  return (
    <div className="flex flex-col items-center gap-1 min-w-[80px]">
      <span className="text-[10px] font-medium text-gray-500 uppercase tracking-wide">{label}</span>
      {isBadge ? (
        <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${badgeClass}`}>
          {value}
        </span>
      ) : (
        <span className={`text-lg font-bold px-2 py-0.5 rounded ${badgeClass}`}>
          {value}
        </span>
      )}
    </div>
  );
}

// ── Snapshot Compare Helpers ────────────────────────────────

function CompareCard({ label, sublabel, value, detail, color }: {
  label: string; sublabel: string; value: string; detail: string; color?: string;
}) {
  return (
    <div className="rounded-lg border p-3" style={{ backgroundColor: 'var(--bg-primary)', borderColor: 'var(--border-default)' }}>
      <div className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>{label}</div>
      <div className={`text-xl font-bold mt-0.5 ${color || ''}`} style={color ? {} : { color: 'var(--text-primary)' }}>{value}</div>
      <div className="text-[10px] mt-0.5" style={{ color: 'var(--text-secondary)' }}>
        {sublabel}{detail ? ` \u00b7 ${detail}` : ''}
      </div>
    </div>
  );
}

function RiskDistCard({ title, dist }: { title: string; dist: Record<string, number> }) {
  if (!dist) return null;
  const total = Object.values(dist).reduce((a, b) => a + b, 0);
  return (
    <div className="rounded-lg border p-3" style={{ backgroundColor: 'var(--bg-primary)', borderColor: 'var(--border-default)' }}>
      <div className="text-xs font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>{title} Risk Distribution ({total})</div>
      <div className="flex gap-2">
        {(['critical', 'high', 'medium', 'low', 'info'] as const).map(level => {
          const count = dist[level] || 0;
          if (!count) return null;
          const colors: Record<string, string> = {
            critical: 'bg-red-100 text-red-700',
            high: 'bg-orange-100 text-orange-700',
            medium: 'bg-yellow-100 text-yellow-700',
            low: 'bg-blue-100 text-blue-700',
            info: 'bg-gray-100 text-gray-600',
          };
          return (
            <span key={level} className={`px-2 py-0.5 rounded text-xs font-medium ${colors[level]}`}>
              {level} {count}
            </span>
          );
        })}
      </div>
    </div>
  );
}
