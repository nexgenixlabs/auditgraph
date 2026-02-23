import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useToast } from '../components/ToastProvider';
import { useConnection } from '../contexts/ConnectionContext';

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
  changes: {
    new_identities: IdentityData[];
    removed_identities: IdentityData[];
    microsoft_removed_identities?: IdentityData[];
    permission_changes: Array<{
      identity: IdentityData;
      added_roles: string[];
      removed_roles: string[];
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
  const [expandedRunId, setExpandedRunId] = useState<number | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [detail, setDetail] = useState<FullDriftReport | null>(null);

  // Collapsible sections in detail view
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
    new_identities: true,
    removed_identities: true,
    microsoft_removed_identities: false,
    permission_changes: true,
    risk_changes: true,
    credential_changes: true,
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

  async function toggleRow(runId: number) {
    if (expandedRunId === runId) {
      setExpandedRunId(null);
      setDetail(null);
      return;
    }

    setExpandedRunId(runId);
    setDetailLoading(true);
    setDetailError(null);
    setDetail(null);

    try {
      const res = await fetch(withConnection(`/api/runs/${runId}/drift`));
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

  // Summary stats
  const totalReports = reports.length;
  const totalChanges = reports.reduce((sum, r) => sum + r.total_changes, 0);

  function exportCsv() {
    const header = ['Report ID', 'Current Run', 'Previous Run', 'Date', 'Total Changes', 'New', 'Removed', 'Permissions', 'Risk', 'Credentials'];
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
        <div className="animate-pulse space-y-6">
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
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Drift History</h2>
        <p className="text-sm text-gray-600 mt-1">
          Timeline of identity changes across discovery runs
        </p>
      </div>

      {/* Empty state */}
      {reports.length === 0 ? (
        <div className="bg-white border rounded-xl p-12 text-center">
          <svg className="w-12 h-12 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          <div className="text-gray-500 font-medium">No drift reports yet</div>
          <div className="text-sm text-gray-400 mt-1">
            Drift data becomes available after 2+ discovery runs
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
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-gray-50 border-b text-left">
                  <th className="px-4 py-3 font-medium text-gray-600 w-8" />
                  <th className="px-4 py-3 font-medium text-gray-600">Run Comparison</th>
                  <th className="px-4 py-3 font-medium text-gray-600">Date</th>
                  <th className="px-4 py-3 font-medium text-gray-600 text-center">Total</th>
                  <th className="px-4 py-3 font-medium text-green-700 text-center">New</th>
                  <th className="px-4 py-3 font-medium text-red-700 text-center">Removed</th>
                  <th className="px-4 py-3 font-medium text-orange-700 text-center">Perms</th>
                  <th className="px-4 py-3 font-medium text-purple-700 text-center">Risk</th>
                  <th className="px-4 py-3 font-medium text-yellow-700 text-center">Creds</th>
                </tr>
              </thead>
              <tbody>
                {reports.map(report => (
                  <React.Fragment key={report.id}>
                    <tr
                      onClick={() => toggleRow(report.current_run_id)}
                      className={`border-b cursor-pointer transition hover:bg-gray-50 ${
                        expandedRunId === report.current_run_id ? 'bg-blue-50' : ''
                      }`}
                    >
                      <td className="px-4 py-3 text-gray-400">
                        <svg
                          className={`w-4 h-4 transition-transform ${
                            expandedRunId === report.current_run_id ? 'rotate-90' : ''
                          }`}
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs text-gray-700">
                          Run #{report.current_run_id} vs #{report.previous_run_id}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-gray-600">
                        {report.run_completed_at
                          ? new Date(report.run_completed_at).toLocaleString()
                          : new Date(report.created_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-center">
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
                      <CountCell count={report.new_identities_count} color="text-green-600" />
                      <CountCell count={report.removed_identities_count} color="text-red-600" />
                      <CountCell count={report.permission_changes_count} color="text-orange-600" />
                      <CountCell count={report.risk_changes_count} color="text-purple-600" />
                      <CountCell count={report.credential_changes_count} color="text-yellow-700" />
                    </tr>

                    {/* Expanded detail row */}
                    {expandedRunId === report.current_run_id && (
                      <tr>
                        <td colSpan={9} className="bg-gray-50 px-6 py-4">
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
    <td className="px-4 py-3 text-center">
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
  ];

  const nonEmpty = sections.filter(s => s.count > 0);

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
                <NewIdentitiesSection items={detail.changes.new_identities} />
              )}
              {section.key === 'removed_identities' && (
                <RemovedIdentitiesSection items={detail.changes.removed_identities} />
              )}
              {section.key === 'microsoft_removed_identities' && (
                <MicrosoftRemovedSection items={detail.changes.microsoft_removed_identities || []} />
              )}
              {section.key === 'permission_changes' && (
                <PermissionChangesSection items={detail.changes.permission_changes} />
              )}
              {section.key === 'risk_changes' && (
                <RiskChangesSection items={detail.changes.risk_changes} />
              )}
              {section.key === 'credential_changes' && (
                <CredentialChangesSection items={detail.changes.credential_changes} />
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

function NewIdentitiesSection({ items }: { items: IdentityData[] }) {
  return (
    <div className="space-y-2">
      {items.map((item, i) => (
        <div key={item.identity_id || i}>
          <div className="flex items-center gap-3 text-sm">
            <span className="text-green-600 font-mono font-bold">+</span>
            <IdentityLink identity={item} />
            <span className="text-gray-400">·</span>
            <span className="text-xs text-gray-500">{categoryLabel(item.identity_category)}</span>
            {riskBadge(item.risk_level)}
          </div>
          {!!item.change_reason && (
            <div className="ml-5 mt-0.5 text-xs text-gray-500 italic">{item.change_reason}</div>
          )}
        </div>
      ))}
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
            <div className="ml-5 mt-0.5 text-xs text-gray-500 italic">{item.change_reason}</div>
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

function PermissionChangesSection({ items }: { items: FullDriftReport['changes']['permission_changes'] }) {
  return (
    <div className="space-y-3">
      {items.map((item, i) => (
        <div key={item.identity?.identity_id || i} className="text-sm">
          <div className="flex items-center gap-2 mb-1">
            <IdentityLink identity={item.identity} />
          </div>
          <div className="ml-5 space-y-0.5">
            {item.added_roles.map((role, j) => (
              <div key={`add-${j}`} className="flex items-center gap-2 text-xs">
                <span className="text-green-600 font-mono">+</span>
                <span className="text-green-700">{role}</span>
              </div>
            ))}
            {item.removed_roles.map((role, j) => (
              <div key={`rem-${j}`} className="flex items-center gap-2 text-xs">
                <span className="text-red-600 font-mono">-</span>
                <span className="text-red-700">{role}</span>
              </div>
            ))}
          </div>
        </div>
      ))}
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
