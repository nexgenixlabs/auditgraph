import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useRemediationQueue } from '../hooks/useRemediationQueue';
import { useToast } from '../components/ToastProvider';
import {
  STATUS_CONFIG,
  SEVERITY_CONFIG,
  statusBadgeClasses,
  severityBadgeClasses,
  statusLabel,
  severityLabel,
} from '../constants/remediation';
import type { RemediationStatus, RemediationSeverity, RemediationItem } from '../types/remediation';

const ALL_STATUSES: RemediationStatus[] = ['open', 'in_progress', 'resolved', 'dismissed'];
const ALL_SEVERITIES: RemediationSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export default function RemediationQueue() {
  const navigate = useNavigate();
  const { addToast } = useToast();
  const {
    items, summary, total, loading, error,
    filters, setFilters, updateStatus, loadMore, hasMore,
  } = useRemediationQueue();

  const [transitioning, setTransitioning] = useState<number | null>(null);

  const openCount = summary?.by_status?.open ?? 0;

  async function handleTransition(item: RemediationItem, newStatus: RemediationStatus) {
    setTransitioning(item.id);
    try {
      await updateStatus(item.id, newStatus);
      addToast(`Updated to ${statusLabel(newStatus)}`, 'success');
    } catch (e) {
      addToast(e instanceof Error ? e.message : 'Failed to update', 'error');
    } finally {
      setTransitioning(null);
    }
  }

  return (
    <div className="p-6 max-w-[1200px] mx-auto">
      {/* Header */}
      <div className="mb-5">
        <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>
          Remediation Queue
        </h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
          {openCount} open item{openCount !== 1 ? 's' : ''} requiring action
        </p>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
          {ALL_STATUSES.map(s => (
            <button
              key={s}
              onClick={() => setFilters({ ...filters, status: filters.status === s ? undefined : s })}
              className="rounded-xl border p-4 text-left transition-colors hover:bg-[var(--bg-elevated)]"
              style={{
                borderColor: filters.status === s ? 'var(--text-primary)' : 'var(--border-default)',
                backgroundColor: 'var(--bg-primary)',
              }}
            >
              <span className="text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>
                {statusLabel(s as RemediationStatus)}
              </span>
              <div className="text-2xl font-bold font-mono mt-1" style={{ color: 'var(--text-primary)' }}>
                {summary.by_status[s] ?? 0}
              </div>
            </button>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2 mb-4">
        <span className="text-xs font-medium" style={{ color: 'var(--text-tertiary)' }}>Severity:</span>
        {ALL_SEVERITIES.map(sev => (
          <button
            key={sev}
            onClick={() => setFilters({ ...filters, severity: filters.severity === sev ? undefined : sev })}
            className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
              filters.severity === sev
                ? severityBadgeClasses(sev)
                : ''
            }`}
            style={
              filters.severity !== sev
                ? { color: 'var(--text-secondary)', backgroundColor: 'var(--bg-elevated)' }
                : undefined
            }
          >
            {severityLabel(sev)}
          </button>
        ))}

        {(filters.status || filters.severity) && (
          <button
            onClick={() => setFilters({})}
            className="text-xs px-2 py-1 rounded hover:underline"
            style={{ color: 'var(--text-secondary)' }}
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="rounded-lg border border-red-300 bg-red-50 p-3 mb-4 text-sm text-red-700">
          {error}
        </div>
      )}

      {/* Loading */}
      {loading && items.length === 0 && (
        <div className="rounded-xl border p-8 text-center" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
          <div className="animate-spin h-6 w-6 border-2 border-blue-600 border-t-transparent rounded-full mx-auto" />
          <p className="text-xs mt-3" style={{ color: 'var(--text-tertiary)' }}>Loading queue...</p>
        </div>
      )}

      {/* Empty State */}
      {!loading && items.length === 0 && (
        <div className="rounded-xl border p-12 text-center" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
          <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
            {filters.status || filters.severity ? 'No items match the current filters' : 'No items in the remediation queue'}
          </p>
          <p className="text-xs mt-2" style={{ color: 'var(--text-tertiary)' }}>
            {filters.status || filters.severity
              ? 'Try adjusting filters or clearing them.'
              : 'Add attack paths to the remediation queue from the Attack Paths page.'}
          </p>
        </div>
      )}

      {/* Table */}
      {items.length > 0 && (
        <div className="rounded-xl border overflow-hidden" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b" style={{ borderColor: 'var(--border-default)' }}>
                  {['Severity', 'Title', 'Identity', 'Score', 'Status', 'Assigned To', 'Created', 'Actions'].map(h => (
                    <th key={h} className="text-left text-xs font-semibold uppercase tracking-wider px-4 py-3"
                      style={{ color: 'var(--text-tertiary)' }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.map(item => (
                  <tr
                    key={item.id}
                    className="border-b cursor-pointer transition-colors hover:bg-[var(--bg-elevated)]"
                    style={{ borderColor: 'var(--border-subtle)' }}
                    onClick={() => navigate(`/remediation-queue/${item.id}`)}
                  >
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${severityBadgeClasses(item.severity)}`}>
                        {severityLabel(item.severity)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-medium text-sm" style={{ color: 'var(--text-primary)' }}>{item.title}</span>
                    </td>
                    <td className="px-4 py-3">
                      {item.identity_display_name ? (
                        <div>
                          <span className="text-sm" style={{ color: 'var(--text-primary)' }}>{item.identity_display_name}</span>
                          {item.identity_principal_type && (
                            <span className="text-xs ml-1.5" style={{ color: 'var(--text-tertiary)' }}>
                              ({item.identity_principal_type})
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>&mdash;</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-mono text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                        {item.priority_score != null ? item.priority_score : item.attack_path_score ?? '\u2014'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${statusBadgeClasses(item.status)}`}>
                        {statusLabel(item.status)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                        {item.assigned_to || '\u2014'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
                        {new Date(item.created_at).toLocaleDateString()}
                      </span>
                    </td>
                    <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                      <StatusDropdown
                        item={item}
                        disabled={transitioning === item.id}
                        onSelect={s => handleTransition(item, s)}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {hasMore && (
            <div className="flex justify-center py-3 border-t" style={{ borderColor: 'var(--border-default)' }}>
              <button
                onClick={loadMore}
                disabled={loading}
                className="text-xs font-medium px-4 py-2 rounded-lg border transition-colors hover:bg-[var(--bg-elevated)]"
                style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-default)' }}
              >
                {loading ? 'Loading...' : `Load more (${items.length} of ${total})`}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}


function StatusDropdown({
  item,
  disabled,
  onSelect,
}: {
  item: RemediationItem;
  disabled: boolean;
  onSelect: (s: RemediationStatus) => void;
}) {
  const nextStatuses = STATUS_CONFIG[item.status]?.nextStatuses ?? [];
  if (nextStatuses.length === 0) return null;

  return (
    <select
      disabled={disabled}
      className="text-xs rounded border px-2 py-1 bg-transparent"
      style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-default)' }}
      value=""
      onChange={e => {
        if (e.target.value) onSelect(e.target.value as RemediationStatus);
      }}
    >
      <option value="">Move to...</option>
      {nextStatuses.map(s => (
        <option key={s} value={s}>{statusLabel(s)}</option>
      ))}
    </select>
  );
}
