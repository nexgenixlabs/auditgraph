import React, { useEffect, useState, useCallback } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import { useToast } from '../components/ToastProvider';
import {
  STATUS_CONFIG,
  statusBadgeClasses,
  severityBadgeClasses,
  statusLabel,
  severityLabel,
} from '../constants/remediation';
import { verdictBadgeClasses, verdictLabel } from '../constants/verdicts';
import type { RemediationItem, RemediationStatus } from '../types/remediation';

export default function RemediationDetail() {
  const { itemId } = useParams<{ itemId: string }>();
  const navigate = useNavigate();
  const { withConnection } = useConnection();
  const { addToast } = useToast();

  const [item, setItem] = useState<RemediationItem | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Status update form
  const [newStatus, setNewStatus] = useState<RemediationStatus | ''>('');
  const [notes, setNotes] = useState('');
  const [assignee, setAssignee] = useState('');
  const [updating, setUpdating] = useState(false);
  const [transitionError, setTransitionError] = useState<string | null>(null);

  const fetchItem = useCallback(async () => {
    if (!itemId) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(withConnection(`/api/remediation-queue/${itemId}`));
      if (!res.ok) throw new Error(res.status === 404 ? 'Item not found' : 'Failed to load');
      setItem(await res.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  }, [itemId, withConnection]);

  useEffect(() => { fetchItem(); }, [fetchItem]);

  async function handleUpdate() {
    if (!item || !newStatus) return;

    // Require notes when resolving
    if (newStatus === 'resolved' && !notes.trim()) {
      setTransitionError('Resolution notes are required when marking as Resolved.');
      return;
    }

    setUpdating(true);
    setTransitionError(null);
    try {
      const body: Record<string, unknown> = { status: newStatus };
      if (notes.trim()) body.resolution_notes = notes.trim();
      if (assignee.trim()) body.assigned_to = assignee.trim();

      const res = await fetch(`/api/remediation-queue/${item.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (res.status === 422) {
        const err = await res.json();
        setTransitionError(err.error || 'Invalid status transition');
        return;
      }
      if (!res.ok) throw new Error('Failed to update');

      const updated = await res.json();
      setItem(updated);
      setNewStatus('');
      setNotes('');
      addToast(`Status updated to ${statusLabel(updated.status)}`, 'success');
    } catch (e) {
      addToast(e instanceof Error ? e.message : 'Update failed', 'error');
    } finally {
      setUpdating(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="animate-spin h-8 w-8 border-2 border-blue-600 border-t-transparent rounded-full" />
      </div>
    );
  }

  if (error || !item) {
    return (
      <div className="p-6 max-w-[1000px] mx-auto">
        <Link to="/remediation-queue" className="text-sm text-blue-500 hover:underline">&larr; Back to Queue</Link>
        <div className="mt-8 text-center py-16 rounded-xl border" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{error || 'Item not found'}</p>
        </div>
      </div>
    );
  }

  const nextStatuses = STATUS_CONFIG[item.status]?.nextStatuses ?? [];

  return (
    <div className="p-6 max-w-[1100px] mx-auto">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 mb-5">
        <Link to="/remediation-queue" className="text-sm hover:underline" style={{ color: 'var(--text-secondary)' }}>
          &larr; Remediation Queue
        </Link>
        <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>/</span>
        <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>Item #{item.id}</span>
      </div>

      {/* Header */}
      <div className="flex items-start gap-3 mb-5">
        <h1 className="text-lg font-bold flex-1" style={{ color: 'var(--text-primary)' }}>{item.title}</h1>
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${severityBadgeClasses(item.severity)}`}>
          {severityLabel(item.severity)}
        </span>
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${statusBadgeClasses(item.status)}`}>
          {statusLabel(item.status)}
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left Column */}
        <div className="lg:col-span-2 space-y-5">
          {/* Identity Card */}
          {item.identity_display_name && (
            <div className="rounded-xl border p-5" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
              <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-tertiary)' }}>
                Identity
              </h3>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{item.identity_display_name}</p>
                  {item.identity_principal_type && (
                    <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>{item.identity_principal_type}</p>
                  )}
                  {item.identity_lineage_verdict && (
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium mt-2 ${verdictBadgeClasses(item.identity_lineage_verdict)}`}>
                      {verdictLabel(item.identity_lineage_verdict)}
                    </span>
                  )}
                </div>
                {item.identity_id && (
                  <button
                    onClick={() => navigate(`/identities/${item.identity_id}`)}
                    className="text-xs px-3 py-1.5 rounded-lg border transition-colors hover:bg-[var(--bg-elevated)]"
                    style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-default)' }}
                  >
                    View Identity &rarr;
                  </button>
                )}
              </div>
            </div>
          )}

          {/* Attack Path Card */}
          {item.path_summary && (
            <div className="rounded-xl border p-5" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
              <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-tertiary)' }}>
                Attack Path
              </h3>
              <p className="text-sm" style={{ color: 'var(--text-primary)' }}>{item.path_summary}</p>
              {item.attack_path_score != null && (
                <div className="flex items-center gap-2 mt-2">
                  <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>Risk Score:</span>
                  <span className="font-mono text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                    {item.attack_path_score}
                  </span>
                </div>
              )}
              {item.attack_path_id && (
                <button
                  onClick={() => navigate(`/attack-paths/${item.attack_path_id}`)}
                  className="text-xs px-3 py-1.5 rounded-lg border transition-colors hover:bg-[var(--bg-elevated)] mt-3"
                  style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-default)' }}
                >
                  View Attack Path &rarr;
                </button>
              )}
            </div>
          )}

          {/* Description / Notes */}
          {(item.description || item.resolution_notes) && (
            <div className="rounded-xl border p-5" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
              <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-tertiary)' }}>
                Details
              </h3>
              {item.description && (
                <p className="text-sm mb-3" style={{ color: 'var(--text-primary)' }}>{item.description}</p>
              )}
              {item.resolution_notes && (
                <div className="pt-3 border-t" style={{ borderColor: 'var(--border-subtle)' }}>
                  <span className="text-xs font-semibold" style={{ color: 'var(--text-tertiary)' }}>Resolution Notes: </span>
                  <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{item.resolution_notes}</span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Column */}
        <div className="space-y-5">
          {/* Status Update Panel */}
          <div className="rounded-xl border p-5" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
            <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-tertiary)' }}>
              Update Status
            </h3>

            {/* Current status */}
            <div className="mb-4">
              <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>Current:</span>
              <span className={`ml-2 inline-flex items-center px-2.5 py-1 rounded text-sm font-medium ${statusBadgeClasses(item.status)}`}>
                {statusLabel(item.status)}
              </span>
            </div>

            {nextStatuses.length > 0 ? (
              <>
                {/* Status select */}
                <label className="block text-xs mb-1" style={{ color: 'var(--text-tertiary)' }}>Transition to</label>
                <select
                  value={newStatus}
                  onChange={e => { setNewStatus(e.target.value as RemediationStatus); setTransitionError(null); }}
                  className="w-full text-sm rounded-lg border px-3 py-2 mb-3 bg-transparent"
                  style={{ color: 'var(--text-primary)', borderColor: 'var(--border-default)' }}
                >
                  <option value="">Select status...</option>
                  {nextStatuses.map(s => (
                    <option key={s} value={s}>{statusLabel(s)}</option>
                  ))}
                </select>

                {/* Resolution notes */}
                <label className="block text-xs mb-1" style={{ color: 'var(--text-tertiary)' }}>
                  Resolution Notes {newStatus === 'resolved' && <span className="text-red-500">*</span>}
                </label>
                <textarea
                  value={notes}
                  onChange={e => { setNotes(e.target.value); setTransitionError(null); }}
                  rows={3}
                  placeholder={newStatus === 'resolved' ? 'Required for resolved status...' : 'Optional notes...'}
                  className="w-full text-sm rounded-lg border px-3 py-2 mb-3 bg-transparent resize-none"
                  style={{ color: 'var(--text-primary)', borderColor: 'var(--border-default)' }}
                />

                {/* Assignee */}
                <label className="block text-xs mb-1" style={{ color: 'var(--text-tertiary)' }}>Assigned To</label>
                <input
                  type="text"
                  value={assignee}
                  onChange={e => setAssignee(e.target.value)}
                  placeholder={item.assigned_to || 'email or name'}
                  className="w-full text-sm rounded-lg border px-3 py-2 mb-3 bg-transparent"
                  style={{ color: 'var(--text-primary)', borderColor: 'var(--border-default)' }}
                />

                {/* Transition error (inline, not toast) */}
                {transitionError && (
                  <div className="text-xs text-red-600 mb-3 p-2 rounded bg-red-50 border border-red-200">
                    {transitionError}
                  </div>
                )}

                <button
                  onClick={handleUpdate}
                  disabled={!newStatus || updating}
                  className="w-full text-sm font-medium px-4 py-2 rounded-lg transition-colors disabled:opacity-50"
                  style={{
                    backgroundColor: newStatus ? '#15306A' : 'var(--bg-elevated)',
                    color: newStatus ? '#fff' : 'var(--text-tertiary)',
                  }}
                >
                  {updating ? 'Updating...' : 'Update Status'}
                </button>
              </>
            ) : (
              <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>No further transitions available.</p>
            )}
          </div>

          {/* Priority Score */}
          <div className="rounded-xl border p-5" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
            <h3 className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-tertiary)' }}>
              Priority Score
            </h3>
            <span className="text-3xl font-bold font-mono" style={{ color: 'var(--text-primary)' }}>
              {item.priority_score ?? '\u2014'}
            </span>
          </div>

          {/* Timeline */}
          <div className="rounded-xl border p-5" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
            <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-tertiary)' }}>
              Timeline
            </h3>
            <div className="space-y-2.5">
              <InfoRow label="Created by" value={item.created_by} />
              <InfoRow label="Created at" value={new Date(item.created_at).toLocaleString()} />
              <InfoRow label="Updated at" value={new Date(item.updated_at).toLocaleString()} />
              {item.resolved_at && (
                <InfoRow label="Resolved at" value={new Date(item.resolved_at).toLocaleString()} />
              )}
              {item.assigned_to && (
                <InfoRow label="Assigned to" value={item.assigned_to} />
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span style={{ color: 'var(--text-tertiary)' }}>{label}</span>
      <span className="font-medium" style={{ color: 'var(--text-primary)' }}>{value}</span>
    </div>
  );
}
