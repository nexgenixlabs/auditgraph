import React, { useState, useEffect } from 'react';
import { useConnection } from '../../contexts/ConnectionContext';

interface SnapshotContextHeaderProps {
  /** Snapshot/run ID — if provided, skips fetch */
  snapshotId?: number | string | null;
  /** Snapshot completion date — if provided, skips fetch */
  snapshotDate?: string | null;
}

function formatSnapshotDate(dateStr: string): string {
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch {
    return dateStr;
  }
}

export function SnapshotContextHeader({ snapshotId, snapshotDate }: SnapshotContextHeaderProps) {
  const { withConnection } = useConnection();
  const [autoId, setAutoId] = useState<number | null>(null);
  const [autoDate, setAutoDate] = useState<string | null>(null);

  const id = snapshotId ?? autoId;
  const date = snapshotDate ?? autoDate;

  useEffect(() => {
    if (snapshotId != null && snapshotDate != null) return;
    let cancelled = false;
    fetch(withConnection('/api/stats'))
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (cancelled || !data?.latest_run) return;
        if (snapshotId == null) setAutoId(data.latest_run.id);
        if (snapshotDate == null) setAutoDate(data.latest_run.completed_at);
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [snapshotId, snapshotDate, withConnection]);

  if (!id && !date) return null;

  return (
    <div className="flex items-center gap-2">
      <p className="text-xs text-gray-500">
        Data as of {date ? formatSnapshotDate(date) : 'latest snapshot'}
        {id ? ` · Snapshot #${id}` : ''}
      </p>
      <span
        className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-700 text-[9px] font-semibold uppercase tracking-wide"
        title="Snapshot data is immutable — it reflects the state at capture time"
      >
        <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
        Immutable
      </span>
    </div>
  );
}
