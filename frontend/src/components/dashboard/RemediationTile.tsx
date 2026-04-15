import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../../contexts/ConnectionContext';
import type { RemediationSummary } from '../../types/remediation';
import { statusLabel, severityLabel } from '../../constants/remediation';

export default function RemediationTile() {
  const navigate = useNavigate();
  const { withConnection } = useConnection();
  const [data, setData] = useState<RemediationSummary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(withConnection('/api/remediation-queue/summary'))
      .then(r => r.ok ? r.json() : null)
      .then(setData)
      .finally(() => setLoading(false));
  }, [withConnection]);

  if (loading) {
    return (
      <div className="rounded-xl border p-5" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
        <div className="animate-pulse space-y-3">
          <div className="h-4 bg-gray-200 rounded w-1/3" />
          <div className="h-8 bg-gray-200 rounded w-1/4" />
        </div>
      </div>
    );
  }

  if (!data || data.total === 0) return null;

  const criticalCount = data.by_severity.CRITICAL ?? 0;

  return (
    <div
      className="rounded-xl border p-5 cursor-pointer transition-colors hover:bg-[var(--bg-elevated)]"
      style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}
      onClick={() => navigate('/remediation-queue')}
    >
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>
          Remediation Queue
        </h3>
        <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>View All &rarr;</span>
      </div>

      <div className="space-y-2">
        <MetricRow label={statusLabel('open')} value={data.by_status.open} color="#3b82f6" total={data.total} />
        <MetricRow label={statusLabel('in_progress')} value={data.by_status.in_progress} color="#eab308" total={data.total} />
        <MetricRow label={statusLabel('resolved')} value={data.by_status.resolved} color="#22c55e" total={data.total} />
        <MetricRow label={statusLabel('dismissed')} value={data.by_status.dismissed} color="#6b7280" total={data.total} />
      </div>

      {criticalCount > 0 && (
        <div className="mt-3 pt-3 border-t flex items-center gap-2" style={{ borderColor: 'var(--border-subtle)' }}>
          <span className="w-2 h-2 rounded-full bg-red-500 flex-shrink-0" />
          <span className="text-xs font-medium" style={{ color: '#ef4444' }}>
            {criticalCount} {severityLabel('CRITICAL')} item{criticalCount !== 1 ? 's' : ''}
          </span>
        </div>
      )}

      {data.avg_resolution_days != null && (
        <div className="mt-2 text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
          Avg resolution: {data.avg_resolution_days} day{data.avg_resolution_days !== 1 ? 's' : ''}
        </div>
      )}
    </div>
  );
}

function MetricRow({ label, value, color, total }: { label: string; value: number; color: string; total: number }) {
  const barPct = total > 0 ? Math.round((value / total) * 100) : 0;
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: color }} />
      <span className="flex-1" style={{ color: 'var(--text-secondary)' }}>{label}</span>
      <span className="font-mono font-semibold w-8 text-right" style={{ color: 'var(--text-primary)' }}>{value}</span>
      <div className="w-12 h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-elevated)' }}>
        <div className="h-full rounded-full" style={{ width: `${barPct}%`, backgroundColor: color }} />
      </div>
    </div>
  );
}
