import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../../contexts/ConnectionContext';

interface SurfaceData {
  total_paths: number;
  critical_paths: number;
  high_paths: number;
  subscription_scope_paths: number;
  keyvault_exposure_paths: number;
}

export default function AttackSurfaceTile() {
  const navigate = useNavigate();
  const { withConnection } = useConnection();
  const [data, setData] = useState<SurfaceData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`/api/dashboard/attack-surface?${withConnection('')}`)
      .then(r => r.ok ? r.json() : null)
      .then(setData)
      .finally(() => setLoading(false));
  }, [withConnection]);

  if (loading) {
    return (
      <div className="bg-white border rounded-xl p-5" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
        <div className="animate-pulse space-y-3">
          <div className="h-4 bg-gray-200 rounded w-1/3" />
          <div className="h-8 bg-gray-200 rounded w-1/4" />
        </div>
      </div>
    );
  }

  if (!data) return null;

  const critPct = data.total_paths > 0 ? Math.round((data.critical_paths / data.total_paths) * 100) : 0;

  return (
    <div className="rounded-xl border p-5 cursor-pointer transition-colors hover:bg-[var(--bg-elevated)]"
      style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}
      onClick={() => navigate('/attack-paths')}>
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>
          Attack Surface
        </h3>
        <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>View All &rarr;</span>
      </div>

      <div className="flex items-baseline gap-2 mb-4">
        <span className="text-2xl font-bold font-mono" style={{ color: data.total_paths > 0 ? '#ef4444' : 'var(--text-tertiary)' }}>
          {data.total_paths}
        </span>
        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>attack paths</span>
      </div>

      <div className="space-y-2">
        <MetricRow label="Critical" value={data.critical_paths} color="#ef4444" pct={critPct} total={data.total_paths} />
        <MetricRow label="High" value={data.high_paths} color="#f97316" total={data.total_paths} />
        <MetricRow label="Sub Scope" value={data.subscription_scope_paths} color="#8b5cf6" total={data.total_paths} />
        <MetricRow label="KV Exposure" value={data.keyvault_exposure_paths} color="#0891b2" total={data.total_paths} />
      </div>
    </div>
  );
}

function MetricRow({ label, value, color, pct, total }: {
  label: string; value: number; color: string; pct?: number; total: number;
}) {
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
