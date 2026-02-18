import React from 'react';
import { Link } from 'react-router-dom';
import { COLORS } from '../../constants/design';

interface DataIntegrity {
  last_scan: string | null;
  total_scanned: number;
  data_completeness_pct: number;
  scan_duration_seconds: number | null;
}

interface DataIntegrityFooterProps {
  dataIntegrity?: DataIntegrity;
}

export default function DataIntegrityFooter({ dataIntegrity }: DataIntegrityFooterProps) {
  if (!dataIntegrity) return null;

  const formatDuration = (seconds: number | null) => {
    if (seconds == null) return '—';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  };

  const formatTime = (iso: string | null) => {
    if (!iso) return '—';
    return new Date(iso).toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  };

  return (
    <div
      className="rounded-xl px-6 py-3 flex items-center justify-between flex-wrap gap-4"
      style={{ backgroundColor: 'var(--bg-secondary)', border: `1px solid ${COLORS.border}` }}
    >
      <div className="flex items-center gap-6 flex-wrap">
        <Stat label="Last Scan" value={formatTime(dataIntegrity.last_scan)} />
        <Stat label="Total Scanned" value={String(dataIntegrity.total_scanned)} />
        <Stat label="Data Completeness" value={`${Math.round(dataIntegrity.data_completeness_pct)}%`} />
        <Stat label="Scan Duration" value={formatDuration(dataIntegrity.scan_duration_seconds)} />
      </div>
      <Link
        to="/activity"
        className="text-[12px] font-medium hover:underline transition"
        style={{ color: COLORS.brandLight }}
      >
        View Activity Log →
      </Link>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[9px] uppercase tracking-wider" style={{ color: COLORS.textMuted }}>{label}</div>
      <div className="text-[13px] font-semibold" style={{ color: COLORS.textPrimary }}>{value}</div>
    </div>
  );
}
