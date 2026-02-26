import React from 'react';

interface DataQualityRibbonProps {
  /** Last scan timestamp (ISO string or null) */
  lastScan?: string | null;
  /** Number of data sources connected */
  sourcesConnected?: number;
  /** Total possible sources */
  sourcesTotal?: number;
  /** Additional status text */
  statusText?: string;
  className?: string;
}

/**
 * Data Quality Ribbon — mandatory on every data-driven page.
 *
 * Shows data freshness, source count, and quality indicators.
 * Placed below the page header, above the content.
 */
export default function DataQualityRibbon({
  lastScan,
  sourcesConnected = 0,
  sourcesTotal = 0,
  statusText,
  className = '',
}: DataQualityRibbonProps) {
  const now = Date.now();
  const scanTime = lastScan ? new Date(lastScan).getTime() : 0;
  const ageMinutes = scanTime ? Math.floor((now - scanTime) / 60000) : Infinity;

  // Freshness indicator
  const freshness = (() => {
    if (!lastScan) return { label: 'No data', dot: 'dqr-dot--unknown' };
    if (ageMinutes < 60) return { label: `${ageMinutes}m ago`, dot: 'dqr-dot--live' };
    if (ageMinutes < 1440) return { label: `${Math.floor(ageMinutes / 60)}h ago`, dot: 'dqr-dot--live' };
    return { label: `${Math.floor(ageMinutes / 1440)}d ago`, dot: 'dqr-dot--stale' };
  })();

  return (
    <div className={`data-quality-ribbon ${className}`}>
      {/* Freshness */}
      <div className="flex items-center gap-1.5">
        <span className={`dqr-dot ${freshness.dot}`} />
        <span>Last scan: {freshness.label}</span>
      </div>

      {/* Separator */}
      <span style={{ color: 'var(--border-default)' }}>|</span>

      {/* Sources */}
      <span>
        {sourcesConnected}/{sourcesTotal} sources connected
      </span>

      {/* Custom status */}
      {statusText && (
        <>
          <span style={{ color: 'var(--border-default)' }}>|</span>
          <span>{statusText}</span>
        </>
      )}
    </div>
  );
}
