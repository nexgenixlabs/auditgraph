// === FILE 1 ===
/**
 * DataContextBanner
 * =================
 *
 * Provenance / freshness banner for any identity surface. Mounted at the
 * top of every identity view so the user can never confuse snapshot data
 * with live data, and can never silently consume a stale live page.
 *
 * Rendering rules (mirror the backend `DataContext`):
 *   1. `live` + fresh    → renders nothing (no visual noise on the happy path)
 *   2. `live` + stale    → orange warning, prompts a refresh
 *   3. `snapshot`        → navy info, shows the snapshot date
 *
 * Brand palette:
 *   Navy   #15306A — snapshot / informational background
 *   Teal   #24A2A1 — (reserved for IdentityTable accents)
 *   Orange #FF7216 — stale-live warning accent (icon + border emphasis)
 */

import type { JSX } from 'react';
import type { DataContext } from '../../types/identity';

/** Props for {@link DataContextBanner}. */
export interface DataContextBannerProps {
  /** Provenance metadata from the API payload. */
  dataContext: DataContext;
  /** Optional extra class names (merged after the variant styles). */
  className?: string;
}

// ---------------------------------------------------------------------------
// Internal — relative / absolute time helpers
// ---------------------------------------------------------------------------

/**
 * Render a duration as `"N units ago"`. Falls back to `"just now"` for
 * sub-minute deltas and to an ISO string for invalid dates.
 */
function formatRelativeTime(isoTimestamp: string | null): string {
  if (!isoTimestamp) {
    return 'an unknown time ago';
  }
  const then = new Date(isoTimestamp).getTime();
  if (Number.isNaN(then)) {
    return isoTimestamp;
  }
  const deltaSeconds = Math.max(0, Math.floor((Date.now() - then) / 1000));

  if (deltaSeconds < 45) {
    return 'just now';
  }

  const units: Array<{ label: string; seconds: number }> = [
    { label: 'year', seconds: 60 * 60 * 24 * 365 },
    { label: 'month', seconds: 60 * 60 * 24 * 30 },
    { label: 'day', seconds: 60 * 60 * 24 },
    { label: 'hour', seconds: 60 * 60 },
    { label: 'minute', seconds: 60 },
  ];

  for (const unit of units) {
    const value = Math.floor(deltaSeconds / unit.seconds);
    if (value >= 1) {
      return `${value} ${unit.label}${value === 1 ? '' : 's'} ago`;
    }
  }
  return 'just now';
}

/** Format an ISO string as `Apr 10, 2026 14:30 UTC` — locale-stable. */
function formatSnapshotDate(isoTimestamp: string | null): string {
  if (!isoTimestamp) {
    return 'unknown date';
  }
  const date = new Date(isoTimestamp);
  if (Number.isNaN(date.getTime())) {
    return isoTimestamp;
  }
  return (
    date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      timeZone: 'UTC',
    }) +
    ' ' +
    date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
      timeZone: 'UTC',
    }) +
    ' UTC'
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * Sticky provenance banner. Returns `null` for the fresh-live case so it
 * adds zero visible chrome when everything is healthy.
 */
export function DataContextBanner({
  dataContext,
  className,
}: DataContextBannerProps): JSX.Element | null {
  // Happy path — live and fresh, no banner.
  if (dataContext.data_mode === 'live' && !dataContext.is_stale) {
    return null;
  }

  const baseLayoutClasses =
    'sticky top-0 z-50 flex w-full items-center gap-3 px-4 py-3 text-sm font-medium';

  // Stale live payload — orange warning.
  if (dataContext.data_mode === 'live') {
    const relative = formatRelativeTime(dataContext.computed_at);
    return (
      <div
        role="alert"
        aria-live="polite"
        data-variant="stale"
        className={[
          baseLayoutClasses,
          'border-b bg-orange-50 border border-orange-200 text-orange-800',
          className ?? '',
        ]
          .filter(Boolean)
          .join(' ')}
      >
        <span
          aria-hidden="true"
          className="flex h-5 w-5 items-center justify-center rounded-full"
          style={{ color: '#FF7216' }}
        >
          ⚠
        </span>
        <span className="flex-1">
          Data may be stale — last scan completed {relative}. Refresh to update.
        </span>
      </div>
    );
  }

  // Snapshot payload — navy info banner.
  const snapshotLabel = formatSnapshotDate(dataContext.snapshot_date);
  return (
    <div
      role="status"
      aria-live="polite"
      data-variant="snapshot"
      className={[
        baseLayoutClasses,
        'border-b bg-blue-950 border border-blue-800 text-white',
        className ?? '',
      ]
        .filter(Boolean)
        .join(' ')}
      style={{ backgroundColor: '#15306A' }}
    >
      <span aria-hidden="true" className="flex h-5 w-5 items-center justify-center">
        📷
      </span>
      <span className="flex-1">
        Viewing historical snapshot from {snapshotLabel}. Live data not shown.
      </span>
    </div>
  );
}

export default DataContextBanner;
