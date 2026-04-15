// === FILE 3 ===
/**
 * IdentityTable
 * =============
 *
 * Canonical identity list surface. Renders a 6-column table of
 * {@link IdentityListRow} entries plus the mandatory
 * {@link DataContextBanner} at the top. The table is pure-presentation:
 * filtering, sorting and pagination live in the parent page.
 *
 * Columns:
 *   1. Identity       — display_name + identity_type badge + cloud icon
 *   2. Risk           — RiskBadge with score
 *   3. Governance     — colored badge
 *   4. Privilege      — PrivilegeLevel badge
 *   5. Last Seen      — relative time (never = "Never")
 *   6. Global ID (F1) — abbreviated UUID + copy-to-clipboard button
 *
 * Brand palette:
 *   Navy   #15306A — header background
 *   Teal   #24A2A1 — selected / active accents
 *   Orange #FF7216 — critical / warning accents (copy-confirm flash)
 */

import { useCallback, useMemo, useState } from 'react';
import type { JSX } from 'react';
import type {
  CloudProvider,
  DataContext,
  GovernanceClassification,
  IdentityListRow,
  IdentityType,
  PrivilegeLevel,
} from '../../types/identity';
import DataContextBanner from './DataContextBanner';
import RiskBadge from './RiskBadge';

// ---------------------------------------------------------------------------
// Brand tokens — keep every hex literal in one place
// ---------------------------------------------------------------------------

const BRAND = {
  navy: '#15306A',
  teal: '#24A2A1',
  orange: '#FF7216',
} as const;

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/** Number of skeleton rows rendered while the table is loading. */
const SKELETON_ROW_COUNT = 8;

/** UUID prefix length shown in the Global ID column (the F1 short form). */
const GLOBAL_ID_PREFIX_LENGTH = 8;

/** Copy-confirm pill duration (ms). */
const COPY_CONFIRM_MS = 1500;

// ---------------------------------------------------------------------------
// Label / color maps — no inline strings below
// ---------------------------------------------------------------------------

const IDENTITY_TYPE_LABELS: Record<IdentityType, string> = {
  human_user: 'User',
  guest_user: 'Guest',
  service_principal: 'SPN',
  managed_identity: 'MI',
  app_registration: 'App',
  ai_agent: 'AI Agent',
};

const CLOUD_PROVIDER_LABELS: Record<CloudProvider, string> = {
  azure: 'Azure',
  aws: 'AWS',
  gcp: 'GCP',
};

const CLOUD_PROVIDER_ICONS: Record<CloudProvider, string> = {
  azure: '☁',
  aws: '◆',
  gcp: '◉',
};

const GOVERNANCE_CLASSES: Record<GovernanceClassification, string> = {
  Governed: 'bg-green-100 text-green-700 border-green-200',
  Ungoverned: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  Orphaned: 'bg-red-100 text-red-700 border-red-200',
  PolicyViolation: 'bg-orange-100 text-orange-700 border-orange-200',
};

const GOVERNANCE_LABELS: Record<GovernanceClassification, string> = {
  Governed: 'Governed',
  Ungoverned: 'Ungoverned',
  Orphaned: 'Orphaned',
  PolicyViolation: 'Policy Violation',
};

const PRIVILEGE_CLASSES: Record<PrivilegeLevel, string> = {
  highly_privileged: 'bg-red-100 text-red-700 border-red-200',
  privileged: 'bg-orange-100 text-orange-700 border-orange-200',
  standard: 'bg-gray-100 text-gray-600 border-gray-200',
};

const PRIVILEGE_LABELS: Record<PrivilegeLevel, string> = {
  highly_privileged: 'Highly Privileged',
  privileged: 'Privileged',
  standard: 'Standard',
};

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

/** Props for {@link IdentityTable}. */
export interface IdentityTableProps {
  /** Rows to render — ordering is preserved as-is. */
  identities: IdentityListRow[];
  /** Show skeletons instead of rows. Ignored once data arrives. */
  isLoading: boolean;
  /** Fired when a row is clicked (not when the copy button is clicked). */
  onRowClick: (identityId: string) => void;
  /** Provenance envelope from the current API response. */
  dataContext: DataContext;
  /** Optional extra class names on the outer wrapper. */
  className?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** `"2 hours ago"` style; returns `"Never"` for a null `last_seen`. */
function formatLastSeen(isoTimestamp: string | null): string {
  if (!isoTimestamp) {
    return 'Never';
  }
  const then = new Date(isoTimestamp).getTime();
  if (Number.isNaN(then)) {
    return 'Never';
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

/** Return the first 8 chars of the UUID for compact display. */
function abbreviateUuid(uuid: string): string {
  if (!uuid) {
    return '';
  }
  return uuid.slice(0, GLOBAL_ID_PREFIX_LENGTH);
}

/** Clipboard copy with a navigator-availability guard. */
async function copyToClipboard(value: string): Promise<boolean> {
  if (typeof navigator === 'undefined' || !navigator.clipboard) {
    return false;
  }
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

interface IdentityTypeChipProps {
  identityType: IdentityType;
}

/** Small pill next to the display name showing the identity type. */
function IdentityTypeChip({ identityType }: IdentityTypeChipProps): JSX.Element {
  return (
    <span
      className="ml-2 inline-flex items-center rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-gray-600"
      data-identity-type={identityType}
    >
      {IDENTITY_TYPE_LABELS[identityType]}
    </span>
  );
}

interface CloudProviderIconProps {
  provider: CloudProvider;
}

function CloudProviderIcon({ provider }: CloudProviderIconProps): JSX.Element {
  return (
    <span
      title={CLOUD_PROVIDER_LABELS[provider]}
      aria-label={CLOUD_PROVIDER_LABELS[provider]}
      data-cloud-provider={provider}
      className="ml-2 inline-flex h-5 w-5 items-center justify-center rounded text-gray-500"
    >
      {CLOUD_PROVIDER_ICONS[provider]}
    </span>
  );
}

interface GovernanceBadgeProps {
  value: GovernanceClassification;
}

function GovernanceBadge({ value }: GovernanceBadgeProps): JSX.Element {
  return (
    <span
      data-governance={value}
      className={[
        'inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold whitespace-nowrap',
        GOVERNANCE_CLASSES[value],
      ].join(' ')}
    >
      {GOVERNANCE_LABELS[value]}
    </span>
  );
}

interface PrivilegeBadgeProps {
  value: PrivilegeLevel;
}

function PrivilegeBadge({ value }: PrivilegeBadgeProps): JSX.Element {
  return (
    <span
      data-privilege-level={value}
      className={[
        'inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold whitespace-nowrap',
        PRIVILEGE_CLASSES[value],
      ].join(' ')}
    >
      {PRIVILEGE_LABELS[value]}
    </span>
  );
}

interface GlobalIdCellProps {
  globalId: string;
}

/** Abbreviated UUID + tooltip + copy button for the F1 cross-cloud id. */
function GlobalIdCell({ globalId }: GlobalIdCellProps): JSX.Element {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(
    async (event: React.MouseEvent<HTMLButtonElement>) => {
      // Don't let the click bubble up to the row (which navigates).
      event.stopPropagation();
      const ok = await copyToClipboard(globalId);
      if (ok) {
        setCopied(true);
        window.setTimeout(() => setCopied(false), COPY_CONFIRM_MS);
      }
    },
    [globalId],
  );

  return (
    <div className="flex items-center gap-2">
      <span
        title={globalId}
        className="font-mono text-xs tabular-nums text-gray-700"
      >
        {abbreviateUuid(globalId)}
      </span>
      <button
        type="button"
        onClick={handleCopy}
        aria-label={`Copy global identity id ${globalId}`}
        title="Copy full id"
        className="inline-flex h-5 w-5 items-center justify-center rounded border border-gray-200 bg-white text-[10px] text-gray-500 transition hover:border-gray-300 hover:text-gray-700"
      >
        {copied ? '✓' : '⧉'}
      </button>
      {copied ? (
        <span
          className="text-[10px] font-semibold"
          style={{ color: BRAND.orange }}
        >
          Copied
        </span>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Skeleton + empty states
// ---------------------------------------------------------------------------

function SkeletonRow(): JSX.Element {
  return (
    <tr className="animate-pulse border-b border-gray-100">
      <td className="px-4 py-3">
        <div className="h-3 w-48 rounded bg-gray-200" />
      </td>
      <td className="px-4 py-3">
        <div className="h-5 w-20 rounded-full bg-gray-200" />
      </td>
      <td className="px-4 py-3">
        <div className="h-5 w-24 rounded-full bg-gray-200" />
      </td>
      <td className="px-4 py-3">
        <div className="h-5 w-28 rounded-full bg-gray-200" />
      </td>
      <td className="px-4 py-3">
        <div className="h-3 w-20 rounded bg-gray-200" />
      </td>
      <td className="px-4 py-3">
        <div className="h-3 w-24 rounded bg-gray-200" />
      </td>
    </tr>
  );
}

function EmptyState(): JSX.Element {
  return (
    <tr>
      <td colSpan={6} className="px-4 py-16">
        <div className="flex flex-col items-center justify-center gap-3 text-center">
          <div
            aria-hidden="true"
            className="flex h-12 w-12 items-center justify-center rounded-full border border-dashed text-2xl"
            style={{
              borderColor: BRAND.teal,
              color: BRAND.teal,
            }}
          >
            ⌕
          </div>
          <div className="text-sm font-semibold text-gray-700">
            No identities match the current filters
          </div>
          <div className="text-xs text-gray-500">
            Try widening the risk or cloud filters, or trigger a fresh scan.
          </div>
        </div>
      </td>
    </tr>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

/**
 * Canonical identity list surface. See file header for column layout,
 * state handling, and brand palette usage.
 */
export function IdentityTable({
  identities,
  isLoading,
  onRowClick,
  dataContext,
  className,
}: IdentityTableProps): JSX.Element {
  // Stable skeleton row ids so the virtual DOM diff doesn't thrash.
  const skeletonRows = useMemo(
    () => Array.from({ length: SKELETON_ROW_COUNT }, (_, i) => i),
    [],
  );

  const handleRowClick = useCallback(
    (identityId: string) => () => onRowClick(identityId),
    [onRowClick],
  );

  const handleRowKeyDown = useCallback(
    (identityId: string) =>
      (event: React.KeyboardEvent<HTMLTableRowElement>) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          onRowClick(identityId);
        }
      },
    [onRowClick],
  );

  const headerStyle: React.CSSProperties = {
    backgroundColor: BRAND.navy,
  };

  const headerCellClasses =
    'sticky top-0 z-10 px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-white';

  return (
    <div
      className={[
        'flex h-full w-full flex-col overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm',
        className ?? '',
      ]
        .filter(Boolean)
        .join(' ')}
    >
      <DataContextBanner dataContext={dataContext} />

      <div className="flex-1 overflow-auto">
        <table className="min-w-full border-collapse">
          <thead>
            <tr style={headerStyle}>
              <th className={headerCellClasses} style={headerStyle}>
                Identity
              </th>
              <th className={headerCellClasses} style={headerStyle}>
                Risk
              </th>
              <th className={headerCellClasses} style={headerStyle}>
                Governance
              </th>
              <th className={headerCellClasses} style={headerStyle}>
                Privilege
              </th>
              <th className={headerCellClasses} style={headerStyle}>
                Last Seen
              </th>
              <th className={headerCellClasses} style={headerStyle}>
                Global ID
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 bg-white text-sm text-gray-800">
            {isLoading ? (
              skeletonRows.map((i) => <SkeletonRow key={`skeleton-${i}`} />)
            ) : identities.length === 0 ? (
              <EmptyState />
            ) : (
              identities.map((row) => (
                <tr
                  key={row.identity_id}
                  tabIndex={0}
                  role="button"
                  aria-label={`Open identity ${row.display_name}`}
                  onClick={handleRowClick(row.identity_id)}
                  onKeyDown={handleRowKeyDown(row.identity_id)}
                  className="cursor-pointer transition-colors hover:bg-blue-50 focus:bg-blue-50 focus:outline-none"
                  style={{ borderLeft: `3px solid transparent` }}
                  onMouseEnter={(e) => {
                    (e.currentTarget as HTMLTableRowElement).style.borderLeft =
                      `3px solid ${BRAND.teal}`;
                  }}
                  onMouseLeave={(e) => {
                    (e.currentTarget as HTMLTableRowElement).style.borderLeft =
                      '3px solid transparent';
                  }}
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center">
                      <span
                        className="truncate font-medium text-gray-900"
                        title={row.display_name}
                      >
                        {row.display_name}
                      </span>
                      <IdentityTypeChip identityType={row.identity_type} />
                      <CloudProviderIcon provider={row.cloud_provider} />
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <RiskBadge label={row.risk_label} score={row.risk_score} />
                  </td>
                  <td className="px-4 py-3">
                    <GovernanceBadge value={row.governance} />
                  </td>
                  <td className="px-4 py-3">
                    <PrivilegeBadge value={row.privilege_level} />
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className="text-xs text-gray-600"
                      title={row.last_seen ?? 'never observed'}
                    >
                      {formatLastSeen(row.last_seen)}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <GlobalIdCell globalId={row.global_identity_id} />
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default IdentityTable;
