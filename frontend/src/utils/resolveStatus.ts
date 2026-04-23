/**
 * Canonical Identity Status Resolver (frontend fallback)
 *
 * The server computes `status` and `status_display` via the Python resolver.
 * This utility provides a client-side fallback and badge config.
 */

export type IdentityStatus = 'active' | 'disabled' | 'deleted' | 'unknown';

export interface StatusDisplay {
  label: string;
  badge_class: string;
}

export const STATUS_BADGE: Record<IdentityStatus, StatusDisplay> = {
  active:   { label: 'Active',   badge_class: 'text-gray-400 font-normal' },
  disabled: { label: 'Disabled', badge_class: 'text-gray-500 font-medium' },
  deleted:  { label: 'Deleted',  badge_class: 'text-gray-400 font-normal' },
  unknown:  { label: 'Unknown',  badge_class: 'text-gray-400 font-normal' },
};

/**
 * Client-side fallback resolver. Prefer server-computed `status_display`.
 */
export function resolveStatus(identity: {
  deleted_at?: string | null;
  enabled?: boolean | null;
  status?: string;
}): IdentityStatus {
  if (identity.deleted_at != null) return 'deleted';
  if (identity.enabled === false) return 'disabled';
  if (identity.enabled === true) return 'active';
  const s = identity.status;
  if (s === 'active' || s === 'disabled' || s === 'deleted') return s;
  return 'unknown';
}

/**
 * Get display config for a given status string.
 */
export function getStatusDisplay(status: string | undefined): StatusDisplay {
  return STATUS_BADGE[(status as IdentityStatus)] || STATUS_BADGE.unknown;
}
