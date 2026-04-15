/**
 * Canonical role usage utilities — single source of truth.
 *
 * Every component that renders role usage badges or looks up role usage
 * entries MUST import from here. Never inline normalizeRoleKey or the
 * badge logic — drift between RolesTab and AccessTab (and any future tab)
 * is the primary bug class this file exists to prevent.
 *
 * Contract: must match backend governance_service._normalize_role_key
 * exactly. Rule: lowercase + trim. Nothing else.
 */
import React from 'react';

export interface RoleUsageEntry {
  used: boolean;
  confidence: 'high' | 'medium' | 'low' | 'none';
  evidence: string;
}

/**
 * Normalize a role display name to the canonical key format used as the
 * key in role_usage lookup dictionaries. Must match backend
 * governance_service._normalize_role_key() exactly.
 */
export function normalizeRoleKey(name: string | undefined | null): string {
  return (name || '').trim().toLowerCase();
}

/**
 * Canonical role usage badge renderer. Single source of truth for all
 * role usage display across all tabs.
 *
 * Used in: RolesTab, AccessTab, drawer Access tab, any future tab.
 * Never inline this logic — always import from here.
 */
export function getRoleUsageBadge(
  roleName: string | undefined | null,
  roleUsage: Record<string, RoleUsageEntry> | undefined | null,
): React.ReactElement {
  const base = 'px-1.5 py-0.5 rounded text-[10px] font-semibold inline-flex items-center';

  const key = normalizeRoleKey(roleName);
  const usage = roleUsage?.[key];

  if (!usage) {
    // Key not found in inference results — data not yet loaded or role not processed
    return (
      <span className={`${base} bg-gray-50 text-gray-400 border border-gray-200`}>
        No data
      </span>
    );
  }
  if (usage.used && usage.confidence === 'high') {
    return (
      <span className={`${base} bg-green-100 text-green-700`} title={usage.evidence}>
        Used
      </span>
    );
  }
  if (usage.used && usage.confidence === 'medium') {
    return (
      <span className={`${base} bg-blue-100 text-blue-700`} title={usage.evidence}>
        Used (inferred)
      </span>
    );
  }
  if (usage.used && usage.confidence === 'low') {
    return (
      <span className={`${base} bg-cyan-100 text-cyan-700`} title={usage.evidence}>
        Possible usage
      </span>
    );
  }
  // Inference ran but found no evidence — definitive result, not fallback
  return (
    <span className={`${base} bg-gray-100 text-gray-500`} title={usage.evidence}>
      No evidence
    </span>
  );
}
