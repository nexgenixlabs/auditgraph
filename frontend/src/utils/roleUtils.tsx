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
  // Inference ran but found no activity signal — this does NOT confirm the role was unused
  return (
    <span className={`${base} bg-gray-100 text-gray-500`} title={usage.evidence || 'No ARM management plane activity observed in the last 90 days. AuditGraph cannot confirm this role was unused — only that no activity was detectable.'}>
      No activity signal
    </span>
  );
}

/**
 * Classification badge for per-role usage confidence (4-tier model).
 *
 * Tiers:
 *   proven:              ARM activity at matching scope, no overlapping roles
 *   likely:              ARM activity detected, but overlapping roles prevent
 *                        deterministic attribution
 *   unknown:             Identity active, but no role-specific evidence
 *   no_observed_usage:   No relevant activity within observation window
 *   telemetry_blind:     No telemetry connectors — cannot determine usage
 *   insufficient_coverage: Coverage data unavailable
 *
 * Legacy "used" value is mapped to "likely" for backward compatibility.
 */
export type RoleUsageClassification =
  | 'proven' | 'likely' | 'unknown'
  | 'no_observed_usage' | 'telemetry_blind' | 'insufficient_coverage'
  | 'used';  // legacy compat

const CLASSIFICATION_CONFIG: Record<string, { label: string; cls: string; title: string }> = {
  proven:                { label: 'Proven Used',              cls: 'bg-green-100 text-green-700',   title: 'Role-scoped ARM activity confirmed — no overlapping roles at this scope' },
  likely:                { label: 'Likely Used',              cls: 'bg-blue-100 text-blue-700',     title: 'Activity detected at scope but overlapping roles prevent deterministic attribution' },
  unknown:               { label: 'Role Unconfirmed',         cls: 'bg-slate-100 text-slate-600',   title: 'Identity active but no role-specific evidence — cannot confirm this role was exercised' },
  no_observed_usage:     { label: 'No activity observed',      cls: 'bg-amber-100 text-amber-700',   title: 'No ARM management plane activity observed in the last 90 days. AuditGraph cannot confirm this role was unused — only that no activity was detectable.' },
  telemetry_blind:       { label: 'Telemetry blind',          cls: 'bg-gray-100 text-gray-500',     title: 'No telemetry connectors available — cannot determine usage' },
  insufficient_coverage: { label: 'Insufficient data',        cls: 'bg-gray-50 text-gray-400 border border-gray-200', title: 'Coverage data unavailable — classification not possible' },
  used:                  { label: 'Likely Used',              cls: 'bg-blue-100 text-blue-700',     title: 'Activity detected (legacy classification)' },
};

export function getClassificationBadge(classification: string | undefined | null): React.ReactElement | null {
  if (!classification) return null;
  const cfg = CLASSIFICATION_CONFIG[classification];
  if (!cfg) return null;
  const base = 'px-1.5 py-0.5 rounded text-[10px] font-semibold inline-flex items-center';
  return (
    <span className={`${base} ${cfg.cls}`} title={cfg.title}>
      {cfg.label}
    </span>
  );
}
