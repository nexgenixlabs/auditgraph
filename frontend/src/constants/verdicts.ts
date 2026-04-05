/**
 * Lineage Verdict SSOT — Single Source of Truth for verdict badges.
 *
 * All verdict label text and Tailwind CSS classes are defined here ONCE.
 * Components must use verdictBadgeClasses() and verdictLabel() — never
 * inline verdict-to-CSS mappings.
 */

// ── Verdict Type ────────────────────────────────────────────────────

export type LineageVerdict =
  | 'ORPHANED'
  | 'AT_RISK'
  | 'STALE'
  | 'UNUSED'
  | 'HEALTHY'
  | 'NEEDS_REVIEW'
  | 'GHOST_MSI'
  | 'FEDERATED_MISCONFIGURED'
  | 'PAT_GOVERNANCE_RISK';

// ── Badge Config ────────────────────────────────────────────────────

export interface VerdictBadgeConfig {
  label: string;
  lightClass: string;
  darkClass: string;
  priority: number; // 1 = most severe
}

export const VERDICT_BADGE_CONFIG: Record<string, VerdictBadgeConfig> = {
  ORPHANED: {
    label: 'Orphaned',
    lightClass: 'bg-red-100 text-red-700',
    darkClass: 'dark:bg-red-900/30 dark:text-red-400',
    priority: 1,
  },
  GHOST_MSI: {
    label: 'Ghost MSI',
    lightClass: 'bg-red-100 text-red-700',
    darkClass: 'dark:bg-red-900/30 dark:text-red-400',
    priority: 2,
  },
  AT_RISK: {
    label: 'At Risk',
    lightClass: 'bg-orange-100 text-orange-700',
    darkClass: 'dark:bg-orange-900/30 dark:text-orange-400',
    priority: 3,
  },
  FEDERATED_MISCONFIGURED: {
    label: 'Fed. Misconfigured',
    lightClass: 'bg-orange-100 text-orange-700',
    darkClass: 'dark:bg-orange-900/30 dark:text-orange-400',
    priority: 4,
  },
  STALE: {
    label: 'Stale',
    lightClass: 'bg-amber-100 text-amber-700',
    darkClass: 'dark:bg-amber-900/30 dark:text-amber-400',
    priority: 5,
  },
  PAT_GOVERNANCE_RISK: {
    label: 'PAT Risk',
    lightClass: 'bg-amber-100 text-amber-700',
    darkClass: 'dark:bg-amber-900/30 dark:text-amber-400',
    priority: 5,
  },
  UNUSED: {
    label: 'Unused',
    lightClass: 'bg-gray-100 text-gray-600',
    darkClass: 'dark:bg-slate-700 dark:text-slate-300',
    priority: 6,
  },
  NEEDS_REVIEW: {
    label: 'Review',
    lightClass: 'bg-blue-100 text-blue-700',
    darkClass: 'dark:bg-blue-900/30 dark:text-blue-400',
    priority: 7,
  },
  HEALTHY: {
    label: 'Healthy',
    lightClass: 'bg-green-100 text-green-700',
    darkClass: 'dark:bg-green-900/30 dark:text-green-400',
    priority: 9,
  },
};

// ── Helpers ─────────────────────────────────────────────────────────

const _FALLBACK: VerdictBadgeConfig = {
  label: 'Unknown',
  lightClass: 'bg-gray-100 text-gray-500',
  darkClass: 'dark:bg-slate-700 dark:text-slate-400',
  priority: 99,
};

/** Combined light + dark Tailwind class string for a verdict badge. */
export function verdictBadgeClasses(verdict?: string): string {
  const cfg = VERDICT_BADGE_CONFIG[verdict || ''] || _FALLBACK;
  return `${cfg.lightClass} ${cfg.darkClass}`;
}

/** Display label for a verdict, falls back to the raw verdict string. */
export function verdictLabel(verdict?: string): string {
  if (!verdict) return _FALLBACK.label;
  return VERDICT_BADGE_CONFIG[verdict]?.label || verdict;
}
