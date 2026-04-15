/**
 * Remediation Queue SSOT — status/severity badge config.
 *
 * All status and severity rendering MUST use statusBadgeClasses() and
 * severityBadgeClasses(). No inline Tailwind color strings for these.
 */
import type { RemediationStatus, RemediationSeverity } from '../types/remediation';

export interface StatusConfig {
  label: string;
  lightClass: string;
  darkClass: string;
  nextStatuses: RemediationStatus[];
}

export interface SeverityConfig {
  label: string;
  lightClass: string;
  darkClass: string;
  sortOrder: number;
}

export const STATUS_CONFIG: Record<RemediationStatus, StatusConfig> = {
  open: {
    label: 'Open',
    lightClass: 'bg-blue-100 text-blue-800',
    darkClass: 'dark:bg-blue-900/30 dark:text-blue-200',
    nextStatuses: ['in_progress', 'dismissed'],
  },
  in_progress: {
    label: 'In Progress',
    lightClass: 'bg-yellow-100 text-yellow-800',
    darkClass: 'dark:bg-yellow-900/30 dark:text-yellow-200',
    nextStatuses: ['resolved', 'dismissed'],
  },
  resolved: {
    label: 'Resolved',
    lightClass: 'bg-green-100 text-green-800',
    darkClass: 'dark:bg-green-900/30 dark:text-green-200',
    nextStatuses: ['open'],
  },
  dismissed: {
    label: 'Dismissed',
    lightClass: 'bg-gray-100 text-gray-600',
    darkClass: 'dark:bg-gray-800 dark:text-gray-400',
    nextStatuses: ['open'],
  },
};

export const SEVERITY_CONFIG: Record<RemediationSeverity, SeverityConfig> = {
  CRITICAL: {
    label: 'Critical',
    lightClass: 'bg-red-100 text-red-800',
    darkClass: 'dark:bg-red-900/30 dark:text-red-200',
    sortOrder: 1,
  },
  HIGH: {
    label: 'High',
    lightClass: 'bg-orange-100 text-orange-800',
    darkClass: 'dark:bg-orange-900/30 dark:text-orange-200',
    sortOrder: 2,
  },
  MEDIUM: {
    label: 'Medium',
    lightClass: 'bg-yellow-100 text-yellow-800',
    darkClass: 'dark:bg-yellow-900/30 dark:text-yellow-200',
    sortOrder: 3,
  },
  LOW: {
    label: 'Low',
    lightClass: 'bg-gray-100 text-gray-600',
    darkClass: 'dark:bg-gray-800 dark:text-gray-400',
    sortOrder: 4,
  },
};

export function statusBadgeClasses(status: RemediationStatus): string {
  const cfg = STATUS_CONFIG[status];
  if (!cfg) return 'bg-gray-100 text-gray-500';
  return `${cfg.lightClass} ${cfg.darkClass}`;
}

export function severityBadgeClasses(severity: RemediationSeverity): string {
  const cfg = SEVERITY_CONFIG[severity];
  if (!cfg) return 'bg-gray-100 text-gray-500';
  return `${cfg.lightClass} ${cfg.darkClass}`;
}

export function statusLabel(status: RemediationStatus): string {
  return STATUS_CONFIG[status]?.label ?? status;
}

export function severityLabel(severity: RemediationSeverity): string {
  return SEVERITY_CONFIG[severity]?.label ?? severity;
}
