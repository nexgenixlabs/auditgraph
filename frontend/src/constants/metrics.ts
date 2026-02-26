/**
 * AuditGraph Metric Registry — Single Source of Truth
 *
 * Every type, label, color, threshold, and helper used across the app
 * is defined here ONCE. Components import from this file instead of
 * re-declaring their own copies.
 */

// ── Identity Categories ─────────────────────────────────────────────

export type IdentityCategory =
  | 'service_principal'
  | 'managed_identity_system'
  | 'managed_identity_user'
  | 'human_user'
  | 'guest'
  | 'unknown';

export const IDENTITY_CATEGORIES: Record<string, { label: string; shortLabel: string; description: string }> = {
  service_principal:      { label: 'Service Principal',      shortLabel: 'SPN',    description: 'App registrations & enterprise apps' },
  managed_identity_user:  { label: 'User Managed Identity',  shortLabel: 'Usr MI', description: 'Reusable across resources' },
  managed_identity_system:{ label: 'System Managed Identity', shortLabel: 'Sys MI', description: 'Azure-managed per resource' },
  human_user:             { label: 'Human User',             shortLabel: 'Human',  description: 'Employees & members' },
  guest:                  { label: 'Guest',                  shortLabel: 'Guest',  description: 'External collaborators' },
};

/** Categories shown in dashboard/overview (excludes system MI & unknown) */
export const CATEGORY_DISPLAY_ORDER: IdentityCategory[] = [
  'service_principal',
  'managed_identity_user',
  'human_user',
  'guest',
];

export const CATEGORY_FILTER_OPTIONS: { value: IdentityCategory | 'all'; label: string }[] = [
  { value: 'all', label: 'All Categories' },
  ...CATEGORY_DISPLAY_ORDER.map(key => ({
    value: key,
    label: IDENTITY_CATEGORIES[key].label,
  })),
];

export function getCategoryLabel(cat?: string): string {
  return IDENTITY_CATEGORIES[cat || '']?.label || 'Unknown';
}

export function getCategoryShortLabel(cat?: string): string {
  return IDENTITY_CATEGORIES[cat || '']?.shortLabel || '?';
}

export function normalizeCategoryFromBackend(raw?: any): IdentityCategory {
  const v = safeLower(raw).trim();
  if (!v) return 'unknown';
  if (v in IDENTITY_CATEGORIES || v === 'unknown') return v as IdentityCategory;
  if (v === 'user' || v === 'human user') return 'human_user';
  if (v.includes('user assigned') || v.includes('user-assigned')) return 'managed_identity_user';
  if (v.includes('system assigned') || v.includes('system-assigned')) return 'managed_identity_system';
  if (v === 'service principal' || v === 'serviceprincipal') return 'service_principal';
  return 'unknown';
}

// ── Risk Levels ──────────────────────────────────────────────────────

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';

export const RISK_LEVELS = ['critical', 'high', 'medium', 'low', 'info'] as const;

export const RISK_ORDER: Record<string, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1, unknown: 0,
};

export const RISK_FILTER_OPTIONS: { value: RiskLevel | 'all'; label: string }[] = [
  { value: 'all', label: 'All Levels' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
];

/** Hex colors for SVG charts (donut, arc gauges) */
export const RISK_HEX: Record<string, { color: string; hoverColor: string }> = {
  critical: { color: '#ef4444', hoverColor: '#dc2626' },
  high:     { color: '#f97316', hoverColor: '#ea580c' },
  medium:   { color: '#eab308', hoverColor: '#ca8a04' },
  low:      { color: '#22c55e', hoverColor: '#16a34a' },
  info:     { color: '#3b82f6', hoverColor: '#2563eb' },
};

/** Tailwind classes for solid buttons / heatmap cells */
export const RISK_SOLID: Record<string, { bg: string; hoverBg: string; text: string }> = {
  critical: { bg: 'bg-red-500',    hoverBg: 'hover:bg-red-600',    text: 'text-white' },
  high:     { bg: 'bg-orange-500', hoverBg: 'hover:bg-orange-600', text: 'text-white' },
  medium:   { bg: 'bg-yellow-400', hoverBg: 'hover:bg-yellow-500', text: 'text-gray-900' },
  low:      { bg: 'bg-green-400',  hoverBg: 'hover:bg-green-500',  text: 'text-white' },
  info:     { bg: 'bg-blue-400',   hoverBg: 'hover:bg-blue-500',   text: 'text-white' },
};

/** Tailwind classes for light badges (pill/chip style) */
export const RISK_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high:     'bg-orange-100 text-orange-700',
  medium:   'bg-yellow-100 text-yellow-700',
  low:      'bg-green-100 text-green-700',
  info:     'bg-blue-100 text-blue-700',
};

// ── Cloud Providers ──────────────────────────────────────────────────

export const CLOUD_BADGE: Record<string, string> = {
  azure: 'bg-blue-100 text-blue-700',
  aws:   'bg-orange-100 text-orange-700',
  gcp:   'bg-red-100 text-red-700',
};

// ── Permission Planes ────────────────────────────────────────────────

export const PERMISSION_PLANE_CONFIG: Record<string, { label: string; badgeClass: string }> = {
  rbac:       { label: 'RBAC',       badgeClass: 'border border-sky-300 text-sky-600 bg-sky-50' },
  entra_id:   { label: 'Entra ID',   badgeClass: 'border border-indigo-300 text-indigo-600 bg-indigo-50' },
  iam:        { label: 'IAM',        badgeClass: 'border border-orange-300 text-orange-600 bg-orange-50' },
  org_policy: { label: 'Org Policy', badgeClass: 'border border-teal-300 text-teal-600 bg-teal-50' },
};

export const CLOUD_PERMISSION_PLANES: Record<string, string[]> = {
  azure: ['rbac', 'entra_id'],
  aws:   ['iam', 'org_policy'],
  gcp:   ['iam', 'org_policy'],
};

export const PERMISSION_PLANE_FILTER_OPTIONS: { value: string; label: string }[] = [
  { value: '', label: 'All Planes' },
  { value: 'rbac', label: 'RBAC' },
  { value: 'entra_id', label: 'Entra ID' },
  { value: 'iam', label: 'IAM' },
  { value: 'org_policy', label: 'Org Policy' },
];

export function getPermissionPlaneLabel(plane?: string): string {
  return PERMISSION_PLANE_CONFIG[plane || '']?.label || plane || 'Unknown';
}

/** Map legacy source values to permission plane */
export function toPermissionPlane(source?: string, permissionPlane?: string): string {
  if (permissionPlane) return permissionPlane;
  if (source === 'entra') return 'entra_id';
  if (source === 'azure') return 'rbac';
  return source || 'unknown';
}

// ── Thresholds ───────────────────────────────────────────────────────

export const THRESHOLDS = {
  CREDENTIAL_EXPIRY_DAYS: 30,
  DORMANT_STALE_DAYS: 90,
  DORMANT_IDLE_DAYS: 30,
  MAX_T0_ACCOUNTS: 2,
  MAX_UNOWNED_SPNS: 3,
} as const;

// ── Activity / Dormancy ──────────────────────────────────────────────

export type DormantStatus = 'yes' | 'idle' | 'never' | 'new' | 'no' | 'unknown';

export function getDormantStatus(activityStatus?: string): DormantStatus {
  const act = safeLower(activityStatus);
  if (act === 'stale') return 'yes';
  if (act === 'never_used') return 'never';
  if (act === 'inactive') return 'idle';
  if (act === 'recently_created') return 'new';
  if (act === 'active') return 'no';
  return 'unknown';
}

export const DORMANT_LABELS: Record<DormantStatus, { label: string; color: string; tooltip: string }> = {
  yes:     { label: `Stale ${THRESHOLDS.DORMANT_STALE_DAYS}d+`,                                     color: 'bg-red-100 text-red-700',    tooltip: `No sign-in activity for ${THRESHOLDS.DORMANT_STALE_DAYS}+ days` },
  idle:    { label: `Idle ${THRESHOLDS.DORMANT_IDLE_DAYS}-${THRESHOLDS.DORMANT_STALE_DAYS}d`,        color: 'bg-orange-100 text-orange-700', tooltip: `No sign-in activity for ${THRESHOLDS.DORMANT_IDLE_DAYS}-${THRESHOLDS.DORMANT_STALE_DAYS} days` },
  never:   { label: 'Never Used',                                                                    color: 'bg-red-100 text-red-800',   tooltip: 'Created 30+ days ago with no recorded sign-in' },
  new:     { label: 'New',                                                                           color: 'bg-blue-100 text-blue-700', tooltip: 'Created within the last 30 days' },
  no:      { label: 'Active',                                                                        color: 'bg-green-100 text-green-700', tooltip: 'Sign-in activity within the last 30 days' },
  unknown: { label: 'Unknown',                                                                       color: 'bg-gray-100 text-gray-500', tooltip: 'No sign-in data — requires Azure AD Premium P1/P2 license' },
};

// ── Data Explanations (Pillar 3: Telemetry Truth) ───────────────────

/** Standard explanations for why data may be missing */
export const DATA_EXPLANATIONS = {
  SIGN_IN:        'Sign-in logs require Azure AD Premium P1/P2',
  PIM:            'PIM requires Azure AD Premium P2 license',
  CA_POLICY:      'CA analysis requires Policy.Read.All permission',
  AUDIT_LOG:      'Audit logs require AuditLog.Read.All permission',
  CREDENTIAL_NA:  'Human users authenticate via Entra ID (password/MFA), not app secrets',
  NO_DATA:        'Not yet collected — run a discovery scan',
} as const;

// ── Identity Dashboard V2 ────────────────────────────────────────────

export type PrivilegedLevel = 'privileged' | 'elevated' | 'standard';

export const PRIVILEGED_LEVELS: Record<PrivilegedLevel, { label: string; color: string; tooltip: string }> = {
  privileged: { label: 'Privileged',  color: 'bg-red-100 text-red-800 border-red-200',     tooltip: 'Tier 0: Global Admin, Privileged Role Admin, Subscription Owner' },
  elevated:   { label: 'Elevated',    color: 'bg-orange-100 text-orange-800 border-orange-200', tooltip: 'Tier 1: User Admin, Exchange Admin, Contributor' },
  standard:   { label: 'Standard',    color: 'bg-gray-100 text-gray-600 border-gray-200',  tooltip: 'Tier 2-3: Limited or no privileged roles' },
};

export type EffectiveScope = 'tenant' | 'directory' | 'subscription' | 'resource_group' | 'resource' | 'none';

export const EFFECTIVE_SCOPE_ORDER: Record<EffectiveScope, number> = {
  tenant: 6, directory: 5, subscription: 4, resource_group: 3, resource: 2, none: 1,
};

export const EFFECTIVE_SCOPE_CONFIG: Record<EffectiveScope, { label: string; color: string; icon: string }> = {
  tenant:         { label: 'Tenant',      color: 'bg-red-100 text-red-700',      icon: 'T' },
  directory:      { label: 'Directory',   color: 'bg-purple-100 text-purple-700', icon: 'D' },
  subscription:   { label: 'Subscription', color: 'bg-orange-100 text-orange-700', icon: 'S' },
  resource_group: { label: 'RG',          color: 'bg-yellow-100 text-yellow-700', icon: 'R' },
  resource:       { label: 'Resource',    color: 'bg-blue-100 text-blue-700',    icon: 'r' },
  none:           { label: 'None',        color: 'bg-gray-100 text-gray-500',    icon: '-' },
};

export type CredentialHealth = 'ok' | 'expiring' | 'expired' | 'none';

export const CREDENTIAL_HEALTH_CONFIG: Record<CredentialHealth, { label: string; color: string }> = {
  ok:       { label: 'OK',       color: 'bg-green-100 text-green-700' },
  expiring: { label: 'Expiring', color: 'bg-orange-100 text-orange-700' },
  expired:  { label: 'Expired',  color: 'bg-red-100 text-red-700' },
  none:     { label: 'None',     color: 'bg-gray-100 text-gray-500' },
};

// Multi-cloud scope labels
export const SCOPE_LABELS: Record<string, Record<string, string>> = {
  azure: { tenant: 'Tenant', subscription: 'Subscription', resource_group: 'Resource Group', resource: 'Resource', directory: 'Directory' },
  aws:   { organization: 'Organization', account: 'Account', resource: 'Resource' },
  gcp:   { organization: 'Organization', project: 'Project', resource: 'Resource' },
};

// Multi-cloud category labels
export const CATEGORY_LABELS_MULTI: Record<string, Record<string, string>> = {
  azure: { human_user: 'Human', guest: 'Guest', service_principal: 'Workload', managed_identity_system: 'System MI', managed_identity_user: 'User MI' },
  aws:   { human_user: 'IAM User', service_principal: 'Role', managed_identity_system: 'Service', guest: 'Federated' },
  gcp:   { human_user: 'User', service_principal: 'Service Acct', guest: 'External' },
};

// ── SPN Exposure Intelligence ────────────────────────────────────────

export const SPN_EXPOSURE_COMPONENTS: Record<string, { label: string; max: number; color: string }> = {
  privilege:       { label: 'Privilege',       max: 40, color: '#ef4444' },
  credential_risk: { label: 'Credential Risk', max: 25, color: '#f97316' },
  exposure:        { label: 'Exposure',        max: 20, color: '#eab308' },
  lifecycle:       { label: 'Lifecycle',        max: 10, color: '#8b5cf6' },
  visibility:      { label: 'Visibility',      max: 5,  color: '#6b7280' },
};

export const EXPOSURE_THRESHOLDS = { critical: 80, high: 60, medium: 35, low: 0 } as const;

export function getExposureLevel(score: number): string {
  if (score >= EXPOSURE_THRESHOLDS.critical) return 'critical';
  if (score >= EXPOSURE_THRESHOLDS.high) return 'high';
  if (score >= EXPOSURE_THRESHOLDS.medium) return 'medium';
  return 'low';
}

export const EXPOSURE_LEVEL_CONFIG: Record<string, { label: string; color: string; badgeClass: string; min: number; max: number }> = {
  critical: { label: 'Critical', color: '#ef4444', badgeClass: 'bg-red-100 text-red-700',    min: 80, max: 100 },
  high:     { label: 'High',     color: '#f97316', badgeClass: 'bg-orange-100 text-orange-700', min: 60, max: 79 },
  medium:   { label: 'Medium',   color: '#eab308', badgeClass: 'bg-yellow-100 text-yellow-700', min: 35, max: 59 },
  low:      { label: 'Low',      color: '#22c55e', badgeClass: 'bg-green-100 text-green-700',  min: 0,  max: 34 },
};

export const LIFECYCLE_STATE_CONFIG: Record<string, { label: string; badgeClass: string; tooltip: string }> = {
  active:          { label: 'Active',          badgeClass: 'bg-green-100 text-green-700',  tooltip: 'High-confidence activity detected' },
  possibly_active: { label: 'Possibly Active', badgeClass: 'bg-blue-100 text-blue-700',   tooltip: 'Some activity signals detected' },
  likely_dormant:  { label: 'Likely Dormant',  badgeClass: 'bg-orange-100 text-orange-700', tooltip: 'Weak activity signals — likely unused' },
  dormant:         { label: 'Dormant',         badgeClass: 'bg-red-100 text-red-700',     tooltip: 'Confirmed dormant — zero sign-ins in 30 days (P2 verified)' },
  blind:           { label: 'Visibility Gap',  badgeClass: 'bg-gray-100 text-gray-600',   tooltip: 'No telemetry — cannot determine usage' },
};

export const OWNER_STATUS_CONFIG: Record<string, { label: string; badgeClass: string }> = {
  owned:          { label: 'Owned',          badgeClass: 'bg-green-100 text-green-700' },
  single_owner:   { label: 'Single Owner',   badgeClass: 'bg-yellow-100 text-yellow-700' },
  resource_bound: { label: 'Resource Bound', badgeClass: 'bg-teal-100 text-teal-700' },
  orphaned:       { label: 'Orphaned',       badgeClass: 'bg-red-100 text-red-700' },
  unknown:        { label: 'Unknown',        badgeClass: 'bg-gray-100 text-gray-500' },
};

export const SCOPE_FLAG_CONFIG: Record<string, { label: string; badgeClass: string }> = {
  tenant:           { label: 'Tenant',      badgeClass: 'bg-red-100 text-red-700' },
  management_group: { label: 'Mgmt Group',  badgeClass: 'bg-red-100 text-red-700' },
  subscription:     { label: 'Subscription', badgeClass: 'bg-orange-100 text-orange-700' },
  resource_group:   { label: 'RG',          badgeClass: 'bg-yellow-100 text-yellow-700' },
  resource:         { label: 'Resource',    badgeClass: 'bg-green-100 text-green-700' },
};

// ── Workload Exposure Score Helpers ───────────────────────────────────

export const LIFECYCLE_BAR_COLORS: Record<string, string> = {
  active: '#36D986', possibly_active: '#4E9FFF', likely_dormant: '#FFB938',
  dormant: '#FF8C42', blind: '#FF4D4D',
};

export const COMPONENT_MAX: Record<string, number> = {
  privilege: 40, credential_risk: 25, exposure: 20, lifecycle: 10, visibility: 5,
};

// ── Workload Identity Type Config ────────────────────────────────────

export const WORKLOAD_TYPE_CONFIG: Record<string, { label: string; badgeClass: string; shortLabel: string }> = {
  spn:              { label: 'Service Principal', badgeClass: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300', shortLabel: 'SPN' },
  app_registration: { label: 'App Registration',  badgeClass: 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300', shortLabel: 'APP' },
  managed_identity: { label: 'Managed Identity',  badgeClass: 'bg-teal-100 text-teal-700 dark:bg-teal-900/40 dark:text-teal-300', shortLabel: 'MI' },
};

// ── AGIRS Scoring Tiers ──────────────────────────────────────────────

export const AGIRS_TIERS: Record<string, [number, number]> = {
  A: [90, 100],
  B: [75, 89],
  C: [60, 74],
  D: [40, 59],
  F: [0, 39],
};

export const AGIRS_COLORS: Record<string, string> = {
  A: '#22c55e',
  B: '#84cc16',
  C: '#eab308',
  D: '#f97316',
  F: '#ef4444',
};

export function getAGIRSTier(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

export function getAGIRSColor(score: number): string {
  return AGIRS_COLORS[getAGIRSTier(score)] || AGIRS_COLORS.F;
}

// ── Helpers ──────────────────────────────────────────────────────────

export function safeLower(v: any): string {
  return String(v ?? '').toLowerCase();
}
