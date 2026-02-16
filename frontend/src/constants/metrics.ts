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

// ── Helpers ──────────────────────────────────────────────────────────

export function safeLower(v: any): string {
  return String(v ?? '').toLowerCase();
}
