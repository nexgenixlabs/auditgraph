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
  // AWS
  | 'iam_user'
  | 'iam_role'
  | 'iam_service_linked_role'
  // GCP
  | 'gcp_service_account'
  | 'gcp_user'
  | 'gcp_group'
  | 'gcp_domain'
  | 'gcp_member'
  | 'unknown';

export const IDENTITY_CATEGORIES: Record<string, { label: string; shortLabel: string; description: string; cloud?: string }> = {
  // Azure
  service_principal:        { label: 'Service Principal',      shortLabel: 'SPN',    description: 'App registrations & enterprise apps', cloud: 'azure' },
  managed_identity_user:    { label: 'User Managed Identity',  shortLabel: 'Usr MI', description: 'Reusable across resources', cloud: 'azure' },
  managed_identity_system:  { label: 'System Managed Identity', shortLabel: 'Sys MI', description: 'Azure-managed per resource', cloud: 'azure' },
  human_user:               { label: 'Human User',             shortLabel: 'Human',  description: 'Employees & members', cloud: 'azure' },
  guest:                    { label: 'Guest',                  shortLabel: 'Guest',  description: 'External collaborators', cloud: 'azure' },
  // AWS
  iam_user:                 { label: 'IAM User',              shortLabel: 'IAM',    description: 'AWS IAM user with console/API access', cloud: 'aws' },
  iam_role:                 { label: 'IAM Role',              shortLabel: 'Role',   description: 'AWS IAM role assumable by principals', cloud: 'aws' },
  iam_service_linked_role:  { label: 'Service-Linked Role',   shortLabel: 'SvcRole', description: 'AWS-managed role for services', cloud: 'aws' },
  // GCP
  gcp_service_account:      { label: 'Service Account',       shortLabel: 'SA',     description: 'GCP service account for workloads', cloud: 'gcp' },
  gcp_user:                 { label: 'GCP User',              shortLabel: 'User',   description: 'Google Cloud user identity', cloud: 'gcp' },
  gcp_group:                { label: 'GCP Group',             shortLabel: 'Group',  description: 'Google Cloud IAM group', cloud: 'gcp' },
  gcp_domain:               { label: 'GCP Domain',            shortLabel: 'Domain', description: 'Google Workspace domain binding', cloud: 'gcp' },
  gcp_member:               { label: 'GCP Member',            shortLabel: 'Member', description: 'Other GCP IAM member type', cloud: 'gcp' },
};

/** Categories shown in filter dropdowns */
export const CATEGORY_DISPLAY_ORDER: IdentityCategory[] = [
  // Azure
  'service_principal',
  'managed_identity_system',
  'managed_identity_user',
  'human_user',
  'guest',
  // AWS
  'iam_user',
  'iam_role',
  // GCP
  'gcp_service_account',
  'gcp_user',
];

/** Virtual group: both managed identity types */
export const MANAGED_IDENTITY_GROUP: IdentityCategory[] = [
  'managed_identity_system',
  'managed_identity_user',
];

/** Return only categories whose cloud provider is in the enabled set */
export function getCategoriesForClouds(enabledClouds: string[]): IdentityCategory[] {
  if (!enabledClouds.length) return CATEGORY_DISPLAY_ORDER; // fallback: show all
  return CATEGORY_DISPLAY_ORDER.filter(key => {
    const cloud = IDENTITY_CATEGORIES[key]?.cloud;
    return cloud && enabledClouds.includes(cloud);
  });
}

/** Get the cloud provider key for a category */
export function getCategoryCloud(cat?: string): string | undefined {
  return IDENTITY_CATEGORIES[cat || '']?.cloud;
}

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
  // Azure aliases
  if (v === 'user' || v === 'human user') return 'human_user';
  if (v.includes('user assigned') || v.includes('user-assigned')) return 'managed_identity_user';
  if (v.includes('system assigned') || v.includes('system-assigned')) return 'managed_identity_system';
  if (v === 'service principal' || v === 'serviceprincipal') return 'service_principal';
  // AWS aliases
  if (v === 'iam user' || v === 'iamuser') return 'iam_user';
  if (v === 'iam role' || v === 'iamrole') return 'iam_role';
  if (v === 'service linked role' || v === 'iam_service_linked') return 'iam_service_linked_role';
  // GCP aliases
  if (v === 'service account' || v === 'serviceaccount') return 'gcp_service_account';
  if (v === 'gcp user' || v === 'gcpuser') return 'gcp_user';
  if (v === 'gcp group' || v === 'gcpgroup') return 'gcp_group';
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

// ── Time constants (milliseconds) ───────────────────────────────────
export const TIME_MS = {
  SECOND: 1000,
  MINUTE: 60_000,
  HOUR: 3_600_000,
  DAY: 86_400_000,
} as const;

// ── Activity / Dormancy ──────────────────────────────────────────────

export type DormantStatus = 'yes' | 'idle' | 'never' | 'new' | 'no' | 'likely_active' | 'unknown';

export function getDormantStatus(activityStatus?: string): DormantStatus {
  const act = safeLower(activityStatus);
  if (act === 'stale') return 'yes';
  if (act === 'never_used') return 'never';
  if (act === 'inactive') return 'idle';
  if (act === 'recently_created') return 'new';
  if (act === 'active') return 'no';
  if (act === 'likely_active') return 'likely_active';
  return 'unknown';
}

export const DORMANT_LABELS: Record<DormantStatus, { label: string; color: string; tooltip: string }> = {
  yes:     { label: `Stale ${THRESHOLDS.DORMANT_STALE_DAYS}d+`,                                     color: 'bg-red-100 text-red-700',    tooltip: `No sign-in activity for ${THRESHOLDS.DORMANT_STALE_DAYS}+ days` },
  idle:    { label: `Idle ${THRESHOLDS.DORMANT_IDLE_DAYS}-${THRESHOLDS.DORMANT_STALE_DAYS}d`,        color: 'bg-orange-100 text-orange-700', tooltip: `No sign-in activity for ${THRESHOLDS.DORMANT_IDLE_DAYS}-${THRESHOLDS.DORMANT_STALE_DAYS} days` },
  never:   { label: 'Never Used',                                                                    color: 'bg-red-100 text-red-800',   tooltip: 'Created 30+ days ago with no recorded sign-in' },
  new:     { label: 'New',                                                                           color: 'bg-blue-100 text-blue-700', tooltip: 'Created within the last 30 days' },
  no:      { label: 'Active',                                                                        color: 'bg-green-100 text-green-700', tooltip: 'Sign-in activity within the last 30 days' },
  likely_active: { label: 'Likely Active', color: 'bg-purple-100 text-purple-700', tooltip: 'Azure does not emit sign-in logs for federated identities (GitHub, AKS, Terraform). Activity is inferred based on configuration and role usage.' },
  unknown: { label: 'Unknown',                                                                       color: 'bg-gray-100 text-gray-500', tooltip: 'Sign-in telemetry unavailable — architecture signals used instead' },
};

// ── Data Explanations (Pillar 3: Telemetry Truth) ───────────────────

/** Standard explanations for why data may be missing */
export const DATA_EXPLANATIONS = {
  SIGN_IN:        'Sign-in logs not available in log-independent mode',
  PIM:            'PIM data requires RoleManagement.Read.Directory permission',
  CA_POLICY:      'CA analysis requires Policy.Read.All permission',
  AUDIT_LOG:      'Audit logs require AuditLog.Read.All permission',
  CREDENTIAL_NA:  'Human users authenticate via Entra ID (password/MFA), not app secrets',
  NO_DATA:        'Not yet collected — capture a snapshot',
} as const;

// ── Identity Dashboard V2 ────────────────────────────────────────────

export type PrivilegedLevel = 'privileged' | 'elevated' | 'standard';

export const PRIVILEGED_LEVELS: Record<PrivilegedLevel, { label: string; color: string; tooltip: string }> = {
  privileged: { label: 'Privileged',  color: 'bg-orange-100 text-orange-700 border-orange-200', tooltip: 'Tier 0: Global Admin, Privileged Role Admin, Subscription Owner' },
  elevated:   { label: 'Elevated',    color: 'bg-orange-100 text-orange-700 border-orange-200', tooltip: 'Tier 1: User Admin, Exchange Admin, Contributor' },
  standard:   { label: 'Standard',    color: 'bg-gray-100 text-gray-600 border-gray-200',  tooltip: 'Tier 2-3: Limited or no privileged roles' },
};

// ── Three-Dimension Identity Classification ─────────────────────────

export type LifecycleState = 'Provisioned' | 'Active' | 'Dormant' | 'Disabled';

export const LIFECYCLE_STATE_DISPLAY: Record<LifecycleState, { label: string; color: string; tooltip: string }> = {
  Provisioned: { label: 'Provisioned', color: 'text-blue-500',  tooltip: 'Identity has been provisioned and granted access but has no observed authentication or activity since creation' },
  Active:      { label: 'Active',      color: 'text-green-500', tooltip: 'Identity has recent sign-in or usage activity' },
  Dormant:     { label: 'Dormant',     color: 'text-amber-500', tooltip: 'No observed authentication or activity in the past 90 days (default \u2014 configurable) while retaining active access' },
  Disabled:    { label: 'Disabled',    color: 'text-gray-400',  tooltip: 'Identity is disabled or deprovisioned in the identity provider \u2014 classified as Ghost if access remains' },
};

export type GovernanceState = 'Governed' | 'Ungoverned' | 'Orphaned' | 'Policy Violation';

export const GOVERNANCE_STATE_DISPLAY: Record<GovernanceState, { label: string; badgeClass: string; tooltip: string }> = {
  Governed:             { label: 'Governed',         badgeClass: 'badge-governance-governed',         tooltip: 'Identity has an owner and is in a healthy governance state' },
  Ungoverned:           { label: 'Ungoverned',       badgeClass: 'badge-governance-ungoverned',       tooltip: 'Identity has governance gaps — stale, unreviewed, or missing policy coverage' },
  Orphaned:             { label: 'Orphaned',         badgeClass: 'badge-governance-orphaned',         tooltip: 'Identity has no owner in the directory' },
  'Policy Violation':   { label: 'Policy Violation', badgeClass: 'badge-governance-ungoverned',       tooltip: 'Identity has an active policy breach' },
};

export type PrivilegeLevel = 'Highly Privileged' | 'Privileged' | 'Standard';

export const PRIVILEGE_LEVEL_DISPLAY: Record<PrivilegeLevel, { label: string; badgeClass: string; tooltip: string }> = {
  'Highly Privileged': { label: 'Highly Privileged', badgeClass: 'badge-privilege-high', tooltip: 'Tier 0: Global Admin, Privileged Role Admin, Subscription Owner' },
  Privileged:          { label: 'Privileged',        badgeClass: 'badge-privilege-med',  tooltip: 'Tier 1: User Admin, Exchange Admin, Contributor' },
  Standard:            { label: 'Standard',          badgeClass: '',                     tooltip: 'Tier 2-3: Limited or no privileged roles' },
};

export type EffectiveScope = 'tenant' | 'directory' | 'subscription' | 'resource_group' | 'resource' | 'none';

export const EFFECTIVE_SCOPE_ORDER: Record<EffectiveScope, number> = {
  tenant: 6, directory: 5, subscription: 4, resource_group: 3, resource: 2, none: 1,
};

export const EFFECTIVE_SCOPE_CONFIG: Record<EffectiveScope, { label: string; color: string; icon: string }> = {
  tenant:         { label: 'Tenant',      color: 'bg-orange-100 text-orange-700', icon: 'T' },
  directory:      { label: 'Directory',   color: 'bg-orange-100 text-orange-700', icon: 'D' },
  subscription:   { label: 'Subscription', color: 'bg-orange-100 text-orange-700', icon: 'S' },
  resource_group: { label: 'RG',          color: 'bg-orange-100 text-orange-700', icon: 'R' },
  resource:       { label: 'Resource',    color: 'bg-orange-100 text-orange-700', icon: 'r' },
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
  ungoverned:     { label: 'No Owner',       badgeClass: 'bg-amber-100 text-amber-700' },
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

// ── Compute / Container Resource Types (SSOT — mirrors backend constants.py) ──

export const COMPUTE_RESOURCE_TYPES = {
  APP_SERVICE: 'app_service',
  FUNCTION: 'function_app',
  VIRTUAL_MACHINE: 'virtual_machine',
  LOGIC_APP: 'logic_app',
} as const;

export const CONTAINER_RESOURCE_TYPES = {
  AKS_CLUSTER: 'aks_cluster',
  ACR_REGISTRY: 'acr_registry',
} as const;

export const DATABASE_SERVER_TYPES = {
  AZURE_SQL: 'azure_sql',
  POSTGRESQL: 'postgresql',
  MYSQL: 'mysql',
  COSMOSDB: 'cosmosdb',
} as const;

export const ANALYTICS_WORKSPACE_TYPES = {
  DATABRICKS: 'databricks',
  SYNAPSE: 'synapse',
  AZURE_ML: 'azure_ml',
} as const;

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

// ── Drift Event Intelligence ─────────────────────────────────

export const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-blue-100 text-blue-600',
};

export const DRIFT_EVENT_LABELS: Record<string, string> = {
  identity_added: 'Identity Added',
  identity_removed: 'Identity Removed',
  identity_disabled: 'Identity Disabled',
  identity_reactivated: 'Identity Reactivated',
  role_assigned: 'Role Assigned',
  role_removed: 'Role Removed',
  privilege_escalated: 'Privilege Escalated',
  privilege_deescalated: 'Privilege De-escalated',
  risk_escalated: 'Risk Escalated',
  risk_deescalated: 'Risk De-escalated',
  spn_credential_expired: 'SPN Credential Expired',
  spn_credential_added: 'SPN Credential Added',
  mfa_disabled: 'MFA Disabled',
  owner_changed: 'Owner Changed',
  microsoft_spn_modified: 'Microsoft SPN Modified',
  classification_added: 'Classification Added',
  classification_removed: 'Classification Removed',
  classification_changed: 'Classification Changed',
  attack_path_created: 'Attack Path Created',
  identity_resurrection: 'Identity Resurrection',
};

// ── Helpers ──────────────────────────────────────────────────────────

export function safeLower(v: any): string {
  return String(v ?? '').toLowerCase();
}
