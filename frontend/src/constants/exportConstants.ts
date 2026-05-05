/**
 * Canonical CSV export column definitions — single source of truth.
 * Must match backend handlers.py streaming export headers exactly.
 */

export interface CsvColumnDef {
  key: string;
  header: string;
}

/**
 * 25-column identity CSV schema (matches backend /api/export/identities).
 * All CSV export paths must use this constant — no inline column arrays.
 */
export const IDENTITY_CSV_COLUMNS: CsvColumnDef[] = [
  { key: 'display_name', header: 'Display Name' },
  { key: 'identity_id', header: 'Identity ID' },
  { key: 'identity_type', header: 'Type' },
  { key: 'identity_category', header: 'Category' },
  { key: 'subscription_name', header: 'Subscription Name' },
  { key: 'subscription_id', header: 'Subscription ID' },
  { key: 'cloud', header: 'Cloud' },
  { key: 'permission_plane', header: 'Permission Plane' },
  { key: 'risk_level', header: 'Risk Level' },
  { key: 'risk_score', header: 'Risk Score' },
  { key: 'privilege_tier', header: 'Privilege Tier' },
  { key: 'entra_role_count', header: 'Entra Roles' },
  { key: 'rbac_role_count', header: 'RBAC Roles' },
  { key: 'api_permission_count', header: 'Graph API Perms' },
  { key: 'credential_count', header: 'Credentials' },
  { key: 'credential_status', header: 'Credential Status' },
  { key: 'credential_expiration', header: 'Credential Expiry' },
  { key: 'created_datetime', header: 'Created' },
  { key: 'last_seen_auth', header: 'Last Active' },
  { key: 'activity_status', header: 'Activity Status' },
  { key: 'owner_display_name', header: 'Owner' },
  { key: 'ca_coverage_status', header: 'CA Coverage' },
  { key: 'ca_mfa_enforced', header: 'CA MFA Enforced' },
  { key: 'enabled', header: 'Enabled' },
  { key: 'risk_reasons', header: 'Risk Reasons' },
];
