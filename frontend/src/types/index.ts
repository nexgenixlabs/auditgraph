/**
 * AuditGraph TypeScript Type Definitions
 *
 * This module defines all TypeScript interfaces used throughout the React
 * frontend application. These types ensure type safety when working with
 * API responses and component props.
 *
 * Core Domain Types:
 *   - Identity: Cloud identity (Azure, AWS, GCP)
 *   - RoleAssignment: Azure RBAC role assignment
 *   - GraphPermission: Microsoft Graph API permission
 *   - DiscoveryRun: Snapshot execution record
 *   - Stats: Dashboard statistics summary
 *
 * API Response Types:
 *   - StatsResponse: Response from /api/stats
 *   - IdentitiesResponse: Response from /api/identities
 *   - RisksResponse: Response from /api/risks
 *   - RunsResponse: Response from /api/runs
 *   - DriftReport: Response from /api/drift/:run_id
 *
 * These types mirror the backend data models and ensure consistent
 * data handling across the frontend application.
 */

// Multi-cloud type definitions
export type CloudProvider = 'azure' | 'aws' | 'gcp';
export type NormalizedIdentityType = 'human' | 'workload' | 'app' | 'group' | 'role' | 'system';
export type IdentityStatus = 'active' | 'disabled' | 'deleted';

/**
 * Represents a discovered cloud identity.
 *
 * Identities can be service principals, users, managed identities, etc.
 * Supports multi-cloud: Azure, AWS, GCP.
 * Each identity has associated role assignments, permissions, and
 * risk assessment data.
 */
export interface Identity {
  // Core identity fields
  identity_id: string;
  display_name: string;
  identity_type: string;
  identity_category?: string;  // Legacy category (kept for backwards compatibility)
  source?: string;
  permission_plane?: 'rbac' | 'entra_id' | 'iam' | 'org_policy';
  risk_level: string;

  // Credential fields
  credential_status?: string;
  credential_count?: number;
  next_expiry?: string;
  credential_risk?: string;
  credential_expiration?: string;

  // Activity fields
  activity_status?: string;
  created_datetime?: string;
  last_sign_in?: string;

  // Role fields
  role_count?: number;
  roles?: RoleAssignment[];
  graph_permissions?: GraphPermission[];

  // Azure-specific fields (legacy)
  app_id?: string;
  object_id?: string;
  risk_reasons?: string;
  enabled?: boolean;

  // Multi-cloud normalized fields
  cloud?: CloudProvider;
  normalized_identity_type?: NormalizedIdentityType;
  canonical_name?: string;
  principal_id?: string;
  tenant_or_org_id?: string;
  is_federated?: boolean;
  status?: IdentityStatus;
  last_seen_auth?: string | null;
  tags?: Record<string, string>;

  // Ownership fields
  owner_display_name?: string | null;
  owner_count?: number;
  owners?: Owner[];

  // Risk scoring fields (enhanced Phase 10C)
  risk_score?: number;
  api_permission_count?: number;
  app_role_count?: number;
}

/**
 * Represents an owner of an application/service principal.
 * Used for accountability tracking.
 */
export interface Owner {
  owner_object_id: string;
  owner_display_name?: string;
  owner_upn?: string;
  owner_type: 'user' | 'servicePrincipal' | 'group';
  ownership_type: 'application' | 'servicePrincipal';
  is_primary_owner?: boolean;
}

export interface RoleAssignment {
  role_name: string;
  scope: string;
  scope_type: string;
  created_on?: string;
}

export interface GraphPermission {
  permission_name: string;
  permission_description?: string;
  resource_name?: string;
  risk_level?: string;
  permission_type?: string;
  permission_id?: string;
  consent_type?: string;
}

export interface DiscoveryRun {
  id: number;
  subscription_id?: string;
  subscription_name?: string;
  started_at?: string;
  completed_at?: string;
  status: string;
  total_identities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
}

export interface Stats {
  total_identities: number;
  actionable_identities: number;
  total_risks: number;
  critical_risks: number;
  high_risks: number;
  medium_risks: number;
  low_risks: number;
  last_scan?: string;
}

// API Response types (what the backend actually returns)
export interface StatsResponse {
  latest_run: {
    id: number;
    total_identities: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    completed_at: string;
  };
  total_discovery_runs: number;
}

export interface IdentitiesResponse {
  count: number;
  run_id: number;
  identities: Identity[];
}

export interface RisksResponse {
  count: number;
  run_id: number;
  risks: Identity[];
}

export interface RunsResponse {
  count: number;
  runs: DiscoveryRun[];
}

export interface DriftChange {
  change_type: string;
  identity_id?: string;
  identity_name?: string;
  old_value?: any;
  new_value?: any;
  details: string;
}

export interface DriftReport {
  current_run_id: number;
  previous_run_id: number;
  changes: {
    new_identities: number;
    removed_identities: number;
    permission_changes: number;
    risk_changes: number;
    credential_changes: number;
    details: any;
  };
}

// Phase 39: Advanced Query Builder types

export type QueryOperator =
  | 'equals'
  | 'not_equals'
  | 'contains'
  | 'not_contains'
  | 'greater_than'
  | 'less_than'
  | 'in'
  | 'not_in'
  | 'is_empty'
  | 'is_not_empty';

export type QueryFieldType = 'string' | 'number' | 'boolean' | 'date';

export interface QueryFieldDefinition {
  name: string;
  type: QueryFieldType;
  label: string;
}

export interface QueryCondition {
  id: string;
  field: string;
  operator: QueryOperator;
  value: any;
}

export interface QueryGroup {
  id: string;
  conditions: QueryCondition[];
}

export interface AdvancedQuery {
  groups: QueryGroup[];
}

export interface QueryFieldsResponse {
  fields: QueryFieldDefinition[];
  operators: QueryOperator[];
  value_suggestions: Record<string, string[]>;
}
