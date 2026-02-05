/**
 * AuditGraph TypeScript Type Definitions
 *
 * This module defines all TypeScript interfaces used throughout the React
 * frontend application. These types ensure type safety when working with
 * API responses and component props.
 *
 * Core Domain Types:
 *   - Identity: Azure identity (SPN, user, managed identity)
 *   - RoleAssignment: Azure RBAC role assignment
 *   - GraphPermission: Microsoft Graph API permission
 *   - DiscoveryRun: Discovery execution record
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

/**
 * Represents a discovered Azure identity.
 *
 * Identities can be service principals, users, or managed identities.
 * Each identity has associated role assignments, permissions, and
 * risk assessment data.
 */
export interface Identity {
  identity_id: string;
  display_name: string;
  identity_type: string;
  source?: string;
  risk_level: string;
  credential_status?: string;
  credential_count?: number;
  next_expiry?: string;
  credential_risk?: string;
  activity_status?: string;
  credential_expiration?: string;
  created_datetime?: string;
  role_count?: number;
  app_id?: string;
  object_id?: string;
  risk_reasons?: string;
  last_sign_in?: string;
  enabled?: boolean;
  roles?: RoleAssignment[];
  graph_permissions?: GraphPermission[];
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
