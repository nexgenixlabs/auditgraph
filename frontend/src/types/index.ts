// src/types/index.ts

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
}

export interface RoleAssignment {
  role_name: string;
  scope: string;
  scope_type: string;
  created_on?: string;
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
