// Shared types for Settings tab components

export interface SettingsData {
  org_name: string;
  discovery_interval_hours: string;
  email_enabled: string;
  email_to: string;
  notify_new_identities: string;
  notify_removed_identities: string;
  notify_permission_changes: string;
  notify_risk_changes: string;
  notify_credential_changes: string;
  notify_weekly_digest: string;
  report_schedule_enabled: string;
  report_schedule_frequency: string;
  report_email_to: string;
  azure_directory_id: string;
  azure_client_id: string;
  azure_client_secret: string;
  aws_access_key_id: string;
  aws_secret_access_key: string;
  aws_region: string;
  gcp_project_id: string;
  gcp_service_account_json: string;
  timezone: string;
  theme: string;
  copilot_api_key: string;
}

export interface StatusData {
  azure_configured: boolean;
  email_configured: boolean;
  scheduler_running: boolean;
  next_run: string | null;
  next_report: string | null;
}

export interface WebhookData {
  id: number;
  name: string;
  url: string;
  secret: string | null;
  event_types: string[];
  headers: Record<string, string> | null;
  enabled: boolean;
  created_at: string | null;
  updated_at: string | null;
  total_deliveries: number;
  successful_deliveries: number;
  last_delivered_at: string | null;
}

export interface WebhookDelivery {
  id: number;
  event_type: string;
  status: string;
  http_status: number | null;
  attempts: number;
  created_at: string | null;
  delivered_at: string | null;
}

export interface CloudProviderConfig {
  enabled: boolean;
  plan: string | null;
}

export interface OrgCloudConfig {
  cloud_providers: Record<string, CloudProviderConfig>;
  addons: Record<string, boolean>;
}

export interface CloudConnection {
  id: number;
  cloud: string;
  label: string;
  status: string;
  azure_directory_id: string | null;
  client_id: string | null;
  last_test_status: string | null;
  last_discovery_at: string | null;
  created_at: string;
  sub_count?: number;
  discovered_count?: number;
  discovery_enabled?: boolean;
  discovery_interval_minutes?: number;
  last_snapshot_started_at?: string | null;
  last_snapshot_completed_at?: string | null;
  metadata?: {
    auto_discovered?: boolean;
    discovered_via?: string;
    discovered_via_label?: string;
    migrated_from_settings?: boolean;
    [key: string]: unknown;
  };
}

export interface ConnectionTestResult {
  status: string;
  message: string;
  subscriptions?: { id: string; name: string }[];
}

export interface RiskRuleCondition {
  field: string;
  op: string;
  value: string | number | boolean;
}

export interface RiskRuleData {
  id: number;
  name: string;
  description: string | null;
  conditions: { all: RiskRuleCondition[] };
  action_type: 'adjust_points' | 'force_level';
  points_adjustment: number;
  force_level: string | null;
  reason_text: string | null;
  enabled: boolean;
  priority: number;
  created_at: string | null;
  updated_at: string | null;
}

export interface UserData {
  id: number;
  username: string;
  display_name: string;
  role: string;
  enabled: boolean;
  last_login_at: string | null;
  created_at: string | null;
  organization_id?: number;
  org_name?: string;
  is_superadmin?: boolean;
}

export interface ApiKeyData {
  id: number;
  key_prefix: string;
  name: string;
  description: string | null;
  role: string;
  enabled: boolean;
  created_by: number | null;
  created_by_name: string | null;
  created_at: string | null;
  last_used_at: string | null;
  expires_at: string | null;
  usage_count: number;
}

export interface ComplianceFramework {
  id: number;
  key: string;
  name: string;
  description: string | null;
  version: string | null;
  enabled: boolean;
  controls: { id: number; control_id: string; name: string }[];
  tier?: string;
  category?: string;
  short_name?: string;
  identity_controls_count?: number;
  total_framework_controls?: number;
  scope_label?: string;
}

export interface SoarPlaybookData {
  id: number;
  name: string;
  description: string | null;
  enabled: boolean;
  trigger_type: string;
  trigger_conditions: Record<string, unknown>;
  action_type: string;
  action_config: Record<string, unknown>;
  integration: string;
  cooldown_minutes: number;
  created_by: string | null;
  created_at: string | null;
  last_triggered_at: string | null;
  trigger_count: number;
}
