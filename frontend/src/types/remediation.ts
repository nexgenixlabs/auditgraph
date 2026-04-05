/**
 * Remediation Queue types — matches backend API response shapes.
 */

export type RemediationStatus = 'open' | 'in_progress' | 'resolved' | 'dismissed';
export type RemediationSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface RemediationItem {
  id: number;
  organization_id: number;
  attack_path_id: number | null;
  identity_id: number | null;
  title: string;
  description: string | null;
  severity: RemediationSeverity;
  status: RemediationStatus;
  assigned_to: string | null;
  priority_score: number | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  resolution_notes: string | null;
  created_by: string;
  // Joined fields
  identity_display_name: string | null;
  identity_principal_type: string | null;
  identity_lineage_verdict: string | null;
  attack_path_score: number | null;
  path_summary: string | null;
}

export interface RemediationSummary {
  total: number;
  by_status: Record<RemediationStatus, number>;
  by_severity: Record<RemediationSeverity, number>;
  avg_resolution_days: number | null;
}

export interface RemediationListResponse {
  items: RemediationItem[];
  total: number;
  summary: RemediationSummary;
}
