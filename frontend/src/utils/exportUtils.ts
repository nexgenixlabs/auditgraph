/**
 * AuditGraph Export Utilities (Phase 33)
 *
 * Shared functions for CSV/JSON file generation and download.
 */

export interface CsvColumn {
  key: string;
  header: string;
}

export function objectsToCSV(data: Record<string, unknown>[], columns: CsvColumn[]): string {
  const headers = columns.map(c => c.header);
  const rows = data.map(row =>
    columns.map(c => {
      const val = row[c.key];
      const str = val === null || val === undefined ? '' : String(val);
      return `"${str.replace(/"/g, '""')}"`;
    }).join(',')
  );
  return [headers.join(','), ...rows].join('\n');
}

export function downloadBlob(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function downloadCSV(data: Record<string, unknown>[], columns: CsvColumn[], filename: string): void {
  const csv = objectsToCSV(data, columns);
  downloadBlob(csv, filename, 'text/csv;charset=utf-8;');
}

export function downloadJSON(data: unknown, filename: string): void {
  const json = JSON.stringify(data, null, 2);
  downloadBlob(json, filename, 'application/json;charset=utf-8;');
}

export function exportFilename(type: string, format: 'csv' | 'json'): string {
  const date = new Date().toISOString().split('T')[0];
  return `auditgraph-${type}-${date}.${format}`;
}

export const IDENTITY_CSV_COLUMNS: CsvColumn[] = [
  { key: 'display_name', header: 'Display Name' },
  { key: 'identity_id', header: 'Identity ID' },
  { key: 'identity_type', header: 'Type' },
  { key: 'identity_category', header: 'Category' },
  { key: 'cloud', header: 'Cloud' },
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
  { key: 'enabled', header: 'Enabled' },
];

export const COMPLIANCE_CSV_COLUMNS: CsvColumn[] = [
  { key: 'framework', header: 'Framework' },
  { key: 'control_id', header: 'Control ID' },
  { key: 'control_name', header: 'Control Name' },
  { key: 'status', header: 'Status' },
  { key: 'current_value', header: 'Current Value' },
  { key: 'threshold', header: 'Required' },
  { key: 'detail', header: 'Detail' },
];

export const DRIFT_CSV_COLUMNS: CsvColumn[] = [
  { key: 'change_type', header: 'Change Type' },
  { key: 'identity_id', header: 'Identity ID' },
  { key: 'display_name', header: 'Display Name' },
  { key: 'detail', header: 'Detail' },
  { key: 'risk_level', header: 'Risk Level' },
];
