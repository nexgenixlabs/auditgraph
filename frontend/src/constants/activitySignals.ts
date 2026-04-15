/**
 * Activity Signals — human-readable labels for last_activity_source values.
 *
 * These map the internal source keys (stored in the identities table)
 * to display strings shown in Trust Signals sections and tooltips.
 */

export const SOURCE_LABELS: Record<string, string> = {
  entra_signin_log: 'Entra sign-in logs',
  graph_signin: 'Graph API sign-in activity',
  entra_noninteractive: 'Non-interactive sign-in',
  role_assignment: 'Role assignment date',
  credential_rotation: 'Credential rotation',
  federated_credential: 'Federated credential',
  created_date: 'Creation date only',
  auditgraph_scan: 'AuditGraph behavioral scan',
  aad_audit: 'AAD audit log',
  static_analysis_only: 'Static analysis',
  arm_activity_log: 'ARM Activity Log',
  directory_audit_log: 'Directory audit log',
  scanner_self: 'AuditGraph scanner (self-reported)',
};

/**
 * Get a human-readable label for an activity source key.
 * Falls back to cleaned-up version of the raw key.
 */
export function getSourceLabel(source: string | null | undefined): string {
  if (!source) return 'Architecture signals';
  return SOURCE_LABELS[source] || source.replace(/_/g, ' ');
}

/**
 * Format an ISO date string as a relative date (e.g. "3d ago", "Yesterday").
 * Returns "—" for null/invalid dates.
 */
export function formatRelativeDate(
  dateStr: string | null | undefined
): string {
  if (!dateStr) return '\u2014';
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) return '\u2014';
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffDays = Math.floor(diffMs / 86_400_000);
  if (diffDays < 0) return 'Future date';
  if (diffDays === 0) return 'Today';
  if (diffDays === 1) return 'Yesterday';
  if (diffDays < 7) return `${diffDays}d ago`;
  if (diffDays < 30) return `${diffDays}d ago`;
  if (diffDays < 365) return `${diffDays}d ago`;
  const years = Math.floor(diffDays / 365);
  return `${years}y ago`;
}

/**
 * Well-known GitHub Actions runner IP prefixes.
 * Used to label IPs as "GitHub Actions runner" in the UI.
 */
const GITHUB_ACTIONS_IP_PREFIXES = [
  '4.148.', '4.175.', '4.196.',
  '20.1.', '20.7.', '20.14.',
  '20.72.', '40.74.', '52.168.',
  '52.175.', '52.232.', '52.240.',
];

/**
 * Enrich an IP address with a display label and tooltip.
 * Detects GitHub Actions runner IPs and scanner self-reported IPs.
 */
export function enrichIpLabel(
  ip: string | null | undefined,
  source: string | null | undefined,
  operation?: string | null,
  date?: string | null,
): { display: string; tooltip: string; isGitHub: boolean } {
  if (!ip) {
    return { display: '\u2014', tooltip: 'No IP observed', isGitHub: false };
  }

  const parts: string[] = [];
  if (date) {
    parts.push(new Date(date).toLocaleString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    }));
  }

  const isGitHub = GITHUB_ACTIONS_IP_PREFIXES.some(prefix => ip.startsWith(prefix));

  if (isGitHub) {
    parts.push('GitHub Actions runner \u00b7 GitHub-owned IP range');
  } else if (source) {
    parts.push(`Source: ${SOURCE_LABELS[source] ?? source}`);
  }
  if (operation) parts.push(operation);

  return {
    display: ip,
    tooltip: parts.join(' \u00b7 ') || ip,
    isGitHub,
  };
}

/**
 * Return a color key based on how recent the last-seen date is.
 */
export function lastSeenColor(
  dateStr: string | null | undefined
): string {
  if (!dateStr) return 'muted';
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return 'muted';
  const diffDays = Math.floor(
    (Date.now() - d.getTime()) / 86_400_000
  );
  if (diffDays <= 7) return 'green';
  if (diffDays <= 30) return 'teal';
  if (diffDays <= 89) return 'amber';
  return 'red';
}
