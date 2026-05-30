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

// \u2500\u2500 Caller IP enrichment \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
//
// Feature D (Founder principle 2026-05-30): when we show "Last 3 callers"
// for an SPN, show what KIND of caller it was \u2014 "GitHub Actions runner",
// "Azure DevOps", "Terraform Cloud", "corp office", etc. \u2014 not just the
// raw IP. Auditors' #1 question is "where is this SPN actually used from?"
// and bare IP strings don't answer that.
//
// Multi-cloud note (P2-B): these constants are Azure-network-centric today
// (GitHub-hosted runners use Azure IPs). When AWS Q3 / GCP Q1 lands, we'll
// add AWS_CODEBUILD_PREFIXES, GCP_CLOUDBUILD_PREFIXES, etc. \u2014 the
// classifyIpOrigin() abstraction below stays the same; only the prefix
// lists grow.

/** GitHub-hosted Actions runners (live in Azure). */
const GITHUB_ACTIONS_IP_PREFIXES = [
  '4.148.', '4.175.', '4.196.',
  '20.1.', '20.7.', '20.14.',
  '20.72.', '40.74.', '52.168.',
  '52.175.', '52.232.', '52.240.',
];

/** Azure DevOps Pipelines hosted-agent IP ranges (subset).
 *  Full list at: https://learn.microsoft.com/en-us/azure/devops/organizations/security/allow-list-ip-url */
const AZURE_DEVOPS_IP_PREFIXES = [
  '13.107.6.', '13.107.9.', '13.107.42.', '13.107.43.',
  '20.36.', '20.37.', '20.38.', '20.39.', '20.40.', '20.41.',
  '20.45.', '20.47.', '20.61.',
  '40.78.', '40.79.', '40.80.', '40.81.', '40.82.',
  '52.150.', '52.151.', '52.155.', '52.156.', '52.157.',
];

/** HashiCorp Terraform Cloud hosted runner ranges. */
const TERRAFORM_CLOUD_IP_PREFIXES = [
  '75.2.', '99.83.', '76.76.21.',
];

/** Generic Microsoft / Azure service IP ranges (catch-all for
 *  Azure-internal service-to-service calls when more-specific
 *  prefixes don't match). */
const AZURE_GENERIC_IP_PREFIXES = [
  '13.', '20.', '40.', '52.', '104.', '168.61.', '168.62.', '168.63.',
];

export type IpOriginKind = 'github_actions' | 'azure_devops' | 'terraform_cloud'
  | 'azure_internal' | 'corporate' | 'unknown';

export interface IpOrigin {
  kind: IpOriginKind;
  label: string;
  tooltip: string;
}

/**
 * Classify an IP into a known origin category. Pure function \u2014 no DB / no
 * settings dependency. Falls through to 'unknown' when nothing matches.
 *
 * `corpIpPrefixes` is an optional list of org-configured corporate office
 * IP ranges (loaded from settings). Future-D scope: surface a settings
 * page so customers can add their corp ranges and see "Corp office" labels.
 */
export function classifyIpOrigin(
  ip: string,
  corpIpPrefixes: string[] = [],
): IpOrigin {
  // Corp office check first \u2014 most specific
  if (corpIpPrefixes.length > 0 && corpIpPrefixes.some(p => ip.startsWith(p))) {
    return {
      kind: 'corporate',
      label: 'Corp office',
      tooltip: 'Org-configured corporate IP range',
    };
  }
  if (GITHUB_ACTIONS_IP_PREFIXES.some(p => ip.startsWith(p))) {
    return {
      kind: 'github_actions',
      label: 'GitHub Actions',
      tooltip: 'GitHub-hosted Actions runner \u2014 automated CI/CD pipeline',
    };
  }
  if (AZURE_DEVOPS_IP_PREFIXES.some(p => ip.startsWith(p))) {
    return {
      kind: 'azure_devops',
      label: 'Azure DevOps',
      tooltip: 'Azure DevOps hosted agent \u2014 pipeline or release',
    };
  }
  if (TERRAFORM_CLOUD_IP_PREFIXES.some(p => ip.startsWith(p))) {
    return {
      kind: 'terraform_cloud',
      label: 'Terraform Cloud',
      tooltip: 'Terraform Cloud hosted runner \u2014 IaC apply',
    };
  }
  if (AZURE_GENERIC_IP_PREFIXES.some(p => ip.startsWith(p))) {
    return {
      kind: 'azure_internal',
      label: 'Azure service',
      tooltip: 'Microsoft / Azure-internal IP range',
    };
  }
  return {
    kind: 'unknown',
    label: 'External',
    tooltip: 'IP not in any known cloud-provider or org-configured range',
  };
}

/** Tailwind color classes for each origin kind \u2014 keep visual coding consistent. */
export const IP_ORIGIN_COLORS: Record<IpOriginKind, string> = {
  github_actions:  'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
  azure_devops:    'bg-blue-500/15 text-blue-300 border-blue-500/30',
  terraform_cloud: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  azure_internal:  'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  corporate:       'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  unknown:         'bg-slate-500/15 text-slate-300 border-slate-500/30',
};

/**
 * Enrich an IP address with a display label and tooltip.
 * Detects GitHub Actions, Azure DevOps, Terraform Cloud, Azure-internal,
 * and corporate IP ranges. (Was: GitHub-only.)
 *
 * Backward compatible: returns `isGitHub` for legacy call sites.
 */
export function enrichIpLabel(
  ip: string | null | undefined,
  source: string | null | undefined,
  operation?: string | null,
  date?: string | null,
  corpIpPrefixes: string[] = [],
): { display: string; tooltip: string; isGitHub: boolean; origin: IpOrigin } {
  if (!ip) {
    const u: IpOrigin = { kind: 'unknown', label: '\u2014', tooltip: 'No IP observed' };
    return { display: '\u2014', tooltip: 'No IP observed', isGitHub: false, origin: u };
  }

  const origin = classifyIpOrigin(ip, corpIpPrefixes);
  const parts: string[] = [];
  if (date) {
    parts.push(new Date(date).toLocaleString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    }));
  }
  parts.push(origin.tooltip);
  if (source) parts.push(`Source: ${SOURCE_LABELS[source] ?? source}`);
  if (operation) parts.push(operation);

  return {
    display: ip,
    tooltip: parts.join(' \u00b7 '),
    isGitHub: origin.kind === 'github_actions',
    origin,
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
