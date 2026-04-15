/**
 * Identity State — architecture-derived state for every identity.
 *
 * AuditGraph ALWAYS knows what an identity IS, what it CAN DO,
 * how it AUTHENTICATES, and who OWNS it. These facts are derivable
 * from Azure Resource Graph + Entra ID state. No logs required.
 *
 * This function ALWAYS returns a meaningful label.
 * "No activity signals" does not exist.
 */

export type IdentityStateColor = 'teal' | 'orange' | 'amber' | 'red' | 'green';

export interface IdentityState {
  label: string;
  sublabel: string;
  color: IdentityStateColor;
  source: string;
}

export const STATE_COLORS: Record<IdentityStateColor, {
  text: string;
  bg: string;
  border: string;
  hex: string;
}> = {
  teal:   { text: 'text-teal-600',   bg: 'bg-teal-50',   border: 'border-teal-200',   hex: '#0d9488' },
  orange: { text: 'text-orange-600', bg: 'bg-orange-50', border: 'border-orange-200', hex: '#ea580c' },
  amber:  { text: 'text-amber-600',  bg: 'bg-amber-50',  border: 'border-amber-200',  hex: '#d97706' },
  red:    { text: 'text-red-600',    bg: 'bg-red-50',    border: 'border-red-200',    hex: '#dc2626' },
  green:  { text: 'text-green-600',  bg: 'bg-green-50',  border: 'border-green-200',  hex: '#16a34a' },
};

function fmtDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
  });
}

/** Input shape — works with both list-level and detail-level data. */
export interface IdentityStateInput {
  enabled?: boolean;
  identity_category?: string;
  role_count?: number;
  privilege_tier?: number | string;
  effective_scope?: string;
  federated_workload_type?: string | null;
  federated_workload_name?: string | null;
  is_federated?: boolean;
  associated_resource_name?: string | null;
  owner_display_name?: string | null;
  activity_status?: string;
  last_activity_date?: string | null;
  last_activity_source?: string | null;
  created_datetime?: string | null;
  credential_count?: number;
  credential_risk?: string;
}

/**
 * Normalize a federated issuer string to a human-readable label.
 * E.g. "https://token.actions.githubusercontent.com" → "GitHub Actions"
 */
export function normalizeIssuer(raw: string | null | undefined): string {
  if (!raw) return 'OIDC';
  const s = raw.toLowerCase();
  if (s.includes('github') || s.includes('actions.githubusercontent'))
    return 'GitHub Actions';
  if (s.includes('terraform') || s.includes('app.terraform.io'))
    return 'Terraform Cloud';
  if (s.includes('gitlab'))
    return 'GitLab CI';
  if (s.includes('azure') || s.includes('sts.windows.net'))
    return 'Azure AD';
  if (s.includes('google') || s.includes('accounts.google'))
    return 'Google Cloud';
  if (s.includes('bitbucket'))
    return 'Bitbucket Pipelines';
  // Fall back to cleaned-up version
  return raw
    .replace(/^https?:\/\//, '')
    .replace(/\/$/, '')
    .replace(/token\.actions\.githubusercontent\.com/, 'GitHub Actions')
    || 'OIDC';
}

export function deriveIdentityState(identity: IdentityStateInput): IdentityState {
  const enabled = identity.enabled !== false; // default true
  const roleCount = identity.role_count ?? 0;
  const category = (identity.identity_category || '').toLowerCase();
  const tier = typeof identity.privilege_tier === 'string'
    ? parseInt(String(identity.privilege_tier).replace('T', ''), 10) || 3
    : (identity.privilege_tier ?? 3);
  const scope = identity.effective_scope || '';

  // ── 1. Disabled account ──────────────────────────────────────────────
  if (!enabled) {
    if (roleCount > 0) {
      return {
        label: 'Disabled',
        sublabel: `${roleCount} role${roleCount !== 1 ? 's' : ''} still assigned`,
        color: 'red',
        source: 'Entra account state + ARM RBAC',
      };
    }
    return {
      label: 'Disabled',
      sublabel: 'Access cleared',
      color: 'green',
      source: 'Entra account state',
    };
  }

  // ── 2. System Managed Identity — active as long as resource runs ─────
  if (category === 'managed_identity_system') {
    const resource = identity.associated_resource_name;
    return {
      label: 'Bound',
      sublabel: resource ? `Attached to ${resource}` : 'System-assigned identity',
      color: 'teal',
      source: 'ARM resource graph',
    };
  }

  // ── 3. Federated OIDC credential ────────────────────────────────────
  if (identity.federated_workload_type || identity.is_federated) {
    const raw = identity.federated_workload_type
      || identity.federated_workload_name || '';
    const issuer = raw
      .replace(/github[_-]?actions?/i, 'GitHub Actions')
      .replace(/terraform[_-]?cloud/i, 'Terraform Cloud')
      || 'OIDC';
    return {
      label: 'Federated',
      sublabel: `OIDC via ${issuer}`,
      color: 'teal',
      source: 'Entra federated credentials',
    };
  }

  // ── 4. Guest / External user ────────────────────────────────────────
  if (category === 'guest') {
    const since = identity.created_datetime;
    return {
      label: 'External',
      sublabel: since
        ? `Unreviewed since ${fmtDate(since)}`
        : 'Unreviewed — no review on record',
      color: 'amber',
      source: 'Entra guest state',
    };
  }

  // ── 5. Privileged identity (T0/T1) ─────────────────────────────────
  if (tier <= 1 && roleCount > 0) {
    const tierLabel = tier === 0
      ? 'Global Admin / Owner' : 'Contributor / Elevated';
    const scopeLabel = scope && scope !== 'none' ? scope : 'tenant-wide';
    return {
      label: 'Privileged',
      sublabel: `${tierLabel} \u00b7 ${scopeLabel}`,
      color: 'orange',
      source: 'ARM RBAC + Entra roles',
    };
  }

  // ── 6. Has roles ────────────────────────────────────────────────────
  if (roleCount > 0) {
    const hasAuthEvidence =
      identity.last_activity_source === 'entra_signin_log'
      || identity.last_activity_source === 'graph_signin'
      || identity.last_activity_source === 'entra_noninteractive';

    if (!hasAuthEvidence) {
      return {
        label: 'Provisioned',
        sublabel: `${roleCount} role${roleCount !== 1 ? 's' : ''} \u2014 no auth observed`,
        color: 'amber',
        source: 'ARM role assignments',
      };
    }

    return {
      label: 'Active',
      sublabel: `${roleCount} role${roleCount !== 1 ? 's' : ''} assigned`,
      color: 'teal',
      source: 'ARM RBAC',
    };
  }

  // ── 7. User MSI without explicit roles (rare) ──────────────────────
  if (category === 'managed_identity_user') {
    return {
      label: 'Bound',
      sublabel: 'User-assigned managed identity',
      color: 'teal',
      source: 'ARM resource graph',
    };
  }

  // ── 8. No roles, no owner — ungoverned ──────────────────────────────
  if (!identity.owner_display_name) {
    return {
      label: 'Ungoverned',
      sublabel: 'No owner \u00b7 no role assignments',
      color: 'red',
      source: 'Entra ownership graph',
    };
  }

  // ── 9. Has owner, no roles ──────────────────────────────────────────
  return {
    label: 'Idle',
    sublabel: 'No role assignments',
    color: 'amber',
    source: 'Entra account state',
  };
}
