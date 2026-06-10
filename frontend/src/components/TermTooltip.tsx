/**
 * AG-POLISH-C (2026-06-10) — Reusable jargon tooltip.
 *
 * Every term that confused the pilot customer ("PIM", "FIC", "Tier T0",
 * "blast radius", "NHI") gets a one-pass definition on hover. Anchored
 * to the term itself with a dotted underline so the affordance is
 * obvious without cluttering the layout.
 *
 * Pattern: <TermTooltip term="PIM" />  → renders "PIM" with hover.
 * Or with explicit copy: <TermTooltip term="PIM" definition="..." />.
 */
import React from 'react';

// SSOT for the canonical definitions. Add a term once; every page using
// <TermTooltip term="..." /> gets the same copy.
const DEFINITIONS: Record<string, string> = {
  PIM: 'Privileged Identity Management. Microsoft Entra feature that lets identities be ELIGIBLE for a privileged role and activate it just-in-time, rather than holding the role permanently. Requires Entra ID P2.',
  FIC: 'Federated Identity Credential. An OIDC trust relationship that lets an external workload (GitHub Actions, Terraform Cloud, Azure DevOps) authenticate to an Entra App Registration as a service principal without storing a secret. Eliminates static credentials but expands the trust surface.',
  NHI: 'Non-Human Identity. Any identity that is not a person: service principals, managed identities, workload identities, CI/CD identities, AI agents, automation accounts.',
  SPN: 'Service Principal. The Entra ID representation of an App Registration when it is granted permissions to access resources. The "identity" half of an Application Registration.',
  MI: 'Managed Identity. An Entra identity automatically provisioned and rotated by Azure for a specific resource (system-assigned) or for explicit assignment to multiple resources (user-assigned). No credential management required.',
  RBAC: 'Role-Based Access Control. Azure’s authorization model — a role (like Owner / Contributor) is assigned at a scope (subscription / resource group / resource), granting the principal the role’s permissions over that scope.',
  'T0': 'Tier 0 — Highest privilege. Global Administrator, Privileged Role Administrator, Subscription Owner. Compromise = tenant-wide blast radius.',
  'T1': 'Tier 1 — High privilege. User Administrator, Exchange Administrator, Contributor at subscription/RG scope.',
  'T2': 'Tier 2 — Medium privilege. Service-specific contributor roles, Key Vault Crypto Officer, etc.',
  'T3': 'Tier 3 — Low / read-only privilege.',
  'Blast Radius': 'The total set of resources an identity can affect if compromised. Computed transitively from RBAC role assignments at all scopes (resource → RG → subscription → MG → tenant).',
  'CIEM': 'Cloud Infrastructure Entitlement Management. The product category that maps which identity has which permissions on which cloud resources. AuditGraph extends CIEM into the AI workload layer.',
  'CISPM': 'Cloud Identity Security Posture Management. Identity-focused subset of CSPM.',
  'JML': 'Joiner / Mover / Leaver. The three lifecycle moments every IGA tracks. AuditGraph derives J/M/L from architecture signals — no HRIS integration required.',
  'Ghost identity': 'A disabled account that still holds role assignments. The roles aren’t revoked when the account is disabled, so any path that re-enables the account inherits the privilege.',
  'Argus': 'AuditGraph’s AI security analyst. Answers natural-language questions about your identity posture by querying the Identity Security Graph. Cross-cutting across human / NHI / AI / workload.',
  'CATEGORIES_REQUIRING': 'The patent-track mapping that attributes Entra audit log events to specific role assignments. Lets us answer "which roles were ACTUALLY exercised" without an inference rule per role.',
  'Federated only': 'A service principal that authenticates only via Federated Identity Credentials (no client secret, no certificate). Common pattern for GitHub Actions / Terraform Cloud OIDC integrations.',
};

interface TermTooltipProps {
  term: string;
  definition?: string; // overrides the SSOT
  children?: React.ReactNode; // if provided, renders children instead of term
  className?: string;
}

export function TermTooltip({ term, definition, children, className }: TermTooltipProps) {
  const text = definition || DEFINITIONS[term] || '';
  if (!text) {
    // No definition available — render plain text (no hover affordance).
    return <span className={className}>{children || term}</span>;
  }
  return (
    <span
      className={`cursor-help underline decoration-dotted decoration-slate-500 underline-offset-2 ${className || ''}`}
      title={text}
    >
      {children || term}
    </span>
  );
}

export default TermTooltip;
