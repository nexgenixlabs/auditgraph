import React, { useState } from 'react';

interface LegendItem {
  term: string;
  color: string;
  definition: string;
}

// P2-A (2026-05-30): Identity Risk Terminology tightening pass.
// Changes from prior version:
//  - Recolored Orphaned (governance gap, not threat) and Over-Privileged
//    (significant exposure, not critical) so the color signals match how
//    they're shown in the inventory tiles (orange/amber, not red).
//  - Added the four states users actually encounter (Active, Stale,
//    Disabled, Privileged) \u2014 terminology that was used in the UI but
//    not defined here, leaving CISOs to guess.
//  - Added a concrete EXAMPLE to each severity (CVSS-style) so the
//    threshold feels real, not abstract.
//  - Replaced "identity provider" with the cloud-agnostic phrasing so
//    the same glossary works when AWS (Q3 2026) and GCP (Q1 2027) land.
//  - Tightened Type definitions to explicitly distinguish Application
//    Identity / Managed Workload Identity / Machine Identity (NHI is the
//    superset; the others are subtypes).

const IDENTITY_STATES: LegendItem[] = [
  { term: 'Ghost', color: '#E8465A', definition: 'A disabled / deleted / deprovisioned identity that still retains live access or role assignments. Access was never fully revoked. Ghost is the highest-priority classification \u2014 it overrides all other identity states. Example: a former employee\'s service principal still holds Contributor 6 months after offboarding.' },
  { term: 'Dormant', color: '#F59E0B', definition: 'An identity with no observed authentication or activity in the past 90 days (configurable in Settings \u2192 Governance) while retaining active access. Applies to humans, guests, and non-human identities.' },
  { term: 'Orphaned', color: '#FF7216', definition: 'An identity with no assigned owner / custodian / accountable party. This is a governance gap, not an active threat \u2014 but it blocks access review and incident response because nobody knows who to ask.' },
  { term: 'Over-Privileged', color: '#FF7216', definition: 'An identity whose assigned permissions materially exceed what it needs based on observed usage. Example: holds Contributor but only used Storage Blob Data Reader operations in the last 90 days \u2014 the unused privilege is removable.' },
  { term: 'Provisioned \u2014 Never Used', color: 'var(--text-secondary, #8B949E)', definition: 'Provisioned and granted access but no observed authentication or activity since creation. Often automation that never shipped, test accounts left behind, or break-glass credentials.' },
  { term: 'Active', color: '#22C55E', definition: 'Recent observed authentication or activity (within the last 30 days). The healthy baseline.' },
  { term: 'Stale', color: '#F59E0B', definition: 'Observed activity 30\u201390 days ago. Approaching dormancy; warrants attention if the identity holds privileged access.' },
  { term: 'Disabled', color: 'var(--text-muted, #484F58)', definition: 'Sign-in is disabled at the identity provider. Without role-assignment cleanup, becomes Ghost \u2014 see above.' },
  { term: 'Privileged', color: '#A78BFA', definition: 'Holds Tier 0 or Tier 1 administrative roles (e.g. Owner, Global Administrator, User Access Administrator). Tier definitions match Microsoft\'s enterprise access model.' },
];

const RISK_SEVERITY: LegendItem[] = [
  { term: 'Critical', color: '#EF4444', definition: 'Immediate threat \u2014 broad or privileged access combined with an active risk signal (exposed secret, expired credential, dormant + Owner, etc.). Requires action now. Risk score 90\u2013100. Example: a service principal with Owner on subscription, no rotated secrets for 400 days, and no owner.' },
  { term: 'High', color: '#F97316', definition: 'Significant exposure \u2014 elevated access with risk findings that need prompt remediation (\u2264 7 days). Risk score 70\u201389. Example: a human user with Contributor and no MFA enforced.' },
  { term: 'Medium', color: '#EAB308', definition: 'Moderate exposure \u2014 should be addressed within 30 days. Risk score 40\u201369.' },
  { term: 'Low', color: '#22C55E', definition: 'Minimal risk \u2014 minor policy deviations with no immediate threat. Risk score 1\u201339.' },
  { term: 'Info', color: 'var(--text-muted, #484F58)', definition: 'Informational only \u2014 no active security risk at this time. Risk score 0.' },
];

const IDENTITY_TYPES: LegendItem[] = [
  { term: 'Human Identity', color: 'var(--teal, #24A2A1)', definition: 'A person \u2014 employee, contractor, administrator, or external collaborator \u2014 with a user account in the cloud identity directory (Entra ID today; IAM Identity Center for AWS, Cloud Identity for GCP when those connectors land).' },
  { term: 'Guest / External', color: 'rgba(245,158,11,0.6)', definition: 'A person originating outside the organization granted controlled access to internal resources. Requires periodic access review and certification.' },
  { term: 'Machine Identity (NHI)', color: 'var(--text-muted, #484F58)', definition: 'Umbrella term for any non-human identity used by software, infrastructure, or automation. Includes Application Identities and Managed Workload Identities below; equivalent to "service accounts" in legacy terminology.' },
  { term: 'Application Identity', color: 'rgba(36,162,161,0.6)', definition: 'NHI subtype: an identity registered to an application or service that authenticates with a secret, certificate, or federated credential (Service Principal in Azure; IAM Role / Programmatic User in AWS; Service Account in GCP).' },
  { term: 'Managed Workload Identity', color: 'var(--text-secondary, #8B949E)', definition: 'NHI subtype: a cloud-managed identity automatically attached to a compute resource (VM, function, container) for resource-to-resource auth. No credentials to manage or rotate (Managed Identity in Azure; Instance Profile in AWS; Workload Identity in GCP).' },
];

function Section({ heading, items }: { heading: string; items: LegendItem[] }) {
  return (
    <div>
      <div style={{
        fontSize: 9, fontWeight: 600, color: 'var(--text-muted, #484F58)',
        letterSpacing: '0.6px', textTransform: 'uppercase' as const,
        paddingBottom: 6, marginBottom: 2,
        borderBottom: '1px solid var(--border, rgba(255,255,255,0.06))',
      }}>
        {heading}
      </div>
      {items.map((item) => (
        <div key={item.term} style={{
          display: 'flex', alignItems: 'flex-start', gap: 8,
          padding: '5px 0',
          borderBottom: '0.5px solid rgba(36,162,161,0.06)',
        }}>
          <span style={{
            width: 7, height: 7, borderRadius: '50%',
            backgroundColor: item.color, marginTop: 4, flexShrink: 0,
          }} />
          <span style={{
            fontSize: 11, fontWeight: 600,
            color: 'var(--text-primary, #E6EDF3)',
            width: 130, flexShrink: 0,
          }}>
            {item.term}
          </span>
          <span style={{
            fontSize: 10, color: 'var(--text-muted, #484F58)',
            lineHeight: 1.45,
          }}>
            {item.definition}
          </span>
        </div>
      ))}
    </div>
  );
}

export function IdentityLegend() {
  const [expanded, setExpanded] = useState(false);

  return (
    <div style={{
      borderTop: '1px solid var(--border, rgba(255,255,255,0.06))',
      padding: '10px 24px',
      background: 'var(--surface1, #0D1117)',
      width: '100%',
    }}>
      <div
        onClick={() => setExpanded((v) => !v)}
        style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          cursor: 'pointer', userSelect: 'none',
        }}
      >
        <span style={{ fontSize: 11, color: 'var(--text-muted, #484F58)', fontWeight: 500 }}>
          &#9432; Identity Risk Terminology
        </span>
        <span style={{ fontSize: 10, color: 'var(--teal, #24A2A1)', cursor: 'pointer' }}>
          {expanded ? '\u25BE Collapse' : '\u25B8 Expand'}
        </span>
      </div>
      <div style={{
        maxHeight: expanded ? 600 : 0,
        transition: 'max-height 0.25s ease',
        overflow: 'hidden',
      }}>
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr 1fr',
          gap: 24,
          paddingTop: 12,
          paddingBottom: 4,
        }}>
          <Section heading="Identity States" items={IDENTITY_STATES} />
          <Section heading="Risk Severity" items={RISK_SEVERITY} />
          <Section heading="Identity Types" items={IDENTITY_TYPES} />
        </div>
        <div style={{ fontSize: 10, color: 'var(--text-muted, #484F58)', fontStyle: 'italic', paddingTop: 8, borderTop: '1px solid var(--border, rgba(255,255,255,0.06))' }}>
          Classification priority: Ghost {'\u2192'} Dormant {'\u2192'} Orphaned {'\u2192'} Over-Privileged {'\u2192'} Never Used. A disabled identity is always Ghost regardless of other states.
        </div>
      </div>
    </div>
  );
}

export default IdentityLegend;
