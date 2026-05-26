import React, { useState } from 'react';

interface LegendItem {
  term: string;
  color: string;
  definition: string;
}

const IDENTITY_STATES: LegendItem[] = [
  { term: 'Ghost', color: 'var(--orange, #FF7216)', definition: 'An identity that is disabled, deleted, or deprovisioned in the identity provider but still retains live access or role assignments. Access was never fully revoked. Ghost is the highest-priority classification \u2014 it overrides all other identity states.' },
  { term: 'Dormant', color: 'var(--amber, #F59E0B)', definition: 'An identity with no observed authentication or activity in the past 90 days (default \u2014 configurable in Settings \u2192 Governance) while retaining active access assignments. Applies to human and external identities only.' },
  { term: 'Orphaned', color: 'var(--red, #E8465A)', definition: 'An identity with no assigned owner, custodian, or accountable party responsible for its lifecycle and access decisions.' },
  { term: 'Over-Privileged', color: 'var(--red, #E8465A)', definition: 'An identity whose assigned permissions materially exceed the access required for its intended business or operational function, based on observed usage.' },
  { term: 'Provisioned \u2014 Never Used', color: 'var(--text-muted, #484F58)', definition: 'An identity that has been provisioned and granted access but has no observed authentication or activity since it was created.' },
];

const RISK_SEVERITY: LegendItem[] = [
  { term: 'Critical', color: '#E8465A', definition: 'Immediate threat \u2014 identity holds broad or privileged access with active risk signals. Requires immediate action.' },
  { term: 'High', color: '#FF7216', definition: 'Significant exposure \u2014 identity holds elevated access with risk findings that require prompt remediation.' },
  { term: 'Medium', color: '#F59E0B', definition: 'Moderate exposure \u2014 identity has access concerns that should be addressed within 30 days.' },
  { term: 'Low', color: 'var(--text-secondary, #8B949E)', definition: 'Minimal risk \u2014 identity has minor policy deviations with no immediate threat to the environment.' },
  { term: 'Info', color: 'var(--text-muted, #484F58)', definition: 'Informational \u2014 identity is flagged for awareness but poses no active security risk at this time.' },
];

const IDENTITY_TYPES: LegendItem[] = [
  { term: 'Human Identity', color: 'var(--teal, #24A2A1)', definition: 'A person within or affiliated with the organization \u2014 employee, contractor, administrator, or external collaborator \u2014 with a user account in the identity provider.' },
  { term: 'Application Identity', color: 'rgba(36,162,161,0.6)', definition: 'A non-human identity used by applications, services, or automation to authenticate and access resources programmatically.' },
  { term: 'Managed Workload Identity', color: 'var(--text-secondary, #8B949E)', definition: 'A cloud-native identity automatically managed and assigned to a compute resource for resource-to-resource authentication. No credentials to manage or rotate.' },
  { term: 'Guest / External', color: 'rgba(245,158,11,0.6)', definition: 'An identity originating outside the organization that has been granted controlled access to internal resources. Requires regular access review and certification.' },
  { term: 'Machine Identity (NHI)', color: 'var(--text-muted, #484F58)', definition: 'Any non-human identity used by software, infrastructure, workloads, or automation to access systems and resources. Includes application identities, managed workload identities, and service accounts across all cloud providers.' },
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
