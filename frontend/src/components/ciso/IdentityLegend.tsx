import React, { useState } from 'react';

interface LegendItem {
  term: string;
  color: string;
  definition: string;
}

const IDENTITY_STATES: LegendItem[] = [
  { term: 'Dormant', color: 'var(--amber, #F59E0B)', definition: 'A human identity with no sign-in activity in the past 90 days, but still holds active role assignments.' },
  { term: 'Ghost', color: 'var(--orange, #FF7216)', definition: 'An identity that is disabled or deleted in Azure AD but still has live RBAC role assignments — access not revoked.' },
  { term: 'Orphaned', color: 'var(--red, #E8465A)', definition: 'An identity with no assigned owner and no accountable person responsible for its access.' },
  { term: 'Over-Privileged', color: 'var(--red, #E8465A)', definition: 'An identity whose assigned roles grant significantly more access than required for its function.' },
  { term: 'Provisioned', color: 'var(--text-muted, #484F58)', definition: 'An identity that exists and has roles assigned but has never been used — no authentication observed.' },
];

const RISK_SEVERITY: LegendItem[] = [
  { term: 'Critical', color: '#E8465A', definition: 'Immediate threat — identity has tenant-wide or subscription-level privileged access with active risk signals.' },
  { term: 'High', color: '#FF7216', definition: 'Significant exposure — identity holds elevated roles with recent risk findings requiring prompt action.' },
  { term: 'Medium', color: '#F59E0B', definition: 'Moderate exposure — identity has access concerns that should be addressed within 30 days.' },
  { term: 'Low', color: 'var(--text-secondary, #8B949E)', definition: 'Minimal risk — identity has minor policy deviations with no immediate threat to the environment.' },
  { term: 'Info', color: 'var(--text-muted, #484F58)', definition: 'Informational — identity is flagged for awareness but poses no active security risk at this time.' },
];

const IDENTITY_TYPES: LegendItem[] = [
  { term: 'Human Identity', color: 'var(--teal, #24A2A1)', definition: 'A person in your organization — employee, contractor, or administrator — with an Azure AD user account.' },
  { term: 'Service Principal', color: 'rgba(36,162,161,0.6)', definition: 'An application or service identity used for automated workloads, CI/CD pipelines, and programmatic access.' },
  { term: 'Managed Identity', color: 'var(--text-secondary, #8B949E)', definition: 'An Azure-native identity assigned to a resource (VM, function, container) — no credentials to manage.' },
  { term: 'Guest User', color: 'rgba(245,158,11,0.6)', definition: 'An external user from outside your organization invited to access resources — requires regular access review.' },
  { term: 'Machine Identity (NHI)', color: 'var(--text-muted, #484F58)', definition: 'Any non-human identity: service principals, managed identities, and workload identities collectively.' },
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
      </div>
    </div>
  );
}

export default IdentityLegend;
