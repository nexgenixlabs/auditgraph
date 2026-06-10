/**
 * Effective Access Explorer — Consolidated privilege and RBAC analysis.
 *
 * Wraps the existing RbacHygiene component under the Access Explainability
 * section with updated header. Shows privilege tiers, scope breakdown,
 * standing privilege findings, and RBAC hygiene scoring.
 *
 * Phase 6: Access Explainability consolidation.
 * Canonical route: /effective-access (replaces /rbac-hygiene)
 */
import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
// AG-POLISH-D (2026-06-10)
import { LoadingState } from '../components/LoadingState';
import { useConnection } from '../contexts/ConnectionContext';
import { SnapshotContextHeader } from '../components/ui/SnapshotContextHeader';
import { normalizeScore } from '../utils/identityRiskScore';

// ─── Theme-aware constants ───
const G = {
  bg: 'var(--bg-primary)',
  surface: 'var(--bg-secondary)',
  surfaceBorder: 'var(--border-default)',
  surfaceHover: 'var(--bg-hover)',
  text: 'var(--text-primary)',
  textSecondary: 'var(--text-secondary)',
  textMuted: 'var(--text-tertiary)',
  accent: '#8B5CF6',
  mono: "'JetBrains Mono', monospace",
  severity: {
    critical: '#FF1744', high: '#FF6D00', medium: '#FFB300', low: '#4ADE80', info: '#42A5F5',
  } as Record<string, string>,
  severityBg: {
    critical: 'rgba(255,23,68,0.12)', high: 'rgba(255,109,0,0.12)',
    medium: 'rgba(255,179,0,0.12)', low: 'rgba(74,222,128,0.12)', info: 'rgba(66,165,245,0.12)',
  } as Record<string, string>,
  grade: {
    A: '#4ADE80', B: '#66BB6A', C: '#FFB300', D: '#FF6D00', F: '#FF1744',
  } as Record<string, string>,
  tier: {
    T1: '#FF1744', T2: '#FF6D00', T3: '#FFB300', T4: '#4ADE80',
  } as Record<string, string>,
  tierBg: {
    T1: 'rgba(255,23,68,0.12)', T2: 'rgba(255,109,0,0.12)',
    T3: 'rgba(255,179,0,0.12)', T4: 'rgba(74,222,128,0.12)',
  } as Record<string, string>,
};

const TIER_LABELS: Record<string, string> = {
  T1: 'Critical', T2: 'Elevated', T3: 'Targeted', T4: 'Read-Only',
};

// ─── Types ───
interface RuleSummary {
  label: string;
  severity: string;
  count: number;
  identities_affected: number;
}

interface Finding {
  rule: string;
  rule_label: string;
  severity: string;
  identity_id: string;
  display_name: string;
  detail: string;
}

interface HygieneData {
  overall_score: number;
  grade: string;
  total_identities: number;
  total_findings: number;
  rules: RuleSummary[];
  tier_distribution: Record<string, number>;
  scope_breakdown: Record<string, number>;
  findings: Finding[];
}

// Thin wrapper — re-exports RbacHygiene with updated header context
export default function EffectiveAccessExplorer() {
  const { withConnection, selectedConnectionId } = useConnection();
  const navigate = useNavigate();
  const [data, setData] = useState<HygieneData | null>(null);
  const [loading, setLoading] = useState(true);
  const [expandedRule, setExpandedRule] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  useEffect(() => {
    setLoading(true);
    fetch(withConnection('/api/rbac-hygiene'))
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setData(d); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [withConnection, selectedConnectionId]);

  const filteredFindings = useMemo(() => {
    if (!data) return [];
    let f = data.findings;
    if (severityFilter !== 'all') f = f.filter(x => x.severity === severityFilter);
    if (expandedRule) f = f.filter(x => x.rule === expandedRule);
    return f;
  }, [data, severityFilter, expandedRule]);

  const gradeColor = (g: string) => G.grade[g] || G.textMuted;
  const sevColor = (s: string) => G.severity[s] || G.textMuted;

  if (loading) {
    return (
      <div style={{ minHeight: 400, display: 'flex', alignItems: 'center', justifyContent: 'center', background: G.bg }}>
        {/* AG-POLISH-D (2026-06-10): drop hand-rolled spinner */}
        <LoadingState message="Loading effective access data…" detail="Computing transitive permission closure" />
      </div>
    );
  }

  if (!data) {
    return (
      <div style={{ padding: 32, textAlign: 'center', color: G.textSecondary }}>
        No RBAC hygiene data available. Capture a snapshot first.
      </div>
    );
  }

  return (
    <div style={{ padding: 24, maxWidth: 1400, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 24, fontWeight: 700, color: G.text, margin: 0 }}>Effective Access Explorer</h1>
        <p style={{ fontSize: 14, color: G.textSecondary, marginTop: 4 }}>
          Privilege tier distribution, scope analysis, and RBAC hygiene findings
        </p>
        <SnapshotContextHeader />
      </div>

      {/* Score + Tier Summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr 1fr', gap: 16, marginBottom: 24 }}>
        {/* Overall Score */}
        <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 12, padding: '20px 28px', textAlign: 'center' }}>
          <div style={{ fontSize: 40, fontWeight: 700, fontFamily: G.mono, color: gradeColor(data.grade) }}>{data.grade}</div>
          <div style={{ fontSize: 12, color: G.textSecondary, marginTop: 4 }}>Hygiene Grade</div>
          <div style={{ fontSize: 20, fontWeight: 700, fontFamily: G.mono, color: G.text, marginTop: 8 }}>{normalizeScore(data.overall_score, 10).toFixed(1)}/10</div>
          <div style={{ fontSize: 11, color: G.textMuted }}>{data.total_identities} identities · {data.total_findings} findings</div>
        </div>

        {/* Privilege Tier Distribution */}
        <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 12, padding: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: G.textSecondary, marginBottom: 12 }}>Privilege Tier Distribution</div>
          {Object.entries(data.tier_distribution).map(([tier, count]) => (
            <div key={tier} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '5px 0', borderBottom: `1px solid ${G.surfaceBorder}` }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ display: 'inline-block', padding: '1px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700, fontFamily: G.mono, background: G.tierBg[tier] || 'transparent', color: G.tier[tier] || G.textMuted }}>{tier}</span>
                <span style={{ fontSize: 11, color: G.textSecondary }}>{TIER_LABELS[tier] || tier}</span>
              </div>
              <span
                onClick={() => navigate(`/identities?privilege_tier=${tier.replace('T', '')}`)}
                style={{ fontSize: 13, fontWeight: 700, fontFamily: G.mono, color: G.text, cursor: 'pointer' }}
              >{count}</span>
            </div>
          ))}
        </div>

        {/* Scope Breakdown */}
        <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 12, padding: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: G.textSecondary, marginBottom: 12 }}>Scope Breakdown</div>
          {Object.entries(data.scope_breakdown).map(([scope, count]) => (
            <div key={scope} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '5px 0', borderBottom: `1px solid ${G.surfaceBorder}` }}>
              <span style={{ fontSize: 11, color: G.textSecondary, textTransform: 'capitalize' }}>{scope.replace(/_/g, ' ')}</span>
              <span style={{ fontSize: 13, fontWeight: 700, fontFamily: G.mono, color: G.text }}>{count}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Finding Rules */}
      <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 12, padding: 16, marginBottom: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: G.textSecondary }}>Findings by Rule</div>
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            style={{ fontSize: 11, padding: '2px 8px', borderRadius: 4, border: `1px solid ${G.surfaceBorder}`, background: G.bg, color: G.textSecondary }}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        {data.rules.map(rule => (
          <div
            key={rule.label}
            onClick={() => setExpandedRule(expandedRule === rule.label ? null : rule.label)}
            style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', borderBottom: `1px solid ${G.surfaceBorder}`, cursor: 'pointer' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: 1, background: sevColor(rule.severity) }} />
              <span style={{ fontSize: 12, color: G.text }}>{rule.label}</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span style={{ fontSize: 10, color: G.textMuted }}>{rule.identities_affected} identities</span>
              <span style={{ fontSize: 13, fontWeight: 700, fontFamily: G.mono, color: sevColor(rule.severity) }}>{rule.count}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Expanded Findings */}
      {filteredFindings.length > 0 && (
        <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 12, padding: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: G.textSecondary, marginBottom: 12 }}>
            {expandedRule ? `Findings: ${expandedRule}` : 'All Findings'} ({filteredFindings.length})
          </div>
          <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${G.surfaceBorder}` }}>
                <th style={{ textAlign: 'left', padding: '6px 8px', fontSize: 10, fontWeight: 600, color: G.textSecondary, textTransform: 'uppercase' }}>Identity</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', fontSize: 10, fontWeight: 600, color: G.textSecondary, textTransform: 'uppercase' }}>Rule</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', fontSize: 10, fontWeight: 600, color: G.textSecondary, textTransform: 'uppercase' }}>Severity</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', fontSize: 10, fontWeight: 600, color: G.textSecondary, textTransform: 'uppercase' }}>Detail</th>
              </tr>
            </thead>
            <tbody>
              {filteredFindings.slice(0, 50).map((f, i) => (
                <tr key={i} style={{ borderBottom: `1px solid ${G.surfaceBorder}` }}>
                  <td style={{ padding: '6px 8px' }}>
                    <Link to={`/identities/${f.identity_id}`} style={{ color: G.accent, textDecoration: 'none', fontSize: 12 }}>{f.display_name}</Link>
                  </td>
                  <td style={{ padding: '6px 8px', color: G.textSecondary }}>{f.rule_label}</td>
                  <td style={{ padding: '6px 8px' }}>
                    <span style={{ display: 'inline-block', padding: '1px 6px', borderRadius: 3, fontSize: 10, fontWeight: 600, background: G.severityBg[f.severity], color: sevColor(f.severity) }}>{f.severity}</span>
                  </td>
                  <td style={{ padding: '6px 8px', color: G.textMuted, fontSize: 11, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const }}>{f.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
