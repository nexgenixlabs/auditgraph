/**
 * Sensitive Data Access — Consolidated resource exposure and data access view.
 *
 * Wraps the existing DataSecurity component under the Access Explainability
 * section with updated header. Shows resource security scoring, identity access
 * patterns, secret hygiene, and data protection posture.
 *
 * Phase 6: Access Explainability consolidation.
 * Canonical route: /sensitive-access (replaces /data-security)
 */
import React, { useEffect, useState, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';

// ─── Theme-aware constants ───
const G = {
  bg: 'var(--bg-primary)',
  surface: 'var(--bg-secondary)',
  surfaceBorder: 'var(--border-default)',
  text: 'var(--text-primary)',
  textSecondary: 'var(--text-secondary)',
  textMuted: 'var(--text-tertiary)',
  accent: '#6366F1',
  mono: "'JetBrains Mono', monospace",
  severity: {
    critical: '#FF1744', high: '#FF6D00', medium: '#FFB300', low: '#4ADE80', info: '#42A5F5',
  } as Record<string, string>,
  severityBg: {
    critical: 'rgba(255,23,68,0.12)', high: 'rgba(255,109,0,0.12)',
    medium: 'rgba(255,179,0,0.12)', low: 'rgba(74,222,128,0.12)', info: 'rgba(66,165,245,0.12)',
  } as Record<string, string>,
  component: {
    network_exposure: '#F87171',
    auth_posture: '#FBBF24',
    logging_audit: '#60A5FA',
    data_protection: '#34D399',
    vault_protection: '#A78BFA',
    identity_access: '#F472B6',
    secret_hygiene: '#FB923C',
    identity_exposure: '#E879F9',
  } as Record<string, string>,
};

const COMP_LABELS: Record<string, string> = {
  network_exposure: 'Network Exposure',
  auth_posture: 'Auth Posture',
  logging_audit: 'Logging & Audit',
  data_protection: 'Data Protection',
  vault_protection: 'Vault Protection',
  identity_access: 'Identity Access',
  secret_hygiene: 'Secret Hygiene',
  identity_exposure: 'Identity Exposure',
};

// ─── Types ───
interface ComponentScore {
  score: number;
  max: number;
  pct: number;
  grade: string;
  findings: number;
}

interface ResourceFinding {
  resource_name: string;
  resource_type: string;
  component: string;
  severity: string;
  title: string;
  detail: string;
}

interface SecurityData {
  overall_score: number;
  overall_grade: string;
  total_resources: number;
  total_findings: number;
  components: Record<string, ComponentScore>;
  risk_distribution: Record<string, number>;
  findings: ResourceFinding[];
}

export default function SensitiveDataAccess() {
  const { withConnection, selectedConnectionId } = useConnection();
  const navigate = useNavigate();
  const [data, setData] = useState<SecurityData | null>(null);
  const [loading, setLoading] = useState(true);
  const [componentFilter, setComponentFilter] = useState<string>('all');

  useEffect(() => {
    setLoading(true);
    fetch(withConnection('/api/data-security'))
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setData(d); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [withConnection, selectedConnectionId]);

  const filteredFindings = useMemo(() => {
    if (!data) return [];
    if (componentFilter === 'all') return data.findings;
    return data.findings.filter(f => f.component === componentFilter);
  }, [data, componentFilter]);

  const gradeColor = (g: string) => {
    const map: Record<string, string> = { A: '#4ADE80', B: '#66BB6A', C: '#FFB300', D: '#FF6D00', F: '#FF1744' };
    return map[g] || G.textMuted;
  };

  if (loading) {
    return (
      <div style={{ minHeight: 400, display: 'flex', alignItems: 'center', justifyContent: 'center', background: G.bg }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ width: 32, height: 32, borderRadius: '50%', border: `3px solid ${G.surfaceBorder}`, borderTopColor: G.accent, animation: 'spin 1s linear infinite', margin: '0 auto 12px' }} />
          <div style={{ fontSize: 12, color: G.textSecondary }}>Loading sensitive data access...</div>
        </div>
        <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
      </div>
    );
  }

  if (!data) {
    return (
      <div style={{ padding: 32, textAlign: 'center', color: G.textSecondary }}>
        No resource security data available. Capture a snapshot first.
      </div>
    );
  }

  return (
    <div style={{ padding: 24, maxWidth: 1400, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 24, fontWeight: 700, color: G.text, margin: 0 }}>Sensitive Data Access</h1>
        <p style={{ fontSize: 14, color: G.textSecondary, marginTop: 4 }}>
          Resource security posture, identity access patterns, and data protection analysis
        </p>
      </div>

      {/* Score + Components Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 16, marginBottom: 24 }}>
        {/* Overall Score */}
        <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 12, padding: '20px 28px', textAlign: 'center' }}>
          <div style={{ fontSize: 40, fontWeight: 700, fontFamily: G.mono, color: gradeColor(data.overall_grade) }}>{data.overall_grade}</div>
          <div style={{ fontSize: 12, color: G.textSecondary, marginTop: 4 }}>Security Grade</div>
          <div style={{ fontSize: 20, fontWeight: 700, fontFamily: G.mono, color: G.text, marginTop: 8 }}>{data.overall_score}/100</div>
          <div style={{ fontSize: 11, color: G.textMuted }}>{data.total_resources} resources · {data.total_findings} findings</div>
        </div>

        {/* Component Scores */}
        <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 12, padding: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: G.textSecondary, marginBottom: 12 }}>Security Components</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
            {Object.entries(data.components).map(([key, comp]) => (
              <button
                key={key}
                onClick={() => setComponentFilter(componentFilter === key ? 'all' : key)}
                style={{
                  background: componentFilter === key ? `${G.component[key]}15` : 'transparent',
                  border: `1px solid ${componentFilter === key ? G.component[key] : G.surfaceBorder}`,
                  borderRadius: 8, padding: '8px 10px', textAlign: 'left', cursor: 'pointer',
                  transition: 'all 150ms',
                }}
              >
                <div style={{ fontSize: 10, color: G.textSecondary, marginBottom: 4 }}>{COMP_LABELS[key] || key}</div>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
                  <span style={{ fontSize: 16, fontWeight: 700, fontFamily: G.mono, color: gradeColor(comp.grade) }}>{comp.grade}</span>
                  <span style={{ fontSize: 10, color: G.textMuted, fontFamily: G.mono }}>{comp.score}/{comp.max}</span>
                </div>
                {comp.findings > 0 && (
                  <div style={{ fontSize: 10, color: G.severity.high, marginTop: 2 }}>{comp.findings} findings</div>
                )}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Resource Risk Distribution */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
        <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 12, padding: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: G.textSecondary, marginBottom: 12 }}>Risk Distribution</div>
          {Object.entries(data.risk_distribution).map(([level, count]) => (
            <div key={level} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '5px 0', borderBottom: `1px solid ${G.surfaceBorder}` }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: 1, background: G.severity[level] || G.textMuted }} />
                <span style={{ fontSize: 11, color: G.textSecondary, textTransform: 'capitalize' }}>{level}</span>
              </div>
              <span style={{ fontSize: 13, fontWeight: 700, fontFamily: G.mono, color: G.text }}>{count}</span>
            </div>
          ))}
        </div>
        <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 12, padding: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: G.textSecondary, marginBottom: 12 }}>Quick Navigation</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <button onClick={() => navigate('/key-vaults')} style={{ textAlign: 'left', padding: '8px 12px', borderRadius: 8, border: `1px solid ${G.surfaceBorder}`, background: G.surface, cursor: 'pointer', fontSize: 12, color: G.text }}>
              Secrets & Keys →
            </button>
            <button onClick={() => navigate('/storage-accounts')} style={{ textAlign: 'left', padding: '8px 12px', borderRadius: 8, border: `1px solid ${G.surfaceBorder}`, background: G.surface, cursor: 'pointer', fontSize: 12, color: G.text }}>
              Storage Exposure →
            </button>
            <button onClick={() => navigate('/resources')} style={{ textAlign: 'left', padding: '8px 12px', borderRadius: 8, border: `1px solid ${G.surfaceBorder}`, background: G.surface, cursor: 'pointer', fontSize: 12, color: G.text }}>
              All Resources →
            </button>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      {filteredFindings.length > 0 && (
        <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 12, padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: G.textSecondary }}>
              {componentFilter !== 'all' ? `${COMP_LABELS[componentFilter]} Findings` : 'All Findings'} ({filteredFindings.length})
            </div>
          </div>
          <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${G.surfaceBorder}` }}>
                <th style={{ textAlign: 'left', padding: '6px 8px', fontSize: 10, fontWeight: 600, color: G.textSecondary, textTransform: 'uppercase' }}>Resource</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', fontSize: 10, fontWeight: 600, color: G.textSecondary, textTransform: 'uppercase' }}>Component</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', fontSize: 10, fontWeight: 600, color: G.textSecondary, textTransform: 'uppercase' }}>Severity</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', fontSize: 10, fontWeight: 600, color: G.textSecondary, textTransform: 'uppercase' }}>Finding</th>
              </tr>
            </thead>
            <tbody>
              {filteredFindings.slice(0, 50).map((f, i) => (
                <tr key={i} style={{ borderBottom: `1px solid ${G.surfaceBorder}` }}>
                  <td style={{ padding: '6px 8px', color: G.text, fontSize: 12 }}>{f.resource_name}</td>
                  <td style={{ padding: '6px 8px' }}>
                    <span style={{ fontSize: 10, color: G.component[f.component] || G.textMuted }}>{COMP_LABELS[f.component] || f.component}</span>
                  </td>
                  <td style={{ padding: '6px 8px' }}>
                    <span style={{ display: 'inline-block', padding: '1px 6px', borderRadius: 3, fontSize: 10, fontWeight: 600, background: G.severityBg[f.severity], color: G.severity[f.severity] || G.textMuted }}>{f.severity}</span>
                  </td>
                  <td style={{ padding: '6px 8px', color: G.textMuted, fontSize: 11, maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const }}>{f.title}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
