import React, { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useConnection } from '../contexts/ConnectionContext';

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
};

const RULE_ICONS: Record<string, string> = {
  orphaned_assignment: '\u26A0',
  disabled_principal: '\u2718',
  dormant_access: '\u23F0',
  credential_risk: '\uD83D\uDD11',
  overprivileged: '\u2B06',
  mg_level_access: '\uD83C\uDFD7',
  guest_standing_access: '\uD83D\uDC64',
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
  identity_db_id: number;
  identity_id: string;
  identity_name: string;
  identity_category: string;
  role_name: string;
  role_source: string;
  scope: string;
  scope_type: string;
  title: string;
  detail: string;
  recommendation: string;
  risk_score: number;
  days_since_activity: number | null;
  credential_status: string | null;
  assignment_age_days: number | null;
}

interface Summary {
  score: number | null;
  grade: string | null;
  total_assignments: number;
  total_findings: number;
  by_rule: Record<string, RuleSummary>;
  by_severity: Record<string, number>;
  analyzed_at: string | null;
  has_data: boolean;
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];
const RULE_KEYS = [
  'orphaned_assignment', 'disabled_principal', 'dormant_access',
  'credential_risk', 'overprivileged', 'mg_level_access', 'guest_standing_access',
];

export default function RbacHygiene() {
  const { isAdmin } = useAuth();
  const { withConnection, selectedConnectionId } = useConnection();

  const [summary, setSummary] = useState<Summary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);

  // Filters
  const [ruleFilter, setRuleFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const pageSize = 50;

  // Detail panel
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // ─── Data loading ───
  const loadSummary = useCallback(async () => {
    try {
      const res = await fetch(withConnection('/api/rbac-hygiene/summary'));
      if (res.ok) setSummary(await res.json());
    } catch { /* ignore */ }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedConnectionId]);

  const loadFindings = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        limit: String(pageSize),
        offset: String(page * pageSize),
      });
      if (ruleFilter) params.set('rule', ruleFilter);
      if (severityFilter) params.set('severity', severityFilter);
      if (sourceFilter) params.set('source', sourceFilter);
      if (search) params.set('search', search);

      const res = await fetch(withConnection(`/api/rbac-hygiene/findings?${params}`));
      if (res.ok) {
        const d = await res.json();
        setFindings(d.findings || []);
        setTotal(d.total || 0);
      }
    } catch { /* ignore */ }
    setLoading(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ruleFilter, severityFilter, sourceFilter, search, page, selectedConnectionId]);

  useEffect(() => { loadSummary(); }, [loadSummary]);
  useEffect(() => { loadFindings(); }, [loadFindings]);

  async function handleScan() {
    if (scanning) return;
    setScanning(true);
    try {
      const res = await fetch(withConnection('/api/rbac-hygiene/scan'), { method: 'POST' });
      if (res.ok) {
        await loadSummary();
        await loadFindings();
      }
    } catch { /* ignore */ }
    setScanning(false);
  }

  // ─── Score Ring ───
  function ScoreRing({ score, grade, size = 100 }: { score: number; grade: string; size?: number }) {
    const r = (size - 8) / 2;
    const circ = 2 * Math.PI * r;
    const offset = circ * (1 - score / 100);
    const color = G.grade[grade] || G.textMuted;
    return (
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--border-default)" strokeWidth={6} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={6}
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
          transform={`rotate(-90 ${size / 2} ${size / 2})`} style={{ transition: 'stroke-dashoffset 0.8s ease' }} />
        <text x={size / 2} y={size / 2 - 6} textAnchor="middle" fill={color}
          style={{ fontSize: size * 0.28, fontWeight: 700, fontFamily: G.mono }}>{score}</text>
        <text x={size / 2} y={size / 2 + 14} textAnchor="middle" fill={G.textMuted}
          style={{ fontSize: size * 0.14, fontWeight: 500 }}>{grade}</text>
      </svg>
    );
  }

  // ─── Severity Badge ───
  function SevBadge({ severity }: { severity: string }) {
    return (
      <span style={{
        display: 'inline-block', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
        textTransform: 'uppercase', letterSpacing: 0.5,
        color: G.severity[severity] || G.textMuted,
        background: G.severityBg[severity] || 'transparent',
      }}>
        {severity}
      </span>
    );
  }

  // ─── Source Badge ───
  function SourceBadge({ source }: { source: string }) {
    const colors: Record<string, string> = { rbac: '#0078D4', entra: '#7C3AED' };
    const labels: Record<string, string> = { rbac: 'RBAC', entra: 'Entra ID' };
    return (
      <span style={{
        display: 'inline-block', padding: '1px 6px', borderRadius: 3, fontSize: 10, fontWeight: 600,
        border: `1px solid ${colors[source] || G.textMuted}`,
        color: colors[source] || G.textMuted,
      }}>
        {labels[source] || source}
      </span>
    );
  }

  const hasData = summary?.has_data;

  return (
    <div style={{ padding: '24px 32px', maxWidth: 1440, margin: '0 auto', color: G.text }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>RBAC Hygiene</h1>
          <p style={{ fontSize: 13, color: G.textSecondary, margin: '4px 0 0' }}>
            Assignment-level analysis of role access health across Azure RBAC and Entra ID
          </p>
        </div>
        {isAdmin && (
          <button onClick={handleScan} disabled={scanning}
            style={{
              padding: '8px 20px', borderRadius: 6, border: 'none', cursor: scanning ? 'wait' : 'pointer',
              background: G.accent, color: '#fff', fontSize: 13, fontWeight: 600,
              opacity: scanning ? 0.6 : 1, transition: 'opacity 0.2s',
            }}>
            {scanning ? 'Scanning...' : 'Run Scan'}
          </button>
        )}
      </div>

      {/* Summary Cards */}
      {hasData && summary && (
        <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr 1fr', gap: 16, marginBottom: 24 }}>
          {/* Score Card */}
          <div style={{
            background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10,
            padding: 20, display: 'flex', alignItems: 'center', gap: 20, minWidth: 260,
          }}>
            <ScoreRing score={summary.score!} grade={summary.grade!} size={96} />
            <div>
              <div style={{ fontSize: 13, color: G.textSecondary, marginBottom: 4 }}>Hygiene Score</div>
              <div style={{ fontSize: 28, fontWeight: 700, fontFamily: G.mono, color: G.grade[summary.grade!] }}>
                {summary.score}
              </div>
              <div style={{ fontSize: 12, color: G.textMuted, marginTop: 2 }}>
                {summary.total_assignments} assignments analyzed
              </div>
            </div>
          </div>

          {/* Severity Breakdown */}
          <div style={{
            background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10, padding: 20,
          }}>
            <div style={{ fontSize: 13, color: G.textSecondary, marginBottom: 12 }}>Findings by Severity</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8 }}>
              {SEVERITY_ORDER.map(sev => {
                const count = summary.by_severity[sev] || 0;
                return (
                  <button key={sev} onClick={() => { setSeverityFilter(sev === severityFilter ? '' : sev); setPage(0); }}
                    style={{
                      padding: '8px 4px', borderRadius: 6, border: severityFilter === sev ? `2px solid ${G.severity[sev]}` : `1px solid ${G.surfaceBorder}`,
                      background: count > 0 ? G.severityBg[sev] : 'transparent', cursor: 'pointer', textAlign: 'center',
                    }}>
                    <div style={{ fontSize: 22, fontWeight: 700, fontFamily: G.mono, color: G.severity[sev] }}>{count}</div>
                    <div style={{ fontSize: 10, textTransform: 'uppercase', color: G.textMuted, marginTop: 2 }}>{sev}</div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Rule Breakdown */}
          <div style={{
            background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10, padding: 20,
          }}>
            <div style={{ fontSize: 13, color: G.textSecondary, marginBottom: 8 }}>Top Issues</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {RULE_KEYS
                .filter(k => (summary.by_rule[k]?.count || 0) > 0)
                .sort((a, b) => (summary.by_rule[b]?.count || 0) - (summary.by_rule[a]?.count || 0))
                .slice(0, 5)
                .map(k => {
                  const r = summary.by_rule[k];
                  return (
                    <button key={k} onClick={() => { setRuleFilter(k === ruleFilter ? '' : k); setPage(0); }}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px', borderRadius: 4,
                        border: ruleFilter === k ? `1px solid ${G.severity[r.severity]}` : '1px solid transparent',
                        background: ruleFilter === k ? G.severityBg[r.severity] : 'transparent',
                        cursor: 'pointer', textAlign: 'left', width: '100%',
                      }}>
                      <span style={{ fontSize: 14, width: 20, textAlign: 'center' }}>{RULE_ICONS[k] || '?'}</span>
                      <span style={{ flex: 1, fontSize: 12, color: G.text }}>{r.label}</span>
                      <span style={{ fontFamily: G.mono, fontSize: 13, fontWeight: 600, color: G.severity[r.severity] }}>{r.count}</span>
                    </button>
                  );
                })}
              {Object.values(summary.by_rule).every(r => r.count === 0) && (
                <div style={{ fontSize: 12, color: G.textMuted, padding: 8 }}>No issues found</div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Empty State */}
      {!hasData && !loading && (
        <div style={{
          background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10,
          padding: 48, textAlign: 'center', marginBottom: 24,
        }}>
          <div style={{ fontSize: 36, marginBottom: 12 }}>&#x1F50D;</div>
          <div style={{ fontSize: 16, fontWeight: 600, color: G.text, marginBottom: 8 }}>No RBAC Hygiene Data</div>
          <div style={{ fontSize: 13, color: G.textSecondary, marginBottom: 16 }}>
            Run a scan to analyze your RBAC assignments for hygiene issues
          </div>
          {isAdmin && (
            <button onClick={handleScan} disabled={scanning}
              style={{
                padding: '8px 20px', borderRadius: 6, border: 'none', cursor: 'pointer',
                background: G.accent, color: '#fff', fontSize: 13, fontWeight: 600,
              }}>
              Run First Scan
            </button>
          )}
        </div>
      )}

      {/* Filters */}
      {hasData && (
        <div style={{
          display: 'flex', gap: 12, marginBottom: 16, alignItems: 'center', flexWrap: 'wrap',
        }}>
          <input
            value={search} onChange={e => { setSearch(e.target.value); setPage(0); }}
            placeholder="Search identities or roles..."
            style={{
              padding: '7px 12px', borderRadius: 6, border: `1px solid ${G.surfaceBorder}`,
              background: G.surface, color: G.text, fontSize: 13, width: 240,
            }}
          />
          <select value={ruleFilter} onChange={e => { setRuleFilter(e.target.value); setPage(0); }}
            style={{
              padding: '7px 10px', borderRadius: 6, border: `1px solid ${G.surfaceBorder}`,
              background: G.surface, color: G.text, fontSize: 12,
            }}>
            <option value="">All Rules</option>
            {RULE_KEYS.map(k => (
              <option key={k} value={k}>{summary?.by_rule[k]?.label || k}</option>
            ))}
          </select>
          <select value={severityFilter} onChange={e => { setSeverityFilter(e.target.value); setPage(0); }}
            style={{
              padding: '7px 10px', borderRadius: 6, border: `1px solid ${G.surfaceBorder}`,
              background: G.surface, color: G.text, fontSize: 12,
            }}>
            <option value="">All Severities</option>
            {SEVERITY_ORDER.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
          </select>
          <select value={sourceFilter} onChange={e => { setSourceFilter(e.target.value); setPage(0); }}
            style={{
              padding: '7px 10px', borderRadius: 6, border: `1px solid ${G.surfaceBorder}`,
              background: G.surface, color: G.text, fontSize: 12,
            }}>
            <option value="">All Sources</option>
            <option value="rbac">RBAC</option>
            <option value="entra">Entra ID</option>
          </select>
          {(ruleFilter || severityFilter || sourceFilter || search) && (
            <button onClick={() => { setRuleFilter(''); setSeverityFilter(''); setSourceFilter(''); setSearch(''); setPage(0); }}
              style={{
                padding: '5px 10px', borderRadius: 4, border: `1px solid ${G.surfaceBorder}`,
                background: 'transparent', color: G.textSecondary, fontSize: 11, cursor: 'pointer',
              }}>
              Clear Filters
            </button>
          )}
          <span style={{ marginLeft: 'auto', fontSize: 12, color: G.textMuted }}>
            {total} finding{total !== 1 ? 's' : ''}
          </span>
        </div>
      )}

      {/* Findings Table + Detail Panel */}
      <div style={{ display: 'flex', gap: 0 }}>
        {/* Table */}
        <div style={{ flex: 1, minWidth: 0, transition: 'all 0.2s' }}>
          {hasData && (
            <div style={{
              background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10,
              overflow: 'hidden',
            }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${G.surfaceBorder}` }}>
                    <th style={thStyle}>Severity</th>
                    <th style={thStyle}>Rule</th>
                    <th style={thStyle}>Identity</th>
                    <th style={thStyle}>Role</th>
                    <th style={thStyle}>Source</th>
                    <th style={thStyle}>Scope</th>
                    <th style={{ ...thStyle, textAlign: 'right' }}>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    <tr><td colSpan={7} style={{ padding: 32, textAlign: 'center', color: G.textMuted }}>Loading...</td></tr>
                  ) : findings.length === 0 ? (
                    <tr><td colSpan={7} style={{ padding: 32, textAlign: 'center', color: G.textMuted }}>No findings match filters</td></tr>
                  ) : findings.map((f, i) => (
                    <tr key={i} onClick={() => setSelectedFinding(selectedFinding === f ? null : f)}
                      style={{
                        borderBottom: `1px solid ${G.surfaceBorder}`, cursor: 'pointer',
                        background: selectedFinding === f ? G.severityBg[f.severity] : 'transparent',
                      }}
                      onMouseEnter={e => { if (selectedFinding !== f) (e.currentTarget as HTMLElement).style.background = G.surfaceHover; }}
                      onMouseLeave={e => { if (selectedFinding !== f) (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
                    >
                      <td style={tdStyle}><SevBadge severity={f.severity} /></td>
                      <td style={tdStyle}>
                        <span title={f.rule_label} style={{ fontSize: 12 }}>
                          {RULE_ICONS[f.rule] || '?'} {f.rule_label}
                        </span>
                      </td>
                      <td style={tdStyle}>
                        <Link to={`/identities/${f.identity_id}`} onClick={e => e.stopPropagation()}
                          style={{ color: G.accent, textDecoration: 'none', fontSize: 12 }}>
                          {f.identity_name}
                        </Link>
                        <div style={{ fontSize: 10, color: G.textMuted }}>{formatCategory(f.identity_category)}</div>
                      </td>
                      <td style={tdStyle}>
                        <span style={{ fontFamily: G.mono, fontSize: 12 }}>{f.role_name}</span>
                      </td>
                      <td style={tdStyle}><SourceBadge source={f.role_source} /></td>
                      <td style={tdStyle}>
                        <span style={{ fontSize: 11, color: G.textSecondary }} title={f.scope}>
                          {f.scope_type}
                        </span>
                      </td>
                      <td style={{ ...tdStyle, textAlign: 'right' }}>
                        <span style={{ fontFamily: G.mono, fontWeight: 600, color: G.severity[f.severity] }}>
                          {f.risk_score}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {/* Pagination */}
              {total > pageSize && (
                <div style={{
                  display: 'flex', justifyContent: 'center', gap: 8, padding: 12,
                  borderTop: `1px solid ${G.surfaceBorder}`,
                }}>
                  <button disabled={page === 0} onClick={() => setPage(p => p - 1)}
                    style={pageBtnStyle(page === 0)}>Previous</button>
                  <span style={{ fontSize: 12, color: G.textMuted, padding: '6px 8px' }}>
                    Page {page + 1} of {Math.ceil(total / pageSize)}
                  </span>
                  <button disabled={(page + 1) * pageSize >= total} onClick={() => setPage(p => p + 1)}
                    style={pageBtnStyle((page + 1) * pageSize >= total)}>Next</button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Detail Panel */}
        {selectedFinding && (
          <div style={{
            width: 420, marginLeft: 16, background: G.surface, border: `1px solid ${G.surfaceBorder}`,
            borderRadius: 10, padding: 20, position: 'sticky', top: 80, alignSelf: 'flex-start',
            maxHeight: 'calc(100vh - 120px)', overflowY: 'auto',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: 16 }}>
              <div>
                <SevBadge severity={selectedFinding.severity} />
                <div style={{ fontSize: 15, fontWeight: 600, marginTop: 8 }}>{selectedFinding.title}</div>
              </div>
              <button onClick={() => setSelectedFinding(null)}
                style={{ background: 'none', border: 'none', color: G.textMuted, cursor: 'pointer', fontSize: 18 }}>
                &#x2715;
              </button>
            </div>

            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 11, color: G.textMuted, textTransform: 'uppercase', marginBottom: 4 }}>Detail</div>
              <div style={{ fontSize: 13, color: G.textSecondary, lineHeight: 1.5 }}>{selectedFinding.detail}</div>
            </div>

            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 11, color: G.textMuted, textTransform: 'uppercase', marginBottom: 4 }}>Recommendation</div>
              <div style={{ fontSize: 13, color: G.text, lineHeight: 1.5, padding: '8px 12px',
                background: 'rgba(139,92,246,0.08)', borderRadius: 6, borderLeft: `3px solid ${G.accent}` }}>
                {selectedFinding.recommendation}
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 16 }}>
              <DetailField label="Identity" value={selectedFinding.identity_name} />
              <DetailField label="Category" value={formatCategory(selectedFinding.identity_category)} />
              <DetailField label="Role" value={selectedFinding.role_name} mono />
              <DetailField label="Source" value={selectedFinding.role_source === 'rbac' ? 'Azure RBAC' : 'Entra ID'} />
              <DetailField label="Scope Type" value={selectedFinding.scope_type} />
              <DetailField label="Risk Score" value={String(selectedFinding.risk_score)} />
              {selectedFinding.days_since_activity != null && (
                <DetailField label="Days Inactive" value={String(selectedFinding.days_since_activity)} />
              )}
              {selectedFinding.credential_status && (
                <DetailField label="Credential Status" value={selectedFinding.credential_status} />
              )}
              {selectedFinding.assignment_age_days != null && (
                <DetailField label="Assignment Age" value={`${selectedFinding.assignment_age_days}d`} />
              )}
            </div>

            {selectedFinding.scope && (
              <div style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 11, color: G.textMuted, textTransform: 'uppercase', marginBottom: 4 }}>Full Scope</div>
                <div style={{
                  fontSize: 11, fontFamily: G.mono, color: G.textSecondary,
                  padding: '6px 8px', background: G.surfaceHover, borderRadius: 4,
                  wordBreak: 'break-all',
                }}>
                  {selectedFinding.scope}
                </div>
              </div>
            )}

            <Link to={`/identities/${selectedFinding.identity_id}`}
              style={{
                display: 'block', textAlign: 'center', padding: '8px 16px', borderRadius: 6,
                border: `1px solid ${G.accent}`, color: G.accent, textDecoration: 'none',
                fontSize: 12, fontWeight: 600, marginTop: 8,
              }}>
              Open Full Identity Detail
            </Link>
          </div>
        )}
      </div>

      {/* Analyzed At */}
      {summary?.analyzed_at && (
        <div style={{ fontSize: 11, color: G.textMuted, textAlign: 'right', marginTop: 12 }}>
          Last analyzed: {new Date(summary.analyzed_at).toLocaleString()}
        </div>
      )}
    </div>
  );
}

// ─── Helpers ───

function DetailField({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div style={{ fontSize: 10, color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>{label}</div>
      <div style={{
        fontSize: 12, color: 'var(--text-primary)', fontWeight: 500,
        fontFamily: mono ? "'JetBrains Mono', monospace" : 'inherit',
      }}>{value}</div>
    </div>
  );
}

function formatCategory(cat: string): string {
  const map: Record<string, string> = {
    service_principal: 'Service Principal',
    human_user: 'Human User',
    guest: 'Guest',
    managed_identity_user: 'User MI',
    managed_identity_system: 'System MI',
  };
  return map[cat] || cat || 'Unknown';
}

const thStyle: React.CSSProperties = {
  padding: '10px 12px', textAlign: 'left', fontSize: 11, fontWeight: 600,
  textTransform: 'uppercase', letterSpacing: 0.5,
  color: 'var(--text-tertiary)',
};

const tdStyle: React.CSSProperties = {
  padding: '10px 12px', verticalAlign: 'middle',
};

function pageBtnStyle(disabled: boolean): React.CSSProperties {
  return {
    padding: '5px 12px', borderRadius: 4, fontSize: 12, cursor: disabled ? 'default' : 'pointer',
    border: '1px solid var(--border-default)', background: 'transparent',
    color: disabled ? 'var(--text-tertiary)' : 'var(--text-primary)', opacity: disabled ? 0.5 : 1,
  };
}
