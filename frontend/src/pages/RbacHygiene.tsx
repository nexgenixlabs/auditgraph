import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useConnection } from '../contexts/ConnectionContext';
import { SnapshotContextHeader } from '../components/ui/SnapshotContextHeader';

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
  risk_level: string;
  role_tier: string;
  days_since_activity: number | null;
  credential_status: string | null;
  assignment_age_days: number | null;
  is_pim_eligible: boolean;
  identity_risk: string;
}

interface ExposureIndex {
  privilege_density: number;
  broad_scope_density: number;
  unhealthy_principals: number;
  permanent_high_priv: number;
  nhi_with_secrets: number;
}

interface Executive {
  standing_priv_ratio: number;
  broad_scope_ratio: number;
  unhealthy_ratio: number;
  top_risk_identities: Array<{
    identity_db_id: number;
    identity_id: string;
    identity_name: string;
    identity_category: string;
    total_risk: number;
    finding_count: number;
    highest_severity: string;
  }>;
  scope_breakdown: Record<string, number>;
  tier_distribution: Record<string, number>;
  total_identities: number;
  pim_coverage: number;
}

interface Drift {
  has_previous: boolean;
  new_findings: number;
  resolved_findings: number;
  score_delta: number;
  new_privileged: Array<{
    identity_name: string;
    role_name: string;
    role_tier: string;
    scope_type: string;
    rule: string;
  }>;
  scope_escalations: Array<{
    identity_name: string;
    role_name: string;
    old_scope: string;
    new_scope: string;
  }>;
  previous_score?: number;
  previous_total_findings?: number;
}

interface Summary {
  score: number | null;
  grade: string | null;
  total_assignments: number;
  total_findings: number;
  by_rule: Record<string, RuleSummary>;
  by_severity: Record<string, number>;
  exposure_index: ExposureIndex;
  tier_distribution: Record<string, number>;
  executive: Executive;
  drift: Drift;
  analyzed_at: string | null;
  has_data: boolean;
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];
const RULE_KEYS = [
  'orphaned_assignment', 'disabled_principal', 'dormant_access',
  'credential_risk', 'overprivileged', 'mg_level_access', 'guest_standing_access',
  'permanent_ga', 'broad_scope_age', 'owner_without_pim',
];

// SVG icons for rules
function RuleIcon({ rule }: { rule: string }) {
  const iconMap: Record<string, React.ReactNode> = {
    orphaned_assignment: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
    ),
    disabled_principal: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
    ),
    dormant_access: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
    ),
    credential_risk: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
    ),
    overprivileged: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polyline points="18 15 12 9 6 15"/></svg>
    ),
    mg_level_access: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 7V4a2 2 0 00-2-2h-4a2 2 0 00-2 2v3"/></svg>
    ),
    guest_standing_access: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
    ),
    permanent_ga: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    ),
    broad_scope_age: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
    ),
    owner_without_pim: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
    ),
  };
  return <span style={{ display: 'inline-flex', alignItems: 'center' }}>{iconMap[rule] || '?'}</span>;
}

export default function RbacHygiene() {
  const navigate = useNavigate();
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
  const [tierFilter, setTierFilter] = useState('');
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

  // Client-side tier filter (since backend doesn't support it)
  const filteredFindings = useMemo(() => {
    if (!tierFilter) return findings;
    return findings.filter(f => f.role_tier === tierFilter);
  }, [findings, tierFilter]);

  const hasData = summary?.has_data;
  const expo = summary?.exposure_index;
  const exec = summary?.executive;
  const drift = summary?.drift;
  const tierDist = summary?.tier_distribution || {};

  return (
    <div style={{ padding: '24px 32px', maxWidth: 1440, margin: '0 auto', color: G.text }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>RBAC Hygiene</h1>
          <p style={{ fontSize: 13, color: G.textSecondary, margin: '4px 0 0' }}>
            Assignment-level analysis with 4-tier role sensitivity scoring
          </p>
          <SnapshotContextHeader />
        </div>
        {isAdmin && (
          <button onClick={handleScan} disabled={scanning}
            style={{
              padding: '8px 20px', borderRadius: 6, border: 'none', cursor: scanning ? 'wait' : 'pointer',
              background: G.accent, color: '#fff', fontSize: 13, fontWeight: 600,
              opacity: scanning ? 0.6 : 1, transition: 'opacity 0.2s',
            }}>
            {scanning ? 'Capturing...' : 'Capture Snapshot'}
          </button>
        )}
      </div>

      {/* ══════ Executive Summary Row ══════ */}
      {hasData && summary && (
        <div style={{ display: 'grid', gridTemplateColumns: '240px 1fr 1fr 1fr', gap: 16, marginBottom: 20 }}>
          {/* Score Ring */}
          <div style={{
            background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10,
            padding: 20, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
          }}>
            <ScoreRing score={summary.score!} grade={summary.grade!} size={100} />
            <div style={{ fontSize: 11, color: G.textMuted, marginTop: 8, textAlign: 'center' }}>
              {summary.total_assignments} assignments
            </div>
            {drift?.has_previous && (
              <div style={{
                fontSize: 11, marginTop: 4, fontWeight: 600, fontFamily: G.mono,
                color: (drift.score_delta ?? 0) > 0 ? '#4ADE80' : (drift.score_delta ?? 0) < 0 ? '#FF1744' : G.textMuted,
              }}>
                {(drift.score_delta ?? 0) > 0 ? '+' : ''}{drift.score_delta ?? 0} vs previous
              </div>
            )}
          </div>

          {/* CISO Card 1: Standing Privilege */}
          <CisoCard
            label="Standing Privilege"
            value={`${exec?.standing_priv_ratio ?? 0}%`}
            sublabel="T1+T2 without PIM"
            color={riskColor(exec?.standing_priv_ratio ?? 0)}
            detail={`PIM coverage: ${exec?.pim_coverage ?? 0}%`}
            onClick={() => navigate('/identities?privilege_tier=0')}
          />

          {/* CISO Card 2: Broad Scope */}
          <CisoCard
            label="Broad Scope Access"
            value={`${exec?.broad_scope_ratio ?? 0}%`}
            sublabel="Subscription+ scope"
            color={riskColor(exec?.broad_scope_ratio ?? 0)}
            detail={`${exec?.total_identities ?? 0} unique identities`}
            onClick={() => navigate('/identities?risk_level=high')}
          />

          {/* CISO Card 3: Unhealthy Principals */}
          <CisoCard
            label="Unhealthy Principals"
            value={`${exec?.unhealthy_ratio ?? 0}%`}
            sublabel="Identities with findings"
            color={riskColor(exec?.unhealthy_ratio ?? 0)}
            detail={`${summary.total_findings} total findings`}
            onClick={() => navigate('/identities?risk_level=critical')}
          />
        </div>
      )}

      {/* ══════ Exposure Index + Tier Distribution ══════ */}
      {hasData && expo && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
          {/* Exposure Index Bars */}
          <div style={{
            background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10, padding: 20,
          }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: G.text, marginBottom: 14 }}>Exposure Index</div>
            <ExposureBar label="Privilege Density" value={expo.privilege_density} sublabel="T1/T2 assignments" />
            <ExposureBar label="Broad Scope" value={expo.broad_scope_density} sublabel="Sub+ scope" />
            <ExposureBar label="Unhealthy" value={expo.unhealthy_principals} sublabel="Identities w/ findings" />
            <ExposureBar label="Permanent High-Priv" value={expo.permanent_high_priv} sublabel="T1/T2 no PIM" />
            <ExposureBar label="NHI Credential Risk" value={expo.nhi_with_secrets} sublabel="SPNs w/ cred issues" />
          </div>

          {/* Tier Distribution + Severity Breakdown */}
          <div style={{
            background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10, padding: 20,
          }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: G.text, marginBottom: 14 }}>Role Sensitivity Distribution</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8, marginBottom: 16 }}>
              {(['T1', 'T2', 'T3', 'T4'] as const).map(tier => {
                const count = tierDist[tier] || 0;
                const totalAssign = summary?.total_assignments || 1;
                const pct = Math.round(count / totalAssign * 100);
                return (
                  <button key={tier} onClick={() => { setTierFilter(tier === tierFilter ? '' : tier); setPage(0); }}
                    style={{
                      padding: '10px 4px', borderRadius: 8, textAlign: 'center', cursor: 'pointer',
                      border: tierFilter === tier ? `2px solid ${G.tier[tier]}` : `1px solid ${G.surfaceBorder}`,
                      background: tierFilter === tier ? G.tierBg[tier] : 'transparent',
                    }}>
                    <div style={{ fontSize: 20, fontWeight: 700, fontFamily: G.mono, color: G.tier[tier] }}>{count}</div>
                    <div style={{ fontSize: 10, fontWeight: 600, color: G.tier[tier] }}>{tier}</div>
                    <div style={{ fontSize: 9, color: G.textMuted, marginTop: 2 }}>{TIER_LABELS[tier]}</div>
                    <div style={{ fontSize: 9, color: G.textMuted }}>{pct}%</div>
                  </button>
                );
              })}
            </div>

            {/* Severity mini-grid */}
            <div style={{ fontSize: 12, color: G.textSecondary, marginBottom: 8, fontWeight: 600 }}>Findings by Severity</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 6 }}>
              {SEVERITY_ORDER.map(sev => {
                const count = summary?.by_severity[sev] || 0;
                return (
                  <button key={sev} onClick={() => { setSeverityFilter(sev === severityFilter ? '' : sev); setPage(0); }}
                    style={{
                      padding: '6px 4px', borderRadius: 6, textAlign: 'center', cursor: 'pointer',
                      border: severityFilter === sev ? `2px solid ${G.severity[sev]}` : `1px solid ${G.surfaceBorder}`,
                      background: count > 0 ? G.severityBg[sev] : 'transparent',
                    }}>
                    <div style={{ fontSize: 16, fontWeight: 700, fontFamily: G.mono, color: G.severity[sev] }}>{count}</div>
                    <div style={{ fontSize: 9, textTransform: 'uppercase', color: G.textMuted }}>{sev}</div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ══════ Drift Section ══════ */}
      {hasData && drift?.has_previous && (
        <div style={{
          background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10,
          padding: 16, marginBottom: 20,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={G.textSecondary} strokeWidth="2" strokeLinecap="round">
              <polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/>
              <polyline points="17 6 23 6 23 12"/>
            </svg>
            <span style={{ fontSize: 13, fontWeight: 600, color: G.text }}>Drift Since Last Snapshot</span>
          </div>
          <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
            <DriftStat label="New Findings" value={drift.new_findings} color="#FF6D00" />
            <DriftStat label="Resolved" value={drift.resolved_findings} color="#4ADE80" />
            <DriftStat label="Score Delta" value={drift.score_delta} color={(drift.score_delta ?? 0) >= 0 ? '#4ADE80' : '#FF1744'} prefix={(drift.score_delta ?? 0) > 0 ? '+' : ''} />
            <DriftStat label="Prev. Findings" value={drift.previous_total_findings ?? 0} color={G.textSecondary} />
          </div>
          {(drift.new_privileged.length > 0 || drift.scope_escalations.length > 0) && (
            <div style={{ marginTop: 12, display: 'flex', gap: 16, flexWrap: 'wrap' }}>
              {drift.new_privileged.length > 0 && (
                <div style={{ flex: 1, minWidth: 280 }}>
                  <div style={{ fontSize: 11, color: G.textMuted, textTransform: 'uppercase', marginBottom: 6 }}>New Privileged Findings</div>
                  {drift.new_privileged.slice(0, 3).map((p, i) => (
                    <div key={i} style={{ fontSize: 12, color: G.text, marginBottom: 3, display: 'flex', gap: 6, alignItems: 'center' }}>
                      <TierBadge tier={p.role_tier} />
                      <span style={{ color: G.textSecondary }}>{p.identity_name}</span>
                      <span style={{ fontFamily: G.mono, fontSize: 11 }}>{p.role_name}</span>
                    </div>
                  ))}
                </div>
              )}
              {drift.scope_escalations.length > 0 && (
                <div style={{ flex: 1, minWidth: 280 }}>
                  <div style={{ fontSize: 11, color: G.textMuted, textTransform: 'uppercase', marginBottom: 6 }}>Scope Escalations</div>
                  {drift.scope_escalations.slice(0, 3).map((s, i) => (
                    <div key={i} style={{ fontSize: 12, color: G.text, marginBottom: 3 }}>
                      <span style={{ color: G.textSecondary }}>{s.identity_name}</span>{' '}
                      <span style={{ fontFamily: G.mono, fontSize: 11 }}>{s.role_name}</span>{' '}
                      <span style={{ color: '#FF6D00', fontSize: 11 }}>{s.old_scope} &rarr; {s.new_scope}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ══════ Top Issues Grid ══════ */}
      {hasData && summary && (
        <div style={{
          background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10,
          padding: 16, marginBottom: 20,
        }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: G.text, marginBottom: 10 }}>Finding Rules</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 6 }}>
            {RULE_KEYS.map(k => {
              const r = summary.by_rule[k];
              if (!r) return null;
              const active = ruleFilter === k;
              return (
                <button key={k} onClick={() => { setRuleFilter(active ? '' : k); setPage(0); }}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 6, padding: '6px 8px', borderRadius: 6,
                    border: active ? `2px solid ${G.severity[r.severity]}` : `1px solid ${G.surfaceBorder}`,
                    background: active ? G.severityBg[r.severity] : 'transparent',
                    cursor: 'pointer', textAlign: 'left',
                  }}>
                  <span style={{ color: G.severity[r.severity] }}><RuleIcon rule={k} /></span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 11, color: G.text, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.label}</div>
                    <div style={{ fontSize: 10, color: G.textMuted }}>{r.identities_affected} identit{r.identities_affected !== 1 ? 'ies' : 'y'}</div>
                  </div>
                  <span style={{ fontFamily: G.mono, fontSize: 14, fontWeight: 700, color: G.severity[r.severity] }}>{r.count}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Empty State */}
      {!hasData && !loading && (
        <div style={{
          background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10,
          padding: 48, textAlign: 'center', marginBottom: 24,
        }}>
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke={G.textMuted} strokeWidth="1.5" strokeLinecap="round" style={{ margin: '0 auto 16px' }}>
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <div style={{ fontSize: 16, fontWeight: 600, color: G.text, marginBottom: 8 }}>No RBAC Hygiene Data</div>
          <div style={{ fontSize: 13, color: G.textSecondary, marginBottom: 16 }}>
            Capture a snapshot to analyze your RBAC assignments for hygiene issues
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

      {/* ══════ Filters ══════ */}
      {hasData && (
        <div style={{
          display: 'flex', gap: 10, marginBottom: 14, alignItems: 'center', flexWrap: 'wrap',
        }}>
          <input
            value={search} onChange={e => { setSearch(e.target.value); setPage(0); }}
            placeholder="Search identities or roles..."
            style={{
              padding: '7px 12px', borderRadius: 6, border: `1px solid ${G.surfaceBorder}`,
              background: G.surface, color: G.text, fontSize: 13, width: 220,
            }}
          />
          <select value={ruleFilter} onChange={e => { setRuleFilter(e.target.value); setPage(0); }}
            style={selectStyle}>
            <option value="">All Rules</option>
            {RULE_KEYS.map(k => (
              <option key={k} value={k}>{summary?.by_rule[k]?.label || k}</option>
            ))}
          </select>
          <select value={severityFilter} onChange={e => { setSeverityFilter(e.target.value); setPage(0); }}
            style={selectStyle}>
            <option value="">All Severities</option>
            {SEVERITY_ORDER.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
          </select>
          <select value={sourceFilter} onChange={e => { setSourceFilter(e.target.value); setPage(0); }}
            style={selectStyle}>
            <option value="">All Sources</option>
            <option value="rbac">RBAC</option>
            <option value="entra">Entra ID</option>
          </select>
          <select value={tierFilter} onChange={e => { setTierFilter(e.target.value); setPage(0); }}
            style={selectStyle}>
            <option value="">All Tiers</option>
            <option value="T1">T1 Critical</option>
            <option value="T2">T2 Elevated</option>
            <option value="T3">T3 Targeted</option>
            <option value="T4">T4 Read-Only</option>
          </select>
          {(ruleFilter || severityFilter || sourceFilter || tierFilter || search) && (
            <button onClick={() => { setRuleFilter(''); setSeverityFilter(''); setSourceFilter(''); setTierFilter(''); setSearch(''); setPage(0); }}
              style={{
                padding: '5px 10px', borderRadius: 4, border: `1px solid ${G.surfaceBorder}`,
                background: 'transparent', color: G.textSecondary, fontSize: 11, cursor: 'pointer',
              }}>
              Clear
            </button>
          )}
          <span style={{ marginLeft: 'auto', fontSize: 12, color: G.textMuted }}>
            {tierFilter ? filteredFindings.length : total} finding{(tierFilter ? filteredFindings.length : total) !== 1 ? 's' : ''}
          </span>
        </div>
      )}

      {/* ══════ Findings Table + Detail Panel ══════ */}
      <div style={{ display: 'flex', gap: 0 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          {hasData && (
            <div style={{
              background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10,
              overflow: 'hidden',
            }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${G.surfaceBorder}` }}>
                    <th style={thStyle}>Sev</th>
                    <th style={thStyle}>Tier</th>
                    <th style={thStyle}>Rule</th>
                    <th style={thStyle}>Identity</th>
                    <th style={thStyle}>Role</th>
                    <th style={thStyle}>Source</th>
                    <th style={thStyle}>Scope</th>
                    <th style={thStyle}>PIM</th>
                    <th style={{ ...thStyle, textAlign: 'right' }}>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    <tr><td colSpan={9} style={{ padding: 32, textAlign: 'center', color: G.textMuted }}>Loading...</td></tr>
                  ) : filteredFindings.length === 0 ? (
                    <tr><td colSpan={9} style={{ padding: 32, textAlign: 'center', color: G.textMuted }}>No findings match filters</td></tr>
                  ) : filteredFindings.map((f, i) => (
                    <tr key={i} onClick={() => setSelectedFinding(selectedFinding === f ? null : f)}
                      style={{
                        borderBottom: `1px solid ${G.surfaceBorder}`, cursor: 'pointer',
                        background: selectedFinding === f ? G.severityBg[f.severity] : 'transparent',
                      }}
                      onMouseEnter={e => { if (selectedFinding !== f) (e.currentTarget as HTMLElement).style.background = G.surfaceHover; }}
                      onMouseLeave={e => { if (selectedFinding !== f) (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
                    >
                      <td style={tdStyle}><SevBadge severity={f.severity} /></td>
                      <td style={tdStyle}><TierBadge tier={f.role_tier} /></td>
                      <td style={tdStyle}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: G.severity[f.severity] }}>
                          <RuleIcon rule={f.rule} />
                          <span style={{ color: G.text }}>{f.rule_label}</span>
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
                      <td style={tdStyle}>
                        {f.is_pim_eligible ? (
                          <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 3, background: 'rgba(74,222,128,0.15)', color: '#4ADE80', fontWeight: 600 }}>PIM</span>
                        ) : (
                          <span style={{ fontSize: 10, color: G.textMuted }}>--</span>
                        )}
                      </td>
                      <td style={{ ...tdStyle, textAlign: 'right' }}>
                        <span style={{ fontFamily: G.mono, fontWeight: 600, fontSize: 12, color: G.severity[f.risk_level] || G.severity[f.severity] }}>
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

        {/* ══════ Detail Panel ══════ */}
        {selectedFinding && (
          <div style={{
            width: 420, marginLeft: 16, background: G.surface, border: `1px solid ${G.surfaceBorder}`,
            borderRadius: 10, padding: 20, position: 'sticky', top: 80, alignSelf: 'flex-start',
            maxHeight: 'calc(100vh - 120px)', overflowY: 'auto',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: 16 }}>
              <div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 8 }}>
                  <SevBadge severity={selectedFinding.severity} />
                  <TierBadge tier={selectedFinding.role_tier} />
                  {selectedFinding.is_pim_eligible && (
                    <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 3, background: 'rgba(74,222,128,0.15)', color: '#4ADE80', fontWeight: 600 }}>PIM</span>
                  )}
                </div>
                <div style={{ fontSize: 15, fontWeight: 600 }}>{selectedFinding.title}</div>
              </div>
              <button onClick={() => setSelectedFinding(null)}
                style={{ background: 'none', border: 'none', color: G.textMuted, cursor: 'pointer', fontSize: 18, padding: 4 }}>
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

            {/* Risk Score Bar */}
            <div style={{ marginBottom: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontSize: 11, color: G.textMuted, textTransform: 'uppercase' }}>Assignment Risk</span>
                <span style={{ fontFamily: G.mono, fontSize: 13, fontWeight: 700, color: G.severity[selectedFinding.risk_level] }}>
                  {selectedFinding.risk_score}/100
                </span>
              </div>
              <div style={{ height: 6, background: G.surfaceHover, borderRadius: 3, overflow: 'hidden' }}>
                <div style={{
                  height: '100%', borderRadius: 3, transition: 'width 0.3s',
                  width: `${selectedFinding.risk_score}%`,
                  background: G.severity[selectedFinding.risk_level] || G.severity[selectedFinding.severity],
                }} />
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 16 }}>
              <DetailField label="Identity" value={selectedFinding.identity_name} />
              <DetailField label="Category" value={formatCategory(selectedFinding.identity_category)} />
              <DetailField label="Role" value={selectedFinding.role_name} mono />
              <DetailField label="Source" value={selectedFinding.role_source === 'rbac' ? 'Azure RBAC' : 'Entra ID'} />
              <DetailField label="Scope Type" value={selectedFinding.scope_type} />
              <DetailField label="Role Tier" value={`${selectedFinding.role_tier} (${TIER_LABELS[selectedFinding.role_tier] || ''})`} />
              <DetailField label="Identity Risk" value={selectedFinding.identity_risk} />
              <DetailField label="PIM Eligible" value={selectedFinding.is_pim_eligible ? 'Yes' : 'No'} />
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

      {/* ══════ Top Risk Identities ══════ */}
      {hasData && exec && exec.top_risk_identities && exec.top_risk_identities.length > 0 && (
        <div style={{
          background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10,
          padding: 16, marginTop: 20,
        }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: G.text, marginBottom: 10 }}>Top Risk Identities</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 10 }}>
            {exec.top_risk_identities.map((id, i) => (
              <Link key={i} to={`/identities/${id.identity_id}`}
                style={{
                  padding: '10px 12px', borderRadius: 8, textDecoration: 'none',
                  border: `1px solid ${G.surfaceBorder}`, background: G.severityBg[id.highest_severity] || 'transparent',
                }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: G.text, marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {id.identity_name}
                </div>
                <div style={{ fontSize: 10, color: G.textMuted, marginBottom: 4 }}>{formatCategory(id.identity_category)}</div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <span style={{ fontFamily: G.mono, fontSize: 14, fontWeight: 700, color: G.severity[id.highest_severity] }}>{id.total_risk}</span>
                  <span style={{ fontSize: 10, color: G.textMuted }}>{id.finding_count} finding{id.finding_count !== 1 ? 's' : ''}</span>
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Analyzed At */}
      {summary?.analyzed_at && (
        <div style={{ fontSize: 11, color: G.textMuted, textAlign: 'right', marginTop: 12 }}>
          Last analyzed: {new Date(summary.analyzed_at).toLocaleString()}
        </div>
      )}
    </div>
  );
}

// ─── Sub-Components ───

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

function SevBadge({ severity }: { severity: string }) {
  return (
    <span style={{
      display: 'inline-block', padding: '2px 6px', borderRadius: 4, fontSize: 10, fontWeight: 600,
      textTransform: 'uppercase', letterSpacing: 0.5,
      color: G.severity[severity] || G.textMuted,
      background: G.severityBg[severity] || 'transparent',
    }}>
      {severity}
    </span>
  );
}

function TierBadge({ tier }: { tier: string }) {
  return (
    <span style={{
      display: 'inline-block', padding: '2px 6px', borderRadius: 4, fontSize: 10, fontWeight: 700,
      fontFamily: G.mono,
      color: G.tier[tier] || G.textMuted,
      background: G.tierBg[tier] || 'transparent',
      border: `1px solid ${G.tier[tier] || G.textMuted}`,
    }}>
      {tier}
    </span>
  );
}

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

function CisoCard({ label, value, sublabel, color, detail, onClick }: {
  label: string; value: string; sublabel: string; color: string; detail: string; onClick?: () => void;
}) {
  const Tag = onClick ? 'button' : 'div';
  return (
    <Tag onClick={onClick} style={{
      background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10, padding: 20,
      borderLeft: `3px solid ${color}`, textAlign: 'left' as const,
      cursor: onClick ? 'pointer' : undefined, transition: 'opacity 0.15s', width: '100%',
    }} className={onClick ? 'hover:opacity-70' : ''}>
      <div style={{ fontSize: 12, color: G.textSecondary, marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, fontFamily: G.mono, color, marginBottom: 2 }}>{value}</div>
      <div style={{ fontSize: 11, color: G.textMuted }}>{sublabel}</div>
      <div style={{ fontSize: 11, color: G.textSecondary, marginTop: 8 }}>{detail}</div>
    </Tag>
  );
}

function ExposureBar({ label, value, sublabel }: { label: string; value: number; sublabel: string }) {
  const color = value >= 50 ? '#FF1744' : value >= 25 ? '#FF6D00' : value >= 10 ? '#FFB300' : '#4ADE80';
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
        <span style={{ fontSize: 12, color: G.text }}>{label}</span>
        <span style={{ fontSize: 12, fontFamily: G.mono, fontWeight: 600, color }}>{value}%</span>
      </div>
      <div style={{ height: 5, background: G.surfaceHover, borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ height: '100%', borderRadius: 3, width: `${Math.min(100, value)}%`, background: color, transition: 'width 0.4s' }} />
      </div>
      <div style={{ fontSize: 10, color: G.textMuted, marginTop: 2 }}>{sublabel}</div>
    </div>
  );
}

function DriftStat({ label, value, color, prefix = '' }: { label: string; value: number; color: string; prefix?: string }) {
  return (
    <div>
      <div style={{ fontSize: 10, color: G.textMuted, textTransform: 'uppercase', marginBottom: 2 }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 700, fontFamily: G.mono, color }}>{prefix}{value}</div>
    </div>
  );
}

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

// ─── Helpers ───

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

function riskColor(pct: number): string {
  if (pct >= 50) return '#FF1744';
  if (pct >= 25) return '#FF6D00';
  if (pct >= 10) return '#FFB300';
  return '#4ADE80';
}

const selectStyle: React.CSSProperties = {
  padding: '7px 10px', borderRadius: 6, border: '1px solid var(--border-default)',
  background: 'var(--bg-secondary)', color: 'var(--text-primary)', fontSize: 12,
};

const thStyle: React.CSSProperties = {
  padding: '8px 10px', textAlign: 'left', fontSize: 10, fontWeight: 600,
  textTransform: 'uppercase', letterSpacing: 0.5,
  color: 'var(--text-tertiary)',
};

const tdStyle: React.CSSProperties = {
  padding: '8px 10px', verticalAlign: 'middle',
};

function pageBtnStyle(disabled: boolean): React.CSSProperties {
  return {
    padding: '5px 12px', borderRadius: 4, fontSize: 12, cursor: disabled ? 'default' : 'pointer',
    border: '1px solid var(--border-default)', background: 'transparent',
    color: disabled ? 'var(--text-tertiary)' : 'var(--text-primary)', opacity: disabled ? 0.5 : 1,
  };
}
