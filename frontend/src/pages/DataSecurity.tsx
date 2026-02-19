import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
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
};

// ─── Types ───
interface ComponentScore {
  score: number;
  max: number;
  pct: number;
  drivers: { name: string; points: number }[];
}

interface ResourceRow {
  id: number;
  resource_id: string;
  name: string;
  resource_type: 'storage_account' | 'key_vault';
  location: string;
  resource_group: string;
  subscription_id: string;
  subscription_name: string;
  risk_level: string;
  risk_score: number;
  risk_reasons: string[];
  key_config: Record<string, unknown>;
  risk_components: Record<string, ComponentScore>;
  blast_radius_score: number;
  critical_overrides: string[];
  tags: Record<string, string>;
}

interface SummaryData {
  total: number;
  storage_accounts: number;
  key_vaults: number;
  by_risk: Record<string, number>;
  at_risk: number;
  avg_score: number;
  component_averages: {
    storage: Record<string, number>;
    key_vault: Record<string, number>;
  };
  top_risks: { name: string; resource_id: string; resource_type: string; risk_score: number; risk_level: string }[];
}

type TabKey = 'all' | 'storage' | 'vaults';

// ─── Sub-Components ───

function ScoreRing({ score, size = 72 }: { score: number; size?: number }) {
  const r = (size - 8) / 2;
  const circ = 2 * Math.PI * r;
  const fill = circ - (score / 100) * circ;
  const color = score >= 70 ? G.severity.critical : score >= 50 ? G.severity.high : score >= 30 ? G.severity.medium : G.severity.low;
  return (
    <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={6} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={6}
        strokeDasharray={circ} strokeDashoffset={fill} strokeLinecap="round" />
      <text x={size / 2} y={size / 2 + 6} textAnchor="middle" fill={color} fontSize={size * 0.26}
        fontFamily={G.mono} fontWeight={700} style={{ transform: 'rotate(90deg)', transformOrigin: 'center' }}>
        {score}
      </text>
    </svg>
  );
}

function RiskBadge({ level }: { level: string }) {
  return (
    <span style={{
      background: G.severityBg[level] || G.severityBg.info,
      color: G.severity[level] || G.severity.info,
      padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700,
      textTransform: 'uppercase', fontFamily: G.mono, letterSpacing: '0.05em',
    }}>
      {level}
    </span>
  );
}

function ResourceTypeBadge({ type }: { type: string }) {
  const isStorage = type === 'storage_account';
  return (
    <span style={{
      background: isStorage ? 'rgba(59,130,246,0.12)' : 'rgba(139,92,246,0.12)',
      color: isStorage ? '#60A5FA' : '#A78BFA',
      padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 600,
      fontFamily: G.mono,
    }}>
      {isStorage ? 'Storage' : 'Key Vault'}
    </span>
  );
}

function ComponentBar({ label, score, max, color }: { label: string; score: number; max: number; color: string }) {
  const pct = max > 0 ? Math.round((score / max) * 100) : 0;
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
        <span style={{ fontSize: 11, color: G.textSecondary }}>{label}</span>
        <span style={{ fontSize: 10, fontFamily: G.mono, color: G.textMuted }}>{score}/{max}</span>
      </div>
      <div style={{ height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.06)', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 3, transition: 'width 0.4s ease' }} />
      </div>
    </div>
  );
}

function StatCard({ label, value, color, subtitle }: { label: string; value: string | number; color: string; subtitle?: string }) {
  return (
    <div style={{
      background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10,
      padding: '16px 20px', minWidth: 140, flex: 1,
    }}>
      <div style={{ fontSize: 28, fontWeight: 700, color, fontFamily: G.mono, lineHeight: 1.1 }}>{value}</div>
      <div style={{ fontSize: 11, color: G.textSecondary, marginTop: 4 }}>{label}</div>
      {subtitle && <div style={{ fontSize: 10, color: G.textMuted, marginTop: 2 }}>{subtitle}</div>}
    </div>
  );
}

// ─── Main Page ───

export default function DataSecurity() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { withConnection } = useConnection();
  const [summary, setSummary] = useState<SummaryData | null>(null);
  const [resources, setResources] = useState<ResourceRow[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<TabKey>((searchParams.get('tab') as TabKey) || 'all');
  const [searchTerm, setSearchTerm] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [sortField, setSortField] = useState<string>('risk_score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [selectedResource, setSelectedResource] = useState<ResourceRow | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const rt = tab === 'storage' ? 'storage_account' : tab === 'vaults' ? 'key_vault' : '';
      const qs = new URLSearchParams();
      qs.set('limit', '200');
      if (rt) qs.set('resource_type', rt);
      if (riskFilter) qs.set('risk_level', riskFilter);
      if (searchTerm) qs.set('search', searchTerm);

      const [sumRes, resRes] = await Promise.all([
        fetch(withConnection('/api/data-security/summary')),
        fetch(withConnection(`/api/resources?${qs}`)),
      ]);
      if (sumRes.ok) setSummary(await sumRes.json());
      if (resRes.ok) {
        const d = await resRes.json();
        setResources(d.resources || []);
        setTotalCount(d.total || 0);
      }
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  }, [tab, riskFilter, searchTerm, withConnection]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const sorted = useMemo(() => {
    const arr = [...resources];
    arr.sort((a, b) => {
      let va: number | string = (a as unknown as Record<string, unknown>)[sortField] as string;
      let vb: number | string = (b as unknown as Record<string, unknown>)[sortField] as string;
      if (sortField === 'risk_level') {
        const order: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
        va = order[va as string] || 0;
        vb = order[vb as string] || 0;
      }
      if (typeof va === 'number' && typeof vb === 'number') return sortDir === 'asc' ? va - vb : vb - va;
      return sortDir === 'asc' ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va));
    });
    return arr;
  }, [resources, sortField, sortDir]);

  const handleSort = (field: string) => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortField(field); setSortDir('desc'); }
  };

  const compKeys = (type: string) =>
    type === 'storage_account'
      ? ['network_exposure', 'auth_posture', 'logging_audit', 'data_protection']
      : ['network_exposure', 'vault_protection', 'identity_access', 'secret_hygiene'];

  // ─── Render ───
  return (
    <div style={{ padding: '24px 32px', maxWidth: 1440, margin: '0 auto', color: G.text }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0, letterSpacing: '-0.02em' }}>
            Data Security Attack Surface
          </h1>
          <p style={{ fontSize: 12, color: G.textMuted, margin: '4px 0 0' }}>
            Component-based risk intelligence for Storage Accounts &amp; Key Vaults
          </p>
        </div>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, marginBottom: 24 }}>
          <StatCard label="Total Resources" value={summary.total} color={G.accent} />
          <StatCard label="Storage Accounts" value={summary.storage_accounts} color="#60A5FA" />
          <StatCard label="Key Vaults" value={summary.key_vaults} color="#A78BFA" />
          <StatCard label="At Risk" value={summary.at_risk} color={G.severity.critical}
            subtitle={`${summary.by_risk.critical} critical, ${summary.by_risk.high} high`} />
          <StatCard label="Avg Risk Score" value={summary.avg_score} color={
            summary.avg_score >= 50 ? G.severity.high : summary.avg_score >= 30 ? G.severity.medium : G.severity.low
          } />
        </div>
      )}

      {/* Component Averages */}
      {summary && (summary.storage_accounts > 0 || summary.key_vaults > 0) && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
          {summary.storage_accounts > 0 && (
            <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10, padding: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: G.text, marginBottom: 14 }}>
                Storage Account Components
                <span style={{ fontSize: 10, color: G.textMuted, marginLeft: 8 }}>avg % exposure</span>
              </div>
              {['network_exposure', 'auth_posture', 'logging_audit', 'data_protection'].map(k => (
                <div key={k} style={{ marginBottom: 10 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                    <span style={{ fontSize: 11, color: G.textSecondary }}>{COMP_LABELS[k]}</span>
                    <span style={{ fontSize: 10, fontFamily: G.mono, color: G.textMuted }}>
                      {summary.component_averages.storage[k] ?? 0}%
                    </span>
                  </div>
                  <div style={{ height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.06)', overflow: 'hidden' }}>
                    <div style={{
                      height: '100%', width: `${summary.component_averages.storage[k] ?? 0}%`,
                      background: G.component[k], borderRadius: 3, transition: 'width 0.4s',
                    }} />
                  </div>
                </div>
              ))}
            </div>
          )}
          {summary.key_vaults > 0 && (
            <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10, padding: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: G.text, marginBottom: 14 }}>
                Key Vault Components
                <span style={{ fontSize: 10, color: G.textMuted, marginLeft: 8 }}>avg % exposure</span>
              </div>
              {['network_exposure', 'vault_protection', 'identity_access', 'secret_hygiene'].map(k => (
                <div key={k} style={{ marginBottom: 10 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                    <span style={{ fontSize: 11, color: G.textSecondary }}>{COMP_LABELS[k]}</span>
                    <span style={{ fontSize: 10, fontFamily: G.mono, color: G.textMuted }}>
                      {summary.component_averages.key_vault[k] ?? 0}%
                    </span>
                  </div>
                  <div style={{ height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.06)', overflow: 'hidden' }}>
                    <div style={{
                      height: '100%', width: `${summary.component_averages.key_vault[k] ?? 0}%`,
                      background: G.component[k], borderRadius: 3, transition: 'width 0.4s',
                    }} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Top Risks */}
      {summary && summary.top_risks.length > 0 && (
        <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10, padding: 20, marginBottom: 24 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Top Risk Resources</div>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            {summary.top_risks.map((r, i) => (
              <div key={i} style={{
                background: G.severityBg[r.risk_level] || G.severityBg.info,
                border: `1px solid ${G.severity[r.risk_level]}33`,
                borderRadius: 8, padding: '10px 14px', minWidth: 180, flex: '1 1 180px', cursor: 'pointer',
              }}
                onClick={() => navigate(`/resources/detail?rid=${encodeURIComponent(r.resource_id)}`)}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: G.text }}>{r.name}</span>
                  <span style={{ fontSize: 16, fontWeight: 700, fontFamily: G.mono, color: G.severity[r.risk_level] }}>
                    {r.risk_score}
                  </span>
                </div>
                <div style={{ display: 'flex', gap: 6 }}>
                  <ResourceTypeBadge type={r.resource_type} />
                  <RiskBadge level={r.risk_level} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tabs + Filters */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 10 }}>
        <div style={{ display: 'flex', gap: 4, background: 'rgba(255,255,255,0.04)', borderRadius: 8, padding: 3 }}>
          {([['all', 'All Resources'], ['storage', 'Storage Accounts'], ['vaults', 'Key Vaults']] as [TabKey, string][]).map(([k, label]) => (
            <button key={k} onClick={() => setTab(k)} style={{
              padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600, border: 'none', cursor: 'pointer',
              background: tab === k ? G.accent : 'transparent',
              color: tab === k ? '#FFF' : G.textSecondary,
              transition: 'all 0.15s',
            }}>
              {label}
            </button>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            type="text" placeholder="Search resources..." value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            style={{
              background: 'rgba(255,255,255,0.04)', border: `1px solid ${G.surfaceBorder}`, borderRadius: 6,
              padding: '6px 12px', fontSize: 12, color: G.text, width: 200, outline: 'none',
            }}
          />
          <select value={riskFilter} onChange={e => setRiskFilter(e.target.value)} style={{
            background: 'rgba(255,255,255,0.04)', border: `1px solid ${G.surfaceBorder}`, borderRadius: 6,
            padding: '6px 10px', fontSize: 12, color: G.text, outline: 'none',
          }}>
            <option value="">All Risks</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <span style={{ fontSize: 11, color: G.textMuted, alignSelf: 'center', fontFamily: G.mono }}>
            {resources.length} of {totalCount}
          </span>
        </div>
      </div>

      {/* Resource Table */}
      <div style={{ display: 'flex', gap: 16 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10, overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${G.surfaceBorder}` }}>
                  {[
                    { key: 'name', label: 'Resource' },
                    { key: 'resource_type', label: 'Type' },
                    { key: 'risk_level', label: 'Risk' },
                    { key: 'risk_score', label: 'Score' },
                    { key: 'location', label: 'Location' },
                    { key: 'subscription_name', label: 'Subscription' },
                  ].map(col => (
                    <th key={col.key} onClick={() => handleSort(col.key)} style={{
                      padding: '10px 12px', textAlign: 'left', fontSize: 10, fontWeight: 600,
                      color: G.textMuted, cursor: 'pointer', whiteSpace: 'nowrap',
                      textTransform: 'uppercase', letterSpacing: '0.05em',
                    }}>
                      {col.label} {sortField === col.key ? (sortDir === 'asc' ? '\u25B2' : '\u25BC') : ''}
                    </th>
                  ))}
                  <th style={{ padding: '10px 12px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: G.textMuted, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Components
                  </th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={7} style={{ padding: 40, textAlign: 'center', color: G.textMuted }}>Loading...</td></tr>
                ) : sorted.length === 0 ? (
                  <tr><td colSpan={7} style={{ padding: 40, textAlign: 'center', color: G.textMuted }}>No resources found</td></tr>
                ) : sorted.map(r => {
                  const isSelected = selectedResource?.resource_id === r.resource_id;
                  const keys = compKeys(r.resource_type);
                  return (
                    <tr key={`${r.resource_type}-${r.id}`}
                      onClick={() => setSelectedResource(isSelected ? null : r)}
                      style={{
                        borderBottom: `1px solid ${G.surfaceBorder}`,
                        cursor: 'pointer',
                        background: isSelected ? 'rgba(99,102,241,0.08)' : 'transparent',
                        transition: 'background 0.1s',
                      }}
                      onMouseEnter={e => { if (!isSelected) (e.currentTarget.style.background = G.surfaceHover); }}
                      onMouseLeave={e => { if (!isSelected) (e.currentTarget.style.background = 'transparent'); }}
                    >
                      <td style={{ padding: '10px 12px', fontWeight: 500, maxWidth: 200 }}>
                        <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.name}>
                          {r.name}
                        </div>
                        <div style={{ fontSize: 10, color: G.textMuted, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {r.resource_group}
                        </div>
                      </td>
                      <td style={{ padding: '10px 12px' }}><ResourceTypeBadge type={r.resource_type} /></td>
                      <td style={{ padding: '10px 12px' }}><RiskBadge level={r.risk_level} /></td>
                      <td style={{ padding: '10px 12px', fontFamily: G.mono, fontWeight: 600, color: G.severity[r.risk_level] || G.text }}>
                        {r.risk_score}
                      </td>
                      <td style={{ padding: '10px 12px', color: G.textSecondary, fontSize: 11 }}>{r.location || '\u2014'}</td>
                      <td style={{ padding: '10px 12px', color: G.textSecondary, fontSize: 11, maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {r.subscription_name || '\u2014'}
                      </td>
                      <td style={{ padding: '10px 12px', width: 160 }}>
                        {r.risk_components && Object.keys(r.risk_components).length > 0 ? (
                          <div style={{ display: 'flex', gap: 2, height: 18, alignItems: 'flex-end' }}>
                            {keys.map(k => {
                              const comp = r.risk_components[k];
                              if (!comp) return null;
                              const barH = Math.max(2, (comp.pct / 100) * 16);
                              return (
                                <div key={k} title={`${COMP_LABELS[k]}: ${comp.score}/${comp.max}`} style={{
                                  width: 24, height: barH, background: G.component[k] || '#666',
                                  borderRadius: 2, transition: 'height 0.3s',
                                }} />
                              );
                            })}
                          </div>
                        ) : (
                          <span style={{ fontSize: 10, color: G.textMuted }}>\u2014</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Detail Panel */}
        {selectedResource && (
          <div style={{
            width: 380, flexShrink: 0, background: G.surface,
            border: `1px solid ${G.surfaceBorder}`, borderRadius: 10,
            padding: 20, maxHeight: 'calc(100vh - 180px)', overflowY: 'auto',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: 16 }}>
              <div>
                <div style={{ fontSize: 14, fontWeight: 600 }}>{selectedResource.name}</div>
                <div style={{ display: 'flex', gap: 6, marginTop: 6 }}>
                  <ResourceTypeBadge type={selectedResource.resource_type} />
                  <RiskBadge level={selectedResource.risk_level} />
                </div>
              </div>
              <button onClick={() => setSelectedResource(null)} style={{
                background: 'none', border: 'none', color: G.textMuted, cursor: 'pointer', fontSize: 18, padding: 4,
              }}>\u00D7</button>
            </div>

            {/* Score Ring */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20 }}>
              <ScoreRing score={selectedResource.risk_score} />
              <div>
                <div style={{ fontSize: 11, color: G.textSecondary }}>Risk Score</div>
                <div style={{ fontSize: 20, fontWeight: 700, fontFamily: G.mono, color: G.severity[selectedResource.risk_level] }}>
                  {selectedResource.risk_score}/100
                </div>
              </div>
            </div>

            {/* Critical Overrides */}
            {selectedResource.critical_overrides && selectedResource.critical_overrides.length > 0 && (
              <div style={{
                background: 'rgba(255,23,68,0.08)', border: '1px solid rgba(255,23,68,0.2)',
                borderRadius: 8, padding: 12, marginBottom: 16,
              }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: G.severity.critical, marginBottom: 6, textTransform: 'uppercase' }}>
                  Critical Overrides
                </div>
                {selectedResource.critical_overrides.map((c, i) => (
                  <div key={i} style={{ fontSize: 11, color: G.text, marginBottom: 3 }}>{c}</div>
                ))}
              </div>
            )}

            {/* Component Breakdown */}
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 10 }}>Component Breakdown</div>
              {compKeys(selectedResource.resource_type).map(k => {
                const comp = selectedResource.risk_components?.[k];
                if (!comp) return null;
                return (
                  <div key={k} style={{ marginBottom: 12 }}>
                    <ComponentBar label={COMP_LABELS[k]} score={comp.score} max={comp.max} color={G.component[k] || '#666'} />
                    {comp.drivers.length > 0 && (
                      <div style={{ paddingLeft: 8 }}>
                        {comp.drivers.map((d, i) => (
                          <div key={i} style={{ fontSize: 10, color: G.textMuted, marginBottom: 2, display: 'flex', justifyContent: 'space-between' }}>
                            <span>{d.name}</span>
                            <span style={{ fontFamily: G.mono, color: G.severity.medium }}>+{d.points}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Resource Details */}
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8 }}>Details</div>
              {[
                ['Location', selectedResource.location],
                ['Resource Group', selectedResource.resource_group],
                ['Subscription', selectedResource.subscription_name],
              ].map(([label, val]) => (
                <div key={label as string} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: `1px solid ${G.surfaceBorder}` }}>
                  <span style={{ fontSize: 11, color: G.textMuted }}>{label}</span>
                  <span style={{ fontSize: 11, color: G.text, fontFamily: G.mono, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {val || '\u2014'}
                  </span>
                </div>
              ))}
            </div>

            {/* Open Full Detail */}
            <button
              onClick={() => navigate(`/resources/detail?rid=${encodeURIComponent(selectedResource.resource_id)}`)}
              style={{
                width: '100%', padding: '10px 0', borderRadius: 6, border: `1px solid ${G.accent}`,
                background: 'transparent', color: G.accent, fontSize: 12, fontWeight: 600,
                cursor: 'pointer', transition: 'all 0.15s',
              }}
              onMouseEnter={e => { e.currentTarget.style.background = G.accent; e.currentTarget.style.color = '#FFF'; }}
              onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = G.accent; }}
            >
              Open Full Detail \u2192
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
