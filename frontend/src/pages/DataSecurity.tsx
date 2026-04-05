import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
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
  risk_trend_delta?: number;
  risk_trend_direction?: 'up' | 'down' | 'stable';
  data_classification?: string;
  classification_source?: string;
}

interface ClassificationStats {
  classified: ClassifiedResource[];
  unclassified_count: number;
  total_resources: number;
  by_classification: Record<string, number>;
}

interface ClassifiedResource {
  resource_id: number;
  resource_name: string;
  resource_type: string;
  classification: string;
  source: string;
  confidence: string;
  classified_by: string;
  classified_at: string | null;
  risk_level: string;
  risk_score: number;
}

interface BlastRadiusSummary {
  identities_with_sensitive_access: BlastRadiusIdentity[];
  summary: {
    total_identities_with_phi_access: number;
    total_identities_with_pci_access: number;
    total_identities_with_pii_access: number;
    total_classified_resources: number;
    highest_risk_identity: string | null;
  };
}

interface BlastRadiusIdentity {
  identity_db_id: number;
  identity_id: string;
  display_name: string;
  identity_type: string;
  identity_category: string;
  risk_level: string;
  sensitive_resources_count: number;
  phi_count: number;
  pci_count: number;
  pii_count: number;
  highest_access: string;
}

const CLASS_COLORS: Record<string, { bg: string; fg: string; border: string }> = {
  PHI: { bg: 'rgba(239,68,68,0.12)', fg: '#F87171', border: 'rgba(239,68,68,0.3)' },
  PCI: { bg: 'rgba(251,191,36,0.12)', fg: '#FBBF24', border: 'rgba(251,191,36,0.3)' },
  PII: { bg: 'rgba(96,165,250,0.12)', fg: '#60A5FA', border: 'rgba(96,165,250,0.3)' },
};

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

function ClassificationBadge({ classification }: { classification?: string }) {
  if (!classification) return <span style={{ fontSize: 10, color: G.textMuted }}>—</span>;
  const c = CLASS_COLORS[classification] || { bg: 'rgba(255,255,255,0.06)', fg: G.textMuted, border: G.surfaceBorder };
  return (
    <span style={{
      background: c.bg, color: c.fg, border: `1px solid ${c.border}`,
      padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700,
      fontFamily: G.mono, letterSpacing: '0.05em',
    }}>
      {classification}
    </span>
  );
}

function StatCard({ label, value, color, subtitle, onClick }: { label: string; value: string | number; color: string; subtitle?: string; onClick?: () => void }) {
  const Tag = onClick ? 'button' : 'div';
  return (
    <Tag onClick={onClick} style={{
      background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10,
      padding: '16px 20px', minWidth: 140, flex: 1, textAlign: 'left' as const,
      cursor: onClick ? 'pointer' : undefined, transition: 'opacity 0.15s',
    }} className={onClick ? 'hover:opacity-70' : ''}>
      <div style={{ fontSize: 28, fontWeight: 700, color, fontFamily: G.mono, lineHeight: 1.1, ...(onClick ? { width: 'fit-content', borderBottom: '1px dashed currentColor' } : {}) }}>{typeof value === 'number' ? value.toLocaleString() : value}</div>
      <div style={{ fontSize: 11, color: G.textSecondary, marginTop: 4 }}>{label}</div>
      {subtitle && <div style={{ fontSize: 10, color: G.textMuted, marginTop: 2 }}>{subtitle}</div>}
    </Tag>
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
  const [classStats, setClassStats] = useState<ClassificationStats | null>(null);
  const [blastRadius, setBlastRadius] = useState<BlastRadiusSummary | null>(null);
  const [classFilter, setClassFilter] = useState('');
  const [showClassifyModal, setShowClassifyModal] = useState(false);
  const [classifyTarget, setClassifyTarget] = useState<ResourceRow | null>(null);
  const [classifyValue, setClassifyValue] = useState('PHI');
  const [classifyNotes, setClassifyNotes] = useState('');
  const [autoClassifying, setAutoClassifying] = useState(false);

  const fetchClassifications = useCallback(async () => {
    try {
      const [clsRes, brRes] = await Promise.all([
        fetch(withConnection('/api/resources/classifications')),
        fetch(withConnection('/api/blast-radius/summary')),
      ]);
      if (clsRes.ok) setClassStats(await clsRes.json());
      if (brRes.ok) setBlastRadius(await brRes.json());
    } catch { /* ignore */ }
  }, [withConnection]);

  const handleClassify = async () => {
    if (!classifyTarget) return;
    try {
      const res = await fetch(withConnection(`/api/resources/${classifyTarget.id}/classify`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          classification: classifyValue,
          notes: classifyNotes,
          resource_type: classifyTarget.resource_type,
        }),
      });
      if (res.ok) {
        setShowClassifyModal(false);
        setClassifyNotes('');
        fetchData();
        fetchClassifications();
      }
    } catch { /* ignore */ }
  };

  const handleDeclassify = async (resourceId: number) => {
    try {
      const res = await fetch(withConnection(`/api/resources/${resourceId}/classify`), { method: 'DELETE' });
      if (res.ok) {
        fetchData();
        fetchClassifications();
      }
    } catch { /* ignore */ }
  };

  const handleAutoClassify = async () => {
    setAutoClassifying(true);
    try {
      const res = await fetch(withConnection('/api/resources/auto-classify'), { method: 'POST' });
      if (res.ok) {
        fetchData();
        fetchClassifications();
      }
    } catch { /* ignore */ }
    setAutoClassifying(false);
  };

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const rt = tab === 'storage' ? 'storage_account' : tab === 'vaults' ? 'key_vault' : '';
      const qs = new URLSearchParams();
      qs.set('limit', '200');
      if (rt) qs.set('resource_type', rt);
      if (riskFilter) qs.set('risk_level', riskFilter);
      if (searchTerm) qs.set('search', searchTerm);

      if (classFilter) qs.set('classification', classFilter);

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
  }, [tab, riskFilter, searchTerm, classFilter, withConnection]);

  useEffect(() => { fetchData(); }, [fetchData]);
  useEffect(() => { fetchClassifications(); }, [fetchClassifications]);

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
      ? ['network_exposure', 'auth_posture', 'logging_audit', 'data_protection', 'identity_exposure']
      : ['network_exposure', 'vault_protection', 'identity_access', 'secret_hygiene', 'identity_exposure'];

  // ─── Render ───
  return (
    <div style={{ padding: '24px 32px', maxWidth: 1440, margin: '0 auto', color: G.text }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0, letterSpacing: '-0.02em' }}>
            Data &amp; Resource Exposure
          </h1>
          <p style={{ fontSize: 12, color: G.textMuted, margin: '4px 0 0' }}>
            Component-based risk intelligence for data resources
          </p>
          <SnapshotContextHeader />
        </div>
        <button onClick={handleAutoClassify} disabled={autoClassifying} style={{
          background: autoClassifying ? 'rgba(255,255,255,0.04)' : G.accent,
          color: '#FFF', border: 'none', borderRadius: 6, padding: '8px 16px',
          fontSize: 12, fontWeight: 600, cursor: autoClassifying ? 'default' : 'pointer',
          opacity: autoClassifying ? 0.6 : 1,
        }}>
          {autoClassifying ? 'Classifying...' : 'Auto-Classify Resources'}
        </button>
      </div>

      {/* Sensitive Data Inventory */}
      {classStats && (classStats.by_classification.PHI > 0 || classStats.by_classification.PCI > 0 || classStats.by_classification.PII > 0) && (
        <div style={{
          background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10,
          padding: 20, marginBottom: 24,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <div style={{ fontSize: 13, fontWeight: 600 }}>Sensitive Data Inventory</div>
            {blastRadius && blastRadius.summary.highest_risk_identity && (
              <span style={{ fontSize: 10, color: G.severity.high, fontFamily: G.mono }}>
                Highest exposure: {blastRadius.summary.highest_risk_identity}
              </span>
            )}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            <div style={{ background: CLASS_COLORS.PHI.bg, border: `1px solid ${CLASS_COLORS.PHI.border}`, borderRadius: 8, padding: '12px 16px', cursor: 'pointer' }}
              onClick={() => setClassFilter(classFilter === 'PHI' ? '' : 'PHI')}>
              <div style={{ fontSize: 22, fontWeight: 700, color: CLASS_COLORS.PHI.fg, fontFamily: G.mono, width: 'fit-content', borderBottom: '1px dashed currentColor' }}>
                {(classStats.by_classification.PHI || 0).toLocaleString()}
              </div>
              <div style={{ fontSize: 11, color: G.textSecondary }}>PHI Resources</div>
              {blastRadius && <div style={{ fontSize: 10, color: G.textMuted, marginTop: 2 }}>
                {blastRadius.summary.total_identities_with_phi_access} identities with access
              </div>}
            </div>
            <div style={{ background: CLASS_COLORS.PCI.bg, border: `1px solid ${CLASS_COLORS.PCI.border}`, borderRadius: 8, padding: '12px 16px', cursor: 'pointer' }}
              onClick={() => setClassFilter(classFilter === 'PCI' ? '' : 'PCI')}>
              <div style={{ fontSize: 22, fontWeight: 700, color: CLASS_COLORS.PCI.fg, fontFamily: G.mono, width: 'fit-content', borderBottom: '1px dashed currentColor' }}>
                {(classStats.by_classification.PCI || 0).toLocaleString()}
              </div>
              <div style={{ fontSize: 11, color: G.textSecondary }}>PCI Resources</div>
              {blastRadius && <div style={{ fontSize: 10, color: G.textMuted, marginTop: 2 }}>
                {blastRadius.summary.total_identities_with_pci_access} identities with access
              </div>}
            </div>
            <div style={{ background: CLASS_COLORS.PII.bg, border: `1px solid ${CLASS_COLORS.PII.border}`, borderRadius: 8, padding: '12px 16px', cursor: 'pointer' }}
              onClick={() => setClassFilter(classFilter === 'PII' ? '' : 'PII')}>
              <div style={{ fontSize: 22, fontWeight: 700, color: CLASS_COLORS.PII.fg, fontFamily: G.mono, width: 'fit-content', borderBottom: '1px dashed currentColor' }}>
                {(classStats.by_classification.PII || 0).toLocaleString()}
              </div>
              <div style={{ fontSize: 11, color: G.textSecondary }}>PII Resources</div>
              {blastRadius && <div style={{ fontSize: 10, color: G.textMuted, marginTop: 2 }}>
                {blastRadius.summary.total_identities_with_pii_access} identities with access
              </div>}
            </div>
            <div style={{ background: 'rgba(255,255,255,0.04)', border: `1px solid ${G.surfaceBorder}`, borderRadius: 8, padding: '12px 16px', cursor: 'pointer' }}
              onClick={() => setClassFilter(classFilter === 'unclassified' ? '' : 'unclassified')}>
              <div style={{ fontSize: 22, fontWeight: 700, color: G.textMuted, fontFamily: G.mono, width: 'fit-content', borderBottom: '1px dashed currentColor' }}>
                {classStats.unclassified_count.toLocaleString()}
              </div>
              <div style={{ fontSize: 11, color: G.textSecondary }}>Unclassified</div>
              <div style={{ fontSize: 10, color: G.textMuted, marginTop: 2 }}>
                {classStats.total_resources} total resources
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Summary Cards */}
      {summary && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, marginBottom: 24 }}>
          <StatCard label="Total Resources" value={summary.total} color={G.accent} onClick={() => navigate('/resources')} />
          <StatCard label="Storage Accounts" value={summary.storage_accounts} color="#60A5FA" onClick={() => navigate('/storage-accounts')} />
          <StatCard label="Key Vaults" value={summary.key_vaults} color="#A78BFA" onClick={() => navigate('/key-vaults')} />
          <StatCard label="At Risk" value={summary.at_risk} color={G.severity.critical}
            subtitle={`${summary.by_risk.critical || 0} critical, ${summary.by_risk.high || 0} high`} onClick={() => navigate('/resources?risk=critical')} />
          <StatCard label="Avg Risk Score" value={summary.avg_score} color={
            summary.avg_score >= 50 ? G.severity.high : summary.avg_score >= 30 ? G.severity.medium : G.severity.low
          } onClick={() => navigate('/resources')} />
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
          <select value={classFilter} onChange={e => setClassFilter(e.target.value)} style={{
            background: 'rgba(255,255,255,0.04)', border: `1px solid ${G.surfaceBorder}`, borderRadius: 6,
            padding: '6px 10px', fontSize: 12, color: G.text, outline: 'none',
          }}>
            <option value="">All Classifications</option>
            <option value="PHI">PHI</option>
            <option value="PCI">PCI</option>
            <option value="PII">PII</option>
            <option value="unclassified">Unclassified</option>
          </select>
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
                    { key: 'data_classification', label: 'Classification' },
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
                    Trend
                  </th>
                  <th style={{ padding: '10px 12px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: G.textMuted, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Components
                  </th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={9} style={{ padding: 40, textAlign: 'center', color: G.textMuted }}>Loading...</td></tr>
                ) : sorted.length === 0 ? (
                  <tr><td colSpan={9} style={{ padding: 40, textAlign: 'center', color: G.textMuted }}>No resources found</td></tr>
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
                      <td style={{ padding: '10px 12px' }}><ClassificationBadge classification={r.data_classification} /></td>
                      <td style={{ padding: '10px 12px' }}><RiskBadge level={r.risk_level} /></td>
                      <td style={{ padding: '10px 12px', fontFamily: G.mono, fontWeight: 600, color: G.severity[r.risk_level] || G.text }}>
                        {r.risk_score}
                      </td>
                      <td style={{ padding: '10px 12px', color: G.textSecondary, fontSize: 11 }}>{r.location || '\u2014'}</td>
                      <td style={{ padding: '10px 12px', color: G.textSecondary, fontSize: 11, maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {r.subscription_name || '\u2014'}
                      </td>
                      <td style={{ padding: '10px 12px', width: 60 }}>
                        {r.risk_trend_direction === 'up' ? (
                          <span style={{ color: G.severity.critical, fontWeight: 600, fontSize: 11 }}>{'\u2191'} +{r.risk_trend_delta}</span>
                        ) : r.risk_trend_direction === 'down' ? (
                          <span style={{ color: G.severity.low, fontWeight: 600, fontSize: 11 }}>{'\u2193'} {r.risk_trend_delta}</span>
                        ) : (
                          <span style={{ color: G.textMuted, fontSize: 11 }}>{'\u2014'}</span>
                        )}
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

            {/* Data Classification */}
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 10 }}>Data Classification</div>
              {selectedResource.data_classification ? (
                <div style={{
                  background: CLASS_COLORS[selectedResource.data_classification]?.bg || 'rgba(255,255,255,0.04)',
                  border: `1px solid ${CLASS_COLORS[selectedResource.data_classification]?.border || G.surfaceBorder}`,
                  borderRadius: 8, padding: 12,
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <ClassificationBadge classification={selectedResource.data_classification} />
                    <button onClick={() => handleDeclassify(selectedResource.id)} style={{
                      background: 'none', border: 'none', color: G.textMuted, cursor: 'pointer', fontSize: 10,
                    }}>Remove</button>
                  </div>
                  {selectedResource.classification_source && (
                    <div style={{ fontSize: 10, color: G.textMuted, marginTop: 6 }}>
                      Source: {selectedResource.classification_source}
                    </div>
                  )}
                </div>
              ) : (
                <button
                  onClick={() => { setClassifyTarget(selectedResource); setShowClassifyModal(true); }}
                  style={{
                    width: '100%', padding: '10px 0', borderRadius: 6,
                    border: `1px dashed ${G.surfaceBorder}`, background: 'transparent',
                    color: G.textSecondary, fontSize: 12, cursor: 'pointer',
                  }}
                >
                  + Classify this resource
                </button>
              )}
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
              Open Full Detail →
            </button>
          </div>
        )}
      </div>

      {/* Blast Radius — Identities with Sensitive Access */}
      {blastRadius && blastRadius.identities_with_sensitive_access.length > 0 && (
        <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 10, padding: 20, marginTop: 24 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 14 }}>
            Identities with Sensitive Data Access
            <span style={{ fontSize: 10, color: G.textMuted, marginLeft: 8 }}>
              {blastRadius.identities_with_sensitive_access.length} identities
            </span>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${G.surfaceBorder}` }}>
                  {['Identity', 'Type', 'PHI', 'PCI', 'PII', 'Total', 'Highest Access', 'Risk'].map(h => (
                    <th key={h} style={{ padding: '8px 10px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: G.textMuted, textTransform: 'uppercase' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {blastRadius.identities_with_sensitive_access.slice(0, 20).map(id => (
                  <tr key={id.identity_db_id} style={{ borderBottom: `1px solid ${G.surfaceBorder}`, cursor: 'pointer' }}
                    onClick={() => navigate(`/identities/${id.identity_id}`)}>
                    <td style={{ padding: '8px 10px', fontWeight: 500 }}>{id.display_name}</td>
                    <td style={{ padding: '8px 10px', color: G.textSecondary }}>{id.identity_category || id.identity_type}</td>
                    <td style={{ padding: '8px 10px', fontFamily: G.mono, color: id.phi_count > 0 ? CLASS_COLORS.PHI.fg : G.textMuted }}>{id.phi_count}</td>
                    <td style={{ padding: '8px 10px', fontFamily: G.mono, color: id.pci_count > 0 ? CLASS_COLORS.PCI.fg : G.textMuted }}>{id.pci_count}</td>
                    <td style={{ padding: '8px 10px', fontFamily: G.mono, color: id.pii_count > 0 ? CLASS_COLORS.PII.fg : G.textMuted }}>{id.pii_count}</td>
                    <td style={{ padding: '8px 10px', fontFamily: G.mono, fontWeight: 600 }}>{id.sensitive_resources_count}</td>
                    <td style={{ padding: '8px 10px' }}>
                      <span style={{
                        padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 600,
                        background: id.highest_access === 'Admin' ? 'rgba(239,68,68,0.12)' : id.highest_access === 'Write' ? 'rgba(251,191,36,0.12)' : 'rgba(96,165,250,0.12)',
                        color: id.highest_access === 'Admin' ? '#F87171' : id.highest_access === 'Write' ? '#FBBF24' : '#60A5FA',
                      }}>{id.highest_access}</span>
                    </td>
                    <td style={{ padding: '8px 10px' }}><RiskBadge level={id.risk_level} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Classify Modal */}
      {showClassifyModal && classifyTarget && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', display: 'flex',
          justifyContent: 'center', alignItems: 'center', zIndex: 9999,
        }} onClick={() => setShowClassifyModal(false)}>
          <div style={{
            background: G.surface, border: `1px solid ${G.surfaceBorder}`, borderRadius: 12,
            padding: 24, width: 400, maxWidth: '90vw',
          }} onClick={e => e.stopPropagation()}>
            <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 4 }}>Classify Resource</div>
            <div style={{ fontSize: 12, color: G.textMuted, marginBottom: 20 }}>{classifyTarget.name}</div>

            <div style={{ marginBottom: 16 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: G.textSecondary, display: 'block', marginBottom: 6 }}>
                Classification
              </label>
              <div style={{ display: 'flex', gap: 8 }}>
                {(['PHI', 'PCI', 'PII'] as const).map(c => (
                  <button key={c} onClick={() => setClassifyValue(c)} style={{
                    flex: 1, padding: '10px 0', borderRadius: 6, fontSize: 13, fontWeight: 700,
                    fontFamily: G.mono, cursor: 'pointer', transition: 'all 0.15s',
                    border: classifyValue === c ? `2px solid ${CLASS_COLORS[c].fg}` : `1px solid ${G.surfaceBorder}`,
                    background: classifyValue === c ? CLASS_COLORS[c].bg : 'transparent',
                    color: classifyValue === c ? CLASS_COLORS[c].fg : G.textSecondary,
                  }}>{c}</button>
                ))}
              </div>
            </div>

            <div style={{ marginBottom: 20 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: G.textSecondary, display: 'block', marginBottom: 6 }}>
                Notes (optional)
              </label>
              <textarea value={classifyNotes} onChange={e => setClassifyNotes(e.target.value)}
                placeholder="e.g., Contains patient audit trail data"
                style={{
                  width: '100%', padding: 10, borderRadius: 6, border: `1px solid ${G.surfaceBorder}`,
                  background: 'rgba(255,255,255,0.04)', color: G.text, fontSize: 12, resize: 'vertical',
                  minHeight: 60, outline: 'none', boxSizing: 'border-box',
                }}
              />
            </div>

            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button onClick={() => setShowClassifyModal(false)} style={{
                padding: '8px 16px', borderRadius: 6, border: `1px solid ${G.surfaceBorder}`,
                background: 'transparent', color: G.textSecondary, fontSize: 12, cursor: 'pointer',
              }}>Cancel</button>
              <button onClick={handleClassify} style={{
                padding: '8px 20px', borderRadius: 6, border: 'none',
                background: CLASS_COLORS[classifyValue]?.fg || G.accent,
                color: '#FFF', fontSize: 12, fontWeight: 600, cursor: 'pointer',
              }}>Classify as {classifyValue}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
