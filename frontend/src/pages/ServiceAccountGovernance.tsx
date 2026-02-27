import React, { useEffect, useState, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useConnection } from '../contexts/ConnectionContext';

// ─── Theme-aware constants (page-scoped) ───
const G = {
  bg: 'var(--bg-primary)',
  surface: 'var(--bg-secondary)',
  surfaceBorder: 'var(--border-default)',
  surfaceHover: 'var(--bg-hover)',
  text: 'var(--text-primary)',
  textSecondary: 'var(--text-secondary)',
  textMuted: 'var(--text-tertiary)',
  band: { Critical: '#FF1744', High: '#FF6D00', Medium: '#FFB300', Low: '#4ADE80' } as Record<string, string>,
  bandBg: { Critical: 'rgba(255,23,68,0.12)', High: 'rgba(255,109,0,0.12)', Medium: 'rgba(255,179,0,0.12)', Low: 'rgba(74,222,128,0.12)' } as Record<string, string>,
  govStatus: { compliant: '#4ADE80', needs_attention: '#FFB300', non_compliant: '#FF1744' } as Record<string, string>,
  cred: { expired: '#FF1744', expiring_soon: '#FFB300', healthy: '#4ADE80', unknown: 'var(--text-tertiary)' } as Record<string, string>,
  accent: '#8B5CF6',
  mono: "'JetBrains Mono', monospace",
  action: {
    Revoke: '#FF1744', Downgrade: '#FF6D00', Rotate: '#FFB300',
    'Re-attest': '#42A5F5', 'Assign Owner': '#AB47BC', Approve: '#4ADE80',
    None: 'var(--text-tertiary)', 'JIT Convert': '#26C6DA',
  } as Record<string, string>,
};

// ─── Types ───
interface GovStats {
  total: number;
  risk_distribution: Record<string, number>;
  governance_breakdown: Record<string, number>;
  action_summary: Record<string, number>;
  top_risk: { identity_id: string; display_name: string; risk_score: number; risk_band: string; recommended_action: string }[];
  recent_decisions: number;
}

interface RiskFactor {
  factor: string;
  impact: number;
  category: string;
}

interface GovItem {
  identity_id: string;
  identity_db_id: number;
  display_name: string;
  identity_category: string;
  risk_score: number;
  risk_band: string;
  risk_factors: RiskFactor[];
  governance_status: string;
  governance_issues: string[];
  recommended_action: string;
  recommended_detail: string;
  expected_reduction: number;
  owner_display_name: string | null;
  owner_count: number;
  credential_risk: string | null;
  credential_count: number;
  activity_status: string;
  last_sign_in: string | null;
  top_role: string;
  role_count: number;
  permission_count: number;
  last_decision: { decision: string; decided_by: string; created_at: string } | null;
}

interface GovDetail {
  identity_id: string;
  identity_db_id: number;
  display_name: string;
  identity_category: string;
  app_id: string | null;
  risk_score: number;
  risk_band: string;
  risk_factors: RiskFactor[];
  category_scores: Record<string, number>;
  governance_status: string;
  governance_issues: string[];
  recommended_action: string;
  recommended_detail: string;
  expected_reduction: number;
  owner_count: number;
  owners: { owner_display_name: string; owner_id: string; owner_type: string }[];
  credential_risk: string | null;
  credential_count: number;
  credentials: { credential_type: string; display_name: string; start_datetime: string | null; end_datetime: string | null }[];
  activity_status: string;
  last_sign_in: string | null;
  created_datetime: string | null;
  roles: { role_name: string; scope: string; scope_type: string }[];
  entra_roles: { role_name: string; is_permanent: boolean }[];
  graph_permissions: { permission_name: string; permission_type: string }[];
  attestation: { status: string; attested_at: string; next_due: string; attester_name: string; justification: string } | null;
  decisions: { decision: string; reason: string; risk_score_snapshot: number; risk_band_snapshot: string; created_at: string; decided_by_name: string; exception_expiry: string | null }[];
}

const CATEGORY_LABELS: Record<string, string> = {
  service_principal: 'Service Principal',
  managed_identity_system: 'System MI',
  managed_identity_user: 'User MI',
};

const DECISION_OPTIONS = [
  { key: 'approve', label: 'Approve', desc: 'Certify current access is appropriate', color: '#4ADE80' },
  { key: 'revoke', label: 'Revoke', desc: 'Remove all access immediately', color: '#FF1744' },
  { key: 'downgrade', label: 'Downgrade', desc: 'Reduce privilege level', color: '#FF6D00' },
  { key: 'rotate', label: 'Rotate', desc: 'Rotate credentials now', color: '#FFB300' },
  { key: 'jit_converted', label: 'JIT Convert', desc: 'Convert to just-in-time access', color: '#26C6DA' },
  { key: 'exception', label: 'Exception', desc: 'Grant temporary exception', color: '#AB47BC' },
];

const RISK_BANDS = ['All', 'Critical', 'High', 'Medium', 'Low'];

type SortField = 'display_name' | 'risk_score' | 'identity_category' | 'owner_count' | 'credential_risk' | 'activity_status' | 'last_sign_in';

export default function ServiceAccountGovernance() {
  const { isAdmin, isReader } = useAuth();
  const { withConnection, selectedConnectionId } = useConnection();
  const canDecide = isAdmin || !isReader;

  const [stats, setStats] = useState<GovStats | null>(null);
  const [items, setItems] = useState<GovItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [activeBand, setActiveBand] = useState('All');
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState<SortField>('risk_score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(0);
  const pageSize = 50;

  // Detail panel
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<GovDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailTab, setDetailTab] = useState<'risk' | 'access' | 'history'>('risk');

  // Decision modal
  const [decisionTarget, setDecisionTarget] = useState<GovItem | null>(null);
  const [decisionType, setDecisionType] = useState('approve');
  const [decisionReason, setDecisionReason] = useState('');
  const [exceptionExpiry, setExceptionExpiry] = useState('');
  const [decisionSubmitting, setDecisionSubmitting] = useState(false);

  const [toast, setToast] = useState<{ msg: string; type: string } | null>(null);
  const animRef = useRef(false);

  // ─── Data loading ───
  const loadList = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        search,
        sort_by: sortBy,
        sort_dir: sortDir,
        limit: String(pageSize),
        offset: String(page * pageSize),
      });
      if (activeBand !== 'All') params.set('risk_band', activeBand);

      const res = await fetch(withConnection(`/api/governance/identities?${params}`));
      if (res.ok) {
        const d = await res.json();
        setItems(d.items || []);
        setTotal(d.total || 0);
      }
    } catch { /* ignore */ }
    setLoading(false);
  }, [activeBand, search, sortBy, sortDir, page, selectedConnectionId]);

  const loadStats = useCallback(async () => {
    try {
      const res = await fetch(withConnection('/api/governance/stats'));
      if (res.ok) setStats(await res.json());
    } catch { /* ignore */ }
  }, [selectedConnectionId]);

  useEffect(() => { loadStats(); }, [loadStats]);
  useEffect(() => { loadList(); }, [loadList]);

  useEffect(() => {
    if (!animRef.current) {
      animRef.current = true;
    }
  }, []);

  // Load detail when selected
  useEffect(() => {
    if (!selectedId) { setDetail(null); return; }
    let cancelled = false;
    setDetailLoading(true);
    setDetailTab('risk');
    fetch(withConnection(`/api/governance/identities/${selectedId}`))
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (!cancelled) { setDetail(d); setDetailLoading(false); } })
      .catch(() => { if (!cancelled) setDetailLoading(false); });
    return () => { cancelled = true; };
  }, [selectedId, selectedConnectionId]);

  // ─── Handlers ───
  function handleSort(field: SortField) {
    if (sortBy === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(field);
      setSortDir(field === 'display_name' ? 'asc' : 'desc');
    }
    setPage(0);
  }

  function sortArrow(field: SortField) {
    if (sortBy !== field) return '';
    return sortDir === 'asc' ? ' \u2191' : ' \u2193';
  }

  async function handleDecision() {
    if (!decisionTarget || !decisionReason.trim()) return;
    setDecisionSubmitting(true);
    try {
      const body: Record<string, string> = { decision: decisionType, reason: decisionReason };
      if (decisionType === 'exception' && exceptionExpiry) body.exception_expiry = exceptionExpiry;

      const res = await fetch(withConnection(`/api/governance/identities/${decisionTarget.identity_id}/decide`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (res.ok) {
        setToast({ msg: `Decision "${decisionType}" recorded for ${decisionTarget.display_name}`, type: 'success' });
        setDecisionTarget(null);
        setDecisionReason('');
        setExceptionExpiry('');
        loadList();
        loadStats();
        if (selectedId === decisionTarget.identity_id) {
          // Refresh detail
          fetch(withConnection(`/api/governance/identities/${selectedId}`))
            .then(r => r.ok ? r.json() : null)
            .then(d => setDetail(d))
            .catch(() => {});
        }
      } else {
        const d = await res.json().catch(() => ({}));
        setToast({ msg: d.error || 'Decision failed', type: 'error' });
      }
    } catch {
      setToast({ msg: 'Network error', type: 'error' });
    }
    setDecisionSubmitting(false);
  }

  useEffect(() => {
    if (toast) {
      const t = setTimeout(() => setToast(null), 4000);
      return () => clearTimeout(t);
    }
  }, [toast]);

  function fmtDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  }

  const totalPages = Math.ceil(total / pageSize);
  const rd = stats?.risk_distribution || {};
  const gb = stats?.governance_breakdown || {};

  // ─── Render ───
  return (
    <div style={{ background: G.bg, fontFamily: "'Inter', sans-serif" }} className="min-h-screen -m-4 -mt-4 p-8">
      <style>{`
        @keyframes gov-fade-up { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
        .gov-card { animation: gov-fade-up 0.4s ease-out both; }
        .gov-card-1 { animation-delay: 0.05s; }
        .gov-card-2 { animation-delay: 0.1s; }
        .gov-card-3 { animation-delay: 0.15s; }
        .gov-card-4 { animation-delay: 0.2s; }
        .gov-card-5 { animation-delay: 0.25s; }
        .gov-row:hover { background: ${G.surfaceHover} !important; }
      `}</style>

      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <div className="flex items-center gap-3">
            <span style={{ background: 'rgba(139,92,246,0.15)', color: G.accent, fontFamily: G.mono }}
                  className="px-2.5 py-1 rounded text-[10px] font-semibold tracking-wider uppercase">
              Identity Governance
            </span>
            {stats && (
              <span style={{ color: G.textMuted }} className="text-xs">
                {stats.total} identities under governance
              </span>
            )}
          </div>
          <h1 style={{ color: G.text }} className="text-2xl font-bold mt-2">
            Non-Human Identity Certification
          </h1>
          <p style={{ color: G.textMuted }} className="text-sm mt-1">
            Risk-aware governance decisions for service principals and managed identities
          </p>
        </div>
        {stats && stats.recent_decisions > 0 && (
          <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}` }}
               className="rounded-lg px-4 py-2 text-right">
            <div style={{ color: G.textMuted }} className="text-[10px] uppercase tracking-wider">Decisions (30d)</div>
            <div style={{ color: G.accent, fontFamily: G.mono }} className="text-xl font-bold">{stats.recent_decisions}</div>
          </div>
        )}
      </div>

      {/* Summary Cards */}
      {stats && (
        <div className="grid grid-cols-5 gap-4 mb-6">
          {/* Total + Risk Distribution */}
          <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}` }}
               className="gov-card gov-card-1 rounded-xl p-4">
            <div>
              <div style={{ color: G.textMuted }} className="text-[10px] uppercase tracking-wider font-medium">Total NHIs</div>
              <button onClick={() => { setActiveBand('All'); setPage(0); }} className="cursor-pointer hover:opacity-70 transition">
                <div style={{ color: G.text, fontFamily: G.mono, width: 'fit-content', borderBottom: '1px dashed currentColor' }} className="text-3xl font-bold mt-1">{stats.total.toLocaleString()}</div>
              </button>
              <div className="flex gap-1 mt-3">
                {['Critical', 'High', 'Medium', 'Low'].map(b => (
                  <button key={b} className="flex-1 text-center cursor-pointer hover:opacity-70 transition" onClick={() => { setActiveBand(b); setPage(0); }}>
                    <div style={{ color: (rd[b] || 0) === 0 ? G.textMuted : G.band[b], fontFamily: G.mono, borderBottom: '1px dashed currentColor', width: 'fit-content', margin: '0 auto' }} className="text-sm font-bold">{(rd[b] || 0).toLocaleString()}</div>
                    <div style={{ color: G.textMuted }} className="text-[9px]">{b}</div>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Critical */}
          <div style={{ background: (rd.Critical || 0) === 0 ? G.surface : G.bandBg.Critical, border: `1px solid ${(rd.Critical || 0) === 0 ? G.surfaceBorder : 'rgba(255,23,68,0.2)'}` }}
               className="gov-card gov-card-2 rounded-xl p-4 cursor-pointer transition hover:scale-[1.01]"
               onClick={() => { setActiveBand('Critical'); setPage(0); }}>
            <div style={{ color: (rd.Critical || 0) === 0 ? G.textMuted : G.band.Critical }} className="text-[10px] uppercase tracking-wider font-medium">Critical Risk</div>
            <div style={{ color: (rd.Critical || 0) === 0 ? G.textMuted : G.band.Critical, fontFamily: G.mono, width: 'fit-content', borderBottom: '1px dashed currentColor' }} className="text-3xl font-bold mt-1">{(rd.Critical || 0).toLocaleString()}</div>
            <div style={{ color: G.textMuted }} className="text-[10px] mt-2">Immediate action required</div>
          </div>

          {/* High */}
          <div style={{ background: (rd.High || 0) === 0 ? G.surface : G.bandBg.High, border: `1px solid ${(rd.High || 0) === 0 ? G.surfaceBorder : 'rgba(255,109,0,0.2)'}` }}
               className="gov-card gov-card-3 rounded-xl p-4 cursor-pointer transition hover:scale-[1.01]"
               onClick={() => { setActiveBand('High'); setPage(0); }}>
            <div style={{ color: (rd.High || 0) === 0 ? G.textMuted : G.band.High }} className="text-[10px] uppercase tracking-wider font-medium">High Risk</div>
            <div style={{ color: (rd.High || 0) === 0 ? G.textMuted : G.band.High, fontFamily: G.mono, width: 'fit-content', borderBottom: '1px dashed currentColor' }} className="text-3xl font-bold mt-1">{(rd.High || 0).toLocaleString()}</div>
            <div style={{ color: G.textMuted }} className="text-[10px] mt-2">Review within 7 days</div>
          </div>

          {/* Governance Breakdown */}
          <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}` }}
               className="gov-card gov-card-4 rounded-xl p-4">
            <div style={{ color: G.textMuted }} className="text-[10px] uppercase tracking-wider font-medium">Governance</div>
            <div className="mt-2 space-y-1.5">
              {[
                { key: 'compliant', label: 'Compliant' },
                { key: 'needs_attention', label: 'Attention' },
                { key: 'non_compliant', label: 'Non-Compliant' },
              ].map(g => {
                const count = gb[g.key] || 0;
                const pct = stats.total > 0 ? (count / stats.total) * 100 : 0;
                return (
                  <button key={g.key} className="w-full text-left cursor-pointer hover:opacity-70 transition" onClick={() => { setSearch(g.key); setPage(0); }}>
                    <div className="flex justify-between text-[10px]">
                      <span style={{ color: G.govStatus[g.key] }}>{g.label}</span>
                      <span style={{ color: G.textSecondary, fontFamily: G.mono, borderBottom: '1px dashed currentColor' }}>{count}</span>
                    </div>
                    <div style={{ background: 'rgba(255,255,255,0.06)' }} className="h-1 rounded-full mt-0.5">
                      <div style={{ width: `${pct}%`, background: G.govStatus[g.key], transition: 'width 0.6s ease-out' }}
                           className="h-full rounded-full" />
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Action Summary */}
          <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}` }}
               className="gov-card gov-card-5 rounded-xl p-4">
            <div style={{ color: G.textMuted }} className="text-[10px] uppercase tracking-wider font-medium">Recommended Actions</div>
            <div className="mt-2 space-y-1">
              {Object.entries(stats.action_summary || {})
                .sort((a, b) => b[1] - a[1])
                .slice(0, 4)
                .map(([action, count]) => (
                  <div key={action} className="flex justify-between items-center">
                    <span style={{ color: G.action[action] || G.textSecondary }} className="text-[10px]">{action}</span>
                    <span style={{ color: G.textSecondary, fontFamily: G.mono }} className="text-[10px]">{count}</span>
                  </div>
                ))}
            </div>
          </div>
        </div>
      )}

      {/* Risk Band Tabs + Search */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex gap-1">
          {RISK_BANDS.map(band => (
            <button
              key={band}
              onClick={() => { setActiveBand(band); setPage(0); }}
              style={{
                background: activeBand === band
                  ? (band === 'All' ? G.accent : G.band[band])
                  : G.surface,
                color: activeBand === band ? '#fff' : G.textSecondary,
                border: `1px solid ${activeBand === band ? 'transparent' : G.surfaceBorder}`,
              }}
              className="px-3 py-1.5 rounded-lg text-xs font-medium transition hover:opacity-90"
            >
              {band}
              {band !== 'All' && stats && (
                <span className="ml-1 opacity-70">({rd[band] || 0})</span>
              )}
            </button>
          ))}
        </div>
        <input
          type="text"
          placeholder="Search identities..."
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(0); }}
          style={{
            background: G.surface,
            border: `1px solid ${G.surfaceBorder}`,
            color: G.text,
          }}
          className="px-3 py-1.5 rounded-lg text-xs w-56 outline-none focus:ring-1 focus:ring-purple-500"
        />
      </div>

      {/* Main content area */}
      <div className="flex gap-0">
        {/* Table */}
        <div style={{
          background: G.surface,
          border: `1px solid ${G.surfaceBorder}`,
          flex: selectedId ? '1 1 0' : '1 1 100%',
          transition: 'flex 0.3s ease',
        }} className="rounded-xl overflow-hidden">
          {loading ? (
            <div style={{ color: G.textMuted }} className="p-12 text-center text-sm">Loading...</div>
          ) : items.length === 0 ? (
            <div style={{ color: G.textMuted }} className="p-12 text-center text-sm">
              No identities found{activeBand !== 'All' ? ` in ${activeBand} risk band` : ''}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr style={{ background: 'rgba(255,255,255,0.03)', borderBottom: `1px solid ${G.surfaceBorder}` }}>
                    {[
                      { key: 'display_name' as SortField, label: 'Identity' },
                      { key: 'identity_category' as SortField, label: 'Type' },
                      { key: 'risk_score' as SortField, label: 'Risk' },
                      { key: null, label: 'Action' },
                      { key: null, label: 'Gov Status' },
                      { key: null, label: 'Top Role' },
                      { key: 'credential_risk' as SortField, label: 'Cred Risk' },
                      { key: 'owner_count' as SortField, label: 'Owner' },
                      { key: 'last_sign_in' as SortField, label: 'Last Active' },
                    ].map((col, i) => (
                      <th key={i}
                          onClick={col.key ? () => handleSort(col.key as SortField) : undefined}
                          style={{ color: G.textMuted, cursor: col.key ? 'pointer' : 'default' }}
                          className="text-left px-3 py-2.5 font-semibold text-[10px] uppercase tracking-wider hover:opacity-80">
                        {col.label}{col.key ? sortArrow(col.key as SortField) : ''}
                      </th>
                    ))}
                    {canDecide && <th style={{ color: G.textMuted }} className="text-center px-3 py-2.5 font-semibold text-[10px] uppercase tracking-wider">Decide</th>}
                  </tr>
                </thead>
                <tbody>
                  {items.map(item => {
                    const isSelected = selectedId === item.identity_id;
                    return (
                      <tr key={item.identity_id}
                          className="gov-row cursor-pointer transition"
                          style={{
                            borderBottom: `1px solid ${G.surfaceBorder}`,
                            background: isSelected ? 'rgba(139,92,246,0.08)' : 'transparent',
                          }}
                          onClick={() => setSelectedId(isSelected ? null : item.identity_id)}>
                        <td className="px-3 py-2.5">
                          <div style={{ color: G.text }} className="font-medium truncate max-w-[180px]" title={item.display_name}>
                            {item.display_name}
                          </div>
                        </td>
                        <td className="px-3 py-2.5">
                          <span style={{ background: 'rgba(255,255,255,0.06)', color: G.textSecondary }}
                                className="px-1.5 py-0.5 rounded text-[10px]">
                            {CATEGORY_LABELS[item.identity_category] || item.identity_category}
                          </span>
                        </td>
                        <td className="px-3 py-2.5">
                          <div className="flex items-center gap-1.5">
                            <span style={{
                              background: G.bandBg[item.risk_band] || G.surface,
                              color: G.band[item.risk_band] || G.textSecondary,
                              fontFamily: G.mono,
                            }} className="px-1.5 py-0.5 rounded text-[10px] font-bold">
                              {item.risk_score}
                            </span>
                            <span style={{ color: G.band[item.risk_band] || G.textMuted }}
                                  className="text-[9px] font-medium">
                              {item.risk_band}
                            </span>
                          </div>
                          {item.expected_reduction > 0 && (
                            <div style={{ color: '#4ADE80' }} className="text-[9px] mt-0.5">
                              -{item.expected_reduction}pts possible
                            </div>
                          )}
                        </td>
                        <td className="px-3 py-2.5">
                          <span style={{
                            color: G.action[item.recommended_action] || G.textSecondary,
                            borderColor: G.action[item.recommended_action] || G.surfaceBorder,
                          }} className="text-[10px] font-semibold">
                            {item.recommended_action}
                          </span>
                        </td>
                        <td className="px-3 py-2.5">
                          <span style={{
                            background: `${G.govStatus[item.governance_status] || G.textMuted}15`,
                            color: G.govStatus[item.governance_status] || G.textMuted,
                          }} className="px-1.5 py-0.5 rounded text-[10px] font-medium">
                            {item.governance_status === 'non_compliant' ? 'Non-Compliant' :
                             item.governance_status === 'needs_attention' ? 'Attention' : 'Compliant'}
                          </span>
                        </td>
                        <td className="px-3 py-2.5">
                          <span style={{ color: G.textSecondary }} className="text-[10px] truncate block max-w-[120px]" title={item.top_role}>
                            {item.top_role || '-'}
                          </span>
                          {item.role_count > 1 && (
                            <span style={{ color: G.textMuted }} className="text-[9px]">+{item.role_count - 1} more</span>
                          )}
                        </td>
                        <td className="px-3 py-2.5">
                          <span style={{
                            color: G.cred[item.credential_risk || ''] || G.cred.unknown,
                          }} className="text-[10px] font-medium">
                            {item.credential_risk || 'N/A'}
                          </span>
                          {item.credential_count > 0 && (
                            <span style={{ color: G.textMuted }} className="text-[9px] ml-1">({item.credential_count})</span>
                          )}
                        </td>
                        <td className="px-3 py-2.5">
                          {item.owner_count > 0 ? (
                            <span style={{ color: G.textSecondary }} className="text-[10px]">
                              {item.owner_display_name || `${item.owner_count}`}
                            </span>
                          ) : (
                            <span style={{ color: '#FF1744' }} className="text-[10px] font-medium">None</span>
                          )}
                        </td>
                        <td className="px-3 py-2.5">
                          <span style={{ color: G.textMuted }} className="text-[10px]">{fmtDate(item.last_sign_in)}</span>
                        </td>
                        {canDecide && (
                          <td className="px-3 py-2.5 text-center" onClick={e => e.stopPropagation()}>
                            <button
                              onClick={() => { setDecisionTarget(item); setDecisionType(item.recommended_action === 'Approve' ? 'approve' : item.recommended_action === 'Revoke' ? 'revoke' : item.recommended_action === 'Downgrade' ? 'downgrade' : item.recommended_action === 'Rotate' ? 'rotate' : 'approve'); setDecisionReason(''); }}
                              style={{ background: 'rgba(139,92,246,0.12)', color: G.accent }}
                              className="px-2 py-1 rounded text-[10px] font-medium hover:opacity-80 transition">
                              Decide
                            </button>
                          </td>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div style={{ borderTop: `1px solid ${G.surfaceBorder}` }}
                 className="flex items-center justify-between px-4 py-3">
              <span style={{ color: G.textMuted }} className="text-xs">{total} total</span>
              <div className="flex gap-1">
                <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
                        style={{ background: G.surface, color: G.textSecondary }}
                        className="px-2.5 py-1 rounded text-xs disabled:opacity-30">
                  Prev
                </button>
                <span style={{ color: G.textMuted }} className="px-2.5 py-1 text-xs">{page + 1}/{totalPages}</span>
                <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}
                        style={{ background: G.surface, color: G.textSecondary }}
                        className="px-2.5 py-1 rounded text-xs disabled:opacity-30">
                  Next
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Detail Side Panel */}
        {selectedId && (
          <div style={{
            width: '520px',
            minWidth: '520px',
            background: 'rgba(255,255,255,0.015)',
            borderLeft: `1px solid ${G.surfaceBorder}`,
            borderTop: `1px solid ${G.surfaceBorder}`,
            borderBottom: `1px solid ${G.surfaceBorder}`,
            borderRight: `1px solid ${G.surfaceBorder}`,
            borderRadius: '0 12px 12px 0',
            marginLeft: '-1px',
          }} className="overflow-y-auto max-h-[calc(100vh-200px)]">
            {detailLoading ? (
              <div style={{ color: G.textMuted }} className="p-8 text-center text-sm">Loading...</div>
            ) : !detail ? (
              <div style={{ color: G.textMuted }} className="p-8 text-center text-sm">Not found</div>
            ) : (
              <div className="p-5 space-y-5">
                {/* Header */}
                <div className="flex items-start justify-between">
                  <div>
                    <h3 style={{ color: G.text }} className="text-sm font-bold truncate max-w-[350px]" title={detail.display_name}>
                      {detail.display_name}
                    </h3>
                    <div className="flex items-center gap-2 mt-1">
                      <span style={{ background: 'rgba(255,255,255,0.06)', color: G.textSecondary }}
                            className="px-1.5 py-0.5 rounded text-[10px]">
                        {CATEGORY_LABELS[detail.identity_category] || detail.identity_category}
                      </span>
                      <span style={{
                        background: `${G.govStatus[detail.governance_status] || G.textMuted}15`,
                        color: G.govStatus[detail.governance_status] || G.textMuted,
                      }} className="px-1.5 py-0.5 rounded text-[10px] font-medium">
                        {detail.governance_status === 'non_compliant' ? 'Non-Compliant' :
                         detail.governance_status === 'needs_attention' ? 'Attention' : 'Compliant'}
                      </span>
                    </div>
                  </div>
                  <button onClick={() => setSelectedId(null)} style={{ color: G.textMuted }}
                          className="hover:opacity-70 text-lg leading-none">&times;</button>
                </div>

                {/* Risk Score Gauge */}
                <div style={{ background: G.bandBg[detail.risk_band], border: `1px solid ${G.band[detail.risk_band]}20` }}
                     className="rounded-xl p-4 text-center">
                  <div style={{ color: G.band[detail.risk_band], fontFamily: G.mono }}
                       className="text-4xl font-bold">{detail.risk_score}</div>
                  <div style={{ color: G.band[detail.risk_band] }} className="text-xs font-semibold mt-1">
                    {detail.risk_band} Risk
                  </div>
                  {detail.expected_reduction > 0 && (
                    <div style={{ color: '#4ADE80' }} className="text-[10px] mt-2">
                      {detail.recommended_action}: -{detail.expected_reduction}pts
                    </div>
                  )}
                </div>

                {/* Recommended Action Banner */}
                <div style={{
                  background: `${G.action[detail.recommended_action] || G.textMuted}12`,
                  border: `1px solid ${G.action[detail.recommended_action] || G.surfaceBorder}30`,
                }} className="rounded-lg p-3">
                  <div className="flex items-center gap-2">
                    <span style={{ color: G.action[detail.recommended_action] || G.textSecondary }}
                          className="text-xs font-bold">{detail.recommended_action}</span>
                    <span style={{ color: G.textSecondary }} className="text-[10px]">{detail.recommended_detail}</span>
                  </div>
                </div>

                {/* Detail Tabs */}
                <div className="flex gap-1">
                  {(['risk', 'access', 'history'] as const).map(tab => (
                    <button key={tab} onClick={() => setDetailTab(tab)}
                            style={{
                              background: detailTab === tab ? G.accent : G.surface,
                              color: detailTab === tab ? '#fff' : G.textSecondary,
                            }}
                            className="px-3 py-1.5 rounded-lg text-[10px] font-medium transition">
                      {tab === 'risk' ? 'Risk Factors' : tab === 'access' ? 'Access Detail' : 'Decision History'}
                    </button>
                  ))}
                </div>

                {/* Tab Content */}
                {detailTab === 'risk' && (
                  <div className="space-y-3">
                    {/* Category breakdown */}
                    <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}` }}
                         className="rounded-lg p-3">
                      <div style={{ color: G.textMuted }} className="text-[10px] uppercase tracking-wider mb-2">Category Scores</div>
                      {['privilege', 'governance', 'usage', 'credential', 'exposure'].map(cat => {
                        const catScore = detail.category_scores[cat] || 0;
                        const maxes: Record<string, number> = { privilege: 35, governance: 25, usage: 20, credential: 15, exposure: 10 };
                        const max = maxes[cat] || 10;
                        const pct = Math.max(0, Math.min(100, (catScore / max) * 100));
                        const color = catScore > max * 0.6 ? G.band.Critical : catScore > max * 0.3 ? G.band.Medium : G.band.Low;
                        return (
                          <div key={cat} className="mb-1.5">
                            <div className="flex justify-between text-[10px]">
                              <span style={{ color: G.textSecondary }} className="capitalize">{cat}</span>
                              <span style={{ color, fontFamily: G.mono }}>{catScore}/{max}</span>
                            </div>
                            <div style={{ background: 'rgba(255,255,255,0.06)' }} className="h-1.5 rounded-full mt-0.5">
                              <div style={{ width: `${pct}%`, background: color, transition: 'width 0.6s ease-out' }}
                                   className="h-full rounded-full" />
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    {/* Individual factors */}
                    <div style={{ color: G.textMuted }} className="text-[10px] uppercase tracking-wider">Risk Factors</div>
                    {detail.risk_factors.map((f, i) => (
                      <div key={i} style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}` }}
                           className="rounded-lg p-2.5 flex items-center justify-between">
                        <div className="flex-1">
                          <div style={{ color: G.textSecondary }} className="text-[10px]">{f.factor}</div>
                          <div style={{ color: G.textMuted }} className="text-[9px] capitalize mt-0.5">{f.category}</div>
                        </div>
                        <span style={{
                          color: f.impact > 0 ? G.band.Critical : '#4ADE80',
                          fontFamily: G.mono,
                        }} className="text-xs font-bold ml-2">
                          {f.impact > 0 ? '+' : ''}{f.impact}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {detailTab === 'access' && (
                  <div className="space-y-3">
                    {/* Roles */}
                    <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}` }}
                         className="rounded-lg p-3">
                      <div style={{ color: G.textMuted }} className="text-[10px] uppercase tracking-wider mb-2">
                        RBAC Roles ({detail.roles.length})
                      </div>
                      {detail.roles.length === 0 ? (
                        <div style={{ color: G.textMuted }} className="text-[10px]">No RBAC roles</div>
                      ) : detail.roles.slice(0, 10).map((r, i) => (
                        <div key={i} className="flex items-center justify-between py-1" style={{ borderBottom: i < Math.min(detail.roles.length, 10) - 1 ? `1px solid ${G.surfaceBorder}` : 'none' }}>
                          <span style={{ color: G.text }} className="text-[10px] font-medium">{r.role_name}</span>
                          <span style={{ color: G.textMuted }} className="text-[9px] truncate max-w-[200px] text-right ml-2" title={r.scope}>
                            {r.scope_type}
                          </span>
                        </div>
                      ))}
                      {detail.roles.length > 10 && (
                        <div style={{ color: G.textMuted }} className="text-[9px] mt-1">+{detail.roles.length - 10} more roles</div>
                      )}
                    </div>

                    {/* Entra Roles */}
                    {detail.entra_roles.length > 0 && (
                      <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}` }}
                           className="rounded-lg p-3">
                        <div style={{ color: G.textMuted }} className="text-[10px] uppercase tracking-wider mb-2">
                          Entra Roles ({detail.entra_roles.length})
                        </div>
                        {detail.entra_roles.map((r, i) => (
                          <div key={i} className="flex items-center justify-between py-1">
                            <span style={{ color: G.text }} className="text-[10px] font-medium">{r.role_name}</span>
                            <span style={{ color: r.is_permanent ? G.band.Critical : G.band.Low }} className="text-[9px]">
                              {r.is_permanent ? 'Permanent' : 'Eligible'}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Credentials */}
                    <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}` }}
                         className="rounded-lg p-3">
                      <div style={{ color: G.textMuted }} className="text-[10px] uppercase tracking-wider mb-2">
                        Credentials ({detail.credentials.length})
                      </div>
                      {detail.credentials.length === 0 ? (
                        <div style={{ color: G.textMuted }} className="text-[10px]">No credentials</div>
                      ) : detail.credentials.map((c, i) => (
                        <div key={i} className="py-1.5" style={{ borderBottom: i < detail.credentials.length - 1 ? `1px solid ${G.surfaceBorder}` : 'none' }}>
                          <div className="flex items-center justify-between">
                            <span style={{ color: G.textSecondary }} className="text-[10px]">{c.credential_type}</span>
                            <span style={{ color: G.textMuted }} className="text-[9px]">
                              {c.end_datetime ? `Exp: ${fmtDate(c.end_datetime)}` : 'No expiry'}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Owners */}
                    <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}` }}
                         className="rounded-lg p-3">
                      <div style={{ color: G.textMuted }} className="text-[10px] uppercase tracking-wider mb-2">
                        Owners ({detail.owners.length})
                      </div>
                      {detail.owners.length === 0 ? (
                        <div style={{ color: '#FF1744' }} className="text-[10px] font-medium">No owner assigned</div>
                      ) : detail.owners.map((o, i) => (
                        <div key={i} style={{ color: G.textSecondary }} className="text-[10px] py-0.5">
                          {o.owner_display_name}
                        </div>
                      ))}
                    </div>

                    {/* Graph Permissions */}
                    {detail.graph_permissions.length > 0 && (
                      <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}` }}
                           className="rounded-lg p-3">
                        <div style={{ color: G.textMuted }} className="text-[10px] uppercase tracking-wider mb-2">
                          API Permissions ({detail.graph_permissions.length})
                        </div>
                        {detail.graph_permissions.slice(0, 8).map((p, i) => (
                          <div key={i} className="flex items-center justify-between py-0.5">
                            <span style={{ color: G.textSecondary }} className="text-[10px]">{p.permission_name}</span>
                            <span style={{ color: G.textMuted }} className="text-[9px]">{p.permission_type}</span>
                          </div>
                        ))}
                        {detail.graph_permissions.length > 8 && (
                          <div style={{ color: G.textMuted }} className="text-[9px] mt-1">+{detail.graph_permissions.length - 8} more</div>
                        )}
                      </div>
                    )}

                    {/* Link to full detail */}
                    <Link to={`/identities/${detail.identity_id}`}
                          style={{ color: G.accent }}
                          className="text-xs hover:underline block text-center mt-2">
                      Open Full Identity Detail &rarr;
                    </Link>
                  </div>
                )}

                {detailTab === 'history' && (
                  <div className="space-y-3">
                    {/* Attestation */}
                    {detail.attestation && (
                      <div style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}` }}
                           className="rounded-lg p-3">
                        <div style={{ color: G.textMuted }} className="text-[10px] uppercase tracking-wider mb-2">Last Attestation</div>
                        <div className="flex items-center justify-between">
                          <span style={{ color: G.textSecondary }} className="text-[10px]">
                            {detail.attestation.attester_name || 'Unknown'} — {detail.attestation.status}
                          </span>
                          <span style={{ color: G.textMuted }} className="text-[9px]">{fmtDate(detail.attestation.attested_at)}</span>
                        </div>
                        {detail.attestation.justification && (
                          <div style={{ color: G.textMuted }} className="text-[9px] mt-1 italic">
                            "{detail.attestation.justification}"
                          </div>
                        )}
                      </div>
                    )}

                    {/* Decision History */}
                    <div style={{ color: G.textMuted }} className="text-[10px] uppercase tracking-wider">
                      Governance Decisions ({detail.decisions.length})
                    </div>
                    {detail.decisions.length === 0 ? (
                      <div style={{ color: G.textMuted }} className="text-[10px]">No decisions recorded yet</div>
                    ) : detail.decisions.map((d, i) => (
                      <div key={i} style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}` }}
                           className="rounded-lg p-3">
                        <div className="flex items-center justify-between">
                          <span style={{ color: G.action[d.decision.charAt(0).toUpperCase() + d.decision.slice(1)] || G.textSecondary }}
                                className="text-[10px] font-bold capitalize">{d.decision.replace(/_/g, ' ')}</span>
                          <span style={{ color: G.textMuted }} className="text-[9px]">{fmtDate(d.created_at)}</span>
                        </div>
                        <div style={{ color: G.textSecondary }} className="text-[10px] mt-1">{d.reason}</div>
                        <div className="flex items-center gap-2 mt-1">
                          <span style={{ color: G.textMuted }} className="text-[9px]">by {d.decided_by_name || 'Unknown'}</span>
                          <span style={{ color: G.band[d.risk_band_snapshot] || G.textMuted, fontFamily: G.mono }}
                                className="text-[9px]">
                            Risk: {d.risk_score_snapshot}
                          </span>
                        </div>
                        {d.exception_expiry && (
                          <div style={{ color: '#AB47BC' }} className="text-[9px] mt-1">
                            Exception expires: {fmtDate(d.exception_expiry)}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {/* Quick Decision from Panel */}
                {canDecide && (
                  <button
                    onClick={() => {
                      const item = items.find(i => i.identity_id === detail.identity_id);
                      if (item) {
                        setDecisionTarget(item);
                        setDecisionType(detail.recommended_action === 'Approve' ? 'approve' : detail.recommended_action === 'Revoke' ? 'revoke' : detail.recommended_action === 'Downgrade' ? 'downgrade' : detail.recommended_action === 'Rotate' ? 'rotate' : 'approve');
                        setDecisionReason('');
                      }
                    }}
                    style={{ background: G.accent, color: '#fff' }}
                    className="w-full py-2.5 rounded-lg text-xs font-medium hover:opacity-90 transition">
                    Make Governance Decision
                  </button>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Decision Modal */}
      {decisionTarget && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => setDecisionTarget(null)}>
          <div style={{ background: '#141820', border: `1px solid ${G.surfaceBorder}` }}
               className="rounded-xl shadow-lg w-full max-w-lg mx-4 p-6 space-y-4"
               onClick={e => e.stopPropagation()}>
            <div>
              <h3 style={{ color: G.text }} className="text-sm font-bold">Governance Decision</h3>
              <p style={{ color: G.textMuted }} className="text-xs mt-1">{decisionTarget.display_name}</p>
              <div className="flex items-center gap-2 mt-2">
                <span style={{
                  background: G.bandBg[decisionTarget.risk_band],
                  color: G.band[decisionTarget.risk_band],
                  fontFamily: G.mono,
                }} className="px-2 py-0.5 rounded text-[10px] font-bold">
                  Risk: {decisionTarget.risk_score} ({decisionTarget.risk_band})
                </span>
              </div>
            </div>

            {/* Decision options */}
            <div className="space-y-1.5">
              <label style={{ color: G.textSecondary }} className="block text-[10px] font-medium uppercase tracking-wider">Decision</label>
              <div className="grid grid-cols-3 gap-2">
                {DECISION_OPTIONS.map(opt => (
                  <button
                    key={opt.key}
                    onClick={() => setDecisionType(opt.key)}
                    style={{
                      background: decisionType === opt.key ? `${opt.color}20` : G.surface,
                      border: `1px solid ${decisionType === opt.key ? opt.color : G.surfaceBorder}`,
                      color: decisionType === opt.key ? opt.color : G.textSecondary,
                    }}
                    className="rounded-lg p-2 text-left transition hover:opacity-90"
                  >
                    <div className="text-[10px] font-bold">{opt.label}</div>
                    <div style={{ color: G.textMuted }} className="text-[9px] mt-0.5">{opt.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Exception expiry */}
            {decisionType === 'exception' && (
              <div>
                <label style={{ color: G.textSecondary }} className="block text-[10px] font-medium uppercase tracking-wider mb-1">Exception Expires</label>
                <input
                  type="date"
                  value={exceptionExpiry}
                  onChange={e => setExceptionExpiry(e.target.value)}
                  style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}`, color: G.text }}
                  className="w-full px-3 py-2 rounded-lg text-xs outline-none"
                />
              </div>
            )}

            {/* Reason */}
            <div>
              <label style={{ color: G.textSecondary }} className="block text-[10px] font-medium uppercase tracking-wider mb-1">Justification</label>
              <textarea
                value={decisionReason}
                onChange={e => setDecisionReason(e.target.value)}
                rows={3}
                placeholder="Why is this decision being made?"
                style={{ background: G.surface, border: `1px solid ${G.surfaceBorder}`, color: G.text }}
                className="w-full px-3 py-2 rounded-lg text-xs outline-none resize-none"
              />
            </div>

            <div className="flex justify-end gap-2">
              <button onClick={() => setDecisionTarget(null)}
                      style={{ color: G.textMuted }}
                      className="px-4 py-2 rounded-lg text-xs hover:opacity-70">
                Cancel
              </button>
              <button onClick={handleDecision}
                      disabled={decisionSubmitting || !decisionReason.trim() || (decisionType === 'exception' && !exceptionExpiry)}
                      style={{
                        background: decisionSubmitting || !decisionReason.trim() ? 'rgba(255,255,255,0.1)' : G.accent,
                        color: '#fff',
                      }}
                      className="px-4 py-2 rounded-lg text-xs font-medium transition disabled:opacity-40 disabled:cursor-not-allowed">
                {decisionSubmitting ? 'Submitting...' : 'Submit Decision'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toast */}
      {toast && (
        <div style={{
          background: toast.type === 'success' ? '#059669' : '#DC2626',
        }} className="fixed bottom-6 right-6 z-50 px-4 py-2.5 rounded-lg shadow-lg text-xs font-medium text-white">
          {toast.msg}
        </div>
      )}
    </div>
  );
}
