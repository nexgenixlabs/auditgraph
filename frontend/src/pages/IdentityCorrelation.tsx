import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useConnection } from '../contexts/ConnectionContext';
import OrphanedFindingPanel from '../components/correlation/OrphanedFindingPanel';

// ─── Types ────────────────────────────────────────────────────────

interface LinkedAccount {
  id: number;
  account_type: string;
  account_upn: string;
  account_enabled: boolean;
  link_confidence: number;
  verified: boolean;
}

interface LinkedHuman {
  id: number;
  display_name: string;
  employee_id: string | null;
  department: string | null;
  account_count: number;
  accounts: LinkedAccount[];
  created_at: string | null;
}

interface LinkedDetail {
  id: number;
  display_name: string;
  employee_id: string | null;
  department: string | null;
  manager_id: string | null;
  accounts: Array<{
    id: number;
    account_type: string;
    account_upn: string;
    account_object_id: string;
    account_enabled: boolean;
    link_confidence: number;
    link_method: string;
    verified: boolean;
    identity_name: string | null;
    risk_score: number | null;
    risk_level: string | null;
    identity_category: string | null;
    identity_enabled: boolean | null;
    activity_status: string | null;
    last_sign_in: string | null;
  }>;
}

interface Finding {
  id: number;
  severity: string;
  privileged_upn: string;
  regular_upn: string;
  azure_roles: string[];
  role_count: number;
  highest_role_privilege: string | null;
  days_since_regular_disabled: number | null;
  subscription_count: number;
  compliance_reference: string | null;
  status: string;
  human_name: string | null;
  employee_id: string | null;
  created_at: string | null;
}

interface FindingDetail {
  id: number;
  severity: string;
  privileged_upn: string;
  regular_upn: string;
  azure_roles: string[];
  role_count: number;
  highest_role_privilege: string | null;
  days_since_regular_disabled: number | null;
  subscription_count: number;
  compliance_reference: string | null;
  has_activity_after_disable: boolean;
  days_out_of_compliance: number;
  status: string;
  human_name: string | null;
  department: string | null;
  remediation_commands: Record<string, string> | null;
  regular_account_upn: string | null;
  regular_account_enabled: boolean | null;
  privileged_account_upn: string | null;
  privileged_account_enabled: boolean | null;
  regular_risk_score: number | null;
  privileged_risk_score: number | null;
  privileged_risk_level: string | null;
  privileged_last_sign_in: string | null;
}

interface CorrelationStats {
  humans_linked: number;
  total_links: number;
  open_findings: number;
  findings_by_severity: Record<string, number>;
}

interface ICEConfig {
  ice_enabled: string;
  ice_privileged_prefixes: string;
  ice_privileged_suffixes: string;
  ice_display_name_similarity_threshold: string;
  ice_creation_window_hours: string;
}

type Tab = 'linked' | 'findings' | 'config';

// ─── Badge Maps ──────────────────────────────────────────────────

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-green-100 text-green-700',
};

const STATUS_BADGE: Record<string, string> = {
  open: 'bg-red-100 text-red-700',
  acknowledged: 'bg-yellow-100 text-yellow-700',
  remediated: 'bg-green-100 text-green-700',
  suppressed: 'bg-gray-100 text-gray-500',
};

const METHOD_LABEL: Record<string, string> = {
  prefix_match: 'Prefix',
  suffix_match: 'Suffix',
  display_name_match: 'Name Match',
  manual: 'Manual',
};

const RISK_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-green-100 text-green-700',
  info: 'bg-blue-100 text-blue-600',
};

// ─── Small Components ─────────────────────────────────────────────

function StatCard({ label, value, color, subtitle }: {
  label: string; value: number; color: string; subtitle?: string;
}) {
  const colorMap: Record<string, string> = {
    blue: 'bg-blue-50 border-blue-200 text-blue-700',
    indigo: 'bg-indigo-50 border-indigo-200 text-indigo-700',
    red: 'bg-red-50 border-red-200 text-red-700',
    orange: 'bg-orange-50 border-orange-200 text-orange-700',
    yellow: 'bg-yellow-50 border-yellow-200 text-yellow-700',
    green: 'bg-green-50 border-green-200 text-green-700',
    gray: 'bg-gray-50 border-gray-200 text-gray-600',
  };
  return (
    <div className={`border rounded-lg p-3 ${colorMap[color] || colorMap.blue}`}>
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-xs font-medium text-gray-600">{label}</div>
      {subtitle && <div className="text-[10px] text-gray-400 mt-0.5">{subtitle}</div>}
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────────

export default function IdentityCorrelation() {
  const location = useLocation();
  const { user } = useAuth();
  const { withConnection, selectedConnectionId } = useConnection();
  const isAdmin = user?.role === 'admin' || user?.role === 'security_admin';

  // Tab
  const [activeTab, setActiveTab] = useState<Tab>('linked');

  // Stats
  const [stats, setStats] = useState<CorrelationStats | null>(null);

  // Linked identities
  const [linkedItems, setLinkedItems] = useState<LinkedHuman[]>([]);
  const [linkedTotal, setLinkedTotal] = useState(0);
  const [linkedLoading, setLinkedLoading] = useState(true);
  const [search, setSearch] = useState('');

  // Linked detail panel
  const [selectedHumanId, setSelectedHumanId] = useState<number | null>(null);
  const [linkedDetail, setLinkedDetail] = useState<LinkedDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Findings
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [findingsLoading, setFindingsLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');

  // Finding detail panel
  const [selectedFindingId, setSelectedFindingId] = useState<number | null>(null);
  const [findingDetail, setFindingDetail] = useState<FindingDetail | null>(null);
  const [findingDetailLoading, setFindingDetailLoading] = useState(false);

  // Config
  const [config, setConfig] = useState<ICEConfig | null>(null);
  const [configLoading, setConfigLoading] = useState(false);
  const [configSaving, setConfigSaving] = useState(false);

  // Link modal
  const [showLinkModal, setShowLinkModal] = useState(false);
  const [linkRegularId, setLinkRegularId] = useState('');
  const [linkPrivilegedId, setLinkPrivilegedId] = useState('');
  const [linkError, setLinkError] = useState('');

  // URL sync
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    const p = new URLSearchParams(location.search);
    if (p.get('tab') === 'findings') setActiveTab('findings');
    if (p.get('tab') === 'config') setActiveTab('config');
    if (p.get('status')) setStatusFilter(p.get('status') || '');
    if (p.get('severity')) setSeverityFilter(p.get('severity') || '');
    setInitialized(true);
  }, [location.search]);

  useEffect(() => {
    if (!initialized) return;
    const p = new URLSearchParams();
    if (activeTab !== 'linked') p.set('tab', activeTab);
    if (statusFilter) p.set('status', statusFilter);
    if (severityFilter) p.set('severity', severityFilter);
    const qs = p.toString();
    window.history.replaceState(null, '', qs ? `${window.location.pathname}?${qs}` : window.location.pathname);
  }, [activeTab, statusFilter, severityFilter, initialized]);

  // ─── Fetch Stats ─────────────────────────────────────────────

  useEffect(() => {
    if (!initialized) return;
    fetch(withConnection('/api/dashboard/identity-correlation'))
      .then(r => r.json())
      .then(setStats)
      .catch(() => {});
  }, [initialized, selectedConnectionId]);

  // ─── Fetch Linked Identities ─────────────────────────────────

  useEffect(() => {
    if (!initialized || activeTab !== 'linked') return;
    setLinkedLoading(true);
    const abort = new AbortController();
    const params = new URLSearchParams();
    params.set('limit', '200');
    if (search) params.set('search', search);

    fetch(withConnection(`/api/correlation/linked?${params}`), { signal: abort.signal })
      .then(r => r.json())
      .then(data => {
        setLinkedItems(data.items || []);
        setLinkedTotal(data.total || 0);
        setLinkedLoading(false);
      })
      .catch(() => setLinkedLoading(false));
    return () => abort.abort();
  }, [initialized, activeTab, search, selectedConnectionId]);

  // ─── Fetch Linked Detail ─────────────────────────────────────

  useEffect(() => {
    if (selectedHumanId == null) { setLinkedDetail(null); return; }
    setDetailLoading(true);
    fetch(withConnection(`/api/correlation/linked/${selectedHumanId}`))
      .then(r => r.json())
      .then(data => { setLinkedDetail(data); setDetailLoading(false); })
      .catch(() => setDetailLoading(false));
  }, [selectedHumanId, selectedConnectionId]);

  // ─── Fetch Findings ──────────────────────────────────────────

  useEffect(() => {
    if (!initialized || activeTab !== 'findings') return;
    setFindingsLoading(true);
    const abort = new AbortController();
    const params = new URLSearchParams();
    params.set('limit', '200');
    if (statusFilter) params.set('status', statusFilter);
    if (severityFilter) params.set('severity', severityFilter);

    fetch(withConnection(`/api/findings/orphaned-privileged?${params}`), { signal: abort.signal })
      .then(r => r.json())
      .then(data => {
        setFindings(data.items || []);
        setFindingsTotal(data.total || 0);
        setFindingsLoading(false);
      })
      .catch(() => setFindingsLoading(false));
    return () => abort.abort();
  }, [initialized, activeTab, statusFilter, severityFilter, selectedConnectionId]);

  // ─── Fetch Finding Detail ────────────────────────────────────

  useEffect(() => {
    if (selectedFindingId == null) { setFindingDetail(null); return; }
    setFindingDetailLoading(true);
    fetch(withConnection(`/api/findings/orphaned-privileged/${selectedFindingId}`))
      .then(r => r.json())
      .then(data => { setFindingDetail(data); setFindingDetailLoading(false); })
      .catch(() => setFindingDetailLoading(false));
  }, [selectedFindingId, selectedConnectionId]);

  // ─── Fetch Config ────────────────────────────────────────────

  useEffect(() => {
    if (!initialized || activeTab !== 'config') return;
    setConfigLoading(true);
    fetch(withConnection('/api/correlation/config'))
      .then(r => r.json())
      .then(data => { setConfig(data); setConfigLoading(false); })
      .catch(() => setConfigLoading(false));
  }, [initialized, activeTab, selectedConnectionId]);

  // ─── Actions ─────────────────────────────────────────────────

  const handleUnlink = useCallback(async (linkId: number) => {
    if (!window.confirm('Remove this account link?')) return;
    const res = await fetch(withConnection(`/api/correlation/link/${linkId}`), { method: 'DELETE' });
    if (res.ok) {
      // Refresh detail
      if (selectedHumanId != null) {
        const d = await fetch(withConnection(`/api/correlation/linked/${selectedHumanId}`)).then(r => r.json());
        setLinkedDetail(d);
      }
      // Refresh list
      const params = new URLSearchParams();
      params.set('limit', '200');
      if (search) params.set('search', search);
      const list = await fetch(withConnection(`/api/correlation/linked?${params}`)).then(r => r.json());
      setLinkedItems(list.items || []);
      setLinkedTotal(list.total || 0);
      // Refresh stats
      fetch(withConnection('/api/dashboard/identity-correlation')).then(r => r.json()).then(setStats).catch(() => {});
    }
  }, [selectedHumanId, search, withConnection]);

  const handleVerify = useCallback(async (linkId: number) => {
    const res = await fetch(withConnection(`/api/correlation/link/${linkId}/verify`), { method: 'PUT' });
    if (res.ok && selectedHumanId != null) {
      const d = await fetch(withConnection(`/api/correlation/linked/${selectedHumanId}`)).then(r => r.json());
      setLinkedDetail(d);
      // Refresh list too
      const params = new URLSearchParams();
      params.set('limit', '200');
      if (search) params.set('search', search);
      const list = await fetch(withConnection(`/api/correlation/linked?${params}`)).then(r => r.json());
      setLinkedItems(list.items || []);
    }
  }, [selectedHumanId, search, withConnection]);

  const handleManualLink = useCallback(async () => {
    setLinkError('');
    if (!linkRegularId.trim() || !linkPrivilegedId.trim()) {
      setLinkError('Both identity IDs are required');
      return;
    }
    const res = await fetch(withConnection('/api/correlation/link'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        regular_identity_id: parseInt(linkRegularId),
        privileged_identity_id: parseInt(linkPrivilegedId),
      }),
    });
    if (res.ok) {
      setShowLinkModal(false);
      setLinkRegularId('');
      setLinkPrivilegedId('');
      // Refresh
      const params = new URLSearchParams();
      params.set('limit', '200');
      if (search) params.set('search', search);
      const list = await fetch(withConnection(`/api/correlation/linked?${params}`)).then(r => r.json());
      setLinkedItems(list.items || []);
      setLinkedTotal(list.total || 0);
      fetch(withConnection('/api/dashboard/identity-correlation')).then(r => r.json()).then(setStats).catch(() => {});
    } else {
      const err = await res.json().catch(() => ({ error: 'Link failed' }));
      setLinkError(err.error || 'Failed to link');
    }
  }, [linkRegularId, linkPrivilegedId, search, withConnection]);

  const handleFindingAction = useCallback(async (findingId: number, action: 'acknowledge' | 'remediate' | 'suppress') => {
    const res = await fetch(withConnection(`/api/findings/orphaned-privileged/${findingId}/${action}`), { method: 'PUT' });
    if (res.ok) {
      // Refresh finding detail
      if (selectedFindingId === findingId) {
        const d = await fetch(withConnection(`/api/findings/orphaned-privileged/${findingId}`)).then(r => r.json());
        setFindingDetail(d);
      }
      // Refresh list
      const params = new URLSearchParams();
      params.set('limit', '200');
      if (statusFilter) params.set('status', statusFilter);
      if (severityFilter) params.set('severity', severityFilter);
      const list = await fetch(withConnection(`/api/findings/orphaned-privileged?${params}`)).then(r => r.json());
      setFindings(list.items || []);
      setFindingsTotal(list.total || 0);
      // Refresh stats
      fetch(withConnection('/api/dashboard/identity-correlation')).then(r => r.json()).then(setStats).catch(() => {});
    }
  }, [selectedFindingId, statusFilter, severityFilter, withConnection]);

  const handleSaveConfig = useCallback(async () => {
    if (!config) return;
    setConfigSaving(true);
    await fetch(withConnection('/api/correlation/config'), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    setConfigSaving(false);
  }, [config, withConnection]);

  // ─── Filtered data ───────────────────────────────────────────

  const filteredLinked = useMemo(() => {
    if (!search) return linkedItems;
    const q = search.toLowerCase();
    return linkedItems.filter(h =>
      h.display_name?.toLowerCase().includes(q) ||
      h.employee_id?.toLowerCase().includes(q) ||
      h.department?.toLowerCase().includes(q)
    );
  }, [linkedItems, search]);

  // ─── Render ──────────────────────────────────────────────────

  const tabClass = (t: Tab) =>
    `px-4 py-2 text-xs font-medium rounded-t-lg cursor-pointer transition-colors ${
      activeTab === t
        ? 'bg-white text-blue-700 border border-b-0 border-gray-200'
        : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50'
    }`;

  return (
    <div className="max-w-7xl mx-auto px-4 py-6 space-y-4">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-gray-900">Identity Correlation</h1>
        <p className="text-sm text-gray-500 mt-1">
          Link regular and privileged accounts to detect orphaned access and enforce lifecycle governance.
        </p>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Linked Humans" value={stats?.humans_linked ?? 0} color="blue" />
        <StatCard label="Total Links" value={stats?.total_links ?? 0} color="indigo" />
        <StatCard
          label="Open Findings"
          value={stats?.open_findings ?? 0}
          color={stats?.open_findings ? 'orange' : 'green'}
        />
        <StatCard
          label="Critical Findings"
          value={stats?.findings_by_severity?.critical ?? 0}
          color={stats?.findings_by_severity?.critical ? 'red' : 'green'}
        />
      </div>

      {/* Tab Toggle */}
      <div className="flex gap-1 border-b border-gray-200">
        <button className={tabClass('linked')} onClick={() => setActiveTab('linked')}>
          Linked Identities
        </button>
        <button className={tabClass('findings')} onClick={() => setActiveTab('findings')}>
          Orphaned Findings
          {!!stats?.open_findings && (
            <span className="ml-1.5 px-1.5 py-0.5 text-[10px] font-bold bg-red-100 text-red-700 rounded-full">
              {stats.open_findings}
            </span>
          )}
        </button>
        {isAdmin && (
          <button className={tabClass('config')} onClick={() => setActiveTab('config')}>
            Configuration
          </button>
        )}
      </div>

      {/* ─── Tab 1: Linked Identities ─── */}
      {activeTab === 'linked' && (
        <div>
          <div className="flex items-center gap-3 mb-3">
            <input
              type="text"
              placeholder="Search by name, employee ID, department..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="flex-1 px-3 py-1.5 text-xs border border-gray-300 rounded-md focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
            />
            {isAdmin && (
              <button
                onClick={() => setShowLinkModal(true)}
                className="px-3 py-1.5 text-xs font-medium bg-blue-600 text-white rounded-md hover:bg-blue-700"
              >
                + Manual Link
              </button>
            )}
            <span className="text-xs text-gray-400">{linkedTotal} total</span>
          </div>

          <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="px-3 py-2 font-medium text-gray-500">Human Name</th>
                  <th className="px-3 py-2 font-medium text-gray-500">Employee ID</th>
                  <th className="px-3 py-2 font-medium text-gray-500">Department</th>
                  <th className="px-3 py-2 font-medium text-gray-500">Accounts</th>
                  <th className="px-3 py-2 font-medium text-gray-500">Regular</th>
                  <th className="px-3 py-2 font-medium text-gray-500">Privileged</th>
                  <th className="px-3 py-2 font-medium text-gray-500">Confidence</th>
                  <th className="px-3 py-2 font-medium text-gray-500">Verified</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {linkedLoading && (
                  <tr><td colSpan={8} className="text-center py-12 text-gray-400">Loading...</td></tr>
                )}
                {!linkedLoading && filteredLinked.length === 0 && (
                  <tr><td colSpan={8} className="text-center py-12 text-gray-400">No linked identities found</td></tr>
                )}
                {!linkedLoading && filteredLinked.map(h => {
                  const regular = h.accounts?.find(a => a.account_type === 'regular');
                  const privileged = h.accounts?.find(a => a.account_type === 'privileged');
                  const avgConfidence = h.accounts?.length
                    ? Math.round(h.accounts.reduce((s, a) => s + (a.link_confidence || 0), 0) / h.accounts.length)
                    : 0;
                  const allVerified = h.accounts?.length > 0 && h.accounts.every(a => a.verified);
                  return (
                    <tr
                      key={h.id}
                      onClick={() => setSelectedHumanId(h.id)}
                      className={`cursor-pointer hover:bg-blue-50/50 transition-colors ${selectedHumanId === h.id ? 'bg-blue-50' : ''}`}
                    >
                      <td className="px-3 py-2 font-medium text-gray-900">{h.display_name}</td>
                      <td className="px-3 py-2 text-gray-600">{h.employee_id || '—'}</td>
                      <td className="px-3 py-2 text-gray-600">{h.department || '—'}</td>
                      <td className="px-3 py-2">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-blue-100 text-blue-700">
                          {h.account_count}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-gray-600 truncate max-w-[180px]">
                        {regular?.account_upn || '—'}
                      </td>
                      <td className="px-3 py-2 text-gray-600 truncate max-w-[180px]">
                        {privileged?.account_upn || '—'}
                      </td>
                      <td className="px-3 py-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                          avgConfidence >= 80 ? 'bg-green-100 text-green-700' :
                          avgConfidence >= 60 ? 'bg-yellow-100 text-yellow-700' :
                          'bg-orange-100 text-orange-700'
                        }`}>
                          {avgConfidence}%
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        {allVerified ? (
                          <svg className="w-4 h-4 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                          </svg>
                        ) : (
                          <span className="text-gray-300">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ─── Tab 2: Orphaned Findings ─── */}
      {activeTab === 'findings' && (
        <div>
          <div className="flex items-center gap-3 mb-3">
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className="px-2 py-1.5 text-xs border border-gray-300 rounded-md"
            >
              <option value="">All Statuses</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="remediated">Remediated</option>
              <option value="suppressed">Suppressed</option>
            </select>
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              className="px-2 py-1.5 text-xs border border-gray-300 rounded-md"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
            </select>
            <span className="text-xs text-gray-400 ml-auto">{findingsTotal} total</span>
          </div>

          <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="px-3 py-2 font-medium text-gray-500">Severity</th>
                  <th className="px-3 py-2 font-medium text-gray-500">Privileged UPN</th>
                  <th className="px-3 py-2 font-medium text-gray-500">Regular UPN</th>
                  <th className="px-3 py-2 font-medium text-gray-500">Roles</th>
                  <th className="px-3 py-2 font-medium text-gray-500">Highest Role</th>
                  <th className="px-3 py-2 font-medium text-gray-500">Days Disabled</th>
                  <th className="px-3 py-2 font-medium text-gray-500">Compliance</th>
                  <th className="px-3 py-2 font-medium text-gray-500">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {findingsLoading && (
                  <tr><td colSpan={8} className="text-center py-12 text-gray-400">Loading...</td></tr>
                )}
                {!findingsLoading && findings.length === 0 && (
                  <tr><td colSpan={8} className="text-center py-12 text-gray-400">No orphaned findings found</td></tr>
                )}
                {!findingsLoading && findings.map(f => (
                  <tr
                    key={f.id}
                    onClick={() => setSelectedFindingId(f.id)}
                    className={`cursor-pointer hover:bg-blue-50/50 transition-colors ${selectedFindingId === f.id ? 'bg-blue-50' : ''}`}
                  >
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEVERITY_BADGE[f.severity] || 'bg-gray-100 text-gray-500'}`}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-medium text-gray-900 truncate max-w-[180px]">{f.privileged_upn}</td>
                    <td className="px-3 py-2 text-gray-600 truncate max-w-[180px]">{f.regular_upn}</td>
                    <td className="px-3 py-2">
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-blue-100 text-blue-700">{f.role_count}</span>
                    </td>
                    <td className="px-3 py-2 text-gray-600 truncate max-w-[120px]">{f.highest_role_privilege || '—'}</td>
                    <td className="px-3 py-2 text-gray-600">{f.days_since_regular_disabled ?? '—'}</td>
                    <td className="px-3 py-2 text-gray-500 truncate max-w-[120px]">{f.compliance_reference || '—'}</td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${STATUS_BADGE[f.status] || 'bg-gray-100 text-gray-500'}`}>
                        {f.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ─── Tab 3: Configuration (admin only) ─── */}
      {activeTab === 'config' && isAdmin && (
        <div className="bg-white border border-gray-200 rounded-lg p-5 max-w-2xl">
          {configLoading ? (
            <div className="animate-pulse space-y-4">
              {[1, 2, 3, 4, 5].map(i => <div key={i} className="h-10 bg-gray-100 rounded" />)}
            </div>
          ) : config ? (
            <div className="space-y-5">
              <h3 className="text-sm font-semibold text-gray-900">ICE Configuration</h3>

              {/* Enable toggle */}
              <label className="flex items-center gap-3 cursor-pointer">
                <div className="relative">
                  <input
                    type="checkbox"
                    checked={config.ice_enabled === 'true'}
                    onChange={e => setConfig({ ...config, ice_enabled: e.target.checked ? 'true' : 'false' })}
                    className="sr-only peer"
                  />
                  <div className="w-9 h-5 bg-gray-200 rounded-full peer-checked:bg-blue-600 transition-colors" />
                  <div className="absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full shadow peer-checked:translate-x-4 transition-transform" />
                </div>
                <span className="text-sm text-gray-700">Enable Identity Correlation Engine</span>
              </label>

              {/* Prefixes */}
              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">Privileged Account Prefixes</label>
                <input
                  type="text"
                  value={config.ice_privileged_prefixes}
                  onChange={e => setConfig({ ...config, ice_privileged_prefixes: e.target.value })}
                  className="w-full px-3 py-1.5 text-xs border border-gray-300 rounded-md focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="ep.,adm-,adm.,a-,admin-"
                />
                <p className="text-[10px] text-gray-400 mt-1">Comma-separated prefixes used to identify privileged accounts (e.g., ep.john → privileged)</p>
              </div>

              {/* Suffixes */}
              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">Privileged Account Suffixes</label>
                <input
                  type="text"
                  value={config.ice_privileged_suffixes}
                  onChange={e => setConfig({ ...config, ice_privileged_suffixes: e.target.value })}
                  className="w-full px-3 py-1.5 text-xs border border-gray-300 rounded-md focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="-admin,.admin,-priv"
                />
                <p className="text-[10px] text-gray-400 mt-1">Comma-separated suffixes for privileged account detection</p>
              </div>

              {/* Similarity Threshold */}
              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">
                  Display Name Similarity Threshold: {Math.round(parseFloat(config.ice_display_name_similarity_threshold) * 100)}%
                </label>
                <input
                  type="range"
                  min="0.5"
                  max="1.0"
                  step="0.05"
                  value={config.ice_display_name_similarity_threshold}
                  onChange={e => setConfig({ ...config, ice_display_name_similarity_threshold: e.target.value })}
                  className="w-full"
                />
                <p className="text-[10px] text-gray-400 mt-1">Minimum fuzzy match score for display name correlation (0.50 = loose, 1.00 = exact)</p>
              </div>

              {/* Creation Window */}
              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">Creation Window (hours)</label>
                <input
                  type="number"
                  min="1"
                  max="720"
                  value={config.ice_creation_window_hours}
                  onChange={e => setConfig({ ...config, ice_creation_window_hours: e.target.value })}
                  className="w-32 px-3 py-1.5 text-xs border border-gray-300 rounded-md focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
                />
                <p className="text-[10px] text-gray-400 mt-1">Accounts created within this window of each other may be correlated</p>
              </div>

              <button
                onClick={handleSaveConfig}
                disabled={configSaving}
                className="px-4 py-2 text-xs font-medium bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
              >
                {configSaving ? 'Saving...' : 'Save Configuration'}
              </button>
            </div>
          ) : (
            <p className="text-sm text-gray-400">Failed to load configuration</p>
          )}
        </div>
      )}

      {/* ─── Linked Detail Panel ─── */}
      {selectedHumanId != null && (
        <div className="fixed inset-0 z-40" onClick={() => setSelectedHumanId(null)} />
      )}
      {selectedHumanId != null && detailLoading && (
        <div className="fixed inset-y-0 right-0 w-[480px] bg-white border-l border-gray-200 shadow-xl z-50 flex items-center justify-center">
          <div className="text-sm text-gray-400">Loading...</div>
        </div>
      )}
      {selectedHumanId != null && linkedDetail && !detailLoading && (
        <div className="fixed inset-y-0 right-0 w-[480px] bg-white border-l border-gray-200 shadow-xl z-50 flex flex-col">
          {/* Panel Header */}
          <div className="bg-gray-50 border-b border-gray-200 px-5 py-4 flex items-center justify-between flex-shrink-0">
            <div>
              <h3 className="text-sm font-bold text-gray-900">{linkedDetail.display_name}</h3>
              <p className="text-[10px] text-gray-500 mt-0.5">
                {linkedDetail.employee_id && `ID: ${linkedDetail.employee_id}`}
                {linkedDetail.department && ` · ${linkedDetail.department}`}
              </p>
            </div>
            <button
              onClick={() => setSelectedHumanId(null)}
              className="p-1 hover:bg-gray-200 rounded"
            >
              <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          {/* Panel Content */}
          <div className="flex-1 overflow-y-auto p-5 space-y-5">
            {/* Info Grid */}
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-gray-50 rounded-lg p-3">
                <div className="text-[10px] text-gray-500 uppercase font-medium">Employee ID</div>
                <div className="text-xs font-medium text-gray-900 mt-0.5">{linkedDetail.employee_id || '—'}</div>
              </div>
              <div className="bg-gray-50 rounded-lg p-3">
                <div className="text-[10px] text-gray-500 uppercase font-medium">Department</div>
                <div className="text-xs font-medium text-gray-900 mt-0.5">{linkedDetail.department || '—'}</div>
              </div>
              <div className="bg-gray-50 rounded-lg p-3">
                <div className="text-[10px] text-gray-500 uppercase font-medium">Manager</div>
                <div className="text-xs font-medium text-gray-900 mt-0.5">{linkedDetail.manager_id || '—'}</div>
              </div>
              <div className="bg-gray-50 rounded-lg p-3">
                <div className="text-[10px] text-gray-500 uppercase font-medium">Linked Accounts</div>
                <div className="text-xs font-medium text-gray-900 mt-0.5">{linkedDetail.accounts?.length || 0}</div>
              </div>
            </div>

            {/* Linked Accounts */}
            <div>
              <h4 className="text-xs font-semibold text-gray-900 mb-2">Linked Accounts</h4>
              <div className="space-y-2">
                {linkedDetail.accounts?.map(acc => (
                  <div key={acc.id} className="border border-gray-200 rounded-lg p-3">
                    <div className="flex items-start justify-between">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-1.5">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                            acc.account_type === 'privileged' ? 'bg-red-100 text-red-700' : 'bg-blue-100 text-blue-700'
                          }`}>
                            {acc.account_type}
                          </span>
                          {acc.verified && (
                            <svg className="w-3.5 h-3.5 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                            </svg>
                          )}
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                            METHOD_LABEL[acc.link_method] ? 'bg-gray-100 text-gray-600' : 'bg-gray-100 text-gray-500'
                          }`}>
                            {METHOD_LABEL[acc.link_method] || acc.link_method}
                          </span>
                        </div>
                        <p className="text-xs text-gray-900 font-medium mt-1 truncate">{acc.account_upn}</p>
                        {acc.identity_name && (
                          <p className="text-[11px] text-gray-500 truncate">{acc.identity_name}</p>
                        )}
                        <div className="flex items-center gap-3 mt-1.5 text-[10px] text-gray-500">
                          {acc.risk_level && (
                            <span className={`px-1 py-0.5 rounded font-semibold ${RISK_BADGE[acc.risk_level] || 'bg-gray-100 text-gray-500'}`}>
                              {acc.risk_level} ({acc.risk_score})
                            </span>
                          )}
                          <span>{acc.account_enabled ? 'Enabled' : 'Disabled'}</span>
                          {acc.activity_status && <span>{acc.activity_status}</span>}
                          <span>Confidence: {acc.link_confidence}%</span>
                        </div>
                        {acc.last_sign_in && (
                          <p className="text-[10px] text-gray-400 mt-0.5">Last sign-in: {new Date(acc.last_sign_in).toLocaleDateString()}</p>
                        )}
                      </div>
                    </div>
                    {isAdmin && (
                      <div className="flex items-center gap-2 mt-2 pt-2 border-t border-gray-100">
                        {!acc.verified && (
                          <button
                            onClick={e => { e.stopPropagation(); handleVerify(acc.id); }}
                            className="px-2 py-1 text-[10px] font-medium bg-green-50 text-green-700 border border-green-200 rounded hover:bg-green-100"
                          >
                            Verify
                          </button>
                        )}
                        <button
                          onClick={e => { e.stopPropagation(); handleUnlink(acc.id); }}
                          className="px-2 py-1 text-[10px] font-medium bg-red-50 text-red-700 border border-red-200 rounded hover:bg-red-100"
                        >
                          Unlink
                        </button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ─── Finding Detail Panel ─── */}
      {selectedFindingId != null && (
        <div className="fixed inset-0 z-40" onClick={() => setSelectedFindingId(null)} />
      )}
      {selectedFindingId != null && findingDetailLoading && (
        <div className="fixed inset-y-0 right-0 w-[480px] bg-white border-l border-gray-200 shadow-xl z-50 flex items-center justify-center">
          <div className="text-sm text-gray-400">Loading...</div>
        </div>
      )}
      {selectedFindingId != null && findingDetail && !findingDetailLoading && (
        <OrphanedFindingPanel
          detail={findingDetail}
          onClose={() => setSelectedFindingId(null)}
          onAction={handleFindingAction}
          isAdmin={isAdmin}
        />
      )}

      {/* ─── Manual Link Modal ─── */}
      {showLinkModal && (
        <>
          <div className="fixed inset-0 z-50 bg-black/60" onClick={() => setShowLinkModal(false)} />
          <div className="fixed inset-0 z-50 flex items-center justify-center pointer-events-none">
            <div className="bg-white rounded-xl shadow-xl border border-gray-200 w-[420px] p-6 pointer-events-auto">
              <h3 className="text-sm font-bold text-gray-900 mb-4">Manual Account Link</h3>
              <p className="text-xs text-gray-500 mb-4">
                Link two identity database IDs (regular and privileged) to the same human.
              </p>
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-gray-700 mb-1">Regular Account ID</label>
                  <input
                    type="number"
                    value={linkRegularId}
                    onChange={e => setLinkRegularId(e.target.value)}
                    className="w-full px-3 py-1.5 text-xs border border-gray-300 rounded-md focus:ring-1 focus:ring-blue-500"
                    placeholder="Identity DB ID for regular account"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-700 mb-1">Privileged Account ID</label>
                  <input
                    type="number"
                    value={linkPrivilegedId}
                    onChange={e => setLinkPrivilegedId(e.target.value)}
                    className="w-full px-3 py-1.5 text-xs border border-gray-300 rounded-md focus:ring-1 focus:ring-blue-500"
                    placeholder="Identity DB ID for privileged account"
                  />
                </div>
                {linkError && (
                  <p className="text-xs text-red-600">{linkError}</p>
                )}
              </div>
              <div className="flex justify-end gap-2 mt-5">
                <button
                  onClick={() => { setShowLinkModal(false); setLinkError(''); }}
                  className="px-3 py-1.5 text-xs text-gray-600 border border-gray-300 rounded-md hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleManualLink}
                  className="px-3 py-1.5 text-xs font-medium bg-blue-600 text-white rounded-md hover:bg-blue-700"
                >
                  Link Accounts
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
