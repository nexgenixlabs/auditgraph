import React, { useEffect, useMemo, useState, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { RISK_BADGE, safeLower } from '../constants/metrics';
import { downloadCSV, exportFilename, RESOURCE_CSV_COLUMNS } from '../utils/exportUtils';

// ─── Types ────────────────────────────────────────────────────────

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
  tags: Record<string, string>;
  created_at: string;
}

interface ResourceStats {
  total: number;
  storage_accounts: number;
  key_vaults: number;
  by_risk: Record<string, number>;
  at_risk: number;
  rotation_compliance?: { total_storage: number; keys_stale: number; avg_key_age_days: number };
  audit_posture?: { total: number; aad_only: number; auditable: number; partial: number; unauditable: number };
  expiry_summary?: {
    secrets: { total: number; expired: number; expiring_soon: number };
    keys: { total: number; expired: number; expiring_soon: number };
    certs: { total: number; expired: number; expiring_soon: number };
  };
}

type SortField = 'name' | 'resource_type' | 'location' | 'resource_group' | 'subscription_name' | 'risk_level' | 'risk_score';

const RISK_ORDER: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

// ─── Small Components ─────────────────────────────────────────────

function SortHeader({ label, field, currentField, currentDir, onSort }: {
  label: string; field: SortField; currentField: SortField; currentDir: 'asc' | 'desc'; onSort: (f: SortField) => void;
}) {
  const isActive = currentField === field;
  return (
    <th className="px-3 py-2.5 cursor-pointer select-none hover:bg-gray-100 whitespace-nowrap text-xs" onClick={() => onSort(field)}>
      <div className="flex items-center gap-0.5">
        <span>{label}</span>
        <span className={`text-[10px] ${isActive ? 'text-blue-600' : 'text-gray-400'}`}>
          {isActive ? (currentDir === 'asc' ? '▲' : '▼') : '↕'}
        </span>
      </div>
    </th>
  );
}

function RiskBadge({ level, score }: { level?: string; score?: number }) {
  const risk = safeLower(level);
  return (
    <div className="flex items-center gap-1">
      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${RISK_BADGE[risk] || 'bg-gray-100 text-gray-600'}`}>
        {risk || '?'}
      </span>
      {score !== undefined && score > 0 && <span className="text-[10px] text-gray-400 font-mono">{score}</span>}
    </div>
  );
}

function ResourceTypeBadge({ type }: { type: string }) {
  const isStorage = type === 'storage_account';
  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
      isStorage ? 'bg-blue-100 text-blue-700' : 'bg-purple-100 text-purple-700'
    }`}>
      {isStorage ? 'Storage Account' : 'Key Vault'}
    </span>
  );
}

function KeyIssuesBadges({ row }: { row: ResourceRow }) {
  const issues: { label: string; color: string }[] = [];
  const cfg = row.key_config || {};

  if (row.resource_type === 'storage_account') {
    if (cfg.public_blob_access) issues.push({ label: 'Public Blob', color: 'bg-red-100 text-red-700' });
    if (cfg.https_only === false) issues.push({ label: 'HTTP', color: 'bg-red-100 text-red-700' });
    if (cfg.shared_key_access && !cfg.diagnostic_logging_enabled) issues.push({ label: 'Unauditable', color: 'bg-red-100 text-red-700' });
    if (cfg.default_network_action === 'Allow') issues.push({ label: 'Allow All', color: 'bg-yellow-100 text-yellow-700' });
    if (!cfg.customer_managed_keys) issues.push({ label: 'No CMK', color: 'bg-yellow-100 text-yellow-700' });
    if (cfg.key_rotation_stale) issues.push({ label: 'Keys Stale', color: 'bg-orange-100 text-orange-700' });
    if (cfg.shared_key_access && !cfg.sas_policy_enabled) issues.push({ label: 'No SAS Policy', color: 'bg-orange-100 text-orange-700' });
    if (cfg.shared_key_access) issues.push({ label: 'Shared Key', color: 'bg-yellow-100 text-yellow-700' });
  } else {
    if (cfg.soft_delete_enabled === false) issues.push({ label: 'No Soft Delete', color: 'bg-red-100 text-red-700' });
    if (!cfg.purge_protection) issues.push({ label: 'No Purge Protect', color: 'bg-red-100 text-red-700' });
    if ((cfg.secrets_expired as number) > 0) issues.push({ label: `${cfg.secrets_expired} Exp. Secrets`, color: 'bg-orange-100 text-orange-700' });
    if ((cfg.keys_expired as number) > 0) issues.push({ label: `${cfg.keys_expired} Exp. Keys`, color: 'bg-orange-100 text-orange-700' });
    if ((cfg.certs_expired as number) > 0) issues.push({ label: `${cfg.certs_expired} Exp. Certs`, color: 'bg-orange-100 text-orange-700' });
    if (cfg.public_network_access === 'Enabled') issues.push({ label: 'Public Access', color: 'bg-yellow-100 text-yellow-700' });
  }

  if (issues.length === 0) return <span className="text-[10px] text-green-600 font-medium">No Issues</span>;

  return (
    <div className="flex flex-wrap gap-0.5">
      {issues.slice(0, 3).map((iss, i) => (
        <span key={i} className={`px-1 py-0.5 rounded text-[9px] font-semibold ${iss.color}`}>{iss.label}</span>
      ))}
      {issues.length > 3 && <span className="text-[9px] text-gray-500">+{issues.length - 3}</span>}
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────

export default function Resources() {
  const navigate = useNavigate();
  const location = useLocation();

  const [resources, setResources] = useState<ResourceRow[]>([]);
  const [stats, setStats] = useState<ResourceStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [initialized, setInitialized] = useState(false);

  const [typeFilter, setTypeFilter] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [search, setSearch] = useState('');
  const [sortField, setSortField] = useState<SortField>('risk_score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  // Sync state from URL params on mount and on URL changes (e.g. client-side link clicks)
  useEffect(() => {
    const p = new URLSearchParams(location.search);
    setTypeFilter(p.get('resource_type') || p.get('type') || 'storage_account');
    setRiskFilter(p.get('risk') || '');
    setSearch(p.get('search') || '');
    setInitialized(true);
  }, [location.search]);

  // Fetch stats (re-fetch when type filter changes for type-specific trending)
  useEffect(() => {
    if (!initialized) return;
    setStats(null); // Clear stale stats immediately
    const abort = new AbortController();
    const params = new URLSearchParams();
    if (typeFilter) params.set('resource_type', typeFilter);
    fetch(`/api/resources/stats?${params}`, { signal: abort.signal })
      .then(r => r.json())
      .then(setStats)
      .catch(() => {});
    return () => abort.abort();
  }, [typeFilter, initialized]);

  // Fetch resources
  useEffect(() => {
    if (!initialized) return;
    setLoading(true);
    const abort = new AbortController();
    const params = new URLSearchParams();
    params.set('limit', '500');
    if (typeFilter) params.set('resource_type', typeFilter);
    if (riskFilter) params.set('risk_level', riskFilter);
    if (search) params.set('search', search);

    fetch(`/api/resources?${params}`, { signal: abort.signal })
      .then(r => r.json())
      .then(data => {
        setResources(data.resources || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
    return () => abort.abort();
  }, [typeFilter, riskFilter, search, initialized]);

  // Client-side sort
  const sorted = useMemo(() => {
    const arr = [...resources];
    arr.sort((a, b) => {
      let cmp = 0;
      if (sortField === 'risk_level') {
        cmp = (RISK_ORDER[safeLower(a.risk_level)] || 0) - (RISK_ORDER[safeLower(b.risk_level)] || 0);
      } else if (sortField === 'risk_score') {
        cmp = (a.risk_score || 0) - (b.risk_score || 0);
      } else {
        const av = String(a[sortField] || '').toLowerCase();
        const bv = String(b[sortField] || '').toLowerCase();
        cmp = av.localeCompare(bv);
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return arr;
  }, [resources, sortField, sortDir]);

  const handleSort = useCallback((f: SortField) => {
    if (f === sortField) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortField(f); setSortDir(f === 'risk_score' || f === 'risk_level' ? 'desc' : 'asc'); }
  }, [sortField]);

  // Update URL params (use replaceState to avoid react-router re-render loop)
  useEffect(() => {
    if (!initialized) return;
    const p = new URLSearchParams();
    if (typeFilter) p.set('resource_type', typeFilter);
    if (riskFilter) p.set('risk', riskFilter);
    if (search) p.set('search', search);
    const qs = p.toString();
    window.history.replaceState(null, '', qs ? `${window.location.pathname}?${qs}` : window.location.pathname);
  }, [typeFilter, riskFilter, search, initialized]);

  const handleCSVExport = useCallback(() => {
    downloadCSV(
      resources as unknown as Record<string, unknown>[],
      RESOURCE_CSV_COLUMNS,
      exportFilename('resources', 'csv')
    );
  }, [resources]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Azure Resources</h1>
          <p className="text-sm text-gray-500 mt-0.5">Storage Accounts & Key Vaults — security configuration audit</p>
        </div>
        <button
          onClick={handleCSVExport}
          disabled={resources.length === 0}
          className="px-3 py-1.5 text-xs font-medium bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-40"
        >
          Export CSV
        </button>
      </div>

      {/* Summary Cards — context-aware based on type filter */}
      {stats && (
        <>
          <div className="grid grid-cols-4 gap-3">
            <StatCard
              label="Storage Accounts"
              value={stats.storage_accounts}
              color="sky"
              onClick={() => setTypeFilter('storage_account')}
              active={typeFilter === 'storage_account'}
            />
            <StatCard
              label="Key Vaults"
              value={stats.key_vaults}
              color="purple"
              onClick={() => setTypeFilter('key_vault')}
              active={typeFilter === 'key_vault'}
            />
            <StatCard label="Total Resources" value={stats.total} color="blue" />
            <StatCard label="At Risk" value={stats.at_risk} color="red" subtitle={`${stats.by_risk.critical || 0} critical, ${stats.by_risk.high || 0} high`} onClick={() => setRiskFilter('critical')} />
          </div>

          {/* Storage-specific stats (shown when All or Storage filter) */}
          {stats.rotation_compliance && (
            <div className="grid grid-cols-4 gap-3">
              <StatCard
                label="Keys Stale (>90d)"
                value={stats.rotation_compliance.keys_stale}
                color={stats.rotation_compliance.keys_stale > 0 ? 'red' : 'green'}
                subtitle={`of ${stats.rotation_compliance.total_storage} storage accounts`}
              />
              <StatCard
                label="Avg Key Age"
                value={stats.rotation_compliance.avg_key_age_days}
                color={stats.rotation_compliance.avg_key_age_days > 90 ? 'red' : 'green'}
                subtitle="days"
              />
              <div />
              <div />
            </div>
          )}

          {/* Audit Posture (storage-only) */}
          {stats.audit_posture && stats.audit_posture.total > 0 && (
            <div className="bg-white border border-gray-200 rounded-lg p-3">
              <div className="text-[10px] uppercase tracking-wider text-gray-500 font-medium mb-2">Access Auditability</div>
              <div className="flex items-center gap-2">
                {/* Stacked bar */}
                <div className="flex-1 h-5 flex rounded-full overflow-hidden bg-gray-100">
                  {stats.audit_posture.aad_only > 0 && (
                    <div className="bg-green-500 h-full" style={{ width: `${(stats.audit_posture.aad_only / stats.audit_posture.total) * 100}%` }} title={`${stats.audit_posture.aad_only} Azure AD Only`} />
                  )}
                  {stats.audit_posture.auditable > 0 && (
                    <div className="bg-blue-500 h-full" style={{ width: `${(stats.audit_posture.auditable / stats.audit_posture.total) * 100}%` }} title={`${stats.audit_posture.auditable} Auditable`} />
                  )}
                  {stats.audit_posture.partial > 0 && (
                    <div className="bg-yellow-400 h-full" style={{ width: `${(stats.audit_posture.partial / stats.audit_posture.total) * 100}%` }} title={`${stats.audit_posture.partial} Partial`} />
                  )}
                  {stats.audit_posture.unauditable > 0 && (
                    <div className="bg-red-500 h-full" style={{ width: `${(stats.audit_posture.unauditable / stats.audit_posture.total) * 100}%` }} title={`${stats.audit_posture.unauditable} Unauditable`} />
                  )}
                </div>
                <div className="flex gap-2 text-[10px] flex-shrink-0">
                  {stats.audit_posture.aad_only > 0 && <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-green-500" />{stats.audit_posture.aad_only} AAD Only</span>}
                  {stats.audit_posture.auditable > 0 && <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-500" />{stats.audit_posture.auditable} Auditable</span>}
                  {stats.audit_posture.partial > 0 && <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-yellow-400" />{stats.audit_posture.partial} Partial</span>}
                  {stats.audit_posture.unauditable > 0 && <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500" />{stats.audit_posture.unauditable} Unauditable</span>}
                </div>
              </div>
            </div>
          )}

          {/* Key Vault-specific stats (shown when All or Key Vault filter) */}
          {stats.expiry_summary && (
            <div className="grid grid-cols-4 gap-3">
              <StatCard
                label="Expired Items"
                value={(stats.expiry_summary.secrets.expired || 0) + (stats.expiry_summary.keys.expired || 0) + (stats.expiry_summary.certs.expired || 0)}
                color={(stats.expiry_summary.secrets.expired + stats.expiry_summary.keys.expired + stats.expiry_summary.certs.expired) > 0 ? 'red' : 'green'}
                subtitle={`${stats.expiry_summary.secrets.expired}s ${stats.expiry_summary.keys.expired}k ${stats.expiry_summary.certs.expired}c`}
              />
              <StatCard
                label="Expiring Soon"
                value={(stats.expiry_summary.secrets.expiring_soon || 0) + (stats.expiry_summary.keys.expiring_soon || 0) + (stats.expiry_summary.certs.expiring_soon || 0)}
                color={(stats.expiry_summary.secrets.expiring_soon + stats.expiry_summary.keys.expiring_soon + stats.expiry_summary.certs.expiring_soon) > 0 ? 'red' : 'green'}
                subtitle="within 30 days"
              />
              <StatCard
                label="Vault Items"
                value={(stats.expiry_summary.secrets.total || 0) + (stats.expiry_summary.keys.total || 0) + (stats.expiry_summary.certs.total || 0)}
                color="blue"
                subtitle={`${stats.expiry_summary.secrets.total}s ${stats.expiry_summary.keys.total}k ${stats.expiry_summary.certs.total}c`}
              />
              <div />
            </div>
          )}
        </>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        {/* Type tabs */}
        <div className="flex rounded-md border border-gray-300 overflow-hidden text-xs">
          {[
            { key: 'storage_account', label: 'Storage Accounts' },
            { key: 'key_vault', label: 'Key Vaults' },
          ].map(t => (
            <button
              key={t.key}
              onClick={() => setTypeFilter(t.key)}
              className={`px-3 py-1.5 ${typeFilter === t.key ? 'bg-blue-600 text-white' : 'bg-white text-gray-700 hover:bg-gray-50'}`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Risk filter */}
        <select
          value={riskFilter}
          onChange={e => setRiskFilter(e.target.value)}
          className="text-xs border border-gray-300 rounded-md px-2 py-1.5"
        >
          <option value="">All Risk Levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>

        {/* Search */}
        <input
          type="text"
          placeholder="Search by name or resource group..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="text-xs border border-gray-300 rounded-md px-2 py-1.5 w-64"
        />

        {(riskFilter || search) && (
          <button
            onClick={() => { setRiskFilter(''); setSearch(''); }}
            className="text-xs text-blue-600 hover:underline"
          >
            Clear filters
          </button>
        )}

        <span className="text-xs text-gray-500 ml-auto">{sorted.length} resources</span>
      </div>

      {/* Table */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-xs">
            <thead className="bg-gray-50 border-b border-gray-200 text-gray-600 uppercase tracking-wider font-medium">
              <tr>
                <SortHeader label="Name" field="name" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Type" field="resource_type" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Location" field="location" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Resource Group" field="resource_group" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Subscription" field="subscription_name" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Risk" field="risk_level" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Score" field="risk_score" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <th className="px-3 py-2.5 text-xs">Key Issues</th>
                <th className="px-3 py-2.5 text-xs w-6"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {loading ? (
                <tr><td colSpan={9} className="px-3 py-8 text-center text-gray-400">Loading resources...</td></tr>
              ) : sorted.length === 0 ? (
                <tr><td colSpan={9} className="px-3 py-8 text-center text-gray-400">No resources found. Run a discovery to populate.</td></tr>
              ) : sorted.map(r => (
                <tr
                  key={`${r.resource_type}-${r.id}`}
                  className="hover:bg-blue-50/40 cursor-pointer transition-colors"
                  onClick={() => navigate(`/resources/detail?rid=${encodeURIComponent(r.resource_id)}`)}
                >
                  <td className="px-3 py-2 font-medium text-gray-900 max-w-[200px] truncate" title={r.name}>{r.name}</td>
                  <td className="px-3 py-2"><ResourceTypeBadge type={r.resource_type} /></td>
                  <td className="px-3 py-2 text-gray-600">{r.location || '—'}</td>
                  <td className="px-3 py-2 text-gray-600 max-w-[160px] truncate" title={r.resource_group}>{r.resource_group || '—'}</td>
                  <td className="px-3 py-2 text-gray-600 max-w-[160px] truncate" title={r.subscription_name}>{r.subscription_name || '—'}</td>
                  <td className="px-3 py-2"><RiskBadge level={r.risk_level} /></td>
                  <td className="px-3 py-2 font-mono text-gray-700">{r.risk_score}</td>
                  <td className="px-3 py-2"><KeyIssuesBadges row={r} /></td>
                  <td className="px-3 py-2 text-gray-400">→</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ─── Stat Card ────────────────────────────────────────────────────

function StatCard({ label, value, color, subtitle, onClick, active }: {
  label: string; value: number; color: string; subtitle?: string; onClick?: () => void; active?: boolean;
}) {
  const colorMap: Record<string, string> = {
    blue: 'bg-blue-50 border-blue-200 text-blue-700',
    sky: 'bg-sky-50 border-sky-200 text-sky-700',
    purple: 'bg-purple-50 border-purple-200 text-purple-700',
    red: 'bg-red-50 border-red-200 text-red-700',
    green: 'bg-green-50 border-green-200 text-green-700',
  };
  return (
    <div
      onClick={onClick}
      className={`border rounded-lg p-3 ${colorMap[color] || colorMap.blue} ${onClick ? 'cursor-pointer hover:shadow-sm transition-shadow' : ''} ${active ? 'ring-2 ring-blue-500 ring-offset-1' : ''}`}
    >
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-xs font-medium opacity-80">{label}</div>
      {subtitle && <div className="text-[10px] opacity-60 mt-0.5">{subtitle}</div>}
    </div>
  );
}
