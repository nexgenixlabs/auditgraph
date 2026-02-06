import React, { useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
type IdentityStatus = 'active' | 'disabled' | 'deleted';

type IdentityCategory =
  | 'service_principal'
  | 'managed_identity_system'
  | 'managed_identity_user'
  | 'human_user'
  | 'guest'
  | 'microsoft_internal'
  | 'unknown';

interface IdentityRow {
  identity_id: string;
  display_name: string;
  identity_type?: string;
  identity_category?: IdentityCategory;

  // Multi-cloud
  cloud?: string;

  // Dates
  created_datetime?: string | null;
  last_seen_auth?: string | null;
  last_sign_in?: string | null;

  // Permissions & Roles
  api_permission_count?: number;
  role_count?: number;
  rbac_role_count?: number;
  entra_role_count?: number;
  rbac_max_risk?: RiskLevel;
  entra_max_risk?: RiskLevel;
  app_role_count?: number;

  // Credentials
  credential_count?: number;
  credential_expiration?: string | null;
  next_expiry?: string | null;
  credential_status?: string | null;

  // Ownership
  owner_display_name?: string | null;
  owner_count?: number;

  // Status
  status?: IdentityStatus;
  enabled?: boolean;

  // Risk
  risk_level?: RiskLevel;
  risk_score?: number;
}

// All sortable fields
type SortField =
  | 'display_name'
  | 'cloud'
  | 'identity_id'
  | 'created_datetime'
  | 'last_seen_auth'
  | 'api_permission_count'
  | 'entra_role_count'
  | 'rbac_role_count'
  | 'credential_expiration'
  | 'app_role_count'
  | 'owner_display_name'
  | 'status'
  | 'risk_level';

const CATEGORY_OPTIONS: { value: IdentityCategory | 'all'; label: string }[] = [
  { value: 'all', label: 'All Categories' },
  { value: 'service_principal', label: 'Service Principal' },
  { value: 'managed_identity_system', label: 'System Assigned Identity' },
  { value: 'managed_identity_user', label: 'User Assigned Identity' },
  { value: 'human_user', label: 'Human User' },
  { value: 'guest', label: 'Guest' },
  { value: 'microsoft_internal', label: 'Microsoft Internal' },
];

const RISK_OPTIONS: { value: RiskLevel | 'all'; label: string }[] = [
  { value: 'all', label: 'All Levels' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
];

function safeLower(v: any): string {
  return String(v ?? '').toLowerCase();
}

function normalizeCategoryFromBackend(raw?: any): IdentityCategory {
  const v = safeLower(raw).trim();
  if (!v) return 'unknown';

  if (['service_principal', 'managed_identity_system', 'managed_identity_user',
       'human_user', 'guest', 'microsoft_internal'].includes(v)) {
    return v as IdentityCategory;
  }

  if (v === 'user' || v === 'human user') return 'human_user';
  if (v.includes('user assigned') || v.includes('user-assigned')) return 'managed_identity_user';
  if (v.includes('system assigned') || v.includes('system-assigned')) return 'managed_identity_system';
  if (v === 'service principal' || v === 'serviceprincipal') return 'service_principal';
  if (v.includes('microsoft')) return 'microsoft_internal';

  return 'unknown';
}

function formatDate(d?: string | null): string {
  if (!d) return '—';
  try {
    const date = new Date(d);
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  } catch {
    return d;
  }
}

function formatDateTime(d?: string | null): string {
  if (!d) return '—';
  try {
    const date = new Date(d);
    return date.toLocaleString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  } catch {
    return d;
  }
}

// Column header with sort arrows
function SortHeader({
  label,
  field,
  currentField,
  currentDir,
  onSort
}: {
  label: string;
  field: SortField;
  currentField: SortField;
  currentDir: 'asc' | 'desc';
  onSort: (f: SortField) => void;
}) {
  const isActive = currentField === field;
  return (
    <th
      className="px-3 py-3 cursor-pointer select-none hover:bg-gray-100 whitespace-nowrap"
      onClick={() => onSort(field)}
    >
      <div className="flex items-center gap-1">
        <span>{label}</span>
        <span className={`text-xs ${isActive ? 'text-blue-600' : 'text-gray-400'}`}>
          {isActive ? (currentDir === 'asc' ? '▲' : '▼') : '↕'}
        </span>
      </div>
    </th>
  );
}

// Cloud badge
function CloudBadge({ cloud }: { cloud?: string }) {
  const c = safeLower(cloud) || 'azure';
  const colors: Record<string, string> = {
    azure: 'bg-blue-100 text-blue-700',
    aws: 'bg-orange-100 text-orange-700',
    gcp: 'bg-red-100 text-red-700',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium uppercase ${colors[c] || colors.azure}`}>
      {c}
    </span>
  );
}

// Status badge
function StatusBadge({ status, enabled }: { status?: string; enabled?: boolean }) {
  const isActive = status === 'active' || (status === undefined && enabled !== false);
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
      isActive ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
    }`}>
      {isActive ? 'Active' : 'Disabled'}
    </span>
  );
}

// Risk badge
function RiskBadge({ level, score }: { level?: RiskLevel; score?: number }) {
  const risk = safeLower(level);
  const styles: Record<string, string> = {
    critical: 'bg-red-100 text-red-800 border-red-200',
    high: 'bg-orange-100 text-orange-800 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    low: 'bg-green-100 text-green-800 border-green-200',
    info: 'bg-blue-100 text-blue-800 border-blue-200',
  };
  const cls = styles[risk] || 'bg-gray-100 text-gray-600 border-gray-200';

  return (
    <div className="flex items-center gap-1">
      <span className={`px-2 py-0.5 rounded text-xs font-medium uppercase border ${cls}`}>
        {risk || 'unknown'}
      </span>
      {score !== undefined && score > 0 && (
        <span className="text-xs text-gray-500 font-mono">({score})</span>
      )}
    </div>
  );
}

export default function IdentitiesPage() {
  const [identities, setIdentities] = useState<IdentityRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState<RiskLevel | 'all'>('all');
  const [categoryFilter, setCategoryFilter] = useState<IdentityCategory | 'all'>('all');

  const [sortField, setSortField] = useState<SortField>('risk_level');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  const navigate = useNavigate();
  const location = useLocation();

  // Parse URL params
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const catParam = params.get('identity_category') || params.get('category');
    const riskParam = params.get('risk_level');

    if (catParam) {
      const found = CATEGORY_OPTIONS.find(o => o.value === catParam);
      if (found && found.value !== 'all') setCategoryFilter(found.value as IdentityCategory);
    }
    if (riskParam) {
      const found = RISK_OPTIONS.find(o => o.value === riskParam);
      if (found && found.value !== 'all') setRiskFilter(found.value as RiskLevel);
    }
  }, [location.search]);

  // Fetch data
  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const resp = await fetch('http://localhost:5001/api/identities');
        if (!resp.ok) throw new Error('Failed to fetch identities');
        const data = await resp.json();

        const rows: IdentityRow[] = (data.identities || []).map((raw: any) => ({
          identity_id: raw.identity_id || raw.id || '',
          display_name: raw.display_name || raw.name || '',
          identity_type: raw.identity_type,
          identity_category: normalizeCategoryFromBackend(raw.identity_category),

          cloud: raw.cloud || 'azure',

          created_datetime: raw.created_datetime || null,
          last_seen_auth: raw.last_seen_auth || raw.last_sign_in || null,
          last_sign_in: raw.last_sign_in || null,

          api_permission_count: raw.api_permission_count ?? 0,
          role_count: raw.role_count ?? 0,
          rbac_role_count: raw.rbac_role_count ?? 0,
          entra_role_count: raw.entra_role_count ?? 0,
          rbac_max_risk: safeLower(raw.rbac_max_risk || 'info') as RiskLevel,
          entra_max_risk: safeLower(raw.entra_max_risk || 'info') as RiskLevel,
          app_role_count: raw.app_role_count ?? 0,

          credential_count: raw.credential_count ?? 0,
          credential_expiration: raw.credential_expiration || raw.next_expiry || null,
          next_expiry: raw.next_expiry || null,
          credential_status: raw.credential_status,

          owner_display_name: raw.owner_display_name || null,
          owner_count: raw.owner_count ?? 0,

          status: raw.status || (raw.enabled === false ? 'disabled' : 'active'),
          enabled: raw.enabled,

          risk_level: safeLower(raw.risk_level || 'unknown') as RiskLevel,
          risk_score: raw.risk_score ?? 0,
        }));

        if (!cancelled) setIdentities(rows);
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load identities');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => { cancelled = true; };
  }, []);

  // Filter and sort
  const filtered = useMemo(() => {
    let result = [...identities];

    // Search filter
    const s = safeLower(search);
    if (s) {
      result = result.filter(i =>
        safeLower(i.display_name).includes(s) ||
        safeLower(i.identity_id).includes(s) ||
        safeLower(i.owner_display_name).includes(s)
      );
    }

    // Risk filter
    if (riskFilter !== 'all') {
      result = result.filter(i => safeLower(i.risk_level) === safeLower(riskFilter));
    }

    // Category filter
    if (categoryFilter !== 'all') {
      result = result.filter(i => i.identity_category === categoryFilter);
    }

    // Sort
    result.sort((a, b) => {
      let aVal: any;
      let bVal: any;

      switch (sortField) {
        case 'display_name':
          aVal = safeLower(a.display_name);
          bVal = safeLower(b.display_name);
          break;
        case 'cloud':
          aVal = safeLower(a.cloud);
          bVal = safeLower(b.cloud);
          break;
        case 'identity_id':
          aVal = safeLower(a.identity_id);
          bVal = safeLower(b.identity_id);
          break;
        case 'created_datetime':
          aVal = a.created_datetime ? new Date(a.created_datetime).getTime() : 0;
          bVal = b.created_datetime ? new Date(b.created_datetime).getTime() : 0;
          break;
        case 'last_seen_auth':
          aVal = a.last_seen_auth ? new Date(a.last_seen_auth).getTime() : 0;
          bVal = b.last_seen_auth ? new Date(b.last_seen_auth).getTime() : 0;
          break;
        case 'api_permission_count':
          aVal = a.api_permission_count ?? 0;
          bVal = b.api_permission_count ?? 0;
          break;
        case 'entra_role_count':
          aVal = a.entra_role_count ?? 0;
          bVal = b.entra_role_count ?? 0;
          break;
        case 'rbac_role_count':
          aVal = a.rbac_role_count ?? 0;
          bVal = b.rbac_role_count ?? 0;
          break;
        case 'credential_expiration':
          aVal = a.credential_expiration ? new Date(a.credential_expiration).getTime() : Infinity;
          bVal = b.credential_expiration ? new Date(b.credential_expiration).getTime() : Infinity;
          break;
        case 'app_role_count':
          aVal = a.app_role_count ?? 0;
          bVal = b.app_role_count ?? 0;
          break;
        case 'owner_display_name':
          aVal = a.owner_display_name ? safeLower(a.owner_display_name) : 'zzz';
          bVal = b.owner_display_name ? safeLower(b.owner_display_name) : 'zzz';
          break;
        case 'status':
          aVal = a.status === 'active' ? 0 : 1;
          bVal = b.status === 'active' ? 0 : 1;
          break;
        case 'risk_level':
        default:
          const riskOrder: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1, unknown: 0 };
          aVal = riskOrder[safeLower(a.risk_level)] || 0;
          bVal = riskOrder[safeLower(b.risk_level)] || 0;
      }

      if (aVal < bVal) return sortDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });

    return result;
  }, [identities, search, riskFilter, categoryFilter, sortField, sortDir]);

  function handleSort(field: SortField) {
    if (field === sortField) {
      setSortDir(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      // Default sort direction based on field type
      setSortDir(['risk_level', 'api_permission_count', 'entra_role_count', 'rbac_role_count', 'app_role_count'].includes(field) ? 'desc' : 'asc');
    }
  }

  function openIdentity(id: string) {
    navigate(`/identities/${encodeURIComponent(id)}`);
  }

  return (
    <div className="max-w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-5">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">All Identities</h2>
          <p className="text-sm text-gray-600">Multi-cloud identity inventory with full sorting</p>
        </div>
        <div className="text-sm text-gray-600 font-medium">
          {loading ? 'Loading…' : `${filtered.length} of ${identities.length} identities`}
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white border rounded-xl p-4 mb-4 shadow-sm">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div>
            <label className="block text-xs font-semibold text-gray-700 mb-1">Search</label>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Name, ID, or Owner…"
              className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-700 mb-1">Risk Level</label>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value as any)}
              className="w-full border rounded-lg px-3 py-2 text-sm"
            >
              {RISK_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-700 mb-1">Category</label>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value as any)}
              className="w-full border rounded-lg px-3 py-2 text-sm"
            >
              {CATEGORY_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
          <div className="flex items-end">
            <button
              onClick={() => { setSearch(''); setRiskFilter('all'); setCategoryFilter('all'); }}
              className="w-full px-4 py-2 text-sm text-blue-600 border border-blue-200 rounded-lg hover:bg-blue-50"
            >
              Clear Filters
            </button>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white border rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 border-b text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">
              <tr>
                <SortHeader label="Identity Name" field="display_name" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Cloud" field="cloud" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Identity ID" field="identity_id" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Created" field="created_datetime" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Last Used" field="last_seen_auth" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="API Perms" field="api_permission_count" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Entra Roles" field="entra_role_count" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="RBAC Roles" field="rbac_role_count" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Secrets/Expiry" field="credential_expiration" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="App Roles" field="app_role_count" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Owner" field="owner_display_name" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Status" field="status" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Risk" field="risk_level" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {loading ? (
                <tr><td colSpan={13} className="px-4 py-8 text-center text-gray-500">Loading identities…</td></tr>
              ) : error ? (
                <tr><td colSpan={13} className="px-4 py-8 text-center text-red-600">{error}</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={13} className="px-4 py-8 text-center text-gray-500">No identities match your filters.</td></tr>
              ) : (
                filtered.map((i) => (
                  <tr
                    key={i.identity_id}
                    className="hover:bg-blue-50 cursor-pointer transition-colors"
                    onClick={() => openIdentity(i.identity_id)}
                  >
                    {/* Identity Name */}
                    <td className="px-3 py-3">
                      <div className="font-medium text-gray-900 truncate max-w-[200px]" title={i.display_name}>
                        {i.display_name}
                      </div>
                    </td>

                    {/* Cloud */}
                    <td className="px-3 py-3">
                      <CloudBadge cloud={i.cloud} />
                    </td>

                    {/* Identity ID */}
                    <td className="px-3 py-3">
                      <code className="text-xs text-gray-500 bg-gray-100 px-1.5 py-0.5 rounded">
                        {i.identity_id.substring(0, 8)}…
                      </code>
                    </td>

                    {/* Created */}
                    <td className="px-3 py-3 text-gray-600 whitespace-nowrap">
                      {formatDate(i.created_datetime)}
                    </td>

                    {/* Last Used */}
                    <td className="px-3 py-3 text-gray-600 whitespace-nowrap">
                      {formatDateTime(i.last_seen_auth)}
                    </td>

                    {/* API Perms */}
                    <td className="px-3 py-3 text-center">
                      <span className={`font-medium ${(i.api_permission_count ?? 0) > 0 ? 'text-purple-700' : 'text-gray-400'}`}>
                        {i.api_permission_count ?? 0}
                      </span>
                    </td>

                    {/* Entra Roles */}
                    <td className="px-3 py-3">
                      {(i.entra_role_count ?? 0) > 0 ? (
                        <div className="flex items-center gap-1">
                          <span className="font-medium text-indigo-700">{i.entra_role_count}</span>
                          <RiskBadge level={i.entra_max_risk} />
                        </div>
                      ) : (
                        <span className="text-gray-400">0</span>
                      )}
                    </td>

                    {/* RBAC Roles */}
                    <td className="px-3 py-3">
                      {(i.rbac_role_count ?? 0) > 0 ? (
                        <div className="flex items-center gap-1">
                          <span className="font-medium text-blue-700">{i.rbac_role_count}</span>
                          <RiskBadge level={i.rbac_max_risk} />
                        </div>
                      ) : (
                        <span className="text-gray-400">0</span>
                      )}
                    </td>

                    {/* Secrets/Expiry */}
                    <td className="px-3 py-3">
                      <div className="text-xs">
                        <span className="text-gray-600">{i.credential_count ?? 0} secret(s)</span>
                        {i.credential_expiration && (
                          <div className="text-orange-600">{formatDate(i.credential_expiration)}</div>
                        )}
                      </div>
                    </td>

                    {/* App Roles */}
                    <td className="px-3 py-3 text-center">
                      <span className={`font-medium ${(i.app_role_count ?? 0) > 0 ? 'text-indigo-700' : 'text-gray-400'}`}>
                        {i.app_role_count ?? 0}
                      </span>
                    </td>

                    {/* Owner */}
                    <td className="px-3 py-3">
                      {i.owner_display_name ? (
                        <span className="text-green-700 text-xs truncate max-w-[100px] block" title={i.owner_display_name}>
                          {i.owner_display_name}
                        </span>
                      ) : (
                        <span className="text-gray-400 text-xs">No owner</span>
                      )}
                    </td>

                    {/* Status */}
                    <td className="px-3 py-3">
                      <StatusBadge status={i.status} enabled={i.enabled} />
                    </td>

                    {/* Risk */}
                    <td className="px-3 py-3">
                      <RiskBadge level={i.risk_level} score={i.risk_score} />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Footer info */}
      <div className="mt-4 text-xs text-gray-500 text-center">
        Click any column header to sort. Click any row to view details.
      </div>
    </div>
  );
}
