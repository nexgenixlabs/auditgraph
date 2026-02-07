import React, { useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

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
  cloud?: string;
  created_datetime?: string | null;
  last_seen_auth?: string | null;
  last_sign_in?: string | null;
  api_permission_count?: number;
  role_count?: number;
  rbac_role_count?: number;
  entra_role_count?: number;
  rbac_max_risk?: RiskLevel;
  entra_max_risk?: RiskLevel;
  graph_max_risk?: RiskLevel;
  app_role_count?: number;
  credential_count?: number;
  credential_expiration?: string | null;
  credential_status?: string | null;
  owner_display_name?: string | null;
  owner_count?: number;
  status?: IdentityStatus;
  enabled?: boolean;
  risk_level?: RiskLevel;
  risk_score?: number;
  activity_status?: string;
  privilege_tier?: number;
}

type SortField =
  | 'display_name'
  | 'identity_type'
  | 'identity_category'
  | 'cloud'
  | 'risk_level'
  | 'entra_role_count'
  | 'rbac_role_count'
  | 'api_permission_count'
  | 'privilege_tier'
  | 'credential_expiration'
  | 'created_datetime'
  | 'last_seen_auth'
  | 'dormant';

const CATEGORY_OPTIONS: { value: IdentityCategory | 'all'; label: string }[] = [
  { value: 'all', label: 'All Categories' },
  { value: 'service_principal', label: 'Service Principal' },
  { value: 'managed_identity_system', label: 'System Assigned MI' },
  { value: 'managed_identity_user', label: 'User Assigned MI' },
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

// ─── Helpers ───────────────────────────────────────────────────────

function safeLower(v: any): string {
  return String(v ?? '').toLowerCase();
}

function normalizeCategoryFromBackend(raw?: any): IdentityCategory {
  const v = safeLower(raw).trim();
  if (!v) return 'unknown';
  if (['service_principal', 'managed_identity_system', 'managed_identity_user',
       'human_user', 'guest', 'microsoft_internal'].includes(v))
    return v as IdentityCategory;
  if (v === 'user' || v === 'human user') return 'human_user';
  if (v.includes('user assigned') || v.includes('user-assigned')) return 'managed_identity_user';
  if (v.includes('system assigned') || v.includes('system-assigned')) return 'managed_identity_system';
  if (v === 'service principal' || v === 'serviceprincipal') return 'service_principal';
  if (v.includes('microsoft')) return 'microsoft_internal';
  return 'unknown';
}

function formatDate(d?: string | null): string {
  if (!d) return '—';
  try { return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }); }
  catch { return d; }
}

const RISK_ORDER: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1, unknown: 0 };

function getPrivilegeTier(row: IdentityRow): number {
  // Use backend-computed tier (role-name-based) when available
  if (row.privilege_tier != null) return row.privilege_tier;
  // Fallback: derive from max risk level
  const rbac = RISK_ORDER[safeLower(row.rbac_max_risk)] || 0;
  const entra = RISK_ORDER[safeLower(row.entra_max_risk)] || 0;
  const graph = RISK_ORDER[safeLower(row.graph_max_risk)] || 0;
  const maxRisk = Math.max(rbac, entra, graph);
  if (maxRisk >= 5) return 0;
  if (maxRisk >= 4) return 1;
  if (maxRisk >= 3) return 2;
  return 3;
}

function getDormantStatus(row: IdentityRow): 'yes' | 'idle' | 'no' | 'unknown' {
  const act = safeLower(row.activity_status);
  if (act === 'stale') return 'yes';
  if (act === 'inactive') return 'idle';
  if (act === 'active') return 'no';
  return 'unknown';
}

function getCategoryLabel(cat?: IdentityCategory): string {
  const labels: Record<string, string> = {
    service_principal: 'Service Principal',
    managed_identity_system: 'System MI',
    managed_identity_user: 'User MI',
    human_user: 'Human User',
    guest: 'Guest',
    microsoft_internal: 'Microsoft Internal',
  };
  return labels[cat || ''] || 'Unknown';
}

function getComplianceRelevance(i: IdentityRow): string {
  const frameworks: string[] = [];
  const risk = i.risk_level || 'unknown';
  const hasPrivilegedRoles = (i.entra_role_count ?? 0) > 0 || (i.rbac_role_count ?? 0) > 0;
  if (risk === 'critical' || risk === 'high') frameworks.push('SOC2', 'HIPAA', 'PCI-DSS');
  else if (risk === 'medium' && hasPrivilegedRoles) frameworks.push('SOC2');
  if ((i.identity_category === 'human_user' || i.identity_category === 'guest') && hasPrivilegedRoles)
    frameworks.push('HIPAA §164.312');
  return frameworks.length > 0 ? Array.from(new Set(frameworks)).join(', ') : 'Low Priority';
}

// ─── Small presentational components ───────────────────────────────

function SortHeader({ label, field, currentField, currentDir, onSort }: {
  label: string; field: SortField; currentField: SortField; currentDir: 'asc' | 'desc'; onSort: (f: SortField) => void;
}) {
  const isActive = currentField === field;
  return (
    <th className="px-2 py-2.5 cursor-pointer select-none hover:bg-gray-100 whitespace-nowrap text-xs" onClick={() => onSort(field)}>
      <div className="flex items-center gap-0.5">
        <span>{label}</span>
        <span className={`text-[10px] ${isActive ? 'text-blue-600' : 'text-gray-400'}`}>
          {isActive ? (currentDir === 'asc' ? '▲' : '▼') : '↕'}
        </span>
      </div>
    </th>
  );
}

function CloudBadge({ cloud }: { cloud?: string }) {
  const c = safeLower(cloud) || 'azure';
  const colors: Record<string, string> = { azure: 'bg-blue-100 text-blue-700', aws: 'bg-orange-100 text-orange-700', gcp: 'bg-red-100 text-red-700' };
  return <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${colors[c] || colors.azure}`}>{c}</span>;
}

function RiskBadge({ level, score }: { level?: RiskLevel; score?: number }) {
  const risk = safeLower(level);
  const styles: Record<string, string> = {
    critical: 'bg-red-100 text-red-800', high: 'bg-orange-100 text-orange-800',
    medium: 'bg-yellow-100 text-yellow-800', low: 'bg-green-100 text-green-800', info: 'bg-blue-100 text-blue-800',
  };
  return (
    <div className="flex items-center gap-1">
      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${styles[risk] || 'bg-gray-100 text-gray-600'}`}>
        {risk || '?'}
      </span>
      {score !== undefined && score > 0 && <span className="text-[10px] text-gray-400 font-mono">{score}</span>}
    </div>
  );
}

function RiskDot({ level }: { level?: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-400', low: 'bg-green-400', info: 'bg-blue-400',
  };
  return <span className={`inline-block w-1.5 h-1.5 rounded-full ${colors[safeLower(level)] || 'bg-gray-300'}`} />;
}

function TierBadge({ tier }: { tier: number }) {
  const cfg: Record<number, { label: string; color: string; title: string }> = {
    0: { label: 'T0', color: 'bg-red-100 text-red-800 border-red-300', title: 'T0 Control Plane — Global Admin, Privileged Role Admin, tenant-wide Owner' },
    1: { label: 'T1', color: 'bg-orange-100 text-orange-800 border-orange-300', title: 'T1 Management Plane — User Admin, Exchange Admin, subscription Owner/Contributor' },
    2: { label: 'T2', color: 'bg-yellow-100 text-yellow-800 border-yellow-300', title: 'T2 Data/App Plane — scoped roles, risky Graph API permissions' },
    3: { label: 'T3', color: 'bg-gray-100 text-gray-600 border-gray-300', title: 'T3 Standard — no privileged roles' },
  };
  const c = cfg[tier] || cfg[3];
  return (
    <span className={`px-1.5 py-0.5 rounded border text-[10px] font-bold ${c.color}`} title={c.title}>
      {c.label}
    </span>
  );
}

function DormantBadge({ status }: { status: 'yes' | 'idle' | 'no' | 'unknown' }) {
  if (status === 'yes') return <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-100 text-red-700">90d+</span>;
  if (status === 'idle') return <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-yellow-100 text-yellow-700">30-90d</span>;
  if (status === 'no') return <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-green-100 text-green-700">Active</span>;
  return <span className="text-[10px] text-gray-300">—</span>;
}

function CategoryBadge({ category }: { category?: IdentityCategory }) {
  const map: Record<string, { label: string; color: string }> = {
    service_principal: { label: 'SPN', color: 'bg-purple-50 text-purple-700' },
    managed_identity_system: { label: 'Sys MI', color: 'bg-cyan-50 text-cyan-700' },
    managed_identity_user: { label: 'Usr MI', color: 'bg-teal-50 text-teal-700' },
    human_user: { label: 'Human', color: 'bg-indigo-50 text-indigo-700' },
    guest: { label: 'Guest', color: 'bg-pink-50 text-pink-700' },
    microsoft_internal: { label: 'MSFT', color: 'bg-sky-50 text-sky-700' },
  };
  const info = map[category || ''] || { label: '?', color: 'bg-gray-50 text-gray-600' };
  return <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${info.color}`}>{info.label}</span>;
}

function TypeLabel({ type }: { type?: string }) {
  const t = safeLower(type);
  const labels: Record<string, string> = {
    serviceprincipal: 'App',
    service_principal: 'App',
    user: 'User',
    group: 'Group',
    managed_identity: 'MI',
  };
  return <span className="text-[11px] text-gray-600">{labels[t] || type || '—'}</span>;
}

// ─── Main component ────────────────────────────────────────────────

export default function IdentitiesPage() {
  const [identities, setIdentities] = useState<IdentityRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState<RiskLevel | 'all'>('all');
  const [categoryFilter, setCategoryFilter] = useState<IdentityCategory | 'all'>('all');
  const [ownerFilter, setOwnerFilter] = useState<'all' | 'unowned'>('all');
  const [activityFilter, setActivityFilter] = useState<'all' | 'dormant'>('all');
  const [tierFilter, setTierFilter] = useState<number | 'all'>('all');
  const [sortField, setSortField] = useState<SortField>('risk_level');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  const navigate = useNavigate();
  const location = useLocation();

  // URL param sync
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const catParam = params.get('identity_category') || params.get('category');
    const riskParam = params.get('risk_level');
    const ownerParam = params.get('owner_status');
    const activityParam = params.get('activity_status');
    const tierParam = params.get('privilege_tier');
    setCategoryFilter(catParam && CATEGORY_OPTIONS.find(o => o.value === catParam) ? catParam as IdentityCategory : 'all');
    setRiskFilter(riskParam && RISK_OPTIONS.find(o => o.value === riskParam) ? riskParam as RiskLevel : 'all');
    setOwnerFilter(ownerParam === 'unowned' ? 'unowned' : 'all');
    setActivityFilter(activityParam === 'dormant' ? 'dormant' : 'all');
    setTierFilter(tierParam != null && ['0', '1', '2', '3'].includes(tierParam) ? Number(tierParam) : 'all');
  }, [location.search]);

  // Fetch
  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const resp = await fetch('http://localhost:5001/api/identities');
        if (!resp.ok) throw new Error('Failed to fetch identities');
        const data = await resp.json();
        const rows: IdentityRow[] = (data.identities || []).map((raw: any) => ({
          identity_id: raw.identity_id || '',
          display_name: raw.display_name || '',
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
          graph_max_risk: safeLower(raw.graph_max_risk || 'info') as RiskLevel,
          app_role_count: raw.app_role_count ?? 0,
          credential_count: raw.credential_count ?? 0,
          credential_expiration: raw.credential_expiration || raw.next_expiry || null,
          credential_status: raw.credential_status,
          owner_display_name: raw.owner_display_name || null,
          owner_count: raw.owner_count ?? 0,
          status: raw.status || (raw.enabled === false ? 'disabled' : 'active'),
          enabled: raw.enabled,
          risk_level: safeLower(raw.risk_level || 'unknown') as RiskLevel,
          risk_score: raw.risk_score ?? 0,
          activity_status: raw.activity_status || 'unknown',
          privilege_tier: raw.privilege_tier ?? undefined,
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

  // Filter & sort
  const filtered = useMemo(() => {
    let result = [...identities];
    const s = safeLower(search);
    if (s) result = result.filter(i => safeLower(i.display_name).includes(s) || safeLower(i.identity_id).includes(s) || safeLower(i.owner_display_name).includes(s));
    if (riskFilter !== 'all') result = result.filter(i => safeLower(i.risk_level) === safeLower(riskFilter));
    if (categoryFilter !== 'all') result = result.filter(i => i.identity_category === categoryFilter);
    if (ownerFilter === 'unowned') result = result.filter(i => !i.owner_display_name && (i.owner_count ?? 0) === 0);
    if (activityFilter === 'dormant') result = result.filter(i => getDormantStatus(i) === 'yes' || getDormantStatus(i) === 'idle');
    if (tierFilter !== 'all') result = result.filter(i => getPrivilegeTier(i) === tierFilter);

    result.sort((a, b) => {
      let aVal: any, bVal: any;
      switch (sortField) {
        case 'display_name': aVal = safeLower(a.display_name); bVal = safeLower(b.display_name); break;
        case 'identity_type': aVal = safeLower(a.identity_type); bVal = safeLower(b.identity_type); break;
        case 'identity_category': aVal = safeLower(a.identity_category); bVal = safeLower(b.identity_category); break;
        case 'cloud': aVal = safeLower(a.cloud); bVal = safeLower(b.cloud); break;
        case 'entra_role_count': aVal = a.entra_role_count ?? 0; bVal = b.entra_role_count ?? 0; break;
        case 'rbac_role_count': aVal = a.rbac_role_count ?? 0; bVal = b.rbac_role_count ?? 0; break;
        case 'api_permission_count': aVal = a.api_permission_count ?? 0; bVal = b.api_permission_count ?? 0; break;
        case 'privilege_tier': aVal = getPrivilegeTier(a); bVal = getPrivilegeTier(b); break;
        case 'credential_expiration':
          aVal = a.credential_expiration ? new Date(a.credential_expiration).getTime() : Infinity;
          bVal = b.credential_expiration ? new Date(b.credential_expiration).getTime() : Infinity;
          break;
        case 'created_datetime':
          aVal = a.created_datetime ? new Date(a.created_datetime).getTime() : 0;
          bVal = b.created_datetime ? new Date(b.created_datetime).getTime() : 0;
          break;
        case 'last_seen_auth':
          aVal = a.last_seen_auth ? new Date(a.last_seen_auth).getTime() : 0;
          bVal = b.last_seen_auth ? new Date(b.last_seen_auth).getTime() : 0;
          break;
        case 'dormant':
          const dormOrder: Record<string, number> = { yes: 3, idle: 2, no: 1, unknown: 0 };
          aVal = dormOrder[getDormantStatus(a)] || 0;
          bVal = dormOrder[getDormantStatus(b)] || 0;
          break;
        case 'risk_level':
        default:
          aVal = RISK_ORDER[safeLower(a.risk_level)] || 0;
          bVal = RISK_ORDER[safeLower(b.risk_level)] || 0;
      }
      if (aVal < bVal) return sortDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
    return result;
  }, [identities, search, riskFilter, categoryFilter, ownerFilter, activityFilter, tierFilter, sortField, sortDir]);

  function handleSort(field: SortField) {
    if (field === sortField) setSortDir(prev => prev === 'asc' ? 'desc' : 'asc');
    else {
      setSortField(field);
      setSortDir(['risk_level', 'entra_role_count', 'rbac_role_count', 'api_permission_count', 'privilege_tier', 'dormant'].includes(field) ? 'desc' : 'asc');
    }
  }

  function toggleSelect(id: string) { setSelectedIds(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; }); }
  function selectAll() { selectedIds.size === filtered.length ? setSelectedIds(new Set()) : setSelectedIds(new Set(filtered.map(i => i.identity_id))); }
  function selectCompliance() {
    setSelectedIds(new Set(filtered.filter(i => i.risk_level === 'critical' || i.risk_level === 'high' || (i.risk_level === 'medium' && ((i.entra_role_count ?? 0) > 0 || (i.rbac_role_count ?? 0) > 0))).map(i => i.identity_id)));
  }

  const selectedIdentities = useMemo(() => selectedIds.size === 0 ? [] : filtered.filter(i => selectedIds.has(i.identity_id)), [filtered, selectedIds]);

  // Export CSV
  function exportToCSV() {
    if (selectedIds.size === 0) { alert('Select identities first.'); return; }
    const headers = ['Display Name','Identity ID','Type','Category','Cloud','Risk','Score','Tier','Entra Roles','RBAC Roles','Graph Perms','Secret/Expiry','Created','Last Used','Dormant','Compliance','Owner'];
    const rows = selectedIdentities.map(i => [
      i.display_name, i.identity_id, i.identity_type || '', getCategoryLabel(i.identity_category),
      i.cloud || 'azure', (i.risk_level || 'unknown').toUpperCase(), i.risk_score ?? 0,
      `T${getPrivilegeTier(i)}`, i.entra_role_count ?? 0, i.rbac_role_count ?? 0,
      i.api_permission_count ?? 0, i.credential_expiration || '', i.created_datetime || '',
      i.last_seen_auth || 'N/A', getDormantStatus(i), getComplianceRelevance(i), i.owner_display_name || '',
    ]);
    const csv = [headers.join(','), ...rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `auditgraph-report-${new Date().toISOString().split('T')[0]}.csv`; a.click();
    URL.revokeObjectURL(url);
  }

  // Export PDF
  function exportToPDF() {
    if (selectedIds.size === 0) { alert('Select identities first.'); return; }
    const doc = new jsPDF({ orientation: 'landscape' });
    doc.setFontSize(18); doc.setTextColor(30, 64, 175); doc.text('AuditGraph GRC Compliance Report', 14, 18);
    doc.setFontSize(9); doc.setTextColor(100);
    doc.text(`Generated: ${new Date().toLocaleString()} | Identities: ${selectedIdentities.length}`, 14, 25);
    const critical = selectedIdentities.filter(i => i.risk_level === 'critical').length;
    const high = selectedIdentities.filter(i => i.risk_level === 'high').length;
    doc.text(`Risk: ${critical} Critical, ${high} High | Frameworks: SOC2, HIPAA, PCI-DSS, NIST 800-53`, 14, 30);

    autoTable(doc, {
      startY: 35,
      head: [['Identity', 'Category', 'Risk', 'Score', 'Tier', 'Roles', 'Perms', 'Dormant', 'Compliance']],
      body: selectedIdentities.map(i => [
        i.display_name.substring(0, 28) + (i.display_name.length > 28 ? '..' : ''),
        getCategoryLabel(i.identity_category), (i.risk_level || '?').toUpperCase(),
        String(i.risk_score ?? 0), `T${getPrivilegeTier(i)}`,
        String((i.entra_role_count ?? 0) + (i.rbac_role_count ?? 0)),
        String(i.api_permission_count ?? 0), getDormantStatus(i).toUpperCase(),
        getComplianceRelevance(i),
      ]),
      styles: { fontSize: 7, cellPadding: 1.5 },
      headStyles: { fillColor: [30, 64, 175], textColor: 255 },
      alternateRowStyles: { fillColor: [245, 247, 250] },
      didParseCell: (data) => {
        if (data.column.index === 2 && data.section === 'body') {
          const r = String(data.cell.raw).toLowerCase();
          if (r === 'critical') { data.cell.styles.fillColor = [254,226,226]; data.cell.styles.textColor = [185,28,28]; }
          else if (r === 'high') { data.cell.styles.fillColor = [255,237,213]; data.cell.styles.textColor = [194,65,12]; }
        }
      },
    });
    doc.save(`auditgraph-grc-report-${new Date().toISOString().split('T')[0]}.pdf`);
  }

  const colSpan = 14; // checkbox + 13 data cols

  return (
    <div className="max-w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-4">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">All Identities</h2>
          <p className="text-sm text-gray-500">Full identity inventory — click any row for deep-dive</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm text-gray-600">
            {loading ? 'Loading…' : `${filtered.length} of ${identities.length}`}
            {selectedIds.size > 0 && <span className="ml-1 text-blue-600 font-semibold">({selectedIds.size} sel)</span>}
          </span>
          {!loading && filtered.length > 0 && (
            <>
              <button onClick={selectCompliance} className="px-2.5 py-1 text-xs font-medium text-purple-700 bg-purple-50 border border-purple-200 rounded-lg hover:bg-purple-100" title="Select GRC-relevant identities">
                GRC Select
              </button>
              {selectedIds.size > 0 && (
                <button onClick={() => setSelectedIds(new Set())} className="px-2.5 py-1 text-xs font-medium text-gray-600 bg-gray-50 border border-gray-200 rounded-lg hover:bg-gray-100">Clear</button>
              )}
              <span className="w-px h-5 bg-gray-300" />
              <button onClick={exportToCSV} className="px-2.5 py-1 text-xs font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50">CSV</button>
              <button onClick={exportToPDF} className="px-2.5 py-1 text-xs font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700">PDF</button>
            </>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white border rounded-xl p-3 mb-3 shadow-sm">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search name, ID, owner…"
            className="border rounded-lg px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500" />
          <select value={riskFilter} onChange={e => setRiskFilter(e.target.value as any)} className="border rounded-lg px-3 py-1.5 text-sm">
            {RISK_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          <select value={categoryFilter} onChange={e => setCategoryFilter(e.target.value as any)} className="border rounded-lg px-3 py-1.5 text-sm">
            {CATEGORY_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          <button onClick={() => { setSearch(''); setRiskFilter('all'); setCategoryFilter('all'); setOwnerFilter('all'); setActivityFilter('all'); setTierFilter('all'); navigate('/identities', { replace: true }); }}
            className="px-3 py-1.5 text-sm text-blue-600 border border-blue-200 rounded-lg hover:bg-blue-50">
            Clear
          </button>
        </div>
        {/* Active filter chips from recommendations */}
        {(ownerFilter !== 'all' || activityFilter !== 'all' || tierFilter !== 'all') && (
          <div className="flex items-center gap-2 mt-2 flex-wrap">
            <span className="text-[10px] text-gray-500 uppercase font-semibold">Active filters:</span>
            {ownerFilter === 'unowned' && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                No Owner
                <button onClick={() => { setOwnerFilter('all'); }} className="hover:text-yellow-600">&times;</button>
              </span>
            )}
            {activityFilter === 'dormant' && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                Dormant
                <button onClick={() => { setActivityFilter('all'); }} className="hover:text-red-600">&times;</button>
              </span>
            )}
            {tierFilter !== 'all' && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                Tier T{tierFilter}
                <button onClick={() => { setTierFilter('all'); }} className="hover:text-purple-600">&times;</button>
              </span>
            )}
          </div>
        )}
      </div>

      {/* Table */}
      <div className="bg-white border rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="min-w-full text-[12px]">
            <thead className="bg-gray-50 border-b text-left font-semibold text-gray-600 uppercase tracking-wider">
              <tr>
                <th className="px-2 py-2.5 w-8">
                  <input type="checkbox" checked={filtered.length > 0 && selectedIds.size === filtered.length} onChange={selectAll}
                    className="w-3.5 h-3.5 text-blue-600 rounded cursor-pointer" />
                </th>
                <SortHeader label="Identity Name" field="display_name" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Type" field="identity_type" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Category" field="identity_category" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Cloud" field="cloud" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Risk" field="risk_level" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Entra" field="entra_role_count" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="RBAC" field="rbac_role_count" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Graph API" field="api_permission_count" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Tier" field="privilege_tier" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Secret/Expiry" field="credential_expiration" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Created" field="created_datetime" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Last Used" field="last_seen_auth" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Dormant" field="dormant" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {loading ? (
                <tr><td colSpan={colSpan} className="px-4 py-8 text-center text-gray-500">Loading…</td></tr>
              ) : error ? (
                <tr><td colSpan={colSpan} className="px-4 py-8 text-center text-red-600">{error}</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={colSpan} className="px-4 py-8 text-center text-gray-500">No identities match filters.</td></tr>
              ) : filtered.map(i => {
                const tier = getPrivilegeTier(i);
                const dormant = getDormantStatus(i);
                return (
                  <tr key={i.identity_id}
                    className={`hover:bg-blue-50 cursor-pointer transition-colors ${selectedIds.has(i.identity_id) ? 'bg-blue-50' : ''}`}
                    onClick={() => navigate(`/identities/${encodeURIComponent(i.identity_id)}`)}
                  >
                    {/* Checkbox */}
                    <td className="px-2 py-2" onClick={e => e.stopPropagation()}>
                      <input type="checkbox" checked={selectedIds.has(i.identity_id)} onChange={() => toggleSelect(i.identity_id)}
                        className="w-3.5 h-3.5 text-blue-600 rounded cursor-pointer" />
                    </td>

                    {/* Name */}
                    <td className="px-2 py-2 max-w-[180px]">
                      <div className="font-medium text-gray-900 truncate" title={i.display_name}>{i.display_name}</div>
                      <div className="text-[10px] text-gray-400 font-mono">{i.identity_id.substring(0, 8)}…</div>
                    </td>

                    {/* Type */}
                    <td className="px-2 py-2"><TypeLabel type={i.identity_type} /></td>

                    {/* Category */}
                    <td className="px-2 py-2"><CategoryBadge category={i.identity_category} /></td>

                    {/* Cloud */}
                    <td className="px-2 py-2"><CloudBadge cloud={i.cloud} /></td>

                    {/* Risk */}
                    <td className="px-2 py-2"><RiskBadge level={i.risk_level} score={i.risk_score} /></td>

                    {/* Entra Roles */}
                    <td className="px-2 py-2 text-center">
                      {(i.entra_role_count ?? 0) > 0 ? (
                        <div className="flex items-center justify-center gap-1">
                          <RiskDot level={i.entra_max_risk} />
                          <span className="font-semibold text-indigo-700">{i.entra_role_count}</span>
                        </div>
                      ) : <span className="text-gray-300">0</span>}
                    </td>

                    {/* RBAC Roles */}
                    <td className="px-2 py-2 text-center">
                      {(i.rbac_role_count ?? 0) > 0 ? (
                        <div className="flex items-center justify-center gap-1">
                          <RiskDot level={i.rbac_max_risk} />
                          <span className="font-semibold text-blue-700">{i.rbac_role_count}</span>
                        </div>
                      ) : <span className="text-gray-300">0</span>}
                    </td>

                    {/* Graph API */}
                    <td className="px-2 py-2 text-center">
                      {(i.api_permission_count ?? 0) > 0 ? (
                        <div className="flex items-center justify-center gap-1">
                          <RiskDot level={i.graph_max_risk} />
                          <span className="font-semibold text-purple-700">{i.api_permission_count}</span>
                        </div>
                      ) : <span className="text-gray-300">0</span>}
                    </td>

                    {/* Privilege Tier */}
                    <td className="px-2 py-2 text-center"><TierBadge tier={tier} /></td>

                    {/* Secret/Expiry */}
                    <td className="px-2 py-2">
                      {i.identity_category === 'human_user' || i.identity_category === 'guest' ? (
                        <span className="text-gray-300">N/A</span>
                      ) : (
                        <div>
                          <span className="text-gray-600">{i.credential_count ?? 0}</span>
                          {i.credential_expiration && (
                            <div className="text-[10px] text-orange-600">{formatDate(i.credential_expiration)}</div>
                          )}
                        </div>
                      )}
                    </td>

                    {/* Created */}
                    <td className="px-2 py-2 text-gray-600 whitespace-nowrap">{formatDate(i.created_datetime)}</td>

                    {/* Last Used */}
                    <td className="px-2 py-2 whitespace-nowrap">
                      {i.last_seen_auth ? (
                        <span className="text-gray-600">{formatDate(i.last_seen_auth)}</span>
                      ) : (
                        <span className="text-gray-300 italic" title="Requires Azure AD Premium P1/P2">P1/P2</span>
                      )}
                    </td>

                    {/* Dormant */}
                    <td className="px-2 py-2 text-center"><DormantBadge status={dormant} /></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="mt-3 text-[11px] text-gray-400 text-center">
        T0 = Control Plane (Global Admin, Priv Role Admin, tenant Owner) |
        T1 = Management Plane (User/Exchange/Intune Admin, sub Owner/Contributor) |
        T2 = Data/App (scoped roles, risky perms) |
        T3 = Standard.
        Dormant: 90d+ = stale, 30-90d = idle.
      </div>
    </div>
  );
}
