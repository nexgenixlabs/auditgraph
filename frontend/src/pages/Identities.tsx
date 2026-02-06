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

// Consolidated sort fields for the cleaned-up column model
type SortField =
  | 'display_name'
  | 'identity_category'
  | 'cloud'
  | 'risk_level'
  | 'role_count'
  | 'api_permission_count'
  | 'credential_expiration'
  | 'owner_display_name'
  | 'status';

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

// Mini risk dot for inline use
function RiskDot({ level }: { level?: string }) {
  const risk = safeLower(level);
  const colors: Record<string, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-400',
    low: 'bg-green-400',
    info: 'bg-blue-400',
  };
  return <span className={`inline-block w-2 h-2 rounded-full ${colors[risk] || 'bg-gray-300'}`} />;
}

// Category badge
function CategoryBadge({ category }: { category?: IdentityCategory }) {
  const labels: Record<string, { label: string; color: string }> = {
    service_principal: { label: 'Service Principal', color: 'bg-purple-50 text-purple-700' },
    managed_identity_system: { label: 'System MI', color: 'bg-cyan-50 text-cyan-700' },
    managed_identity_user: { label: 'User MI', color: 'bg-teal-50 text-teal-700' },
    human_user: { label: 'Human', color: 'bg-indigo-50 text-indigo-700' },
    guest: { label: 'Guest', color: 'bg-pink-50 text-pink-700' },
    microsoft_internal: { label: 'Microsoft', color: 'bg-sky-50 text-sky-700' },
  };

  const info = labels[category || ''] || { label: 'Unknown', color: 'bg-gray-50 text-gray-600' };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${info.color}`}>
      {info.label}
    </span>
  );
}

// Category label helper
function getCategoryLabel(cat?: IdentityCategory): string {
  const labels: Record<string, string> = {
    service_principal: 'Service Principal',
    managed_identity_system: 'System Assigned MI',
    managed_identity_user: 'User Assigned MI',
    human_user: 'Human User',
    guest: 'Guest',
    microsoft_internal: 'Microsoft Internal',
  };
  return labels[cat || ''] || 'Unknown';
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

  // Selection state for export
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  const navigate = useNavigate();
  const location = useLocation();

  // Parse URL params - reset filters based on URL
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const catParam = params.get('identity_category') || params.get('category');
    const riskParam = params.get('risk_level');

    if (catParam) {
      const found = CATEGORY_OPTIONS.find(o => o.value === catParam);
      if (found && found.value !== 'all') {
        setCategoryFilter(found.value as IdentityCategory);
      } else {
        setCategoryFilter('all');
      }
    } else {
      setCategoryFilter('all');
    }

    if (riskParam) {
      const found = RISK_OPTIONS.find(o => o.value === riskParam);
      if (found && found.value !== 'all') {
        setRiskFilter(found.value as RiskLevel);
      } else {
        setRiskFilter('all');
      }
    } else {
      setRiskFilter('all');
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
        case 'identity_category':
          aVal = safeLower(a.identity_category);
          bVal = safeLower(b.identity_category);
          break;
        case 'cloud':
          aVal = safeLower(a.cloud);
          bVal = safeLower(b.cloud);
          break;
        case 'role_count':
          aVal = (a.entra_role_count ?? 0) + (a.rbac_role_count ?? 0);
          bVal = (b.entra_role_count ?? 0) + (b.rbac_role_count ?? 0);
          break;
        case 'api_permission_count':
          aVal = (a.api_permission_count ?? 0) + (a.app_role_count ?? 0);
          bVal = (b.api_permission_count ?? 0) + (b.app_role_count ?? 0);
          break;
        case 'credential_expiration':
          aVal = a.credential_expiration ? new Date(a.credential_expiration).getTime() : Infinity;
          bVal = b.credential_expiration ? new Date(b.credential_expiration).getTime() : Infinity;
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
      setSortDir(['risk_level', 'role_count', 'api_permission_count'].includes(field) ? 'desc' : 'asc');
    }
  }

  function openIdentity(id: string) {
    navigate(`/identities/${encodeURIComponent(id)}`);
  }

  // Selection helpers
  function toggleSelect(id: string) {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  function selectAll() {
    if (selectedIds.size === filtered.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filtered.map(i => i.identity_id)));
    }
  }

  function selectCompliance() {
    const complianceIds = filtered
      .filter(i =>
        i.risk_level === 'critical' ||
        i.risk_level === 'high' ||
        (i.risk_level === 'medium' && ((i.entra_role_count ?? 0) > 0 || (i.rbac_role_count ?? 0) > 0))
      )
      .map(i => i.identity_id);
    setSelectedIds(new Set(complianceIds));
  }

  function clearSelection() {
    setSelectedIds(new Set());
  }

  // Get selected identities for export
  const selectedIdentities = useMemo(() => {
    if (selectedIds.size === 0) return [];
    return filtered.filter(i => selectedIds.has(i.identity_id));
  }, [filtered, selectedIds]);

  // Helper to determine compliance relevance
  function getComplianceRelevance(i: IdentityRow): string {
    const frameworks: string[] = [];
    const risk = i.risk_level || 'unknown';
    const hasPrivilegedRoles = (i.entra_role_count ?? 0) > 0 || (i.rbac_role_count ?? 0) > 0;

    if (risk === 'critical' || risk === 'high') {
      frameworks.push('SOC2', 'HIPAA', 'PCI-DSS');
    } else if (risk === 'medium' && hasPrivilegedRoles) {
      frameworks.push('SOC2');
    }

    if (i.identity_category === 'human_user' || i.identity_category === 'guest') {
      if (hasPrivilegedRoles) frameworks.push('HIPAA §164.312');
    }

    return frameworks.length > 0 ? Array.from(new Set(frameworks)).join(', ') : 'Low Priority';
  }

  // Export to CSV
  function exportToCSV() {
    if (selectedIds.size === 0) {
      alert('Please select identities to export. Use checkboxes or "Select for GRC" button.');
      return;
    }

    const headers = [
      'Display Name', 'Identity ID', 'Category', 'Cloud', 'Risk Level', 'Risk Score',
      'Compliance Relevance', 'Status', 'Entra Roles', 'RBAC Roles',
      'API Permissions', 'App Roles', 'Created', 'Last Sign-in', 'Owner',
    ];

    const rows = selectedIdentities.map(i => [
      i.display_name, i.identity_id, getCategoryLabel(i.identity_category),
      i.cloud || 'azure', (i.risk_level || 'unknown').toUpperCase(), i.risk_score ?? 0,
      getComplianceRelevance(i), i.enabled === false ? 'Disabled' : 'Active',
      i.entra_role_count ?? 0, i.rbac_role_count ?? 0, i.api_permission_count ?? 0,
      i.app_role_count ?? 0, i.created_datetime || '', i.last_seen_auth || 'N/A (Premium required)',
      i.owner_display_name || 'No owner',
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `auditgraph-grc-report-${new Date().toISOString().split('T')[0]}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  }

  // Export to PDF (GRC Audit Report)
  function exportToPDF() {
    if (selectedIds.size === 0) {
      alert('Please select identities to export. Use checkboxes or "Select for GRC" button.');
      return;
    }

    const doc = new jsPDF({ orientation: 'landscape' });

    doc.setFontSize(20);
    doc.setTextColor(30, 64, 175);
    doc.text('AuditGraph GRC Compliance Report', 14, 20);

    doc.setFontSize(10);
    doc.setTextColor(100);
    doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 28);
    doc.text(`Selected Identities: ${selectedIdentities.length}`, 14, 34);

    const critical = selectedIdentities.filter(i => i.risk_level === 'critical').length;
    const high = selectedIdentities.filter(i => i.risk_level === 'high').length;
    const medium = selectedIdentities.filter(i => i.risk_level === 'medium').length;
    doc.text(`Risk Summary: ${critical} Critical, ${high} High, ${medium} Medium`, 14, 40);

    doc.setFontSize(9);
    doc.setTextColor(80);
    doc.text('Applicable Frameworks: SOC2 (Least Privilege), HIPAA §164.312 (Access Controls), PCI-DSS 7.1 (Need-to-Know)', 14, 46);

    const tableData = selectedIdentities.map(i => [
      i.display_name.substring(0, 25) + (i.display_name.length > 25 ? '...' : ''),
      getCategoryLabel(i.identity_category),
      (i.risk_level || 'unknown').toUpperCase(),
      String(i.risk_score ?? 0),
      getComplianceRelevance(i),
      String((i.entra_role_count ?? 0) + (i.rbac_role_count ?? 0)),
      String((i.api_permission_count ?? 0) + (i.app_role_count ?? 0)),
      i.enabled === false ? 'Disabled' : 'Active',
    ]);

    autoTable(doc, {
      startY: 52,
      head: [['Identity', 'Category', 'Risk', 'Score', 'Compliance', 'Roles', 'Perms', 'Status']],
      body: tableData,
      styles: { fontSize: 8, cellPadding: 2 },
      headStyles: { fillColor: [30, 64, 175], textColor: 255 },
      alternateRowStyles: { fillColor: [245, 247, 250] },
      columnStyles: {
        0: { cellWidth: 45 },
        1: { cellWidth: 35 },
        2: { cellWidth: 18, halign: 'center' },
        3: { cellWidth: 15, halign: 'center' },
        4: { cellWidth: 45 },
        5: { cellWidth: 15, halign: 'center' },
        6: { cellWidth: 15, halign: 'center' },
        7: { cellWidth: 20, halign: 'center' },
      },
      didParseCell: function(data) {
        if (data.column.index === 2 && data.section === 'body') {
          const risk = String(data.cell.raw).toLowerCase();
          if (risk === 'critical') {
            data.cell.styles.fillColor = [254, 226, 226];
            data.cell.styles.textColor = [185, 28, 28];
          } else if (risk === 'high') {
            data.cell.styles.fillColor = [255, 237, 213];
            data.cell.styles.textColor = [194, 65, 12];
          } else if (risk === 'medium') {
            data.cell.styles.fillColor = [254, 249, 195];
            data.cell.styles.textColor = [161, 98, 7];
          }
        }
      },
    });

    const pageCount = (doc as any).getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      (doc as any).setPage(i);
      doc.setFontSize(8);
      doc.setTextColor(150);
      doc.text(
        `AuditGraph - GRC Compliance Report | Page ${i} of ${pageCount}`,
        doc.internal.pageSize.width / 2,
        doc.internal.pageSize.height - 10,
        { align: 'center' }
      );
    }

    doc.save(`auditgraph-grc-compliance-report-${new Date().toISOString().split('T')[0]}.pdf`);
  }

  return (
    <div className="max-w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-5">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">All Identities</h2>
          <p className="text-sm text-gray-600">Multi-cloud identity inventory with full sorting</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-sm text-gray-600 font-medium">
            {loading ? 'Loading…' : `${filtered.length} of ${identities.length} identities`}
            {selectedIds.size > 0 && (
              <span className="ml-2 text-blue-600 font-semibold">
                ({selectedIds.size} selected)
              </span>
            )}
          </div>
          {!loading && filtered.length > 0 && (
            <div className="flex items-center gap-2">
              <button
                onClick={selectCompliance}
                className="inline-flex items-center gap-1 px-3 py-1.5 text-sm font-medium text-purple-700 bg-purple-50 border border-purple-200 rounded-lg hover:bg-purple-100 transition"
                title="Select identities relevant for HIPAA, PCI-DSS, SOC2 compliance audits"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                Select for GRC
              </button>
              {selectedIds.size > 0 && (
                <button
                  onClick={clearSelection}
                  className="inline-flex items-center gap-1 px-3 py-1.5 text-sm font-medium text-gray-600 bg-gray-50 border border-gray-200 rounded-lg hover:bg-gray-100 transition"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                  Clear
                </button>
              )}
              <div className="w-px h-6 bg-gray-300" />
              <button
                onClick={exportToCSV}
                className="inline-flex items-center gap-1 px-3 py-1.5 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition"
                title="Export to CSV"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                CSV
              </button>
              <button
                onClick={exportToPDF}
                className="inline-flex items-center gap-1 px-3 py-1.5 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 transition"
                title="Export PDF Report"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                </svg>
                PDF Report
              </button>
            </div>
          )}
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

      {/* Table - Cleaned up 9-column model */}
      <div className="bg-white border rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 border-b text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">
              <tr>
                <th className="px-3 py-3 w-10">
                  <input
                    type="checkbox"
                    checked={filtered.length > 0 && selectedIds.size === filtered.length}
                    onChange={selectAll}
                    className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500 cursor-pointer"
                    title="Select all visible identities"
                  />
                </th>
                <SortHeader label="Identity Name" field="display_name" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Category" field="identity_category" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Cloud" field="cloud" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Risk" field="risk_level" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Roles" field="role_count" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Permissions" field="api_permission_count" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Secrets / Expiry" field="credential_expiration" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Owner" field="owner_display_name" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Status" field="status" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {loading ? (
                <tr><td colSpan={10} className="px-4 py-8 text-center text-gray-500">Loading identities…</td></tr>
              ) : error ? (
                <tr><td colSpan={10} className="px-4 py-8 text-center text-red-600">{error}</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={10} className="px-4 py-8 text-center text-gray-500">No identities match your filters.</td></tr>
              ) : (
                filtered.map((i) => {
                  const totalRoles = (i.entra_role_count ?? 0) + (i.rbac_role_count ?? 0);
                  const totalPerms = (i.api_permission_count ?? 0) + (i.app_role_count ?? 0);

                  return (
                    <tr
                      key={i.identity_id}
                      className={`hover:bg-blue-50 cursor-pointer transition-colors ${selectedIds.has(i.identity_id) ? 'bg-blue-50' : ''}`}
                      onClick={() => openIdentity(i.identity_id)}
                    >
                      {/* Checkbox */}
                      <td className="px-3 py-3" onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={selectedIds.has(i.identity_id)}
                          onChange={() => toggleSelect(i.identity_id)}
                          className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500 cursor-pointer"
                        />
                      </td>

                      {/* Identity Name */}
                      <td className="px-3 py-3">
                        <div className="font-medium text-gray-900 truncate max-w-[220px]" title={i.display_name}>
                          {i.display_name}
                        </div>
                        <div className="text-xs text-gray-400 font-mono mt-0.5">{i.identity_id.substring(0, 8)}…</div>
                      </td>

                      {/* Category */}
                      <td className="px-3 py-3">
                        <CategoryBadge category={i.identity_category} />
                      </td>

                      {/* Cloud */}
                      <td className="px-3 py-3">
                        <CloudBadge cloud={i.cloud} />
                      </td>

                      {/* Risk */}
                      <td className="px-3 py-3">
                        <RiskBadge level={i.risk_level} score={i.risk_score} />
                      </td>

                      {/* Roles (combined Entra + RBAC) */}
                      <td className="px-3 py-3">
                        {totalRoles > 0 ? (
                          <div className="space-y-0.5">
                            {(i.entra_role_count ?? 0) > 0 && (
                              <div className="flex items-center gap-1 text-xs">
                                <RiskDot level={i.entra_max_risk} />
                                <span className="text-indigo-700 font-medium">{i.entra_role_count}</span>
                                <span className="text-gray-400">Entra</span>
                              </div>
                            )}
                            {(i.rbac_role_count ?? 0) > 0 && (
                              <div className="flex items-center gap-1 text-xs">
                                <RiskDot level={i.rbac_max_risk} />
                                <span className="text-blue-700 font-medium">{i.rbac_role_count}</span>
                                <span className="text-gray-400">RBAC</span>
                              </div>
                            )}
                          </div>
                        ) : (
                          <span className="text-gray-300 text-xs">—</span>
                        )}
                      </td>

                      {/* Permissions (combined API + App Roles) */}
                      <td className="px-3 py-3">
                        {totalPerms > 0 ? (
                          <div className="space-y-0.5">
                            {(i.api_permission_count ?? 0) > 0 && (
                              <div className="text-xs">
                                <span className="text-purple-700 font-medium">{i.api_permission_count}</span>
                                <span className="text-gray-400 ml-1">API</span>
                              </div>
                            )}
                            {(i.app_role_count ?? 0) > 0 && (
                              <div className="text-xs">
                                <span className="text-indigo-700 font-medium">{i.app_role_count}</span>
                                <span className="text-gray-400 ml-1">App</span>
                              </div>
                            )}
                          </div>
                        ) : (
                          <span className="text-gray-300 text-xs">—</span>
                        )}
                      </td>

                      {/* Secrets/Expiry */}
                      <td className="px-3 py-3">
                        {i.identity_category === 'human_user' || i.identity_category === 'guest' ? (
                          <span className="text-xs text-gray-300">N/A</span>
                        ) : (
                          <div className="text-xs">
                            <span className="text-gray-600">{i.credential_count ?? 0} secret(s)</span>
                            {i.credential_expiration && (
                              <div className="text-orange-600">{formatDate(i.credential_expiration)}</div>
                            )}
                          </div>
                        )}
                      </td>

                      {/* Owner */}
                      <td className="px-3 py-3">
                        {i.owner_display_name ? (
                          <span className="text-green-700 text-xs truncate max-w-[100px] block" title={i.owner_display_name}>
                            {i.owner_display_name}
                          </span>
                        ) : (
                          <span className="text-gray-300 text-xs">No owner</span>
                        )}
                      </td>

                      {/* Status */}
                      <td className="px-3 py-3">
                        <StatusBadge status={i.status} enabled={i.enabled} />
                      </td>
                    </tr>
                  );
                })
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
