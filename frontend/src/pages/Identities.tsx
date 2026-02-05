import React, { useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';

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

  // legacy and canonical
  identity_type?: string;
  identity_category?: IdentityCategory;
  identity_category_label?: string;

  risk_level?: RiskLevel;

  created_datetime?: string | null;
  activity_status?: string | null;

  credential_count?: number;
  next_expiry?: string | null;
  credential_risk?: string | null;
  credential_status?: string | null;
  credential_expiration?: string | null;

  role_count?: number;
}

const CATEGORY_OPTIONS: { value: IdentityCategory | 'all'; label: string }[] = [
  { value: 'all', label: 'All Categories' },
  { value: 'service_principal', label: 'Service Principal' },
  { value: 'managed_identity_system', label: 'System Assigned Identity' },
  { value: 'managed_identity_user', label: 'User Assigned Identity' },
  { value: 'human_user', label: 'Human User' },
  { value: 'guest', label: 'Guest' },
  { value: 'microsoft_internal', label: 'Microsoft Internal' },
  { value: 'unknown', label: 'Unknown' },
];

const RISK_OPTIONS: { value: RiskLevel | 'all'; label: string }[] = [
  { value: 'all', label: 'All Levels' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
  { value: 'unknown', label: 'Unknown' },
];

function safeLower(v: any) {
  return String(v ?? '').toLowerCase();
}

// Normalize identity_type coming from the API, which may vary across versions
// (e.g., "managed identity", "ManagedIdentity", etc.).
function normalizeIdentityType(raw?: any): string {
  const v = safeLower(raw).replace(/[\s-]+/g, '_').trim();
  if (!v) return '';

  // Canonical values
  if (v === 'service_principal' || v === 'serviceprincipal') return 'service_principal';
  if (v === 'managed_identity' || v === 'managedidentity') return 'managed_identity';
  if (v === 'user') return 'user';
  if (v === 'managed_identity_system') return 'managed_identity_system';
  if (v === 'managed_identity_user') return 'managed_identity_user';

  // Common variants
  if (v === 'service' || v === 'spn' || v.includes('service_principal')) return 'service_principal';
  if (v.includes('managed_identity') || v.includes('managedidentity') || v.includes('managed_identity')) return 'managed_identity';
  if (v.includes('managed_identity_system') || v.includes('system_assigned')) return 'managed_identity_system';
  if (v.includes('managed_identity_user') || v.includes('user_assigned')) return 'managed_identity_user';

  return v;
}

// Backend may send identity_category as a label (e.g., "User Assigned Identity")
// Normalize common variants to canonical UI keys.
function normalizeCategoryFromBackend(raw?: any): IdentityCategory | undefined {
  const v = safeLower(raw).trim();
  if (!v) return undefined;

  // Already canonical?
  if (CATEGORY_OPTIONS.some(o => o.value === (v as any))) return v as IdentityCategory;

  // USER VARIANTS
  if (v === 'user' || v === 'users') return 'human_user';
  if (v === 'human user' || v === 'human_user') return 'human_user';
  
  // GUEST VARIANTS
  if (v === 'guest' || v === 'guest user') return 'guest';

  // USER ASSIGNED MANAGED IDENTITY VARIANTS
  if (
    v === 'user assigned identity' ||
    v === 'managed identity (user)' ||
    v === 'managed identity (user assigned)' ||
    v.includes('user assigned') ||
    v.includes('user-assigned') ||
    v.includes('userassigned')
  ) return 'managed_identity_user';

  // SYSTEM ASSIGNED MANAGED IDENTITY VARIANTS
  if (
    v === 'system assigned identity' ||
    v === 'managed identity (system)' ||
    v === 'managed identity (system assigned)' ||
    v.includes('system assigned') ||
    v.includes('system-assigned') ||
    v.includes('systemassigned')
  ) return 'managed_identity_system';

  // MICROSOFT INTERNAL VARIANTS
  if (v === 'microsoft internal' || v === 'microsoft-internal' || v === 'microsoft_internal') return 'microsoft_internal';

  // SERVICE PRINCIPAL VARIANTS
  if (v === 'service principal' || v === 'service_principal' || v === 'serviceprincipal') return 'service_principal';

  return undefined;
}

function looksLikeMicrosoftFirstParty(identityId?: string, displayName?: string) {
  const id = safeLower(identityId).trim();
  const name = safeLower(displayName).trim();

  if (!id && !name) return false;

  // Guardrails: don't classify our own/custom SPNs as Microsoft internal
  // unless they explicitly contain strong Microsoft tokens.
  const customPrefixes = ['spn-', 'app-', 'svc-', 'auditgraph', 'nexgenix', 'lantern'];
  const strongMsTokens = ['microsoft', 'azure', 'entra', 'aad', 'office', 'sharepoint', 'exchange', 'teams', 'intune', 'defender', 'sentinel'];
  if (customPrefixes.some(p => name.startsWith(p) || name.includes(p))) {
    if (!strongMsTokens.some(t => name.includes(t))) return false;
  }

  // Well-known Microsoft appId patterns (rare but keep)
  if (id.endsWith('000000000000')) return true;
  if (id.startsWith('00000001-0000-0000-c000-000000000000')) return true;
  if (id.startsWith('00000002-0000-0000-c000-000000000000')) return true;
  if (id.startsWith('00000003-0000-0000-c000-000000000000')) return true;
  if (id.startsWith('00000004-0000-0ff1-ce00-000000000000')) return true;
  if (id.startsWith('00000005-0000-0000-c000-000000000000')) return true;
  if (id.startsWith('00000006-0000-0ff1-ce00-000000000000')) return true;
  if (id.startsWith('00000007-0000-0000-c000-000000000000')) return true;
  if (id.startsWith('00000007-0000-0ff1-ce00-000000000000')) return true;
  if (id.startsWith('00000009-0000-0000-c000-000000000000')) return true;
  if (id.startsWith('0000000a-0000-0000-c000-000000000000')) return true;
  if (id.startsWith('0000000c-0000-0000-c000-000000000000')) return true;
  if (id.startsWith('00000012-0000-0000-c000-000000000000')) return true;

  // Name-based heuristics (more conservative; avoid generic tokens that cause false positives)
  const tokens = [
    'microsoft',
    'azure',
    'entra',
    'active directory',
    'azure ad',
    'aad',
    'ms graph',
    'graph',
    'office',
    'm365',
    'o365',
    'sharepoint',
    'exchange',
    'teams',
    'intune',
    'defender',
    'sentinel',
    'azure monitor',
    'monitor',
    'log analytics',
    'key vault',
    'cosmosdb',
    'storage',
    'windows',
    'dynamics',
    'powerbi',
    'power bi',
    'bing',
    'billing rp',
    'azure advisor',
    'advisor',
    'azure ad notification',
    'notification',
    'microsoft entra',
  ];

  if (tokens.some(t => name.includes(t))) return true;

  // Conservative prefixes
  if (name.startsWith('microsoft ') || name.startsWith('azure ')) return true;

  return false;
}



function deriveCategoryKey(row: Partial<IdentityRow> & { [k: string]: any }): IdentityCategory {
  const t = normalizeIdentityType(row.identity_type);
  const name = row.display_name || '';
  const id = row.identity_id || '';

  // 1) Backend-provided key or label
  const providedKey = row.identity_category_key ?? row.identity_category;
  const normalized = normalizeCategoryFromBackend(providedKey);
  
  // Special case: If backend explicitly says microsoft_internal, trust it
  if (normalized === 'microsoft_internal') {
    return 'microsoft_internal';
  }
  
  // For managed identities from backend, trust them (but verify with additional checks)
  if (normalized === 'managed_identity_system') return 'managed_identity_system';
  if (normalized === 'managed_identity_user') return 'managed_identity_user';
  
  // For human users and guests, trust backend
  if (normalized === 'human_user') return 'human_user';
  if (normalized === 'guest') return 'guest';
  
  // For service_principal from backend, DON'T trust it yet - need to check if it's Microsoft Internal

  // 2) Derive by identity_type
  if (t === 'user') {
    const n = safeLower(name);
    if (n.includes('#ext#') || n.includes('guest')) return 'guest';
    return 'human_user';
  }

  // Managed identities (new storage)
  if (t === 'managed_identity') {
    // If backend gave us a label in another field, attempt to infer system vs user
    const hint = normalizeCategoryFromBackend((row as any).identity_category_label);
    if (hint === 'managed_identity_system' || hint === 'managed_identity_user') return hint;

    // System MI commonly uses this name
    if (safeLower(name) === 'managed service identity') return 'managed_identity_system';

    // Check for user-assigned patterns in name
    const n = safeLower(name);
    if (n.includes('user assigned') || n.includes('uamtest') || n.includes('uam')) return 'managed_identity_user';

    // Default (most MI identities in Entra inventory are user-assigned)
    return 'managed_identity_user';
  }

  if (t === 'managed_identity_system') return 'managed_identity_system';
  if (t === 'managed_identity_user') return 'managed_identity_user';

  // 3) Service principals - CRITICAL SECTION
  // This is where we separate customer SPNs from Microsoft Internal SPNs
  
  if (t === 'service_principal' || normalized === 'service_principal') {
    // Special case: "Managed Service Identity" is actually a system-assigned MI, not an SPN
    if (safeLower(name) === 'managed service identity') return 'managed_identity_system';

    // CRITICAL: Check if this is Microsoft first-party
    // If it is, it should go to microsoft_internal, NOT service_principal
    if (looksLikeMicrosoftFirstParty(id, name)) {
      return 'microsoft_internal';
    }

    // If we get here, it's a genuine customer service principal
    return 'service_principal';
  }

  return 'unknown';
}

function categoryLabel(cat?: IdentityCategory): string {
  const match = CATEGORY_OPTIONS.find(o => o.value === cat);
  return match?.label || 'Unknown';
}

function riskBadge(r?: RiskLevel) {
  const risk = safeLower(r);
  const styles: Record<string, string> = {
    critical: 'bg-red-100 text-red-800',
    high: 'bg-orange-100 text-orange-800',
    medium: 'bg-yellow-100 text-yellow-800',
    low: 'bg-green-100 text-green-800',
    info: 'bg-blue-100 text-blue-800',
    unknown: 'bg-gray-100 text-gray-600',
  };
  const cls = styles[risk] || styles.unknown;
  return <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium uppercase ${cls}`}>{risk || 'unknown'}</span>;
}

function formatDate(d?: string | null) {
  if (!d) return '—';
  try {
    return new Date(d).toLocaleString();
  } catch {
    return d;
  }
}

export default function IdentitiesPage() {
  const [identities, setIdentities] = useState<IdentityRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState<RiskLevel | 'all'>('all');
  const [categoryFilter, setCategoryFilter] = useState<IdentityCategory | 'all'>('all');

  const [sortField, setSortField] = useState<'display_name' | 'identity_category' | 'risk_level' | 'role_count'>('display_name');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');

  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const catParam = params.get('category');
    if (catParam) {
      const found = CATEGORY_OPTIONS.find(o => o.value === catParam);
      if (found && found.value !== 'all') {
        setCategoryFilter(found.value as any);
      }
    }
  }, [location.search]);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const resp = await fetch('http://localhost:5001/api/identities');
        if (!resp.ok) throw new Error('Failed to fetch identities');
        const data = await resp.json();

        const rows: IdentityRow[] = (data.identities || []).map((raw: any, idx: number) => {
          const derived = deriveCategoryKey(raw);
          
          // Log ALL service principals and microsoft_internal to debug duplication
          const isSPN = safeLower(raw.identity_type) === 'service_principal' || safeLower(raw.identity_category).includes('service principal');
          const isMSInternal = safeLower(raw.identity_category).includes('microsoft') || safeLower(raw.display_name).includes('azure') || safeLower(raw.display_name).includes('microsoft');
          
          if (isSPN || isMSInternal) {
            console.log(`\n[${derived.toUpperCase()}] ${raw.display_name}`);
            console.log('  identity_type:', raw.identity_type);
            console.log('  identity_category:', raw.identity_category);
            console.log('  normalized category:', normalizeCategoryFromBackend(raw.identity_category));
            console.log('  Microsoft 1P check:', looksLikeMicrosoftFirstParty(raw.identity_id, raw.display_name));
            console.log('  → FINAL:', derived);
          }
          
          return {
            identity_id: raw.identity_id || raw.id || '',
            display_name: raw.display_name || raw.name || '',
            identity_type: raw.identity_type || raw.type,
            identity_category: derived,
            identity_category_label: categoryLabel(derived),
            risk_level: safeLower(raw.risk_level || raw.risk || 'unknown') as RiskLevel,
            created_datetime: raw.created_datetime || raw.created || null,
            activity_status: raw.activity_status || raw.status || null,
            credential_count: raw.credential_count ?? 0,
            next_expiry: raw.next_expiry || raw.credential_expiration || null,
            role_count: raw.role_count ?? 0,
          };
        });
        
        // Summary statistics
        const categoryCounts = rows.reduce((acc, r) => {
          acc[r.identity_category || 'unknown'] = (acc[r.identity_category || 'unknown'] || 0) + 1;
          return acc;
        }, {} as Record<string, number>);
        console.log('\n========== CATEGORY SUMMARY ==========');
        console.log(categoryCounts);
        console.log('======================================\n');

        if (!cancelled) setIdentities(rows);
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load identities');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  const filtered = useMemo(() => {
    let result = [...identities];

    const s = safeLower(search);
    if (s) {
      result = result.filter(i => safeLower(i.display_name).includes(s) || safeLower(i.identity_id).includes(s));
    }

    if (riskFilter !== 'all') {
      const rf = safeLower(riskFilter);
      result = result.filter(i => safeLower(i.risk_level) === rf);
    }

    if (categoryFilter !== 'all') {
      const cf = safeLower(categoryFilter);
      console.log(`\n🔍 FILTERING by category: "${categoryFilter}" (normalized: "${cf}")`);
      console.log(`Before filter: ${result.length} identities`);
      
      result = result.filter(i => {
        const iCat = safeLower(i.identity_category);
        const matches = iCat === cf;
        return matches;
      });
      
      console.log(`After filter: ${result.length} identities`);
      
      // Show first 5 results
      console.log('First 5 filtered results:');
      result.slice(0, 5).forEach(r => {
        console.log(`  - ${r.display_name} [${r.identity_category}]`);
      });
    }

    result.sort((a, b) => {
      let aValue: any;
      let bValue: any;

      switch (sortField) {
        case 'risk_level': {
          const riskOrder: Record<string, number> = {
            critical: 6,
            high: 5,
            medium: 4,
            low: 3,
            info: 2,
            unknown: 1,
          };
          aValue = riskOrder[safeLower(a.risk_level)] || 0;
          bValue = riskOrder[safeLower(b.risk_level)] || 0;
          break;
        }
        case 'role_count':
          aValue = a.role_count ?? 0;
          bValue = b.role_count ?? 0;
          break;
        case 'identity_category':
          aValue = safeLower(a.identity_category);
          bValue = safeLower(b.identity_category);
          break;
        case 'display_name':
        default:
          aValue = safeLower(a.display_name);
          bValue = safeLower(b.display_name);
      }

      if (aValue < bValue) return sortDir === 'asc' ? -1 : 1;
      if (aValue > bValue) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });

    return result;
  }, [identities, search, riskFilter, categoryFilter, sortField, sortDir]);

  function toggleSort(field: typeof sortField) {
    if (field === sortField) {
      setSortDir(prev => (prev === 'asc' ? 'desc' : 'asc'));
      return;
    }
    setSortField(field);
    setSortDir(field === 'risk_level' ? 'desc' : 'asc');
  }

  function clearAll() {
    setSearch('');
    setRiskFilter('all');
    setCategoryFilter('all');
  }

  function openIdentity(id: string) {
    navigate(`/identities/${encodeURIComponent(id)}`);
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-5">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">All Identities</h2>
          <p className="text-sm text-gray-600">Filter by identity category and risk to focus your review.</p>
        </div>
        <div className="text-sm text-gray-600">
          {loading ? 'Loading…' : `${filtered.length} of ${identities.length} identities`}
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white border rounded-2xl p-4 mb-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <label className="block text-xs font-semibold text-gray-700 mb-1">Search</label>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search identities…"
              className="w-full border rounded-lg px-3 py-2 text-sm"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-gray-700 mb-1">Risk Level</label>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value as any)}
              className="w-full border rounded-lg px-3 py-2 text-sm"
            >
              {RISK_OPTIONS.map(o => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-gray-700 mb-1">Identity Category</label>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value as any)}
              className="w-full border rounded-lg px-3 py-2 text-sm"
            >
              {CATEGORY_OPTIONS.map(o => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
        </div>

        <div className="flex items-center justify-between mt-4">
          <div className="text-xs text-gray-500">
            Tip: "Service principals" are **not** managed identities. Use the category filter to separate them.
          </div>
          <button onClick={clearAll} className="text-xs text-blue-600 hover:underline">
            Clear all
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white border rounded-2xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead className="bg-gray-50 border-b">
              <tr className="text-left text-xs font-semibold text-gray-600">
                <th className="px-4 py-3 cursor-pointer select-none" onClick={() => toggleSort('display_name')}>
                  Identity Name {sortField === 'display_name' ? (sortDir === 'asc' ? '▲' : '▼') : ''}
                </th>
                <th className="px-4 py-3 cursor-pointer select-none" onClick={() => toggleSort('identity_category')}>
                  Category {sortField === 'identity_category' ? (sortDir === 'asc' ? '▲' : '▼') : ''}
                </th>
                <th className="px-4 py-3 cursor-pointer select-none" onClick={() => toggleSort('risk_level')}>
                  Risk {sortField === 'risk_level' ? (sortDir === 'asc' ? '▲' : '▼') : ''}
                </th>
                <th className="px-4 py-3">Roles</th>
                <th className="px-4 py-3">Credentials</th>
                <th className="px-4 py-3">Created</th>
              </tr>
            </thead>

            <tbody className="divide-y">
              {loading ? (
                <tr><td className="px-4 py-6 text-sm text-gray-600" colSpan={6}>Loading identities…</td></tr>
              ) : error ? (
                <tr><td className="px-4 py-6 text-sm text-red-600" colSpan={6}>{error}</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td className="px-4 py-6 text-sm text-gray-600" colSpan={6}>No identities match your filters.</td></tr>
              ) : (
                filtered.map((i) => (
                  <tr
                    key={i.identity_id}
                    className="hover:bg-gray-50 cursor-pointer"
                    onClick={() => openIdentity(i.identity_id)}
                  >
                    <td className="px-4 py-3">
                      <div className="text-sm font-medium text-gray-900">{i.display_name}</div>
                      <div className="text-xs text-gray-500">{i.identity_id}</div>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700">
                      {categoryLabel(i.identity_category)}
                    </td>
                    <td className="px-4 py-3">
                      {riskBadge(i.risk_level)}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700">
                      {i.role_count ?? 0}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700">
                      {i.credential_count ?? 0}
                      {i.next_expiry ? (
                        <div className="text-xs text-gray-500">Next: {formatDate(i.next_expiry)}</div>
                      ) : (
                        <div className="text-xs text-gray-400">No expiry</div>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700">{formatDate(i.created_datetime)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
