import React, { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';

type IdentityCategory =
  | 'service_principal'
  | 'managed_identity_system'
  | 'managed_identity_user'
  | 'human_user'
  | 'guest'
  | 'microsoft_internal'
  | 'unknown';

interface Owner {
  owner_object_id: string;
  owner_display_name?: string;
  owner_upn?: string;
  owner_type?: string;
  is_primary_owner?: boolean;
}

interface IdentityDetailsResponse {
  run_id: number;
  identity: {
    identity_id: string;
    display_name: string;
    identity_type?: string;
    identity_category?: IdentityCategory;
    risk_level?: RiskLevel;
    risk_score?: number;  // NEW: Points-based risk score
    risk_reasons?: string[];

    credential_status?: string;
    credential_expiration?: string | null;

    created_datetime?: string | null;
    activity_status?: string | null;
    last_sign_in?: string | null;

    enabled?: boolean;
    is_microsoft_system?: boolean;

    object_id?: string | null;
    app_id?: string | null;

    tags?: any;

    // NEW: Multi-cloud fields
    cloud?: string;
    normalized_identity_type?: string;
    principal_id?: string;
    tenant_or_org_id?: string;
    owner_display_name?: string | null;
    owner_count?: number;
    api_permission_count?: number;
    app_role_count?: number;
  };
  roles: any[];
  graph_permissions: any[];
  app_roles: any[];
  owners: Owner[];  // NEW: Ownership tracking
}

function safeLower(v: any) {
  return String(v ?? '').toLowerCase();
}

// Backend may send identity_category as a label. Normalize common variants.
function normalizeCategoryFromBackend(raw?: any): string | undefined {
  const v = safeLower(raw).trim();
  if (!v) return undefined;

  // Canonical keys
  const keys = [
    'service_principal',
    'managed_identity_system',
    'managed_identity_user',
    'human_user',
    'guest',
    'microsoft_internal',
    'unknown',
  ];
  if (keys.includes(v)) return v;

  if (
    v === 'user assigned identity' ||
    v === 'managed identity (user assigned)' ||
    v.includes('user assigned') ||
    v.includes('user-assigned') ||
    v.includes('userassigned')
  ) return 'managed_identity_user';

  if (
    v === 'system assigned identity' ||
    v === 'managed identity (system assigned)' ||
    v.includes('system assigned') ||
    v.includes('system-assigned') ||
    v.includes('systemassigned')
  ) return 'managed_identity_system';

  if (v === 'microsoft internal' || v === 'microsoft-internal' || v === 'microsoft_internal') return 'microsoft_internal';
  if (v === 'human user' || v === 'human_user' || v === 'user') return 'human_user';
  if (v === 'guest') return 'guest';
  if (v === 'service principal' || v === 'service_principal') return 'service_principal';

  return undefined;
}

function formatDate(iso?: string | null) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function riskBadge(level?: string) {
  const v = safeLower(level);
  const base = 'px-2 py-1 rounded-full text-xs font-semibold inline-flex items-center';
  if (v === 'critical') return <span className={`${base} bg-red-100 text-red-700`}>CRITICAL</span>;
  if (v === 'high') return <span className={`${base} bg-orange-100 text-orange-700`}>HIGH</span>;
  if (v === 'medium') return <span className={`${base} bg-yellow-100 text-yellow-700`}>MEDIUM</span>;
  if (v === 'low') return <span className={`${base} bg-green-100 text-green-700`}>LOW</span>;
  if (v === 'info') return <span className={`${base} bg-blue-100 text-blue-700`}>INFO</span>;
  return <span className={`${base} bg-gray-100 text-gray-700`}>UNKNOWN</span>;
}

function categoryLabel(catRaw?: any, typeRaw?: any) {
  const cat = normalizeCategoryFromBackend(catRaw) || safeLower(catRaw);
  const t = safeLower(typeRaw);

  // Prefer normalized category when available
  const key = cat || t;

  switch (key) {
    case 'service_principal': return 'Service Principal';
    case 'managed_identity_system': return 'System Assigned Identity';
    case 'managed_identity_user': return 'User Assigned Identity';
    case 'managed_identity': return 'User Assigned Identity';
    case 'human_user': return 'Human User';
    case 'guest': return 'Guest';
    case 'microsoft_internal': return 'Microsoft Internal';
    default: return 'Unknown';
  }
}


export default function IdentityDetail() {
  const { id } = useParams<{ id: string }>();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<IdentityDetailsResponse | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(`/api/identities/${encodeURIComponent(id || '')}`);
        if (!res.ok) throw new Error(`API error: ${res.status}`);
        const json = await res.json();
        if (!cancelled) setData(json);
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load identity details');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    if (id) load();
    return () => {
      cancelled = true;
    };
  }, [id]);

  const identity = data?.identity;

  const groupedRoles = useMemo(() => {
    const roles = data?.roles || [];
    const azure = roles.filter((r: any) => safeLower(r.role_type) === 'azure');
    const entra = roles.filter((r: any) => safeLower(r.role_type) === 'entra');
    return { azure, entra };
  }, [data]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <div className="text-sm text-gray-500">
            <Link to="/identities" className="text-blue-600 hover:underline">← Back to Identities</Link>
          </div>
          <h2 className="text-2xl font-bold text-gray-900 mt-1">Identity Details</h2>
        </div>
      </div>

      {loading ? (
        <div className="bg-white border rounded-2xl p-6 text-gray-600">Loading…</div>
      ) : error ? (
        <div className="bg-white border rounded-2xl p-6 text-red-600">{error}</div>
      ) : !identity ? (
        <div className="bg-white border rounded-2xl p-6 text-gray-600">Identity not found.</div>
      ) : (
        <>
          {/* Header card */}
          <div className="bg-white border rounded-2xl p-6 mb-4">
            <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4">
              <div>
                <div className="text-xl font-bold text-gray-900">{identity.display_name}</div>
                <div className="text-sm text-gray-500 mt-1 break-all">{identity.identity_id}</div>

                <div className="flex flex-wrap items-center gap-2 mt-3">
                  {riskBadge(identity.risk_level)}
                  {identity.risk_score !== undefined && (
                    <span className="px-2 py-1 rounded-full text-xs font-semibold bg-purple-100 text-purple-700">
                      {identity.risk_score} pts
                    </span>
                  )}
                  <span className="px-2 py-1 rounded-full text-xs font-semibold bg-blue-100 text-blue-700">
                    {identity.cloud || 'azure'}
                  </span>
                  <span className="px-2 py-1 rounded-full text-xs font-semibold bg-gray-100 text-gray-700">
                    {categoryLabel(identity.identity_category)}
                  </span>
                  {identity.enabled === false ? (
                    <span className="px-2 py-1 rounded-full text-xs font-semibold bg-red-50 text-red-700">
                      Disabled
                    </span>
                  ) : null}
                  {identity.is_microsoft_system ? (
                    <span className="px-2 py-1 rounded-full text-xs font-semibold bg-blue-50 text-blue-700">
                      Microsoft Internal
                    </span>
                  ) : null}
                </div>
              </div>

              <div className="text-sm text-gray-700 space-y-1">
                <div><span className="font-semibold">Created:</span> {formatDate(identity.created_datetime)}</div>
                <div><span className="font-semibold">Last Sign-in:</span> {formatDate(identity.last_sign_in)}</div>
                <div><span className="font-semibold">Activity:</span> {identity.activity_status || 'unknown'}</div>
                <div><span className="font-semibold">Credential:</span> {identity.credential_status || 'Unknown'}</div>
                <div><span className="font-semibold">Owner:</span> {identity.owner_display_name || <span className="text-gray-400">No owner</span>}</div>
                <div><span className="font-semibold">API Permissions:</span> {identity.api_permission_count ?? 0}</div>
                <div><span className="font-semibold">App Roles:</span> {identity.app_role_count ?? 0}</div>
              </div>
            </div>

            {/* Risk reasons */}
            <div className="mt-5">
              <div className="text-sm font-semibold text-gray-900 mb-2">Risk Reasons</div>
              {identity.risk_reasons && identity.risk_reasons.length > 0 ? (
                <ul className="list-disc list-inside text-sm text-gray-700 space-y-1">
                  {identity.risk_reasons.map((r, idx) => (
                    <li key={idx}>{r}</li>
                  ))}
                </ul>
              ) : (
                <div className="text-sm text-gray-500">No risk reasons recorded.</div>
              )}
            </div>
          </div>

          {/* Roles */}
          <div className="bg-white border rounded-2xl p-6 mb-4">
            <div className="text-lg font-semibold text-gray-900 mb-3">Roles</div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="border rounded-xl p-4">
                <div className="font-semibold text-gray-900 mb-2">Azure RBAC</div>
                {groupedRoles.azure.length === 0 ? (
                  <div className="text-sm text-gray-500">No Azure RBAC roles.</div>
                ) : (
                  <ul className="text-sm text-gray-700 space-y-2">
                    {groupedRoles.azure.map((r: any, idx: number) => (
                      <li key={idx} className="border rounded-lg p-3">
                        <div className="flex items-center justify-between gap-2">
                          <div className="font-semibold">{r.role_name}</div>
                          {riskBadge(r.risk_level)}
                        </div>
                        <div className="text-xs text-gray-500 mt-1 break-all">{r.scope}</div>
                        {r.why_critical ? (
                          <div className="text-xs text-gray-700 mt-2">{r.why_critical}</div>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <div className="border rounded-xl p-4">
                <div className="font-semibold text-gray-900 mb-2">Entra Directory Roles</div>
                {groupedRoles.entra.length === 0 ? (
                  <div className="text-sm text-gray-500">No Entra roles.</div>
                ) : (
                  <ul className="text-sm text-gray-700 space-y-2">
                    {groupedRoles.entra.map((r: any, idx: number) => (
                      <li key={idx} className="border rounded-lg p-3">
                        <div className="flex items-center justify-between gap-2">
                          <div className="font-semibold">{r.role_name}</div>
                          {riskBadge(r.risk_level)}
                        </div>
                        <div className="text-xs text-gray-500 mt-1 break-all">{r.scope}</div>
                        {r.why_critical ? (
                          <div className="text-xs text-gray-700 mt-2">{r.why_critical}</div>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </div>

          {/* Graph Permissions */}
          <div className="bg-white border rounded-2xl p-6 mb-4">
            <div className="text-lg font-semibold text-gray-900 mb-3">Microsoft Graph API Permissions</div>
            {(data?.graph_permissions || []).length === 0 ? (
              <div className="text-sm text-gray-500">No Graph permissions discovered.</div>
            ) : (
              <div className="space-y-2">
                {data!.graph_permissions.map((p: any, idx: number) => (
                  <div key={idx} className="border rounded-lg p-3">
                    <div className="flex items-center justify-between gap-2">
                      <div className="font-semibold text-gray-900">{p.permission_name}</div>
                      {riskBadge(p.risk_level)}
                    </div>
                    {p.permission_description ? (
                      <div className="text-xs text-gray-600 mt-1">{p.permission_description}</div>
                    ) : null}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* App Roles */}
          <div className="bg-white border rounded-2xl p-6 mb-4">
            <div className="text-lg font-semibold text-gray-900 mb-3">Application Role Assignments</div>
            {(data?.app_roles || []).length === 0 ? (
              <div className="text-sm text-gray-500">No custom app role assignments discovered.</div>
            ) : (
              <div className="space-y-2">
                {data!.app_roles.map((r: any, idx: number) => (
                  <div key={idx} className="border rounded-lg p-3">
                    <div className="flex items-center justify-between gap-2">
                      <div className="font-semibold text-gray-900">{r.resource_display_name || 'App'}</div>
                      {riskBadge(r.risk_level)}
                    </div>
                    <div className="text-xs text-gray-500 mt-1 break-all">{r.resource_id}</div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Owners (Accountability) */}
          <div className="bg-white border rounded-2xl p-6">
            <div className="text-lg font-semibold text-gray-900 mb-3">Ownership / Accountability</div>
            {(data?.owners || []).length === 0 ? (
              <div className="text-sm text-gray-500">No owners discovered for this identity.</div>
            ) : (
              <div className="space-y-2">
                {data!.owners.map((o: Owner, idx: number) => (
                  <div key={idx} className="border rounded-lg p-3">
                    <div className="flex items-center justify-between gap-2">
                      <div className="font-semibold text-gray-900">
                        {o.owner_display_name || o.owner_upn || o.owner_object_id}
                      </div>
                      {o.is_primary_owner && (
                        <span className="px-2 py-1 rounded-full text-xs font-semibold bg-green-100 text-green-700">
                          Primary
                        </span>
                      )}
                    </div>
                    {o.owner_upn && (
                      <div className="text-xs text-gray-500 mt-1">{o.owner_upn}</div>
                    )}
                    <div className="text-xs text-gray-400 mt-1">Type: {o.owner_type || 'user'}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
