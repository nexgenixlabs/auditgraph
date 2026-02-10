import React, { useEffect, useMemo, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  type IdentityCategory, type RiskLevel,
  RISK_BADGE, RISK_ORDER, CLOUD_BADGE, DORMANT_LABELS,
  safeLower, normalizeCategoryFromBackend, getCategoryLabel,
  getDormantStatus as getDormantStatusFromActivity,
} from '../constants/metrics';

// ── Types (copied from IdentityDetail.tsx) ──────────────────────

interface Owner {
  owner_object_id: string;
  owner_display_name?: string;
  owner_upn?: string;
  owner_type?: string;
  is_primary_owner?: boolean;
}

interface TrendData {
  previous_risk_level?: string | null;
  previous_risk_score?: number | null;
  risk_direction?: 'worsened' | 'improved' | 'unchanged' | 'new';
  is_new?: boolean;
}

interface IdentityDetailsResponse {
  run_id: number;
  identity: {
    identity_id: string;
    display_name: string;
    identity_type?: string;
    identity_category?: IdentityCategory;
    risk_level?: RiskLevel;
    risk_score?: number;
    risk_reasons?: string[];
    credential_status?: string;
    credential_count?: number;
    credential_expiration?: string | null;
    created_datetime?: string | null;
    activity_status?: string | null;
    last_sign_in?: string | null;
    last_seen_auth?: string | null;
    enabled?: boolean;
    cloud?: string;
    owner_display_name?: string | null;
    owner_count?: number;
    api_permission_count?: number;
    app_role_count?: number;
    ca_coverage_status?: string | null;
    ca_mfa_enforced?: boolean;
  };
  roles: any[];
  graph_permissions: any[];
  app_roles: any[];
  owners: Owner[];
  trend?: TrendData | null;
}

// ── Diff helpers ────────────────────────────────────────────────

type DiffResult = 'better' | 'worse' | 'equal';

function compareRiskLevels(a?: string, b?: string): DiffResult {
  const av = RISK_ORDER[safeLower(a)] ?? 0;
  const bv = RISK_ORDER[safeLower(b)] ?? 0;
  if (av < bv) return 'better';
  if (av > bv) return 'worse';
  return 'equal';
}

function diffBorder(result: DiffResult): string {
  if (result === 'better') return 'border-green-300';
  if (result === 'worse') return 'border-red-300';
  return 'border-gray-200';
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function diffCellBg(result: DiffResult): string {
  if (result === 'better') return 'bg-green-50';
  if (result === 'worse') return 'bg-red-50';
  return 'bg-gray-50';
}

function roleKey(r: any): string {
  return `${r.role_name || ''}||${safeLower(r.role_type)}||${r.scope || ''}`;
}

function credentialCountdown(expiration?: string | null): string {
  if (!expiration) return 'N/A';
  const diff = new Date(expiration).getTime() - Date.now();
  if (diff < 0) return 'Expired';
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  if (days === 0) return 'Today';
  if (days === 1) return '1 day';
  return `${days} days`;
}

const CRED_STATUS_COLORS: Record<string, string> = {
  expired: 'text-red-700 bg-red-50',
  expiring_soon: 'text-orange-700 bg-orange-50',
  valid: 'text-green-700 bg-green-50',
  unknown: 'text-gray-600 bg-gray-100',
};

const ROLE_TYPE_BADGE: Record<string, string> = {
  entra: 'bg-purple-100 text-purple-700',
  rbac: 'bg-blue-100 text-blue-700',
  app: 'bg-teal-100 text-teal-700',
};

// ── Collapsible section ─────────────────────────────────────────

function CompareSection({ title, defaultOpen = true, count, children }: {
  title: string;
  defaultOpen?: boolean;
  count?: string;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-5 py-3 bg-gray-50 hover:bg-gray-100 transition text-left"
      >
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold text-gray-900">{title}</span>
          {count && <span className="text-xs text-gray-400">{count}</span>}
        </div>
        <svg className={`w-4 h-4 text-gray-500 transition-transform ${open ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && <div className="p-5">{children}</div>}
    </div>
  );
}

// ── Role/Permission pill ────────────────────────────────────────

function RolePill({ role }: { role: any }) {
  const typeBadge = ROLE_TYPE_BADGE[safeLower(role.role_type)] || 'bg-gray-100 text-gray-600';
  const riskBadge = RISK_BADGE[safeLower(role.risk_level)] || 'bg-gray-100 text-gray-600';
  return (
    <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white border text-xs">
      <span className="font-medium text-gray-900 truncate max-w-[200px]">{role.role_name}</span>
      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${typeBadge}`}>{safeLower(role.role_type) || '?'}</span>
      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${riskBadge}`}>{safeLower(role.risk_level) || '?'}</span>
      {role.scope && <span className="text-[10px] text-gray-400 truncate max-w-[150px]" title={role.scope}>{role.scope}</span>}
    </div>
  );
}

function PermPill({ perm }: { perm: any }) {
  const riskBadge = RISK_BADGE[safeLower(perm.risk_level)] || 'bg-gray-100 text-gray-600';
  return (
    <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white border text-xs">
      <span className="font-medium text-gray-900 truncate max-w-[250px]">{perm.permission_name || perm.role_name}</span>
      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${riskBadge}`}>{safeLower(perm.risk_level) || '?'}</span>
    </div>
  );
}

// ── Main Component ──────────────────────────────────────────────

export default function IdentityComparison() {
  const location = useLocation();

  const [idA, idB] = useMemo(() => {
    const params = new URLSearchParams(location.search);
    const idsParam = params.get('ids') || '';
    const parts = idsParam.split(',').map(s => decodeURIComponent(s.trim())).filter(Boolean);
    return [parts[0] || '', parts[1] || ''];
  }, [location.search]);

  const [dataA, setDataA] = useState<IdentityDetailsResponse | null>(null);
  const [dataB, setDataB] = useState<IdentityDetailsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [swapped, setSwapped] = useState(false);

  useEffect(() => {
    let cancelled = false;
    if (!idA || !idB) {
      setError('Two identity IDs required for comparison');
      setLoading(false);
      return;
    }

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const [resA, resB] = await Promise.all([
          fetch(`/api/identities/${encodeURIComponent(idA)}`),
          fetch(`/api/identities/${encodeURIComponent(idB)}`),
        ]);
        if (!resA.ok) throw new Error(`Failed to fetch identity A: ${resA.status}`);
        if (!resB.ok) throw new Error(`Failed to fetch identity B: ${resB.status}`);
        const [jsonA, jsonB] = await Promise.all([resA.json(), resB.json()]);
        if (!cancelled) { setDataA(jsonA); setDataB(jsonB); }
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load comparison data');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [idA, idB]);

  const left = swapped ? dataB : dataA;
  const right = swapped ? dataA : dataB;

  // ── Role diff ──────────────────────────────────────────────
  const roleDiff = useMemo(() => {
    if (!left || !right) return { common: [] as any[], onlyLeft: [] as any[], onlyRight: [] as any[] };
    const leftRoles = left.roles || [];
    const rightRoles = right.roles || [];
    const leftKeys = new Set(leftRoles.map(roleKey));
    const rightKeys = new Set(rightRoles.map(roleKey));
    return {
      common: leftRoles.filter(r => rightKeys.has(roleKey(r))),
      onlyLeft: leftRoles.filter(r => !rightKeys.has(roleKey(r))),
      onlyRight: rightRoles.filter(r => !leftKeys.has(roleKey(r))),
    };
  }, [left, right]);

  // ── Permission diff ────────────────────────────────────────
  const permDiff = useMemo(() => {
    if (!left || !right) return { common: [] as any[], onlyLeft: [] as any[], onlyRight: [] as any[] };
    const leftPerms = [...(left.graph_permissions || []), ...(left.app_roles || [])];
    const rightPerms = [...(right.graph_permissions || []), ...(right.app_roles || [])];
    const keyFn = (p: any) => p.permission_name || `${p.role_name}||${p.app_display_name}`;
    const leftKeys = new Set(leftPerms.map(keyFn));
    const rightKeys = new Set(rightPerms.map(keyFn));
    return {
      common: leftPerms.filter(p => rightKeys.has(keyFn(p))),
      onlyLeft: leftPerms.filter(p => !rightKeys.has(keyFn(p))),
      onlyRight: rightPerms.filter(p => !leftKeys.has(keyFn(p))),
    };
  }, [left, right]);

  // ── Loading ────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse space-y-6">
          <div className="h-8 bg-gray-200 rounded w-64" />
          <div className="grid grid-cols-2 gap-6">
            <div className="h-48 bg-gray-100 rounded-xl" />
            <div className="h-48 bg-gray-100 rounded-xl" />
          </div>
          <div className="h-64 bg-gray-100 rounded-xl" />
        </div>
      </div>
    );
  }

  // ── Error ──────────────────────────────────────────────────
  if (error || !left || !right) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-center">
          <div className="text-red-700 font-semibold mb-2">{error || 'Missing identity data'}</div>
          <Link to="/identities" className="text-sm text-blue-600 hover:underline">
            Back to Identities
          </Link>
        </div>
      </div>
    );
  }

  const li = left.identity;
  const ri = right.identity;
  const riskCmp = compareRiskLevels(li.risk_level, ri.risk_level);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link to="/identities" className="text-gray-400 hover:text-gray-600 transition">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <div>
            <h2 className="text-2xl font-bold text-gray-900">Identity Comparison</h2>
            <p className="text-sm text-gray-500">Side-by-side analysis of two identities</p>
          </div>
        </div>
        <button
          onClick={() => setSwapped(!swapped)}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border rounded-lg hover:bg-gray-50 transition"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
          </svg>
          Swap
        </button>
      </div>

      {/* Identity name chips */}
      <div className="grid grid-cols-2 gap-6">
        <Link to={`/identities/${encodeURIComponent(li.identity_id)}`} className="block bg-white border-2 border-blue-200 rounded-xl px-5 py-3 hover:border-blue-400 transition">
          <div className="text-xs text-blue-500 font-medium mb-1">Identity A</div>
          <div className="text-sm font-semibold text-gray-900 truncate">{li.display_name || li.identity_id}</div>
          <div className="text-[10px] text-gray-400 font-mono truncate">{li.identity_id}</div>
        </Link>
        <Link to={`/identities/${encodeURIComponent(ri.identity_id)}`} className="block bg-white border-2 border-purple-200 rounded-xl px-5 py-3 hover:border-purple-400 transition">
          <div className="text-xs text-purple-500 font-medium mb-1">Identity B</div>
          <div className="text-sm font-semibold text-gray-900 truncate">{ri.display_name || ri.identity_id}</div>
          <div className="text-[10px] text-gray-400 font-mono truncate">{ri.identity_id}</div>
        </Link>
      </div>

      {/* Section 1: Identity Overview */}
      <CompareSection title="Identity Overview" defaultOpen>
        <div className="grid grid-cols-2 gap-6">
          {[li, ri].map((identity, idx) => {
            const side = idx === 0 ? riskCmp : (riskCmp === 'better' ? 'worse' : riskCmp === 'worse' ? 'better' : 'equal');
            const cat = normalizeCategoryFromBackend(identity.identity_category);
            const dormant = getDormantStatusFromActivity(identity.activity_status || undefined);
            const dormantCfg = DORMANT_LABELS[dormant];
            const riskBadge = RISK_BADGE[safeLower(identity.risk_level)] || 'bg-gray-100 text-gray-600';
            const cloudBadge = CLOUD_BADGE[safeLower(identity.cloud)] || 'bg-gray-100 text-gray-600';
            return (
              <div key={idx} className={`border-2 rounded-xl p-4 space-y-3 ${diffBorder(side as DiffResult)}`}>
                <div className="flex items-center justify-between">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${riskBadge}`}>
                    {safeLower(identity.risk_level) || 'unknown'}
                  </span>
                  <span className="text-xs font-semibold text-gray-600">Score: {identity.risk_score ?? '—'}</span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <div className="text-gray-400">Type</div>
                    <div className="font-medium text-gray-700">{identity.identity_type || '—'}</div>
                  </div>
                  <div>
                    <div className="text-gray-400">Category</div>
                    <div className="font-medium text-gray-700">{getCategoryLabel(cat)}</div>
                  </div>
                  <div>
                    <div className="text-gray-400">Cloud</div>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${cloudBadge}`}>
                      {safeLower(identity.cloud) || '—'}
                    </span>
                  </div>
                  <div>
                    <div className="text-gray-400">Activity</div>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${dormantCfg.color}`}>
                      {dormantCfg.label}
                    </span>
                  </div>
                  <div>
                    <div className="text-gray-400">Created</div>
                    <div className="font-medium text-gray-700">
                      {identity.created_datetime ? new Date(identity.created_datetime).toLocaleDateString() : '—'}
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-400">Owner</div>
                    <div className="font-medium text-gray-700 truncate">{identity.owner_display_name || 'Unowned'}</div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </CompareSection>

      {/* Section 2: Risk Analysis */}
      <CompareSection title="Risk Analysis" defaultOpen>
        <div className="space-y-2">
          {[
            { label: 'Risk Level', left: safeLower(li.risk_level) || 'unknown', right: safeLower(ri.risk_level) || 'unknown' },
            { label: 'Risk Score', left: String(li.risk_score ?? '—'), right: String(ri.risk_score ?? '—') },
            { label: 'Trend', left: left.trend?.risk_direction || '—', right: right.trend?.risk_direction || '—' },
          ].map(row => {
            const leftBetter = row.label === 'Risk Score'
              ? (li.risk_score ?? 0) < (ri.risk_score ?? 0)
              : row.label === 'Risk Level'
                ? (RISK_ORDER[safeLower(li.risk_level)] ?? 0) < (RISK_ORDER[safeLower(ri.risk_level)] ?? 0)
                : false;
            const rightBetter = row.label === 'Risk Score'
              ? (ri.risk_score ?? 0) < (li.risk_score ?? 0)
              : row.label === 'Risk Level'
                ? (RISK_ORDER[safeLower(ri.risk_level)] ?? 0) < (RISK_ORDER[safeLower(li.risk_level)] ?? 0)
                : false;
            return (
              <div key={row.label} className="grid grid-cols-3 gap-4 text-sm">
                <div className={`px-3 py-2 rounded-lg text-center font-medium ${leftBetter ? 'bg-green-50 text-green-800' : rightBetter ? 'bg-red-50 text-red-800' : 'bg-gray-50 text-gray-700'}`}>
                  {row.left}
                </div>
                <div className="px-3 py-2 text-center text-xs font-semibold text-gray-500 flex items-center justify-center">
                  {row.label}
                </div>
                <div className={`px-3 py-2 rounded-lg text-center font-medium ${rightBetter ? 'bg-green-50 text-green-800' : leftBetter ? 'bg-red-50 text-red-800' : 'bg-gray-50 text-gray-700'}`}>
                  {row.right}
                </div>
              </div>
            );
          })}

          {/* Risk reasons */}
          <div className="grid grid-cols-2 gap-4 mt-3">
            {[li.risk_reasons, ri.risk_reasons].map((reasons, idx) => (
              <div key={idx}>
                <div className="text-xs font-medium text-gray-500 mb-1">Risk Reasons</div>
                {(reasons && reasons.length > 0) ? (
                  <ul className="space-y-1">
                    {reasons.map((r, i) => (
                      <li key={i} className="text-xs text-gray-700 flex items-start gap-1.5">
                        <span className="text-red-400 mt-0.5">*</span>
                        {r}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="text-xs text-gray-400">None</div>
                )}
              </div>
            ))}
          </div>
        </div>
      </CompareSection>

      {/* Section 3: Roles */}
      <CompareSection
        title="Roles"
        defaultOpen
        count={`${roleDiff.common.length} common, ${roleDiff.onlyLeft.length} unique A, ${roleDiff.onlyRight.length} unique B`}
      >
        <div className="space-y-4">
          {roleDiff.common.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-gray-500 mb-2">Common Roles ({roleDiff.common.length})</div>
              <div className="flex flex-wrap gap-2">
                {roleDiff.common.map((r, i) => <RolePill key={i} role={r} />)}
              </div>
            </div>
          )}
          {roleDiff.onlyLeft.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-blue-600 mb-2">
                Only in {li.display_name || 'A'} ({roleDiff.onlyLeft.length})
              </div>
              <div className="bg-blue-50/50 rounded-lg p-3 flex flex-wrap gap-2">
                {roleDiff.onlyLeft.map((r, i) => <RolePill key={i} role={r} />)}
              </div>
            </div>
          )}
          {roleDiff.onlyRight.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-purple-600 mb-2">
                Only in {ri.display_name || 'B'} ({roleDiff.onlyRight.length})
              </div>
              <div className="bg-purple-50/50 rounded-lg p-3 flex flex-wrap gap-2">
                {roleDiff.onlyRight.map((r, i) => <RolePill key={i} role={r} />)}
              </div>
            </div>
          )}
          {roleDiff.common.length === 0 && roleDiff.onlyLeft.length === 0 && roleDiff.onlyRight.length === 0 && (
            <div className="text-xs text-gray-400 text-center py-4">No roles assigned to either identity</div>
          )}
        </div>
      </CompareSection>

      {/* Section 4: Permissions */}
      <CompareSection
        title="Permissions"
        defaultOpen={false}
        count={`${permDiff.common.length} common, ${permDiff.onlyLeft.length} unique A, ${permDiff.onlyRight.length} unique B`}
      >
        <div className="space-y-4">
          {permDiff.common.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-gray-500 mb-2">Common Permissions ({permDiff.common.length})</div>
              <div className="flex flex-wrap gap-2">
                {permDiff.common.map((p, i) => <PermPill key={i} perm={p} />)}
              </div>
            </div>
          )}
          {permDiff.onlyLeft.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-blue-600 mb-2">
                Only in {li.display_name || 'A'} ({permDiff.onlyLeft.length})
              </div>
              <div className="bg-blue-50/50 rounded-lg p-3 flex flex-wrap gap-2">
                {permDiff.onlyLeft.map((p, i) => <PermPill key={i} perm={p} />)}
              </div>
            </div>
          )}
          {permDiff.onlyRight.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-purple-600 mb-2">
                Only in {ri.display_name || 'B'} ({permDiff.onlyRight.length})
              </div>
              <div className="bg-purple-50/50 rounded-lg p-3 flex flex-wrap gap-2">
                {permDiff.onlyRight.map((p, i) => <PermPill key={i} perm={p} />)}
              </div>
            </div>
          )}
          {permDiff.common.length === 0 && permDiff.onlyLeft.length === 0 && permDiff.onlyRight.length === 0 && (
            <div className="text-xs text-gray-400 text-center py-4">No permissions assigned to either identity</div>
          )}
        </div>
      </CompareSection>

      {/* Section 5: Credentials */}
      <CompareSection title="Credentials" defaultOpen={false}>
        <div className="grid grid-cols-2 gap-6">
          {[li, ri].map((identity, idx) => {
            const statusColor = CRED_STATUS_COLORS[safeLower(identity.credential_status)] || CRED_STATUS_COLORS.unknown;
            return (
              <div key={idx} className="space-y-2">
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <div className="text-gray-400">Status</div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${statusColor}`}>
                      {identity.credential_status || 'unknown'}
                    </span>
                  </div>
                  <div>
                    <div className="text-gray-400">Count</div>
                    <div className="font-medium text-gray-700">{identity.credential_count ?? '—'}</div>
                  </div>
                  <div className="col-span-2">
                    <div className="text-gray-400">Expires In</div>
                    <div className={`font-medium ${identity.credential_status === 'expired' ? 'text-red-600' : identity.credential_status === 'expiring_soon' ? 'text-orange-600' : 'text-gray-700'}`}>
                      {credentialCountdown(identity.credential_expiration)}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </CompareSection>

      {/* Section 6: Compliance */}
      <CompareSection title="Compliance (Conditional Access)" defaultOpen={false}>
        <div className="grid grid-cols-2 gap-6">
          {[li, ri].map((identity, idx) => {
            const covered = identity.ca_coverage_status === 'covered';
            const mfa = identity.ca_mfa_enforced;
            return (
              <div key={idx} className="space-y-2 text-xs">
                <div>
                  <div className="text-gray-400 mb-1">CA Coverage</div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${covered ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'}`}>
                    {identity.ca_coverage_status || 'unknown'}
                  </span>
                </div>
                <div>
                  <div className="text-gray-400 mb-1">MFA Enforced</div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${mfa ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'}`}>
                    {mfa ? 'Yes' : 'No'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </CompareSection>

      {/* Section 7: Ownership */}
      <CompareSection title="Ownership" defaultOpen={false}>
        <div className="grid grid-cols-2 gap-6">
          {[left.owners, right.owners].map((owners, idx) => (
            <div key={idx}>
              {owners && owners.length > 0 ? (
                <div className="space-y-2">
                  {owners.map((o, i) => (
                    <div key={i} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-gray-50 border text-xs">
                      <div className="flex-1 min-w-0">
                        <div className="font-medium text-gray-900 truncate">{o.owner_display_name || o.owner_upn || o.owner_object_id}</div>
                        {o.owner_upn && o.owner_display_name && (
                          <div className="text-[10px] text-gray-400 truncate">{o.owner_upn}</div>
                        )}
                      </div>
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-gray-100 text-gray-600">
                        {o.owner_type || '?'}
                      </span>
                      {o.is_primary_owner && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-blue-50 text-blue-600">Primary</span>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-orange-600 bg-orange-50 rounded-lg px-3 py-2 text-center">Unowned</div>
              )}
            </div>
          ))}
        </div>
      </CompareSection>
    </div>
  );
}
