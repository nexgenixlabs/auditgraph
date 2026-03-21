import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import {
  type RiskLevel, type PrivilegedLevel, type EffectiveScope, type CredentialHealth, type DormantStatus,
  RISK_BADGE, RISK_ORDER, PRIVILEGED_LEVELS, EFFECTIVE_SCOPE_CONFIG, CREDENTIAL_HEALTH_CONFIG,
  DORMANT_LABELS, DATA_EXPLANATIONS, CLOUD_BADGE,
  safeLower, getCategoryLabel, getDormantStatus as getDormantStatusFromActivity,
} from '../constants/metrics';

// ─── Types ────────────────────────────────────────────────────────

interface IdentityDetail {
  identity_id: string;
  display_name: string;
  identity_type?: string;
  identity_category?: string;
  cloud?: string;
  risk_level?: string;
  risk_score?: number;
  risk_reasons?: string[];
  activity_status?: string;
  last_seen_auth?: string | null;
  created_datetime?: string | null;
  credential_count?: number;
  credential_risk?: string;
  credential_status?: string;
  credential_expiration?: string | null;
  owner_display_name?: string | null;
  owner_count?: number;
  is_federated?: boolean;
  tenant_or_org_id?: string;
  ca_coverage_status?: string | null;
  ca_mfa_enforced?: boolean;
  status?: string;
  principal_id?: string;
  api_permission_count?: number;
  app_role_count?: number;
  risk_factors?: { code: string; description: string; severity: string; points: number; category: string; evidence: string }[];
}

interface RoleEdge {
  role_name: string;
  role_type: string;
  scope: string;
  scope_type: string;
  risk_level: string;
  usage_status?: string;
  last_used_display?: string;
  is_removable?: boolean;
}

interface EnrichedRole {
  role_name: string;
  role_type?: string;
  scope?: string;
  scope_type?: string;
  risk_level?: string;
  usage_status?: string;
  last_used_display?: string;
  last_used_at?: string;
  is_removable?: boolean;
  days_since_used?: number;
  days_since_assigned?: number;
  redundant_with?: string;
  why_critical?: string;
}

interface CredentialItem {
  credential_id: string;
  credential_type: string;
  display_name?: string;
  age_days?: number | null;
  days_to_expiry?: number | null;
  status: string;
  exposure_risk?: string;
  exposure_flags?: string[];
  issuer?: string | null;
  subject?: string | null;
}

interface ScopeItem {
  subscription_id: string;
  subscription_level_roles: string[];
  resource_groups: {
    name: string;
    roles: string[];
    resources: { type: string; name: string; roles: string[] }[];
  }[];
}

interface GraphPermission {
  permission_name: string;
  permission_type?: string;
  resource_app?: string;
  consent_type?: string;
}

interface OwnerInfo {
  owner_display_name: string;
  owner_upn?: string;
  owner_type?: string;
  is_primary_owner?: boolean;
}

// ─── Props ────────────────────────────────────────────────────────

interface IdentityDrawerProps {
  identityId: string;
  onClose: () => void;
}

// ─── Helpers ──────────────────────────────────────────────────────

function formatDate(d?: string | null): string {
  if (!d) return '—';
  try { return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }); }
  catch { return d; }
}

function relativeTime(d?: string | null): string {
  if (!d) return '';
  try {
    const days = Math.floor((Date.now() - new Date(d).getTime()) / 86400000);
    if (days === 0) return 'today';
    if (days === 1) return '1 day ago';
    if (days < 30) return `${days}d ago`;
    if (days < 365) return `${Math.floor(days / 30)}mo ago`;
    return `${Math.floor(days / 365)}y ago`;
  } catch { return ''; }
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

// ─── Tab types ────────────────────────────────────────────────────

type TabId = 'overview' | 'access' | 'api' | 'credentials' | 'usage' | 'risk';

const TABS: { id: TabId; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'access', label: 'Access' },
  { id: 'api', label: 'API Perms' },
  { id: 'credentials', label: 'Creds' },
  { id: 'usage', label: 'Usage' },
  { id: 'risk', label: 'Risk' },
];

// ─── Component ────────────────────────────────────────────────────

export default function IdentityDrawer({ identityId, onClose }: IdentityDrawerProps) {
  const { withConnection } = useConnection();
  const [tab, setTab] = useState<TabId>('overview');
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState<IdentityDetail | null>(null);
  const [roles, setRoles] = useState<RoleEdge[]>([]);
  const [credentials, setCredentials] = useState<CredentialItem[]>([]);
  const [scopeHierarchy, setScopeHierarchy] = useState<ScopeItem[]>([]);
  const [graphPermissions, setGraphPermissions] = useState<GraphPermission[]>([]);
  const [owners, setOwners] = useState<OwnerInfo[]>([]);
  const [entraScopes, setEntraScopes] = useState<{ role_name: string; directory_scope: string; risk_level: string; usage_status?: string; last_used_display?: string; is_removable?: boolean }[]>([]);
  const [enrichedRoles, setEnrichedRoles] = useState<EnrichedRole[]>([]);
  const [agentInfo, setAgentInfo] = useState<{
    detected_platform?: string; classification_confidence?: number;
    days_inactive?: number | null; agirs_score?: number;
    has_orphan_finding?: boolean;
  } | null>(null);

  // Fetch identity detail + graph data
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setTab('overview');

    Promise.all([
      fetch(withConnection(`/api/identities/${encodeURIComponent(identityId)}`)).then(r => r.ok ? r.json() : null),
      fetch(withConnection(`/api/identities/${encodeURIComponent(identityId)}/graph-data`)).then(r => r.ok ? r.json() : null),
    ]).then(([detailData, graphData]) => {
      if (cancelled) return;
      if (detailData) {
        setDetail(detailData.identity || detailData);
        setGraphPermissions(detailData.graph_permissions || []);
        setOwners(detailData.owners || []);
        setEnrichedRoles(detailData.roles || []);
      }
      if (graphData) {
        setRoles(graphData.trust_relationships?.role_edges || []);
        setCredentials(graphData.secret_exposure || []);
        setScopeHierarchy(graphData.effective_scope?.scope_hierarchy || []);
        setEntraScopes(graphData.effective_scope?.entra_scopes || []);
        setAgentInfo(graphData.agent_info || null);
      }
      setLoading(false);
    }).catch(() => {
      if (!cancelled) setLoading(false);
    });

    return () => { cancelled = true; };
  }, [identityId]);

  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  const dormantStatus = detail ? getDormantStatusFromActivity(detail.activity_status) : 'unknown';

  return (
    <div className="fixed inset-y-0 right-0 w-[560px] max-w-full bg-white shadow-lg z-50 flex flex-col border-l">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b bg-gray-50 flex-shrink-0">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold text-gray-900 truncate max-w-[280px]">
              {detail?.display_name || 'Loading…'}
            </h3>
            {detail && <RiskBadge level={detail.risk_level} score={detail.risk_score} />}
          </div>
          <p className="text-[10px] text-gray-400 font-mono mt-0.5">{identityId.substring(0, 24)}…</p>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <Link
            to={`/identities/${encodeURIComponent(identityId)}`}
            className="px-2.5 py-1 text-xs font-medium text-blue-700 bg-blue-50 border border-blue-200 rounded-lg hover:bg-blue-100"
          >
            Full Detail
          </Link>
          <button onClick={onClose} className="w-7 h-7 flex items-center justify-center text-gray-400 hover:text-gray-600 hover:bg-gray-200 rounded-lg text-lg leading-none">&times;</button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b bg-white flex-shrink-0 px-2">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-3 py-2 text-xs font-medium border-b-2 transition-colors ${
              tab === t.id
                ? 'border-blue-600 text-blue-700'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="flex-1 overflow-y-auto p-4">
        {loading ? (
          <div className="flex items-center justify-center py-12 text-gray-400">
            <svg className="animate-spin w-5 h-5 mr-2" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            Loading…
          </div>
        ) : !detail ? (
          <p className="text-sm text-gray-400 text-center py-8">Failed to load identity details.</p>
        ) : tab === 'overview' ? (
          <OverviewTab detail={detail} dormantStatus={dormantStatus} owners={owners} agentInfo={agentInfo} />
        ) : tab === 'access' ? (
          <AccessTab roles={roles} scopeHierarchy={scopeHierarchy} entraScopes={entraScopes} enrichedRoles={enrichedRoles} detail={detail} />
        ) : tab === 'api' ? (
          <ApiPermsTab permissions={graphPermissions} />
        ) : tab === 'credentials' ? (
          <CredentialsTab credentials={credentials} detail={detail} />
        ) : tab === 'usage' ? (
          <UsageTab detail={detail} dormantStatus={dormantStatus} roles={roles} />
        ) : (
          <RiskTab detail={detail} />
        )}
      </div>
    </div>
  );
}

// ─── Tab 1: Overview ──────────────────────────────────────────────

function OverviewTab({ detail, dormantStatus, owners, agentInfo }: {
  detail: IdentityDetail; dormantStatus: DormantStatus; owners: OwnerInfo[];
  agentInfo?: { detected_platform?: string; classification_confidence?: number; days_inactive?: number | null; agirs_score?: number; has_orphan_finding?: boolean } | null;
}) {
  const rows: [string, React.ReactNode][] = [
    ['Category', <span className="font-medium">{getCategoryLabel(detail.identity_category)}</span>],
    ['Cloud', <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${CLOUD_BADGE[safeLower(detail.cloud)] || CLOUD_BADGE.azure}`}>{safeLower(detail.cloud) || 'azure'}</span>],
    ['Status', <span className={`font-medium ${detail.status === 'active' ? 'text-green-700' : 'text-red-600'}`}>{detail.status || 'active'}</span>],
    ['Activity', <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${DORMANT_LABELS[dormantStatus].color}`}>{DORMANT_LABELS[dormantStatus].label}</span>],
    ['MFA', detail.ca_mfa_enforced
      ? <span className="text-green-700 font-medium text-xs">Enforced</span>
      : detail.ca_coverage_status === 'covered'
        ? <span className="text-yellow-600 font-medium text-xs">CA Covered (no MFA)</span>
        : <span className="text-red-500 font-medium text-xs">Not Enforced</span>
    ],
    ['CA Coverage', <span className={`text-xs font-medium ${detail.ca_coverage_status === 'covered' ? 'text-green-700' : 'text-red-500'}`}>{detail.ca_coverage_status || 'Unknown'}</span>],
    ['Created', <span className="text-gray-700">{formatDate(detail.created_datetime)}</span>],
    ['Last Used', <span className="text-gray-700">{formatDate(detail.last_seen_auth)} <span className="text-gray-400 text-[10px]">{relativeTime(detail.last_seen_auth)}</span></span>],
  ];

  if (detail.is_federated) {
    rows.push(['Federated', <span className="text-orange-600 font-medium text-xs">Yes — {detail.tenant_or_org_id || 'external tenant'}</span>]);
  }

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        {rows.map(([label, value]) => (
          <div key={label} className="flex items-center justify-between py-1.5 border-b border-gray-50">
            <span className="text-xs text-gray-500">{label}</span>
            <div>{value}</div>
          </div>
        ))}
      </div>

      {/* Owners */}
      {owners.length > 0 && (
        <div>
          <h4 className="text-[10px] text-gray-500 uppercase font-semibold mb-2">Owners ({owners.length})</h4>
          <div className="space-y-1">
            {owners.map((o, idx) => (
              <div key={idx} className="flex items-center gap-2 text-xs bg-gray-50 rounded-lg px-2.5 py-1.5">
                <span className="w-5 h-5 rounded-full bg-blue-100 text-blue-700 text-[10px] font-bold flex items-center justify-center">
                  {(o.owner_display_name || '?')[0].toUpperCase()}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="font-medium text-gray-900 truncate">{o.owner_display_name}</div>
                  {o.owner_upn && <div className="text-[10px] text-gray-400 truncate">{o.owner_upn}</div>}
                </div>
                {o.is_primary_owner && <span className="text-[9px] text-blue-600 font-semibold">Primary</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {owners.length === 0 && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-2.5 text-xs text-yellow-700">
          No owners assigned — this identity is ownerless.
        </div>
      )}

      {/* Phase 3: AI Agent Risk section — only shown for classified agents */}
      {agentInfo && <AgentRiskSection agentInfo={agentInfo} identityId={detail.identity_id} />}
    </div>
  );
}

function AgentRiskSection({ agentInfo, identityId }: {
  agentInfo: { detected_platform?: string; classification_confidence?: number; days_inactive?: number | null; agirs_score?: number; has_orphan_finding?: boolean };
  identityId: string;
}) {
  const [expanded, setExpanded] = useState(true);
  const [blastRadius, setBlastRadius] = useState<{
    reachable_subscription_count?: number; reachable_resource_group_count?: number;
    reachable_resource_count?: number; sensitive_resource_count?: number;
    resource_breakdown?: Record<string, number>;
    delegations?: { target_display_name: string }[];
  } | null>(null);
  const [blastLoading, setBlastLoading] = useState(true);
  const [blastError, setBlastError] = useState(false);
  const { withConnection } = useConnection();

  const fetchBlastRadius = () => {
    setBlastLoading(true);
    setBlastError(false);
    fetch(withConnection(`/api/agent-identities/${encodeURIComponent(identityId)}/blast-radius`))
      .then(r => { if (!r.ok) throw new Error('API error'); return r.json(); })
      .then(data => { setBlastRadius(data); setBlastLoading(false); })
      .catch(() => { setBlastError(true); setBlastLoading(false); });
  };

  useEffect(() => { fetchBlastRadius(); }, [identityId]);

  const isOrphaned = agentInfo.has_orphan_finding;
  const daysLabel = agentInfo.days_inactive != null ? `${agentInfo.days_inactive} days` : 'Never signed in';

  // Blast radius resolved with zero resources — valid empty state
  const isEmptyBlastRadius = !blastLoading && !blastError && blastRadius != null
    && (blastRadius.reachable_resource_count == null || blastRadius.reachable_resource_count === 0);

  return (
    <div className="mt-3" data-testid="agent-risk-section">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-1.5 w-full text-left"
      >
        <svg className={`w-3 h-3 text-gray-400 transition-transform ${expanded ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
        </svg>
        <span className="text-[10px] text-gray-500 uppercase font-semibold tracking-wider">AI Agent Risk</span>
        {isOrphaned && (
          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-red-100 text-red-700 border border-red-200 ml-1">
            ORPHANED
          </span>
        )}
      </button>

      {expanded && (
        <div className={`mt-2 rounded-lg border p-3 space-y-2 ${isOrphaned ? 'border-red-200 bg-red-50' : 'border-amber-200 bg-amber-50'}`}>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div>
              <span className="text-gray-500">Platform</span>
              <div className="font-medium text-gray-900">{agentInfo.detected_platform || 'Unknown'}</div>
            </div>
            <div>
              <span className="text-gray-500">Days Inactive</span>
              <div className={`font-medium ${isOrphaned ? 'text-red-700' : 'text-gray-900'}`}>{daysLabel}</div>
            </div>
            <div>
              <span className="text-gray-500">AGIRS Score</span>
              <div className="font-medium text-gray-900">{agentInfo.agirs_score ?? 'N/A'}</div>
            </div>
            <div>
              <span className="text-gray-500">Confidence</span>
              <div className="font-medium text-gray-900">
                {agentInfo.classification_confidence != null
                  ? `${(agentInfo.classification_confidence * 100).toFixed(0)}%`
                  : 'N/A'}
              </div>
            </div>
          </div>

          {isOrphaned && (
            <div className="flex items-center gap-1.5 text-[10px] text-red-700 bg-red-100 rounded px-2 py-1.5 border border-red-200">
              <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <span className="font-semibold">IASM-AG-001: Orphaned AI Agent SPN — CRITICAL</span>
            </div>
          )}

          {/* H3: Loading skeleton for blast radius */}
          {blastLoading && (
            <div className="animate-pulse space-y-2" data-testid="blast-radius-skeleton">
              <div className="h-3 bg-gray-200 rounded w-[40%]" />
              <div className="h-3 bg-gray-200 rounded w-[60%]" />
              <div className="h-3 bg-gray-200 rounded w-[50%]" />
              <div className="h-4 bg-gray-200 rounded w-[80%]" />
            </div>
          )}

          {/* H3: Error state for blast radius */}
          {blastError && (
            <div className="text-xs space-y-1.5" data-testid="blast-radius-error">
              <p className="text-gray-500">Blast radius unavailable — data will refresh on next scan</p>
              <button
                onClick={fetchBlastRadius}
                className="text-xs text-gray-500 hover:text-gray-700 underline"
                data-testid="blast-radius-retry"
              >
                Retry
              </button>
            </div>
          )}

          {/* H3: Empty state — agent has zero resources in scope */}
          {isEmptyBlastRadius && (
            <p className="text-xs text-gray-500" data-testid="blast-radius-empty">
              No resources in scope — this agent has no active role assignments
            </p>
          )}

          {/* Blast radius data — only when loaded successfully with resources */}
          {!blastLoading && !blastError && blastRadius && blastRadius.reachable_resource_count != null && blastRadius.reachable_resource_count > 0 && (
            <div className="text-xs" data-testid="blast-radius-data">
              <div className="text-gray-500 font-medium mb-1">If compromised, attacker gains access to:</div>
              <div className="grid grid-cols-2 gap-1 text-gray-700">
                {(blastRadius.reachable_subscription_count ?? 0) > 0 && (
                  <div className="flex items-center gap-1">
                    <span className="font-semibold">{blastRadius.reachable_subscription_count}</span> subscription{(blastRadius.reachable_subscription_count ?? 0) !== 1 ? 's' : ''}
                  </div>
                )}
                {(blastRadius.reachable_resource_group_count ?? 0) > 0 && (
                  <div className="flex items-center gap-1">
                    <span className="font-semibold">{blastRadius.reachable_resource_group_count}</span> resource group{(blastRadius.reachable_resource_group_count ?? 0) !== 1 ? 's' : ''}
                  </div>
                )}
                {blastRadius.resource_breakdown && Object.entries(blastRadius.resource_breakdown).map(([type, count]) => (
                  <div key={type} className="flex items-center gap-1">
                    <span className="font-semibold">{count as number}</span> {(type as string).replace(/_/g, ' ')}
                  </div>
                ))}
              </div>
            </div>
          )}

          {blastRadius?.delegations && blastRadius.delegations.length > 0 && (
            <div className="text-xs text-gray-700">
              <span className="text-gray-500">Delegates to: </span>
              {blastRadius.delegations.map((d, i) => (
                <span key={i} className="font-medium text-amber-700">
                  {d.target_display_name}{i < blastRadius.delegations!.length - 1 ? ', ' : ''}
                </span>
              ))}
            </div>
          )}

          <Link
            to={`/identities/${encodeURIComponent(identityId)}`}
            className="inline-flex items-center gap-1 text-[10px] text-blue-600 hover:text-blue-800 font-medium"
          >
            View full blast radius
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
            </svg>
          </Link>
        </div>
      )}
    </div>
  );
}

// ─── Tab 2: Effective Access ──────────────────────────────────────

function AccessTab({ roles, scopeHierarchy, entraScopes, enrichedRoles, detail }: {
  roles: RoleEdge[]; scopeHierarchy: ScopeItem[];
  entraScopes: { role_name: string; directory_scope: string; risk_level: string; usage_status?: string; last_used_display?: string; is_removable?: boolean }[];
  enrichedRoles: EnrichedRole[];
  detail: IdentityDetail;
}) {
  const [scriptCopied, setScriptCopied] = useState(false);

  // Build lookup from enriched roles using composite key (role_name::scope)
  const enrichedLookup: Record<string, EnrichedRole> = {};
  for (const er of enrichedRoles) {
    const compositeKey = `${er.role_name}::${er.scope || ''}`;
    enrichedLookup[compositeKey] = er;
    const nameKey = `name:${er.role_name}`;
    if (!enrichedLookup[nameKey]) enrichedLookup[nameKey] = er;
  }
  const findEnriched = (roleName: string, scope?: string): EnrichedRole | undefined => {
    return enrichedLookup[`${roleName}::${scope || ''}`] || enrichedLookup[`name:${roleName}`];
  };

  const removableRoles = enrichedRoles.filter(r => r.is_removable);
  const removableCount = removableRoles.length;

  const USAGE_BADGE: Record<string, { label: string; color: string; ts: string }> = {
    active: { label: 'Active', color: 'bg-green-100 text-green-700', ts: 'text-green-600' },
    stale: { label: 'Stale', color: 'bg-yellow-100 text-yellow-700', ts: 'text-yellow-600' },
    dormant: { label: 'Dormant', color: 'bg-orange-100 text-orange-700', ts: 'text-orange-600' },
    never_used: { label: 'Never Used', color: 'bg-red-100 text-red-700', ts: 'text-red-500' },
    definitely_unused: { label: 'Never Used', color: 'bg-red-100 text-red-700', ts: 'text-red-500' },
  };

  // Generate cleanup script for all removable roles
  const handleCopyCleanup = () => {
    const objId = detail.principal_id || detail.identity_id;
    const lines = [
      `# AuditGraph Least-Privilege Cleanup`,
      `# Identity: ${detail.display_name}`,
      `# Removable roles: ${removableRoles.length}`,
      `# Generated: ${new Date().toISOString()}`,
      ``,
      `Connect-AzAccount`,
      ``,
    ];
    removableRoles.forEach((role, i) => {
      lines.push(`# --- Role ${i + 1}: ${role.role_name} (${role.usage_status || 'unused'}) ---`);
      if (role.scope) {
        lines.push(`Remove-AzRoleAssignment \``);
        lines.push(`  -ObjectId "${objId}" \``);
        lines.push(`  -RoleDefinitionName "${role.role_name}" \``);
        lines.push(`  -Scope "${role.scope}"`);
      } else {
        lines.push(`# Scope not available — find manually:`);
        lines.push(`# Get-AzRoleAssignment -ObjectId "${objId}"`);
      }
      lines.push(``);
    });
    navigator.clipboard.writeText(lines.join('\n'));
    setScriptCopied(true);
    setTimeout(() => setScriptCopied(false), 2000);
  };

  // Generate single-role PS1 script and copy to clipboard
  const handleCopyRoleScript = (er: EnrichedRole) => {
    const objId = detail.principal_id || detail.identity_id;
    const script = er.scope
      ? [
          `# Remove ${er.role_name} from ${detail.display_name}`,
          `# Scope: ${er.scope}`,
          `# Status: ${er.usage_status || 'unknown'}${er.last_used_display ? ' · ' + er.last_used_display : ''}`,
          ``,
          `Connect-AzAccount`,
          `Remove-AzRoleAssignment \``,
          `  -ObjectId "${objId}" \``,
          `  -RoleDefinitionName "${er.role_name}" \``,
          `  -Scope "${er.scope}"`,
        ].join('\n')
      : `# Scope not available — find manually:\n# Get-AzRoleAssignment -ObjectId "${objId}"`;
    navigator.clipboard.writeText(script);
  };

  // Render usage badge + timestamp inline
  const usageBadge = (usage: string | undefined, lastUsed: string | undefined) => {
    const ub = usage ? USAGE_BADGE[usage] : null;
    if (!ub) return null;
    return (
      <span className="flex items-center gap-1">
        <span className={`px-1 py-0.5 rounded text-[9px] font-semibold ${ub.color}`}>{ub.label}</span>
        {lastUsed && lastUsed !== 'No data' && (
          <span className={`text-[10px] ${ub.ts}`}>· {lastUsed}</span>
        )}
      </span>
    );
  };

  return (
    <div className="space-y-4">
      {/* Element 2: Removable roles banner with Copy Cleanup Script */}
      {removableCount > 0 && (
        <div className="flex items-center justify-between bg-orange-50 border border-orange-200 rounded-lg px-3 py-2.5">
          <div>
            <div className="flex items-center gap-1.5">
              <svg className="w-4 h-4 text-orange-600 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
              <span className="text-xs font-semibold text-orange-800">
                {removableCount} unused role assignment{removableCount > 1 ? 's' : ''} detected
              </span>
            </div>
            <div className="text-[10px] text-orange-600 mt-0.5 ml-5.5">
              Based on last sign-in activity
            </div>
          </div>
          <button
            onClick={handleCopyCleanup}
            className="flex-shrink-0 ml-3 px-2.5 py-1.5 text-[10px] font-medium rounded-md bg-orange-100 text-orange-800 hover:bg-orange-200 transition border border-orange-200"
          >
            {scriptCopied ? 'Copied!' : 'Copy cleanup script'}
          </button>
        </div>
      )}

      {/* Entra Directory Roles */}
      {entraScopes.length > 0 && (
        <div>
          <h4 className="text-[10px] text-gray-500 uppercase font-semibold mb-2">Entra Directory Roles ({entraScopes.length})</h4>
          <div className="space-y-1">
            {entraScopes.map((r, idx) => {
              const er = findEnriched(r.role_name, r.directory_scope);
              const usage = r.usage_status || er?.usage_status;
              const lastUsed = r.last_used_display || er?.last_used_display;
              const removable = r.is_removable || er?.is_removable;
              return (
                <div key={idx} className={`rounded-lg px-2.5 py-1.5 ${removable ? 'bg-orange-50 border border-orange-200' : 'bg-purple-50'}`}>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-purple-900">{r.role_name}</span>
                    <div className="flex items-center gap-1">
                      {usageBadge(usage, lastUsed)}
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase ${RISK_BADGE[safeLower(r.risk_level)] || 'bg-gray-100 text-gray-500'}`}>{r.risk_level}</span>
                      {removable && er && (
                        <button
                          onClick={() => er && handleCopyRoleScript(er)}
                          className="px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold bg-orange-100 text-orange-700 hover:bg-orange-200 transition border border-orange-200"
                          title={`Copy PowerShell to remove ${r.role_name}`}
                        >
                          PS1
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ARM Scope Hierarchy */}
      {scopeHierarchy.length > 0 && (
        <div>
          <h4 className="text-[10px] text-gray-500 uppercase font-semibold mb-2">Azure Subscriptions ({scopeHierarchy.length})</h4>
          {scopeHierarchy.map((sub, sIdx) => (
            <div key={sIdx} className="mb-3 border rounded-lg overflow-hidden">
              <div className="bg-blue-50 px-2.5 py-2 flex items-center gap-2">
                <span className="text-[10px] text-blue-600 font-mono">{sub.subscription_id.substring(0, 16)}…</span>
                {sub.subscription_level_roles.length > 0 && (
                  <div className="flex gap-1 flex-wrap">
                    {sub.subscription_level_roles.map((r, rIdx) => (
                      <span key={rIdx} className="px-1.5 py-0.5 rounded text-[9px] font-semibold bg-blue-100 text-blue-700">{r}</span>
                    ))}
                  </div>
                )}
              </div>
              {sub.resource_groups.map((rg, rgIdx) => (
                <div key={rgIdx} className="border-t">
                  <div className="px-2.5 py-1.5 bg-gray-50 flex items-center gap-2 pl-6">
                    <span className="text-[10px] text-gray-600 font-medium">{rg.name}</span>
                    {rg.roles.map((r, rIdx) => (
                      <span key={rIdx} className="px-1 py-0.5 rounded text-[9px] font-medium bg-yellow-100 text-yellow-700">{r}</span>
                    ))}
                  </div>
                  {rg.resources.map((res, resIdx) => (
                    <div key={resIdx} className="px-2.5 py-1 flex items-center gap-2 pl-10 border-t border-gray-50">
                      <span className="text-[10px] text-gray-500">{res.type}</span>
                      <span className="text-[10px] text-gray-700 font-medium truncate">{res.name}</span>
                      {res.roles.map((r, rIdx) => (
                        <span key={rIdx} className="px-1 py-0.5 rounded text-[9px] bg-green-100 text-green-700">{r}</span>
                      ))}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          ))}
        </div>
      )}

      {/* All roles list */}
      {roles.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-2">
            <h4 className="text-[10px] text-gray-500 uppercase font-semibold">All Role Assignments ({roles.length})</h4>
            {removableCount > 0 && (
              <span className="px-1.5 py-0.5 rounded-full text-[9px] font-semibold bg-orange-100 text-orange-700">
                {removableCount} removable
              </span>
            )}
          </div>
          <div className="space-y-1 max-h-[300px] overflow-y-auto">
            {roles.map((r, idx) => {
              const er = findEnriched(r.role_name, r.scope);
              const usage = r.usage_status || er?.usage_status;
              const lastUsed = r.last_used_display || er?.last_used_display;
              const isRemovable = r.is_removable || er?.is_removable || ['stale', 'dormant', 'never_used'].includes(usage || '');
              return (
                <div key={idx} className={`text-xs rounded px-2.5 py-1.5 ${isRemovable ? 'bg-orange-50 border border-orange-200' : 'bg-gray-50'}`}>
                  <div className="flex items-center justify-between">
                    <div className="min-w-0 flex-1">
                      <span className="font-medium text-gray-900">{r.role_name}</span>
                      <span className="text-[10px] text-gray-400 ml-1">{r.role_type}</span>
                    </div>
                    <div className="flex items-center gap-1 flex-shrink-0">
                      {usageBadge(usage, lastUsed)}
                      <span className={`px-1 py-0.5 rounded text-[9px] font-semibold uppercase ${RISK_BADGE[safeLower(r.risk_level)] || 'bg-gray-100 text-gray-500'}`}>{r.risk_level}</span>
                      {isRemovable && er && (
                        <button
                          onClick={() => handleCopyRoleScript(er)}
                          className="px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold bg-orange-100 text-orange-700 hover:bg-orange-200 transition border border-orange-200"
                          title={`Copy PowerShell to remove ${r.role_name}`}
                        >
                          PS1
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {entraScopes.length === 0 && scopeHierarchy.length === 0 && roles.length === 0 && (
        <p className="text-sm text-gray-400 text-center py-8">No role assignments found.</p>
      )}
    </div>
  );
}

// ─── Tab 3: API Permissions ───────────────────────────────────────

function ApiPermsTab({ permissions }: { permissions: GraphPermission[] }) {
  if (permissions.length === 0) {
    return <p className="text-sm text-gray-400 text-center py-8">No Graph API permissions.</p>;
  }

  // Group by resource_app
  const grouped: Record<string, GraphPermission[]> = {};
  permissions.forEach(p => {
    const app = p.resource_app || 'Unknown';
    if (!grouped[app]) grouped[app] = [];
    grouped[app].push(p);
  });

  const dangerPatterns = ['.ReadWrite', '.Write', 'Admin', '.All', 'FullControl'];

  return (
    <div className="space-y-4">
      {Object.entries(grouped).map(([app, perms]) => (
        <div key={app}>
          <h4 className="text-[10px] text-gray-500 uppercase font-semibold mb-2">{app} ({perms.length})</h4>
          <div className="space-y-1">
            {perms.map((p, idx) => {
              const isDangerous = dangerPatterns.some(pat => p.permission_name.includes(pat));
              return (
                <div key={idx} className={`flex items-center justify-between text-xs rounded px-2.5 py-1.5 ${isDangerous ? 'bg-red-50' : 'bg-gray-50'}`}>
                  <span className={`font-medium ${isDangerous ? 'text-red-700' : 'text-gray-900'}`}>{p.permission_name}</span>
                  <div className="flex items-center gap-1.5">
                    <span className={`px-1 py-0.5 rounded text-[9px] font-medium ${
                      p.permission_type === 'Application' ? 'bg-orange-100 text-orange-700' : 'bg-blue-100 text-blue-600'
                    }`}>
                      {p.permission_type || 'Application'}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Tab 4: Credentials ──────────────────────────────────────────

function CredentialsTab({ credentials, detail }: { credentials: CredentialItem[]; detail: IdentityDetail }) {
  if (detail.identity_category === 'human_user' || detail.identity_category === 'guest') {
    return (
      <div className="text-center py-8">
        <p className="text-sm text-gray-400">{DATA_EXPLANATIONS.CREDENTIAL_NA}</p>
      </div>
    );
  }

  if (credentials.length === 0) {
    return <p className="text-sm text-gray-400 text-center py-8">No credentials registered.</p>;
  }

  const activeCount = credentials.filter(c => c.status !== 'expired').length;
  const expiredCount = credentials.filter(c => c.status === 'expired').length;

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="grid grid-cols-3 gap-2">
        <div className="bg-gray-50 rounded-lg p-2 text-center">
          <div className="text-lg font-bold text-gray-900">{credentials.length}</div>
          <div className="text-[10px] text-gray-500">Total</div>
        </div>
        <div className="bg-green-50 rounded-lg p-2 text-center">
          <div className="text-lg font-bold text-green-700">{activeCount}</div>
          <div className="text-[10px] text-green-600">Active</div>
        </div>
        <div className={`rounded-lg p-2 text-center ${expiredCount > 0 ? 'bg-red-50' : 'bg-gray-50'}`}>
          <div className={`text-lg font-bold ${expiredCount > 0 ? 'text-red-700' : 'text-gray-400'}`}>{expiredCount}</div>
          <div className={`text-[10px] ${expiredCount > 0 ? 'text-red-600' : 'text-gray-500'}`}>Expired</div>
        </div>
      </div>

      {activeCount > 1 && (
        <div className="bg-orange-50 border border-orange-200 rounded-lg p-2.5 text-xs text-orange-700">
          Multiple active credentials detected — consider rotating unused secrets.
        </div>
      )}

      {/* Credential list */}
      <div className="space-y-2">
        {credentials.map((c, idx) => (
          <div key={idx} className={`border rounded-lg p-2.5 ${c.status === 'expired' ? 'border-red-200 bg-red-50/50' : 'border-gray-200'}`}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-medium text-gray-900">{c.display_name || c.credential_type}</span>
              <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase ${
                c.exposure_risk === 'critical' ? 'bg-red-100 text-red-700' :
                c.exposure_risk === 'high' ? 'bg-orange-100 text-orange-700' :
                c.exposure_risk === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                'bg-green-100 text-green-700'
              }`}>{c.exposure_risk || c.status}</span>
            </div>
            <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-[10px]">
              <div className="flex justify-between"><span className="text-gray-400">Type</span><span className="text-gray-700">{c.credential_type}</span></div>
              {c.age_days != null && <div className="flex justify-between"><span className="text-gray-400">Age</span><span className="text-gray-700">{c.age_days}d</span></div>}
              {c.days_to_expiry != null && (
                <div className="flex justify-between">
                  <span className="text-gray-400">Expiry</span>
                  <span className={c.days_to_expiry < 0 ? 'text-red-600 font-medium' : c.days_to_expiry <= 30 ? 'text-orange-600 font-medium' : 'text-gray-700'}>
                    {c.days_to_expiry < 0 ? `Expired ${Math.abs(c.days_to_expiry)}d ago` : `${c.days_to_expiry}d left`}
                  </span>
                </div>
              )}
            </div>
            {c.exposure_flags && c.exposure_flags.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-1.5">
                {c.exposure_flags.map((flag, fIdx) => (
                  <span key={fIdx} className="px-1 py-0.5 rounded text-[9px] bg-gray-100 text-gray-600">{flag}</span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Tab 5: Usage Intelligence ────────────────────────────────────

function UsageTab({ detail, dormantStatus, roles }: { detail: IdentityDetail; dormantStatus: DormantStatus; roles: RoleEdge[] }) {
  const { withConnection } = useConnection();
  const [usageData, setUsageData] = useState<any>(null);
  const [usageLoading, setUsageLoading] = useState(true);

  useEffect(() => {
    setUsageLoading(true);
    fetch(withConnection(`/api/identities/${encodeURIComponent(detail.identity_id)}/usage`))
      .then(r => r.ok ? r.json() : null)
      .then(data => { setUsageData(data); setUsageLoading(false); })
      .catch(() => setUsageLoading(false));
  }, [detail.identity_id]);

  // Fallback to role-based data if API fails
  const totalRoles = usageData?.granted_vs_used?.total_roles ?? roles.length;
  const usedRoles = usageData?.granted_vs_used?.used_roles ?? roles.filter(r => r.usage_status !== 'definitely_unused').length;
  const neverUsedCount = usageData?.granted_vs_used?.never_used_count ?? roles.filter(r => r.usage_status === 'definitely_unused').length;
  const neverUsedRoles = usageData?.granted_vs_used?.never_used_roles ?? roles.filter(r => r.usage_status === 'definitely_unused').map(r => ({ role_name: r.role_name, role_type: r.role_type, scope_type: r.scope_type }));

  const confidence = usageData?.confidence || (detail.last_seen_auth ? 'medium' : 'low');
  const confidenceLabels: Record<string, string> = {
    high: 'High — recent sign-in logs available',
    medium: 'Medium — sign-in data exists but may be stale',
    low: 'Low — no sign-in telemetry available',
  };

  const usageSource = usageData?.usage_source || 'none';
  const sourceLabels: Record<string, { label: string; color: string }> = {
    sign_in_logs: { label: 'Sign-In Logs', color: 'bg-green-100 text-green-700' },
    audit_logs: { label: 'Audit Logs', color: 'bg-blue-100 text-blue-700' },
    inferred: { label: 'Inferred', color: 'bg-yellow-100 text-yellow-700' },
    none: { label: 'No Data', color: 'bg-gray-100 text-gray-500' },
  };
  const src = sourceLabels[usageSource] || sourceLabels.none;

  return (
    <div className="space-y-4">
      {usageLoading && (
        <div className="text-center py-4 text-gray-400 text-xs">Loading usage data…</div>
      )}

      {/* Last used */}
      <div className="bg-gray-50 rounded-lg p-3">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-gray-500">Last Used</span>
          <span className="text-sm font-medium text-gray-900">{formatDate(usageData?.last_used || detail.last_seen_auth)}</span>
        </div>
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-gray-500">Relative</span>
          <span className="text-sm text-gray-700">{relativeTime(usageData?.last_used || detail.last_seen_auth) || 'Never / Unknown'}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-xs text-gray-500">Source</span>
          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${src.color}`}>{src.label}</span>
        </div>
      </div>

      {/* Confidence */}
      <div className={`rounded-lg p-2.5 text-xs border ${
        confidence === 'high' ? 'bg-green-50 border-green-200 text-green-700' :
        confidence === 'medium' ? 'bg-yellow-50 border-yellow-200 text-yellow-700' :
        'bg-gray-50 border-gray-200 text-gray-500'
      }`}>
        <span className="font-semibold">Data Confidence:</span> {confidenceLabels[confidence] || confidenceLabels.low}
      </div>

      {/* Dormancy */}
      <div className="flex items-center justify-between py-2 border-b border-gray-100">
        <span className="text-xs text-gray-500">Dormancy Status</span>
        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${DORMANT_LABELS[dormantStatus].color}`}>
          {DORMANT_LABELS[dormantStatus].label}
        </span>
      </div>

      {/* Granted vs Used */}
      {totalRoles > 0 && (
        <div>
          <h4 className="text-[10px] text-gray-500 uppercase font-semibold mb-2">Granted vs Used Roles</h4>
          <div className="flex gap-2 mb-2">
            <div className="flex-1 bg-blue-50 rounded-lg p-2 text-center">
              <div className="text-lg font-bold text-blue-700">{totalRoles}</div>
              <div className="text-[10px] text-blue-500">Granted</div>
            </div>
            <div className="flex-1 bg-green-50 rounded-lg p-2 text-center">
              <div className="text-lg font-bold text-green-700">{usedRoles}</div>
              <div className="text-[10px] text-green-500">Used</div>
            </div>
            <div className={`flex-1 rounded-lg p-2 text-center ${neverUsedCount > 0 ? 'bg-red-50' : 'bg-gray-50'}`}>
              <div className={`text-lg font-bold ${neverUsedCount > 0 ? 'text-red-700' : 'text-gray-400'}`}>{neverUsedCount}</div>
              <div className={`text-[10px] ${neverUsedCount > 0 ? 'text-red-500' : 'text-gray-400'}`}>Never Used</div>
            </div>
          </div>
          {/* Progress bar */}
          <div className="w-full bg-gray-200 rounded-full h-2 overflow-hidden">
            <div className="bg-green-500 h-2 rounded-full transition-all" style={{ width: `${totalRoles > 0 ? (usedRoles / totalRoles) * 100 : 0}%` }} />
          </div>
          <div className="text-[10px] text-gray-400 mt-1">{totalRoles > 0 ? Math.round((usedRoles / totalRoles) * 100) : 0}% of granted roles have usage evidence</div>

          {/* Never-used list */}
          {neverUsedRoles.length > 0 && (
            <div className="mt-3">
              <h4 className="text-[10px] text-red-500 uppercase font-semibold mb-1">Never-Used Roles</h4>
              <div className="space-y-1">
                {neverUsedRoles.slice(0, 10).map((r: any, idx: number) => (
                  <div key={idx} className="text-xs bg-red-50 rounded px-2.5 py-1 text-red-700">
                    {r.role_name} <span className="text-red-400">({r.role_type}, {r.scope_type})</span>
                  </div>
                ))}
                {neverUsedRoles.length > 10 && (
                  <div className="text-[10px] text-gray-400">+{neverUsedRoles.length - 10} more</div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Permission count */}
      {usageData?.granted_vs_used?.total_permissions != null && (
        <div className="flex items-center justify-between py-2 border-t border-gray-100">
          <span className="text-xs text-gray-500">API Permissions</span>
          <span className="text-sm font-medium text-gray-700">{usageData.granted_vs_used.total_permissions}</span>
        </div>
      )}
    </div>
  );
}

// ─── Tab 6: Risk Breakdown ────────────────────────────────────────

function RiskTab({ detail }: { detail: IdentityDetail }) {
  // Prefer structured risk_factors (V2), fall back to parsed risk_reasons
  const structuredFactors = detail.risk_factors || [];
  const reasons = detail.risk_reasons || [];

  type FactorCard = { id: number; code: string; description: string; points: number; severity: string; evidence: string; category: string };

  let factors: FactorCard[];

  if (structuredFactors.length > 0) {
    // V2 structured factors
    factors = structuredFactors.map((f, idx) => ({
      id: idx,
      code: f.code,
      description: f.description,
      points: f.points,
      severity: f.severity,
      evidence: f.evidence || '',
      category: f.category || 'unknown',
    }));
  } else {
    // Legacy: parse risk_reasons strings
    factors = reasons.map((reason, idx) => {
      const pointsMatch = reason.match(/\(\+(\d+)\)\s*$/);
      const points = pointsMatch ? parseInt(pointsMatch[1], 10) : 0;
      const description = pointsMatch ? reason.replace(pointsMatch[0], '').trim() : reason;
      let severity = 'low';
      if (points >= 300) severity = 'critical';
      else if (points >= 200) severity = 'high';
      else if (points >= 100) severity = 'medium';
      return { id: idx, code: '', description, points, severity, evidence: '', category: '' };
    });
  }

  if (factors.length === 0 || (factors.length === 1 && factors[0].description.includes('No elevated'))) {
    return (
      <div className="text-center py-8">
        <div className="text-3xl mb-2">&#9989;</div>
        <p className="text-sm text-gray-500">No risk factors identified.</p>
        <p className="text-[10px] text-gray-400 mt-1">Risk score: {detail.risk_score ?? 0}</p>
      </div>
    );
  }

  // Sort by points desc
  factors.sort((a, b) => b.points - a.points);

  const SEVERITY_STYLE: Record<string, { border: string; bg: string; badge: string }> = {
    critical: { border: 'border-red-200', bg: 'bg-red-50/50', badge: 'bg-red-100 text-red-700' },
    high: { border: 'border-orange-200', bg: 'bg-orange-50/50', badge: 'bg-orange-100 text-orange-700' },
    medium: { border: 'border-yellow-200', bg: 'bg-yellow-50/50', badge: 'bg-yellow-100 text-yellow-700' },
    low: { border: 'border-gray-200', bg: '', badge: 'bg-gray-100 text-gray-600' },
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between mb-2">
        <h4 className="text-[10px] text-gray-500 uppercase font-semibold">Risk Factors ({factors.length})</h4>
        <RiskBadge level={detail.risk_level} score={detail.risk_score} />
      </div>

      {factors.map(f => {
        const s = SEVERITY_STYLE[f.severity] || SEVERITY_STYLE.low;
        return (
          <div key={f.id} className={`border rounded-lg p-2.5 ${s.border} ${s.bg}`}>
            <div className="flex items-center justify-between mb-0.5">
              <div className="flex items-center gap-1.5">
                <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase ${s.badge}`}>{f.severity}</span>
                {f.code && <span className="text-[9px] text-gray-400 font-mono">{f.code}</span>}
              </div>
              <span className="text-xs font-mono text-gray-500">+{f.points}</span>
            </div>
            <p className="text-xs text-gray-700 mt-1">{f.description}</p>
            {f.evidence && <p className="text-[10px] text-gray-400 mt-0.5 font-mono">{f.evidence}</p>}
          </div>
        );
      })}
    </div>
  );
}
