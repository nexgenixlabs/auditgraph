import React, { useEffect, useState } from 'react';
import { useConnection } from '../../contexts/ConnectionContext';
import { EnrichmentTierBadge } from './EnrichmentTierBadge';
import { OrphanBadge } from './OrphanBadge';
import { WorkloadAssociationsPanel } from './WorkloadAssociationsPanel';
import { FederatedMappingsPanel } from './FederatedMappingsPanel';
import { RoleTopologyPanel } from './RoleTopologyPanel';
import { OwnerGraphPanel } from './OwnerGraphPanel';

// ── Unified lineage response shape (GET /api/identities/{id}/lineage) ──────

interface ResourceBinding {
  resource_id: string;
  resource_type: string;
  resource_name: string;
  resource_group: string;
  subscription_id: string;
  region: string;
  binding_method: string;
  confidence_score: number;
  binding_evidence: Record<string, unknown>;
  last_verified_at: string | null;
}

interface Signal {
  source: string;
  weight: number;
  detail: string;
}

interface LineageData {
  identity_id: string;
  display_name: string;
  identity_category: string;
  cloud: 'azure' | 'aws' | 'gcp';
  workload_origin: {
    origin: string;
    source: string;
    workload_type: string | null;
    workload_confidence: number;
    is_discovery_connector: boolean;
  };
  confidence: {
    level: string;
    score: number;
    enrichment_tier: string;
    signals: Signal[];
  };
  arm_associations: ResourceBinding[];
  managed_identity_bindings: ResourceBinding[];
  federated_credentials: Array<Record<string, unknown>>;
  dependency_impact: {
    level: string;
    resources: Array<{ resource_name: string; resource_type: string; impact_level: string }>;
    statement: string;
    total_bound: number;
  };
  recommended_action: {
    action: string;
    action_text: string;
    orphan_status: string;
    risk_summary: string[];
    active_role_count: number;
  };
  role_topology: {
    workload_type: string;
    workload_confidence: number;
    role_assignments: Array<{ role_name: string; scope: string; scope_type?: string; resource_type?: string }>;
  } | null;
  app_registration: {
    object_id: string | null;
    display_name: string;
    is_external: boolean;
    publisher_domain: string | null;
    sign_in_audience: string | null;
    owners: Array<{ display_name: string; id?: string }>;
    likely_service: string | null;
    reply_url_hostnames: string[];
    notes: string;
    required_apis: string[] | null;
    created_at: string | null;
  } | null;
  sign_in: {
    pattern: string;
    dormancy_days: number;
    last_sign_in: string | null;
    last_delegated: string | null;
    last_noninteractive: string | null;
  } | null;
}

// ── Impact level badge colors ──────────────────────────────────────────────

const IMPACT_BADGE: Record<string, { label: string; cls: string }> = {
  high:          { label: 'High Impact',    cls: 'bg-red-100 text-red-700' },
  medium:        { label: 'Medium Impact',  cls: 'bg-amber-100 text-amber-700' },
  low:           { label: 'Low Impact',     cls: 'bg-gray-100 text-gray-600' },
  none_detected: { label: 'No Impact Data', cls: 'bg-gray-50 text-gray-400' },
};

// ── Sub-components ─────────────────────────────────────────────────────────

function LineageScoreRing({ score }: { score: number }): React.ReactElement {
  const r = 22;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color = score >= 70 ? '#22c55e' : score >= 40 ? '#f59e0b' : score >= 15 ? '#f97316' : '#9ca3af';

  return (
    <div className="flex items-center gap-2">
      <svg width="54" height="54" className="shrink-0">
        <circle cx="27" cy="27" r={r} fill="none" stroke="#e5e7eb" strokeWidth="4" />
        <circle cx="27" cy="27" r={r} fill="none" stroke={color}
          strokeWidth="4" strokeDasharray={circ} strokeDashoffset={offset}
          strokeLinecap="round" transform="rotate(-90 27 27)" />
        <text x="27" y="27" textAnchor="middle" dominantBaseline="central"
          className="text-xs font-bold fill-gray-700">{score}</text>
      </svg>
      <div>
        <p className="text-xs font-semibold text-gray-700">Lineage Score</p>
        <p className="text-[10px] text-gray-500">
          {score >= 70 ? 'High confidence' : score >= 40 ? 'Moderate confidence' : 'Low confidence'}
        </p>
      </div>
    </div>
  );
}

function LoadingSkeleton(): React.ReactElement {
  return (
    <div className="space-y-4 animate-pulse">
      <div className="flex items-center gap-4">
        <div className="w-14 h-14 rounded-full bg-gray-200" />
        <div className="space-y-2 flex-1">
          <div className="h-4 bg-gray-200 rounded w-32" />
          <div className="h-3 bg-gray-100 rounded w-24" />
        </div>
        <div className="h-5 bg-gray-200 rounded w-28" />
        <div className="h-5 bg-gray-200 rounded w-24" />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="h-48 bg-gray-100 rounded-lg" />
        <div className="h-48 bg-gray-100 rounded-lg" />
        <div className="h-48 bg-gray-100 rounded-lg" />
        <div className="h-48 bg-gray-100 rounded-lg" />
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────

export function LineageTab({ spnId }: { spnId: string }): React.ReactElement {
  const { withConnection } = useConnection();
  const [data, setData] = useState<LineageData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!spnId) return;
    setLoading(true);
    setError(null);

    const abort = new AbortController();
    fetch(withConnection(`/api/identities/${spnId}/lineage`), { signal: abort.signal })
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(d => { setData(d); setLoading(false); })
      .catch(e => {
        if (e.name !== 'AbortError') {
          setError(e.message || 'Failed to load lineage data');
          setLoading(false);
        }
      });

    return () => abort.abort();
  }, [spnId, withConnection]);

  if (loading) return <LoadingSkeleton />;

  if (error || !data) {
    return (
      <div className="text-center py-8">
        <p className="text-xs text-gray-500">{error || 'No lineage data available.'}</p>
        <p className="text-[10px] text-gray-400 mt-1">Run a lineage scan to populate this tab.</p>
      </div>
    );
  }

  const allBindings = [...data.arm_associations, ...data.managed_identity_bindings];
  const impactBadge = IMPACT_BADGE[data.dependency_impact.level] || IMPACT_BADGE.none_detected;

  // Adapt shapes for existing sub-panels
  const roleTopologyLegacy = data.role_topology ? {
    workloadType: data.role_topology.workload_type,
    confidence: data.role_topology.workload_confidence,
    roleAssignments: data.role_topology.role_assignments.map(r => ({
      roleName: r.role_name, scope: r.scope,
    })),
    topResources: [] as string[],
  } : null;

  const appRegLegacy = data.app_registration ? {
    displayName: data.app_registration.display_name,
    owners: data.app_registration.owners.map(o => ({
      displayName: o.display_name, id: o.id,
    })),
    notes: data.app_registration.notes,
    description: data.app_registration.likely_service || '',
    inferredHostUrls: data.app_registration.reply_url_hostnames,
    createdAt: data.app_registration.created_at,
  } : null;

  const orphanStatusLegacy = {
    orphanStatus: data.recommended_action.orphan_status,
    orphanReasons: data.recommended_action.risk_summary,
    recommendedAction: data.recommended_action.action_text,
    activeRoleCount: data.recommended_action.active_role_count,
  };

  return (
    <div className="space-y-4">
      {/* Header: Score + Badges */}
      <div className="flex items-center justify-between flex-wrap gap-3 bg-gray-50 rounded-lg px-4 py-3 border border-gray-200">
        <LineageScoreRing score={data.confidence.score} />
        <div className="flex items-center gap-2 flex-wrap">
          <EnrichmentTierBadge tier={data.confidence.enrichment_tier} />
          <OrphanBadge classification={orphanStatusLegacy} />
          {data.dependency_impact.level !== 'none_detected' && (
            <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold ${impactBadge.cls}`}>
              {impactBadge.label}
            </span>
          )}
        </div>
      </div>

      {/* Dependency Impact Banner */}
      {data.dependency_impact.level === 'high' && (
        <div className="bg-red-50 border border-red-200 rounded-lg px-4 py-3">
          <p className="text-xs font-bold text-red-800 uppercase mb-1">Deletion Impact Warning</p>
          <p className="text-xs text-red-700 whitespace-pre-line">{data.dependency_impact.statement}</p>
        </div>
      )}

      {/* 2x2 Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <WorkloadAssociationsPanel bindings={allBindings as any} />
        <FederatedMappingsPanel mappings={data.federated_credentials as any} />
        <RoleTopologyPanel topology={roleTopologyLegacy} />
        <OwnerGraphPanel appReg={appRegLegacy} objectId={data.identity_id} clientId={data.identity_id} />
      </div>

      {/* Sign-in enrichment summary */}
      {data.sign_in && (
        <div className="bg-white border border-gray-200 rounded-lg px-4 py-3">
          <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider mb-2 flex items-center gap-2">
            <svg className="w-4 h-4 text-teal-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Sign-In Activity
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div>
              <p className="text-[10px] text-gray-500">Sign-In Type</p>
              <p className="text-xs font-medium text-gray-700">{data.sign_in.pattern.replace(/_/g, ' ')}</p>
            </div>
            <div>
              <p className="text-[10px] text-gray-500">Dormancy</p>
              <p className="text-xs font-medium text-gray-700">
                {data.sign_in.dormancy_days >= 0
                  ? `${data.sign_in.dormancy_days} days`
                  : 'Never signed in'}
              </p>
            </div>
            <div>
              <p className="text-[10px] text-gray-500">Last Sign-In</p>
              <p className="text-xs font-medium text-gray-700">
                {data.sign_in.last_sign_in
                  ? new Date(data.sign_in.last_sign_in).toLocaleDateString()
                  : '\u2014'}
              </p>
            </div>
            <div>
              <p className="text-[10px] text-gray-500">Confidence</p>
              <p className="text-xs font-medium text-gray-700 capitalize">{data.confidence.level}</p>
            </div>
          </div>
        </div>
      )}

      {/* Recommended Action */}
      {!!data.recommended_action.action_text && (
        <div className="bg-white border border-gray-200 rounded-lg px-4 py-3">
          <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">Recommended Action</h3>
          <div className={`px-3 py-2.5 rounded-lg border ${
            data.recommended_action.action === 'ORPHANED' ? 'bg-red-50 border-red-200' :
            data.recommended_action.action === 'AT_RISK'  ? 'bg-amber-50 border-amber-200' :
            data.recommended_action.action === 'STALE'    ? 'bg-amber-50 border-amber-200' :
            data.recommended_action.action === 'HEALTHY'  ? 'bg-green-50 border-green-200' :
                                                             'bg-blue-50 border-blue-200'
          }`}>
            <p className={`text-xs leading-relaxed ${
              data.recommended_action.action === 'ORPHANED' ? 'text-red-700' :
              data.recommended_action.action === 'AT_RISK'  ? 'text-amber-700' :
              data.recommended_action.action === 'STALE'    ? 'text-amber-700' :
              data.recommended_action.action === 'HEALTHY'  ? 'text-green-700' :
                                                               'text-blue-700'
            }`}>
              {data.recommended_action.action_text}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

export default LineageTab;
