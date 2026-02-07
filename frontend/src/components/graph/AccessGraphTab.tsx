import React, { useEffect, useState, useMemo } from 'react';
import { ReactFlow, Controls, Background, MiniMap } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { nodeTypes } from './nodes';

type ViewMode = 'executive' | 'technical';

interface GraphDataResponse {
  identity_id: string;
  display_name: string;
  risk_level: string;
  risk_score: number;
  trust_relationships: {
    federated_trusts: Array<{
      credential_id: number;
      issuer: string;
      subject: string;
      issuer_label: string;
      trust_risk: string;
      trust_reason: string;
    }>;
    ownership_edges: Array<{
      owner_object_id: string;
      owner_display_name: string;
      owner_upn?: string;
      owner_type: string;
      is_primary_owner: boolean;
    }>;
    role_edges: Array<{
      role_name: string;
      role_type: string;
      scope: string;
      scope_type: string;
      risk_level: string;
      usage_status: string;
    }>;
  };
  effective_scope: {
    subscription_count: number;
    resource_group_count: number;
    resource_count: number;
    scope_hierarchy: Array<{
      subscription_id: string;
      resource_groups: Array<{
        name: string;
        roles: string[];
        resources: Array<{ type: string; name: string }>;
      }>;
      subscription_level_roles: string[];
    }>;
    entra_scopes: Array<{
      role_name: string;
      directory_scope: string;
      scope_label: string;
      risk_level: string;
    }>;
    blast_radius_label: string;
  };
  secret_exposure: Array<{
    credential_id: number;
    credential_type: string;
    display_name?: string;
    age_days?: number;
    days_to_expiry?: number;
    status: string;
    issuer?: string;
    subject?: string;
    issuer_label?: string;
    exposure_flags: string[];
    exposure_risk: string;
  }>;
  graph: {
    executive_nodes: any[];
    executive_edges: any[];
    technical_nodes: any[];
    technical_edges: any[];
  };
}

const riskBadgeColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-green-100 text-green-700',
  info: 'bg-blue-100 text-blue-700',
};

function RiskBadge({ level }: { level: string }) {
  const c = riskBadgeColors[level] || 'bg-gray-100 text-gray-600';
  return <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${c}`}>{level}</span>;
}

function CollapsiblePanel({ title, count, defaultOpen, children }: { title: string; count?: number; defaultOpen?: boolean; children: React.ReactNode }) {
  const [open, setOpen] = useState(defaultOpen ?? true);
  return (
    <div className="bg-white border rounded-xl overflow-hidden">
      <button onClick={() => setOpen(!open)} className="w-full px-5 py-3 flex items-center justify-between bg-gray-50 hover:bg-gray-100 transition">
        <div className="flex items-center gap-2">
          <svg className={`w-4 h-4 text-gray-500 transition-transform ${open ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
          <span className="text-sm font-semibold text-gray-900">{title}</span>
          {count != null && count > 0 && (
            <span className="px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-blue-100 text-blue-700">{count}</span>
          )}
        </div>
      </button>
      {open && <div className="px-5 py-4">{children}</div>}
    </div>
  );
}

// ── Trust Relationships Panel ─────────────────────────────────
function TrustPanel({ data }: { data: GraphDataResponse['trust_relationships'] }) {
  const hasFed = data.federated_trusts.length > 0;
  const hasOwners = data.ownership_edges.length > 0;

  if (!hasFed && !hasOwners) {
    return <div className="text-sm text-gray-500">No federated trusts or ownership data found.</div>;
  }

  return (
    <div className="space-y-4">
      {hasFed && (
        <div>
          <h4 className="text-xs font-semibold text-gray-700 uppercase mb-2">Federated Trusts</h4>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr className="text-left text-gray-500 border-b">
                <th className="pb-1.5 pr-4">Issuer</th>
                <th className="pb-1.5 pr-4">Subject</th>
                <th className="pb-1.5 pr-4">Risk</th>
                <th className="pb-1.5">Reason</th>
              </tr></thead>
              <tbody>
                {data.federated_trusts.map((ft, i) => (
                  <tr key={i} className="border-b border-gray-100">
                    <td className="py-2 pr-4 font-medium text-gray-900">{ft.issuer_label}</td>
                    <td className="py-2 pr-4 text-gray-600 max-w-[200px] truncate" title={ft.subject}>{ft.subject}</td>
                    <td className="py-2 pr-4"><RiskBadge level={ft.trust_risk} /></td>
                    <td className="py-2 text-gray-600">{ft.trust_reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {hasOwners && (
        <div>
          <h4 className="text-xs font-semibold text-gray-700 uppercase mb-2">Ownership</h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {data.ownership_edges.map((o, i) => (
              <div key={i} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-green-50 border border-green-200">
                <svg className="w-4 h-4 text-green-600 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5.121 17.804A13.937 13.937 0 0112 16c2.5 0 4.847.655 6.879 1.804M15 10a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
                <div className="min-w-0">
                  <div className="text-xs font-medium text-gray-900 truncate">{o.owner_display_name}</div>
                  <div className="text-[10px] text-gray-500 truncate">{o.owner_upn || o.owner_type}{o.is_primary_owner ? ' (primary)' : ''}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Effective Scope Panel ─────────────────────────────────────
function ScopePanel({ data }: { data: GraphDataResponse['effective_scope'] }) {
  return (
    <div className="space-y-4">
      {/* Blast radius summary bar */}
      <div className="flex items-center gap-4 px-4 py-3 rounded-lg bg-purple-50 border border-purple-200">
        <svg className="w-5 h-5 text-purple-600 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        <div>
          <div className="text-xs font-bold text-purple-800 uppercase">Blast Radius</div>
          <div className="text-sm font-medium text-gray-900">{data.blast_radius_label}</div>
        </div>
        <div className="flex items-center gap-3 ml-auto">
          {data.subscription_count > 0 && (
            <div className="text-center">
              <div className="text-lg font-bold text-purple-700">{data.subscription_count}</div>
              <div className="text-[9px] text-gray-500">Subs</div>
            </div>
          )}
          {data.resource_group_count > 0 && (
            <div className="text-center">
              <div className="text-lg font-bold text-purple-600">{data.resource_group_count}</div>
              <div className="text-[9px] text-gray-500">RGs</div>
            </div>
          )}
          {data.resource_count > 0 && (
            <div className="text-center">
              <div className="text-lg font-bold text-purple-500">{data.resource_count}</div>
              <div className="text-[9px] text-gray-500">Resources</div>
            </div>
          )}
        </div>
      </div>

      {/* Scope hierarchy tree */}
      {data.scope_hierarchy.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold text-gray-700 uppercase mb-2">Azure RBAC Scope Hierarchy</h4>
          <div className="space-y-2">
            {data.scope_hierarchy.map((sub, si) => (
              <div key={si} className="border rounded-lg p-3">
                <div className="flex items-center gap-2 mb-2">
                  <svg className="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
                  </svg>
                  <span className="text-xs font-medium text-gray-900">Subscription: {sub.subscription_id.substring(0, 8)}...</span>
                  {sub.subscription_level_roles.length > 0 && (
                    <span className="text-[10px] text-red-600 font-semibold">
                      Sub-level: {sub.subscription_level_roles.join(', ')}
                    </span>
                  )}
                </div>
                {sub.resource_groups.map((rg, ri) => (
                  <div key={ri} className="ml-6 py-1.5 border-l-2 border-gray-200 pl-3 mb-1">
                    <div className="flex items-center gap-1.5">
                      <svg className="w-3 h-3 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                      </svg>
                      <span className="text-[11px] font-medium text-gray-800">{rg.name}</span>
                      <span className="text-[9px] text-gray-500">({rg.roles.join(', ')})</span>
                    </div>
                    {rg.resources.length > 0 && (
                      <div className="ml-4 mt-1 space-y-0.5">
                        {rg.resources.map((res, resI) => (
                          <div key={resI} className="text-[10px] text-gray-500">
                            {res.type} / <span className="font-medium text-gray-700">{res.name}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Entra scopes */}
      {data.entra_scopes.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold text-gray-700 uppercase mb-2">Entra Directory Scopes</h4>
          <div className="space-y-1.5">
            {data.entra_scopes.map((es, i) => (
              <div key={i} className="flex items-center justify-between px-3 py-2 rounded-lg bg-gray-50 border">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium text-gray-900">{es.role_name}</span>
                  <span className="text-[10px] text-gray-500">{es.scope_label}</span>
                </div>
                <RiskBadge level={es.risk_level} />
              </div>
            ))}
          </div>
        </div>
      )}

      {data.scope_hierarchy.length === 0 && data.entra_scopes.length === 0 && (
        <div className="text-sm text-gray-500">No scoped access found.</div>
      )}
    </div>
  );
}

// ── Secret Exposure Panel ─────────────────────────────────────
function ExposurePanel({ data }: { data: GraphDataResponse['secret_exposure'] }) {
  if (data.length === 0) {
    return <div className="text-sm text-gray-500">No credentials found for this identity.</div>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead><tr className="text-left text-gray-500 border-b">
          <th className="pb-1.5 pr-3">Type</th>
          <th className="pb-1.5 pr-3">Name</th>
          <th className="pb-1.5 pr-3">Age</th>
          <th className="pb-1.5 pr-3">Expiry</th>
          <th className="pb-1.5 pr-3">Status</th>
          <th className="pb-1.5 pr-3">Risk</th>
          <th className="pb-1.5">Exposure Flags</th>
        </tr></thead>
        <tbody>
          {data.map((c, i) => {
            const rowBg = c.exposure_risk === 'critical' ? 'bg-red-50' :
                          c.exposure_risk === 'high' ? 'bg-orange-50' : '';
            return (
              <tr key={i} className={`border-b border-gray-100 ${rowBg}`}>
                <td className="py-2 pr-3">
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-gray-200 text-gray-700">
                    {c.credential_type === 'secret' ? 'Secret' : c.credential_type === 'certificate' ? 'Cert' : 'Federated'}
                  </span>
                </td>
                <td className="py-2 pr-3 font-medium text-gray-900 max-w-[150px] truncate">{c.display_name || '(unnamed)'}</td>
                <td className="py-2 pr-3 text-gray-600">{c.age_days != null ? `${c.age_days}d` : '--'}</td>
                <td className="py-2 pr-3 text-gray-600">
                  {c.days_to_expiry != null ? (
                    c.days_to_expiry < 0 ? <span className="text-red-600 font-semibold">Expired</span> :
                    `${c.days_to_expiry}d`
                  ) : c.credential_type === 'federated' ? 'N/A' : '--'}
                </td>
                <td className="py-2 pr-3">
                  <span className={`text-[10px] font-medium ${
                    c.status === 'expired' ? 'text-red-600' :
                    c.status === 'expiring_soon' ? 'text-orange-600' : 'text-green-600'
                  }`}>{c.status}</span>
                </td>
                <td className="py-2 pr-3"><RiskBadge level={c.exposure_risk} /></td>
                <td className="py-2">
                  <div className="flex flex-wrap gap-1">
                    {c.exposure_flags.map((flag, fi) => (
                      <span key={fi} className="px-1.5 py-0.5 rounded text-[9px] bg-gray-100 text-gray-700 border">{flag}</span>
                    ))}
                    {c.exposure_flags.length === 0 && <span className="text-gray-400">No issues</span>}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── Main Access Graph Tab ─────────────────────────────────────
export default function AccessGraphTab({ identityId }: { identityId: string }) {
  const [data, setData] = useState<GraphDataResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [viewMode, setViewMode] = useState<ViewMode>('executive');

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError('');
    fetch(`http://localhost:5001/api/identities/${encodeURIComponent(identityId)}/graph-data`)
      .then(res => {
        if (!res.ok) throw new Error(`API error: ${res.status}`);
        return res.json();
      })
      .then(json => { if (!cancelled) setData(json); })
      .catch(e => { if (!cancelled) setError(e?.message || 'Failed to load graph data'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [identityId]);

  const nodes = useMemo(() => {
    if (!data) return [];
    return viewMode === 'executive' ? data.graph.executive_nodes : data.graph.technical_nodes;
  }, [data, viewMode]);

  const edges = useMemo(() => {
    if (!data) return [];
    return viewMode === 'executive' ? data.graph.executive_edges : data.graph.technical_edges;
  }, [data, viewMode]);

  const trustCount = (data?.trust_relationships.federated_trusts.length ?? 0) +
                     (data?.trust_relationships.ownership_edges.length ?? 0);
  const exposureCount = data?.secret_exposure.filter(s => s.exposure_flags.length > 0).length ?? 0;

  if (loading) {
    return (
      <div className="space-y-4 animate-pulse">
        <div className="h-10 bg-gray-100 rounded-lg w-64" />
        <div className="h-[450px] bg-gray-100 rounded-xl" />
        <div className="h-40 bg-gray-100 rounded-xl" />
      </div>
    );
  }

  if (error) {
    return <div className="bg-white border rounded-xl p-6 text-red-600">{error}</div>;
  }

  if (!data) return null;

  return (
    <div className="space-y-4">
      {/* View Mode Toggle */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1 bg-gray-100 rounded-lg p-0.5">
          <button
            onClick={() => setViewMode('executive')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition ${
              viewMode === 'executive' ? 'bg-white text-blue-700 shadow-sm' : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            Executive Risk Story
          </button>
          <button
            onClick={() => setViewMode('technical')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition ${
              viewMode === 'technical' ? 'bg-white text-blue-700 shadow-sm' : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            Technical Trust Graph
          </button>
        </div>
        <span className="text-[10px] text-gray-500">
          {viewMode === 'executive' ? 'Simplified view for risk communication' : 'Full relationship graph with all edges'}
        </span>
      </div>

      {/* Graph Canvas */}
      <div className="border rounded-xl overflow-hidden bg-gray-50" style={{ height: 450 }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.3 }}
          minZoom={0.3}
          maxZoom={2}
          proOptions={{ hideAttribution: true }}
          defaultEdgeOptions={{
            type: 'smoothstep',
            style: { stroke: '#94a3b8', strokeWidth: 1.5 },
            labelStyle: { fontSize: 10, fill: '#64748b' },
          }}
        >
          <Controls position="bottom-right" showInteractive={false} />
          <Background gap={20} size={1} color="#e2e8f0" />
          {viewMode === 'technical' && <MiniMap pannable zoomable nodeStrokeWidth={3} />}
        </ReactFlow>
      </div>

      {/* Detail Panels */}
      <CollapsiblePanel title="Trust Relationships" count={trustCount} defaultOpen={trustCount > 0}>
        <TrustPanel data={data.trust_relationships} />
      </CollapsiblePanel>

      <CollapsiblePanel title="Effective Scope" count={data.effective_scope.subscription_count + data.effective_scope.entra_scopes.length}>
        <ScopePanel data={data.effective_scope} />
      </CollapsiblePanel>

      <CollapsiblePanel title="Secret Exposure Intelligence" count={exposureCount} defaultOpen={exposureCount > 0}>
        <ExposurePanel data={data.secret_exposure} />
      </CollapsiblePanel>
    </div>
  );
}
