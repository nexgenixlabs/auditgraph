import React from 'react';
import { Link } from 'react-router-dom';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine,
} from 'recharts';
import {
  type IdentityDetailsResponse,
  type Owner,
  type RoleIntelligence,
  type PimData,
  type TabId,
  TIER_CONFIG,
  formatDate,
  credentialCountdown,
  safeLower,
  DATA_EXPLANATIONS,
  DORMANT_LABELS,
  getDormantStatus,
} from './types';

export interface CorrelatedAccount {
  id: number;
  identity_id?: string;
  object_id: string;
  display_name: string;
  upn: string;
  account_type: string;
  enabled: boolean;
  deleted: boolean;
  is_zombie: boolean;
  risk_score: number;
  risk_level: string;
  privilege_tier: string;
  link_method: string;
  link_confidence: number;
  verified: boolean;
}

export interface CorrelatedAccountsData {
  human_identity: { id: number; display_name: string } | null;
  accounts: CorrelatedAccount[];
  zombie_persona: boolean;
}

export interface OverviewTabProps {
  identity: IdentityDetailsResponse['identity'];
  data: IdentityDetailsResponse;
  roles: any[];
  graphPermissions: any[];
  appRoles: any[];
  owners: Owner[];
  groupedRoles: { azure: any[]; entra: any[] };
  privilegeTier: { tier: number; reasons: string[] };
  effectiveScope: { subscriptions: string[]; resourceGroups: string[]; tenantWide: boolean; entraScopes: string[] };
  riskHistory: { run_id: number; date: string; risk_score: number; risk_level: string }[];
  correlatedAccounts: CorrelatedAccountsData | null;
  roleIntel: RoleIntelligence[];
  pimData: PimData | null;
  onTabChange: (tab: TabId) => void;
}

export default function OverviewTab({
  identity,
  data,
  roles,
  graphPermissions,
  appRoles,
  owners,
  groupedRoles,
  privilegeTier,
  effectiveScope,
  riskHistory,
  correlatedAccounts,
  roleIntel,
  pimData,
  onTabChange,
}: OverviewTabProps) {
  return (
    <div className="space-y-6">
      {/* Correlated Accounts / Zombie Warning */}
      {correlatedAccounts && correlatedAccounts.accounts.length > 1 && (
        <div>
          {correlatedAccounts.zombie_persona && (
            <div className="bg-red-50 border border-red-200 rounded-xl p-4 mb-3 flex items-start gap-3">
              <svg className="w-5 h-5 text-red-600 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
              <div>
                <div className="text-sm font-semibold text-red-800">Zombie Persona Detected</div>
                <div className="text-xs text-red-600 mt-1">
                  This identity is part of a zombie persona — a disabled account retains access via this correlated active account.
                  The human behind these accounts may still have access despite their primary account being disabled.
                </div>
              </div>
            </div>
          )}
          <div className="border rounded-xl p-4">
            <div className="text-sm font-semibold text-gray-900 mb-3 flex items-center gap-2">
              Correlated Accounts
              {correlatedAccounts.human_identity && (
                <span className="text-xs font-normal text-gray-500">
                  — {correlatedAccounts.human_identity.display_name}
                </span>
              )}
            </div>
            <div className="space-y-2">
              {correlatedAccounts.accounts.map((acct) => (
                <div key={acct.id} className="flex items-center gap-3 p-2 rounded-lg hover:bg-gray-50">
                  <Link to={`/identities/${acct.identity_id || acct.id}`} className="text-sm font-medium text-blue-600 hover:underline flex-1 min-w-0 truncate">
                    {acct.display_name || acct.upn || acct.object_id}
                  </Link>
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                    acct.account_type === 'privileged' ? 'bg-purple-100 text-purple-700' : 'bg-gray-100 text-gray-600'
                  }`}>
                    {acct.account_type}
                  </span>
                  {acct.enabled ? (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-green-100 text-green-700">Active</span>
                  ) : (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-red-100 text-red-700">
                      {acct.deleted ? 'Deleted' : 'Disabled'}
                    </span>
                  )}
                  {acct.is_zombie && (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-red-100 text-red-700">Zombie</span>
                  )}
                  {acct.risk_level && (
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                      acct.risk_level === 'critical' ? 'bg-red-100 text-red-700' :
                      acct.risk_level === 'high' ? 'bg-orange-100 text-orange-700' :
                      acct.risk_level === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                      'bg-green-100 text-green-700'
                    }`}>
                      {acct.risk_level}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Identity Security Posture — 4-quadrant view */}
      <div>
        <div className="text-sm font-semibold text-gray-900 mb-3">Identity Security Posture</div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {/* Activity — uses effective_last_used (MAX of observed + Azure sign-in) */}
          {(() => {
            const isConnector = !!identity.is_discovery_connector;

            // Demo safety fallback: connector is ALWAYS active (it's running right now)
            const effectiveLastUsed = isConnector
              ? (identity.effective_last_used || new Date().toISOString())
              : identity.effective_last_used;
            const effectiveLastUsedSource: string | null | undefined = isConnector
              ? (identity.effective_last_used_source || 'auditgraph')
              : identity.effective_last_used_source;

            const hasEffective = !!effectiveLastUsed;

            // Debug logging
            console.log('LAST_USED_DEBUG_UI', {
              effectiveLastUsed,
              effectiveLastUsedSource,
              isConnector,
              activity_status: identity.activity_status,
              raw_effective: identity.effective_last_used,
              raw_source: identity.effective_last_used_source,
            });

            // Override dormant status when effective_last_used exists OR connector
            let dormant = getDormantStatus(identity.activity_status || undefined);
            if (hasEffective || isConnector) dormant = 'no'; // Force "Active"
            const dcfg = DORMANT_LABELS[dormant];

            // Compute relative time label
            let lastUsedLabel = '';
            let sourceBadge: React.ReactNode = null;
            if (isConnector) {
              lastUsedLabel = 'Actively used by AuditGraph';
              sourceBadge = <span className="ml-1 px-1 py-0.5 rounded text-[8px] font-semibold bg-emerald-100 text-emerald-700">AG</span>;
            } else if (hasEffective) {
              if (effectiveLastUsedSource === 'inferred_federated') {
                // Federated identities: no Azure sign-in logs, infer from existence
                const fedType = (identity as any).federated_workload_type || '';
                const fedLabel = fedType === 'github_actions' ? 'GitHub Actions'
                  : fedType === 'aks' ? 'AKS'
                  : fedType === 'terraform' ? 'Terraform'
                  : 'federated credentials';
                lastUsedLabel = `Likely active (${fedLabel})`;
                sourceBadge = <span className="ml-1 px-1 py-0.5 rounded text-[8px] font-semibold bg-purple-100 text-purple-700">Inferred</span>;
              } else {
                const d = new Date(effectiveLastUsed!);
                const now = new Date();
                const diffDays = Math.floor((now.getTime() - d.getTime()) / (1000 * 60 * 60 * 24));
                if (diffDays === 0) lastUsedLabel = 'Last used: Today';
                else if (diffDays === 1) lastUsedLabel = 'Last used: Yesterday';
                else lastUsedLabel = `Last used: ${diffDays}d ago`;

                sourceBadge = effectiveLastUsedSource === 'auditgraph'
                  ? <span className="ml-1 px-1 py-0.5 rounded text-[8px] font-semibold bg-emerald-100 text-emerald-700">AG</span>
                  : <span className="ml-1 px-1 py-0.5 rounded text-[8px] font-semibold bg-blue-100 text-blue-700">Azure</span>;
              }
            } else {
              lastUsedLabel = 'No activity observed';
            }

            return (
              <div className="border rounded-xl p-4" title={dcfg.tooltip}>
                <div className="text-[10px] uppercase font-semibold text-gray-400 tracking-wider mb-2">Activity</div>
                <span className={`px-2 py-1 rounded-full text-xs font-semibold ${dcfg.color}`}>{dcfg.label}</span>
                <div className="text-[10px] text-gray-500 mt-2 flex items-center">
                  {lastUsedLabel}
                  {sourceBadge}
                </div>
              </div>
            );
          })()}

          {/* Credentials */}
          <div className="border rounded-xl p-4">
            <div className="text-[10px] uppercase font-semibold text-gray-400 tracking-wider mb-2">Credentials</div>
            {(identity.identity_category === 'human_user' || identity.identity_category === 'guest') ? (
              <span className="text-xs text-gray-400 italic">N/A (Entra ID auth)</span>
            ) : (
              <>
                <span className={`px-2 py-1 rounded-full text-xs font-semibold ${
                  safeLower(identity.credential_status) === 'expired' ? 'bg-red-100 text-red-700' :
                  safeLower(identity.credential_status) === 'expiring_soon' ? 'bg-orange-100 text-orange-700' :
                  safeLower(identity.credential_status) === 'valid' ? 'bg-green-100 text-green-700' :
                  'bg-gray-100 text-gray-500'
                }`}>
                  {identity.credential_status || 'No credentials'}
                </span>
                <div className="text-[10px] text-gray-500 mt-2">
                  {(identity.credential_count ?? 0)} secret{(identity.credential_count ?? 0) !== 1 ? 's' : ''}/cert{(identity.credential_count ?? 0) !== 1 ? 's' : ''}
                  {identity.credential_expiration && (
                    <span className="ml-1">· {credentialCountdown(identity.credential_expiration)}</span>
                  )}
                </div>
              </>
            )}
          </div>

          {/* Conditional Access */}
          <div className="border rounded-xl p-4">
            <div className="text-[10px] uppercase font-semibold text-gray-400 tracking-wider mb-2">CA Coverage</div>
            {identity.ca_coverage_status ? (
              <>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-1 rounded-full text-xs font-semibold ${
                    identity.ca_coverage_status === 'covered' ? 'bg-green-100 text-green-700' :
                    identity.ca_coverage_status === 'partial' ? 'bg-yellow-100 text-yellow-700' :
                    'bg-red-100 text-red-700'
                  }`}>
                    {identity.ca_coverage_status === 'covered' ? 'Covered' :
                     identity.ca_coverage_status === 'partial' ? 'Partial' : 'Not Covered'}
                  </span>
                </div>
                <div className="text-[10px] text-gray-500 mt-2">
                  {identity.ca_mfa_enforced ? 'MFA enforced' : 'No MFA requirement'}
                </div>
              </>
            ) : (
              <span className="text-xs text-gray-400 italic" title={DATA_EXPLANATIONS.CA_POLICY}>Unknown</span>
            )}
          </div>

          {/* PIM */}
          <div className="border rounded-xl p-4">
            <div className="text-[10px] uppercase font-semibold text-gray-400 tracking-wider mb-2">PIM</div>
            {pimData ? (
              <>
                <span className={`px-2 py-1 rounded-full text-xs font-semibold ${
                  pimData.eligible_assignments.length > 0 ? 'bg-emerald-100 text-emerald-700' : 'bg-gray-100 text-gray-500'
                }`}>
                  {pimData.eligible_assignments.length > 0 ? `${pimData.eligible_assignments.length} eligible` : 'None'}
                </span>
                {pimData.overuse_metrics.always_active_pattern && (
                  <div className="text-[10px] text-red-600 mt-2 font-medium">Always-active pattern detected</div>
                )}
              </>
            ) : (
              <button
                onClick={() => onTabChange('pim')}
                className="text-xs text-blue-600 hover:underline"
              >
                Load PIM data
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Risk Score Trajectory */}
      {riskHistory.length >= 2 && (
        <div className="border border-gray-200 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <div>
              <div className="text-sm font-semibold text-gray-900">Risk Score Trajectory</div>
              <div className="text-[10px] text-gray-500">Score trend across snapshots</div>
            </div>
            <div className="flex items-center gap-2 text-[10px] text-gray-500">
              <span>{riskHistory.length} runs</span>
              <span className="text-gray-300">|</span>
              <span>
                {riskHistory[0].risk_score} pts → {riskHistory[riskHistory.length - 1].risk_score} pts
                {riskHistory[riskHistory.length - 1].risk_score > riskHistory[0].risk_score
                  ? <span className="text-red-500 ml-1">↑</span>
                  : riskHistory[riskHistory.length - 1].risk_score < riskHistory[0].risk_score
                    ? <span className="text-green-500 ml-1">↓</span>
                    : <span className="text-gray-400 ml-1">→</span>
                }
              </span>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={160}>
            <LineChart data={riskHistory} margin={{ top: 5, right: 10, left: -15, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
              <XAxis
                dataKey="date"
                tick={{ fontSize: 9, fill: '#9ca3af' }}
                tickFormatter={(d: string) => {
                  try { return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }); } catch { return ''; }
                }}
              />
              <YAxis tick={{ fontSize: 9, fill: '#9ca3af' }} domain={[0, 'auto']} allowDecimals={false} />
              <ReferenceLine y={70} stroke="#ef4444" strokeDasharray="3 3" strokeOpacity={0.4} label={{ value: 'Critical', fontSize: 8, fill: '#ef4444' }} />
              <Tooltip
                content={({ active, payload }) => {
                  if (!active || !payload?.length) return null;
                  const p = payload[0]?.payload as {date: string; risk_score: number; risk_level: string} | undefined;
                  if (!p) return null;
                  const levelColor: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
                  return (
                    <div className="bg-white border rounded-lg shadow-lg px-3 py-2 text-xs">
                      <div className="text-gray-500 mb-1">
                        {(() => { try { return new Date(p.date).toLocaleDateString(); } catch { return p.date; } })()}
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: levelColor[p.risk_level] || '#6b7280' }} />
                        <span className="font-semibold">{p.risk_score}</span>
                        <span className="capitalize text-gray-400">{p.risk_level}</span>
                      </div>
                    </div>
                  );
                }}
              />
              <Line
                type="monotone"
                dataKey="risk_score"
                stroke="#7c3aed"
                strokeWidth={2}
                dot={{ r: 3, fill: '#7c3aed', strokeWidth: 0 }}
                activeDot={{ r: 5, fill: '#7c3aed' }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Privilege Tier Explanation */}
      {(() => {
        const tc = TIER_CONFIG[privilegeTier.tier];
        return (
          <div className={`border rounded-xl p-4 ${tc.borderColor}`}>
            <div className="flex items-center gap-3 mb-2">
              <span className={`px-2.5 py-1 rounded-full border text-sm font-bold ${tc.color}`}>{tc.label}</span>
              <div>
                <div className="text-sm font-semibold text-gray-900">{tc.name}</div>
                <div className="text-xs text-gray-500">{tc.description}</div>
              </div>
            </div>
            {privilegeTier.reasons.length > 0 && (
              <div className="mt-2 space-y-1">
                <div className="text-[10px] uppercase font-semibold text-gray-400 tracking-wider">Classification reasons</div>
                {privilegeTier.reasons.map((r, i) => (
                  <div key={i} className="text-xs text-gray-600 flex items-center gap-1.5">
                    <span className="w-1 h-1 rounded-full bg-gray-400 flex-shrink-0" />
                    {r}
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })()}

      {/* Effective Access Scope */}
      {(effectiveScope.subscriptions.length > 0 || effectiveScope.entraScopes.length > 0 || (data?.roles || []).length > 0) && (
        <div>
          <div className="text-sm font-semibold text-gray-900 mb-3">Effective Access Scope</div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* Entra Directory */}
            <div className="bg-indigo-50 border border-indigo-200 rounded-xl p-4">
              <div className="text-[10px] uppercase font-semibold text-indigo-400 tracking-wider mb-2">Entra Directory</div>
              <div className="text-lg font-bold text-indigo-700">{groupedRoles.entra.length} role{groupedRoles.entra.length !== 1 ? 's' : ''}</div>
              <div className="text-[10px] text-gray-500 mt-1">
                {effectiveScope.tenantWide
                  ? <span className="text-red-600 font-medium">Tenant-wide scope</span>
                  : effectiveScope.entraScopes.length > 0
                    ? `${effectiveScope.entraScopes.length} scoped`
                    : 'No Entra roles'
                }
              </div>
            </div>

            {/* Azure RBAC */}
            <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
              <div className="text-[10px] uppercase font-semibold text-blue-400 tracking-wider mb-2">Azure RBAC</div>
              <div className="text-lg font-bold text-blue-700">{groupedRoles.azure.length} role{groupedRoles.azure.length !== 1 ? 's' : ''}</div>
              <div className="text-[10px] text-gray-500 mt-1">
                {effectiveScope.subscriptions.length > 0
                  ? `${effectiveScope.subscriptions.length} sub${effectiveScope.subscriptions.length !== 1 ? 's' : ''}, ${effectiveScope.resourceGroups.length} RG${effectiveScope.resourceGroups.length !== 1 ? 's' : ''}`
                  : 'No RBAC roles'
                }
              </div>
            </div>

            {/* Graph API */}
            <div className="bg-purple-50 border border-purple-200 rounded-xl p-4">
              <div className="text-[10px] uppercase font-semibold text-purple-400 tracking-wider mb-2">Graph API</div>
              <div className="text-lg font-bold text-purple-700">{identity.api_permission_count ?? 0} perm{(identity.api_permission_count ?? 0) !== 1 ? 's' : ''}</div>
              <div className="text-[10px] text-gray-500 mt-1">
                {(identity.app_role_count ?? 0) > 0 ? `+ ${identity.app_role_count} app role${(identity.app_role_count ?? 0) !== 1 ? 's' : ''}` : 'Application-level access'}
              </div>
            </div>
          </div>

          {/* Scope details */}
          {effectiveScope.subscriptions.length > 0 && (
            <div className="mt-3 text-xs text-gray-500">
              <span className="font-medium text-gray-700">Subscriptions:</span>{' '}
              {effectiveScope.subscriptions.map((s, i) => (
                <span key={s}>
                  <span className="font-mono text-gray-600">{s.substring(0, 8)}...</span>
                  {i < effectiveScope.subscriptions.length - 1 && ', '}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Quick stats grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <button onClick={() => onTabChange('roles')} className="bg-gray-50 rounded-xl p-4 text-center hover:bg-gray-100 transition">
          <div className="text-2xl font-bold text-gray-900">{(data?.roles || []).length}</div>
          <div className="text-xs text-gray-500 mt-1">Total Roles</div>
        </button>
        <button onClick={() => onTabChange('permissions')} className="bg-gray-50 rounded-xl p-4 text-center hover:bg-gray-100 transition">
          <div className="text-2xl font-bold text-purple-700">{identity.api_permission_count ?? 0}</div>
          <div className="text-xs text-gray-500 mt-1">API Permissions</div>
        </button>
        <button onClick={() => onTabChange('credentials')} className="bg-gray-50 rounded-xl p-4 text-center hover:bg-gray-100 transition">
          <div className="text-2xl font-bold text-gray-900">{identity.credential_count ?? 0}</div>
          <div className="text-xs text-gray-500 mt-1">Credentials</div>
        </button>
        <button onClick={() => onTabChange('ownership')} className="bg-gray-50 rounded-xl p-4 text-center hover:bg-gray-100 transition">
          <div className="text-2xl font-bold text-gray-900">{(data?.owners || []).length}</div>
          <div className="text-xs text-gray-500 mt-1">Owners</div>
        </button>
      </div>

      {/* Risk reasons */}
      <div>
        <div className="text-sm font-semibold text-gray-900 mb-2">Risk Reasons</div>
        {identity.risk_reasons && identity.risk_reasons.length > 0 ? (
          <ul className="space-y-2">
            {identity.risk_reasons.map((r, idx) => (
              <li key={idx} className="flex items-start gap-2 text-sm text-gray-700">
                <span className="text-red-500 mt-0.5">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                </span>
                {r}
              </li>
            ))}
          </ul>
        ) : (
          <div className="text-sm text-gray-500">No risk reasons recorded.</div>
        )}
      </div>
    </div>
  );
}
