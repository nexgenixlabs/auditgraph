import React, { useEffect, useState } from 'react';
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
import { OWNER_STATUS_CONFIG, TIME_MS } from '../../constants/metrics';
import { normalizeScore } from '../../utils/identityRiskScore';

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

// ── Compute Findings inline component (FIX 5) ──
const FINDING_SEVERITY: Record<string, { cls: string; label: string }> = {
  CRITICAL: { cls: 'bg-red-100 text-red-700', label: 'Critical' },
  HIGH:     { cls: 'bg-orange-100 text-orange-700', label: 'High' },
  MEDIUM:   { cls: 'bg-yellow-100 text-yellow-700', label: 'Medium' },
  LOW:      { cls: 'bg-blue-100 text-blue-700', label: 'Low' },
};

function ComputeFindings({ identityId }: { identityId: string }) {
  const [findings, setFindings] = useState<any[]>([]);
  useEffect(() => {
    if (!identityId) return;
    fetch(`/api/identities/${identityId}/compute-findings`)
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d?.findings?.length) setFindings(d.findings); })
      .catch(() => {});
  }, [identityId]);

  if (!findings.length) return null;
  return (
    <div className="bg-amber-50 border border-amber-200 rounded-xl p-4">
      <div className="text-sm font-semibold text-amber-900 mb-2 flex items-center gap-2">
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
        Compute Findings ({findings.length})
      </div>
      <div className="space-y-2">
        {findings.map((f: any, i: number) => {
          const sev = FINDING_SEVERITY[f.severity] || FINDING_SEVERITY.MEDIUM;
          return (
            <div key={i} className="flex items-start gap-2 text-sm">
              <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium ${sev.cls} shrink-0`}>
                {sev.label}
              </span>
              <span className="text-gray-800">{f.title}</span>
              {!!f.resource && <span className="text-gray-400 text-xs ml-auto shrink-0">{f.resource}</span>}
            </div>
          );
        })}
      </div>
    </div>
  );
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
          {/* Activity — canonical state from build_identity_state() */}
          {(() => {
            const isConnector = !!identity.is_discovery_connector;
            const authActivity = (identity as any).auth_activity;
            const hasCanonicalState = !!(identity as any).activity_label && !!authActivity;

            // Use canonical state from backend when available
            if (hasCanonicalState && !isConnector) {
              const anyActivity = authActivity?.any_activity_observed;
              const activityLabel = (identity as any).activity_label as string;
              const activityDetail = (identity as any).activity_detail as string;
              const isDormant = (identity as any).is_dormant;
              const confidence = authActivity?.confidence || 'none';

              const badgeColor = anyActivity
                ? 'bg-green-100 text-green-700'
                : 'bg-gray-100 text-gray-500';
              const badgeLabel = isDormant ? 'Dormant' : (anyActivity ? 'Active' : 'Unknown');

              // Source badge based on which signal
              let sourceBadge: React.ReactNode = null;
              if (authActivity?.interactive_signin) {
                sourceBadge = <span className="ml-1 px-1 py-0.5 rounded text-[8px] font-semibold bg-blue-100 text-blue-700">Sign-in</span>;
              } else if (authActivity?.arm_activity) {
                sourceBadge = <span className="ml-1 px-1 py-0.5 rounded text-[8px] font-semibold bg-emerald-100 text-emerald-700">ARM</span>;
              } else if (authActivity?.non_interactive_signin) {
                sourceBadge = <span className="ml-1 px-1 py-0.5 rounded text-[8px] font-semibold bg-blue-100 text-blue-700">Non-interactive</span>;
              } else if (authActivity?.lineage_activity) {
                sourceBadge = <span className="ml-1 px-1 py-0.5 rounded text-[8px] font-semibold bg-purple-100 text-purple-700">Lineage</span>;
              } else if (authActivity?.token_usage) {
                sourceBadge = <span className="ml-1 px-1 py-0.5 rounded text-[8px] font-semibold bg-cyan-100 text-cyan-700">Token</span>;
              }

              return (
                <div className="border rounded-xl p-4 relative group" title={activityDetail}>
                  <div className="text-[10px] uppercase font-semibold text-gray-400 tracking-wider mb-2">Activity</div>
                  <span className={`px-2 py-1 rounded-full text-xs font-semibold ${badgeColor}`}>{badgeLabel}</span>
                  <div className="text-[10px] text-gray-500 mt-2 flex items-center">
                    {activityDetail}
                    {sourceBadge}
                  </div>
                  {confidence === 'inferred' && (
                    <div className="text-[9px] text-gray-400 mt-1">Confidence: Inferred</div>
                  )}
                  {!anyActivity && (
                    <div className="text-[9px] text-gray-400 mt-1">Log-independent mode — activity inferred from static analysis</div>
                  )}
                </div>
              );
            }

            // Legacy fallback: connector or no canonical state
            const effectiveLastUsed = isConnector
              ? (identity.effective_last_used || new Date().toISOString())
              : identity.effective_last_used;
            const effectiveLastUsedSource: string | null | undefined = isConnector
              ? (identity.effective_last_used_source || 'auditgraph')
              : identity.effective_last_used_source;

            const hasEffective = !!effectiveLastUsed;
            const isFederatedInferred = effectiveLastUsedSource === 'inferred_federated';

            let dormant = getDormantStatus(identity.activity_status || undefined);
            if (isConnector || (hasEffective && !isFederatedInferred)) dormant = 'no';
            if (isFederatedInferred) dormant = 'likely_active';
            const dcfg = DORMANT_LABELS[dormant];

            let lastUsedLabel = '';
            let sourceBadge: React.ReactNode = null;
            if (isConnector) {
              lastUsedLabel = 'Actively used by AuditGraph';
              sourceBadge = <span className="ml-1 px-1 py-0.5 rounded text-[8px] font-semibold bg-emerald-100 text-emerald-700">AG</span>;
            } else if (isFederatedInferred) {
              const fedType = (identity as any).federated_workload_type || '';
              const fedLabel = fedType === 'github_actions' ? 'GitHub Actions'
                : fedType === 'aks' ? 'AKS'
                : fedType === 'terraform' ? 'Terraform'
                : 'federated workload';
              lastUsedLabel = `No Azure logs \u2014 inferred from ${fedLabel}`;
              sourceBadge = <span className="ml-1 px-1 py-0.5 rounded text-[8px] font-semibold bg-purple-100 text-purple-700">Inferred</span>;
            } else if (hasEffective) {
              const d = new Date(effectiveLastUsed!);
              const now = new Date();
              const diffDays = Math.floor((now.getTime() - d.getTime()) / TIME_MS.DAY);
              if (diffDays === 0) lastUsedLabel = 'Last used: Today';
              else if (diffDays === 1) lastUsedLabel = 'Last used: Yesterday';
              else lastUsedLabel = `Last used: ${diffDays}d ago`;
              sourceBadge = effectiveLastUsedSource === 'auditgraph'
                ? <span className="ml-1 px-1 py-0.5 rounded text-[8px] font-semibold bg-emerald-100 text-emerald-700">AG</span>
                : <span className="ml-1 px-1 py-0.5 rounded text-[8px] font-semibold bg-blue-100 text-blue-700">Azure</span>;
            } else {
              lastUsedLabel = 'No activity observed';
            }

            return (
              <div className="border rounded-xl p-4 relative group" title={dcfg.tooltip}>
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

          {/* Ownership */}
          <div className="border rounded-xl p-4">
            <div className="text-[10px] uppercase font-semibold text-gray-400 tracking-wider mb-2">Ownership</div>
            {(() => {
              const os = (identity as any).owner_status;
              const cfg = OWNER_STATUS_CONFIG[os] ?? OWNER_STATUS_CONFIG['unknown'];
              return <span className={`px-2 py-1 rounded-full text-xs font-semibold ${cfg.badgeClass}`}>{cfg.label}</span>;
            })()}
            <div className="text-[10px] text-gray-500 mt-2">{identity.owner_count || 0} owner(s)</div>
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

      {/* Rule 4: Activity Source panel — shows data source hierarchy */}
      {!!(identity as any).activity_sources && (
        <div className="border border-gray-200 rounded-xl p-4">
          <div className="text-sm font-semibold text-gray-900 mb-2">Activity Source</div>
          <div className="space-y-1.5">
            {((identity as any).activity_sources as Array<{ type: string; label: string; available: boolean; detail?: string }>).map((src) => (
              <div key={src.type} className="flex items-center gap-2 text-xs">
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${src.available ? 'bg-green-500' : 'bg-gray-300'}`} />
                <span className={src.available ? 'text-gray-800' : 'text-gray-400'}>{src.label}</span>
                {src.available && <span className="text-[10px] text-green-600 font-medium">Available</span>}
                {!src.available && <span className="text-[10px] text-gray-400">Not available</span>}
                {!!src.detail && <span className="text-[10px] text-purple-600 ml-1">— {src.detail}</span>}
              </div>
            ))}
          </div>
          {!!(identity as any).federated_workload_type && (
            <div className="mt-3 p-2 bg-purple-50 border border-purple-100 rounded-lg text-[10px] text-purple-700">
              Azure does not emit sign-in logs for federated identities (GitHub, AKS, Terraform).
              Activity is inferred based on configuration and role usage.
            </div>
          )}
        </div>
      )}

      {/* Auth Activity Breakdown — structured view from canonical state */}
      {!!(identity as any).auth_activity && (
        <div className="border border-gray-200 rounded-xl p-4">
          <div className="text-sm font-semibold text-gray-900 mb-2">Auth Activity Breakdown</div>
          <table className="w-full text-xs">
            <tbody>
              {[
                { label: 'Interactive sign-in', key: 'interactive_signin', unavailableNote: 'Log-independent mode' },
                { label: 'Non-interactive sign-in', key: 'non_interactive_signin', unavailableNote: 'Log-independent mode' },
                { label: 'ARM deployment activity', key: 'arm_activity', unavailableNote: '' },
                { label: 'Token issuance', key: 'token_usage', unavailableNote: 'Log-independent mode' },
                { label: 'Lineage activity', key: 'lineage_activity', unavailableNote: '' },
                { label: 'AuditGraph scan observed', key: 'auditgraph_scan', unavailableNote: '' },
              ].map(({ label, key, unavailableNote }) => {
                const auth = (identity as any).auth_activity;
                const observed = auth?.[key];
                return (
                  <tr key={key} className="border-b border-gray-100 last:border-0">
                    <td className="py-1.5 pr-3 text-gray-600">{label}</td>
                    <td className="py-1.5">
                      {observed ? (
                        <span className="text-green-700 font-medium">Observed</span>
                      ) : unavailableNote ? (
                        <span className="text-gray-400">Not available · {unavailableNote}</span>
                      ) : (
                        <span className="text-gray-400">Not observed</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <div className="mt-2 text-[10px] text-gray-400">
            Data confidence: {(identity as any).auth_activity?.confidence || 'none'}
            {(identity as any).is_dormant === false && (identity as any).auth_activity?.any_activity_observed && (
              <span className="ml-2 text-green-600 font-medium">Dormancy: Active</span>
            )}
            {(identity as any).is_dormant === true && (
              <span className="ml-2 text-orange-600 font-medium">Dormancy: Dormant</span>
            )}
          </div>
        </div>
      )}

      {/* Activity source mismatch warning — identity authenticated but
          no role-scoped activity detected. Same visual style as the
          "No owners assigned" amber banner. */}
      {!!(identity as any).activity_mismatch_warning && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex items-start gap-3">
          <svg className="w-5 h-5 text-amber-600 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div>
            <div className="text-sm font-semibold text-amber-800">Activity Source Mismatch</div>
            <div className="text-xs text-amber-600 mt-1">{(identity as any).activity_mismatch_warning}</div>
          </div>
        </div>
      )}

      {/* Rule 6: Active Access hints for federated identities */}
      {!!((identity as any).federated_active_access as Array<{ role: string; scope: string; scope_type: string }> | undefined)?.length && (
        <div className="border border-purple-200 rounded-xl p-4 bg-purple-50/30">
          <div className="text-sm font-semibold text-gray-900 mb-2">Active Access</div>
          <div className="text-[10px] text-gray-500 mb-2">
            Has active role assignments — implies usage even without sign-in logs
          </div>
          <div className="space-y-1">
            {((identity as any).federated_active_access as Array<{ role: string; scope: string; scope_type: string }>).slice(0, 5).map((a, idx) => {
              const scopeShort = a.scope?.split('/').filter(Boolean).slice(-2).join('/') || a.scope;
              return (
                <div key={idx} className="flex items-center gap-2 text-xs">
                  <span className="px-1.5 py-0.5 bg-blue-100 text-blue-700 rounded text-[10px] font-medium">{a.role}</span>
                  <span className="text-gray-400">{'\u2192'}</span>
                  <span className="text-gray-600 truncate" title={a.scope}>{scopeShort}</span>
                  <span className="text-[9px] text-gray-400">({a.scope_type})</span>
                </div>
              );
            })}
            {((identity as any).federated_active_access as Array<unknown>).length > 5 && (
              <div className="text-[10px] text-gray-400">+ {((identity as any).federated_active_access as Array<unknown>).length - 5} more</div>
            )}
          </div>
        </div>
      )}

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
                {normalizeScore(riskHistory[0].risk_score, 10).toFixed(1)} → {normalizeScore(riskHistory[riskHistory.length - 1].risk_score, 10).toFixed(1)}/10
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

      {/* Hosted On — SAMI resource context */}
      {!!identity.resource_context && !!identity.resource_context.resource_id && (
        <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
          <div className="text-sm font-semibold text-blue-900 mb-2 flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
            </svg>
            Hosted On
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm">
            <div>
              <div className="text-xs text-blue-600 font-medium">Resource</div>
              <div className="text-gray-900 font-mono text-xs mt-0.5 truncate" title={identity.resource_context.resource_name || ''}>
                {identity.resource_context.resource_name || 'Unknown'}
              </div>
            </div>
            <div>
              <div className="text-xs text-blue-600 font-medium">Type</div>
              <div className="text-gray-900 text-xs mt-0.5 truncate" title={identity.resource_context.resource_type || ''}>
                {(identity.resource_context.resource_type || '').split('/').pop()}
              </div>
            </div>
            <div>
              <div className="text-xs text-blue-600 font-medium">Resource Group</div>
              <div className="text-gray-900 text-xs mt-0.5 truncate" title={identity.resource_context.resource_group || ''}>
                {identity.resource_context.resource_group || 'N/A'}
              </div>
            </div>
          </div>
          {/* Compute context badges */}
          {(identity.resource_context.state || identity.resource_context.jit_enabled !== undefined || (identity.resource_context.env_secret_count ?? 0) > 0) && (
            <div className="flex gap-2 mt-2 flex-wrap">
              {!!identity.resource_context.state && (
                <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                  identity.resource_context.state === 'running' ? 'bg-green-100 text-green-700' :
                  identity.resource_context.state === 'stopped' || identity.resource_context.state === 'deallocated' ? 'bg-gray-100 text-gray-600' :
                  'bg-blue-100 text-blue-700'
                }`}>
                  {identity.resource_context.state}
                </span>
              )}
              {identity.resource_context.jit_enabled === true && (
                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-700">
                  JIT Enabled
                </span>
              )}
              {identity.resource_context.jit_enabled === false && (
                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-yellow-100 text-yellow-700">
                  No JIT
                </span>
              )}
              {(identity.resource_context.env_secret_count ?? 0) > 0 && (
                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-700">
                  {identity.resource_context.env_secret_count} Env Secret{(identity.resource_context.env_secret_count ?? 0) > 1 ? 's' : ''} Exposed
                </span>
              )}
            </div>
          )}
          <div className="text-xs text-blue-500 mt-2 font-mono truncate" title={identity.resource_context.resource_id}>
            {identity.resource_context.resource_id}
          </div>
        </div>
      )}

      {/* Compute findings (FIX 5) */}
      <ComputeFindings identityId={identity.identity_id} />

      {/* Database Admin context (Phase 3A) */}
      {!!data && !!(data as any).database_admin_context && (data as any).database_admin_context.length > 0 && (
        <div className="bg-white rounded-xl border shadow-sm p-5">
          <h3 className="text-sm font-semibold text-gray-900 mb-3">Database Admin</h3>
          <div className="space-y-2">
            {((data as any).database_admin_context as Array<{server_name:string; server_type:string; risk_level:string; mixed_auth_enabled:boolean; has_open_firewall:boolean}>).map((srv, i) => (
              <div key={i} className="flex items-center justify-between py-2 px-3 rounded-lg bg-gray-50">
                <div>
                  <span className="text-sm font-medium text-gray-800">{srv.server_name}</span>
                  <span className="text-xs text-gray-400 ml-2">{srv.server_type}</span>
                </div>
                <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                  srv.risk_level === 'critical' ? 'bg-red-100 text-red-700' :
                  srv.risk_level === 'high' ? 'bg-orange-100 text-orange-700' :
                  'bg-green-100 text-green-700'
                }`}>
                  {srv.risk_level === 'critical' ? 'Mixed Auth + Open FW' :
                   srv.risk_level === 'high' ? 'Mixed Auth' : 'AAD-Only'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Analytics context (Phase 3B) */}
      {!!data && !!(data as any).analytics_context && !!(data as any).analytics_context.workspace_type && (
        <div className="bg-white rounded-xl border shadow-sm p-5">
          <h3 className="text-sm font-semibold text-gray-900 mb-3">Analytics Workspace</h3>
          <div className="space-y-2">
            <div className="flex items-center gap-2 py-2 px-3 rounded-lg bg-gray-50">
              <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                (data as any).analytics_context.workspace_type === 'databricks' ? 'bg-red-100 text-red-700' :
                (data as any).analytics_context.workspace_type === 'synapse' ? 'bg-blue-100 text-blue-700' :
                'bg-purple-100 text-purple-700'
              }`}>
                {(data as any).analytics_context.workspace_type === 'databricks' ? 'Databricks' :
                 (data as any).analytics_context.workspace_type === 'synapse' ? 'Synapse' : 'Azure ML'}
              </span>
              <span className="text-sm font-medium text-gray-800">{(data as any).analytics_context.workspace_name}</span>
            </div>
            {(data as any).analytics_context.no_expiry_pat_count > 0 && (
              <div className="text-xs text-red-600 px-3">
                {'\u26A0'} {(data as any).analytics_context.no_expiry_pat_count} active PATs with no expiry — credentials bypass Entra lifecycle
              </div>
            )}
            {(data as any).analytics_context.admin_sprawl_flag && (
              <div className="text-xs text-amber-600 px-3">
                {'\u26A0'} Workspace admin sprawl (recommended: {'\u2264'}3)
              </div>
            )}
          </div>
        </div>
      )}

      {/* DevOps pipeline context (Phase 4A) */}
      {!!data && !!(data as any).devops_context && (data as any).devops_context.length > 0 && (
        <div className="bg-white rounded-xl border shadow-sm p-5">
          <h3 className="text-sm font-semibold text-gray-900 mb-3">Used in Pipelines</h3>
          <div className="space-y-2">
            {((data as any).devops_context as Array<{
              ado_organization: string; ado_project: string;
              connection_name: string; scope_level: string; is_subscription_scope: boolean;
            }>).map((sc, i) => (
              <div key={i} className="flex items-center gap-2 py-2 px-3 rounded-lg bg-gray-50">
                <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                  sc.is_subscription_scope ? 'bg-red-100 text-red-700' : 'bg-blue-100 text-blue-700'
                }`}>
                  {sc.is_subscription_scope ? 'SUBSCRIPTION' : sc.scope_level?.toUpperCase() || 'RESOURCE'}
                </span>
                <span className="text-sm font-medium text-gray-800">{sc.connection_name}</span>
                <span className="text-xs text-gray-400">{sc.ado_organization}/{sc.ado_project}</span>
              </div>
            ))}
          </div>
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
