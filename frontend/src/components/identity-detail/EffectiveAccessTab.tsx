import React from 'react';
import {
  type EffectiveAccessData,
  type IdentityDetailsResponse,
  DataSource,
} from './types';
import { getRoleUsageBadge, type RoleUsageEntry } from '../../utils/roleUtils';
// AG-POLISH-D (2026-06-10)
import { LoadingState } from '../LoadingState';

interface EffectiveAccessTabProps {
  effectiveAccessData: EffectiveAccessData | null;
  effectiveAccessLoading: boolean;
  sensitiveAccessData: any;
  data: IdentityDetailsResponse;
}

// Sprint B.6 — Blast Radius rollup. Pure parse of scope strings client-side;
// no new endpoint needed. We don't know resource-level access without explicit
// data-plane discovery, so the "Resources" tile is intentionally absent — it'd
// be a number we can't substantiate. Subs / RGs / Key Vaults / Storage / Sensitive
// are all derivable from scope ARMpath alone.
interface BlastRollup {
  subscriptions: number;
  resourceGroups: number;
  keyVaults: number;
  storageAccounts: number;
  resources: number;          // every other scoped resource
  tenantWide: boolean;
  totalRoles: number;
  sensitiveCount: number;
  phi: number; pci: number; pii: number;
}

function computeBlastRollup(effectiveAccess: EffectiveAccessData | null, sensitiveAccess: any): BlastRollup {
  const subs = new Set<string>();
  const rgs = new Set<string>();
  const kvs = new Set<string>();
  const sas = new Set<string>();
  const resources = new Set<string>();
  let tenantWide = false;

  const entries = effectiveAccess?.effective_access || [];
  for (const e of entries) {
    const scope = String((e as any).scope || '');
    if (scope === '/' || (e as any).scope_type === 'tenant') { tenantWide = true; continue; }

    const m = scope.match(/^\/subscriptions\/([^/]+)/);
    if (m) subs.add(m[1]);

    const rgm = scope.match(/\/resourceGroups\/([^/]+)/i);
    if (rgm) rgs.add(rgm[1]);

    // /providers/Microsoft.KeyVault/vaults/<name>
    const kvm = scope.match(/\/providers\/Microsoft\.KeyVault\/vaults\/([^/]+)/i);
    if (kvm) { kvs.add(kvm[1]); continue; }

    const sam = scope.match(/\/providers\/Microsoft\.Storage\/storageAccounts\/([^/]+)/i);
    if (sam) { sas.add(sam[1]); continue; }

    // anything else under a resource provider
    if (scope.includes('/providers/')) resources.add(scope);
  }

  const br = sensitiveAccess?.blast_radius || {};
  const byClass = br.by_classification || {};
  return {
    subscriptions: subs.size,
    resourceGroups: rgs.size,
    keyVaults: kvs.size,
    storageAccounts: sas.size,
    resources: resources.size,
    tenantWide,
    totalRoles: entries.length,
    sensitiveCount: br.total_sensitive || 0,
    phi: byClass.PHI || 0,
    pci: byClass.PCI || 0,
    pii: byClass.PII || 0,
  };
}

export function EffectiveAccessTab({ effectiveAccessData, effectiveAccessLoading, sensitiveAccessData, data }: EffectiveAccessTabProps) {
  const roleUsage = (data as any)?.role_usage as Record<string, RoleUsageEntry> | undefined;
  const rollup = computeBlastRollup(effectiveAccessData, sensitiveAccessData);
  return (
    <div className="space-y-4">
      {/* AG-POLISH-D (2026-06-10) */}
      {effectiveAccessLoading ? (
        <LoadingState size="sm" message="Loading effective access…" detail="Computing transitive role closure for this identity" />
      ) : !effectiveAccessData || effectiveAccessData.effective_access.length === 0 ? (
        <div className="text-center py-8">
          <div className="text-sm text-gray-500">No role assignments found for this identity.</div>
        </div>
      ) : (
        <>
          {/* Sprint B.6 — Blast Radius rollup. Promotes the BR out of the
              Access Graph (where it was buried) into the executive read.
              Derived entirely from scope ARMpath parsing — no extra fetch. */}
          <div className="bg-white border rounded-2xl p-4">
            <div className="flex items-center justify-between mb-3">
              <div>
                <div className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Blast Radius</div>
                <div className="text-sm font-bold text-gray-900 mt-0.5">
                  {rollup.tenantWide ? 'Tenant-Wide Exposure'
                   : rollup.subscriptions >= 3 ? 'Multi-Subscription Exposure'
                   : rollup.subscriptions === 2 ? 'Cross-Subscription Exposure'
                   : rollup.subscriptions === 1 ? 'Single-Subscription Exposure'
                   : 'Scope Pending'}
                </div>
              </div>
              {rollup.tenantWide && (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-red-100 text-red-700 border border-red-200">
                  Tenant-Wide
                </span>
              )}
            </div>
            <div className="grid grid-cols-6 gap-2">
              <div className="rounded-lg p-3" style={{ background: 'rgba(168,85,247,0.07)', border: '1px solid rgba(168,85,247,0.18)' }}>
                <div className="text-2xl font-bold text-purple-700 leading-none">{rollup.subscriptions}</div>
                <div className="text-[10px] text-gray-500 mt-1 uppercase tracking-wider">Subscriptions</div>
              </div>
              <div className="rounded-lg p-3" style={{ background: 'rgba(56,189,248,0.07)', border: '1px solid rgba(56,189,248,0.18)' }}>
                <div className="text-2xl font-bold text-sky-600 leading-none">{rollup.resourceGroups}</div>
                <div className="text-[10px] text-gray-500 mt-1 uppercase tracking-wider">Resource Groups</div>
              </div>
              <div className="rounded-lg p-3" style={{ background: 'rgba(139,92,246,0.07)', border: '1px solid rgba(139,92,246,0.18)' }}>
                <div className="text-2xl font-bold text-violet-600 leading-none">{rollup.keyVaults}</div>
                <div className="text-[10px] text-gray-500 mt-1 uppercase tracking-wider">Key Vaults</div>
              </div>
              <div className="rounded-lg p-3" style={{ background: 'rgba(59,130,246,0.07)', border: '1px solid rgba(59,130,246,0.18)' }}>
                <div className="text-2xl font-bold text-blue-600 leading-none">{rollup.storageAccounts}</div>
                <div className="text-[10px] text-gray-500 mt-1 uppercase tracking-wider">Storage</div>
              </div>
              <div className="rounded-lg p-3" style={{ background: 'rgba(34,197,94,0.07)', border: '1px solid rgba(34,197,94,0.18)' }}>
                <div className="text-2xl font-bold text-emerald-600 leading-none">{rollup.resources}</div>
                <div className="text-[10px] text-gray-500 mt-1 uppercase tracking-wider">Other Res.</div>
              </div>
              <div className="rounded-lg p-3" style={{ background: 'rgba(239,68,68,0.07)', border: '1px solid rgba(239,68,68,0.18)' }}>
                <div className="text-2xl font-bold text-red-600 leading-none">{rollup.sensitiveCount}</div>
                <div className="text-[10px] text-gray-500 mt-1 uppercase tracking-wider">Sensitive</div>
              </div>
            </div>
            {(rollup.phi + rollup.pci + rollup.pii) > 0 && (
              <div className="mt-2 flex items-center gap-2 flex-wrap text-[10px]">
                <span className="text-gray-500 uppercase tracking-wider font-semibold">Classifications:</span>
                {rollup.phi > 0 && <span className="px-1.5 py-0.5 rounded bg-red-100 text-red-700 font-bold">{rollup.phi} PHI</span>}
                {rollup.pci > 0 && <span className="px-1.5 py-0.5 rounded bg-amber-100 text-amber-700 font-bold">{rollup.pci} PCI</span>}
                {rollup.pii > 0 && <span className="px-1.5 py-0.5 rounded bg-blue-100 text-blue-700 font-bold">{rollup.pii} PII</span>}
              </div>
            )}
            <div className="mt-2 text-[10px] text-gray-400 italic">
              Counts derived from scope ARMpath parsing — distinct resources at each tier with at least one role assignment.
            </div>
          </div>

          {/* Summary Bar */}
          <div className="grid grid-cols-3 gap-3">
            {[
              { label: 'Admin', count: effectiveAccessData.summary.admin_scopes, color: 'bg-red-100 text-red-700 border-red-200' },
              { label: 'Write', count: effectiveAccessData.summary.write_scopes, color: 'bg-amber-100 text-amber-700 border-amber-200' },
              { label: 'Read', count: effectiveAccessData.summary.read_scopes, color: 'bg-blue-100 text-blue-700 border-blue-200' },
            ].map(s => (
              <div key={s.label} className={`rounded-xl border p-3 text-center ${s.color}`}>
                <div className="text-2xl font-bold">{s.count}</div>
                <div className="text-xs font-semibold uppercase tracking-wider">{s.label} Scopes</div>
              </div>
            ))}
          </div>

          {/* Sensitive Data Warning */}
          {sensitiveAccessData && sensitiveAccessData.blast_radius?.total_sensitive > 0 && (
            <div className="rounded-xl border p-3" style={{ background: 'rgba(239,68,68,0.06)', borderColor: 'rgba(239,68,68,0.2)' }}>
              <div className="flex items-center gap-3 text-xs">
                <span className="font-bold text-red-500">SENSITIVE DATA EXPOSURE</span>
                <span className="text-gray-500">This identity can access</span>
                {Object.entries(sensitiveAccessData.blast_radius?.by_classification || {}).map(([cls, count]) => (
                  <span key={cls} className="px-2 py-0.5 rounded text-[10px] font-bold font-mono" style={{
                    background: cls === 'PHI' ? 'rgba(239,68,68,0.12)' : cls === 'PCI' ? 'rgba(251,191,36,0.12)' : 'rgba(96,165,250,0.12)',
                    color: cls === 'PHI' ? '#F87171' : cls === 'PCI' ? '#FBBF24' : '#60A5FA',
                  }}>{count as number} {cls}</span>
                ))}
                <span className="text-gray-500">classified resources</span>
              </div>
            </div>
          )}

          {/* Stats row */}
          <div className="flex items-center gap-4 text-xs text-gray-500 px-1">
            <span><span className="font-semibold text-gray-700">{effectiveAccessData.summary.total_roles}</span> total roles</span>
            <span><span className="font-semibold text-gray-700">{effectiveAccessData.summary.total_permissions}</span> effective permissions</span>
            <span>Categories: {effectiveAccessData.summary.categories.join(', ') || 'None'}</span>
          </div>

          {/* Access Table */}
          <div className="border rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-gray-50 text-left text-xs text-gray-500 uppercase tracking-wider">
                  <th className="px-4 py-2.5">Access Level</th>
                  <th className="px-4 py-2.5">Role</th>
                  <th className="px-4 py-2.5">Usage</th>
                  <th className="px-4 py-2.5">Source</th>
                  <th className="px-4 py-2.5">Scope</th>
                  <th className="px-4 py-2.5">Category</th>
                  <th className="px-4 py-2.5">Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {effectiveAccessData.effective_access.map((entry, idx) => (
                  <tr key={idx} className="hover:bg-gray-50 group">
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold ${
                        entry.access_level === 'Admin' ? 'bg-red-100 text-red-700' :
                        entry.access_level === 'Write' ? 'bg-amber-100 text-amber-700' :
                        'bg-blue-100 text-blue-700'
                      }`}>
                        {entry.access_level}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="font-medium text-gray-900">{entry.role_name}</div>
                      {entry.why_critical && (
                        <div className="text-[10px] text-red-500 mt-0.5 max-w-xs truncate" title={entry.why_critical}>
                          {entry.why_critical}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {getRoleUsageBadge(entry.role_name, roleUsage)}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-medium ${entry.role_source === 'azure_rbac' ? 'text-blue-600' : 'text-purple-600'}`}>
                        {entry.role_source === 'azure_rbac' ? 'Azure RBAC' : 'Entra ID'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="text-gray-700 max-w-[200px] truncate" title={entry.scope}>
                        {entry.scope_display}
                      </div>
                      <div className="text-[10px] text-gray-400">{entry.scope_type}</div>
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500">{entry.category}</td>
                    <td className="px-4 py-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                        entry.risk_level === 'critical' ? 'bg-red-100 text-red-700' :
                        entry.risk_level === 'high' ? 'bg-orange-100 text-orange-700' :
                        entry.risk_level === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                        'bg-gray-100 text-gray-500'
                      }`}>
                        {entry.risk_level}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Expanded Permissions */}
          <div className="space-y-3">
            <div className="text-xs font-semibold text-gray-500 uppercase tracking-wider px-1">Permission Details</div>
            {effectiveAccessData.effective_access.map((entry, idx) => (
              <details key={idx} className="border rounded-lg overflow-hidden">
                <summary className="px-4 py-2.5 bg-gray-50 cursor-pointer hover:bg-gray-100 flex items-center gap-2 text-sm">
                  <span className={`w-2 h-2 rounded-full ${
                    entry.access_level === 'Admin' ? 'bg-red-500' :
                    entry.access_level === 'Write' ? 'bg-amber-500' : 'bg-blue-500'
                  }`} />
                  <span className="font-medium text-gray-800">{entry.role_name}</span>
                  <span className="text-gray-400 text-xs">@ {entry.scope_display}</span>
                  <span className="ml-auto text-xs text-gray-400">{entry.permissions.length} permissions</span>
                </summary>
                <div className="px-4 py-3 space-y-1.5">
                  {entry.permissions.map((perm, pIdx) => (
                    <div key={pIdx} className="flex items-center gap-2 text-xs text-gray-600">
                      <span className={`w-1 h-1 rounded-full ${
                        entry.access_level === 'Admin' ? 'bg-red-400' :
                        entry.access_level === 'Write' ? 'bg-amber-400' : 'bg-blue-400'
                      }`} />
                      {perm}
                    </div>
                  ))}
                </div>
              </details>
            ))}
          </div>
        </>
      )}
      <DataSource label="AuditGraph Permission Resolver" apiSource="/api/identities/{id}/effective-access" collectedAt={data?.evidence?.collected_at} />
    </div>
  );
}
