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

export function EffectiveAccessTab({ effectiveAccessData, effectiveAccessLoading, sensitiveAccessData, data }: EffectiveAccessTabProps) {
  const roleUsage = (data as any)?.role_usage as Record<string, RoleUsageEntry> | undefined;
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
