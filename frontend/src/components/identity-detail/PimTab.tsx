import React from 'react';
import {
  type PimData,
  type IdentityDetailsResponse,
  formatDate,
  DataSource,
  DATA_EXPLANATIONS,
} from './types';

interface PimTabProps {
  pimData: PimData | null;
  pimLoading: boolean;
  data: IdentityDetailsResponse;
  identity: IdentityDetailsResponse['identity'];
  riskLevel?: string;
  identityCategory?: string;
}

export function PimTab({ pimData, pimLoading, data, identity, riskLevel, identityCategory }: PimTabProps) {
  return (
    <div className="space-y-6">
      {pimLoading ? (
        <div className="animate-pulse space-y-4">
          <div className="h-20 bg-gray-100 rounded-xl" />
          <div className="h-40 bg-gray-100 rounded-xl" />
        </div>
      ) : !pimData || (pimData.eligible_assignments.length === 0 && pimData.activations.length === 0) ? (
        <div className="py-8 space-y-4 px-4">
          <div className="text-center">
            <svg className="w-12 h-12 text-gray-300 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
            <div className="text-sm text-gray-500">No PIM role eligibility assignments found.</div>
            <div className="text-xs text-gray-400 mt-1">
              {DATA_EXPLANATIONS.PIM}
            </div>
            <div className="text-xs text-gray-400 mt-1">
              Source: Microsoft Graph API /roleManagement/directory/roleEligibilityScheduleInstances
            </div>
          </div>
          {(() => {
            const rl = (riskLevel || '').toLowerCase();
            const isHighRisk = rl === 'critical' || rl === 'high';
            if (!isHighRisk) return null;
            return (
              <div className="border-l-4 border-l-amber-400 bg-amber-50 rounded-r-lg p-4">
                <div className="text-sm font-semibold text-amber-800 mb-1">NIST AC-6 — Least Privilege</div>
                <div className="text-xs text-amber-700">
                  This {rl.toUpperCase()} {identityCategory === 'service_principal' ? 'service principal' : 'identity'} has no PIM role eligibility. Standing privileged access without just-in-time controls increases breach exposure.
                </div>
              </div>
            );
          })()}
        </div>
      ) : (
        <>
          {/* Overuse Metrics */}
          <div>
            <div className="text-sm font-semibold text-gray-900 mb-3">Overuse Metrics (Last 30 Days)</div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-gray-50 rounded-xl p-4">
                <div className="text-xs text-gray-500 mb-1">Activations</div>
                <div className={`text-2xl font-bold ${pimData.overuse_metrics.activation_frequency_30d > 10 ? 'text-orange-600' : 'text-gray-900'}`}>
                  {pimData.overuse_metrics.activation_frequency_30d}
                </div>
              </div>
              <div className="bg-gray-50 rounded-xl p-4">
                <div className="text-xs text-gray-500 mb-1">Total Active Hours</div>
                <div className="text-2xl font-bold text-gray-900">
                  {pimData.overuse_metrics.total_active_hours_30d}h
                </div>
              </div>
              <div className="bg-gray-50 rounded-xl p-4">
                <div className="text-xs text-gray-500 mb-1">Always-Active Pattern</div>
                <div className="text-sm font-semibold mt-1">
                  {pimData.overuse_metrics.always_active_pattern ? (
                    <span className="px-2 py-1 rounded-full text-xs bg-red-100 text-red-700">Detected</span>
                  ) : (
                    <span className="px-2 py-1 rounded-full text-xs bg-green-100 text-green-700">Not Detected</span>
                  )}
                </div>
              </div>
            </div>
            {pimData.overuse_metrics.always_active_pattern && (
              <div className="mt-3 bg-red-50 border border-red-200 rounded-xl p-3 text-sm text-red-700">
                This identity is active &gt;80% of the time via PIM. Consider converting to a permanent (non-PIM) assignment or reviewing if JIT governance is being bypassed.
              </div>
            )}
          </div>

          {/* Eligible Roles */}
          <div>
            <div className="text-sm font-semibold text-gray-900 mb-3 flex items-center gap-2">
              Eligible Roles
              <span className="px-2 py-0.5 rounded-full text-xs bg-emerald-100 text-emerald-700">
                {pimData.eligible_assignments.length}
              </span>
            </div>
            {pimData.eligible_assignments.length === 0 ? (
              <div className="text-sm text-gray-500 bg-gray-50 rounded-xl p-4">No PIM eligible roles.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm">
                  <thead>
                    <tr className="border-b text-gray-500 text-xs">
                      <th className="text-left py-2 pr-4 font-medium">Role Name</th>
                      <th className="text-left py-2 pr-4 font-medium">Scope</th>
                      <th className="text-left py-2 pr-4 font-medium">Type</th>
                      <th className="text-left py-2 pr-4 font-medium">Member</th>
                      <th className="text-left py-2 font-medium">Expiration</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {pimData.eligible_assignments.map((ea, idx) => (
                      <tr key={idx}>
                        <td className="py-2.5 pr-4 font-medium text-gray-900">{ea.role_name}</td>
                        <td className="py-2.5 pr-4 text-gray-600 text-xs font-mono">{ea.directory_scope || '/'}</td>
                        <td className="py-2.5 pr-4">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                            ea.assignment_type === 'permanent_eligible'
                              ? 'bg-red-100 text-red-700'
                              : 'bg-blue-100 text-blue-700'
                          }`}>
                            {ea.assignment_type === 'permanent_eligible' ? 'Permanent' : 'Time-Bound'}
                          </span>
                        </td>
                        <td className="py-2.5 pr-4 text-gray-600 text-xs">{ea.member_type || '\u2014'}</td>
                        <td className="py-2.5 text-gray-600 text-xs">
                          {ea.end_datetime ? formatDate(ea.end_datetime) : <span className="text-red-600 font-medium">No expiry</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Activation History */}
          <div>
            <div className="text-sm font-semibold text-gray-900 mb-3 flex items-center gap-2">
              Activation History
              <span className="px-2 py-0.5 rounded-full text-xs bg-purple-100 text-purple-700">
                {pimData.activations.length}
              </span>
            </div>
            {pimData.activations.length === 0 ? (
              <div className="text-sm text-gray-500 bg-gray-50 rounded-xl p-4">No PIM activation records.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm">
                  <thead>
                    <tr className="border-b text-gray-500 text-xs">
                      <th className="text-left py-2 pr-4 font-medium">Role</th>
                      <th className="text-left py-2 pr-4 font-medium">Status</th>
                      <th className="text-left py-2 pr-4 font-medium">Start</th>
                      <th className="text-left py-2 pr-4 font-medium">End</th>
                      <th className="text-left py-2 pr-4 font-medium">Justification</th>
                      <th className="text-left py-2 font-medium">Ticket</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {pimData.activations.map((act, idx) => (
                      <tr key={idx}>
                        <td className="py-2.5 pr-4 font-medium text-gray-900">{act.role_name}</td>
                        <td className="py-2.5 pr-4">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                            act.status === 'Active' ? 'bg-green-100 text-green-700' :
                            act.status === 'Expired' ? 'bg-gray-100 text-gray-600' :
                            'bg-red-100 text-red-700'
                          }`}>{act.status || '\u2014'}</span>
                        </td>
                        <td className="py-2.5 pr-4 text-gray-600 text-xs">{formatDate(act.activation_start)}</td>
                        <td className="py-2.5 pr-4 text-gray-600 text-xs">{formatDate(act.activation_end)}</td>
                        <td className="py-2.5 pr-4 text-gray-600 text-xs max-w-[200px] truncate" title={act.justification || ''}>
                          {act.justification || <span className="text-gray-300">{'\u2014'}</span>}
                        </td>
                        <td className="py-2.5 text-gray-600 text-xs">
                          {act.ticket_number ? (
                            <span className="font-mono">{act.ticket_number}</span>
                          ) : (
                            <span className="text-gray-300">{'\u2014'}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
      <DataSource label="Microsoft Graph API" apiSource="/roleManagement/directory/roleEligibilityScheduleInstances" collectedAt={data?.evidence?.collected_at} />
    </div>
  );
}
