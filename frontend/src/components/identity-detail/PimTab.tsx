import React from 'react';
import {
  type PimData,
  type PimShouldBePimFinding,
  type IdentityDetailsResponse,
  formatDate,
  DataSource,
  DATA_EXPLANATIONS,
} from './types';
import { COLORS } from '../../constants/ciso';

interface PimTabProps {
  pimData: PimData | null;
  pimLoading: boolean;
  data: IdentityDetailsResponse;
  identity: IdentityDetailsResponse['identity'];
  riskLevel?: string;
  identityCategory?: string;
}

// Standing privileged assignments that should be PIM-eligible.
// Microsoft Zero Trust / NIST AC-6 / CIS Azure 1.22-1.23 best-practice panel.
// Themed with the CISO board palette (constants/ciso.ts) for cross-product consistency.
function ShouldBePimPanel({ findings }: { findings: PimShouldBePimFinding[] }) {
  if (!findings || findings.length === 0) return null;
  const redundant = findings.filter(f => f.has_pim_alt).length;
  const convertable = findings.length - redundant;
  return (
    <div
      className="rounded-xl p-5 mb-4"
      style={{
        background: COLORS.surface,
        border: `1px solid ${COLORS.danger}`,
        boxShadow: `0 0 0 1px ${COLORS.dangerSoft}`,
      }}
    >
      <div className="flex items-start gap-3">
        <div
          className="flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center"
          style={{ background: COLORS.dangerSoft }}
        >
          <svg className="w-5 h-5" fill="none" stroke={COLORS.danger} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M12 9v2m0 4h.01M5 19h14a2 2 0 001.84-2.75L13.74 4a2 2 0 00-3.48 0L3.16 16.25A2 2 0 005 19z"/>
          </svg>
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <div className="text-sm font-semibold" style={{ color: COLORS.text }}>
              Standing Privileged Roles — Should Be PIM-Eligible
            </div>
            <span
              className="px-2 py-0.5 rounded-full text-xs font-medium"
              style={{ background: COLORS.dangerSoft, color: COLORS.danger }}
            >
              {findings.length} finding{findings.length === 1 ? '' : 's'}
            </span>
          </div>
          <div className="text-xs mt-1" style={{ color: COLORS.textSecondary }}>
            Microsoft best practice (Zero Trust) and NIST AC-6 require privileged roles to use
            just-in-time activation with time-bound access — not standing/permanent assignments.
          </div>
          {(convertable > 0 || redundant > 0) && (
            <div className="text-xs mt-2 space-x-3" style={{ color: COLORS.textSecondary }}>
              {convertable > 0 && (
                <span>
                  <span className="font-semibold" style={{ color: COLORS.danger }}>{convertable}</span> to convert to PIM-eligible
                </span>
              )}
              {redundant > 0 && (
                <span>
                  <span className="font-semibold" style={{ color: COLORS.warning }}>{redundant}</span> redundant (PIM-alt already exists)
                </span>
              )}
            </div>
          )}
          <div className="mt-3 overflow-x-auto">
            <table className="min-w-full text-xs">
              <thead>
                <tr style={{ borderBottom: `1px solid ${COLORS.border}`, color: COLORS.textSecondary }}>
                  <th className="text-left py-1.5 pr-3 font-semibold">Role</th>
                  <th className="text-left py-1.5 pr-3 font-semibold">Scope</th>
                  <th className="text-left py-1.5 pr-3 font-semibold">Source</th>
                  <th className="text-left py-1.5 pr-3 font-semibold">Status</th>
                  <th className="text-left py-1.5 font-semibold">Recommendation</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f, idx) => (
                  <tr key={idx} className="align-top" style={{ borderBottom: `1px solid ${COLORS.border}` }}>
                    <td className="py-2 pr-3 font-medium" style={{ color: COLORS.text }}>{f.role_name}</td>
                    <td className="py-2 pr-3">
                      <span
                        className="px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wide"
                        style={{ background: COLORS.surfaceAlt, color: COLORS.textSecondary }}
                      >
                        {f.scope_type}
                      </span>
                      <div
                        className="text-[10px] font-mono truncate max-w-[260px]"
                        style={{ color: COLORS.textMuted }}
                        title={f.scope}
                      >
                        {f.scope}
                      </div>
                    </td>
                    <td className="py-2 pr-3">
                      <span
                        className="px-1.5 py-0.5 rounded text-[10px] font-medium uppercase"
                        style={
                          f.kind === 'entra'
                            ? { background: 'rgba(139,92,246,0.15)', color: COLORS.purple }
                            : { background: COLORS.accentSoft, color: COLORS.accent }
                        }
                      >
                        {f.kind === 'entra' ? 'Entra' : 'Azure RBAC'}
                      </span>
                    </td>
                    <td className="py-2 pr-3">
                      <span
                        className="px-1.5 py-0.5 rounded text-[10px] font-medium"
                        style={
                          f.has_pim_alt
                            ? { background: COLORS.warningSoft, color: COLORS.warning }
                            : { background: COLORS.dangerSoft, color: COLORS.danger }
                        }
                      >
                        {f.has_pim_alt ? 'Redundant' : 'Standing'}
                      </span>
                    </td>
                    <td className="py-2 max-w-[420px]">
                      <div className="text-[11px] leading-relaxed" style={{ color: COLORS.text }}>
                        {f.recommendation}
                      </div>
                      {f.frameworks && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {(f.frameworks.cis || []).map(c => (
                            <span
                              key={c}
                              className="px-1 py-0.5 rounded text-[9px]"
                              style={{ background: COLORS.accentSoft, color: COLORS.accent, border: `1px solid ${COLORS.accent}33` }}
                            >
                              {c}
                            </span>
                          ))}
                          {(f.frameworks.nist || []).map(c => (
                            <span
                              key={c}
                              className="px-1 py-0.5 rounded text-[9px]"
                              style={{ background: COLORS.successSoft, color: COLORS.success, border: `1px solid ${COLORS.success}33` }}
                            >
                              NIST {c}
                            </span>
                          ))}
                          {(f.frameworks.mitre || []).map(c => (
                            <span
                              key={c}
                              className="px-1 py-0.5 rounded text-[9px]"
                              style={{ background: COLORS.dangerSoft, color: COLORS.danger, border: `1px solid ${COLORS.danger}33` }}
                            >
                              MITRE {c}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="text-[11px] mt-3" style={{ color: COLORS.textMuted }}>
            Configure PIM in <span className="font-mono" style={{ color: COLORS.textSecondary }}>Entra admin center → Identity Governance → Privileged Identity Management</span>.
          </div>
        </div>
      </div>
    </div>
  );
}

export function PimTab({ pimData, pimLoading, data, identity, riskLevel, identityCategory }: PimTabProps) {
  const shouldBePim = pimData?.should_be_pim || [];
  return (
    <div className="space-y-6">
      {pimLoading ? (
        <div className="animate-pulse space-y-4">
          <div className="h-20 bg-gray-100 rounded-xl" />
          <div className="h-40 bg-gray-100 rounded-xl" />
        </div>
      ) : !pimData || (pimData.eligible_assignments.length === 0 && pimData.activations.length === 0 && shouldBePim.length === 0) ? (
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
          {/* PIM hygiene — standing privileged that should be PIM-eligible.
              Rendered first so it's the lead message when present. */}
          <ShouldBePimPanel findings={shouldBePim} />

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
