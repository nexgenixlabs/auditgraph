import React from 'react';
import {
  type RoleIntelligence,
  type IdentityDetailsResponse,
  formatUsd,
  violationRiskColor,
  riskBadge,
  DataSource,
  safeLower,
} from './types';

interface IdentityComplianceTabProps {
  roleIntel: RoleIntelligence[];
  data: IdentityDetailsResponse;
}

export function IdentityComplianceTab({ roleIntel, data }: IdentityComplianceTabProps) {
  const identity = data.identity;

  return (
    <div className="space-y-6">
      {/* GRC Framework Summary */}
      <div>
        <div className="text-sm font-semibold text-gray-900 mb-3">GRC Framework Relevance</div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {(() => {
            const risk = safeLower(identity.risk_level);
            const hasPrivRoles = (data?.roles || []).length > 0;
            const hasHipaa = roleIntel.some(ri => ri.hipaa_violations.length > 0);
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            const hasAttacks = roleIntel.some(ri => ri.attack_patterns.length > 0);
            const isHuman = identity.identity_category === 'human_user' || identity.identity_category === 'guest';

            const frameworks = [
              {
                name: 'SOC 2',
                relevant: risk === 'critical' || risk === 'high' || (risk === 'medium' && hasPrivRoles),
                reason: hasPrivRoles ? 'Privileged access requires SOC 2 CC6.1 controls' : 'Low-risk identity',
              },
              {
                name: 'HIPAA',
                relevant: hasHipaa || (isHuman && hasPrivRoles),
                reason: hasHipaa ? `${roleIntel.reduce((s, r) => s + r.hipaa_violations.length, 0)} violation mappings found` : 'No HIPAA-relevant permissions',
              },
              {
                name: 'PCI-DSS',
                relevant: risk === 'critical' || risk === 'high',
                reason: risk === 'critical' || risk === 'high' ? 'Req 7/8: Privileged access control' : 'Below PCI threshold',
              },
              {
                name: 'NIST 800-53',
                relevant: hasPrivRoles,
                reason: hasPrivRoles ? 'AC-6: Least Privilege applies' : 'No privileged roles',
              },
            ];

            return frameworks.map(fw => (
              <div key={fw.name} className={`rounded-xl p-4 border ${fw.relevant ? 'bg-amber-50 border-amber-200' : 'bg-gray-50 border-gray-200'}`}>
                <div className="flex items-center justify-between mb-1">
                  <span className="font-semibold text-sm text-gray-900">{fw.name}</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${fw.relevant ? 'bg-amber-100 text-amber-800' : 'bg-gray-100 text-gray-500'}`}>
                    {fw.relevant ? 'Relevant' : 'Low'}
                  </span>
                </div>
                <div className="text-xs text-gray-600">{fw.reason}</div>
              </div>
            ));
          })()}
        </div>
      </div>

      {/* Per-Role Intelligence */}
      {roleIntel.length === 0 ? (
        <div className="text-center py-8">
          <svg className="w-12 h-12 text-gray-300 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div className="text-sm text-gray-500">No compliance intelligence data for this identity's roles.</div>
          <div className="text-xs text-gray-400 mt-1">
            Attack patterns and HIPAA mappings are populated for privileged roles.
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="text-sm font-semibold text-gray-900">Per-Role Intelligence</div>
          {roleIntel.map((ri, idx) => (
            <div key={idx} className="border rounded-xl overflow-hidden">
              {/* Role header */}
              <div className="bg-gray-50 px-4 py-3 border-b flex items-center justify-between">
                <div className="font-semibold text-gray-900 text-sm">{ri.role_name}</div>
                <div className="flex items-center gap-2">
                  {ri.attack_patterns.length > 0 && (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-red-100 text-red-700">
                      {ri.attack_patterns.length} incident{ri.attack_patterns.length > 1 ? 's' : ''}
                    </span>
                  )}
                  {ri.hipaa_violations.length > 0 && (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-purple-100 text-purple-700">
                      {ri.hipaa_violations.length} HIPAA
                    </span>
                  )}
                </div>
              </div>

              <div className="p-4 space-y-4">
                {/* Attack Patterns / Real-World Incidents */}
                {ri.attack_patterns.length > 0 && (
                  <div>
                    <div className="text-xs font-semibold text-gray-700 mb-2 flex items-center gap-1">
                      <svg className="w-3.5 h-3.5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                      </svg>
                      Real-World Incidents
                    </div>
                    <div className="space-y-2">
                      {ri.attack_patterns.map((ap, apIdx) => (
                        <div key={apIdx} className="bg-red-50 border border-red-100 rounded-lg p-3">
                          <div className="flex items-start justify-between gap-2">
                            <div className="font-medium text-sm text-gray-900">{ap.attack_scenario}</div>
                            {ap.estimated_cost_usd > 0 && (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-200 text-red-900 whitespace-nowrap">
                                {formatUsd(ap.estimated_cost_usd)}
                              </span>
                            )}
                          </div>
                          <div className="text-xs text-gray-700 mt-1">{ap.real_world_example}</div>
                          <div className="flex items-center gap-3 mt-2 text-[10px] text-gray-500">
                            {ap.company_affected && <span className="font-medium">{ap.company_affected}</span>}
                            {ap.breach_year > 0 && <span>{ap.breach_year}</span>}
                          </div>
                          {ap.source && (
                            <div className="mt-1.5 text-[10px] text-gray-400 italic">
                              Source: {ap.source}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* HIPAA Violations */}
                {ri.hipaa_violations.length > 0 && (
                  <div>
                    <div className="text-xs font-semibold text-gray-700 mb-2 flex items-center gap-1">
                      <svg className="w-3.5 h-3.5 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                      HIPAA Violation Mappings
                    </div>
                    <div className="overflow-x-auto">
                      <table className="min-w-full text-xs">
                        <thead>
                          <tr className="border-b text-gray-500">
                            <th className="text-left py-1.5 pr-3 font-medium">Section</th>
                            <th className="text-left py-1.5 pr-3 font-medium">Violation</th>
                            <th className="text-left py-1.5 pr-3 font-medium">Risk</th>
                            <th className="text-left py-1.5 font-medium">Penalty Range</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-100">
                          {ri.hipaa_violations.map((hv, hvIdx) => (
                            <tr key={hvIdx}>
                              <td className="py-2 pr-3 font-mono text-gray-700 whitespace-nowrap">{hv.hipaa_section}</td>
                              <td className="py-2 pr-3 text-gray-700">{hv.violation_explanation}</td>
                              <td className="py-2 pr-3">
                                <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${violationRiskColor(hv.violation_risk)}`}>
                                  {hv.violation_risk}
                                </span>
                              </td>
                              <td className="py-2 text-gray-700 whitespace-nowrap">
                                {formatUsd(hv.typical_penalty_min)} – {formatUsd(hv.typical_penalty_max)}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
      <DataSource label="AuditGraph Intelligence Engine" apiSource="Role-based GRC mapping" collectedAt={data?.evidence?.collected_at} />
    </div>
  );
}
