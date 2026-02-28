import React from 'react';
import {
  type IdentityDetailsResponse,
  type RoleIntelligence,
  type TabId,
  riskBadge,
  usageStatusBadge,
  DataSource,
} from './types';

interface RolesTabProps {
  identity: IdentityDetailsResponse['identity'];
  data: IdentityDetailsResponse;
  groupedRoles: { azure: any[]; entra: any[] };
  intelByRole: Record<string, RoleIntelligence>;
  setActiveTab: (tab: TabId) => void;
}

export function RolesTab({ identity, data, groupedRoles, intelByRole, setActiveTab }: RolesTabProps) {
  return (
    <div>
      <DataSource label="Azure Resource Manager + Microsoft Graph API" apiSource="/roleAssignments, /roleManagement/directory" collectedAt={data?.evidence?.collected_at} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-3">
        {/* Azure RBAC */}
        <div>
          <div className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
            Azure RBAC Roles
            <span className="px-2 py-0.5 rounded-full text-xs bg-blue-100 text-blue-700">
              {groupedRoles.azure.length}
            </span>
          </div>
          {groupedRoles.azure.length === 0 ? (
            <div className="text-sm text-gray-500 bg-gray-50 rounded-xl p-4">No Azure RBAC roles assigned.</div>
          ) : (
            <div className="space-y-2">
              {groupedRoles.azure.map((r: any, idx: number) => {
                const intel = intelByRole[r.role_name];
                return (
                <div key={idx} className="border rounded-xl p-4">
                  <div className="flex items-center justify-between gap-2">
                    <div className="font-semibold text-gray-900 text-sm">{r.role_name}</div>
                    <div className="flex items-center gap-1">
                      {usageStatusBadge(r.usage_status, r.redundant_with)}
                      {riskBadge(r.risk_level)}
                    </div>
                  </div>
                  <div className="text-xs text-gray-500 mt-1 break-all">{r.scope}</div>
                  <div className="flex flex-wrap gap-2 mt-2 text-xs text-gray-500">
                    {r.days_since_assigned != null && (
                      <span>Assigned {r.days_since_assigned}d ago</span>
                    )}
                    {r.resource_type && <span>| {r.resource_type}</span>}
                    {!r.scope_exists && <span className="text-red-600">| Resource deleted</span>}
                    {r.redundant_with && <span className="text-yellow-600">| Redundant with {r.redundant_with}</span>}
                  </div>
                  {r.why_critical && (
                    <div className="text-xs text-gray-700 mt-2 bg-red-50 p-2 rounded">{r.why_critical}</div>
                  )}
                  {intel && (
                    <div className="flex items-center gap-2 mt-2">
                      {intel.attack_patterns.length > 0 && (
                        <button onClick={() => setActiveTab('compliance')} className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-50 text-red-700 hover:bg-red-100 transition">
                          {intel.attack_patterns.length} incident{intel.attack_patterns.length > 1 ? 's' : ''}
                        </button>
                      )}
                      {intel.hipaa_violations.length > 0 && (
                        <button onClick={() => setActiveTab('compliance')} className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-purple-50 text-purple-700 hover:bg-purple-100 transition">
                          {intel.hipaa_violations.length} HIPAA
                        </button>
                      )}
                    </div>
                  )}
                </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Entra Directory Roles */}
        <div>
          <div className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
            Entra Directory Roles
            <span className="px-2 py-0.5 rounded-full text-xs bg-indigo-100 text-indigo-700">
              {groupedRoles.entra.length}
            </span>
          </div>
          {groupedRoles.entra.length === 0 ? (
            <div className="text-sm text-gray-500 bg-gray-50 rounded-xl p-4">No Entra directory roles assigned.</div>
          ) : (
            <div className="space-y-2">
              {groupedRoles.entra.map((r: any, idx: number) => {
                const intel = intelByRole[r.role_name];
                return (
                <div key={idx} className="border rounded-xl p-4">
                  <div className="flex items-center justify-between gap-2">
                    <div className="font-semibold text-gray-900 text-sm">{r.role_name}</div>
                    <div className="flex items-center gap-1">
                      {usageStatusBadge(r.usage_status, r.redundant_with)}
                      {riskBadge(r.risk_level)}
                    </div>
                  </div>
                  <div className="text-xs text-gray-500 mt-1 break-all">{r.scope}</div>
                  <div className="flex flex-wrap gap-2 mt-2 text-xs text-gray-500">
                    {r.days_since_assigned != null && (
                      <span>Assigned {r.days_since_assigned}d ago</span>
                    )}
                    {r.redundant_with && <span className="text-yellow-600">| Redundant with {r.redundant_with}</span>}
                  </div>
                  {r.why_critical && (
                    <div className="text-xs text-gray-700 mt-2 bg-red-50 p-2 rounded">{r.why_critical}</div>
                  )}
                  {intel && (
                    <div className="flex items-center gap-2 mt-2">
                      {intel.attack_patterns.length > 0 && (
                        <button onClick={() => setActiveTab('compliance')} className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-50 text-red-700 hover:bg-red-100 transition">
                          {intel.attack_patterns.length} incident{intel.attack_patterns.length > 1 ? 's' : ''}
                        </button>
                      )}
                      {intel.hipaa_violations.length > 0 && (
                        <button onClick={() => setActiveTab('compliance')} className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-purple-50 text-purple-700 hover:bg-purple-100 transition">
                          {intel.hipaa_violations.length} HIPAA
                        </button>
                      )}
                    </div>
                  )}
                </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
