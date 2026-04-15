import React from 'react';
import {
  type IdentityDetailsResponse,
  riskBadge,
  DataSource,
} from './types';

interface PermissionsTabProps {
  data: IdentityDetailsResponse;
}

export function PermissionsTab({ data }: PermissionsTabProps) {
  return (
    <div className="space-y-6">
      <DataSource label="Microsoft Graph API" apiSource="/servicePrincipals/{id}/appRoleAssignments" collectedAt={data?.evidence?.collected_at} />
      {/* Graph API Permissions */}
      <div>
        <div className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
          Microsoft Graph API Permissions
          <span className="px-2 py-0.5 rounded-full text-xs bg-purple-100 text-purple-700">
            {(data?.graph_permissions || []).length}
          </span>
        </div>
        {(data?.graph_permissions || []).length === 0 ? (
          <div className="text-sm text-gray-500 bg-gray-50 rounded-xl p-4">No Graph API permissions discovered.</div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {data!.graph_permissions.map((p: any, idx: number) => (
              <div key={idx} className="border rounded-xl p-4">
                <div className="flex items-center justify-between gap-2">
                  <div className="font-semibold text-gray-900 text-sm">{p.permission_name}</div>
                  {riskBadge(p.risk_level)}
                </div>
                {p.permission_description && (
                  <div className="text-xs text-gray-600 mt-1">{p.permission_description}</div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* App Role Assignments */}
      <div>
        <div className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
          Application Role Assignments
          <span className="px-2 py-0.5 rounded-full text-xs bg-indigo-100 text-indigo-700">
            {(data?.app_roles || []).length}
          </span>
        </div>
        {(data?.app_roles || []).length === 0 ? (
          <div className="text-sm text-gray-500 bg-gray-50 rounded-xl p-4">No custom app role assignments discovered.</div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {data!.app_roles.map((r: any, idx: number) => (
              <div key={idx} className="border rounded-xl p-4">
                <div className="flex items-center justify-between gap-2">
                  <div className="font-semibold text-gray-900 text-sm">{r.resource_display_name || 'App'}</div>
                  {riskBadge(r.risk_level)}
                </div>
                <div className="text-xs text-gray-500 mt-1 break-all">{r.resource_id}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
