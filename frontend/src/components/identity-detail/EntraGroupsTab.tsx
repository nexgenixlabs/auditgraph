import React, { useEffect, useState } from 'react';
import { useConnection } from '../../contexts/ConnectionContext';

interface EntraGroup {
  id: number;
  group_id: string;
  display_name: string;
  description?: string;
  security_enabled: boolean;
  is_role_assignable: boolean;
  is_privileged: boolean;
  member_count: number;
  rbac_roles: { role_name: string; scope: string; scope_type: string }[];
  is_nested: boolean;
  depth: number;
  member_type: string;
}

interface EntraGroupsTabProps {
  identityId: string;
  riskLevel?: string;
}

export function EntraGroupsTab({ identityId }: EntraGroupsTabProps) {
  const { withConnection } = useConnection();
  const [groups, setGroups] = useState<EntraGroup[]>([]);
  const [totalGroups, setTotalGroups] = useState(0);
  const [withAzureAccess, setWithAzureAccess] = useState(0);
  const [directPrivWithoutGroups, setDirectPrivWithoutGroups] = useState(false);
  const [privilegeLevel, setPrivilegeLevel] = useState('unknown');
  const [showAll, setShowAll] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const accessOnly = !showAll;
        const res = await fetch(withConnection(
          `/api/identities/${identityId}/entra-groups?access_only=${accessOnly}`
        ));
        if (res.ok) {
          const data = await res.json();
          setGroups(data.groups || []);
          setTotalGroups(data.total_groups || 0);
          setWithAzureAccess(data.with_azure_access || 0);
          setDirectPrivWithoutGroups(!!data.direct_privilege_without_groups);
          setPrivilegeLevel(data.privilege_level || 'unknown');
        }
      } catch { /* ignore */ }
      setLoading(false);
    })();
  }, [identityId, withConnection, showAll]);

  if (loading) {
    return (
      <div className="animate-pulse space-y-3 p-4">
        <div className="h-16 bg-gray-100 rounded-xl" />
        <div className="h-16 bg-gray-100 rounded-xl" />
        <div className="h-16 bg-gray-100 rounded-xl" />
      </div>
    );
  }

  const directoryOnlyCount = totalGroups - withAzureAccess;

  if (groups.length === 0 && !showAll) {
    return (
      <div className="py-8 space-y-4 px-4">
        {directPrivWithoutGroups && (
          <div className="border-l-4 border-l-amber-400 bg-amber-50 rounded-r-lg p-4">
            <div className="text-sm font-semibold text-amber-800 mb-1">CIS v8 §5.4 — Restrict Admin Privileges</div>
            <div className="text-xs text-amber-700">
              This highly privileged identity has direct subscription-scope role assignments with no group-based access control. Consider adding to a role-assignable security group for auditable privilege management.
            </div>
          </div>
        )}
        <div className="text-center">
          <svg className="w-12 h-12 text-gray-300 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
          </svg>
          <p className="text-gray-500">
            {privilegeLevel === 'highly_privileged'
              ? 'This identity is not a member of any Entra security groups'
              : 'No groups with Azure role assignments found.'}
          </p>
          {directoryOnlyCount > 0 && (
            <button
              onClick={() => setShowAll(true)}
              className="mt-2 text-xs text-blue-600 hover:text-blue-800 hover:underline"
            >
              View all {directoryOnlyCount} directory groups &rarr;
            </button>
          )}
        </div>
      </div>
    );
  }

  const nestedCount = groups.filter(g => g.is_nested).length;

  return (
    <div className="space-y-4 p-4">
      {/* Summary */}
      <div className="flex items-end gap-3">
        <div className="rounded-lg border border-purple-200 p-3 bg-purple-50 min-w-[140px]">
          <div className="text-2xl font-bold font-mono text-purple-700">{withAzureAccess}</div>
          <div className="text-xs text-gray-500">Groups with Azure access</div>
        </div>
        <div className="rounded-lg border border-blue-200 p-3 bg-blue-50 min-w-[140px]">
          <div className="text-2xl font-bold font-mono text-blue-600">{nestedCount}</div>
          <div className="text-xs text-gray-500">Nested Memberships</div>
        </div>
        {directoryOnlyCount > 0 && (
          <div className="pb-1">
            <span className="text-xs text-gray-400">
              {directoryOnlyCount} additional directory group{directoryOnlyCount !== 1 ? 's' : ''} (no Azure roles)
            </span>
            {!showAll ? (
              <button
                onClick={() => setShowAll(true)}
                className="ml-2 text-xs text-blue-500 hover:text-blue-700 hover:underline"
              >
                View all &rarr;
              </button>
            ) : (
              <button
                onClick={() => setShowAll(false)}
                className="ml-2 text-xs text-blue-500 hover:text-blue-700 hover:underline"
              >
                Show access-relevant only
              </button>
            )}
          </div>
        )}
      </div>

      {/* Group Table */}
      <div className="bg-white rounded-lg border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-50 border-b">
              {['Group Name', 'Type', 'Members', 'Depth', 'Inherited Roles', 'Status'].map(h => (
                <th key={h} className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {groups.map((g) => (
              <tr key={`${g.group_id}-${g.depth}`} className="border-b hover:bg-gray-50">
                <td className="px-4 py-3">
                  <div className="font-medium text-gray-900">{g.display_name || 'Unnamed Group'}</div>
                  {g.description && (
                    <div className="text-xs text-gray-400 mt-0.5 truncate max-w-xs">{g.description}</div>
                  )}
                </td>
                <td className="px-4 py-3">
                  <span className="px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-700">
                    {g.is_role_assignable ? 'Role-Assignable' : 'Security'}
                  </span>
                </td>
                <td className="px-4 py-3 font-mono text-gray-700">{g.member_count ?? '-'}</td>
                <td className="px-4 py-3">
                  {g.depth === 0 ? (
                    <span className="text-xs text-green-600 font-medium">Direct</span>
                  ) : (
                    <span className="text-xs text-amber-600 font-medium">Nested (L{g.depth})</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  {g.rbac_roles && g.rbac_roles.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {g.rbac_roles.slice(0, 3).map((r, ri) => (
                        <span key={ri} className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-purple-100 text-purple-700">
                          {r.role_name}
                        </span>
                      ))}
                      {g.rbac_roles.length > 3 && (
                        <span className="text-[10px] text-gray-400">+{g.rbac_roles.length - 3} more</span>
                      )}
                    </div>
                  ) : (
                    <span className="text-xs text-gray-400">None</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  {g.is_privileged ? (
                    <span className="px-2 py-0.5 rounded text-xs font-bold bg-red-100 text-red-700">Privileged</span>
                  ) : (
                    <span className="px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-600">Standard</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
