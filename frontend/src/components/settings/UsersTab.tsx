import React from 'react';
import type { UserData } from './types';

export interface UsersTabProps {
  users: UserData[];
  userError: string | null;
  setUserError: (error: string | null) => void;
  openUserModal: (u?: UserData) => void;
  handleToggleUser: (u: UserData) => void;
  userDeleteConfirm: number | null;
  setUserDeleteConfirm: (id: number | null) => void;
  handleUserDelete: (id: number) => void;
  isSuperAdmin: boolean;
}

export function UsersTab({
  users,
  userError,
  setUserError,
  openUserModal,
  handleToggleUser,
  userDeleteConfirm,
  setUserDeleteConfirm,
  handleUserDelete,
  isSuperAdmin,
}: UsersTabProps) {
  return (
    <>
      {/* Section 7: User Management */}
      <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-lg font-semibold text-gray-900">User Management</div>
            <p className="text-sm text-gray-500 mt-0.5">
              Manage user accounts and role-based access control
            </p>
          </div>
          <button
            onClick={() => openUserModal()}
            className="px-4 py-2 rounded-lg text-sm font-medium bg-blue-600 text-white hover:bg-blue-700 transition"
          >
            + Add User
          </button>
        </div>

        {userError && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">
            {userError}
            <button onClick={() => setUserError(null)} className="ml-2 font-medium underline">Dismiss</button>
          </div>
        )}

        {users.length === 0 ? (
          <p className="text-sm text-gray-400 py-4 text-center">No users configured</p>
        ) : (
          <div className="space-y-2">
            {users.map(u => (
              <div key={u.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg border">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center text-xs font-bold text-gray-600 uppercase">
                    {u.display_name.charAt(0)}
                  </div>
                  <div>
                    <div className="text-sm font-medium text-gray-900 flex items-center gap-2">
                      {u.display_name}
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium uppercase ${
                        u.role === 'admin' ? 'bg-red-50 text-red-700' :
                        u.role === 'security_admin' ? 'bg-amber-50 text-amber-700' :
                        u.role === 'security_analyst' ? 'bg-cyan-50 text-cyan-700' :
                        u.role === 'compliance' ? 'bg-green-50 text-green-700' :
                        'bg-blue-50 text-blue-700'
                      }`}>
                        {u.role === 'security_admin' ? 'Security Admin' :
                         u.role === 'security_analyst' ? 'Security Analyst' : u.role}
                      </span>
                      {!u.enabled && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-yellow-50 text-yellow-700">DISABLED</span>
                      )}
                      {isSuperAdmin && u.org_name && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-purple-50 text-purple-700">{u.org_name}</span>
                      )}
                    </div>
                    <div className="text-xs text-gray-500">
                      @{u.username}
                      {u.last_login_at && <> &middot; Last login: {new Date(u.last_login_at).toLocaleDateString()}</>}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleToggleUser(u)}
                    className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                      u.enabled ? 'bg-green-500' : 'bg-gray-300'
                    }`}
                    title={u.enabled ? 'Disable user' : 'Enable user'}
                  >
                    <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                      u.enabled ? 'translate-x-4' : 'translate-x-0.5'
                    }`} />
                  </button>
                  <button
                    onClick={() => openUserModal(u)}
                    className="px-2 py-1 text-xs text-blue-600 hover:bg-blue-50 rounded transition"
                  >
                    Edit
                  </button>
                  {userDeleteConfirm === u.id ? (
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => handleUserDelete(u.id)}
                        className="px-2 py-1 text-xs text-white bg-red-600 hover:bg-red-700 rounded transition"
                      >
                        Confirm
                      </button>
                      <button
                        onClick={() => setUserDeleteConfirm(null)}
                        className="px-2 py-1 text-xs text-gray-600 hover:bg-gray-100 rounded transition"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => setUserDeleteConfirm(u.id)}
                      className="px-2 py-1 text-xs text-red-600 hover:bg-red-50 rounded transition"
                    >
                      Delete
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        <p className="text-xs text-gray-400">
          Roles: Admin (full access), Security Admin (scan + remediation), Security Analyst (findings + simulations), Reader (read-only), Compliance (reports + compliance config). The last admin cannot be deleted or demoted.
        </p>
      </div>
    </>
  );
}
