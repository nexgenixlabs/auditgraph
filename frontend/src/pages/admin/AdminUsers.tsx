import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../../contexts/AuthContext';

type PortalRole = 'superadmin' | 'poweradmin' | 'billing' | 'reader';

interface PortalUser {
  id: number;
  username: string;
  display_name: string;
  role: string;
  portal_role: PortalRole;
  enabled: boolean;
  is_superadmin: boolean;
  created_at: string;
  last_login_at: string | null;
}

const ROLE_BADGE_COLORS: Record<PortalRole, string> = {
  superadmin: 'bg-purple-100 text-purple-700',
  poweradmin: 'bg-blue-100 text-blue-700',
  billing: 'bg-green-100 text-green-700',
  reader: 'bg-gray-100 text-gray-600',
};

export default function AdminUsers() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<PortalUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Create user modal
  const [showCreate, setShowCreate] = useState(false);
  const [createForm, setCreateForm] = useState({
    username: '',
    display_name: '',
    password: '',
    portal_role: 'reader' as PortalRole,
  });
  const [createLoading, setCreateLoading] = useState(false);

  // Edit user modal
  const [showEdit, setShowEdit] = useState<PortalUser | null>(null);
  const [editForm, setEditForm] = useState({
    display_name: '',
    portal_role: 'reader' as PortalRole,
    enabled: true,
  });

  const fetchUsers = useCallback(async () => {
    try {
      const res = await fetch('/api/portal-users');
      if (!res.ok) throw new Error('Failed to load portal users');
      const data = await res.json();
      setUsers(data.users || []);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load users');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchUsers(); }, [fetchUsers]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreateLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: createForm.username,
          display_name: createForm.display_name,
          password: createForm.password,
          role: 'admin',
          portal_role: createForm.portal_role,
          is_superadmin: createForm.portal_role === 'superadmin',
        }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to create user');
      }
      setSuccess('Portal user created successfully');
      setShowCreate(false);
      setCreateForm({ username: '', display_name: '', password: '', portal_role: 'reader' });
      fetchUsers();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create user');
    } finally {
      setCreateLoading(false);
    }
  }

  async function handleEdit() {
    if (!showEdit) return;
    setError(null);
    try {
      const res = await fetch(`/api/users/${showEdit.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          display_name: editForm.display_name,
          portal_role: editForm.portal_role,
          is_superadmin: editForm.portal_role === 'superadmin',
          enabled: editForm.enabled,
        }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to update user');
      }
      setSuccess('User updated successfully');
      setShowEdit(null);
      fetchUsers();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update user');
    }
  }

  async function handleRemovePortalAccess(userId: number) {
    setError(null);
    try {
      const res = await fetch(`/api/users/${userId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ portal_role: null, is_superadmin: false }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to remove portal access');
      }
      setSuccess('Portal access removed');
      fetchUsers();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to remove access');
    }
  }

  // Clear messages after 3s
  useEffect(() => {
    if (success) { const t = setTimeout(() => setSuccess(null), 3000); return () => clearTimeout(t); }
  }, [success]);
  useEffect(() => {
    if (error) { const t = setTimeout(() => setError(null), 5000); return () => clearTimeout(t); }
  }, [error]);

  if (loading) {
    return <div className="text-sm text-gray-500 p-8">Loading portal users...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-900">Portal Users</h1>
          <p className="text-sm text-gray-500 mt-1">Manage admin portal staff across all portal roles</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 transition"
        >
          + Add Portal User
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">{error}</div>
      )}
      {success && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-3 text-sm text-green-700">{success}</div>
      )}

      {/* Role Legend */}
      <div className="bg-white rounded-xl border border-gray-200 p-4">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Portal Roles</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div className="flex items-start gap-3">
            <span className="inline-block px-2 py-0.5 rounded text-xs font-medium bg-purple-100 text-purple-700 mt-0.5">superadmin</span>
            <div className="text-xs text-gray-600">Full platform access — tenant management, billing, user management, delete operations</div>
          </div>
          <div className="flex items-start gap-3">
            <span className="inline-block px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-700 mt-0.5">poweradmin</span>
            <div className="text-xs text-gray-600">Create/edit/provision tenants, view billing & monitoring. Cannot delete tenants or manage portal users</div>
          </div>
          <div className="flex items-start gap-3">
            <span className="inline-block px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-700 mt-0.5">billing</span>
            <div className="text-xs text-gray-600">Read-only tenant list and billing page only</div>
          </div>
          <div className="flex items-start gap-3">
            <span className="inline-block px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-600 mt-0.5">reader</span>
            <div className="text-xs text-gray-600">Read-only overview, tenant list, and monitoring only</div>
          </div>
        </div>
      </div>

      {/* Users Table */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 border-b border-gray-200">
            <tr>
              <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase">User</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase">Portal Role</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase">Status</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase">Last Login</th>
              <th className="text-right px-4 py-3 text-xs font-semibold text-gray-500 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {users.length === 0 ? (
              <tr>
                <td colSpan={5} className="text-center py-8 text-gray-400">No portal users found</td>
              </tr>
            ) : users.map(u => (
              <tr key={u.id} className="hover:bg-gray-50">
                <td className="px-4 py-3">
                  <div className="font-medium text-gray-900">{u.display_name}</div>
                  <div className="text-xs text-gray-500">{u.username}</div>
                </td>
                <td className="px-4 py-3">
                  <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${
                    ROLE_BADGE_COLORS[u.portal_role] || ROLE_BADGE_COLORS.reader
                  }`}>
                    {u.portal_role}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${
                    u.enabled ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'
                  }`}>
                    {u.enabled ? 'Active' : 'Disabled'}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs text-gray-500">
                  {u.last_login_at ? new Date(u.last_login_at).toLocaleDateString() : 'Never'}
                </td>
                <td className="px-4 py-3 text-right">
                  <div className="flex items-center justify-end gap-2">
                    <button
                      onClick={() => {
                        setShowEdit(u);
                        setEditForm({
                          display_name: u.display_name,
                          portal_role: u.portal_role,
                          enabled: u.enabled,
                        });
                      }}
                      className="text-xs text-blue-600 hover:text-blue-800"
                    >
                      Edit
                    </button>
                    {u.id !== currentUser?.id && (
                      <button
                        onClick={() => handleRemovePortalAccess(u.id)}
                        className="text-xs text-red-600 hover:text-red-800"
                      >
                        Remove Access
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Create User Modal */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowCreate(false)}>
          <div className="bg-white rounded-xl shadow-xl w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
            <h2 className="text-lg font-bold text-gray-900 mb-4">Add Portal User</h2>
            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
                <input
                  type="text"
                  value={createForm.username}
                  onChange={e => setCreateForm(f => ({ ...f, username: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="username"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Display Name</label>
                <input
                  type="text"
                  value={createForm.display_name}
                  onChange={e => setCreateForm(f => ({ ...f, display_name: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Full Name"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
                <input
                  type="password"
                  value={createForm.password}
                  onChange={e => setCreateForm(f => ({ ...f, password: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Min 8 characters"
                  required
                  minLength={8}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Portal Role</label>
                <select
                  value={createForm.portal_role}
                  onChange={e => setCreateForm(f => ({ ...f, portal_role: e.target.value as PortalRole }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                >
                  <option value="reader">Reader — read-only overview, tenants, and monitoring</option>
                  <option value="billing">Billing — read-only tenants and billing page</option>
                  <option value="poweradmin">Power Admin — create/edit/provision tenants, view billing</option>
                  <option value="superadmin">Superadmin — full platform access</option>
                </select>
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreate(false)}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createLoading || !createForm.username || !createForm.display_name || !createForm.password}
                  className={`px-4 py-2 text-sm font-medium text-white rounded-lg transition ${
                    createLoading ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'
                  }`}
                >
                  {createLoading ? 'Creating...' : 'Create User'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit User Modal */}
      {showEdit && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowEdit(null)}>
          <div className="bg-white rounded-xl shadow-xl w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
            <h2 className="text-lg font-bold text-gray-900 mb-4">Edit Portal User</h2>
            <p className="text-sm text-gray-500 mb-4">{showEdit.username}</p>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Display Name</label>
                <input
                  type="text"
                  value={editForm.display_name}
                  onChange={e => setEditForm(f => ({ ...f, display_name: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Portal Role</label>
                <select
                  value={editForm.portal_role}
                  onChange={e => setEditForm(f => ({ ...f, portal_role: e.target.value as PortalRole }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  disabled={showEdit.id === currentUser?.id}
                >
                  <option value="reader">Reader</option>
                  <option value="billing">Billing</option>
                  <option value="poweradmin">Power Admin</option>
                  <option value="superadmin">Superadmin</option>
                </select>
                {showEdit.id === currentUser?.id && (
                  <p className="text-xs text-gray-400 mt-1">Cannot change your own portal role</p>
                )}
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="edit-enabled"
                  checked={editForm.enabled}
                  onChange={e => setEditForm(f => ({ ...f, enabled: e.target.checked }))}
                  disabled={showEdit.id === currentUser?.id}
                  className="rounded border-gray-300"
                />
                <label htmlFor="edit-enabled" className="text-sm text-gray-700">Account enabled</label>
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowEdit(null)}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200"
                >
                  Cancel
                </button>
                <button
                  onClick={handleEdit}
                  className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 transition"
                >
                  Save Changes
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
