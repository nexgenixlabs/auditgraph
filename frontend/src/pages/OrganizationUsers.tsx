import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../contexts/AuthContext';

interface UserRow {
  id: number;
  username: string;
  display_name: string;
  role: string;
  enabled: boolean;
  auth_provider?: string;
  last_login_at?: string;
  email?: string;
}

interface Invitation {
  id: number;
  email: string;
  role: string;
  status: string;
  expires_at: string;
  created_at: string;
  invited_by_name?: string;
}

interface PermissionMatrix {
  [permission: string]: string[];
}

const ROLE_COLORS: Record<string, string> = {
  admin: 'bg-red-50 text-red-700',
  security_admin: 'bg-amber-50 text-amber-700',
  security_analyst: 'bg-cyan-50 text-cyan-700',
  compliance: 'bg-green-50 text-green-700',
  reader: 'bg-blue-50 text-blue-700',
  owner: 'bg-purple-50 text-purple-700',
};

const ROLE_LABELS: Record<string, string> = {
  admin: 'Admin',
  security_admin: 'Security Admin',
  security_analyst: 'Security Analyst',
  compliance: 'Compliance',
  reader: 'Reader',
  owner: 'Owner',
};

const AUTH_PROVIDER_LABELS: Record<string, { label: string; color: string }> = {
  local: { label: 'Local', color: 'bg-gray-100 text-gray-600' },
  saml: { label: 'SAML', color: 'bg-indigo-50 text-indigo-700' },
  oidc: { label: 'OIDC', color: 'bg-violet-50 text-violet-700' },
  scim: { label: 'SCIM', color: 'bg-teal-50 text-teal-700' },
};

type FilterTab = 'all' | 'active' | 'pending' | 'disabled';

export default function OrganizationUsers() {
  const { user, isAdmin } = useAuth();
  const [users, setUsers] = useState<UserRow[]>([]);
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [permissions, setPermissions] = useState<PermissionMatrix | null>(null);
  const [loading, setLoading] = useState(true);
  const [filterTab, setFilterTab] = useState<FilterTab>('all');
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [showPermissions, setShowPermissions] = useState(false);

  // Invite modal
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('reader');
  const [inviting, setInviting] = useState(false);
  const [inviteError, setInviteError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [usersRes, invRes, permRes] = await Promise.all([
        fetch('/api/users'),
        fetch('/api/invitations'),
        fetch('/api/auth/permissions'),
      ]);
      if (usersRes.ok) {
        const data = await usersRes.json();
        setUsers(data.users || []);
      }
      if (invRes.ok) {
        const data = await invRes.json();
        setInvitations(data.invitations || []);
      }
      if (permRes.ok) {
        const data = await permRes.json();
        setPermissions(data.permissions || null);
      }
    } catch { /* ignore */ }
    setLoading(false);
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const pendingInvitations = invitations.filter(i => i.status === 'pending');

  // Build unified list
  const filteredUsers = users.filter(u => {
    if (filterTab === 'active' && !u.enabled) return false;
    if (filterTab === 'disabled' && u.enabled) return false;
    if (filterTab === 'pending') return false;
    if (roleFilter && u.role !== roleFilter) return false;
    if (search) {
      const s = search.toLowerCase();
      return u.display_name.toLowerCase().includes(s) || u.username.toLowerCase().includes(s);
    }
    return true;
  });

  const filteredInvitations = filterTab === 'pending' || filterTab === 'all'
    ? pendingInvitations.filter(i => !search || i.email.toLowerCase().includes(search.toLowerCase()))
    : [];

  const handleInvite = async () => {
    setInviteError(null);
    if (!inviteEmail || !inviteEmail.includes('@')) {
      setInviteError('Please enter a valid email address');
      return;
    }
    setInviting(true);
    try {
      const res = await fetch('/api/invitations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: inviteEmail, role: inviteRole }),
      });
      const data = await res.json();
      if (!res.ok) {
        setInviteError(data.error || 'Failed to send invitation');
      } else {
        setShowInviteModal(false);
        setInviteEmail('');
        setInviteRole('reader');
        fetchData();
      }
    } catch {
      setInviteError('Network error');
    }
    setInviting(false);
  };

  const handleRevokeInvitation = async (id: number) => {
    await fetch(`/api/invitations/${id}`, { method: 'DELETE' });
    fetchData();
  };

  const handleToggleUser = async (u: UserRow) => {
    await fetch(`/api/users/${u.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !u.enabled }),
    });
    fetchData();
  };

  const handleChangeRole = async (u: UserRow, newRole: string) => {
    await fetch(`/api/users/${u.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: newRole }),
    });
    fetchData();
  };

  const tabs: { key: FilterTab; label: string; count: number }[] = [
    { key: 'all', label: 'All', count: users.length + pendingInvitations.length },
    { key: 'active', label: 'Active', count: users.filter(u => u.enabled).length },
    { key: 'pending', label: 'Pending Invitations', count: pendingInvitations.length },
    { key: 'disabled', label: 'Disabled', count: users.filter(u => !u.enabled).length },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Team Members</h1>
          <p className="text-sm text-gray-500 mt-1">Manage users and invitations for your organization</p>
        </div>
        {isAdmin && (
          <button
            onClick={() => setShowInviteModal(true)}
            className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 transition flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
            </svg>
            Invite User
          </button>
        )}
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center gap-1 border-b border-gray-200">
        {tabs.map(tab => (
          <button
            key={tab.key}
            onClick={() => setFilterTab(tab.key)}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 transition ${
              filterTab === tab.key
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            {tab.label}
            <span className="ml-1.5 text-xs bg-gray-100 text-gray-600 px-1.5 py-0.5 rounded-full">{tab.count}</span>
          </button>
        ))}
      </div>

      {/* Search + Role Filter */}
      <div className="flex items-center gap-3">
        <div className="flex-1 relative">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by name or email..."
            className="w-full pl-10 pr-4 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          />
        </div>
        <select
          value={roleFilter}
          onChange={e => setRoleFilter(e.target.value)}
          className="px-3 py-2 border rounded-lg text-sm"
        >
          <option value="">All Roles</option>
          {['admin', 'security_admin', 'security_analyst', 'compliance', 'reader'].map(r => (
            <option key={r} value={r}>{ROLE_LABELS[r] || r}</option>
          ))}
        </select>
      </div>

      {/* Users Table */}
      {loading ? (
        <div className="text-center py-12 text-gray-400">Loading...</div>
      ) : (
        <div className="bg-white rounded-xl border shadow-sm overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-50 border-b">
                <th className="text-left px-4 py-3 font-medium text-gray-600">User</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Role</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Auth Provider</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Status</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Last Login</th>
                {isAdmin && <th className="text-right px-4 py-3 font-medium text-gray-600">Actions</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {/* Active users */}
              {filteredUsers.map(u => (
                <tr key={`user-${u.id}`} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center text-xs font-bold text-gray-600 uppercase">
                        {u.display_name.charAt(0)}
                      </div>
                      <div>
                        <div className="font-medium text-gray-900">{u.display_name}</div>
                        <div className="text-xs text-gray-500">{u.username}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    {isAdmin && u.id !== user?.id ? (
                      <select
                        value={u.role}
                        onChange={e => handleChangeRole(u, e.target.value)}
                        className={`px-2 py-1 rounded text-xs font-medium border-0 cursor-pointer ${ROLE_COLORS[u.role] || 'bg-gray-100 text-gray-600'}`}
                      >
                        {['admin', 'security_admin', 'security_analyst', 'compliance', 'reader'].map(r => (
                          <option key={r} value={r}>{ROLE_LABELS[r] || r}</option>
                        ))}
                      </select>
                    ) : (
                      <span className={`px-2 py-1 rounded text-xs font-medium ${ROLE_COLORS[u.role] || 'bg-gray-100 text-gray-600'}`}>
                        {ROLE_LABELS[u.role] || u.role}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${AUTH_PROVIDER_LABELS[u.auth_provider || 'local']?.color || 'bg-gray-100 text-gray-600'}`}>
                      {AUTH_PROVIDER_LABELS[u.auth_provider || 'local']?.label || u.auth_provider || 'Local'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${u.enabled ? 'bg-green-50 text-green-700' : 'bg-yellow-50 text-yellow-700'}`}>
                      {u.enabled ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500">
                    {u.last_login_at ? new Date(u.last_login_at).toLocaleDateString() : 'Never'}
                  </td>
                  {isAdmin && (
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        {u.id !== user?.id && (
                          <>
                            <button
                              onClick={() => handleToggleUser(u)}
                              className={`px-2 py-1 text-xs rounded transition ${u.enabled ? 'text-yellow-600 hover:bg-yellow-50' : 'text-green-600 hover:bg-green-50'}`}
                            >
                              {u.enabled ? 'Disable' : 'Enable'}
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  )}
                </tr>
              ))}

              {/* Pending invitations */}
              {filteredInvitations.map(inv => (
                <tr key={`inv-${inv.id}`} className="hover:bg-gray-50 bg-blue-50/30">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center text-xs font-bold text-blue-600">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                        </svg>
                      </div>
                      <div>
                        <div className="font-medium text-gray-900">{inv.email}</div>
                        <div className="text-xs text-gray-500">
                          Invited {inv.invited_by_name ? `by ${inv.invited_by_name}` : ''} on {new Date(inv.created_at).toLocaleDateString()}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${ROLE_COLORS[inv.role] || 'bg-gray-100 text-gray-600'}`}>
                      {ROLE_LABELS[inv.role] || inv.role}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-1 rounded text-xs font-medium bg-gray-100 text-gray-500">—</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-1 rounded text-xs font-medium bg-blue-50 text-blue-700">Pending</span>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500">
                    Expires {new Date(inv.expires_at).toLocaleDateString()}
                  </td>
                  {isAdmin && (
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => handleRevokeInvitation(inv.id)}
                        className="px-2 py-1 text-xs text-red-600 hover:bg-red-50 rounded transition"
                      >
                        Revoke
                      </button>
                    </td>
                  )}
                </tr>
              ))}

              {filteredUsers.length === 0 && filteredInvitations.length === 0 && (
                <tr>
                  <td colSpan={isAdmin ? 6 : 5} className="px-4 py-12 text-center text-gray-400">
                    No users found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Permission Matrix Accordion */}
      {permissions && (
        <div className="bg-white rounded-xl border shadow-sm overflow-hidden">
          <button
            onClick={() => setShowPermissions(prev => !prev)}
            className="w-full flex items-center justify-between px-6 py-4 text-left hover:bg-gray-50 transition"
          >
            <div>
              <div className="text-sm font-semibold text-gray-900">Permission Matrix</div>
              <div className="text-xs text-gray-500">View which roles have access to each capability</div>
            </div>
            <svg className={`w-5 h-5 text-gray-400 transition-transform ${showPermissions ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {showPermissions && (
            <div className="border-t px-6 py-4">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-2 font-medium text-gray-600">Permission</th>
                    {['owner', 'admin', 'security_admin', 'security_analyst', 'compliance', 'reader'].map(role => (
                      <th key={role} className="text-center py-2 font-medium text-gray-600">
                        {ROLE_LABELS[role] || role}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {Object.entries(permissions).map(([perm, roles]) => (
                    <tr key={perm} className="hover:bg-gray-50">
                      <td className="py-2 text-gray-700 font-medium">
                        {perm.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
                      </td>
                      {['owner', 'admin', 'security_admin', 'security_analyst', 'compliance', 'reader'].map(role => (
                        <td key={role} className="text-center py-2">
                          {roles.includes(role) ? (
                            <span className="inline-block w-5 h-5 rounded-full bg-green-100 text-green-700 leading-5 text-center">✓</span>
                          ) : (
                            <span className="inline-block w-5 h-5 rounded-full bg-gray-100 text-gray-300 leading-5 text-center">—</span>
                          )}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Invite Modal */}
      {showInviteModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowInviteModal(false)}>
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Invite Team Member</h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Email Address</label>
                <input
                  type="email"
                  value={inviteEmail}
                  onChange={e => setInviteEmail(e.target.value)}
                  autoFocus
                  className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="colleague@company.com"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Role</label>
                <div className="flex flex-wrap gap-2">
                  {['admin', 'security_admin', 'security_analyst', 'compliance', 'reader'].map(role => (
                    <button
                      key={role}
                      onClick={() => setInviteRole(role)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition ${
                        inviteRole === role
                          ? role === 'admin' ? 'bg-red-600 text-white border-red-600'
                            : role === 'security_admin' ? 'bg-amber-600 text-white border-amber-600'
                            : role === 'security_analyst' ? 'bg-cyan-600 text-white border-cyan-600'
                            : role === 'compliance' ? 'bg-green-600 text-white border-green-600'
                            : 'bg-blue-600 text-white border-blue-600'
                          : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                      }`}
                    >
                      {ROLE_LABELS[role] || role}
                    </button>
                  ))}
                </div>
              </div>

              {inviteError && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">{inviteError}</div>
              )}
            </div>

            <div className="flex justify-end gap-3 mt-6">
              <button
                onClick={() => setShowInviteModal(false)}
                className="px-4 py-2 text-sm text-gray-600 hover:bg-gray-100 rounded-lg transition"
              >
                Cancel
              </button>
              <button
                onClick={handleInvite}
                disabled={inviting}
                className="px-4 py-2 text-sm font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-40 transition"
              >
                {inviting ? 'Sending...' : 'Send Invitation'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
