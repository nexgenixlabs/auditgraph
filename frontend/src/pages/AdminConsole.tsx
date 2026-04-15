import React, { useState } from 'react';
import { Routes, Route, Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { AdminOverview, AdminTenants, AdminOnboarding, AdminMonitoring, AdminBilling, AdminUsers, AdminProfile, AdminActionLog, AdminPlatformOps } from './admin';
import AdminSLA from './admin/AdminSLA';

type PortalRole = 'superadmin' | 'poweradmin' | 'billing' | 'reader';

const ALL_PORTAL_ROLES: PortalRole[] = ['superadmin', 'poweradmin', 'billing', 'reader'];

type NavItem = {
  path: string;
  label: string;
  icon: string;
  allowedRoles?: PortalRole[];
};

const NAV_ITEMS: NavItem[] = [
  { path: '', label: 'Overview', icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6' },
  { path: 'tenants', label: 'Clients', icon: 'M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4', allowedRoles: ['superadmin', 'poweradmin'] },
  { path: 'users', label: 'Users', icon: 'M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z', allowedRoles: ['superadmin'] },
  { path: 'onboarding', label: 'Onboarding', icon: 'M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z', allowedRoles: ['superadmin', 'poweradmin'] },
  { path: 'monitoring', label: 'Monitoring', icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z', allowedRoles: ['superadmin', 'poweradmin', 'reader'] },
  { path: 'sla', label: 'SLA', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z', allowedRoles: ['superadmin', 'poweradmin', 'reader'] },
  { path: 'billing', label: 'Billing', icon: 'M9 14l6-6m-5.5.5h.01m4.99 5h.01M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16l3.5-2 3.5 2 3.5-2 3.5 2z', allowedRoles: ['superadmin', 'poweradmin', 'billing'] },
  { path: 'action-log', label: 'Action Log', icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01', allowedRoles: ['superadmin', 'poweradmin', 'reader'] },
  { path: 'platform-ops', label: 'Platform Ops', icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z', allowedRoles: ['superadmin'] },
  { path: 'profile', label: 'Profile', icon: 'M5.121 17.804A13.937 13.937 0 0112 16c2.5 0 4.847.655 6.879 1.804M15 10a3 3 0 11-6 0 3 3 0 016 0zm6 2a9 9 0 11-18 0 9 9 0 0118 0z' },
];

const ROLE_BADGE_COLORS: Record<PortalRole, string> = {
  superadmin: 'bg-purple-900/50 text-purple-300',
  poweradmin: 'bg-blue-900/50 text-blue-300',
  billing: 'bg-green-900/50 text-green-300',
  reader: 'bg-gray-700/50 text-gray-300',
};

/* ─── Admin Login Screen ─── */
function AdminLogin() {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const userData = await login(username, password);
      const portalRole = userData?.portal_role;
      if (!portalRole || !(ALL_PORTAL_ROLES as string[]).includes(portalRole)) {
        setError('Access denied. This portal is for platform administrators only.');
        return;
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950">
      <div className="w-full max-w-md px-4">
        {/* Brand */}
        <div className="text-center mb-8">
          <img src="/auditgraph-logo.png" alt="NexgenixLabs" className="w-16 h-16 rounded-2xl mb-4 mx-auto" />
          <h1 className="text-2xl font-bold text-white">NexgenixLabs</h1>
          <p className="text-sm text-gray-400 mt-1">Platform Administration</p>
        </div>

        <div className="bg-gray-900 rounded-xl border border-gray-700 shadow-lg p-8 space-y-5">
          {error && (
            <div className="bg-red-900/40 border border-red-700 rounded-lg p-3 text-sm text-red-300">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Username</label>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                autoFocus
                autoComplete="username"
                className="w-full px-3 py-2 border border-gray-600 rounded-lg text-sm bg-gray-800 text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="Admin username"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Password</label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                autoComplete="current-password"
                className="w-full px-3 py-2 border border-gray-600 rounded-lg text-sm bg-gray-800 text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="Enter your password"
              />
            </div>

            <button
              type="submit"
              disabled={loading || !username || !password}
              className={`w-full py-2.5 rounded-lg text-sm font-medium text-white transition ${
                loading || !username || !password
                  ? 'bg-gray-600 cursor-not-allowed'
                  : 'bg-blue-600 hover:bg-blue-700'
              }`}
            >
              {loading ? 'Signing in...' : 'Sign In to Admin Portal'}
            </button>
          </form>
        </div>

        <p className="text-center text-xs text-gray-600 mt-6">
          Platform Administration Only
        </p>
      </div>
    </div>
  );
}

/* ─── Admin Console (authenticated) ─── */
export default function AdminConsole() {
  const { user, loading, logout, activeOrgId, switchOrganization } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  // Loading state
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-950">
        <div className="text-gray-400 text-sm">Loading...</div>
      </div>
    );
  }

  const portalRole = user?.portal_role as PortalRole | undefined;
  const hasPortalAccess = !!portalRole && (ALL_PORTAL_ROLES as string[]).includes(portalRole);

  // Not logged in or no portal access — show admin login
  if (!user || !hasPortalAccess) {
    return <AdminLogin />;
  }

  const currentPath = location.pathname.replace('/admin', '').replace(/^\//, '');

  // Filter nav items based on role
  const visibleNav = NAV_ITEMS.filter(item => {
    if (!item.allowedRoles) return true; // visible to all portal roles
    return item.allowedRoles.includes(portalRole);
  });

  // Check if user's role allows a route
  function isRouteAllowed(allowedRoles?: PortalRole[]) {
    if (!allowedRoles) return true;
    return !!portalRole && allowedRoles.includes(portalRole);
  }

  function handleBackToDashboard() {
    switchOrganization(null);
    navigate('/');
  }

  const badgeColor = ROLE_BADGE_COLORS[portalRole] || ROLE_BADGE_COLORS.reader;

  return (
    <div className="flex flex-col h-screen">
      {/* Admin Top Bar */}
      <div className="h-14 bg-gray-900 border-b border-gray-700 flex items-center justify-between px-5 flex-shrink-0">
        <div className="flex items-center gap-3">
          <img src="/auditgraph-logo.png" alt="NexgenixLabs" className="w-8 h-8 rounded-lg" />
          <div>
            <span className="text-sm font-semibold text-white">NexgenixLabs</span>
            <span className="text-xs text-gray-400 ml-2">Admin Portal</span>
          </div>
        </div>
        <div className="flex items-center gap-4">
          {!!activeOrgId && (
            <button
              onClick={handleBackToDashboard}
              className="text-xs text-blue-400 hover:text-blue-300 transition"
            >
              Back to Dashboard
            </button>
          )}
          <Link to="/admin/profile" className="flex items-center gap-2 hover:opacity-80 transition">
            <span className="text-xs text-gray-400">{user?.display_name || user?.username}</span>
            <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${badgeColor}`}>
              {portalRole}
            </span>
          </Link>
          <button
            onClick={() => { logout(); }}
            className="text-xs text-gray-400 hover:text-white transition"
          >
            Logout
          </button>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <div className="w-56 bg-gray-900 text-white flex-shrink-0 overflow-y-auto">
          <div className="p-4 border-b border-gray-700">
            <h2 className="text-sm font-bold text-white">Admin Console</h2>
            <p className="text-[10px] text-gray-400 mt-0.5">Platform Management</p>
          </div>
          <nav className="p-2 space-y-0.5">
            {visibleNav.map(item => {
              const isActive = item.path === ''
                ? currentPath === '' || currentPath === '/'
                : currentPath.startsWith(item.path);
              return (
                <Link
                  key={item.path}
                  to={`/admin${item.path ? `/${item.path}` : ''}`}
                  className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition ${
                    isActive
                      ? 'bg-blue-600 text-white font-medium'
                      : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                  }`}
                >
                  <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={item.icon} />
                  </svg>
                  {item.label}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Content */}
        <div className="flex-1 bg-gray-50 p-6 overflow-y-auto">
          <Routes>
            <Route index element={<AdminOverview />} />
            {isRouteAllowed(['superadmin', 'poweradmin']) && <Route path="tenants" element={<AdminTenants />} />}
            {isRouteAllowed(['superadmin']) && <Route path="users" element={<AdminUsers />} />}
            {isRouteAllowed(['superadmin', 'poweradmin']) && <Route path="onboarding" element={<AdminOnboarding />} />}
            {isRouteAllowed(['superadmin', 'poweradmin', 'reader']) && <Route path="monitoring" element={<AdminMonitoring />} />}
            {isRouteAllowed(['superadmin', 'poweradmin', 'reader']) && <Route path="sla" element={<AdminSLA />} />}
            {isRouteAllowed(['superadmin', 'poweradmin', 'billing']) && <Route path="billing" element={<AdminBilling />} />}
            {isRouteAllowed(['superadmin', 'poweradmin', 'reader']) && <Route path="action-log" element={<AdminActionLog />} />}
            {isRouteAllowed(['superadmin']) && <Route path="platform-ops" element={<AdminPlatformOps />} />}
            <Route path="profile" element={<AdminProfile />} />
          </Routes>
        </div>
      </div>
    </div>
  );
}
