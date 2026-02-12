import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useTenant } from '../contexts/TenantContext';

interface TenantOption {
  id: number;
  name: string;
  slug: string;
  plan: string;
}

export default function Login() {
  const { login } = useAuth();
  const { resolvedTenant, isPortal, tenantSlug } = useTenant();
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [showTenantPicker, setShowTenantPicker] = useState(false);
  const [userTenants, setUserTenants] = useState<TenantOption[]>([]);

  // Phase 54: SSO status
  const [ssoEnabled, setSsoEnabled] = useState(false);
  const [ssoForced, setSsoForced] = useState(false);

  // Phase 78: Forced password change
  const [forcePasswordChange, setForcePasswordChange] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [changingPassword, setChangingPassword] = useState(false);

  useEffect(() => {
    const slug = tenantSlug || resolvedTenant?.slug;
    if (!slug) return;
    fetch(`/api/auth/sso-status?tenant_slug=${encodeURIComponent(slug)}`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data) {
          setSsoEnabled(data.sso_enabled === true);
          setSsoForced(data.sso_force_sso === true);
        }
      })
      .catch(() => {});
  }, [tenantSlug, resolvedTenant]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      // Subdomain mode: scope login to detected tenant
      // Dev mode: no tenant scoping
      const userData = await login(username, password, tenantSlug || undefined);

      // Phase 78: Check if password change is required
      if (userData?.force_password_change) {
        setForcePasswordChange(true);
        setLoading(false);
        return;
      }

      if (isPortal) {
        // Portal mode: users with portal access go straight to admin console
        const portalRole = userData?.portal_role;
        if (portalRole && ['superadmin', 'poweradmin', 'billing', 'reader'].includes(portalRole)) {
          navigate('/admin');
          return;
        }

        // Non-superadmin portal login: check tenants
        try {
          const res = await fetch('/api/auth/tenants');
          if (res.ok) {
            const data = await res.json();
            const tenants: TenantOption[] = data.tenants || [];

            if (tenants.length <= 1) {
              navigate('/');
            } else {
              setUserTenants(tenants);
              setShowTenantPicker(true);
            }
            return;
          }
        } catch {
          // If tenant fetch fails, just navigate normally
        }
      }

      navigate('/');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  async function handlePasswordChange(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (newPassword.length < 12) {
      setError('Password must be at least 12 characters');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setChangingPassword(true);
    try {
      const res = await fetch('/api/auth/password', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: password, new_password: newPassword }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to change password');

      // Re-login with new password
      const userData = await login(username, newPassword, tenantSlug || undefined);
      setForcePasswordChange(false);

      if (isPortal) {
        const portalRole = userData?.portal_role;
        if (portalRole && ['superadmin', 'poweradmin', 'billing', 'reader'].includes(portalRole)) {
          navigate('/admin');
          return;
        }
      }
      navigate('/');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to change password');
    } finally {
      setChangingPassword(false);
    }
  }

  function handleTenantSelect(tenant: TenantOption) {
    // In production, this would redirect to the subdomain
    // For now, store the selected tenant and navigate
    const hostname = window.location.hostname;
    const isDev = hostname === 'localhost' || hostname === '127.0.0.1';

    if (isDev) {
      // Dev mode: just navigate to dashboard (tenant already in JWT)
      navigate('/');
    } else {
      // Production: redirect to tenant subdomain
      const baseDomain = hostname.split('.').slice(1).join('.') || hostname;
      window.location.href = `${window.location.protocol}//${tenant.slug}.${baseDomain}`;
    }
  }

  // Tenant picker view (after successful portal login for superadmins)
  if (showTenantPicker) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
        <div className="w-full max-w-lg px-4">
          <div className="text-center mb-6">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-blue-600 text-white text-2xl font-bold mb-4">
              AG
            </div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Select Organization</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Choose which organization to access</p>
          </div>

          <div className="space-y-2">
            {userTenants.map(t => (
              <button
                key={t.id}
                onClick={() => handleTenantSelect(t)}
                className="w-full flex items-center justify-between p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl hover:border-blue-400 hover:shadow-sm transition group"
              >
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 flex items-center justify-center text-sm font-bold">
                    {t.name.substring(0, 2).toUpperCase()}
                  </div>
                  <div className="text-left">
                    <div className="text-sm font-semibold text-gray-900 dark:text-white">{t.name}</div>
                    <div className="text-xs text-gray-500">{t.slug}.auditgraph.ai</div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                    t.plan === 'enterprise' ? 'bg-purple-100 text-purple-700' :
                    t.plan === 'pro' ? 'bg-blue-100 text-blue-700' :
                    'bg-gray-100 text-gray-600'
                  }`}>{t.plan}</span>
                  <span className="text-gray-400 group-hover:text-blue-600 transition">{'\u2192'}</span>
                </div>
              </button>
            ))}
          </div>

          {/* Option to go to admin console */}
          <div className="mt-4 text-center">
            <button
              onClick={() => navigate('/')}
              className="text-xs text-gray-500 hover:text-blue-600 transition"
            >
              Continue to Admin Console {'\u2192'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Forced password change form
  if (forcePasswordChange) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
        <div className="w-full max-w-md px-4">
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-blue-600 text-white text-2xl font-bold mb-4">
              AG
            </div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Set New Password</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Your administrator requires you to set a new password</p>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm p-8 space-y-5">
            {error && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">
                {error}
              </div>
            )}

            <form onSubmit={handlePasswordChange} className="space-y-5">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">New Password</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={e => setNewPassword(e.target.value)}
                  autoFocus
                  autoComplete="new-password"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Minimum 12 characters"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Confirm Password</label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={e => setConfirmPassword(e.target.value)}
                  autoComplete="new-password"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Re-enter your new password"
                />
                {newPassword && confirmPassword && newPassword !== confirmPassword && (
                  <p className="text-xs text-red-600 mt-1">Passwords do not match</p>
                )}
              </div>

              <button
                type="submit"
                disabled={changingPassword || newPassword.length < 12 || newPassword !== confirmPassword}
                className={`w-full py-2.5 rounded-lg text-sm font-medium text-white transition ${
                  changingPassword || newPassword.length < 12 || newPassword !== confirmPassword
                    ? 'bg-gray-400 cursor-not-allowed'
                    : 'bg-blue-600 hover:bg-blue-700'
                }`}
              >
                {changingPassword ? 'Updating Password...' : 'Set Password & Continue'}
              </button>
            </form>
          </div>

          <p className="text-center text-xs text-gray-400 mt-6">
            Enterprise Identity Risk Intelligence
          </p>
        </div>
      </div>
    );
  }

  // Login form
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
      <div className="w-full max-w-md px-4">
        {/* Brand */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-blue-600 text-white text-2xl font-bold mb-4">
            AG
          </div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">AuditGraph</h1>
          {resolvedTenant ? (
            <div className="mt-2">
              <p className="text-sm text-gray-500">
                Sign in to <span className="font-semibold text-gray-700 dark:text-gray-300">{resolvedTenant.name}</span>
              </p>
              <span className={`inline-block mt-1 px-2 py-0.5 rounded text-[10px] font-semibold ${
                resolvedTenant.plan === 'enterprise' ? 'bg-purple-100 text-purple-700' :
                resolvedTenant.plan === 'pro' ? 'bg-blue-100 text-blue-700' :
                'bg-gray-100 text-gray-600'
              }`}>{resolvedTenant.plan}</span>
            </div>
          ) : (
            <p className="text-sm text-gray-500 mt-1">Sign in to your account</p>
          )}
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm p-8 space-y-5">
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">
              {error}
            </div>
          )}

          {/* Phase 54: SSO Button */}
          {ssoEnabled && (
            <>
              <button
                type="button"
                onClick={() => {
                  const slug = tenantSlug || resolvedTenant?.slug;
                  if (slug) window.location.href = `/api/auth/saml/login?tenant_slug=${encodeURIComponent(slug)}`;
                }}
                className="w-full py-2.5 rounded-lg text-sm font-medium border-2 border-blue-600 text-blue-600 hover:bg-blue-50 transition flex items-center justify-center gap-2"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                Sign in with SSO
              </button>
              {!ssoForced && (
                <div className="flex items-center gap-3 text-xs text-gray-400">
                  <div className="flex-1 h-px bg-gray-200 dark:bg-gray-700" />
                  <span>or sign in with credentials</span>
                  <div className="flex-1 h-px bg-gray-200 dark:bg-gray-700" />
                </div>
              )}
              {ssoForced && (
                <p className="text-xs text-gray-500 text-center">
                  Your organization requires SSO for authentication.
                </p>
              )}
            </>
          )}

          {/* Local login form (hidden when SSO is forced) */}
          {!ssoForced && (
            <form onSubmit={handleSubmit} className="space-y-5">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Username</label>
                <input
                  type="text"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  autoFocus={!ssoEnabled}
                  autoComplete="username"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Enter your username"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Password</label>
                <input
                  type="password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  autoComplete="current-password"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Enter your password"
                />
              </div>

              <button
                type="submit"
                disabled={loading || !username || !password}
                className={`w-full py-2.5 rounded-lg text-sm font-medium text-white transition ${
                  loading || !username || !password
                    ? 'bg-gray-400 cursor-not-allowed'
                    : 'bg-blue-600 hover:bg-blue-700'
                }`}
              >
                {loading ? 'Signing in...' : 'Sign In'}
              </button>
            </form>
          )}
        </div>

        <p className="text-center text-xs text-gray-400 mt-6">
          Enterprise Identity Risk Intelligence
        </p>
      </div>
    </div>
  );
}
