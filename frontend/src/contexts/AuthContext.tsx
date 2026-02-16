import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';

interface User {
  id: number;
  username: string;
  display_name: string;
  role: 'admin' | 'security_admin' | 'compliance' | 'reader';
  tenant_id?: number;
  tenant_name?: string;
  is_superadmin?: boolean;
  portal_role?: 'superadmin' | 'poweradmin' | 'billing' | 'reader' | null;
  force_password_change?: boolean;
}

type PortalContext = 'admin' | 'client';

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  login: (username: string, password: string, tenantSlug?: string, portal?: PortalContext) => Promise<any>;
  loginWithSsoCode: (code: string) => Promise<void>;
  logout: () => Promise<void>;
  isAdmin: boolean;
  isReader: boolean;
  isSecurityAdmin: boolean;
  isSuperAdmin: boolean;
  canActivateSubscriptions: boolean;
  canSeePricing: boolean;
  canManageConnections: boolean;
  canManageUsers: boolean;
  activeTenantId: number | null;
  activeTenantName: string | null;
  switchTenant: (tenantId: number | null, tenantName?: string) => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/**
 * API base URL — empty string in dev (proxy handles it),
 * full backend URL in production (SWA has no proxy).
 * Set via REACT_APP_API_URL at build time.
 */
const API_BASE = process.env.REACT_APP_API_URL || '';

/** Resolve a /api/* path to a full URL when API_BASE is set. */
function resolveApiUrl(url: string): string {
  if (API_BASE && url.startsWith('/api/')) {
    return `${API_BASE}${url}`;
  }
  return url;
}

/** Detect which portal we're running in based on current URL path. */
function detectPortal(): PortalContext {
  return window.location.pathname.startsWith('/admin') ? 'admin' : 'client';
}

/** Get localStorage key names for a given portal context. */
function tokenKeys(portal: PortalContext) {
  if (portal === 'admin') {
    return { access: 'admin_access_token', refresh: 'admin_refresh_token' };
  }
  return { access: 'access_token', refresh: 'refresh_token' };
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const originalFetchRef = useRef<typeof window.fetch>(window.fetch.bind(window));
  const refreshingRef = useRef<Promise<boolean> | null>(null);

  // Phase 46: Tenant switching for superadmins
  const [activeTenantId, setActiveTenantId] = useState<number | null>(() => {
    const stored = localStorage.getItem('active_tenant_id');
    return stored ? parseInt(stored, 10) : null;
  });
  const [activeTenantName, setActiveTenantName] = useState<string | null>(
    () => localStorage.getItem('active_tenant_name')
  );

  const switchTenant = useCallback((tenantId: number | null, tenantName?: string) => {
    setActiveTenantId(tenantId);
    setActiveTenantName(tenantName || null);
    if (tenantId !== null) {
      localStorage.setItem('active_tenant_id', String(tenantId));
      localStorage.setItem('active_tenant_name', tenantName || '');
    } else {
      localStorage.removeItem('active_tenant_id');
      localStorage.removeItem('active_tenant_name');
    }
  }, []);

  const tryRefresh = useCallback(async (): Promise<boolean> => {
    const portal = detectPortal();
    const keys = tokenKeys(portal);
    const refreshToken = localStorage.getItem(keys.refresh);
    if (!refreshToken) return false;

    try {
      const res = await originalFetchRef.current(resolveApiUrl('/api/auth/refresh'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
      if (!res.ok) return false;

      const data = await res.json();
      localStorage.setItem(keys.access, data.access_token);
      localStorage.setItem(keys.refresh, data.refresh_token);
      setUser(data.user);
      return true;
    } catch {
      return false;
    }
  }, []);

  // Global fetch interceptor
  useEffect(() => {
    const origFetch = originalFetchRef.current;

    window.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;

      // Attach auth header to API calls (except login/refresh)
      if (url.startsWith('/api/') && !url.startsWith('/api/auth/login') && !url.startsWith('/api/auth/refresh')) {
        const portal = detectPortal();
        const keys = tokenKeys(portal);
        const token = localStorage.getItem(keys.access);
        if (token) {
          const headers = new Headers(init?.headers);
          if (!headers.has('Authorization')) {
            headers.set('Authorization', `Bearer ${token}`);
          }
          // Phase 46: Attach tenant override header for superadmins (admin portal only)
          const activeTid = localStorage.getItem('active_tenant_id');
          if (activeTid && !headers.has('X-Tenant-Id')) {
            const currentPortal = detectPortal();
            if (currentPortal === 'admin') {
              headers.set('X-Tenant-Id', activeTid);
            }
          }
          init = { ...init, headers };
        }
      }

      // Resolve /api/* URLs to full backend URL when API_BASE is set (SWA mode)
      const resolvedInput = typeof input === 'string' ? resolveApiUrl(input) : input;
      let response = await origFetch(resolvedInput, init);

      // On 401, try token refresh once (deduplicated)
      if (response.status === 401 && url.startsWith('/api/') && !url.startsWith('/api/auth/')) {
        if (!refreshingRef.current) {
          refreshingRef.current = tryRefresh().finally(() => { refreshingRef.current = null; });
        }
        const refreshed = await refreshingRef.current;
        if (refreshed) {
          const portal = detectPortal();
          const keys = tokenKeys(portal);
          const newToken = localStorage.getItem(keys.access);
          if (newToken) {
            const headers = new Headers(init?.headers);
            headers.set('Authorization', `Bearer ${newToken}`);
            response = await origFetch(resolvedInput, { ...init, headers });
          }
        } else {
          const portal = detectPortal();
          const keys = tokenKeys(portal);
          localStorage.removeItem(keys.access);
          localStorage.removeItem(keys.refresh);
          setUser(null);
        }
      }

      return response;
    };

    return () => { window.fetch = origFetch; };
  }, [tryRefresh]);

  // Check existing token on mount
  useEffect(() => {
    const portal = detectPortal();
    const keys = tokenKeys(portal);
    const token = localStorage.getItem(keys.access);
    if (!token) {
      setLoading(false);
      return;
    }

    originalFetchRef.current(resolveApiUrl('/api/auth/me'), {
      headers: { 'Authorization': `Bearer ${token}` },
    })
      .then(res => {
        if (!res.ok) throw new Error('Invalid token');
        return res.json();
      })
      .then(data => setUser(data.user))
      .catch(() => {
        tryRefresh().then(ok => {
          if (!ok) {
            localStorage.removeItem(keys.access);
            localStorage.removeItem(keys.refresh);
          }
        });
      })
      .finally(() => setLoading(false));
  }, [tryRefresh]);

  const login = useCallback(async (username: string, password: string, tenantSlug?: string, portal?: PortalContext) => {
    const resolvedPortal = portal || detectPortal();
    const keys = tokenKeys(resolvedPortal);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const body: any = { username, password, portal: resolvedPortal };
    if (tenantSlug) body.tenant_slug = tenantSlug;
    const res = await originalFetchRef.current(resolveApiUrl('/api/auth/login'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.message || data.error || 'Login failed');
    }
    const data = await res.json();
    localStorage.setItem(keys.access, data.access_token);
    localStorage.setItem(keys.refresh, data.refresh_token);
    // Don't set user when force_password_change is required — keeps user null
    // so the /login route stays active and Login.tsx can show the password change form
    if (!data.user?.force_password_change) {
      setUser(data.user);
    }
    return data.user;
  }, []);

  // Phase 54: SSO code-to-token exchange
  const loginWithSsoCode = useCallback(async (code: string) => {
    const portal = detectPortal();
    const keys = tokenKeys(portal);
    const res = await originalFetchRef.current(resolveApiUrl('/api/auth/saml/token'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || 'SSO login failed');
    }
    const data = await res.json();
    localStorage.setItem(keys.access, data.access_token);
    localStorage.setItem(keys.refresh, data.refresh_token);
    setUser(data.user);
  }, []);

  const logout = useCallback(async () => {
    const portal = detectPortal();
    const keys = tokenKeys(portal);
    const refreshToken = localStorage.getItem(keys.refresh);
    const accessToken = localStorage.getItem(keys.access);
    try {
      await originalFetchRef.current(resolveApiUrl('/api/auth/logout'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {}),
        },
        body: JSON.stringify({ refresh_token: refreshToken, portal }),
      });
    } catch { /* ignore */ }
    // Only clear the current portal's tokens
    localStorage.removeItem(keys.access);
    localStorage.removeItem(keys.refresh);
    // Only clear tenant context if logging out of admin portal
    if (portal === 'admin') {
      localStorage.removeItem('active_tenant_id');
      localStorage.removeItem('active_tenant_name');
      setActiveTenantId(null);
      setActiveTenantName(null);
    }
    setUser(null);
  }, []);

  const role = user?.role;
  const value: AuthContextValue = {
    user,
    loading,
    login,
    loginWithSsoCode,
    logout,
    isAdmin: role === 'admin',
    isReader: role === 'reader' || role === 'admin',
    isSecurityAdmin: role === 'security_admin',
    isSuperAdmin: user?.is_superadmin === true,
    canActivateSubscriptions: role === 'admin' || role === 'security_admin',
    canSeePricing: role === 'admin',
    canManageConnections: role === 'admin' || role === 'security_admin',
    canManageUsers: role === 'admin',
    activeTenantId,
    activeTenantName,
    switchTenant,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
}
