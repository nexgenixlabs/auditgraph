import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';

interface User {
  id: number;
  username: string;
  display_name: string;
  role: 'admin' | 'security_admin' | 'compliance' | 'reader';
  organization_id?: number;
  org_name?: string;
  is_superadmin?: boolean;
  portal_role?: 'superadmin' | 'poweradmin' | 'billing' | 'reader' | null;
  force_password_change?: boolean;
}

type PortalContext = 'admin' | 'client';

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  login: (username: string, password: string, tenantSlug?: string) => Promise<any>;
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
  canManageSettings: boolean;
  canExportData: boolean;
  canManageRemediation: boolean;
  canViewCompliance: boolean;
  canTriggerScans: boolean;
  activeOrgId: number | null;
  activeOrgName: string | null;
  switchOrganization: (orgId: number | null, orgName?: string) => void;
  // Phase 1B: Impersonation
  isImpersonating: boolean;
  impersonatorUsername: string | null;
  impersonate: (orgId: number) => Promise<void>;
  exitImpersonation: () => void;
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
  if (window.location.pathname.startsWith('/admin')) return 'admin';
  if (window.location.hostname.startsWith('admin.')) return 'admin';
  return 'client';
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

  // Phase 46: Organization switching for superadmins
  const [activeOrgId, setActiveOrgId] = useState<number | null>(() => {
    // Migration: move old key to new key
    const oldStored = localStorage.getItem('active_tenant_id');
    if (oldStored) {
      localStorage.setItem('active_org_id', oldStored);
      localStorage.removeItem('active_tenant_id');
    }
    const stored = localStorage.getItem('active_org_id');
    return stored ? parseInt(stored, 10) : null;
  });
  const [activeOrgName, setActiveOrgName] = useState<string | null>(
    () => {
      // Migration: move old key to new key
      const oldStored = localStorage.getItem('active_tenant_name');
      if (oldStored) {
        localStorage.setItem('active_org_name', oldStored);
        localStorage.removeItem('active_tenant_name');
      }
      return localStorage.getItem('active_org_name');
    }
  );

  // Phase 1B: Impersonation state
  const [isImpersonating, setIsImpersonating] = useState<boolean>(
    () => localStorage.getItem('impersonating') === 'true'
  );
  const [impersonatorUsername, setImpersonatorUsername] = useState<string | null>(
    () => localStorage.getItem('impersonator_username')
  );

  const switchOrganization = useCallback((orgId: number | null, orgName?: string) => {
    setActiveOrgId(orgId);
    setActiveOrgName(orgName || null);
    if (orgId !== null) {
      localStorage.setItem('active_org_id', String(orgId));
      localStorage.setItem('active_org_name', orgName || '');
    } else {
      localStorage.removeItem('active_org_id');
      localStorage.removeItem('active_org_name');
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
          // Phase 46: Attach organization override header for superadmins (any portal)
          const activeOid = localStorage.getItem('active_org_id');
          if (activeOid && !headers.has('X-Organization-Id')) {
            headers.set('X-Organization-Id', activeOid);
          }
          // Phase 1B: Send portal context header in dev mode (no subdomain routing)
          if (!API_BASE && detectPortal() === 'admin') {
            headers.set('X-Portal-Context', 'admin');
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

  // Phase 1B: login no longer accepts portal param — derived from host on backend
  const login = useCallback(async (username: string, password: string, tenantSlug?: string) => {
    const resolvedPortal = detectPortal();
    const keys = tokenKeys(resolvedPortal);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const body: any = { username, password };
    if (tenantSlug) body.tenant_slug = tenantSlug;

    // Phase 1B: Build headers — include portal context for dev mode
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (!API_BASE && resolvedPortal === 'admin') {
      headers['X-Portal-Context'] = 'admin';
    }

    const res = await originalFetchRef.current(resolveApiUrl('/api/auth/login'), {
      method: 'POST',
      headers,
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
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
    } catch { /* ignore */ }
    // Only clear the current portal's tokens
    localStorage.removeItem(keys.access);
    localStorage.removeItem(keys.refresh);
    // Clear impersonation state
    localStorage.removeItem('impersonating');
    localStorage.removeItem('impersonator_username');
    localStorage.removeItem('admin_backup_access');
    localStorage.removeItem('admin_backup_refresh');
    setIsImpersonating(false);
    setImpersonatorUsername(null);
    // Only clear organization context if logging out of admin portal
    if (portal === 'admin') {
      localStorage.removeItem('active_org_id');
      localStorage.removeItem('active_org_name');
      setActiveOrgId(null);
      setActiveOrgName(null);
    }
    setUser(null);
  }, []);

  // Phase 1B: Impersonation — generate tenant-scoped tokens from admin portal
  const impersonate = useCallback(async (orgId: number) => {
    const adminKeys = tokenKeys('admin');
    const adminAccess = localStorage.getItem(adminKeys.access);
    const adminRefresh = localStorage.getItem(adminKeys.refresh);

    // Backup admin tokens
    if (adminAccess) localStorage.setItem('admin_backup_access', adminAccess);
    if (adminRefresh) localStorage.setItem('admin_backup_refresh', adminRefresh);

    const res = await originalFetchRef.current(resolveApiUrl('/api/admin/impersonate'), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(adminAccess ? { 'Authorization': `Bearer ${adminAccess}` } : {}),
        'X-Portal-Context': 'admin',
      },
      body: JSON.stringify({ organization_id: orgId }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || 'Impersonation failed');
    }
    const data = await res.json();

    // Store tenant-scoped tokens as client tokens
    const clientKeys = tokenKeys('client');
    localStorage.setItem(clientKeys.access, data.access_token);
    localStorage.setItem(clientKeys.refresh, data.refresh_token);
    localStorage.setItem('impersonating', 'true');
    localStorage.setItem('impersonator_username', user?.username || '');
    setIsImpersonating(true);
    setImpersonatorUsername(user?.username || null);

    // Redirect to client portal root
    window.location.href = '/';
  }, [user]);

  // Phase 1B+1C: Exit impersonation — log end, restore admin tokens
  const exitImpersonation = useCallback(async () => {
    // Phase 1C: Log impersonation end on backend
    const clientKeys = tokenKeys('client');
    const clientToken = localStorage.getItem(clientKeys.access);
    try {
      await originalFetchRef.current(resolveApiUrl('/api/admin/impersonate/end'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(clientToken ? { 'Authorization': `Bearer ${clientToken}` } : {}),
        },
      });
    } catch { /* ignore — best-effort logging */ }

    // Clear client tokens
    localStorage.removeItem(clientKeys.access);
    localStorage.removeItem(clientKeys.refresh);

    // Restore admin tokens from backup
    const adminKeys = tokenKeys('admin');
    const backupAccess = localStorage.getItem('admin_backup_access');
    const backupRefresh = localStorage.getItem('admin_backup_refresh');
    if (backupAccess) localStorage.setItem(adminKeys.access, backupAccess);
    if (backupRefresh) localStorage.setItem(adminKeys.refresh, backupRefresh);
    localStorage.removeItem('admin_backup_access');
    localStorage.removeItem('admin_backup_refresh');
    localStorage.removeItem('impersonating');
    localStorage.removeItem('impersonator_username');
    setIsImpersonating(false);
    setImpersonatorUsername(null);

    // Redirect back to admin portal
    window.location.href = '/admin';
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
    canManageSettings: role === 'admin',
    canExportData: role === 'admin' || role === 'security_admin' || role === 'compliance',
    canManageRemediation: role === 'admin' || role === 'security_admin',
    canTriggerScans: role === 'admin' || role === 'security_admin',
    canViewCompliance: role === 'admin' || role === 'security_admin' || role === 'compliance',
    activeOrgId,
    activeOrgName,
    switchOrganization,
    isImpersonating,
    impersonatorUsername,
    impersonate,
    exitImpersonation,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
}
