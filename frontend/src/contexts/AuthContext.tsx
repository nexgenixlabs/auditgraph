import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { isAdminHost } from '../utils/hostDetection';

interface User {
  id: number;
  username: string;
  display_name: string;
  role: 'admin' | 'security_admin' | 'security_analyst' | 'compliance' | 'reader';
  organization_id?: number;
  org_name?: string;
  is_superadmin?: boolean;
  portal_role?: 'superadmin' | 'poweradmin' | 'billing' | 'reader' | null;
  force_password_change?: boolean;
  is_demo?: boolean;
  impersonating?: boolean;
  impersonator_username?: string;
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
  canManageFindings: boolean;
  canRunSimulations: boolean;
  canViewCompliance: boolean;
  canTriggerScans: boolean;
  isDemo: boolean;
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

/** Detect which portal we're running in based on current URL path or hostname. */
function detectPortal(): PortalContext {
  if (window.location.pathname.startsWith('/admin')) return 'admin';
  if (isAdminHost()) return 'admin';
  return 'client';
}

/** Read the CSRF double-submit cookie value (set by server, readable by JS). */
function getCsrfToken(): string {
  const match = document.cookie.split('; ').find(row => row.startsWith('csrf_token='));
  return match ? match.split('=')[1] : '';
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const originalFetchRef = useRef<typeof window.fetch>(window.fetch.bind(window));
  const refreshingRef = useRef<Promise<boolean> | null>(null);

  // Phase 46: Organization switching for superadmins (non-sensitive UI state — OK in localStorage)
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

  // Phase S1: Impersonation state derived from /api/auth/me response (no longer localStorage)
  const [isImpersonating, setIsImpersonating] = useState(false);
  const [impersonatorUsername, setImpersonatorUsername] = useState<string | null>(null);

  // Phase S1 migration: clear legacy localStorage token keys on mount
  useEffect(() => {
    const legacyKeys = [
      'access_token', 'refresh_token',
      'admin_access_token', 'admin_refresh_token',
      'admin_backup_access', 'admin_backup_refresh',
      'impersonating', 'impersonator_username',
    ];
    legacyKeys.forEach(k => localStorage.removeItem(k));
  }, []);

  const switchOrganization = useCallback((orgId: number | null, orgName?: string) => {
    const prevOrgId = localStorage.getItem('active_org_id');
    setActiveOrgId(orgId);
    setActiveOrgName(orgName || null);
    if (orgId !== null) {
      localStorage.setItem('active_org_id', String(orgId));
      localStorage.setItem('active_org_name', orgName || '');
    } else {
      localStorage.removeItem('active_org_id');
      localStorage.removeItem('active_org_name');
    }
    // Force full page reload on org switch to guarantee all components refetch
    // with the new org context. Without this, stale data from the previous org
    // remains in component state (subscriptions, groups, identities, etc.)
    const newOrgId = orgId !== null ? String(orgId) : null;
    if (prevOrgId !== newOrgId && prevOrgId !== null) {
      window.location.reload();
    }
  }, []);

  // Phase S1: Cookie-based refresh — server reads refresh token from httpOnly cookie
  const tryRefresh = useCallback(async (): Promise<boolean> => {
    try {
      const res = await originalFetchRef.current(resolveApiUrl('/api/auth/refresh'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({}),
      });
      if (!res.ok) return false;

      const data = await res.json();
      // Cookies are set by server response — no localStorage needed
      setUser(data.user);
      return true;
    } catch {
      return false;
    }
  }, []);

  // Global fetch interceptor — Phase S1: cookie-based auth (no Authorization header from storage)
  useEffect(() => {
    const origFetch = originalFetchRef.current;

    window.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;

      // Attach credentials + CSRF + org context to API calls
      if (url.startsWith('/api/') || (API_BASE && url.startsWith(API_BASE))) {
        const headers = new Headers(init?.headers);

        // Phase S1: CSRF token for mutating requests (double-submit cookie pattern).
        // If the csrf_token cookie is missing (cross-subdomain session whose
        // cookie expired or was set before the CSRF flow shipped), trigger a
        // refresh first — /api/auth/refresh re-issues all auth cookies including
        // a fresh csrf_token. Otherwise the request would 403 with no recovery.
        const method = (init?.method || 'GET').toUpperCase();
        if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
          let csrf = getCsrfToken();
          if (!csrf && !url.includes('/api/auth/')) {
            if (!refreshingRef.current) {
              refreshingRef.current = tryRefresh().finally(() => { refreshingRef.current = null; });
            }
            await refreshingRef.current;
            csrf = getCsrfToken();
          }
          if (csrf) headers.set('X-CSRF-Token', csrf);
        }

        // Phase 46: Attach organization override header for superadmins
        const activeOid = localStorage.getItem('active_org_id');
        if (activeOid && !headers.has('X-Organization-Id')) {
          headers.set('X-Organization-Id', activeOid);
        }
        // Send portal context header so backend knows admin context
        if (detectPortal() === 'admin') {
          headers.set('X-Portal-Context', 'admin');
        }

        init = { ...init, headers, credentials: 'include' };
      }

      // Resolve /api/* URLs to full backend URL when API_BASE is set (SWA mode)
      const resolvedInput = typeof input === 'string' ? resolveApiUrl(input) : input;
      let response = await origFetch(resolvedInput, init);

      // On 401, try cookie-based token refresh once (deduplicated)
      if (response.status === 401 && url.startsWith('/api/') && !url.startsWith('/api/auth/')) {
        if (!refreshingRef.current) {
          refreshingRef.current = tryRefresh().finally(() => { refreshingRef.current = null; });
        }
        const refreshed = await refreshingRef.current;
        if (refreshed) {
          // Retry with new cookies (set by refresh response).
          // Re-read CSRF token — refresh may have rotated it.
          const retryHeaders = new Headers(init?.headers);
          const retryMethod = (init?.method || 'GET').toUpperCase();
          if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(retryMethod)) {
            const freshCsrf = getCsrfToken();
            if (freshCsrf) retryHeaders.set('X-CSRF-Token', freshCsrf);
          }
          response = await origFetch(resolvedInput, { ...init, headers: retryHeaders });
        } else {
          setUser(null);
        }
      }

      // On 403 CSRF mismatch (stale or duplicate cookie — JS reads one value,
      // browser sends a different one), force a refresh which re-issues a single
      // canonical csrf_token cookie, then retry once. Distinct from the 401
      // refresh path which handles expired access tokens.
      if (response.status === 403 && url.startsWith('/api/') && !url.startsWith('/api/auth/')) {
        const retryMethod = (init?.method || 'GET').toUpperCase();
        if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(retryMethod)) {
          let isCsrfError = false;
          try {
            const cloned = response.clone();
            const body = await cloned.text();
            isCsrfError = body.includes('CSRF token mismatch');
          } catch { /* non-text body — skip */ }
          if (isCsrfError) {
            if (!refreshingRef.current) {
              refreshingRef.current = tryRefresh().finally(() => { refreshingRef.current = null; });
            }
            const refreshed = await refreshingRef.current;
            if (refreshed) {
              const retryHeaders = new Headers(init?.headers);
              const freshCsrf = getCsrfToken();
              if (freshCsrf) retryHeaders.set('X-CSRF-Token', freshCsrf);
              response = await origFetch(resolvedInput, { ...init, headers: retryHeaders });
            }
            // HOTFIX 2026-05-31: previous version did
            //   setUser(null); window.location.href = '/login?reason=session_expired'
            // when refresh also failed. That created an aggressive page-bounce
            // loop — any failed mutating request (e.g. Argus chat 500 when
            // Anthropic key absent) would force a full page reload to /login,
            // which the router immediately bounced back to /. Removed the auto-
            // redirect; let the caller's error toast surface naturally so the
            // user can decide whether to logout themselves. The original 401
            // refresh path above still calls setUser(null) when warranted.
          }
        }
      }

      return response;
    };

    return () => { window.fetch = origFetch; };
  }, [tryRefresh]);

  // Check auth state on mount via /api/auth/me (cookies sent automatically)
  useEffect(() => {
    originalFetchRef.current(resolveApiUrl('/api/auth/me'), {
      credentials: 'include',
      headers: detectPortal() === 'admin' ? { 'X-Portal-Context': 'admin' } : {},
    })
      .then(res => {
        if (!res.ok) throw new Error('Not authenticated');
        return res.json();
      })
      .then(data => {
        setUser(data.user);
        // Phase S1: Derive impersonation state from server response
        if (data.user?.impersonating) {
          setIsImpersonating(true);
          setImpersonatorUsername(data.user.impersonator_username || null);
        }
      })
      .catch(() => {
        // Try refresh — cookies may contain a valid refresh token
        tryRefresh().catch(() => { /* no valid session */ });
      })
      .finally(() => setLoading(false));
  }, [tryRefresh]);

  // Phase S1: login — server sets httpOnly cookies; frontend only stores user state
  const login = useCallback(async (username: string, password: string, tenantSlug?: string) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const body: any = { username, password };
    if (tenantSlug) body.tenant_slug = tenantSlug;

    // Send portal context header so backend knows admin context even on cross-origin API calls
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (detectPortal() === 'admin') {
      headers['X-Portal-Context'] = 'admin';
    }

    const res = await originalFetchRef.current(resolveApiUrl('/api/auth/login'), {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.message || data.error || 'Login failed');
    }
    const data = await res.json().catch(() => ({}));
    // Cookies are set by server response — no localStorage needed
    // Don't set user when force_password_change is required — keeps user null
    // so the /login route stays active and Login.tsx can show the password change form
    if (!data.user?.force_password_change) {
      setUser(data.user);
    }
    return data.user;
  }, []);

  // Phase 54: SSO code-to-token exchange — server sets cookies
  const loginWithSsoCode = useCallback(async (code: string) => {
    const res = await originalFetchRef.current(resolveApiUrl('/api/auth/saml/token'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ code }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || 'SSO login failed');
    }
    const data = await res.json();
    setUser(data.user);
  }, []);

  // Phase S1: logout — server clears httpOnly cookies
  const logout = useCallback(async () => {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const csrf = getCsrfToken();
    if (csrf) headers['X-CSRF-Token'] = csrf;
    if (detectPortal() === 'admin') headers['X-Portal-Context'] = 'admin';

    try {
      await originalFetchRef.current(resolveApiUrl('/api/auth/logout'), {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({}),
      });
    } catch { /* ignore */ }

    setIsImpersonating(false);
    setImpersonatorUsername(null);
    // Only clear organization context if logging out of admin portal
    if (detectPortal() === 'admin') {
      localStorage.removeItem('active_org_id');
      localStorage.removeItem('active_org_name');
      setActiveOrgId(null);
      setActiveOrgName(null);
    }
    setUser(null);
  }, []);

  // Phase S1: Impersonation — server manages cookie swap (backup + restore)
  const impersonate = useCallback(async (orgId: number) => {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Portal-Context': 'admin',
    };
    const csrf = getCsrfToken();
    if (csrf) headers['X-CSRF-Token'] = csrf;

    const res = await originalFetchRef.current(resolveApiUrl('/api/admin/impersonate'), {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify({ organization_id: orgId }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || 'Impersonation failed');
    }
    // Server sets client cookies + admin backup cookies — no localStorage needed
    setIsImpersonating(true);
    setImpersonatorUsername(user?.username || null);

    // Redirect to client portal root
    window.location.href = '/';
  }, [user]);

  // Phase S1: Exit impersonation — server restores admin cookies from backup
  const exitImpersonation = useCallback(async () => {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const csrf = getCsrfToken();
    if (csrf) headers['X-CSRF-Token'] = csrf;

    try {
      await originalFetchRef.current(resolveApiUrl('/api/admin/impersonate/end'), {
        method: 'POST',
        headers,
        credentials: 'include',
      });
    } catch { /* ignore — best-effort logging */ }

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
    canExportData: role === 'admin' || role === 'security_admin' || role === 'security_analyst' || role === 'compliance',
    canManageRemediation: role === 'admin' || role === 'security_admin' || role === 'security_analyst',
    canManageFindings: role === 'admin' || role === 'security_admin' || role === 'security_analyst',
    canRunSimulations: role === 'admin' || role === 'security_admin' || role === 'security_analyst',
    canTriggerScans: role === 'admin' || role === 'security_admin',
    canViewCompliance: role === 'admin' || role === 'security_admin' || role === 'security_analyst' || role === 'compliance',
    isDemo: !!user?.is_demo,
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
