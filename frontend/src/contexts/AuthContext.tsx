import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';

interface User {
  id: number;
  username: string;
  display_name: string;
  role: 'admin' | 'auditor' | 'viewer';
  tenant_id?: number;
  tenant_name?: string;
  is_superadmin?: boolean;
  portal_role?: 'superadmin' | 'support' | null;
}

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  login: (username: string, password: string, tenantSlug?: string) => Promise<any>;
  loginWithSsoCode: (code: string) => Promise<void>;
  logout: () => Promise<void>;
  isAdmin: boolean;
  isAuditor: boolean;
  isSuperAdmin: boolean;
  activeTenantId: number | null;
  activeTenantName: string | null;
  switchTenant: (tenantId: number | null, tenantName?: string) => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

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
    const refreshToken = localStorage.getItem('refresh_token');
    if (!refreshToken) return false;

    try {
      const res = await originalFetchRef.current('/api/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
      if (!res.ok) return false;

      const data = await res.json();
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('refresh_token', data.refresh_token);
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
        const token = localStorage.getItem('access_token');
        if (token) {
          const headers = new Headers(init?.headers);
          if (!headers.has('Authorization')) {
            headers.set('Authorization', `Bearer ${token}`);
          }
          // Phase 46: Attach tenant override header for superadmins
          const activeTid = localStorage.getItem('active_tenant_id');
          if (activeTid && !headers.has('X-Tenant-Id')) {
            headers.set('X-Tenant-Id', activeTid);
          }
          init = { ...init, headers };
        }
      }

      let response = await origFetch(input, init);

      // On 401, try token refresh once (deduplicated)
      if (response.status === 401 && url.startsWith('/api/') && !url.startsWith('/api/auth/')) {
        if (!refreshingRef.current) {
          refreshingRef.current = tryRefresh().finally(() => { refreshingRef.current = null; });
        }
        const refreshed = await refreshingRef.current;
        if (refreshed) {
          const newToken = localStorage.getItem('access_token');
          if (newToken) {
            const headers = new Headers(init?.headers);
            headers.set('Authorization', `Bearer ${newToken}`);
            response = await origFetch(input, { ...init, headers });
          }
        } else {
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          setUser(null);
        }
      }

      return response;
    };

    return () => { window.fetch = origFetch; };
  }, [tryRefresh]);

  // Check existing token on mount
  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) {
      setLoading(false);
      return;
    }

    originalFetchRef.current('/api/auth/me', {
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
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
          }
        });
      })
      .finally(() => setLoading(false));
  }, [tryRefresh]);

  const login = useCallback(async (username: string, password: string, tenantSlug?: string) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const body: any = { username, password };
    if (tenantSlug) body.tenant_slug = tenantSlug;
    const res = await originalFetchRef.current('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || 'Login failed');
    }
    const data = await res.json();
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);
    setUser(data.user);
    return data.user;
  }, []);

  // Phase 54: SSO code-to-token exchange
  const loginWithSsoCode = useCallback(async (code: string) => {
    const res = await originalFetchRef.current('/api/auth/saml/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || 'SSO login failed');
    }
    const data = await res.json();
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);
    setUser(data.user);
  }, []);

  const logout = useCallback(async () => {
    const refreshToken = localStorage.getItem('refresh_token');
    const accessToken = localStorage.getItem('access_token');
    try {
      await originalFetchRef.current('/api/auth/logout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {}),
        },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
    } catch { /* ignore */ }
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('active_tenant_id');
    localStorage.removeItem('active_tenant_name');
    setActiveTenantId(null);
    setActiveTenantName(null);
    setUser(null);
  }, []);

  const value: AuthContextValue = {
    user,
    loading,
    login,
    loginWithSsoCode,
    logout,
    isAdmin: user?.role === 'admin',
    isAuditor: user?.role === 'auditor' || user?.role === 'admin',
    isSuperAdmin: user?.is_superadmin === true,
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
