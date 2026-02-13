import React, { createContext, useContext, useState, useEffect } from 'react';

interface ResolvedTenant {
  id: number;
  name: string;
  slug: string;
  plan: string;
  enabled: boolean;
}

interface TenantContextValue {
  tenantSlug: string | null;
  resolvedTenant: ResolvedTenant | null;
  loading: boolean;
  error: string | null;
  isPortal: boolean;
}

const TenantContext = createContext<TenantContextValue>({
  tenantSlug: null,
  resolvedTenant: null,
  loading: false,
  error: null,
  isPortal: false,
});

const RESERVED_PREFIXES = ['app', 'www', 'api', 'admin', 'mail', 'smtp'];

function extractTenantSlug(): string | null {
  // Dev override via env var
  const envSlug = process.env.REACT_APP_DEV_TENANT_SLUG;
  if (envSlug) return envSlug;

  const hostname = window.location.hostname;

  // Dev mode or platform hostnames: no tenant scoping
  if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname.startsWith('192.168.')
      || hostname.endsWith('.azurewebsites.net')) {
    return null;
  }

  // Production: slug.app.auditgraph.ai or slug.auditgraph.ai
  const parts = hostname.split('.');
  if (parts.length >= 3 && !RESERVED_PREFIXES.includes(parts[0])) {
    return parts[0];
  }

  return null;
}

export function TenantProvider({ children }: { children: React.ReactNode }) {
  const [tenantSlug] = useState<string | null>(() => extractTenantSlug());
  const [resolvedTenant, setResolvedTenant] = useState<ResolvedTenant | null>(null);
  const [loading, setLoading] = useState<boolean>(!!tenantSlug);
  const [error, setError] = useState<string | null>(null);

  const isPortal = !tenantSlug;

  useEffect(() => {
    if (!tenantSlug) return;

    let mounted = true;
    setLoading(true);

    // Use the raw fetch (not the intercepted one) since this is pre-auth
    const origFetch = window.fetch;
    origFetch(`/api/tenants/by-slug/${encodeURIComponent(tenantSlug)}`)
      .then(res => {
        if (!res.ok) throw new Error(res.status === 404 ? 'Organization not found' : 'Failed to resolve organization');
        return res.json();
      })
      .then(data => {
        if (!mounted) return;
        const t = data.tenant;
        if (!t.enabled) {
          setError('This organization is currently disabled. Please contact your administrator.');
        } else {
          setResolvedTenant(t);
        }
        setLoading(false);
      })
      .catch(err => {
        if (!mounted) return;
        setError(err.message || 'Failed to resolve organization');
        setLoading(false);
      });

    return () => { mounted = false; };
  }, [tenantSlug]);

  return (
    <TenantContext.Provider value={{ tenantSlug, resolvedTenant, loading, error, isPortal }}>
      {children}
    </TenantContext.Provider>
  );
}

export function useTenant(): TenantContextValue {
  return useContext(TenantContext);
}
