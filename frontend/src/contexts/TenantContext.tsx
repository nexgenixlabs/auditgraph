import React, { createContext, useContext, useState, useEffect } from 'react';

interface ResolvedOrganization {
  id: number;
  name: string;
  slug: string;
  plan: string;
  enabled: boolean;
}

interface OrganizationContextValue {
  orgSlug: string | null;
  resolvedOrganization: ResolvedOrganization | null;
  loading: boolean;
  error: string | null;
  isPortal: boolean;
  /** @deprecated Use orgSlug instead */
  tenantSlug: string | null;
  /** @deprecated Use resolvedOrganization instead */
  resolvedTenant: ResolvedOrganization | null;
}

const OrganizationContext = createContext<OrganizationContextValue>({
  orgSlug: null,
  resolvedOrganization: null,
  loading: false,
  error: null,
  isPortal: false,
  tenantSlug: null,
  resolvedTenant: null,
});

const RESERVED_PREFIXES = ['app', 'www', 'api', 'admin', 'mail', 'smtp', 'dev', 'qa', 'stage', 'staging', 'prod'];

function extractOrgSlug(): string | null {
  // Dev override via env var
  const envSlug = process.env.REACT_APP_DEV_TENANT_SLUG;
  if (envSlug) return envSlug;

  const hostname = window.location.hostname;

  // Dev mode or platform hostnames: no organization scoping
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

export function OrganizationProvider({ children }: { children: React.ReactNode }) {
  const [orgSlug] = useState<string | null>(() => extractOrgSlug());
  const [resolvedOrganization, setResolvedOrganization] = useState<ResolvedOrganization | null>(null);
  const [loading, setLoading] = useState<boolean>(!!orgSlug);
  const [error, setError] = useState<string | null>(null);

  const isPortal = !orgSlug;

  useEffect(() => {
    if (!orgSlug) return;

    let mounted = true;
    setLoading(true);

    // Use the raw fetch (not the intercepted one) since this is pre-auth
    const origFetch = window.fetch;
    origFetch(`/api/clients/by-slug/${encodeURIComponent(orgSlug)}`)
      .then(res => {
        if (!res.ok) throw new Error(res.status === 404 ? 'Organization not found' : 'Failed to resolve organization');
        return res.json();
      })
      .then(data => {
        if (!mounted) return;
        const t = data.organization || data.tenant;
        if (!t.enabled) {
          setError('This organization is currently disabled. Please contact your administrator.');
        } else {
          setResolvedOrganization(t);
        }
        setLoading(false);
      })
      .catch(err => {
        if (!mounted) return;
        setError(err.message || 'Failed to resolve organization');
        setLoading(false);
      });

    return () => { mounted = false; };
  }, [orgSlug]);

  const value: OrganizationContextValue = {
    orgSlug,
    resolvedOrganization,
    loading,
    error,
    isPortal,
    // Deprecated aliases for backward compatibility during migration
    tenantSlug: orgSlug,
    resolvedTenant: resolvedOrganization,
  };

  return (
    <OrganizationContext.Provider value={value}>
      {children}
    </OrganizationContext.Provider>
  );
}

export function useOrganization(): OrganizationContextValue {
  return useContext(OrganizationContext);
}

/** @deprecated Use OrganizationProvider instead */
export const TenantProvider = OrganizationProvider;

/** @deprecated Use useOrganization instead */
export const useTenant = useOrganization;
