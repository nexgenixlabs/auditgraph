/**
 * IdentityDrawerContext — intercepts /identities navigation on CISODashboard
 * to open an inline right-side drawer instead of navigating away.
 *
 * When no <IdentityDrawerProvider> wraps a component, useIdentityDrawer()
 * returns null so DN falls back to normal navigate().
 */
import React, { createContext, useContext, useState, useCallback } from 'react';

/** Pre-populated identity metadata from the calling context (e.g. finding row).
 *  Used as immediate display while the full detail API loads. */
export interface IdentityPrefill {
  display_name?: string;
  identity_category?: string;
  risk_level?: string;
  risk_score?: number;
}

/** selectedIdentityId: numeric DB id OR UUID identity_id string — both accepted. */
interface DrawerState {
  open: boolean;
  filterUrl: string | null;
  selectedIdentityId: number | string | null;
  prefill: IdentityPrefill | null;
}

interface IdentityDrawerContextValue {
  state: DrawerState;
  openDrawer: (filterUrl: string) => void;
  openIdentity: (id: number | string, prefill?: IdentityPrefill) => void;
  closeDrawer: () => void;
  selectIdentity: (id: number | string) => void;
  backToList: () => void;
}

const IdentityDrawerCtx = createContext<IdentityDrawerContextValue | null>(null);

export function IdentityDrawerProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<DrawerState>({
    open: false,
    filterUrl: null,
    selectedIdentityId: null,
    prefill: null,
  });

  const openDrawer = useCallback((filterUrl: string) => {
    setState({ open: true, filterUrl, selectedIdentityId: null, prefill: null });
  }, []);

  const openIdentity = useCallback((id: number | string, prefill?: IdentityPrefill) => {
    setState({ open: true, filterUrl: null, selectedIdentityId: id, prefill: prefill || null });
  }, []);

  const closeDrawer = useCallback(() => {
    setState({ open: false, filterUrl: null, selectedIdentityId: null, prefill: null });
  }, []);

  const selectIdentity = useCallback((id: number | string) => {
    setState(prev => ({ ...prev, selectedIdentityId: id, prefill: null }));
  }, []);

  const backToList = useCallback(() => {
    setState(prev => {
      if (!prev.filterUrl) return { open: false, filterUrl: null, selectedIdentityId: null, prefill: null };
      return { ...prev, selectedIdentityId: null, prefill: null };
    });
  }, []);

  return (
    <IdentityDrawerCtx.Provider value={{ state, openDrawer, openIdentity, closeDrawer, selectIdentity, backToList }}>
      {children}
    </IdentityDrawerCtx.Provider>
  );
}

/** Returns null when no provider wraps the tree (safe fallback for non-CISO pages). */
export function useIdentityDrawer(): IdentityDrawerContextValue | null {
  return useContext(IdentityDrawerCtx);
}
