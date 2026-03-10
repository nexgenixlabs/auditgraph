/**
 * IdentityDrawerContext — intercepts /identities navigation on CISODashboard
 * to open an inline right-side drawer instead of navigating away.
 *
 * When no <IdentityDrawerProvider> wraps a component, useIdentityDrawer()
 * returns null so DN falls back to normal navigate().
 */
import React, { createContext, useContext, useState, useCallback } from 'react';

interface DrawerState {
  open: boolean;
  filterUrl: string | null;
  selectedIdentityId: number | null;
}

interface IdentityDrawerContextValue {
  state: DrawerState;
  openDrawer: (filterUrl: string) => void;
  openIdentity: (id: number) => void;
  closeDrawer: () => void;
  selectIdentity: (id: number) => void;
  backToList: () => void;
}

const IdentityDrawerCtx = createContext<IdentityDrawerContextValue | null>(null);

export function IdentityDrawerProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<DrawerState>({
    open: false,
    filterUrl: null,
    selectedIdentityId: null,
  });

  const openDrawer = useCallback((filterUrl: string) => {
    setState({ open: true, filterUrl, selectedIdentityId: null });
  }, []);

  const openIdentity = useCallback((id: number) => {
    setState({ open: true, filterUrl: '/identities', selectedIdentityId: id });
  }, []);

  const closeDrawer = useCallback(() => {
    setState({ open: false, filterUrl: null, selectedIdentityId: null });
  }, []);

  const selectIdentity = useCallback((id: number) => {
    setState(prev => ({ ...prev, selectedIdentityId: id }));
  }, []);

  const backToList = useCallback(() => {
    setState(prev => ({ ...prev, selectedIdentityId: null }));
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
