import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { useAuth } from './AuthContext';
import { api } from '../services/apiClient';
import { isAdminHost } from '../utils/hostDetection';

interface CloudConnection {
  id: number;
  label: string;
  cloud: string;
  azure_directory_id: string;
  status: string;
  metadata?: {
    auto_discovered?: boolean;
    discovered_via?: string;
    discovered_via_label?: string;
    [key: string]: unknown;
  };
}

interface ConnectionContextType {
  connections: CloudConnection[];
  selectedConnectionId: number | null; // null = "All Connections"
  setSelectedConnectionId: (id: number | null) => void;
  connectionParam: string; // ready-to-append query param string
  loading: boolean;
}

const ConnectionContext = createContext<ConnectionContextType>({
  connections: [],
  selectedConnectionId: null,
  setSelectedConnectionId: () => {},
  connectionParam: '',
  loading: true,
});

export function ConnectionProvider({ children }: { children: React.ReactNode }) {
  const { user } = useAuth();
  const [connections, setConnections] = useState<CloudConnection[]>([]);
  const [selectedConnectionId, setSelectedConnectionId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user) {
      setConnections([]);
      setLoading(false);
      return;
    }
    // Skip connection fetch on admin portal — connections are client-scoped
    const isAdmin = window.location.pathname.startsWith('/admin')
      || isAdminHost();
    if (isAdmin) {
      setConnections([]);
      setLoading(false);
      return;
    }
    api.get<{ connections: CloudConnection[] }>('/client/connections')
      .then(data => {
        setConnections(
          (data.connections || []).filter((c: CloudConnection) => c.status === 'connected')
        );
      })
      .catch(() => setConnections([]))
      .finally(() => setLoading(false));
  }, [user]);

  const connectionParam = selectedConnectionId
    ? `connection_id=${selectedConnectionId}`
    : '';

  return (
    <ConnectionContext.Provider value={{
      connections, selectedConnectionId, setSelectedConnectionId, connectionParam, loading,
    }}>
      {children}
    </ConnectionContext.Provider>
  );
}

export function useConnection() {
  const ctx = useContext(ConnectionContext);

  /** Append connection_id= to any URL when a specific connection is selected. */
  const withConnection = useCallback((url: string) => {
    if (!ctx.connectionParam) return url;
    return url.includes('?') ? `${url}&${ctx.connectionParam}` : `${url}?${ctx.connectionParam}`;
  }, [ctx.connectionParam]);

  return { ...ctx, withConnection };
}
