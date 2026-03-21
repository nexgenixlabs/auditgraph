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
  refreshConnections: () => void;
  onConnectionDeleted: (deletedId: number) => void;
}

const ConnectionContext = createContext<ConnectionContextType>({
  connections: [],
  selectedConnectionId: null,
  setSelectedConnectionId: () => {},
  connectionParam: '',
  loading: true,
  refreshConnections: () => {},
  onConnectionDeleted: () => {},
});

export function ConnectionProvider({ children }: { children: React.ReactNode }) {
  const { user } = useAuth();
  const [connections, setConnections] = useState<CloudConnection[]>([]);
  const [selectedConnectionId, setSelectedConnectionId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchConnections = useCallback(() => {
    if (!user) {
      setConnections([]);
      setLoading(false);
      return;
    }
    const isAdmin = window.location.pathname.startsWith('/admin')
      || isAdminHost();
    if (isAdmin) {
      setConnections([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    api.get<{ connections: CloudConnection[] }>('/client/connections')
      .then(data => {
        setConnections(
          (data.connections || []).filter((c: CloudConnection) => c.status === 'connected')
        );
      })
      .catch(() => setConnections([]))
      .finally(() => setLoading(false));
  }, [user]);

  useEffect(() => {
    fetchConnections();
  }, [fetchConnections]);

  const onConnectionDeleted = useCallback((deletedId: number) => {
    // Reset selection if the deleted connection was selected
    if (selectedConnectionId === deletedId) {
      setSelectedConnectionId(null);
    }
    // Refresh the list to remove it
    fetchConnections();
  }, [selectedConnectionId, fetchConnections]);

  const connectionParam = selectedConnectionId
    ? `connection_id=${selectedConnectionId}`
    : '';

  return (
    <ConnectionContext.Provider value={{
      connections, selectedConnectionId, setSelectedConnectionId,
      connectionParam, loading, refreshConnections: fetchConnections,
      onConnectionDeleted,
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
