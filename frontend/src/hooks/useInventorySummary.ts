import { useState, useEffect, useMemo } from 'react';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';
import { formatRelativeTime } from '../utils/displayHelpers';

interface InventoryConnection {
  id: number;
  label: string;
  status: string;
  cloud: string;
  last_discovery_at: string | null;
  inventory_subscriptions: number;
  monitored_subscriptions: number;
  active_inventory_subscriptions: number;
  last_subscription_discovered_at: string | null;
}

interface InventoryAggregate {
  total_connections: number;
  inventory_subscriptions: number;
  monitored_subscriptions: number;
  active_inventory_subscriptions: number;
  last_discovery_at: string | null;
}

interface InventoryResponse {
  has_connection: boolean;
  connections: InventoryConnection[];
  aggregate: InventoryAggregate;
}

export type InventoryHeaderState = 'loading' | 'no_connection' | 'no_scan' | 'has_scan';

export interface InventorySummaryResult {
  loading: boolean;
  headerState: InventoryHeaderState;
  headerSubtitle: string;
  totalInventorySubscriptions: number;
  lastDiscoveryFormatted: string;
  aggregate: InventoryAggregate | null;
}

export function useInventorySummary(): InventorySummaryResult {
  const { withConnection, selectedConnectionId, connections, loading: connectionLoading } = useConnection();
  const { activeOrgId } = useAuth();
  const [data, setData] = useState<InventoryResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    if (connectionLoading) return;
    if (connections.length === 0) {
      setData(null);
      setLoading(false);
      return;
    }

    setLoading(true);
    fetch(withConnection('/api/inventory/summary'))
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (!cancelled) setData(d); })
      .catch(() => { if (!cancelled) setData(null); })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId, activeOrgId, connectionLoading, connections.length]);

  return useMemo(() => {
    if (loading || connectionLoading) {
      return {
        loading: true,
        headerState: 'loading' as const,
        headerSubtitle: '',
        totalInventorySubscriptions: 0,
        lastDiscoveryFormatted: '',
        aggregate: null,
      };
    }

    if (connections.length === 0) {
      return {
        loading: false,
        headerState: 'no_connection' as const,
        headerSubtitle: 'No connection configured',
        totalInventorySubscriptions: 0,
        lastDiscoveryFormatted: '\u2014',
        aggregate: null,
      };
    }

    // API failed or returned empty — show neutral dash, never crash
    if (!data || !data.has_connection) {
      return {
        loading: false,
        headerState: 'no_connection' as const,
        headerSubtitle: '\u2014',
        totalInventorySubscriptions: 0,
        lastDiscoveryFormatted: '\u2014',
        aggregate: null,
      };
    }

    const agg = data.aggregate;
    const subCount = agg.inventory_subscriptions;
    const subLabel = `${subCount} sub${subCount !== 1 ? 's' : ''}`;

    // 'no_scan': connection exists but last_discovery_at is null
    //   → show call-to-action, not a potentially misleading 0 count
    if (!agg.last_discovery_at) {
      return {
        loading: false,
        headerState: 'no_scan' as const,
        headerSubtitle: 'No scan yet \u00b7 run discovery',
        totalInventorySubscriptions: subCount,
        lastDiscoveryFormatted: '\u2014',
        aggregate: agg,
      };
    }

    const relTime = formatRelativeTime(agg.last_discovery_at, '\u2014');
    return {
      loading: false,
      headerState: 'has_scan' as const,
      headerSubtitle: `Last scan ${relTime} \u00b7 ${subLabel}`,
      totalInventorySubscriptions: subCount,
      lastDiscoveryFormatted: relTime,
      aggregate: agg,
    };
  }, [loading, connectionLoading, connections.length, data]);
}
