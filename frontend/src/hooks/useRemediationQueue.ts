/**
 * useRemediationQueue — custom hook for the remediation queue list page.
 *
 * Syncs filters to URL search params so pages are shareable/bookmarkable.
 * Uses the global fetch interceptor (no localStorage.getItem('auth_token')).
 */
import { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import type {
  RemediationItem,
  RemediationSummary,
  RemediationStatus,
  RemediationSeverity,
  RemediationListResponse,
} from '../types/remediation';

export interface RemediationFilters {
  status?: RemediationStatus;
  severity?: RemediationSeverity;
}

export interface UseRemediationQueueReturn {
  items: RemediationItem[];
  summary: RemediationSummary | null;
  total: number;
  loading: boolean;
  error: string | null;
  filters: RemediationFilters;
  setFilters: (f: RemediationFilters) => void;
  updateStatus: (
    itemId: number,
    status: RemediationStatus,
    notes?: string,
    assignee?: string,
  ) => Promise<RemediationItem | null>;
  refetch: () => void;
  loadMore: () => void;
  hasMore: boolean;
}

const PAGE_SIZE = 50;

export function useRemediationQueue(): UseRemediationQueueReturn {
  const [searchParams, setSearchParams] = useSearchParams();
  const { withConnection } = useConnection();

  const [items, setItems] = useState<RemediationItem[]>([]);
  const [summary, setSummary] = useState<RemediationSummary | null>(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);

  // Derive filters from URL params
  const filters: RemediationFilters = {
    status: (searchParams.get('status') as RemediationStatus) || undefined,
    severity: (searchParams.get('severity') as RemediationSeverity) || undefined,
  };

  const setFilters = useCallback(
    (f: RemediationFilters) => {
      const params = new URLSearchParams();
      if (f.status) params.set('status', f.status);
      if (f.severity) params.set('severity', f.severity);
      setSearchParams(params, { replace: true });
      setOffset(0);
    },
    [setSearchParams],
  );

  const fetchItems = useCallback(
    async (appendOffset = 0) => {
      setLoading(true);
      setError(null);
      try {
        const params = new URLSearchParams();
        if (filters.status) params.set('status', filters.status);
        if (filters.severity) params.set('severity', filters.severity);
        params.set('limit', String(PAGE_SIZE));
        params.set('offset', String(appendOffset));

        const url = withConnection(`/api/remediation-queue?${params.toString()}`);
        const res = await fetch(url);
        if (!res.ok) {
          throw new Error(res.status === 403 ? 'Access denied' : 'Failed to load remediation queue');
        }
        const data: RemediationListResponse = await res.json();
        if (appendOffset === 0) {
          setItems(data.items);
        } else {
          setItems(prev => [...prev, ...data.items]);
        }
        setTotal(data.total);
        setSummary(data.summary);
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Unknown error');
      } finally {
        setLoading(false);
      }
    },
    [filters.status, filters.severity, withConnection],
  );

  // Re-fetch on filter change
  useEffect(() => {
    setOffset(0);
    fetchItems(0);
  }, [fetchItems]);

  const refetch = useCallback(() => {
    setOffset(0);
    fetchItems(0);
  }, [fetchItems]);

  const loadMore = useCallback(() => {
    const nextOffset = offset + PAGE_SIZE;
    setOffset(nextOffset);
    fetchItems(nextOffset);
  }, [offset, fetchItems]);

  const updateStatus = useCallback(
    async (
      itemId: number,
      newStatus: RemediationStatus,
      notes?: string,
      assignee?: string,
    ): Promise<RemediationItem | null> => {
      const body: Record<string, unknown> = { status: newStatus };
      if (notes !== undefined) body.resolution_notes = notes;
      if (assignee !== undefined) body.assigned_to = assignee;

      const res = await fetch(`/api/remediation-queue/${itemId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (res.status === 422) {
        const err = await res.json();
        throw new Error(err.error || 'Invalid status transition');
      }
      if (!res.ok) {
        throw new Error('Failed to update status');
      }

      const updated: RemediationItem = await res.json();

      // Update local state
      setItems(prev => prev.map(i => (i.id === itemId ? { ...i, ...updated } : i)));

      return updated;
    },
    [],
  );

  return {
    items,
    summary,
    total,
    loading,
    error,
    filters,
    setFilters,
    updateStatus,
    refetch,
    loadMore,
    hasMore: items.length < total,
  };
}
