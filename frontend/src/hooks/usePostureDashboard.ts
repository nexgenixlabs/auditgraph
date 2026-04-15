/**
 * Two-phase posture dashboard hook (v3.1).
 *
 * Phase 1: Fetch ?include=core → render Blocks 0-3 immediately.
 * Phase 2: Fetch ?include=full ONLY AFTER core renders → hydrate Blocks 4-7.
 *
 * A3: full is never requested on initial page load or if core failed.
 * A6: Two-level error fallback:
 *   Level 1 (core fails) → phase='error', page shows unavailable banner
 *   Level 2 (full fails) → phase='core_only', blocks 4-7 show skeleton + retry
 */
import { useState, useEffect, useCallback, useRef } from 'react';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';
import type { PostureV31Response } from '../utils/cisoViewModel';

export type PosturePhase = 'loading' | 'core' | 'full' | 'error' | 'core_only';

export interface PostureDashboardResult {
  data: PostureV31Response | null;
  phase: PosturePhase;
  refetch: () => void;
}

/** Validate that a parsed JSON object has the required v3.1 core shape. */
function isValidPostureResponse(obj: unknown): obj is PostureV31Response {
  if (!obj || typeof obj !== 'object') return false;
  const o = obj as Record<string, unknown>;
  return (
    typeof o.posture_score === 'number' &&
    typeof o.posture_status === 'string' &&
    typeof o.narrative_text === 'string' &&
    o.identity_risk != null && typeof o.identity_risk === 'object' &&
    o.coverage != null && typeof o.coverage === 'object' &&
    o.scan_metadata != null && typeof o.scan_metadata === 'object'
  );
}

export function usePostureDashboard(): PostureDashboardResult {
  const { withConnection, selectedConnectionId, connections, loading: connectionLoading } = useConnection();
  const { activeOrgId } = useAuth();
  const [data, setData] = useState<PostureV31Response | null>(null);
  const [phase, setPhase] = useState<PosturePhase>('loading');
  const fetchId = useRef(0);
  const fullRetried = useRef(false);

  // ── Phase 1: Fetch core ──
  const doFetch = useCallback(() => {
    if (connectionLoading || connections.length === 0) return;

    const id = ++fetchId.current;
    setPhase('loading');
    setData(null);
    fullRetried.current = false;

    const controller = new AbortController();

    (async () => {
      try {
        // A3: Always fetch ?include=core first, never full on initial load
        const coreUrl = withConnection('/api/dashboard/posture?include=core');
        const coreRes = await fetch(coreUrl, { signal: controller.signal });
        if (!coreRes.ok) throw new Error(`Core ${coreRes.status}`);
        const coreJson = await coreRes.json();
        if (id !== fetchId.current) return;

        if (!isValidPostureResponse(coreJson)) {
          console.warn('[PostureDashboard] Invalid core response shape, falling back to legacy');
          throw new Error('Invalid response shape');
        }

        setData(coreJson);
        setPhase('core');
      } catch (err) {
        if (id !== fetchId.current) return;
        if ((err as Error).name === 'AbortError') return;
        console.warn('[PostureDashboard] Core fetch error:', (err as Error).message);
        // A6 Level 1: core failed → error state, page shows unavailable banner
        setPhase('error');
      }
    })();

    return () => controller.abort();
  }, [withConnection, connectionLoading, connections.length]);

  // ── Phase 2: Fetch full ONLY AFTER core renders (separate effect) ──
  useEffect(() => {
    // A3: Never fetch full if core hasn't rendered or if core failed
    if (phase !== 'core') return;

    const id = fetchId.current;
    const controller = new AbortController();

    (async () => {
      try {
        const fullUrl = withConnection('/api/dashboard/posture?include=full');
        const fullRes = await fetch(fullUrl, { signal: controller.signal });
        if (!fullRes.ok) throw new Error(`Full ${fullRes.status}`);
        const fullJson = await fullRes.json();
        if (id !== fetchId.current) return;

        if (!isValidPostureResponse(fullJson)) {
          console.warn('[PostureDashboard] Invalid full response shape, keeping core data');
          setPhase('core_only');
          return;
        }

        setData(fullJson);
        setPhase('full');
      } catch (err) {
        if (id !== fetchId.current) return;
        if ((err as Error).name === 'AbortError') return;
        console.warn('[PostureDashboard] Full fetch error:', (err as Error).message);
        // A6 Level 2: full failed — keep core data, mark as core_only
        setPhase('core_only');
      }
    })();

    return () => controller.abort();
  }, [phase === 'core', withConnection]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── A6 Level 2: Silent retry of full after 5s when core_only ──
  useEffect(() => {
    if (phase !== 'core_only' || fullRetried.current) return;
    fullRetried.current = true;

    const id = fetchId.current;
    const timer = setTimeout(async () => {
      try {
        const fullUrl = withConnection('/api/dashboard/posture?include=full');
        const fullRes = await fetch(fullUrl);
        if (!fullRes.ok) return;
        const fullJson = await fullRes.json();
        if (id !== fetchId.current) return;
        if (!isValidPostureResponse(fullJson)) return;
        setData(fullJson);
        setPhase('full');
      } catch {
        // Silent — do not change phase
      }
    }, 5000);

    return () => clearTimeout(timer);
  }, [phase, withConnection]);

  useEffect(() => {
    const cleanup = doFetch();
    return cleanup;
  }, [doFetch, selectedConnectionId, activeOrgId]);

  return { data, phase, refetch: doFetch };
}
