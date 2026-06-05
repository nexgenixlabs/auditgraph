/**
 * AG-181 (Tier 2C): AI Agent Lifecycle — J/M/L for AI agents.
 *
 * Backend: GET /api/dashboard/ai-jml-snapshot?window_days=N
 *   → {
 *       joiners:   AiLifecycleEvent[],
 *       movers:    AiLifecycleEvent[],
 *       leavers:   AiLifecycleEvent[],
 *       totals:    { joiners, movers, leavers, all },
 *       recent_events: AiLifecycleEvent[],
 *       window_days: number,
 *     }
 *
 * Tells the per-agent J/M/L story:
 *   Joiners — new AI agents detected in the window.
 *   Movers  — privilege / owner / model / capacity changes on existing agents.
 *   Leavers — agents decommissioned in the window.
 *
 * Shared event types live in frontend/src/types/security_events.ts.
 */
import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import type { LifecycleEventType, Severity, MitreTechnique } from '../types/security_events';
import { MitreChipStrip } from '../components/security/MitreChip';

// ─── Shape of the snapshot payload ─────────────────────────────────────────
// Mirrors AILifecycleEngine.get_jml_snapshot. Reuses the canonical
// LifecycleEventType / Severity enums so any drift is caught by tsc.

interface AiLifecycleEvent {
  event_id: number;
  event_type: LifecycleEventType;
  severity: Severity;
  identity_db_id: number;
  identity_id: string;
  display_name: string | null;
  occurred_at: string;
  description: string;
  discovery_run_id?: number | null;
  prev_run_id?: number | null;
  mitre_techniques?: MitreTechnique[];
}

interface JmlTotals {
  joiners: number;
  movers: number;
  leavers: number;
  all?: number;
}

interface JmlSnapshot {
  joiners: AiLifecycleEvent[];
  movers: AiLifecycleEvent[];
  leavers: AiLifecycleEvent[];
  totals: JmlTotals;
  recent_events: AiLifecycleEvent[];
  window_days?: number;
}

type BucketKey = 'joiners' | 'movers' | 'leavers';

const BUCKET_META: Record<BucketKey, {
  label: string;
  // J=blue, M=amber, L=gray per spec.
  chipBg: string;
  chipText: string;
  ringActive: string;
  countText: string;
  // accent dot used by the J→M→L cascade animation
  dotBg: string;
}> = {
  joiners: {
    label: 'Joiners',
    chipBg: 'bg-blue-100',
    chipText: 'text-blue-800',
    ringActive: 'ring-blue-300',
    countText: 'text-blue-700',
    dotBg: 'bg-blue-500',
  },
  movers: {
    label: 'Movers',
    chipBg: 'bg-amber-100',
    chipText: 'text-amber-800',
    ringActive: 'ring-amber-300',
    countText: 'text-amber-700',
    dotBg: 'bg-amber-500',
  },
  leavers: {
    label: 'Leavers',
    chipBg: 'bg-gray-100',
    chipText: 'text-gray-700',
    ringActive: 'ring-gray-300',
    countText: 'text-gray-700',
    dotBg: 'bg-gray-500',
  },
};

// ─── Event-type display names (spec §6) ────────────────────────────────────

const EVENT_TYPE_LABEL: Partial<Record<LifecycleEventType, string>> = {
  model_changed: 'Model Changed',
  ai_permissions_escalated: 'Privilege Escalated',
  ai_owner_changed: 'Owner Changed',
  model_version_bumped: 'Model Version Bumped',
  deployment_added: 'Deployment Added',
  deployment_removed: 'Deployment Removed',
  capacity_expanded: 'Capacity Expanded',
  ai_agent_joiner: 'AI Agent Joined',
  ai_agent_mover: 'AI Agent Moved',
  ai_agent_leaver: 'AI Agent Left',
};

function labelFor(eventType: LifecycleEventType): string {
  return EVENT_TYPE_LABEL[eventType] || eventType.replace(/_/g, ' ');
}

// Privilege escalations are always treated as critical for display, per spec §6.
function effectiveSeverity(ev: AiLifecycleEvent): Severity {
  if (ev.event_type === 'ai_permissions_escalated') return 'critical';
  return ev.severity;
}

const SEVERITY_CHIP: Record<Severity, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-amber-100 text-amber-800 border-amber-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
  info: 'bg-gray-100 text-gray-700 border-gray-200',
};

const WINDOW_OPTIONS: ReadonlyArray<7 | 30 | 90> = [7, 30, 90];

// ─── Helpers ───────────────────────────────────────────────────────────────

function fmtTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function truncate(s: string, n: number): string {
  if (!s) return '';
  return s.length > n ? s.slice(0, Math.max(0, n - 1)) + '…' : s;
}

// MITRE technique IDs flattened from the event's tagged techniques.
function mitreIds(ev: AiLifecycleEvent): string[] {
  if (!ev.mitre_techniques || ev.mitre_techniques.length === 0) return [];
  return ev.mitre_techniques.map(t => t.id).filter(Boolean);
}

// ─── Page ─────────────────────────────────────────────────────────────────

export default function AILifecycle(): React.ReactElement {
  const navigate = useNavigate();
  const [windowDays, setWindowDays] = useState<7 | 30 | 90>(7);
  const [data, setData] = useState<JmlSnapshot | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  // Cascade animation key — bumped on every successful load so the J/M/L dots
  // re-trigger their staggered fade-in (CSS-only, no extra deps).
  const [pulseKey, setPulseKey] = useState<number>(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetch(`/api/dashboard/ai-jml-snapshot?window_days=${windowDays}`)
      .then(async r => {
        if (!r.ok) throw new Error(`http_${r.status}`);
        return r.json() as Promise<JmlSnapshot>;
      })
      .then(d => {
        if (cancelled) return;
        setData(d);
        setPulseKey(k => k + 1);
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : 'fetch_failed');
        setData(null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [windowDays]);

  const totals = useMemo<JmlTotals>(() => {
    if (!data) return { joiners: 0, movers: 0, leavers: 0, all: 0 };
    return {
      joiners: data.totals?.joiners ?? data.joiners?.length ?? 0,
      movers: data.totals?.movers ?? data.movers?.length ?? 0,
      leavers: data.totals?.leavers ?? data.leavers?.length ?? 0,
      all: data.totals?.all,
    };
  }, [data]);

  const grandTotal = totals.joiners + totals.movers + totals.leavers;

  const buckets: ReadonlyArray<{ key: BucketKey; count: number; items: AiLifecycleEvent[] }> = useMemo(() => {
    return [
      { key: 'joiners', count: totals.joiners, items: data?.joiners ?? [] },
      { key: 'movers',  count: totals.movers,  items: data?.movers  ?? [] },
      { key: 'leavers', count: totals.leavers, items: data?.leavers ?? [] },
    ];
  }, [data, totals]);

  const goToIdentity = (identityId: string): void => {
    navigate(`/identities/${encodeURIComponent(identityId)}`);
  };

  // ─── Render ──────────────────────────────────────────────────────────────

  return (
    <div className="p-6 space-y-6 max-w-7xl">
      {/* Local CSS for the J → M → L pulse + dot cascade. Tailwind only
          otherwise; this keyframe is purely cosmetic and ignored if reduced-motion is on. */}
      <style>{`
        @keyframes ag-jml-pulse {
          0%   { transform: scale(1);    opacity: 0.6; }
          50%  { transform: scale(1.08); opacity: 1; }
          100% { transform: scale(1);    opacity: 1; }
        }
        @keyframes ag-jml-dot {
          0%   { transform: translateX(-6px); opacity: 0; }
          60%  { transform: translateX(0);    opacity: 1; }
          100% { transform: translateX(0);    opacity: 1; }
        }
        .ag-jml-pulse-j { animation: ag-jml-pulse 380ms ease-out 0ms 1 both; }
        .ag-jml-pulse-m { animation: ag-jml-pulse 380ms ease-out 140ms 1 both; }
        .ag-jml-pulse-l { animation: ag-jml-pulse 380ms ease-out 280ms 1 both; }
        .ag-jml-dot-j   { animation: ag-jml-dot 380ms ease-out 0ms 1 both; }
        .ag-jml-dot-m   { animation: ag-jml-dot 380ms ease-out 140ms 1 both; }
        .ag-jml-dot-l   { animation: ag-jml-dot 380ms ease-out 280ms 1 both; }
        @media (prefers-reduced-motion: reduce) {
          .ag-jml-pulse-j, .ag-jml-pulse-m, .ag-jml-pulse-l,
          .ag-jml-dot-j,   .ag-jml-dot-m,   .ag-jml-dot-l { animation: none !important; }
        }
      `}</style>

      {/* Header */}
      <div>
        <div className="flex items-center gap-2 text-xs font-medium text-gray-500 uppercase tracking-wider">
          Identity Security
          <span className="text-gray-300">·</span>
          <span>Lifecycle</span>
        </div>
        <h1 className="text-2xl font-semibold text-gray-900 mt-1">Identity Lifecycle</h1>
        <p className="text-sm text-gray-600 mt-2 max-w-3xl">
          Joiners, movers, and leavers across every non-human identity — model
          changes, permission escalations, owner changes, credential rotation.
          AI agents are highlighted as a subtype where applicable.
        </p>
      </div>

      {/* Day-range selector */}
      <div className="flex items-center gap-2">
        <span className="text-xs font-medium uppercase tracking-wider text-gray-500">Window</span>
        <div role="tablist" aria-label="Lifecycle window in days" className="inline-flex rounded-full border border-gray-200 bg-white p-0.5">
          {WINDOW_OPTIONS.map(d => {
            const active = windowDays === d;
            return (
              <button
                key={d}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => setWindowDays(d)}
                className={`px-3 py-1 text-xs font-semibold rounded-full transition ${
                  active
                    ? 'bg-gray-900 text-white shadow-sm'
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                {d} days
              </button>
            );
          })}
        </div>
        {loading && (
          <span className="text-xs text-gray-400 ml-2" aria-live="polite">Loading…</span>
        )}
      </div>

      {error && !loading && (
        <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-800">
          Unable to load AI lifecycle snapshot. Run a discovery and retry.
        </div>
      )}

      {/* Loading skeleton — only on first load before any data is present */}
      {loading && !data && !error && (
        <div className="space-y-4 animate-pulse">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="h-40 bg-gray-100 rounded-xl" />
            <div className="h-40 bg-gray-100 rounded-xl" />
            <div className="h-40 bg-gray-100 rounded-xl" />
          </div>
          <div className="h-64 bg-gray-100 rounded-xl" />
        </div>
      )}

      {/* Empty state — totals are all zero */}
      {!loading && !error && data && grandTotal === 0 && (
        <div className="rounded-xl border border-gray-200 bg-white p-10 text-center">
          <div className="text-sm font-medium text-gray-900">
            No AI lifecycle events in the last {windowDays} days.
          </div>
          <p className="text-xs text-gray-500 mt-2 max-w-md mx-auto">
            The lifecycle log populates after at least 2 discovery runs have completed.
          </p>
        </div>
      )}

      {/* Three bucket cards */}
      {!loading && !error && data && grandTotal > 0 && (
        <>
          <div key={`buckets-${pulseKey}`} className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {buckets.map((b, idx) => {
              const meta = BUCKET_META[b.key];
              const pulseClass = b.key === 'joiners' ? 'ag-jml-pulse-j'
                : b.key === 'movers' ? 'ag-jml-pulse-m'
                : 'ag-jml-pulse-l';
              const dotClass = b.key === 'joiners' ? 'ag-jml-dot-j'
                : b.key === 'movers' ? 'ag-jml-dot-m'
                : 'ag-jml-dot-l';
              // Top 5 identity_ids in this bucket, surfaced as click-through chips.
              const topIds: AiLifecycleEvent[] = b.items.slice(0, 5);
              return (
                <div
                  key={b.key}
                  className={`rounded-xl border border-gray-200 bg-white p-4 ring-2 ring-transparent hover:${meta.ringActive} transition`}
                >
                  <div className="flex items-center justify-between">
                    <span
                      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-bold uppercase tracking-wider ${meta.chipBg} ${meta.chipText}`}
                    >
                      <span
                        aria-hidden
                        className={`inline-block w-1.5 h-1.5 rounded-full ${meta.dotBg} ${dotClass}`}
                      />
                      {meta.label}
                    </span>
                    <span className="text-xs text-gray-400">
                      {idx === 0 ? 'New' : idx === 1 ? 'Changed' : 'Decommissioned'}
                    </span>
                  </div>

                  <div className={`mt-3 text-4xl font-bold ${meta.countText} ${pulseClass}`}>
                    {b.count.toLocaleString()}
                  </div>

                  {topIds.length > 0 ? (
                    <div className="mt-4">
                      <div className="text-[10px] font-semibold uppercase tracking-wider text-gray-500 mb-2">
                        {b.items.length > topIds.length
                          ? `Top ${topIds.length} of ${b.count.toLocaleString()}`
                          : `Agents (${topIds.length})`}
                      </div>
                      <ul className="space-y-1">
                        {topIds.map(ev => (
                          <li key={`${b.key}-${ev.event_id}`}>
                            <button
                              type="button"
                              onClick={() => goToIdentity(ev.identity_id)}
                              className="block w-full text-left text-xs font-mono text-gray-700 hover:text-blue-700 hover:underline truncate"
                              title={ev.identity_id}
                            >
                              {truncate(ev.display_name || ev.identity_id, 40)}
                            </button>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : (
                    <div className="mt-4 text-xs text-gray-400">No agents in this bucket.</div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Recent events table */}
          <div className="rounded-xl border border-gray-200 bg-white overflow-hidden">
            <div className="px-5 py-3 border-b border-gray-100 flex items-center justify-between">
              <h2 className="text-sm font-semibold text-gray-900">Recent Events</h2>
              <span className="text-xs text-gray-500">
                {(data.recent_events?.length || 0).toLocaleString()} event{data.recent_events?.length === 1 ? '' : 's'} in the last {windowDays} days
              </span>
            </div>

            {(!data.recent_events || data.recent_events.length === 0) ? (
              <div className="p-8 text-center text-sm text-gray-500">
                No events captured in this window.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-gray-50 text-xs text-gray-500 uppercase tracking-wider">
                    <tr>
                      <th className="text-left py-2 px-4 font-medium">Event</th>
                      <th className="text-left py-2 px-4 font-medium">Identity</th>
                      <th className="text-left py-2 px-4 font-medium">Severity</th>
                      <th className="text-left py-2 px-4 font-medium">When</th>
                      <th className="text-left py-2 px-4 font-medium">Description</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {data.recent_events.map(ev => {
                      const sev = effectiveSeverity(ev);
                      const ids = mitreIds(ev);
                      return (
                        <tr
                          key={`evt-${ev.event_id}`}
                          onClick={() => goToIdentity(ev.identity_id)}
                          className="hover:bg-gray-50 cursor-pointer"
                        >
                          <td className="py-3 px-4 align-top">
                            <div className="font-medium text-gray-900">{labelFor(ev.event_type)}</div>
                            {ids.length > 0 && (
                              <div className="mt-1">
                                <MitreChipStrip ids={ids} max={4} size="sm" />
                              </div>
                            )}
                          </td>
                          <td className="py-3 px-4 align-top">
                            <div className="font-medium text-gray-900 truncate max-w-[18ch]" title={ev.display_name || ev.identity_id}>
                              {ev.display_name || ev.identity_id}
                            </div>
                            <div className="text-xs text-gray-500 font-mono truncate max-w-[24ch]" title={ev.identity_id}>
                              {ev.identity_id}
                            </div>
                          </td>
                          <td className="py-3 px-4 align-top">
                            <span
                              className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold border uppercase tracking-wider ${SEVERITY_CHIP[sev] || SEVERITY_CHIP.info}`}
                            >
                              {sev}
                            </span>
                          </td>
                          <td className="py-3 px-4 align-top text-xs text-gray-600 whitespace-nowrap">
                            {fmtTime(ev.occurred_at)}
                          </td>
                          <td className="py-3 px-4 align-top text-sm text-gray-700">
                            {ev.description || '—'}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
