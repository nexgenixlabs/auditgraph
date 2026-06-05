/**
 * AG-182 (Tier 3A): Agent Activity Timeline — /ai-runtime/activity
 *
 * "CrowdStrike for AI Agents." Per-agent forensic timeline + behavior
 * baseline + the anomalies derived from drift against that baseline.
 *
 * Two panels:
 *   A. Recent Anomalies — last N anomalies across the fleet
 *      (volume_spike / new_peer / new_resource / off_hours_break)
 *   B. Per-Agent Timeline — picker → baseline strip + chronological
 *      event list with expandable raw payload
 *
 * No fake data. No seeded events. If the engine has not yet learned
 * a 14-day baseline, the strip is replaced by a "Still learning" badge.
 * If no anomalies / no events exist, honest empty states render.
 */
import React, { useEffect, useMemo, useState } from 'react';
import { useConnection } from '../contexts/ConnectionContext';
import type { Severity } from '../types/security_events';

// ─── Server response shapes ─────────────────────────────────────────────

type AnomalyType = 'volume_spike' | 'new_peer' | 'new_resource' | 'off_hours_break' | string;

interface ActivityAnomaly {
  id?: number;
  identity_db_id?: number | null;
  identity_id: string;
  anomaly_type: AnomalyType;
  severity: Severity | string;
  detected_at: string;
  baseline_value: number | null;
  observed_value: number | null;
  delta_pct: number | null;
  description: string;
  related_event_ids?: number[];
  resolved?: boolean;
  resolved_at?: string | null;
}

interface AnomaliesResponse {
  anomalies: ActivityAnomaly[];
  total: number;
}

interface AgentBaseline {
  id?: number;
  identity_db_id?: number;
  identity_id?: string;
  window_days?: number | null;
  avg_daily_model_invocations: number | null;
  p95_daily_model_invocations: number | null;
  avg_daily_records_read: number | null;
  p95_daily_records_read: number | null;
  avg_daily_distinct_peers: number | null;
  hourly_pattern?: Record<string, number> | null;
  samples_count: number;
  is_active: boolean;
  computed_at?: string | null;
}

interface BaselineResponse {
  baseline: AgentBaseline | null;
  still_learning: boolean;
  identity_id: string;
}

// Server-side ActivityEventCategory is broader than the shared
// ActivityEventCategory union (engine emits app-specific strings like
// 'arm_write'/'rbac_grant'). Accept any string here so the page never
// breaks when the engine ships a new category.
interface TimelineEvent {
  id?: number;
  identity_id?: string;
  category: string;
  occurred_at: string;
  source: string;
  resource_id?: string | null;
  resource_type?: string | null;
  operation_name?: string | null;
  metric_value?: number | null;
  severity?: Severity | string | null;
  raw_payload?: Record<string, unknown> | null;
  ingested_at?: string | null;
}

interface TimelineResponse {
  events: TimelineEvent[];
  identity_id: string;
  hours: number;
}

interface AgentListItem {
  identity_id: string;
  display_name?: string | null;
}

interface AgentsListResponse {
  items: AgentListItem[];
  total: number;
}

// ─── Display tables ─────────────────────────────────────────────────────

const ANOMALY_META: Record<string, { label: string; color: string; bg: string; border: string }> = {
  volume_spike:    { label: 'Volume Spike',    color: '#f87171', bg: 'rgba(239,68,68,0.10)',  border: 'rgba(239,68,68,0.35)' },
  new_peer:        { label: 'New Peer',        color: '#fb923c', bg: 'rgba(249,115,22,0.10)', border: 'rgba(249,115,22,0.35)' },
  new_resource:    { label: 'New Resource',    color: '#fb923c', bg: 'rgba(249,115,22,0.10)', border: 'rgba(249,115,22,0.35)' },
  off_hours_break: { label: 'Off-Hours Break', color: '#facc15', bg: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.35)' },
};

function anomalyMeta(t: string) {
  return ANOMALY_META[t] || {
    label: t.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
    color: '#9ca3af',
    bg: 'rgba(156,163,175,0.10)',
    border: 'rgba(156,163,175,0.35)',
  };
}

const SEV_CHIP: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: '#f87171', bg: 'rgba(239,68,68,0.12)',  border: 'rgba(239,68,68,0.40)' },
  high:     { color: '#fb923c', bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.40)' },
  medium:   { color: '#facc15', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.40)' },
  low:      { color: '#4ade80', bg: 'rgba(34,197,94,0.12)',  border: 'rgba(34,197,94,0.40)' },
  info:     { color: '#9ca3af', bg: 'rgba(156,163,175,0.12)', border: 'rgba(156,163,175,0.40)' },
};

function sevChip(s: string | undefined | null) {
  if (!s) return SEV_CHIP.info;
  return SEV_CHIP[s.toLowerCase()] || SEV_CHIP.info;
}

// Dot color per event category. Engine emits a slightly broader set than
// the shared union (e.g. 'arm_write', 'rbac_grant') — unknown categories
// fall back to a neutral slate dot.
const CATEGORY_DOT: Record<string, string> = {
  model_call:        '#a78bfa', // violet
  secret_read:       '#f87171', // red
  data_access:       '#60a5fa', // blue
  permission_change: '#fb923c', // orange
  auth_event:        '#facc15', // amber
  anomaly:           '#ef4444', // strong red
  arm_write:         '#fb923c',
  rbac_grant:        '#fb923c',
};

function categoryDot(c: string): string {
  return CATEGORY_DOT[c] || '#94a3b8';
}

function categoryLabel(c: string): string {
  return c.replace(/_/g, ' ').replace(/\b\w/g, ch => ch.toUpperCase());
}

// Tiny inline icon set (no external deps). 12px stroked glyph per category.
function CategoryIcon({ category }: { category: string }) {
  const stroke = categoryDot(category);
  const common = {
    width: 12, height: 12, viewBox: '0 0 24 24', fill: 'none',
    stroke, strokeWidth: 2, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const,
  };
  switch (category) {
    case 'model_call':
      return (
        <svg {...common}><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2" /></svg>
      );
    case 'secret_read':
      return (
        <svg {...common}><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V7a4 4 0 1 1 8 0v4" /></svg>
      );
    case 'data_access':
      return (
        <svg {...common}><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6" /></svg>
      );
    case 'permission_change':
    case 'rbac_grant':
      return (
        <svg {...common}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
      );
    case 'auth_event':
      return (
        <svg {...common}><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M3 12h12" /></svg>
      );
    case 'anomaly':
      return (
        <svg {...common}><path d="M12 9v4M12 17h.01M10.3 3.86l-8.06 14a2 2 0 0 0 1.73 3h16.06a2 2 0 0 0 1.73-3l-8.06-14a2 2 0 0 0-3.46 0z" /></svg>
      );
    case 'arm_write':
      return (
        <svg {...common}><path d="M12 20h9M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z" /></svg>
      );
    default:
      return <svg {...common}><circle cx="12" cy="12" r="6" /></svg>;
  }
}

// ─── Formatting helpers ─────────────────────────────────────────────────

function fmtRelativeTime(iso: string): string {
  try {
    const d = new Date(iso);
    const diffMs = Date.now() - d.getTime();
    if (!Number.isFinite(diffMs)) return iso;
    const s = Math.round(diffMs / 1000);
    if (s < 60) return `${s}s ago`;
    const m = Math.round(s / 60);
    if (m < 60) return `${m}m ago`;
    const h = Math.round(m / 60);
    if (h < 48) return `${h}h ago`;
    const days = Math.round(h / 24);
    return `${days}d ago`;
  } catch {
    return iso;
  }
}

function fmtAbsTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function fmtNumber(n: number | null | undefined, digits = 1): string {
  if (n == null || !Number.isFinite(n)) return '—';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(digits)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(digits)}K`;
  if (Number.isInteger(n)) return String(n);
  return n.toFixed(digits);
}

function fmtDeltaPct(p: number | null | undefined): string | null {
  if (p == null || !Number.isFinite(p)) return null;
  const sign = p >= 0 ? '+' : '';
  return `${sign}${p.toFixed(0)}%`;
}

function isFreshAnomaly(detectedAt: string, now: number): boolean {
  const t = new Date(detectedAt).getTime();
  if (!Number.isFinite(t)) return false;
  return now - t <= 60 * 60 * 1000; // last hour
}

// ─── Skeletons / shared atoms ───────────────────────────────────────────

function Spinner() {
  return (
    <div className="flex items-center justify-center py-8">
      <div className="animate-spin h-6 w-6 border-2 border-violet-500 border-t-transparent rounded-full" />
    </div>
  );
}

// ─── Recent Anomalies panel (A) ─────────────────────────────────────────

function AnomalyRow({ a, fresh }: { a: ActivityAnomaly; fresh: boolean }) {
  const meta = anomalyMeta(a.anomaly_type);
  const sev = sevChip(a.severity);
  const delta = fmtDeltaPct(a.delta_pct);

  return (
    <div
      className={`rounded-xl border px-3 py-3 transition-all ${fresh ? 'animate-pulse-border' : ''}`}
      style={{
        borderColor: fresh ? meta.border : 'var(--border-default)',
        backgroundColor: fresh ? meta.bg : 'var(--bg-raised)',
        boxShadow: fresh ? `0 0 0 1px ${meta.border}` : undefined,
      }}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span
              className="text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border"
              style={{ color: meta.color, backgroundColor: meta.bg, borderColor: meta.border }}
            >
              {meta.label}
            </span>
            <span
              className="text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border"
              style={{ color: sev.color, backgroundColor: sev.bg, borderColor: sev.border }}
            >
              {a.severity}
            </span>
            <span className="text-[10px] font-mono truncate" style={{ color: 'var(--text-tertiary)' }}>
              {a.identity_id}
            </span>
          </div>
          {a.description && (
            <p className="text-xs mt-1.5 leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
              {a.description}
            </p>
          )}
          <div className="flex items-center gap-3 mt-1.5 text-[10px] font-mono" style={{ color: 'var(--text-tertiary)' }}>
            {a.baseline_value != null && (
              <span>baseline {fmtNumber(a.baseline_value)}</span>
            )}
            {a.observed_value != null && (
              <span style={{ color: meta.color }}>observed {fmtNumber(a.observed_value)}</span>
            )}
            {delta && (
              <span style={{ color: meta.color }}>{delta}</span>
            )}
          </div>
        </div>
        <div className="flex-shrink-0 text-right">
          <p className="text-[10px] font-mono" style={{ color: 'var(--text-tertiary)' }}>{fmtRelativeTime(a.detected_at)}</p>
          {a.resolved && (
            <span className="inline-block mt-1 text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border"
              style={{ color: '#4ade80', backgroundColor: 'rgba(34,197,94,0.10)', borderColor: 'rgba(34,197,94,0.35)' }}>
              Resolved
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

function AnomaliesPanel({ withConnection, onPickAgent }: {
  withConnection: (url: string) => string;
  onPickAgent: (identityId: string) => void;
}) {
  const [items, setItems] = useState<ActivityAnomaly[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetch(withConnection('/api/ai-agents/activity/anomalies?limit=20'))
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<AnomaliesResponse>;
      })
      .then(d => { if (!cancelled) setItems(d.anomalies || []); })
      .catch(e => { if (!cancelled) setError(e.message || 'fetch_error'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [withConnection]);

  // Most-recent 5
  const top5 = items.slice(0, 5);
  const now = Date.now();

  return (
    <div className="rounded-xl border" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
      <div className="px-4 py-3 border-b flex items-center justify-between gap-3" style={{ borderColor: 'var(--border-subtle)' }}>
        <div>
          <h3 className="text-sm font-semibold text-white">Recent Anomalies</h3>
          <p className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
            Volume spikes, new peers, new resources, off-hours bursts — drift from 14-day baseline.
          </p>
        </div>
        {items.length > 0 && (
          <span className="text-[10px] font-mono" style={{ color: 'var(--text-tertiary)' }}>
            {items.length} total
          </span>
        )}
      </div>
      <div className="p-3 space-y-2">
        {loading && <Spinner />}
        {!loading && error && (
          <div className="rounded-lg border p-4 text-center"
            style={{ borderColor: 'rgba(239,68,68,0.35)', backgroundColor: 'rgba(239,68,68,0.06)' }}>
            <p className="text-xs" style={{ color: '#f87171' }}>Failed to load anomalies ({error}).</p>
          </div>
        )}
        {!loading && !error && top5.length === 0 && (
          <div className="rounded-lg border-dashed border p-6 text-center"
            style={{ borderColor: 'var(--border-subtle)' }}>
            <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
              No anomalies detected.
            </p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-tertiary)' }}>
              Either every agent is within its learned baseline, or the behavior engine has not yet
              accumulated enough samples to flag drift.
            </p>
          </div>
        )}
        {!loading && !error && top5.map((a, i) => (
          <button
            key={a.id ?? `${a.identity_id}-${a.detected_at}-${i}`}
            onClick={() => onPickAgent(a.identity_id)}
            className="w-full text-left transition-colors hover:opacity-90"
          >
            <AnomalyRow a={a} fresh={isFreshAnomaly(a.detected_at, now)} />
          </button>
        ))}
      </div>
    </div>
  );
}

// ─── Per-Agent Timeline panel (B) ───────────────────────────────────────

function BaselineStrip({ baseline, stillLearning }: {
  baseline: AgentBaseline | null;
  stillLearning: boolean;
}) {
  const cards: Array<{ label: string; value: string; sublabel?: string; color?: string }> = [
    {
      label: 'Avg model calls / day',
      value: fmtNumber(baseline?.avg_daily_model_invocations ?? null),
      sublabel: baseline?.p95_daily_model_invocations != null ? `p95 ${fmtNumber(baseline.p95_daily_model_invocations)}` : undefined,
      color: '#a78bfa',
    },
    {
      label: 'p95 model calls / day',
      value: fmtNumber(baseline?.p95_daily_model_invocations ?? null),
      sublabel: 'volume ceiling',
      color: '#a78bfa',
    },
    {
      label: 'Avg records read / day',
      value: fmtNumber(baseline?.avg_daily_records_read ?? null),
      sublabel: baseline?.p95_daily_records_read != null ? `p95 ${fmtNumber(baseline.p95_daily_records_read)}` : undefined,
      color: '#60a5fa',
    },
    {
      label: 'Distinct peers / day',
      value: fmtNumber(baseline?.avg_daily_distinct_peers ?? null),
      sublabel: 'principals interacted with',
      color: '#4ade80',
    },
  ];

  return (
    <div className="relative">
      {stillLearning && (
        <div className="absolute -top-2 right-3 z-10">
          <span
            className="inline-block text-[9px] font-bold uppercase tracking-wider px-2 py-1 rounded-full border"
            style={{
              color: '#facc15',
              backgroundColor: 'rgba(245,158,11,0.10)',
              borderColor: 'rgba(245,158,11,0.40)',
            }}
            title="The behavior engine needs ~14 days of activity to publish a stable baseline."
          >
            Still learning ({baseline?.samples_count ?? 0}/14 days)
          </span>
        </div>
      )}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {cards.map(c => (
          <div key={c.label} className="rounded-lg border p-3"
            style={{
              borderColor: 'var(--border-subtle)',
              backgroundColor: 'var(--bg-surface)',
              opacity: stillLearning ? 0.6 : 1,
            }}>
            <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>
              {c.label}
            </p>
            <p className="text-2xl font-bold font-mono mt-1" style={{ color: c.color || 'var(--text-primary)' }}>
              {c.value}
            </p>
            {c.sublabel && (
              <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-tertiary)' }}>{c.sublabel}</p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function TimelineEventRow({ ev, index }: { ev: TimelineEvent; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const dotColor = categoryDot(ev.category);
  const sev = ev.severity ? sevChip(ev.severity) : null;

  // First-render cascade fade-in (capped at 30 events). Pure inline style
  // animation — keeps the CSS confined to this file via the @keyframes
  // defined in <style> at the bottom of the page.
  const delayMs = Math.min(index, 30) * 30;

  const label = ev.operation_name || categoryLabel(ev.category);

  return (
    <div
      className="rounded-lg border transition-all"
      style={{
        borderColor: 'var(--border-subtle)',
        backgroundColor: 'var(--bg-surface)',
        animation: `aaTl-fadeIn 360ms ease-out both`,
        animationDelay: `${delayMs}ms`,
      }}
    >
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full text-left px-3 py-2.5 flex items-center gap-3"
        aria-expanded={expanded}
      >
        <span
          className="flex-shrink-0 inline-flex items-center justify-center w-6 h-6 rounded-full"
          style={{ backgroundColor: `${dotColor}22`, border: `1px solid ${dotColor}66` }}
        >
          <CategoryIcon category={ev.category} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-semibold truncate" style={{ color: 'var(--text-primary)' }}>
              {label}
            </span>
            <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
              {categoryLabel(ev.category)}
            </span>
            {sev && (
              <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border"
                style={{ color: sev.color, backgroundColor: sev.bg, borderColor: sev.border }}>
                {ev.severity}
              </span>
            )}
            <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>· {ev.source}</span>
            {ev.metric_value != null && (
              <span className="text-[10px] font-mono" style={{ color: 'var(--text-tertiary)' }}>
                · {fmtNumber(ev.metric_value)}
              </span>
            )}
          </div>
        </div>
        <span className="text-[10px] font-mono flex-shrink-0" style={{ color: 'var(--text-tertiary)' }}>
          {fmtRelativeTime(ev.occurred_at)}
        </span>
        <span
          aria-hidden
          className="flex-shrink-0 inline-block transition-transform"
          style={{ color: 'var(--text-tertiary)', transform: expanded ? 'rotate(90deg)' : 'rotate(0)' }}
        >
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="9 18 15 12 9 6" />
          </svg>
        </span>
      </button>

      {expanded && (
        <div className="px-3 pb-3 pt-1 border-t"
          style={{ borderColor: 'var(--border-subtle)' }}>
          <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-1.5 text-[11px]">
            <div>
              <dt className="uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Occurred</dt>
              <dd className="font-mono" style={{ color: 'var(--text-secondary)' }}>{fmtAbsTime(ev.occurred_at)}</dd>
            </div>
            {ev.resource_id && (
              <div className="min-w-0">
                <dt className="uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Resource</dt>
                <dd className="font-mono break-all" style={{ color: 'var(--text-secondary)' }}>{ev.resource_id}</dd>
              </div>
            )}
            {ev.resource_type && (
              <div>
                <dt className="uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Resource Type</dt>
                <dd className="font-mono" style={{ color: 'var(--text-secondary)' }}>{ev.resource_type}</dd>
              </div>
            )}
            <div>
              <dt className="uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Source</dt>
              <dd className="font-mono" style={{ color: 'var(--text-secondary)' }}>{ev.source}</dd>
            </div>
          </dl>
          {ev.raw_payload && Object.keys(ev.raw_payload).length > 0 && (
            <div className="mt-2">
              <p className="text-[10px] uppercase tracking-wider font-semibold mb-1"
                style={{ color: 'var(--text-tertiary)' }}>
                Raw payload
              </p>
              <pre className="text-[10px] font-mono rounded p-2 overflow-x-auto whitespace-pre-wrap break-all"
                style={{ backgroundColor: 'var(--bg-elevated, #0b1220)', color: 'var(--text-secondary)' }}>
                {JSON.stringify(ev.raw_payload, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function AgentPicker({
  agents, value, onChange, loading,
}: {
  agents: AgentListItem[];
  value: string;
  onChange: (id: string) => void;
  loading: boolean;
}) {
  return (
    <div className="flex items-center gap-2 flex-wrap">
      <label className="text-[10px] uppercase tracking-wider font-semibold"
        style={{ color: 'var(--text-tertiary)' }}>
        Agent
      </label>
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        disabled={loading || agents.length === 0}
        className="text-xs rounded-md border px-2 py-1.5 min-w-[280px] font-mono"
        style={{
          backgroundColor: 'var(--bg-surface)',
          color: 'var(--text-primary)',
          borderColor: 'var(--border-default)',
        }}
      >
        {agents.length === 0 && (
          <option value="">{loading ? 'Loading agents…' : 'No AI agents discovered'}</option>
        )}
        {agents.length > 0 && !value && <option value="">Select an AI agent…</option>}
        {agents.map(a => (
          <option key={a.identity_id} value={a.identity_id}>
            {a.display_name ? `${a.display_name} — ${a.identity_id}` : a.identity_id}
          </option>
        ))}
      </select>
    </div>
  );
}

function PerAgentPanel({ withConnection, selectedId, onSelectId }: {
  withConnection: (url: string) => string;
  selectedId: string;
  onSelectId: (id: string) => void;
}) {
  const [agents, setAgents] = useState<AgentListItem[]>([]);
  const [agentsLoading, setAgentsLoading] = useState(true);

  // Per-agent fetched state
  const [baseline, setBaseline] = useState<AgentBaseline | null>(null);
  const [stillLearning, setStillLearning] = useState(false);
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load the agent list once.
  useEffect(() => {
    let cancelled = false;
    setAgentsLoading(true);
    fetch(withConnection('/api/ai-agents/enriched?per_page=200&include_possible=false'))
      .then(r => r.ok ? (r.json() as Promise<AgentsListResponse>) : Promise.reject(new Error(`HTTP ${r.status}`)))
      .then(d => {
        if (cancelled) return;
        const items = (d.items || []).map(x => ({
          identity_id: x.identity_id,
          display_name: x.display_name ?? null,
        }));
        setAgents(items);
      })
      .catch(() => { if (!cancelled) setAgents([]); })
      .finally(() => { if (!cancelled) setAgentsLoading(false); });
    return () => { cancelled = true; };
  }, [withConnection]);

  // Auto-pick the first agent the first time the list loads, unless the
  // caller already injected a selection from an anomaly click.
  useEffect(() => {
    if (!selectedId && agents.length > 0) onSelectId(agents[0].identity_id);
  }, [selectedId, agents, onSelectId]);

  // Fetch baseline + timeline for the selected agent.
  useEffect(() => {
    if (!selectedId) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    setEvents([]);
    setBaseline(null);
    setStillLearning(false);

    const encId = encodeURIComponent(selectedId);
    Promise.all([
      fetch(withConnection(`/api/ai-agents/${encId}/baseline`)).then(r => r.ok ? r.json() as Promise<BaselineResponse> : Promise.reject(new Error(`baseline HTTP ${r.status}`))),
      fetch(withConnection(`/api/ai-agents/${encId}/activity-timeline?hours=24`)).then(r => r.ok ? r.json() as Promise<TimelineResponse> : Promise.reject(new Error(`timeline HTTP ${r.status}`))),
    ])
      .then(([b, t]) => {
        if (cancelled) return;
        setBaseline(b.baseline);
        setStillLearning(b.still_learning || !b.baseline);
        setEvents(t.events || []);
      })
      .catch(e => { if (!cancelled) setError(e.message || 'fetch_error'); })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, [selectedId, withConnection]);

  return (
    <div className="rounded-xl border" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
      <div className="px-4 py-3 border-b flex items-center justify-between gap-3 flex-wrap"
        style={{ borderColor: 'var(--border-subtle)' }}>
        <div>
          <h3 className="text-sm font-semibold text-white">Per-Agent Forensic Timeline</h3>
          <p className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
            Learned 14-day baseline + last 24h of activity, sorted newest first. Click any event for the raw payload.
          </p>
        </div>
        <AgentPicker
          agents={agents}
          value={selectedId}
          onChange={onSelectId}
          loading={agentsLoading}
        />
      </div>

      <div className="p-4 space-y-4">
        {!selectedId && (
          <div className="rounded-lg border-dashed border p-6 text-center"
            style={{ borderColor: 'var(--border-subtle)' }}>
            <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
              {agentsLoading ? 'Loading AI agents…' : 'No AI agent selected.'}
            </p>
            {!agentsLoading && agents.length === 0 && (
              <p className="text-xs mt-1" style={{ color: 'var(--text-tertiary)' }}>
                No AI agents have been discovered yet. Run an AI discovery scan to populate this panel.
              </p>
            )}
          </div>
        )}

        {selectedId && loading && <Spinner />}

        {selectedId && !loading && error && (
          <div className="rounded-lg border p-4 text-center"
            style={{ borderColor: 'rgba(239,68,68,0.35)', backgroundColor: 'rgba(239,68,68,0.06)' }}>
            <p className="text-xs" style={{ color: '#f87171' }}>
              Failed to load agent data ({error}).
            </p>
          </div>
        )}

        {selectedId && !loading && !error && (
          <>
            <BaselineStrip baseline={baseline} stillLearning={stillLearning || !baseline} />

            {events.length === 0 ? (
              <div className="rounded-lg border-dashed border p-6 text-center"
                style={{ borderColor: 'var(--border-subtle)' }}>
                <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                  No activity events in the last 24 hours.
                </p>
                <p className="text-xs mt-1" style={{ color: 'var(--text-tertiary)' }}>
                  The behavior engine ingests events from cloud control-plane and audit log feeds —
                  nothing has landed for this agent in the lookback window.
                </p>
              </div>
            ) : (
              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-[10px] uppercase tracking-wider font-semibold"
                    style={{ color: 'var(--text-tertiary)' }}>
                    Timeline · last 24h · {events.length} event{events.length === 1 ? '' : 's'}
                  </p>
                </div>
                {/* Horizontally scroll-able on narrow screens, vertically scrollable always */}
                <div className="space-y-1.5 max-h-[640px] overflow-y-auto overflow-x-auto pr-1">
                  {events.map((ev, i) => (
                    <TimelineEventRow
                      key={ev.id ?? `${ev.occurred_at}-${i}`}
                      ev={ev}
                      index={i}
                    />
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ─── Page ───────────────────────────────────────────────────────────────

export default function AgentActivityTimeline() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [selectedAgentId, setSelectedAgentId] = useState<string>('');

  // Reset agent selection when scope changes so we don't show stale data.
  useEffect(() => { setSelectedAgentId(''); }, [selectedConnectionId]);

  // Stable identity for the picker handler — also used when clicking an
  // anomaly row to jump-to-agent in panel B.
  const onPickAgent = useMemo(() => (id: string) => setSelectedAgentId(id), []);

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      {/* Page-local keyframes (no external CSS file changes) */}
      <style>{`
        @keyframes aaTl-fadeIn {
          from { opacity: 0; transform: translateY(4px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes aaTl-pulseBorder {
          0%, 100% { box-shadow: 0 0 0 1px rgba(239,68,68,0.45); }
          50%      { box-shadow: 0 0 0 2px rgba(239,68,68,0.85); }
        }
        .animate-pulse-border {
          animation: aaTl-pulseBorder 1.8s ease-in-out infinite;
        }
      `}</style>

      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">AI Agent Activity</h1>
        <p className="text-sm mt-2 max-w-3xl leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
          Per-agent forensic timeline + learned 14-day behavior baseline. Volume spikes,
          new peers, new resources, off-hours bursts.
        </p>
      </div>

      {/* A. Recent Anomalies */}
      <AnomaliesPanel withConnection={withConnection} onPickAgent={onPickAgent} />

      {/* B. Per-Agent Timeline */}
      <PerAgentPanel
        withConnection={withConnection}
        selectedId={selectedAgentId}
        onSelectId={setSelectedAgentId}
      />
    </div>
  );
}
