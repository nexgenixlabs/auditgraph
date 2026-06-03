/**
 * AI Identity Attack Paths — /ai-risk/attack-paths
 *
 * Filters /api/attack-paths to source_entity_type='ai_agent' and renders the
 * AI-agent exfiltration chains (Agent -> MI -> Secret -> Data -> Egress).
 *
 * Layout:
 *   - Header + caption
 *   - 3-stat CTA row (paths / agents at risk / critical) with count-up animation
 *   - Left list (path summaries) + right pane (cinematic AttackPathView)
 *   - Honest empty state when no AI paths exist
 *
 * Reuses the cinematic AttackPathView (AG-Hero-2) via dynamic import. That
 * component consumes a different prop shape than the API row — we map
 * API rows -> AttackPathView paths in mapApiRowToViewPath().
 */
import React, { useEffect, useMemo, useState, lazy, Suspense } from 'react';
import { Link } from 'react-router-dom';
import { MitreChipStrip } from '../components/security/MitreChip';
import type { PathNode, AttackPathRow } from '../types/security_events';

// Dynamic import — keeps ReactFlow + cinematic chain off the initial bundle
// and lazy-loads only when this page is actually viewed.
const AttackPathView = lazy(() => import('../components/graph/AttackPathView'));

// ─── API row (server shape returned by GET /api/attack-paths) ───────────
interface ApiAttackPath {
  id: number;
  source_entity_name: string;
  source_entity_id: string;
  source_entity_type: string;
  path_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  risk_score: number;
  description?: string;
  narrative?: string;
  impact?: string;
  path_length?: number;
  affected_resource_count?: number;
  target_resource_id?: string;
  target_resource_type?: string;
  path_nodes?: PathNode[];
  // optional rollup fields that the backend may surface for AI paths
  record_count?: number;
  records_estimate?: number;
  rollup?: {
    vault_count?: number;
    secret_count?: number;
    storage_count?: number;
    records_estimate?: number | null;
    classification?: string | null;
    egress_status?: 'open' | 'restricted' | null;
  };
}

// ─── AttackPathView prop shape (must match component contract) ──────────
interface ViewPathStep {
  node_type: string;
  node_id: string;
  node_label: string;
  description: string;
  mitre_techniques?: Array<string | { id: string }>;
  classification?: string;
  cloud?: string;
}

interface ViewPath {
  type: string;
  risk_level: string;
  steps: ViewPathStep[];
  impact: string;
  narrative: string;
  // pass-through rollup the view will pick up via the (path as any).rollup read
  rollup?: ApiAttackPath['rollup'];
}

// ─── Display helpers ────────────────────────────────────────────────────
const SEV_BADGE: Record<string, { text: string; bg: string; border: string }> = {
  critical: { text: '#f87171', bg: 'rgba(239,68,68,0.10)',  border: 'rgba(239,68,68,0.35)' },
  high:     { text: '#fb923c', bg: 'rgba(249,115,22,0.10)', border: 'rgba(249,115,22,0.35)' },
  medium:   { text: '#facc15', bg: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.35)' },
  low:      { text: '#4ade80', bg: 'rgba(34,197,94,0.10)',  border: 'rgba(34,197,94,0.35)' },
};

const TYPE_LABELS: Record<string, string> = {
  ai_agent_exfiltration: 'AI Agent Exfiltration',
  ai_agent_secret_access: 'AI Agent Secret Access',
  ai_agent_data_access: 'AI Agent Data Access',
  ai_agent_privilege_escalation: 'AI Agent Privilege Escalation',
  PRIVILEGE_ESCALATION: 'Privilege Escalation',
  KEYVAULT_SECRET_ACCESS: 'Key Vault Access',
  SPN_SECRET_EXPOSURE: 'Secret Exposure',
  ROLE_CHAINING: 'Role Chaining',
  direct_escalation: 'Direct Escalation',
  lateral_movement: 'Lateral Movement',
  sensitive_data_exposure: 'Data Exposure',
  cross_tenant_risk: 'Cross-Tenant',
  privilege_accumulation: 'Privilege Accumulation',
};

function prettyType(t: string): string {
  return TYPE_LABELS[t] || t.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

/** Map API PathNode[] -> AttackPathView step shape. */
function mapApiRowToViewPath(row: ApiAttackPath): ViewPath {
  const nodes = row.path_nodes || [];
  const steps: ViewPathStep[] = nodes.map((n, i) => {
    // mitre_techniques on PathNode is MitreTechnique[] objects; the view
    // accepts both strings and {id} objects, so pass through as-is.
    const mt = (n.mitre_techniques || []).map((t) =>
      typeof t === 'string' ? t : { id: (t as { id: string }).id }
    );
    return {
      node_type: n.node_type as string,
      node_id: (n.evidence_id as string) || `${row.id}-${i}`,
      node_label: n.label || '',
      description: (n.description as string) || '',
      mitre_techniques: mt,
      classification: (n.classification as string) || undefined,
      cloud: 'azure',
    };
  });
  return {
    type: row.path_type,
    risk_level: (row.severity || 'medium') as string,
    steps,
    impact: row.impact || row.description || '',
    narrative: row.narrative || '',
    rollup: row.rollup,
  };
}

/** Collect a few MITRE IDs from path_nodes for the list preview chip strip. */
function previewMitreIds(row: ApiAttackPath, max = 3): string[] {
  const ids: string[] = [];
  for (const n of row.path_nodes || []) {
    for (const t of n.mitre_techniques || []) {
      const id = typeof t === 'string' ? t : (t as { id: string }).id;
      if (id && !ids.includes(id)) ids.push(id);
      if (ids.length >= max) return ids;
    }
  }
  return ids;
}

/** Honest record-count rollup, returns null if backend gave nothing. */
function recordRollupLabel(row: ApiAttackPath): string | null {
  const n = row.record_count ?? row.records_estimate ?? row.rollup?.records_estimate ?? null;
  if (n == null) return null;
  if (n >= 1_000_000) return `~${(n / 1_000_000).toFixed(1)}M records`;
  if (n >= 1_000) return `~${(n / 1_000).toFixed(1)}K records`;
  return `~${n} records`;
}

// ─── Count-up hook (0 -> target over ~600ms) ────────────────────────────
function useCountUp(target: number, durationMs = 600): number {
  const [value, setValue] = useState(0);
  useEffect(() => {
    if (target === 0) { setValue(0); return; }
    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / durationMs);
      // ease-out cubic
      const eased = 1 - Math.pow(1 - t, 3);
      setValue(Math.round(target * eased));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, durationMs]);
  return value;
}

// ─── Skeleton ───────────────────────────────────────────────────────────
function LoadingSkeleton() {
  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      <div>
        <div className="h-7 w-72 rounded bg-slate-700/40 animate-pulse" />
        <div className="mt-2 h-4 w-full max-w-2xl rounded bg-slate-700/30 animate-pulse" />
      </div>
      <div className="grid grid-cols-3 gap-3">
        {[0, 1, 2].map(i => (
          <div key={i} className="h-20 rounded-xl bg-slate-700/30 animate-pulse" />
        ))}
      </div>
      <div className="space-y-2">
        {[0, 1, 2].map(i => (
          <div key={i} className="h-14 rounded-xl bg-slate-700/30 animate-pulse" />
        ))}
      </div>
    </div>
  );
}

// ─── Stat card with count-up ────────────────────────────────────────────
function StatCard({ label, value, color, sublabel }: { label: string; value: number; color: string; sublabel?: string }) {
  const counted = useCountUp(value);
  return (
    <div className="rounded-xl border p-4"
      style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
      <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>
        {label}
      </p>
      <p className="text-3xl font-bold font-mono mt-1 tabular-nums transition-colors" style={{ color }}>
        {counted}
      </p>
      {sublabel && (
        <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>{sublabel}</p>
      )}
    </div>
  );
}

// ─── Empty state ────────────────────────────────────────────────────────
function EmptyState() {
  return (
    <div className="p-6 max-w-[1100px] mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>AI Identity Attack Paths</h1>
        <p className="text-sm mt-2 max-w-3xl leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
          Architecture-derived exfiltration chains for AI agents. Each path shows how a compromised
          AI agent could move through a managed identity, harvest secrets, reach sensitive data, and
          egress — mapped to MITRE ATT&amp;CK, computed without log retention.
        </p>
      </div>
      <div className="rounded-xl border p-10 text-center"
        style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
        <svg className="w-12 h-12 mx-auto mb-4" fill="none" stroke="var(--accent-success)" strokeWidth={1.5}
          viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <path d="M9 12l2 2 4-4" />
        </svg>
        <h2 className="text-base font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
          No AI exfiltration paths detected in this tenant
        </h2>
        <p className="text-sm max-w-xl mx-auto leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
          Either no AI agents have access to sensitive resources, or discovery has not run yet.
        </p>
        <div className="mt-5">
          <Link to="/ai-inventory"
            className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border transition-colors hover:bg-[var(--bg-elevated)]"
            style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-default)' }}>
            View AI Inventory &rarr;
          </Link>
        </div>
      </div>
    </div>
  );
}

// ─── Path summary card (left list) ──────────────────────────────────────
function PathSummary({
  row, selected, onClick,
}: { row: ApiAttackPath; selected: boolean; onClick: () => void }) {
  const sev = SEV_BADGE[row.severity] || SEV_BADGE.low;
  const mitre = useMemo(() => previewMitreIds(row, 3), [row]);
  const records = recordRollupLabel(row);

  return (
    <button
      onClick={onClick}
      className={`w-full text-left rounded-xl border px-3 py-3 transition-all ${selected ? 'ring-1' : 'hover:bg-[var(--bg-elevated)]'}`}
      style={{
        borderColor: selected ? sev.border : 'var(--border-default)',
        backgroundColor: selected ? sev.bg : 'var(--bg-raised)',
        // @ts-ignore tailwind ring color falls back to currentColor; set explicit
        boxShadow: selected ? `0 0 0 1px ${sev.border}` : undefined,
      }}
    >
      <div className="flex items-start justify-between gap-2 mb-1.5">
        <div className="min-w-0 flex-1">
          <div className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>
            {row.source_entity_name || 'Unknown AI agent'}
          </div>
          <div className="text-[11px] mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
            {prettyType(row.path_type)}
          </div>
        </div>
        <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border flex-shrink-0"
          style={{ color: sev.text, backgroundColor: sev.bg, borderColor: sev.border }}>
          {row.severity}
        </span>
      </div>

      <div className="flex items-center gap-3 text-[11px] font-mono" style={{ color: sev.text }}>
        <span title="CVSS-aligned 0-10">{(row.risk_score ?? 0).toFixed(1)}</span>
        {records && (
          <span style={{ color: 'var(--text-secondary)' }}>{records}</span>
        )}
      </div>

      {mitre.length > 0 && (
        <div className="mt-2">
          <MitreChipStrip ids={mitre} size="sm" />
        </div>
      )}
    </button>
  );
}

// ─── Fallback path view (used if AttackPathView fails / Suspense pending) ──
function FallbackPathView({ row }: { row: ApiAttackPath }) {
  const mitreIds = useMemo(() => {
    const ids: string[] = [];
    for (const n of row.path_nodes || []) {
      for (const t of n.mitre_techniques || []) {
        const id = typeof t === 'string' ? t : (t as { id: string }).id;
        if (id) ids.push(id);
      }
    }
    return ids;
  }, [row]);
  const sev = SEV_BADGE[row.severity] || SEV_BADGE.low;
  const nodes = row.path_nodes || [];

  return (
    <div className="rounded-xl border p-5 space-y-4"
      style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
      <div>
        <div className="flex items-center gap-2 mb-1.5">
          <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border"
            style={{ color: sev.text, backgroundColor: sev.bg, borderColor: sev.border }}>
            {row.severity}
          </span>
          <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
            {row.source_entity_name} — {prettyType(row.path_type)}
          </span>
        </div>
        {row.impact && (
          <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
            {row.impact}
          </p>
        )}
      </div>

      {mitreIds.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>
            MITRE ATT&amp;CK
          </span>
          <MitreChipStrip ids={mitreIds} size="sm" />
        </div>
      )}

      <ol className="space-y-1.5">
        {nodes.map((n, i) => (
          <li key={i} className="text-xs flex items-start gap-2"
            style={{ color: 'var(--text-secondary)' }}>
            <span className="font-mono text-[10px] mt-0.5 flex-shrink-0" style={{ color: 'var(--text-tertiary)' }}>
              {String(i + 1).padStart(2, '0')}.
            </span>
            <span>
              <span className="font-semibold" style={{ color: 'var(--text-primary)' }}>{n.label}</span>
              {n.description && (
                <span className="ml-1" style={{ color: 'var(--text-tertiary)' }}> — {n.description}</span>
              )}
            </span>
          </li>
        ))}
      </ol>

      {row.narrative && (
        <p className="text-[11px] italic pt-2 border-t"
          style={{ color: 'var(--text-tertiary)', borderColor: 'var(--border-subtle)' }}>
          {row.narrative}
        </p>
      )}
    </div>
  );
}

// ─── Page ───────────────────────────────────────────────────────────────
export default function AIAttackPaths() {
  const [rows, setRows] = useState<ApiAttackPath[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedIdx, setSelectedIdx] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetch('/api/attack-paths?source_entity_type=ai_agent&limit=200')
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data: { paths?: ApiAttackPath[]; items?: ApiAttackPath[]; attack_paths?: ApiAttackPath[] }) => {
        if (cancelled) return;
        const list = data.paths || data.items || data.attack_paths || [];
        // Defense-in-depth filter — endpoint is already scoped, but guard
        // against backends that ignore the source_entity_type filter.
        const filtered = list.filter(p => (p.source_entity_type || '').toLowerCase() === 'ai_agent');
        setRows(filtered);
        setSelectedIdx(0);
      })
      .catch(e => { if (!cancelled) setError(e.message || 'fetch_error'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  // Stat aggregates
  const stats = useMemo(() => {
    const totalPaths = rows.length;
    const uniqueAgents = new Set(rows.map(r => r.source_entity_id).filter(Boolean));
    const critical = rows.filter(r => r.severity === 'critical').length;
    return {
      totalPaths,
      agentsAtRisk: uniqueAgents.size,
      critical,
    };
  }, [rows]);

  const selectedRow = rows[selectedIdx] || null;

  // Pre-compute the AttackPathView props for the selected row.
  // The view expects {paths, summary}; we hand it the single selected path
  // (the left-list selection lives in this page, not in the view).
  const viewProps = useMemo(() => {
    if (!selectedRow) return null;
    const viewPath = mapApiRowToViewPath(selectedRow);
    return {
      paths: [viewPath],
      summary: {
        total_paths: stats.totalPaths,
        critical_paths: stats.critical,
        max_blast_radius: selectedRow.severity || 'medium',
      },
    };
  }, [selectedRow, stats.totalPaths, stats.critical]);

  if (loading) return <LoadingSkeleton />;
  if (error) {
    return (
      <div className="p-6 max-w-[1100px] mx-auto">
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>AI Identity Attack Paths</h1>
        <div className="mt-6 rounded-xl border p-8 text-center"
          style={{ borderColor: 'rgba(239,68,68,0.35)', backgroundColor: 'rgba(239,68,68,0.06)' }}>
          <p className="text-sm" style={{ color: '#f87171' }}>Failed to load attack paths ({error}).</p>
          <p className="text-xs mt-2" style={{ color: 'var(--text-tertiary)' }}>
            Verify the API is reachable and try again.
          </p>
        </div>
      </div>
    );
  }
  if (rows.length === 0) return <EmptyState />;

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>AI Identity Attack Paths</h1>
        <p className="text-sm mt-2 max-w-3xl leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
          Architecture-derived exfiltration chains for AI agents — each path traces how a compromised
          agent could move from its managed identity through a secret store to sensitive data and out
          via network egress. Mapped to MITRE ATT&amp;CK, computed without log retention.
        </p>
      </div>

      {/* CTA stats row */}
      <div className="grid grid-cols-3 gap-3">
        <StatCard label="Paths" value={stats.totalPaths} color="#f87171"
          sublabel={`across ${stats.totalPaths === 1 ? '1 chain' : `${stats.totalPaths} chains`}`} />
        <StatCard label="Agents at risk" value={stats.agentsAtRisk} color="#fb923c"
          sublabel={stats.agentsAtRisk === 1 ? '1 AI identity' : `${stats.agentsAtRisk} AI identities`} />
        <StatCard label="Critical" value={stats.critical} color="#ef4444"
          sublabel="severity-critical paths" />
      </div>

      {/* Two-column layout (stacks on mobile) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left: path list */}
        <div className="lg:col-span-4 space-y-2 lg:max-h-[640px] lg:overflow-y-auto lg:pr-1">
          {rows.map((row, idx) => (
            <PathSummary
              key={row.id}
              row={row}
              selected={idx === selectedIdx}
              onClick={() => setSelectedIdx(idx)}
            />
          ))}
        </div>

        {/* Right: cinematic view */}
        <div className="lg:col-span-8">
          {selectedRow && viewProps && (
            <div className="rounded-xl border p-4"
              style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
              <Suspense fallback={<FallbackPathView row={selectedRow} />}>
                <AttackPathView paths={viewProps.paths} summary={viewProps.summary} />
              </Suspense>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
