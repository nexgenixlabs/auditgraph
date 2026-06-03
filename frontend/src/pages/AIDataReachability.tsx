/**
 * AI Data Reachability — AG-180 Tier 2A
 *
 * Route: /ai-access/data-reachability
 *
 * For every AI agent in the tenant, surfaces which data classifications
 * (PHI / PCI / PII / Source / HR / Financial / Confidential) the agent can
 * reach, with record-count estimates.
 *
 * Architecture-derived: RBAC + resource posture. No log dependency, no Purview.
 *
 * Data sources (already wired):
 *   GET  /api/data-security                   → org-wide classification rollup
 *   GET  /api/ai-agents/<id>/data-reachability → per-agent rollup
 *   POST /api/resources/auto-classify         → admin scan trigger
 *
 * Strict: no fake data, no hardcoded numbers. Empty/null record counts render
 * as "—".
 */
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useConnection } from '../contexts/ConnectionContext';
import { useToast } from '../components/ToastProvider';
import { CLASS_COLORS } from '../types/security_events';

// ─── Types (matches backend response shapes) ─────────────────────────────

interface ClassificationRollup {
  data_classification: string;          // 'PHI' | 'PCI' | 'PII' | 'SOURCE' | 'HR' | 'FINANCIAL' | 'CONFIDENTIAL'
  resource_count: number;
  tag_sourced: number;
  pattern_sourced: number;
  est_records: number | null;
}

interface DataSecuritySummary {
  classifications: ClassificationRollup[];
  agents_with_reachability: number;
  total_classified_resources: number;
}

// ─── Constants ───────────────────────────────────────────────────────────

/** The seven canonical classes (rendered in this fixed order — cards present
 *  even when the class has zero resources, so the user sees full coverage). */
const ALL_CLASSES = ['PHI', 'PCI', 'PII', 'SOURCE', 'HR', 'FINANCIAL', 'CONFIDENTIAL'] as const;
type ClassKey = typeof ALL_CLASSES[number];

const CLASS_LABEL: Record<ClassKey, string> = {
  PHI: 'PHI',
  PCI: 'PCI',
  PII: 'PII',
  SOURCE: 'Source',
  HR: 'HR',
  FINANCIAL: 'Financial',
  CONFIDENTIAL: 'Confidential',
};

const CLASS_BLURB: Record<ClassKey, string> = {
  PHI: 'Protected health info',
  PCI: 'Payment / cardholder data',
  PII: 'Personally identifiable info',
  SOURCE: 'Source code / IP',
  HR: 'HR / employee records',
  FINANCIAL: 'Financial / accounting',
  CONFIDENTIAL: 'Internal confidential',
};

// ─── Count-up hook (number animates from 0 to value over duration ms) ────

function useCountUp(target: number, durationMs: number = 500): number {
  const [value, setValue] = useState(0);
  const startRef = useRef<number | null>(null);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    startRef.current = null;
    if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
    if (target <= 0) {
      setValue(0);
      return;
    }
    const step = (ts: number) => {
      if (startRef.current === null) startRef.current = ts;
      const elapsed = ts - startRef.current;
      const pct = Math.min(1, elapsed / durationMs);
      // ease-out cubic for a calmer finish
      const eased = 1 - Math.pow(1 - pct, 3);
      setValue(Math.round(target * eased));
      if (pct < 1) {
        rafRef.current = requestAnimationFrame(step);
      }
    };
    rafRef.current = requestAnimationFrame(step);
    return () => {
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
    };
  }, [target, durationMs]);

  return value;
}

// ─── Class chip (uses CLASS_COLORS from shared types) ───────────────────

function ClassChip({ cls }: { cls: ClassKey }) {
  const color = CLASS_COLORS[cls];
  return (
    <span
      className="inline-flex items-center text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border"
      style={{
        color,
        borderColor: color,
        backgroundColor: `${color}1A`, // ~10% alpha hex suffix
      }}
    >
      {CLASS_LABEL[cls]}
    </span>
  );
}

// ─── Animated count display ──────────────────────────────────────────────

function AnimatedCount({ value }: { value: number }) {
  const display = useCountUp(value, 500);
  return <>{display.toLocaleString()}</>;
}

// ─── Classification hero card ───────────────────────────────────────────

function ClassCard({ cls, rollup }: { cls: ClassKey; rollup: ClassificationRollup | undefined }) {
  const color = CLASS_COLORS[cls];
  const resourceCount = rollup?.resource_count ?? 0;
  const estRecords = rollup?.est_records;
  const tagSourced = rollup?.tag_sourced ?? 0;
  const patternSourced = rollup?.pattern_sourced ?? 0;

  return (
    <div
      className="rounded-xl border p-4 flex flex-col gap-2 transition hover:translate-y-[-1px]"
      style={{
        borderColor: resourceCount > 0 ? `${color}55` : 'var(--border-default)',
        backgroundColor: 'var(--bg-raised)',
      }}
    >
      <div className="flex items-center justify-between">
        <ClassChip cls={cls} />
        <span className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>
          Class
        </span>
      </div>

      <div className="text-[11px]" style={{ color: 'var(--text-tertiary)' }}>
        {CLASS_BLURB[cls]}
      </div>

      <div className="mt-1">
        <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>
          Resources
        </p>
        <p className="text-2xl font-bold font-mono" style={{ color: 'var(--text-primary)' }}>
          <AnimatedCount value={resourceCount} />
        </p>
      </div>

      <div>
        <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>
          Est. records
        </p>
        <p className="text-lg font-bold font-mono" style={{ color: estRecords == null ? 'var(--text-tertiary)' : 'var(--text-primary)' }}>
          {estRecords == null ? '—' : <AnimatedCount value={estRecords} />}
        </p>
      </div>

      {resourceCount > 0 ? (
        <div
          className="text-[10px] mt-auto pt-2 border-t"
          style={{ color: 'var(--text-tertiary)', borderColor: 'var(--border-subtle)' }}
          title={
            `${tagSourced} resources carry an explicit data-classification tag (HIGH confidence — ` +
            `you applied this label). ${patternSourced} matched a resource-name heuristic ` +
            `(MEDIUM confidence — suspected, not confirmed). We never inspect data-plane content.`
          }
        >
          <span style={{ color }} className="font-semibold">{tagSourced}</span> tagged
          {' · '}
          <span style={{ color }} className="font-semibold">{patternSourced}</span> suspected (name)
        </div>
      ) : (
        <div
          className="text-[10px] mt-auto pt-2 border-t"
          style={{ color: 'var(--text-tertiary)', borderColor: 'var(--border-subtle)' }}
        >
          No resources classified
        </div>
      )}
    </div>
  );
}

// ─── Main page ──────────────────────────────────────────────────────────

export default function AIDataReachability() {
  const { withConnection, selectedConnectionId } = useConnection();
  const { user } = useAuth();
  const { addToast } = useToast();

  const [data, setData] = useState<DataSecuritySummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [classifying, setClassifying] = useState(false);

  const isAdmin = user?.role === 'admin' || user?.role === 'security_admin';

  // Fetch the org-wide classification rollup
  const loadSummary = React.useCallback(() => {
    setLoading(true);
    setError(null);
    fetch(withConnection('/api/data-security'))
      .then(r => {
        if (!r.ok) {
          setError('fetch_error');
          return null;
        }
        return r.json() as Promise<DataSecuritySummary>;
      })
      .then(d => {
        if (d && Array.isArray(d.classifications)) {
          setData(d);
        }
      })
      .catch(() => setError('fetch_error'))
      .finally(() => setLoading(false));
  }, [withConnection]);

  useEffect(() => {
    loadSummary();
  }, [loadSummary, selectedConnectionId]);

  // Map classifications array → keyed lookup so card order is stable
  const byClass = useMemo<Record<string, ClassificationRollup | undefined>>(() => {
    const m: Record<string, ClassificationRollup | undefined> = {};
    if (data?.classifications) {
      for (const c of data.classifications) {
        if (c?.data_classification) {
          m[c.data_classification.toUpperCase()] = c;
        }
      }
    }
    return m;
  }, [data]);

  const handleAutoClassify = async () => {
    if (classifying) return;
    setClassifying(true);
    try {
      const res = await fetch(withConnection('/api/resources/auto-classify'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!res.ok) {
        addToast('Auto-classification failed. Check permissions and try again.', 'error');
        return;
      }
      const payload = (await res.json()) as { classified?: number };
      const n = typeof payload.classified === 'number' ? payload.classified : 0;
      if (n > 0) {
        addToast(`Auto-classified ${n.toLocaleString()} resource${n === 1 ? '' : 's'}.`, 'success');
      } else {
        addToast('Auto-classification complete — no new resources classified.', 'info');
      }
      loadSummary();
    } catch {
      addToast('Auto-classification request failed.', 'error');
    } finally {
      setClassifying(false);
    }
  };

  // ── Loading ────────────────────────────────────────────────────────
  if (loading && !data) {
    return (
      <div className="p-6 flex items-center justify-center py-20">
        <div className="animate-spin h-8 w-8 border-2 border-violet-500 border-t-transparent rounded-full" />
      </div>
    );
  }

  // ── Fetch error ────────────────────────────────────────────────────
  if (error && !data) {
    return (
      <div className="p-6 max-w-[1400px] mx-auto">
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>AI Data Reachability</h1>
        <div
          className="mt-6 rounded-xl border p-6 text-center"
          style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)', color: 'var(--text-secondary)' }}
        >
          <p className="text-sm">Unable to load data classification summary.</p>
          <button
            onClick={loadSummary}
            className="mt-3 text-xs font-semibold px-3 py-1.5 rounded border hover:bg-slate-800/40 transition"
            style={{ borderColor: 'var(--border-default)', color: 'var(--text-primary)' }}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  const totalClassified = data?.total_classified_resources ?? 0;
  const agentsWithReachability = data?.agents_with_reachability ?? 0;

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>AI Data Reachability</h1>
          <p className="text-sm mt-1 max-w-3xl" style={{ color: 'var(--text-secondary)' }}>
            For every AI agent, which resources tagged or named as PHI / PCI / PII / Source / HR /
            Financial / Confidential they could reach — derived from RBAC + resource posture.
            <span className="block mt-1 text-[11px]" style={{ color: 'var(--text-tertiary)' }}>
              <span className="font-semibold">We never read data-plane content.</span> Classification is
              based on Azure tags you set and resource-name patterns. We surface the trust signal you
              applied; we do not look inside the resource.
            </span>
          </p>
        </div>
        {isAdmin && (
          <button
            onClick={handleAutoClassify}
            disabled={classifying}
            className="flex-shrink-0 text-xs font-semibold px-3 py-2 rounded border transition disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-800/40"
            style={{
              borderColor: 'var(--border-default)',
              color: 'var(--text-primary)',
              backgroundColor: 'var(--bg-raised)',
            }}
          >
            {classifying ? (
              <span className="flex items-center gap-2">
                <span className="animate-spin h-3 w-3 border-2 border-current border-t-transparent rounded-full" />
                Classifying…
              </span>
            ) : (
              'Auto-classify resources'
            )}
          </button>
        )}
      </div>

      {/* Summary strip */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        <div
          className="rounded-xl border p-4"
          style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}
        >
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>
            Classified Resources
          </p>
          <p className="text-3xl font-bold font-mono mt-1" style={{ color: 'var(--text-primary)' }}>
            <AnimatedCount value={totalClassified} />
          </p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>
            across storage, SQL, cosmos
          </p>
        </div>
        <div
          className="rounded-xl border p-4"
          style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}
        >
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>
            Agents w/ Reachability
          </p>
          <p className="text-3xl font-bold font-mono mt-1" style={{ color: 'var(--text-primary)' }}>
            <AnimatedCount value={agentsWithReachability} />
          </p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>
            AI agents with RBAC into ≥1 classified resource
          </p>
        </div>
        <div
          className="rounded-xl border p-4"
          style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}
        >
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>
            Active Classes
          </p>
          <p className="text-3xl font-bold font-mono mt-1" style={{ color: 'var(--text-primary)' }}>
            <AnimatedCount value={data?.classifications?.length ?? 0} />
          </p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>
            of {ALL_CLASSES.length} total
          </p>
        </div>
      </div>

      {/* Empty state */}
      {totalClassified === 0 ? (
        <div
          className="rounded-xl border p-8 text-center"
          style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}
        >
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            No classified data detected yet. Either no PHI/PCI/PII/Source/HR resources exist in this tenant, or
            auto-classification has not run.
          </p>
          {isAdmin ? (
            <button
              onClick={handleAutoClassify}
              disabled={classifying}
              className="mt-4 text-xs font-semibold px-3 py-2 rounded border transition disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-800/40"
              style={{
                borderColor: 'var(--border-default)',
                color: 'var(--text-primary)',
                backgroundColor: 'var(--bg-surface)',
              }}
            >
              {classifying ? 'Classifying…' : "Click 'Auto-classify resources' to scan"}
            </button>
          ) : (
            <p className="text-[11px] mt-2" style={{ color: 'var(--text-tertiary)' }}>
              Ask an admin to run auto-classification.
            </p>
          )}
        </div>
      ) : (
        <>
          {/* Hero classification cards */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: 'var(--text-secondary)' }}>
                Data classes
              </h2>
              <span className="text-[11px]" style={{ color: 'var(--text-tertiary)' }}>
                {data?.classifications?.length ?? 0} active · {ALL_CLASSES.length - (data?.classifications?.length ?? 0)} unseen
              </span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-3">
              {ALL_CLASSES.map(cls => (
                <ClassCard key={cls} cls={cls} rollup={byClass[cls]} />
              ))}
            </div>
          </div>

          {/* Agent → Data section */}
          <div
            className="rounded-xl border p-5"
            style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                  Agent → Data drill-down
                </h2>
                <p className="text-[11px] mt-1 max-w-2xl" style={{ color: 'var(--text-secondary)' }}>
                  {agentsWithReachability > 0
                    ? `${agentsWithReachability.toLocaleString()} AI agent${agentsWithReachability === 1 ? ' has' : 's have'} RBAC into one or more classified resources.`
                    : 'No AI agents currently reach classified data.'}
                </p>
              </div>
            </div>

            <div
              className="mt-4 rounded-lg border p-4"
              style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}
            >
              <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                Per-agent drill-down is available via the <span className="font-semibold" style={{ color: 'var(--text-primary)' }}>Agent Investigate</span> drawer
                on any AI agent. Open an agent from the inventory and switch to the Data Reachability section to see
                exactly which classifications it can reach, broken down by resource.
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                <Link
                  to="/ai-inventory/agents"
                  className="text-xs font-semibold px-3 py-1.5 rounded border hover:bg-slate-800/40 transition"
                  style={{
                    borderColor: 'var(--border-default)',
                    color: 'var(--text-primary)',
                    backgroundColor: 'var(--bg-raised)',
                  }}
                >
                  Open AI Inventory →
                </Link>
                <Link
                  to="/ai-access"
                  className="text-xs font-semibold px-3 py-1.5 rounded border hover:bg-slate-800/40 transition"
                  style={{
                    borderColor: 'var(--border-default)',
                    color: 'var(--text-primary)',
                    backgroundColor: 'var(--bg-raised)',
                  }}
                >
                  AI Access overview →
                </Link>
              </div>
            </div>
          </div>

          {/* Methodology footer */}
          <div className="text-[10px] leading-relaxed" style={{ color: 'var(--text-tertiary)' }}>
            <span className="font-semibold uppercase tracking-wider">How this is computed:</span> classifications come
            from resource tags (<code className="font-mono">data-classification=</code>) and resource-name patterns
            (e.g. <code className="font-mono">*-phi-*</code>). Reachability is derived from RBAC role assignments
            scoped to each classified resource — no telemetry, no log dependency. Record-count estimates use
            container/blob heuristics where the resource exposes them; "—" means we cannot estimate without
            fabricating a number.
          </div>
        </>
      )}
    </div>
  );
}
