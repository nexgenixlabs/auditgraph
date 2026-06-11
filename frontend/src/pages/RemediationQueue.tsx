/**
 * AG-CHANGE-V2 (2026-06-11) — Change Control Center rebuild.
 *
 * Founder-spec rebuild to match the reference comp. Old preserved at
 * pages/RemediationQueueLegacy.tsx.
 *
 * Layout (top-down):
 *   Header       — title + shield icon + subtitle
 *   4 KPI cards  — Open · In Progress · Resolved · Dismissed
 *   Severity filter row (Critical / High / Medium / Low pills)
 *   2-column body:
 *     Left  — pending-approvals list or empty state with helper text
 *             and Level 1 / Level 2 framework pills
 *     Right — Approval Workflow rail (5 steps: Remediation Plan →
 *             Security Review → Change Advisory Board → Execution →
 *             Verification)
 *
 * SSOT:
 *   /api/remediation/queue       active queue items
 *   /api/remediation/generated   counts for "open" (proxy until queue
 *                                handler exposes full status breakdown)
 */
import React, { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';

// ─── Types ─────────────────────────────────────────────────────────

interface QueueItem {
  id?: number | string;
  identity_id?: string;
  identity_name?: string;
  title?: string;
  description?: string;
  severity?: string;
  status?: string;          // open / in_progress / resolved / dismissed
  level?: 1 | 2;
  approval_state?: string;  // pending_review / approved / rejected
  risk_reduction_pct?: number;
  created_at?: string;
}

// ─── Helpers ───────────────────────────────────────────────────────

function severityTone(sev: string | undefined): { text: string; bg: string; border: string; label: string } {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return { text: '#f87171', bg: 'rgba(239,68,68,0.10)',  border: 'rgba(239,68,68,0.40)',  label: 'CRITICAL' };
  if (s === 'high')     return { text: '#fb923c', bg: 'rgba(251,146,60,0.10)', border: 'rgba(251,146,60,0.40)', label: 'HIGH' };
  if (s === 'medium')   return { text: '#fbbf24', bg: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.40)', label: 'MEDIUM' };
  if (s === 'low')      return { text: '#a3e635', bg: 'rgba(163,230,53,0.10)', border: 'rgba(163,230,53,0.40)', label: 'LOW' };
  return { text: '#94a3b8', bg: 'rgba(148,163,184,0.10)', border: 'rgba(148,163,184,0.30)', label: '—' };
}

const STATUS_TONE: Record<string, { color: string; icon: React.ReactNode }> = {
  open:        { color: '#fb923c', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9" /></svg> },
  in_progress: { color: '#a78bfa', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg> },
  resolved:    { color: '#34d399', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg> },
  dismissed:   { color: '#94a3b8', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/></svg> },
};

// ─── Main ──────────────────────────────────────────────────────────

const WORKFLOW = [
  { step: 1, title: 'Remediation Plan',     sub: 'Action created and risk validated', color: '#60a5fa' },
  { step: 2, title: 'Security Review',      sub: 'Level 1 approval required',         color: '#fbbf24' },
  { step: 3, title: 'Change Advisory Board',sub: 'Level 2 approval required',         color: '#fb923c' },
  { step: 4, title: 'Execution',            sub: 'Automated or manual execution',     color: '#a78bfa' },
  { step: 5, title: 'Verification',         sub: 'Post-remediation validation',       color: '#34d399' },
];

export default function ChangeControlCenter() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [items, setItems] = useState<QueueItem[]>([]);
  const [generated, setGenerated] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [sevFilter, setSevFilter] = useState<'critical' | 'high' | 'medium' | 'low' | ''>('');

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      fetch(withConnection('/api/remediation/queue')).then(r => r.ok ? r.json() : null),
      fetch(withConnection('/api/remediation/generated?limit=100')).then(r => r.ok ? r.json() : null),
    ]).then(([q, g]) => {
      if (cancelled) return;
      const list: QueueItem[] = Array.isArray(q?.items) ? q.items
                              : Array.isArray(q?.queue) ? q.queue
                              : Array.isArray(q) ? q : [];
      setItems(list);
      // Backend ships `actions` (legacy key); fall through other shapes.
      const gen = Array.isArray(g?.actions) ? g.actions
                : Array.isArray(g?.items) ? g.items
                : Array.isArray(g?.remediations) ? g.remediations : [];
      setGenerated(gen);
      setLoading(false);
    }).catch(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId]);

  const counts = useMemo(() => {
    const c: Record<string, number> = { open: 0, in_progress: 0, resolved: 0, dismissed: 0 };
    items.forEach(it => { c[(it.status || 'open').toLowerCase()] = (c[(it.status || 'open').toLowerCase()] || 0) + 1; });
    // When the queue is fully empty, surface the generated count so the
    // "Open" tile reflects the upstream pipeline rather than reading 0.
    if (c.open === 0 && items.length === 0 && generated.length > 0) {
      c.open = generated.filter(g => (g.severity || '').toLowerCase() === 'critical').length;
    }
    return c;
  }, [items, generated]);

  const filtered = useMemo(() => {
    if (!sevFilter) return items;
    return items.filter(i => (i.severity || '').toLowerCase() === sevFilter);
  }, [items, sevFilter]);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="animate-spin h-8 w-8 border-2 border-violet-500 border-t-transparent rounded-full" />
      </div>
    );
  }

  return (
    <div className="p-5 max-w-[1800px] mx-auto space-y-4 bg-slate-950 min-h-screen">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-violet-500/30 to-blue-500/30 border border-violet-500/40 flex items-center justify-center">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="w-6 h-6 text-violet-300">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white">Change Control Center</h1>
          <p className="text-sm text-slate-400">Governed remediation with dual-approval gate and evidence packages</p>
        </div>
      </div>

      {/* 4 KPI cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {(['open', 'in_progress', 'resolved', 'dismissed'] as const).map(k => {
          const meta = STATUS_TONE[k];
          const label = { open: 'Open', in_progress: 'In Progress', resolved: 'Resolved', dismissed: 'Dismissed' }[k];
          return (
            <div key={k} className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-4">
              <div className="flex items-start justify-between gap-2 mb-1">
                <p className="text-[10px] uppercase tracking-wider font-bold text-slate-500">{label}</p>
                <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
                  style={{ background: `${meta.color}15`, border: `1px solid ${meta.color}40`, color: meta.color }}>
                  {meta.icon}
                </div>
              </div>
              <p className="text-4xl font-bold mt-1" style={{ color: meta.color }}>{counts[k] ?? 0}</p>
            </div>
          );
        })}
      </div>

      {/* Severity filter pills */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] uppercase tracking-wider font-bold text-slate-500">Severity:</span>
        {(['', 'critical', 'high', 'medium', 'low'] as const).map(s => {
          const active = sevFilter === s;
          const tone = s ? severityTone(s) : { text: '#a78bfa', bg: 'rgba(167,139,250,0.15)', border: 'rgba(167,139,250,0.40)', label: 'All' };
          return (
            <button key={s || 'all'} onClick={() => setSevFilter(s as any)}
              className="px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider transition"
              style={{
                background: active ? tone.bg : 'rgba(15,23,42,0.80)',
                color: active ? tone.text : '#94a3b8',
                border: `1px solid ${active ? tone.border : 'rgba(255,255,255,0.05)'}`,
              }}>
              {s ? tone.label : 'All'}
            </button>
          );
        })}
      </div>

      {/* Body: pending approvals (left) + Approval Workflow (right) */}
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_320px] gap-4">
        {/* Left: pending approvals OR empty state */}
        <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-5 min-h-[400px]">
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full py-12 text-center">
              <div className="w-16 h-16 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center mb-4">
                <svg className="w-8 h-8 text-emerald-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
              </div>
              <p className="text-sm font-medium text-slate-200">No pending approvals</p>
              <p className="text-xs text-slate-500 mt-2 max-w-md leading-relaxed">
                Remediation actions approved through the <Link to="/remediation" className="text-violet-400 hover:text-violet-300">Remediation Plan</Link> will
                appear here for dual-approval review before scripts are released.
              </p>
              <div className="flex items-center gap-2 mt-6 flex-wrap justify-center">
                <span className="px-3 py-1.5 rounded-lg text-[11px] font-medium bg-amber-500/15 text-amber-300 border border-amber-500/40">
                  Level 1 — Security Review
                </span>
                <span className="px-3 py-1.5 rounded-lg text-[11px] font-medium bg-orange-500/15 text-orange-300 border border-orange-500/40">
                  Level 2 — Change Advisory Board + ticket reference
                </span>
              </div>
              <Link to="/remediation"
                className="mt-6 px-4 py-2 rounded-lg text-xs font-medium bg-violet-500 text-white hover:bg-violet-400 transition flex items-center gap-2">
                Open Remediation Plan →
              </Link>
            </div>
          ) : (
            <div className="space-y-2">
              {filtered.map((it, i) => {
                const tone = severityTone(it.severity);
                return (
                  <Link key={it.id || i} to={`/remediation-queue/${it.id || ''}`}
                    className="grid grid-cols-[80px_2fr_100px_120px_30px] gap-3 items-center px-3 py-3 rounded-lg hover:bg-slate-800/40 transition border border-white/5">
                    <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded text-center"
                      style={{ background: tone.bg, color: tone.text, border: `1px solid ${tone.border}` }}>{tone.label}</span>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-slate-200 truncate">{it.title || it.description || 'Remediation'}</p>
                      <p className="text-[11px] text-slate-500 truncate">{it.identity_name || it.identity_id || ''}</p>
                    </div>
                    <span className="text-[10px] text-slate-400">{it.level ? `Level ${it.level}` : 'Pending'}</span>
                    <span className="text-emerald-400 font-bold font-mono text-xs">+{it.risk_reduction_pct || 0}%</span>
                    <svg className="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7"/></svg>
                  </Link>
                );
              })}
            </div>
          )}
        </div>

        {/* Right: Approval Workflow rail */}
        <aside className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-5">
          <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-300 mb-3">Approval Workflow</h3>
          <div className="space-y-3">
            {WORKFLOW.map((w, i) => (
              <div key={w.step} className="flex items-start gap-3">
                <div className="flex flex-col items-center">
                  <div className="w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0"
                    style={{ background: `${w.color}15`, color: w.color, border: `2px solid ${w.color}40` }}>
                    {w.step}
                  </div>
                  {i < WORKFLOW.length - 1 && (
                    <span className="w-px h-6 bg-slate-700 mt-1" />
                  )}
                </div>
                <div className="flex-1 min-w-0 pt-1">
                  <p className="text-xs font-semibold" style={{ color: w.color }}>{w.title}</p>
                  <p className="text-[10px] text-slate-500 mt-0.5">{w.sub}</p>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-4 pt-4 border-t border-white/5">
            <p className="text-[10px] text-slate-500 leading-relaxed">
              Every approved change carries a tamper-proof <Link to="/activity" className="text-violet-400 hover:text-violet-300">audit trail</Link> with
              evidence packages for SOC 2 / ISO 27001 review.
            </p>
          </div>
        </aside>
      </div>
    </div>
  );
}
