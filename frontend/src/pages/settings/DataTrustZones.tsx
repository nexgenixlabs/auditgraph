/**
 * AG-193 (Sprint 1) — Data Trust Zones
 *
 * CISO-asserted classification scope rules. Customer-facing copy says
 * "Data Trust Zones" everywhere — never "Classification Scope Rules".
 *
 * Settings → Data Trust Zones page (admin only).
 *
 * Layout:
 *   Header — what zones are, principle ("we never read your data")
 *   Class chips — 7 classification buttons (PHI/PCI/PII/HR/FINANCIAL/SOURCE/CONFIDENTIAL)
 *   Active zones — grouped by classification, each with scope info + coverage
 *   Add-zone modal — pick class, scope type, scope value, optional notes
 *   Recompute button — applies zones now (otherwise next discovery does it)
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';

const CLASSES = [
  { key: 'PHI',          label: 'PHI',          color: '#dc2626', desc: 'Protected Health Information (HIPAA)' },
  { key: 'PCI',          label: 'PCI',          color: '#ea580c', desc: 'Payment Card Industry (PCI-DSS)' },
  { key: 'PII',          label: 'PII',          color: '#d97706', desc: 'Personally Identifiable Information (GDPR/CCPA)' },
  { key: 'SOURCE',       label: 'Source Code',  color: '#7c3aed', desc: 'Source code repositories, build artifacts' },
  { key: 'HR',           label: 'HR',           color: '#0891b2', desc: 'Employee records, compensation' },
  { key: 'FINANCIAL',    label: 'Financial',    color: '#059669', desc: 'Internal financials, ledgers' },
  { key: 'CONFIDENTIAL', label: 'Confidential', color: '#475569', desc: 'Other internal-only data' },
] as const;

const SCOPE_TYPES = [
  { key: 'subscription',            label: 'Subscription (exact)',         hint: 'Subscription ID — e.g. df244a11-2de3-4448-b59c-2ad019f3319a' },
  { key: 'resource_group',          label: 'Resource Group (exact)',       hint: 'Resource group name — e.g. carehub-centus-prd-rg' },
  { key: 'subscription_pattern',    label: 'Subscription (glob pattern)',  hint: 'Wildcard subscription — e.g. *healthcare* (matches against the sub ID/name)' },
  { key: 'resource_group_pattern',  label: 'Resource Group (glob pattern)', hint: 'Wildcard RG — e.g. customer-* or *-prod-rg' },
] as const;

interface Zone {
  id: number;
  classification: string;
  scope_type: string;
  scope_value: string;
  asserted_by: string | null;
  asserted_at: string | null;
  notes: string | null;
  created_at: string | null;
  updated_at: string | null;
}

interface Coverage {
  resource_count: number;
  by_type: Record<string, number>;
}

interface ArgusSuggestion {
  classification: string;
  scope_type: string;
  scope_value: string;
  matched_resources: number;
  currently_unclassified: number;
  reason: string;
}

interface AuditEvent {
  id: number;
  action_type: string;
  description: string;
  metadata: any;
  user_id: number | null;
  created_at: string | null;
}

export default function DataTrustZones() {
  const [zones, setZones] = useState<Zone[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [coverage, setCoverage] = useState<Record<number, Coverage>>({});
  const [addOpen, setAddOpen] = useState(false);
  const [recomputing, setRecomputing] = useState(false);
  const [recomputeResult, setRecomputeResult] = useState<string | null>(null);
  // AG-193 Sprint 2 — Argus suggestions + audit log
  const [argus, setArgus] = useState<ArgusSuggestion[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [tab, setTab] = useState<'zones' | 'audit'>('zones');
  // AG-198 Sprint 3 — Purview status
  const [purview, setPurview] = useState<{ enabled: boolean; cached_labels: number; mapped_labels: number; message: string } | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch('/api/data-trust-zones');
      if (!r.ok) throw new Error(`list failed: ${r.status}`);
      const d = await r.json();
      const list: Zone[] = d.zones || [];
      setZones(list);
      // Fetch coverage for each in parallel
      const covMap: Record<number, Coverage> = {};
      await Promise.all(list.map(async z => {
        try {
          const cr = await fetch(`/api/data-trust-zones/${z.id}/coverage`);
          if (cr.ok) {
            const cd = await cr.json();
            covMap[z.id] = { resource_count: cd.resource_count, by_type: cd.by_type || {} };
          }
        } catch {}
      }));
      setCoverage(covMap);
      setError(null);
    } catch (e: any) {
      setError(e.message || 'failed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // AG-193 Sprint 2 — pull Argus suggestions + audit log alongside zones
  useEffect(() => {
    fetch('/api/argus/classification-suggestions')
      .then(r => r.ok ? r.json() : null)
      .then(d => setArgus((d?.suggestions || []) as ArgusSuggestion[]))
      .catch(() => {});
    fetch('/api/data-trust-zones/audit')
      .then(r => r.ok ? r.json() : null)
      .then(d => setAuditEvents((d?.events || []) as AuditEvent[]))
      .catch(() => {});
    fetch('/api/purview/status')
      .then(r => r.ok ? r.json() : null)
      .then(d => setPurview(d as any))
      .catch(() => {});
  }, [zones.length]); // refetch after CRUD

  async function acceptArgusSuggestion(s: ArgusSuggestion) {
    try {
      const r = await fetch('/api/data-trust-zones', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          classification: s.classification,
          scope_type: s.scope_type,
          scope_value: s.scope_value,
          notes: `Accepted Argus suggestion (${s.matched_resources} matched resources)`,
        }),
      });
      if (!r.ok) { const d = await r.json(); alert(d.error || `Status ${r.status}`); return; }
      refresh();
    } catch (e: any) { alert(e.message); }
  }

  const grouped = useMemo(() => {
    const m: Record<string, Zone[]> = {};
    for (const c of CLASSES) m[c.key] = [];
    for (const z of zones) {
      if (!m[z.classification]) m[z.classification] = [];
      m[z.classification].push(z);
    }
    return m;
  }, [zones]);

  const totalClassified = useMemo(() =>
    Object.values(coverage).reduce((a, c) => a + (c?.resource_count || 0), 0),
  [coverage]);

  async function revoke(id: number) {
    if (!window.confirm('Revoke this zone? Resources will be re-classified on the next scan.')) return;
    try {
      const r = await fetch(`/api/data-trust-zones/${id}`, { method: 'DELETE' });
      if (!r.ok) throw new Error(`delete failed: ${r.status}`);
      refresh();
    } catch (e: any) { alert(e.message); }
  }

  async function recompute() {
    setRecomputing(true);
    setRecomputeResult(null);
    try {
      const r = await fetch('/api/data-trust-zones/recompute', { method: 'POST' });
      const d = await r.json();
      const updated = d.rows_updated || 0;
      const byCls = d.by_classification || {};
      const parts = Object.entries(byCls).map(([k, v]) => `${v} ${k}`).join(', ');
      setRecomputeResult(updated > 0
        ? `Recomputed: ${updated} resources classified (${parts}).`
        : 'No changes — classifications were already up to date.');
      refresh();
    } catch (e: any) {
      setRecomputeResult(`Failed: ${e.message}`);
    } finally {
      setRecomputing(false);
    }
  }

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <p className="text-[10px] uppercase tracking-[0.2em] font-bold text-violet-400">Platform · Classification</p>
        </div>
        <h1 className="text-2xl font-bold text-white mt-1">Data Trust Zones</h1>
        <p className="text-sm text-slate-400 mt-2 max-w-3xl leading-relaxed">
          Tell AuditGraph where your sensitive data lives so the Unified Identity Graph can
          map identity → AI agent → model → <strong>classified data</strong> with real exposure
          numbers. We propagate your assertions down the ARM tree at every scan.
        </p>
        <p className="text-[11px] text-slate-500 mt-2 max-w-3xl">
          <strong className="text-emerald-400">We never read your data.</strong> Zones are
          metadata-only — we use the subscription / resource group scope you assert, not the
          contents of any storage account or database. Same read-only Azure permissions you
          already granted.
        </p>
      </div>

      {/* Stat bar + Recompute */}
      <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-4 flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-6">
          <div>
            <p className="text-[10px] uppercase tracking-wider font-bold text-slate-500">Active Zones</p>
            <p className="text-2xl font-bold font-mono text-white">{zones.length}</p>
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-wider font-bold text-slate-500">Classified Resources</p>
            <p className="text-2xl font-bold font-mono text-emerald-300">{totalClassified.toLocaleString()}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {recomputeResult && (
            <span className="text-[11px] text-slate-400 max-w-md">{recomputeResult}</span>
          )}
          <button onClick={recompute} disabled={recomputing}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-700 hover:bg-slate-600 text-white border border-slate-600 disabled:opacity-50">
            {recomputing ? 'Recomputing…' : 'Recompute Now'}
          </button>
          <button onClick={() => setAddOpen(true)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-violet-500 hover:bg-violet-400 text-white">
            + Add Zone
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg bg-rose-500/10 border border-rose-500/30 p-3 text-rose-300 text-sm">
          {error}
        </div>
      )}

      {/* AG-198 Sprint 3 — Purview connector status */}
      {purview && (
        <div className={`rounded-xl border p-3 flex items-center justify-between gap-3 ${purview.enabled
          ? 'bg-emerald-500/5 border-emerald-500/30'
          : 'bg-slate-800/40 border-slate-700/50'}`}>
          <div className="flex items-center gap-3 min-w-0">
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider flex-shrink-0
              ${purview.enabled ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-700/50 text-slate-400'}`}>
              Purview {purview.enabled ? '· ON' : '· OFF'}
            </span>
            <div className="min-w-0">
              <p className="text-[11px] text-slate-300">{purview.message}</p>
              <p className="text-[10px] text-slate-500 mt-0.5">
                {purview.mapped_labels} Purview classifier labels mapped · {purview.cached_labels} cached for this tenant
              </p>
            </div>
          </div>
        </div>
      )}

      {/* AG-193 Sprint 2 — Argus suggestions */}
      {argus.length > 0 && (
        <div className="rounded-xl bg-violet-500/5 border border-violet-500/20 p-4">
          <div className="flex items-center gap-2 mb-3">
            <span className="text-[10px] uppercase tracking-wider font-bold text-violet-300">Argus Suggestions</span>
            <span className="text-[11px] text-slate-400">— resources whose names suggest a classification</span>
          </div>
          <div className="space-y-2">
            {argus.slice(0, 5).map((s, i) => {
              const c = CLASSES.find(c => c.key === s.classification);
              return (
                <div key={i} className="flex items-center justify-between gap-3 p-2.5 rounded-lg bg-slate-900/40 border border-slate-700/40">
                  <div className="flex items-center gap-3 min-w-0">
                    <span className="px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider flex-shrink-0"
                      style={{ background: `${c?.color || '#94a3b8'}22`, color: c?.color || '#94a3b8' }}>
                      {s.classification}
                    </span>
                    <div className="min-w-0">
                      <p className="text-sm font-mono text-white truncate">{s.scope_value}</p>
                      <p className="text-[10px] text-slate-400 mt-0.5">{s.reason}</p>
                    </div>
                  </div>
                  <button onClick={() => acceptArgusSuggestion(s)}
                    className="px-3 py-1 rounded text-[10px] font-medium bg-violet-500 hover:bg-violet-400 text-white flex-shrink-0">
                    Accept → Create Zone
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-700/40">
        <button onClick={() => setTab('zones')}
          className={`px-3 py-2 text-xs font-medium border-b-2 transition ${tab === 'zones' ? 'border-violet-500 text-white' : 'border-transparent text-slate-400 hover:text-white'}`}>
          Active Zones
        </button>
        <button onClick={() => setTab('audit')}
          className={`px-3 py-2 text-xs font-medium border-b-2 transition ${tab === 'audit' ? 'border-violet-500 text-white' : 'border-transparent text-slate-400 hover:text-white'}`}>
          Audit Log ({auditEvents.length})
        </button>
      </div>

      {tab === 'audit' && (
        <div className="rounded-xl bg-[#0f172a]/60 border border-white/5 p-3 space-y-1.5">
          {auditEvents.length === 0 ? (
            <p className="text-[11px] text-slate-500 italic py-3 px-2">No zone activity yet.</p>
          ) : auditEvents.map(ev => (
            <div key={ev.id} className="flex items-start justify-between gap-3 p-2 rounded bg-slate-800/30 border border-slate-700/30">
              <div className="min-w-0 flex-1">
                <p className="text-xs text-slate-200">{ev.description}</p>
                <p className="text-[10px] text-slate-500 mt-0.5">
                  {ev.action_type}
                  {ev.user_id && ` · user #${ev.user_id}`}
                  {ev.created_at && ` · ${new Date(ev.created_at).toLocaleString()}`}
                </p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Per-class blocks (Zones tab) */}
      {tab === 'zones' && (
      <>
      <div className="space-y-4">
        {CLASSES.map(c => {
          const items = grouped[c.key] || [];
          return (
            <div key={c.key} className="rounded-xl bg-[#0f172a]/60 border border-white/5">
              <div className="px-4 py-3 border-b border-white/5 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
                    style={{ background: `${c.color}22`, color: c.color, border: `1px solid ${c.color}55` }}>
                    {c.label}
                  </span>
                  <span className="text-[11px] text-slate-500">{c.desc}</span>
                </div>
                <span className="text-[11px] text-slate-500">{items.length} zone{items.length !== 1 ? 's' : ''}</span>
              </div>
              <div className="p-3 space-y-2">
                {items.length === 0 ? (
                  <p className="text-[11px] text-slate-500 italic py-2 px-2">No zones — add one to classify resources as {c.label}.</p>
                ) : items.map(z => {
                  const cov = coverage[z.id];
                  return (
                    <div key={z.id} className="flex items-center justify-between gap-3 p-2.5 rounded-lg bg-slate-800/40 border border-slate-700/40">
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-mono text-white truncate">{z.scope_value}</p>
                        <p className="text-[10px] text-slate-500 mt-0.5">
                          {SCOPE_TYPES.find(s => s.key === z.scope_type)?.label || z.scope_type}
                          {z.asserted_by && ` · asserted by ${z.asserted_by}`}
                          {z.asserted_at && ` · ${new Date(z.asserted_at).toLocaleDateString()}`}
                        </p>
                        {z.notes && <p className="text-[10px] text-slate-400 mt-1 italic">{z.notes}</p>}
                      </div>
                      <div className="flex items-center gap-3 flex-shrink-0">
                        <div className="text-right">
                          <p className="text-base font-mono font-bold text-emerald-300">{cov?.resource_count ?? '—'}</p>
                          <p className="text-[9px] uppercase tracking-wider text-slate-500 font-bold">classified</p>
                        </div>
                        <button onClick={() => revoke(z.id)}
                          title="Revoke (soft-delete)"
                          className="px-2 py-1 rounded text-[10px] font-medium text-rose-300 hover:bg-rose-500/10 border border-rose-500/30">
                          Revoke
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      </>)}

      {loading && <p className="text-center text-[11px] text-slate-500">Loading…</p>}

      {/* Add zone modal */}
      {addOpen && (
        <AddZoneModal
          onClose={() => setAddOpen(false)}
          onCreated={() => { setAddOpen(false); refresh(); }}
        />
      )}
    </div>
  );
}

// ─── Add Zone Modal ───

function AddZoneModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [classification, setClassification] = useState<string>('PHI');
  const [scopeType, setScopeType] = useState<string>('resource_group');
  const [scopeValue, setScopeValue] = useState<string>('');
  const [notes, setNotes] = useState<string>('');
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit() {
    if (!scopeValue.trim()) { setErr('Scope value is required'); return; }
    setSaving(true);
    setErr(null);
    try {
      const r = await fetch('/api/data-trust-zones', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          classification,
          scope_type: scopeType,
          scope_value: scopeValue.trim(),
          notes: notes.trim() || null,
        }),
      });
      const d = await r.json();
      if (!r.ok) { setErr(d.error || `Status ${r.status}`); setSaving(false); return; }
      onCreated();
    } catch (e: any) {
      setErr(e.message || 'failed');
      setSaving(false);
    }
  }

  const scopeHint = SCOPE_TYPES.find(s => s.key === scopeType)?.hint;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-slate-900 border border-white/10 rounded-xl p-6 max-w-md w-full mx-4 space-y-4"
        onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-bold text-white">Add Data Trust Zone</h2>

        <div>
          <label className="text-[10px] uppercase tracking-wider font-bold text-slate-400">Classification</label>
          <div className="mt-1.5 grid grid-cols-4 gap-1.5">
            {CLASSES.map(c => (
              <button key={c.key} onClick={() => setClassification(c.key)}
                className="px-2 py-1.5 rounded text-[10px] font-bold uppercase tracking-wider border transition"
                style={{
                  background: classification === c.key ? `${c.color}33` : 'transparent',
                  borderColor: classification === c.key ? c.color : '#334155',
                  color: classification === c.key ? c.color : '#94a3b8',
                }}>
                {c.label}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="text-[10px] uppercase tracking-wider font-bold text-slate-400">Scope Type</label>
          <select value={scopeType} onChange={e => setScopeType(e.target.value)}
            className="mt-1.5 w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm text-white">
            {SCOPE_TYPES.map(s => <option key={s.key} value={s.key}>{s.label}</option>)}
          </select>
        </div>

        <div>
          <label className="text-[10px] uppercase tracking-wider font-bold text-slate-400">Scope Value</label>
          <input value={scopeValue} onChange={e => setScopeValue(e.target.value)}
            className="mt-1.5 w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm text-white font-mono"
            placeholder={scopeHint?.split(' — ')[1]?.split(' — ')[0] || 'value...'} />
          {scopeHint && <p className="text-[10px] text-slate-500 mt-1">{scopeHint}</p>}
        </div>

        <div>
          <label className="text-[10px] uppercase tracking-wider font-bold text-slate-400">Notes (optional)</label>
          <input value={notes} onChange={e => setNotes(e.target.value)}
            className="mt-1.5 w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm text-white"
            placeholder="Why this is classified as such..." />
        </div>

        {err && <div className="rounded-lg bg-rose-500/10 border border-rose-500/30 p-2 text-[11px] text-rose-300">{err}</div>}

        <div className="flex items-center justify-end gap-2 pt-2">
          <button onClick={onClose} className="px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-white">Cancel</button>
          <button onClick={submit} disabled={saving}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-violet-500 hover:bg-violet-400 text-white disabled:opacity-50">
            {saving ? 'Creating…' : 'Create Zone'}
          </button>
        </div>
      </div>
    </div>
  );
}
