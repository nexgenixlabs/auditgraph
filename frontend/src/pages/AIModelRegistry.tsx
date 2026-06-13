/**
 * AIModelRegistry — Tier 2.2 page
 *
 * Lists every AI model deployed in the tenant + its approval status.
 * Admins can submit for review, approve, reject, or revoke. The auto-
 * classification (baseline / finetune / custom / high) is a hint —
 * the source of truth is the row in ai_model_approvals.
 *
 * Source: GET  /api/ai-security/model-registry
 *         POST /api/ai-security/model-registry/{submit,decide,revoke}
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useToast } from '../components/ToastProvider';
// AG-POLISH-D (2026-06-10)
import { LoadingState } from '../components/LoadingState';

type EffectiveStatus = 'approved' | 'pending_review' | 'rejected' | 'revoked' | 'unverified' | 'expired';

interface ModelRow {
  model_name: string;
  model_format: string | null;
  model_version: string | null;
  deployment_count: number;
  account_count: number;
  agent_count: number;
  max_capacity: number | null;
  first_seen: string | null;
  last_seen: string | null;
  auto_classification: 'baseline' | 'medium' | 'high' | 'custom' | 'finetune';
  approval: {
    id: number | null;
    status: string;
    effective_status: EffectiveStatus;
    risk_classification: string | null;
    requested_by: string | null;
    requested_at: string | null;
    reviewed_by: string | null;
    reviewed_at: string | null;
    justification: string | null;
    review_notes: string | null;
    expires_at: string | null;
  };
}

interface RegistryResponse {
  models: ModelRow[];
  summary: {
    total_models: number;
    total_deployments: number;
    agents_using_models: number;
    by_status: Record<EffectiveStatus, number>;
    by_risk_class: Record<string, number>;
  };
  computed_at: string;
}

const STATUS_STYLE: Record<EffectiveStatus, { text: string; bg: string; border: string }> = {
  approved:       { text: 'text-emerald-300', bg: 'bg-emerald-900/30', border: 'border-emerald-800/50' },
  pending_review: { text: 'text-amber-300',   bg: 'bg-amber-900/30',   border: 'border-amber-800/50'   },
  rejected:       { text: 'text-red-300',     bg: 'bg-red-900/30',     border: 'border-red-800/50'     },
  revoked:        { text: 'text-rose-300',    bg: 'bg-rose-900/30',    border: 'border-rose-800/50'    },
  expired:        { text: 'text-orange-300',  bg: 'bg-orange-900/30',  border: 'border-orange-800/50'  },
  unverified:     { text: 'text-slate-400',   bg: 'bg-slate-800/40',   border: 'border-slate-700/50'   },
};

const RISK_STYLE: Record<string, { text: string }> = {
  baseline:  { text: 'text-emerald-300' },
  medium:    { text: 'text-amber-300'   },
  high:      { text: 'text-orange-300'  },
  custom:    { text: 'text-violet-300'  },
  finetune:  { text: 'text-rose-300'    },
};

export default function AIModelRegistry() {
  const { user } = useAuth();
  const { addToast } = useToast();
  const [data, setData] = useState<RegistryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeRow, setActiveRow] = useState<ModelRow | null>(null);
  const [filter, setFilter] = useState<'all' | EffectiveStatus>('all');

  const canDecide = user?.role === 'admin' || (user as { role?: string })?.role === 'security_admin';

  const load = useCallback(() => {
    setLoading(true);
    fetch('/api/ai-security/model-registry')
      .then(r => r.json())
      .then((d: RegistryResponse) => { setData(d); setLoading(false); })
      .catch((e: Error) => { setError(e.message); setLoading(false); });
  }, []);
  useEffect(() => { load(); }, [load]);

  const filtered = useMemo(() => {
    if (!data) return [];
    if (filter === 'all') return data.models;
    return data.models.filter(m => m.approval.effective_status === filter);
  }, [data, filter]);

  const submit = async (m: ModelRow, justification: string) => {
    const r = await fetch('/api/ai-security/model-registry/submit', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model_name: m.model_name, model_format: m.model_format, model_version: m.model_version,
        justification,
      }),
    });
    if (!r.ok) { addToast(`Submit failed: ${r.status}`, 'error'); return; }
    setActiveRow(null);
    load();
  };

  const decide = async (m: ModelRow, decision: 'approved' | 'rejected', notes: string, expiresAt: string) => {
    const r = await fetch('/api/ai-security/model-registry/decide', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model_name: m.model_name, model_format: m.model_format, model_version: m.model_version,
        decision, review_notes: notes,
        expires_at: expiresAt || null,
      }),
    });
    if (!r.ok) { addToast(`Decision failed: ${r.status}`, 'error'); return; }
    setActiveRow(null);
    load();
  };

  const revokeModel = async (m: ModelRow, notes: string) => {
    if (!window.confirm(`Revoke approval for ${m.model_name}?`)) return;
    const r = await fetch('/api/ai-security/model-registry/revoke', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model_name: m.model_name, model_format: m.model_format, model_version: m.model_version,
        notes,
      }),
    });
    if (!r.ok) { addToast(`Revoke failed: ${r.status}`, 'error'); return; }
    setActiveRow(null);
    load();
  };

  {/* AG-POLISH-D (2026-06-10) */}
  if (loading && !data) {
    return <div className="p-6"><LoadingState message="Loading model registry…" detail="Enumerating Cognitive Services + AI Foundry deployments" /></div>;
  }
  if (error) {
    return <div className="p-6 text-sm text-rose-400">{error}</div>;
  }
  if (!data) return null;

  const s = data.summary;

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">AI Model Registry</h1>
          <p className="text-sm text-slate-400 mt-1 max-w-3xl">
            Every AI model deployed in your tenant + its approval status. Custom and fine-tuned models
            should be approved before production use — they embed customer data or behavior outside
            vendor catalogs. <span className="text-slate-500">Auto-classification is advisory; the
            source of truth is the approval row.</span>
          </p>
        </div>
      </div>

      {/* Summary strip */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <SummaryCard label="Models discovered"      value={s.total_models}                 hint="distinct (name, version)" />
        <SummaryCard label="Deployments"            value={s.total_deployments}            hint="incl. duplicates across accounts" />
        <SummaryCard label="Agents using models"    value={s.agents_using_models}          hint="AI agents tied via Cog Services account" />
        <SummaryCard label="Approved"               value={s.by_status.approved || 0}      hint="green" valueClass="text-emerald-300" />
        <SummaryCard label="Needs attention"        value={(s.by_status.pending_review || 0) + (s.by_status.unverified || 0) + (s.by_status.expired || 0)}
                     hint="pending + unverified + expired"
                     valueClass={(s.by_status.pending_review || 0) + (s.by_status.unverified || 0) + (s.by_status.expired || 0) > 0 ? 'text-amber-300' : 'text-slate-400'} />
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-2">
        <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Filter</span>
        {(['all','approved','pending_review','unverified','rejected','revoked','expired'] as const).map(k => (
          <button key={k}
                  onClick={() => setFilter(k as 'all' | EffectiveStatus)}
                  className={`text-xs px-2 py-1 rounded border transition ${
                    filter === k
                      ? 'border-violet-700 bg-violet-900/30 text-violet-200'
                      : 'border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                  }`}>
            {k === 'all' ? 'All' : k.replace('_',' ')}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="rounded-xl border border-white/5 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-900/60 text-[10px] uppercase tracking-wider text-slate-500">
            <tr>
              <th className="text-left px-3 py-2">Model</th>
              <th className="text-left px-3 py-2">Vendor</th>
              <th className="text-left px-3 py-2">Auto-class</th>
              <th className="text-left px-3 py-2">Status</th>
              <th className="text-right px-3 py-2">Agents</th>
              <th className="text-right px-3 py-2">Deployments</th>
              <th className="text-left px-3 py-2">Reviewed by</th>
              <th className="text-left px-3 py-2">Expires</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {filtered.map(m => {
              const st = STATUS_STYLE[m.approval.effective_status];
              const rs = RISK_STYLE[m.auto_classification] || RISK_STYLE.baseline;
              return (
                <tr key={`${m.model_name}|${m.model_format}|${m.model_version}`}
                    className="border-t border-white/5 hover:bg-slate-900/40 transition">
                  <td className="px-3 py-2 text-slate-200 font-mono text-xs">{m.model_name}</td>
                  <td className="px-3 py-2 text-slate-400 text-xs">{m.model_format || '—'}</td>
                  <td className={`px-3 py-2 text-xs font-semibold ${rs.text}`}>{m.auto_classification}</td>
                  <td className={`px-3 py-2 text-xs`}>
                    <span className={`px-2 py-0.5 rounded border text-[10px] font-bold uppercase ${st.bg} ${st.text} ${st.border}`}>
                      {m.approval.effective_status.replace('_',' ')}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-right text-slate-300 font-mono text-xs">{m.agent_count}</td>
                  <td className="px-3 py-2 text-right text-slate-300 font-mono text-xs">{m.deployment_count}</td>
                  <td className="px-3 py-2 text-slate-400 text-xs">{m.approval.reviewed_by || '—'}</td>
                  <td className="px-3 py-2 text-slate-400 text-xs">{m.approval.expires_at ? m.approval.expires_at.slice(0,10) : '—'}</td>
                  <td className="px-3 py-2 text-right">
                    <button onClick={() => setActiveRow(m)}
                            className="text-xs px-2 py-1 rounded border border-slate-700 text-slate-300 hover:border-violet-600 hover:text-violet-300 transition">
                      Review →
                    </button>
                  </td>
                </tr>
              );
            })}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={9} className="px-3 py-12 text-center">
                  <div className="max-w-md mx-auto">
                    <svg className="w-10 h-10 mx-auto mb-3 text-slate-600" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                    <div className="text-sm font-semibold text-slate-300">No models match this filter</div>
                    <p className="text-xs text-slate-500 mt-1 leading-relaxed">
                      Try clearing the filter, or re-run discovery — the
                      Cognitive Services producer needs a fresh scan to
                      populate <code className="font-mono">azure_ai_model_deployments</code>.
                    </p>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Drawer / Modal */}
      {activeRow && (
        <ReviewModal model={activeRow} canDecide={canDecide}
                     onClose={() => setActiveRow(null)}
                     onSubmit={submit}
                     onDecide={decide}
                     onRevoke={revokeModel} />
      )}
    </div>
  );
}

function SummaryCard({ label, value, hint, valueClass }: { label: string; value: number; hint?: string; valueClass?: string }) {
  return (
    <div className="rounded-xl border border-white/5 bg-slate-900/40 p-3">
      <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500">{label}</p>
      <p className={`text-2xl font-bold font-mono mt-1 ${valueClass || 'text-slate-100'}`}>{value}</p>
      {hint && <p className="text-[10px] text-slate-500 mt-0.5">{hint}</p>}
    </div>
  );
}

function ReviewModal({
  model, canDecide,
  onClose, onSubmit, onDecide, onRevoke,
}: {
  model: ModelRow; canDecide: boolean;
  onClose: () => void;
  onSubmit: (m: ModelRow, justification: string) => void;
  onDecide: (m: ModelRow, decision: 'approved'|'rejected', notes: string, expiresAt: string) => void;
  onRevoke: (m: ModelRow, notes: string) => void;
}) {
  const [justification, setJustification] = useState('');
  const [notes, setNotes] = useState(model.approval.review_notes || '');
  const [expiresAt, setExpiresAt] = useState(model.approval.expires_at?.slice(0,10) || '');
  const st = model.approval.effective_status;
  const canSubmit = st === 'unverified' || st === 'rejected' || st === 'revoked' || st === 'expired';
  const canApprove = st === 'pending_review' && canDecide;
  const canRevoke  = (st === 'approved') && canDecide;

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0f172a] rounded-xl border border-white/10 max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-5 border-b border-white/5">
          <h2 className="text-lg font-bold text-slate-100 font-mono">{model.model_name}</h2>
          <p className="text-xs text-slate-400 mt-1">
            {model.model_format || 'unknown vendor'} · v{model.model_version || '—'} ·
            <span className="ml-1 text-violet-300">{model.auto_classification}</span> ·
            <span className="ml-1">{model.deployment_count} deployment(s), {model.agent_count} agent(s)</span>
          </p>
        </div>

        <div className="p-5 space-y-4 text-sm">
          {/* Current status */}
          <div>
            <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1">Current status</p>
            <span className={`px-2 py-1 rounded border text-xs font-bold uppercase ${STATUS_STYLE[st].bg} ${STATUS_STYLE[st].text} ${STATUS_STYLE[st].border}`}>
              {st.replace('_',' ')}
            </span>
            {model.approval.expires_at && (
              <span className="ml-3 text-xs text-slate-400">expires {model.approval.expires_at.slice(0,10)}</span>
            )}
          </div>

          {/* History */}
          {model.approval.requested_by && (
            <div className="text-xs text-slate-400 space-y-1">
              <p><span className="text-slate-500">Requested:</span> {model.approval.requested_by} · {model.approval.requested_at?.slice(0,19).replace('T',' ')}</p>
              {model.approval.justification && <p className="pl-3 italic text-slate-400">"{model.approval.justification}"</p>}
              {model.approval.reviewed_by && (
                <p><span className="text-slate-500">Reviewed:</span> {model.approval.reviewed_by} · {model.approval.reviewed_at?.slice(0,19).replace('T',' ')}</p>
              )}
              {model.approval.review_notes && <p className="pl-3 italic text-slate-400">"{model.approval.review_notes}"</p>}
            </div>
          )}

          {/* Actions */}
          {canSubmit && (
            <div>
              <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Justification</label>
              <textarea value={justification} onChange={e => setJustification(e.target.value)}
                        placeholder="What is this model used for? Who reviewed the prompts / training data?"
                        className="mt-1 w-full bg-slate-900/60 border border-slate-700 rounded p-2 text-xs text-slate-200 font-mono resize-none"
                        rows={3} />
              <button onClick={() => onSubmit(model, justification)}
                      disabled={justification.trim().length < 5}
                      className="mt-2 w-full bg-amber-700 hover:bg-amber-600 disabled:bg-slate-700 disabled:opacity-50 text-white text-xs font-semibold py-2 rounded transition">
                Submit for Review
              </button>
            </div>
          )}

          {canApprove && (
            <div className="space-y-2 pt-2 border-t border-white/5">
              <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Reviewer notes</label>
              <textarea value={notes} onChange={e => setNotes(e.target.value)}
                        placeholder="Reasoning, restrictions, data governance approvals…"
                        className="w-full bg-slate-900/60 border border-slate-700 rounded p-2 text-xs text-slate-200 font-mono resize-none"
                        rows={2} />
              <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Expires (optional)</label>
              <input type="date" value={expiresAt} onChange={e => setExpiresAt(e.target.value)}
                     className="w-full bg-slate-900/60 border border-slate-700 rounded p-2 text-xs text-slate-200" />
              <div className="grid grid-cols-2 gap-2 pt-1">
                <button onClick={() => onDecide(model, 'rejected', notes, '')}
                        className="bg-rose-800 hover:bg-rose-700 text-white text-xs font-semibold py-2 rounded transition">
                  Reject
                </button>
                <button onClick={() => onDecide(model, 'approved', notes, expiresAt ? `${expiresAt}T00:00:00Z` : '')}
                        className="bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-semibold py-2 rounded transition">
                  Approve
                </button>
              </div>
            </div>
          )}

          {canRevoke && (
            <div className="pt-2 border-t border-white/5">
              <button onClick={() => onRevoke(model, notes)}
                      className="w-full bg-rose-800 hover:bg-rose-700 text-white text-xs font-semibold py-2 rounded transition">
                Revoke approval
              </button>
            </div>
          )}
        </div>

        <div className="p-3 border-t border-white/5 flex justify-end">
          <button onClick={onClose} className="text-xs text-slate-400 hover:text-slate-200 px-3 py-1">Close</button>
        </div>
      </div>
    </div>
  );
}
