/**
 * AIFindings — Tier 2.3 page
 *
 * Unified AI-specific findings stream — all detectors emit here so
 * triage is one place. Statuses: open → acknowledged → suppressed →
 * resolved.
 *
 * Source: GET /api/ai-security/findings, POST /api/ai-security/findings/recompose,
 *         PATCH /api/ai-security/findings/<id>/status
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useToast } from '../components/ToastProvider';
// AG-POLISH-D (2026-06-10)
import { LoadingState } from '../components/LoadingState';

type Severity = 'critical' | 'high' | 'medium' | 'low';
type Status = 'open' | 'acknowledged' | 'suppressed' | 'resolved';

interface Finding {
  finding_id: string;
  entity_type: string;
  entity_id: string;
  finding_type: string;
  severity: Severity;
  risk_score: number;
  title: string;
  description: string;
  recommended_fix: string | null;
  status: Status;
  metadata: Record<string, unknown>;
  first_detected_at: string | null;
  last_detected_at: string | null;
  occurrence_count: number;
}

interface FindingsResponse {
  findings: Finding[];
  summary: {
    total: number;
    by_severity: Record<Severity, number>;
    by_type: Record<string, number>;
    by_status: Record<Status, number>;
  };
}

const SEV_STYLE: Record<Severity, { text: string; bg: string; border: string; dot: string; rank: number }> = {
  critical: { text: 'text-red-300',     bg: 'bg-red-900/30',     border: 'border-red-800/50',     dot: 'bg-red-400',     rank: 1 },
  high:     { text: 'text-orange-300',  bg: 'bg-orange-900/30',  border: 'border-orange-800/50',  dot: 'bg-orange-400',  rank: 2 },
  medium:   { text: 'text-amber-300',   bg: 'bg-amber-900/30',   border: 'border-amber-800/50',   dot: 'bg-amber-400',   rank: 3 },
  low:      { text: 'text-emerald-300', bg: 'bg-emerald-900/30', border: 'border-emerald-800/50', dot: 'bg-emerald-400', rank: 4 },
};

const STATUS_STYLE: Record<Status, { text: string; bg: string; border: string }> = {
  open:         { text: 'text-amber-300',   bg: 'bg-amber-900/30',   border: 'border-amber-800/50' },
  acknowledged: { text: 'text-blue-300',    bg: 'bg-blue-900/30',    border: 'border-blue-800/50'  },
  suppressed:   { text: 'text-slate-400',   bg: 'bg-slate-800/40',   border: 'border-slate-700/50' },
  resolved:     { text: 'text-emerald-300', bg: 'bg-emerald-900/30', border: 'border-emerald-800/50' },
};

export default function AIFindings() {
  const { addToast } = useToast();
  const [data, setData] = useState<FindingsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterSev, setFilterSev] = useState<Severity | 'all'>('all');
  const [filterStatus, setFilterStatus] = useState<Status | 'all'>('open');
  const [recomposing, setRecomposing] = useState(false);
  const [activeFinding, setActiveFinding] = useState<Finding | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    fetch('/api/ai-security/findings?limit=500')
      .then(r => r.json())
      .then((d: FindingsResponse) => { setData(d); setLoading(false); })
      .catch((e: Error) => { setError(e.message); setLoading(false); });
  }, []);
  useEffect(() => { load(); }, [load]);

  const recompose = async () => {
    setRecomposing(true);
    try {
      const r = await fetch('/api/ai-security/findings/recompose', { method: 'POST' });
      if (!r.ok) throw new Error(`Recompose failed: ${r.status}`);
      load();
    } catch (e) {
      addToast(e instanceof Error ? e.message : 'Recompose failed', 'error');
    } finally {
      setRecomposing(false);
    }
  };

  const updateStatus = async (f: Finding, newStatus: Status) => {
    const r = await fetch(`/api/ai-security/findings/${f.finding_id}/status`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus }),
    });
    if (!r.ok) { addToast(`Status update failed: ${r.status}`, 'error'); return; }
    setActiveFinding(null);
    load();
  };

  const filtered = useMemo(() => {
    if (!data) return [];
    return data.findings
      .filter(f => filterSev === 'all' || f.severity === filterSev)
      .filter(f => filterStatus === 'all' || f.status === filterStatus)
      .sort((a, b) => SEV_STYLE[a.severity].rank - SEV_STYLE[b.severity].rank);
  }, [data, filterSev, filterStatus]);

  {/* AG-POLISH-D (2026-06-10) */}
  if (loading && !data) {
    return <div className="p-6"><LoadingState message="Loading AI findings…" detail="Aggregating detectors across all AI workload signals" /></div>;
  }
  if (error) return <div className="p-6 text-sm text-rose-400">{error}</div>;
  if (!data) return null;

  const s = data.summary;
  const openCount = s.by_status.open || 0;

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">AI Findings</h1>
          <p className="text-sm text-slate-400 mt-1 max-w-3xl">
            One unified surface for AI-specific risk findings — composed from
            ownership, privilege, data-reachability, network, model-registry,
            and credential detectors.
          </p>
        </div>
        <button onClick={recompose}
                disabled={recomposing}
                className="text-xs font-semibold px-3 py-2 rounded border border-violet-700 text-violet-200 hover:bg-violet-900/30 transition disabled:opacity-50">
          {recomposing ? 'Recomposing…' : 'Recompose findings'}
        </button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <SummaryCard label="Total findings"  value={s.total}                          />
        <SummaryCard label="Critical"        value={s.by_severity.critical || 0} valueClass="text-red-300" />
        <SummaryCard label="High"            value={s.by_severity.high || 0}     valueClass="text-orange-300" />
        <SummaryCard label="Open"            value={openCount}                   valueClass="text-amber-300" />
        <SummaryCard label="Distinct types"  value={Object.keys(s.by_type).length} />
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-3 flex-wrap">
        <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Severity</span>
        {(['all','critical','high','medium','low'] as const).map(k => (
          <button key={k} onClick={() => setFilterSev(k)}
                  className={`text-xs px-2 py-1 rounded border transition ${
                    filterSev === k
                      ? 'border-violet-700 bg-violet-900/30 text-violet-200'
                      : 'border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                  }`}>{k}</button>
        ))}
        <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold ml-3">Status</span>
        {(['all','open','acknowledged','suppressed','resolved'] as const).map(k => (
          <button key={k} onClick={() => setFilterStatus(k)}
                  className={`text-xs px-2 py-1 rounded border transition ${
                    filterStatus === k
                      ? 'border-violet-700 bg-violet-900/30 text-violet-200'
                      : 'border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                  }`}>{k}</button>
        ))}
      </div>

      {/* Findings table */}
      <div className="rounded-xl border border-white/5 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-900/60 text-[10px] uppercase tracking-wider text-slate-500">
            <tr>
              <th className="text-left px-3 py-2 w-24">Severity</th>
              <th className="text-left px-3 py-2">Title</th>
              <th className="text-left px-3 py-2">Entity</th>
              <th className="text-left px-3 py-2 w-28">Type</th>
              <th className="text-left px-3 py-2 w-28">Status</th>
              <th className="text-right px-3 py-2 w-24">Detected</th>
              <th className="px-3 py-2 w-24" />
            </tr>
          </thead>
          <tbody>
            {filtered.map(f => {
              const sev = SEV_STYLE[f.severity];
              const st  = STATUS_STYLE[f.status];
              return (
                <tr key={f.finding_id}
                    className="border-t border-white/5 hover:bg-slate-900/40 transition cursor-pointer"
                    onClick={() => setActiveFinding(f)}>
                  <td className={`px-3 py-2 text-xs`}>
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border font-bold uppercase ${sev.bg} ${sev.text} ${sev.border}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-slate-200 text-xs">{f.title}</td>
                  <td className="px-3 py-2 text-slate-400 font-mono text-[11px] truncate max-w-[260px]">
                    {f.entity_id}
                  </td>
                  <td className="px-3 py-2 text-slate-500 font-mono text-[10px]">{f.finding_type.replace('ai_','')}</td>
                  <td className="px-3 py-2 text-xs">
                    <span className={`px-2 py-0.5 rounded border text-[10px] font-bold uppercase ${st.bg} ${st.text} ${st.border}`}>
                      {f.status}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-right text-slate-500 text-[10px]">
                    ×{f.occurrence_count}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <span className="text-xs text-violet-300">Review →</span>
                  </td>
                </tr>
              );
            })}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-8 text-center text-slate-500 text-sm">
                  No findings match these filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Detail drawer */}
      {activeFinding && (
        <FindingDetailModal finding={activeFinding}
                            onClose={() => setActiveFinding(null)}
                            onUpdateStatus={updateStatus} />
      )}
    </div>
  );
}

function SummaryCard({ label, value, valueClass }: { label: string; value: number; valueClass?: string }) {
  return (
    <div className="rounded-xl border border-white/5 bg-slate-900/40 p-3">
      <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500">{label}</p>
      <p className={`text-2xl font-bold font-mono mt-1 ${valueClass || 'text-slate-100'}`}>{value}</p>
    </div>
  );
}

function FindingDetailModal({
  finding, onClose, onUpdateStatus,
}: {
  finding: Finding;
  onClose: () => void;
  onUpdateStatus: (f: Finding, status: Status) => void;
}) {
  const sev = SEV_STYLE[finding.severity];

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0f172a] rounded-xl border border-white/10 max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-5 border-b border-white/5">
          <div className="flex items-center gap-3 mb-2">
            <span className={`px-2 py-0.5 rounded border text-xs font-bold uppercase ${sev.bg} ${sev.text} ${sev.border}`}>
              {finding.severity}
            </span>
            <span className="text-xs text-slate-500 font-mono">{finding.finding_type}</span>
          </div>
          <h2 className="text-lg font-bold text-slate-100">{finding.title}</h2>
          <p className="text-xs text-slate-400 mt-1 font-mono">{finding.entity_id}</p>
        </div>

        <div className="p-5 space-y-4 text-sm">
          <div>
            <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1">Description</p>
            <p className="text-slate-300 leading-relaxed">{finding.description}</p>
          </div>

          {finding.recommended_fix && (
            <div className="rounded bg-violet-900/20 border border-violet-800/40 p-3">
              <p className="text-[10px] uppercase tracking-wider text-violet-400 font-semibold mb-1">Recommended fix</p>
              <p className="text-violet-200 text-xs leading-relaxed">{finding.recommended_fix}</p>
            </div>
          )}

          {finding.metadata && Object.keys(finding.metadata).length > 0 && (
            <details>
              <summary className="cursor-pointer text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Evidence</summary>
              <pre className="mt-2 text-[11px] text-slate-300 font-mono bg-slate-900/60 border border-white/5 rounded p-2 overflow-x-auto">
                {JSON.stringify(finding.metadata, null, 2)}
              </pre>
            </details>
          )}

          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-slate-400">
            <span><span className="text-slate-500">First detected:</span> {finding.first_detected_at?.slice(0,19).replace('T',' ')}</span>
            <span><span className="text-slate-500">Last detected:</span> {finding.last_detected_at?.slice(0,19).replace('T',' ')}</span>
            <span><span className="text-slate-500">Occurrences:</span> {finding.occurrence_count}</span>
            <span><span className="text-slate-500">Risk score:</span> {finding.risk_score}</span>
          </div>

          {/* Status workflow */}
          <div className="pt-3 border-t border-white/5">
            <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-2">Update status</p>
            <div className="grid grid-cols-2 gap-2">
              {finding.status !== 'acknowledged' && (
                <button onClick={() => onUpdateStatus(finding, 'acknowledged')}
                        className="bg-blue-800 hover:bg-blue-700 text-white text-xs font-semibold py-2 rounded transition">
                  Acknowledge
                </button>
              )}
              {finding.status !== 'suppressed' && (
                <button onClick={() => onUpdateStatus(finding, 'suppressed')}
                        className="bg-slate-700 hover:bg-slate-600 text-white text-xs font-semibold py-2 rounded transition">
                  Suppress
                </button>
              )}
              {finding.status !== 'resolved' && (
                <button onClick={() => onUpdateStatus(finding, 'resolved')}
                        className="bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-semibold py-2 rounded transition col-span-2">
                  Mark Resolved
                </button>
              )}
              {finding.status !== 'open' && (
                <button onClick={() => onUpdateStatus(finding, 'open')}
                        className="bg-amber-800 hover:bg-amber-700 text-white text-xs font-semibold py-2 rounded transition col-span-2">
                  Reopen
                </button>
              )}
            </div>
          </div>
        </div>

        <div className="p-3 border-t border-white/5 flex justify-end">
          <button onClick={onClose} className="text-xs text-slate-400 hover:text-slate-200 px-3 py-1">Close</button>
        </div>
      </div>
    </div>
  );
}
