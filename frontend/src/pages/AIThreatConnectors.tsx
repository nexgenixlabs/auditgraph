/**
 * AIThreatConnectors — Tier 4 page
 *
 * Partner connector status + signal feed. AuditGraph doesn't detect
 * prompt injection / jailbreaks — partners do. This page shows which
 * partners are wired, how many signals have landed, and the recent
 * signal feed (with full evidence).
 *
 * Sources:
 *   GET /api/ai-security/threat-connectors
 *   POST /api/ai-security/threat-connectors  (register/update)
 *   GET /api/ai-security/threat-signals
 *   POST /api/ai-security/threat-signals?vendor=<v>  (simulate ingest)
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface Connector {
  vendor: string;
  display_name: string;
  is_enabled: boolean;
  last_signal_at: string | null;
  total_signals: number;
  config: Record<string, unknown>;
}

interface Signal {
  id: number;
  identity_id: string | null;
  vendor: string;
  signal_type: string;
  severity: Severity;
  score: number | null;
  title: string;
  description: string | null;
  evidence: Record<string, unknown>;
  external_id: string | null;
  occurred_at: string | null;
  received_at: string | null;
  status: string;
}

const SEV_STYLE: Record<Severity, { text: string; bg: string; border: string; dot: string }> = {
  critical: { text: 'text-red-300',     bg: 'bg-red-900/30',     border: 'border-red-800/50',     dot: 'bg-red-400'     },
  high:     { text: 'text-orange-300',  bg: 'bg-orange-900/30',  border: 'border-orange-800/50',  dot: 'bg-orange-400'  },
  medium:   { text: 'text-amber-300',   bg: 'bg-amber-900/30',   border: 'border-amber-800/50',   dot: 'bg-amber-400'   },
  low:      { text: 'text-emerald-300', bg: 'bg-emerald-900/30', border: 'border-emerald-800/50', dot: 'bg-emerald-400' },
  info:     { text: 'text-slate-400',   bg: 'bg-slate-800/30',   border: 'border-slate-700/50',   dot: 'bg-slate-500'   },
};

const VENDOR_LABEL: Record<string, string> = {
  azure_content_filter: 'Azure Content Filter',
  bedrock_guardrails:   'AWS Bedrock Guardrails',
  lakera_guard:         'Lakera Guard',
  openai_moderation:    'OpenAI Moderation',
  nemo_guardrails:      'NVIDIA NeMo Guardrails',
  custom:               'Custom',
};

export default function AIThreatConnectors() {
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [supported, setSupported] = useState<string[]>([]);
  const [signals, setSignals] = useState<Signal[]>([]);
  const [summary, setSummary] = useState<{ by_severity: Record<Severity, number>; by_vendor: Record<string, number> } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterVendor, setFilterVendor] = useState<string>('');
  const [filterSeverity, setFilterSeverity] = useState<Severity | ''>('');
  const [activeSignal, setActiveSignal] = useState<Signal | null>(null);
  const [registerOpen, setRegisterOpen] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    const params = new URLSearchParams();
    if (filterVendor)   params.set('vendor',   filterVendor);
    if (filterSeverity) params.set('severity', filterSeverity);
    Promise.all([
      fetch('/api/ai-security/threat-connectors').then(r => r.json()),
      fetch(`/api/ai-security/threat-signals?${params.toString()}`).then(r => r.json()),
    ]).then(([c, s]) => {
      setConnectors(c.connectors || []);
      setSupported(c.supported || []);
      setSignals(s.signals || []);
      setSummary({ by_severity: s.by_severity, by_vendor: s.by_vendor });
      setLoading(false);
    }).catch((e: Error) => { setError(e.message); setLoading(false); });
  }, [filterVendor, filterSeverity]);

  useEffect(() => { load(); }, [load]);

  const registerConnector = async (vendor: string, displayName: string) => {
    const r = await fetch('/api/ai-security/threat-connectors', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vendor, display_name: displayName, is_enabled: true }),
    });
    if (!r.ok) { alert(`Register failed: ${r.status}`); return; }
    setRegisterOpen(null);
    load();
  };

  const totalSignals = useMemo(() =>
    connectors.reduce((s, c) => s + c.total_signals, 0)
  , [connectors]);

  if (loading && connectors.length === 0) {
    return <div className="p-6 text-sm text-slate-400">Loading threat connectors…</div>;
  }
  if (error) return <div className="p-6 text-sm text-rose-400">{error}</div>;

  const unregisteredVendors = supported.filter(
    v => !connectors.some(c => c.vendor === v)
  );

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Threat Source Connectors</h1>
        <p className="text-sm text-slate-400 max-w-3xl mt-1">
          AuditGraph doesn't detect prompt injection / jailbreaks — partners do.
          This page wires partner signals into AuditGraph's Findings catalog and
          Abuse Scenarios. Add a connector, then point the partner's webhook at{' '}
          <span className="font-mono text-violet-300">/api/ai-security/threat-signals?vendor=&lt;v&gt;</span>.
        </p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <SummaryCard label="Total signals (rolling)" value={totalSignals} hint="across all connectors" />
        <SummaryCard label="Connectors enabled" value={connectors.filter(c => c.is_enabled).length} />
        <SummaryCard label="Critical (recent)" value={summary?.by_severity.critical || 0} valueClass="text-red-300" />
        <SummaryCard label="High (recent)" value={summary?.by_severity.high || 0} valueClass="text-orange-300" />
      </div>

      {/* Connector grid */}
      <div>
        <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500 mb-2">Connected partners</p>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {connectors.map(c => (
            <div key={c.vendor} className="rounded-xl border border-white/5 bg-slate-900/40 p-3">
              <div className="flex items-start justify-between gap-2 mb-2">
                <div>
                  <p className="text-sm font-semibold text-slate-100">{c.display_name}</p>
                  <p className="text-[10px] text-slate-500 font-mono mt-0.5">{c.vendor}</p>
                </div>
                <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                  c.is_enabled ? 'bg-emerald-900/30 text-emerald-300 border border-emerald-800/40'
                              : 'bg-slate-800 text-slate-500 border border-slate-700'
                }`}>
                  {c.is_enabled ? 'enabled' : 'disabled'}
                </span>
              </div>
              <div className="text-xs text-slate-400 space-y-0.5">
                <p><span className="text-slate-500">Total signals:</span> <span className="font-mono text-slate-200">{c.total_signals.toLocaleString()}</span></p>
                <p><span className="text-slate-500">Last signal:</span> <span className="font-mono text-slate-300">{c.last_signal_at ? c.last_signal_at.slice(0,19).replace('T',' ') : '—'}</span></p>
              </div>
            </div>
          ))}
          {unregisteredVendors.map(v => (
            <div key={v} className="rounded-xl border border-dashed border-slate-700/50 bg-slate-900/20 p-3 flex flex-col">
              <p className="text-sm font-semibold text-slate-400">{VENDOR_LABEL[v] || v}</p>
              <p className="text-[10px] text-slate-500 font-mono mt-0.5">{v}</p>
              <button onClick={() => setRegisterOpen(v)}
                      className="mt-3 text-xs px-2 py-1 rounded border border-violet-700 text-violet-200 hover:bg-violet-900/30 transition">
                Add connector →
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-2 flex-wrap pt-2">
        <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Vendor</span>
        <button onClick={() => setFilterVendor('')}
                className={`text-xs px-2 py-1 rounded border transition ${
                  !filterVendor ? 'border-violet-700 bg-violet-900/30 text-violet-200'
                                : 'border-slate-800 text-slate-400 hover:border-slate-700'
                }`}>all</button>
        {connectors.map(c => (
          <button key={c.vendor} onClick={() => setFilterVendor(c.vendor)}
                  className={`text-xs px-2 py-1 rounded border transition ${
                    filterVendor === c.vendor
                      ? 'border-violet-700 bg-violet-900/30 text-violet-200'
                      : 'border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}>
            {c.vendor}
          </button>
        ))}

        <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold ml-3">Severity</span>
        {(['', 'critical','high','medium','low'] as const).map(k => (
          <button key={k || 'all'} onClick={() => setFilterSeverity(k as Severity | '')}
                  className={`text-xs px-2 py-1 rounded border transition ${
                    filterSeverity === k
                      ? 'border-violet-700 bg-violet-900/30 text-violet-200'
                      : 'border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}>
            {k || 'all'}
          </button>
        ))}
      </div>

      {/* Signals table */}
      <div className="rounded-xl border border-white/5 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-900/60 text-[10px] uppercase tracking-wider text-slate-500">
            <tr>
              <th className="text-left px-3 py-2 w-24">Severity</th>
              <th className="text-left px-3 py-2 w-32">Vendor</th>
              <th className="text-left px-3 py-2 w-28">Signal type</th>
              <th className="text-left px-3 py-2">Title</th>
              <th className="text-left px-3 py-2">Agent</th>
              <th className="text-right px-3 py-2 w-24">Received</th>
              <th className="px-3 py-2 w-20" />
            </tr>
          </thead>
          <tbody>
            {signals.map(s => {
              const sev = SEV_STYLE[s.severity];
              return (
                <tr key={s.id}
                    className="border-t border-white/5 hover:bg-slate-900/40 transition cursor-pointer"
                    onClick={() => setActiveSignal(s)}>
                  <td className="px-3 py-2 text-xs">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border font-bold uppercase ${sev.bg} ${sev.text} ${sev.border}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />
                      {s.severity}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-slate-400 font-mono text-[10px]">{s.vendor}</td>
                  <td className="px-3 py-2 text-slate-300 font-mono text-[11px]">{s.signal_type}</td>
                  <td className="px-3 py-2 text-slate-200 text-xs">{s.title}</td>
                  <td className="px-3 py-2 text-slate-400 font-mono text-[11px] truncate max-w-[240px]">
                    {s.identity_id || '—'}
                  </td>
                  <td className="px-3 py-2 text-right text-slate-500 text-[10px]">
                    {s.received_at ? s.received_at.slice(0,19).replace('T',' ') : '—'}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <span className="text-xs text-violet-300">Open →</span>
                  </td>
                </tr>
              );
            })}
            {signals.length === 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-8 text-center text-slate-500 text-sm">
                  No signals match these filters. Wire a partner webhook to{' '}
                  <span className="font-mono text-violet-300">/api/ai-security/threat-signals</span>{' '}
                  to start receiving.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {activeSignal && (
        <SignalDetailModal signal={activeSignal} onClose={() => setActiveSignal(null)} />
      )}

      {registerOpen && (
        <RegisterModal vendor={registerOpen}
                       defaultName={VENDOR_LABEL[registerOpen] || registerOpen}
                       onClose={() => setRegisterOpen(null)}
                       onRegister={registerConnector} />
      )}
    </div>
  );
}

function SummaryCard({ label, value, valueClass, hint }:
  { label: string; value: number; valueClass?: string; hint?: string }) {
  return (
    <div className="rounded-xl border border-white/5 bg-slate-900/40 p-3">
      <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500">{label}</p>
      <p className={`text-2xl font-bold font-mono mt-1 ${valueClass || 'text-slate-100'}`}>{value.toLocaleString()}</p>
      {hint && <p className="text-[10px] text-slate-500 mt-0.5">{hint}</p>}
    </div>
  );
}

function SignalDetailModal({ signal, onClose }: { signal: Signal; onClose: () => void }) {
  const sev = SEV_STYLE[signal.severity];
  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0f172a] rounded-xl border border-white/10 max-w-3xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-5 border-b border-white/5">
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <span className={`text-xs font-bold px-2 py-0.5 rounded uppercase ${sev.bg} ${sev.text} ${sev.border} border`}>
              {signal.severity}
            </span>
            <span className="text-xs text-slate-400 font-mono">{signal.vendor}</span>
            <span className="text-xs text-slate-500">·</span>
            <span className="text-xs text-slate-400 font-mono">{signal.signal_type}</span>
            {signal.score != null && (
              <span className="text-xs text-amber-300 font-mono">score {signal.score.toFixed(3)}</span>
            )}
          </div>
          <h2 className="text-base font-bold text-slate-100">{signal.title}</h2>
          {signal.description && <p className="text-xs text-slate-400 mt-1">{signal.description}</p>}
        </div>

        <div className="p-5 space-y-3 text-sm">
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-slate-400">
            <span><span className="text-slate-500">Agent:</span> <span className="font-mono">{signal.identity_id || '—'}</span></span>
            <span><span className="text-slate-500">Status:</span> {signal.status}</span>
            <span><span className="text-slate-500">Occurred:</span> {signal.occurred_at?.slice(0,19).replace('T',' ') || '—'}</span>
            <span><span className="text-slate-500">Received:</span> {signal.received_at?.slice(0,19).replace('T',' ') || '—'}</span>
            {signal.external_id && (
              <span className="col-span-2"><span className="text-slate-500">External ID:</span> <span className="font-mono">{signal.external_id}</span></span>
            )}
          </div>

          <div>
            <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1">Evidence</p>
            <pre className="text-[10px] text-slate-300 font-mono bg-slate-900/60 border border-white/5 rounded p-2 overflow-x-auto">
              {JSON.stringify(signal.evidence, null, 2)}
            </pre>
          </div>
        </div>

        <div className="p-3 border-t border-white/5 flex justify-end">
          <button onClick={onClose} className="text-xs text-slate-400 hover:text-slate-200 px-3 py-1">Close</button>
        </div>
      </div>
    </div>
  );
}

function RegisterModal({ vendor, defaultName, onClose, onRegister }: {
  vendor: string; defaultName: string;
  onClose: () => void;
  onRegister: (vendor: string, displayName: string) => void;
}) {
  const [name, setName] = useState(defaultName);
  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0f172a] rounded-xl border border-white/10 max-w-md w-full">
        <div className="p-5 border-b border-white/5">
          <h2 className="text-base font-bold text-slate-100">Register connector</h2>
          <p className="text-xs text-slate-400 mt-1 font-mono">{vendor}</p>
        </div>
        <div className="p-5 space-y-3">
          <div>
            <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Display name</label>
            <input type="text" value={name} onChange={e => setName(e.target.value)}
                   className="mt-1 w-full bg-slate-900/60 border border-slate-700 rounded p-2 text-sm text-slate-200" />
          </div>
          <p className="text-xs text-slate-500">
            After registering, point the partner's webhook at{' '}
            <span className="font-mono text-violet-300">POST /api/ai-security/threat-signals?vendor={vendor}</span>.
          </p>
        </div>
        <div className="p-3 border-t border-white/5 flex justify-end gap-2">
          <button onClick={onClose} className="text-xs text-slate-400 hover:text-slate-200 px-3 py-1">Cancel</button>
          <button onClick={() => onRegister(vendor, name)}
                  className="text-xs px-3 py-1 rounded bg-violet-700 hover:bg-violet-600 text-white font-semibold">
            Register
          </button>
        </div>
      </div>
    </div>
  );
}
