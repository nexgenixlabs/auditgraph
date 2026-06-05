/**
 * AIAbuseScenariosCard — Tier 2.1 (headline AI-ISPM feature)
 *
 * For one AI agent, renders the 5 abuse scenarios:
 *   • Prompt Injection Compromise
 *   • Service Principal Credential Theft
 *   • Owner Departure / Orphaning
 *   • Tool Abuse
 *   • Upstream Supply Chain Compromise
 *
 * Each shows: severity badge · headline · blast-radius $ · MITRE refs ·
 * one-line recommendation. Click to expand evidence detail.
 *
 * No fake data — server returns honest empty-state when an agent has no
 * reach (severity=low, $0). We render exactly what came back.
 */
import React, { useEffect, useState } from 'react';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'none';

interface BlastRadius {
  dollar_low: number;
  dollar_mid: number;
  dollar_high: number;
  dollar_low_display: string;
  dollar_mid_display: string;
  dollar_high_display: string;
  records: number;
}

interface Scenario {
  key: string;
  label: string;
  description: string;
  threat_source: string;
  severity: Severity;
  headline: string;
  mitre_techniques: string[];
  mitre_names: string[];
  evidence: Record<string, unknown>;
  blast_radius: BlastRadius;
  recommendation: string;
}

interface AbuseScenariosResponse {
  identity_db_id: number;
  identity_id: string | null;
  display_name: string | null;
  scenarios: Scenario[];
  worst_severity: Severity;
  computed_at: string;
  error?: string;
}

const SEV_STYLE: Record<Severity, { text: string; bg: string; border: string; dot: string; label: string }> = {
  critical: { text: 'text-red-300',     bg: 'bg-red-900/30',     border: 'border-red-800/50',     dot: 'bg-red-400',     label: 'CRITICAL' },
  high:     { text: 'text-orange-300',  bg: 'bg-orange-900/30',  border: 'border-orange-800/50',  dot: 'bg-orange-400',  label: 'HIGH'     },
  medium:   { text: 'text-amber-300',   bg: 'bg-amber-900/30',   border: 'border-amber-800/50',   dot: 'bg-amber-400',   label: 'MEDIUM'   },
  low:      { text: 'text-emerald-300', bg: 'bg-emerald-900/30', border: 'border-emerald-800/50', dot: 'bg-emerald-400', label: 'LOW'      },
  none:     { text: 'text-slate-400',   bg: 'bg-slate-800/30',   border: 'border-slate-700/50',   dot: 'bg-slate-500',   label: '—'        },
};

const SCENARIO_ICON: Record<string, string> = {
  prompt_injection: '⚡', // injection / lightning
  credential_theft: '🔑',
  owner_departure:  '👤',
  tool_abuse:       '🛠',
  supply_chain:     '🔗',
};

interface Props {
  identityId: string;
}

export function AIAbuseScenariosCard({ identityId }: Props) {
  const [data, setData] = useState<AbuseScenariosResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetch(`/api/ai-agents/${encodeURIComponent(identityId)}/abuse-scenarios`)
      .then(async r => {
        if (!r.ok) {
          const body = await r.json().catch(() => null);
          throw new Error((body && body.error) || `Failed (${r.status})`);
        }
        return r.json() as Promise<AbuseScenariosResponse>;
      })
      .then(d => { if (!cancelled) { setData(d); setLoading(false); } })
      .catch(e => { if (!cancelled) { setError(e.message); setLoading(false); } });
    return () => { cancelled = true; };
  }, [identityId]);

  if (loading) {
    return (
      <div className="rounded-xl border border-white/5 bg-[#0f172a] p-4">
        <p className="text-[11px] text-slate-500 uppercase tracking-wider font-semibold">AI Abuse Scenarios</p>
        <div className="mt-3 h-6 w-32 bg-slate-800/60 rounded animate-pulse" />
      </div>
    );
  }
  if (error || !data) {
    return (
      <div className="rounded-xl border border-white/5 bg-[#0f172a] p-4">
        <p className="text-[11px] text-slate-500 uppercase tracking-wider font-semibold">AI Abuse Scenarios</p>
        <p className="mt-2 text-xs text-slate-500">{error || 'No data available.'}</p>
      </div>
    );
  }

  const worst = SEV_STYLE[data.worst_severity] || SEV_STYLE.low;

  return (
    <div className="rounded-xl border border-white/5 bg-[#0f172a] p-4 space-y-3"
         title="For each threat source, AuditGraph computes the identity blast radius IF the threat succeeds. Architecture-derived, no telemetry required.">
      {/* Header */}
      <div className="flex items-center justify-between gap-2">
        <div>
          <p className="text-[11px] text-slate-500 uppercase tracking-wider font-semibold">
            AI Abuse Scenarios
          </p>
          <p className="text-[10px] text-slate-500 mt-0.5">
            What happens if a threat succeeds against this agent
          </p>
        </div>
        <span className={`text-[10px] font-bold px-2 py-1 rounded ${worst.bg} ${worst.text} ${worst.border} border`}>
          WORST: {worst.label}
        </span>
      </div>

      {/* Scenarios list */}
      <div className="space-y-1.5">
        {data.scenarios.map(s => {
          const style = SEV_STYLE[s.severity] || SEV_STYLE.low;
          const isOpen = expanded === s.key;
          const hasBlast = s.blast_radius && s.blast_radius.dollar_mid > 0;
          return (
            <div key={s.key}
                 className={`rounded-lg border ${style.border} ${style.bg} overflow-hidden`}>
              <button
                type="button"
                onClick={() => setExpanded(isOpen ? null : s.key)}
                className="w-full text-left px-3 py-2 hover:brightness-110 transition flex items-center gap-2"
              >
                <span className="text-base flex-shrink-0">{SCENARIO_ICON[s.key] || '•'}</span>
                <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-slate-200 truncate">{s.label}</span>
                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${style.text} ${style.bg}`}>
                      {style.label}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5 truncate" title={s.headline}>
                    {s.headline}
                  </p>
                </div>
                {hasBlast && (
                  <div className="text-right flex-shrink-0">
                    <p className={`text-xs font-bold font-mono ${style.text}`}>
                      {s.blast_radius.dollar_mid_display}
                    </p>
                    <p className="text-[9px] font-mono text-slate-500">
                      {s.blast_radius.dollar_low_display} – {s.blast_radius.dollar_high_display}
                    </p>
                  </div>
                )}
                <svg className={`w-3 h-3 text-slate-500 flex-shrink-0 transition-transform ${isOpen ? 'rotate-180' : ''}`}
                     viewBox="0 0 12 12" fill="none">
                  <path d="M3 4.5L6 7.5L9 4.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </button>

              {isOpen && (
                <div className="px-3 pb-3 pt-1 space-y-2 border-t border-white/5 text-[11px]">
                  <p className="text-slate-400 leading-relaxed">{s.description}</p>

                  {/* MITRE chips */}
                  {s.mitre_techniques && s.mitre_techniques.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {s.mitre_techniques.map((t, i) => (
                        <span key={t}
                              className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-violet-900/30 text-violet-300 border border-violet-800/40"
                              title={s.mitre_names[i] || t}>
                          MITRE {t}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Recommendation */}
                  {s.recommendation && (
                    <div className="rounded bg-slate-800/40 border border-white/5 px-2 py-1.5">
                      <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500 mb-0.5">
                        Recommended fix
                      </p>
                      <p className="text-[11px] text-slate-200 leading-relaxed">{s.recommendation}</p>
                    </div>
                  )}

                  {/* Evidence — render real fields, no hardcoded keys */}
                  {s.evidence && Object.keys(s.evidence).length > 0 && (
                    <details className="text-slate-400">
                      <summary className="cursor-pointer text-[10px] uppercase tracking-wider font-semibold hover:text-slate-200">
                        Evidence
                      </summary>
                      <div className="mt-1.5 grid grid-cols-2 gap-x-3 gap-y-0.5">
                        {Object.entries(s.evidence).map(([k, v]) => (
                          <div key={k} className="contents">
                            <span className="text-[10px] text-slate-500 font-mono">{k}</span>
                            <span className="text-[10px] text-slate-300 font-mono text-right truncate" title={String(v)}>
                              {formatEvidence(v)}
                            </span>
                          </div>
                        ))}
                      </div>
                    </details>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      <p className="text-[10px] text-slate-500 leading-relaxed">
        Architecture-derived · No telemetry required · Threat sources we DON'T detect (prompt injection,
        jailbreak): partner with Azure Content Filter, Bedrock Guardrails, or Lakera.
      </p>
    </div>
  );
}

function formatEvidence(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'boolean') return v ? 'yes' : 'no';
  if (Array.isArray(v)) {
    if (v.length === 0) return '—';
    if (typeof v[0] === 'string') return v.slice(0, 3).join(', ');
    return `${v.length} item(s)`;
  }
  if (typeof v === 'object') return JSON.stringify(v).slice(0, 60);
  const s = String(v);
  return s.length > 30 ? s.slice(0, 30) + '…' : s;
}

export default AIAbuseScenariosCard;
