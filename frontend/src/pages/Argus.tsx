import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { ExplainRiskWaterfall } from '../components/argus/ExplainRiskWaterfall';
import { AttackPathInvestigator } from '../components/argus/AttackPathInvestigator';
import NlQuery from '../components/argus/NlQuery';
import ReasonChain from '../components/argus/ReasonChain';
import CisoRecommendations from '../components/argus/CisoRecommendations';
import WhatIfSimulator from '../components/argus/WhatIfSimulator';
import ExecutiveSummary from '../components/argus/ExecutiveSummary';
import WhoCanReach from '../components/argus/WhoCanReach';
import { useConnection } from '../contexts/ConnectionContext';

/**
 * Argus — AI Identity Security Analyst (AG-184 EPIC root page).
 *
 * Hosts the full layer surface:
 *   - Layer 1 (AG-185): NL Query           — plain-English question → identity list
 *   - Layer 2 (AG-186): Reasoning Chain    — 3-5 hop synthesised narrative
 *   - Layer 3 (AG-187): Investigate        — attack-path natural-language query
 *   - Layer 4 (AG-188): CISO Recommendations — top-5 ranked priorities
 *   - Layer 5 (AG-189): Explain Why        — risk-score waterfall
 *   - Layer 6 (AG-190): What-If Simulator  — role-removal projection
 *   - Layer 7 (AG-191): Executive Summary  — board-ready prose
 *   - XGRAPH  (AG-192): Who-Can-Reach      — cross-identity data-class reach
 *
 * Argus is positioned as an analyst, not a chatbot — the chat panel
 * (CopilotPanel) remains the conversational surface; this page is the
 * structured-output home for the layers that benefit from rich UI.
 */

interface AIAgentOption {
  identity_id: string;
  display_name: string;
}

type Tab =
  | 'nlquery'
  | 'reason'
  | 'investigate'
  | 'recommend'
  | 'explain'
  | 'whatif'
  | 'executive'
  | 'whoreaches';

interface TabDef {
  id: Tab;
  label: string;
  sublabel: string;
}

const TABS: TabDef[] = [
  { id: 'nlquery',     label: 'NL Query',           sublabel: 'Layer 1 — plain English to identities' },
  { id: 'reason',      label: 'Reasoning Chain',    sublabel: 'Layer 2 — multi-hop board questions' },
  { id: 'investigate', label: 'Investigate Path',   sublabel: 'Layer 3 — natural-language chain query' },
  { id: 'recommend',   label: 'What to Fix',        sublabel: 'Layer 4 — top remediation priorities' },
  { id: 'explain',     label: 'Explain Risk Score', sublabel: 'Layer 5 — contribution waterfall' },
  { id: 'whatif',      label: 'What-If Simulator',  sublabel: 'Layer 6 — projection without a role' },
  { id: 'executive',   label: 'Executive Summary',  sublabel: 'Layer 7 — board-ready narrative' },
  { id: 'whoreaches',  label: 'Who Can Reach',      sublabel: 'XGRAPH — cross-identity data reach' },
];

export default function Argus() {
  const [tab, setTab] = useState<Tab>('investigate');
  const [selectedAgent, setSelectedAgent] = useState<string>('');
  const [agentOptions, setAgentOptions] = useState<AIAgentOption[]>([]);
  const [optionsLoading, setOptionsLoading] = useState(false);
  const { withConnection, selectedConnectionId } = useConnection();

  useEffect(() => {
    // Only fetch the agent list when the user is on the Explain tab —
    // saves a request for the default Investigate landing. Other tabs
    // that need this list (e.g. What-If) load their own pickers.
    if (tab !== 'explain') return;
    let cancelled = false;
    setOptionsLoading(true);
    fetch(withConnection('/api/ai-agents/enriched?per_page=200&include_possible=false'))
      .then(r => (r.ok ? r.json() : null))
      .then(data => {
        if (cancelled || !data) return;
        // Accept any of the common response shapes.
        const list =
          (data?.identities as AIAgentOption[]) ||
          (data?.agents as AIAgentOption[]) ||
          (data?.items as AIAgentOption[]) ||
          [];
        setAgentOptions(
          list
            .filter(a => a.identity_id && a.display_name)
            .sort((a, b) => a.display_name.localeCompare(b.display_name))
        );
      })
      .catch(() => { /* silent — empty-state UX below covers it */ })
      .finally(() => { if (!cancelled) setOptionsLoading(false); });
    return () => { cancelled = true; };
  }, [tab, withConnection, selectedConnectionId]);

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider font-semibold mb-1"
             style={{ color: 'var(--text-tertiary)' }}>
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md"
                style={{ background: 'rgba(139,92,246,0.18)', color: '#a78bfa', border: '1px solid rgba(139,92,246,0.35)' }}>
            <svg className="w-3 h-3" viewBox="0 0 20 20" fill="currentColor"><path d="M10 1a4.5 4.5 0 0 0-4.5 4.5V8H4a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2h-1.5V5.5A4.5 4.5 0 0 0 10 1Zm-2.5 7V5.5a2.5 2.5 0 0 1 5 0V8h-5Z"/></svg>
            ARGUS
          </span>
          <span>AI Identity Security Analyst</span>
        </div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
          Argus — Reason Across The Identity Graph
        </h1>
        <p className="text-sm mt-1 max-w-3xl" style={{ color: 'var(--text-secondary)' }}>
          Argus reasons across human identities, machine identities, AI agents, OAuth applications,
          permissions, attack paths, and sensitive data exposure to explain risk and answer security
          questions in plain English. <span className="font-semibold">Every answer cites the graph
          evidence it used — no hallucinated findings.</span>
        </p>
      </div>

      {/* Tab strip — horizontal scroll on narrow screens to fit 8 tabs */}
      <div className="flex gap-2 border-b mb-5 overflow-x-auto"
           style={{ borderColor: 'var(--border-default)' }}>
        {TABS.map(t => (
          <TabButton
            key={t.id}
            active={tab === t.id}
            onClick={() => setTab(t.id)}
            label={t.label}
            sublabel={t.sublabel}
          />
        ))}
        <div className="ml-auto flex items-center gap-2 pb-2 flex-shrink-0">
          <Link
            to="/copilot-history"
            className="text-[10px] uppercase tracking-wider font-medium hover:underline whitespace-nowrap"
            style={{ color: 'var(--text-tertiary)' }}
            title="Conversational Argus (chat-style) remains in the Copilot panel"
          >
            Open Conversational Argus →
          </Link>
        </div>
      </div>

      {/* Active tab body */}
      {tab === 'nlquery' && (
        <div className="space-y-4">
          <div className="rounded-xl border p-4"
               style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
            <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
              Type any question and Argus translates it to a structured query
              against the latest discovery. The translator is intent-based — if
              Argus can't parse it, the result tells you which fields it
              skipped instead of pretending it understood.
            </p>
          </div>
          <NlQuery />
        </div>
      )}

      {tab === 'reason' && (
        <div className="space-y-4">
          <div className="rounded-xl border p-4"
               style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
            <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
              Pick a board-level question. Argus runs a 3-5 hop SQL chain against
              the canonical AI / RBAC / posture tables and synthesises a single
              narrative — every claim is backed by an evidence row.
              No LLM. No fabricated counts.
            </p>
          </div>
          <ReasonChain />
        </div>
      )}

      {tab === 'investigate' && (
        <div className="space-y-4">
          <div className="rounded-xl border p-4"
               style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
            <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
              Ask in plain English. Argus matches your query against persisted attack paths
              (computed from architecture, no telemetry needed) and explains exactly what it
              matched. If no persisted path matches and you allow it, Argus can compute one
              live.
            </p>
          </div>
          <AttackPathInvestigator />
        </div>
      )}

      {tab === 'recommend' && (
        <div className="space-y-4">
          <div className="rounded-xl border p-4"
               style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
            <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
              Argus ranks the top remediation priorities for this week by{' '}
              <span className="font-semibold">affected × max blast radius</span>.
              Every priority maps 1:1 to a fired signal in the same catalog the
              risk-score waterfall uses, so the two views never disagree.
            </p>
          </div>
          <CisoRecommendations />
        </div>
      )}

      {tab === 'explain' && (
        <div className="space-y-4">
          <div className="rounded-xl border p-4"
               style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
            <p className="text-xs leading-relaxed mb-3" style={{ color: 'var(--text-secondary)' }}>
              Pick any AI agent. Argus breaks down the risk score into its contributing signals
              with weights, MITRE techniques, and the exact graph evidence behind each contribution
              ("Holds KV Admin on <span className="font-mono">kv-prod-secrets</span> since
              2026-04-12"). Designed for auditors — every number is defensible.
            </p>
            <div className="flex items-center gap-3 flex-wrap">
              <label className="text-[10px] uppercase tracking-wider font-semibold"
                     style={{ color: 'var(--text-tertiary)' }}>
                AI Agent
              </label>
              <select
                value={selectedAgent}
                onChange={e => setSelectedAgent(e.target.value)}
                className="text-xs px-2 py-1.5 rounded border min-w-[280px]"
                style={{
                  borderColor: 'var(--border-default)',
                  backgroundColor: 'var(--bg-raised)',
                  color: 'var(--text-primary)',
                }}
                disabled={optionsLoading || agentOptions.length === 0}
              >
                <option value="">
                  {optionsLoading
                    ? 'Loading agents…'
                    : agentOptions.length === 0
                      ? 'No AI agents discovered'
                      : 'Pick an agent…'}
                </option>
                {agentOptions.map(a => (
                  <option key={a.identity_id} value={a.identity_id}>
                    {a.display_name} — {a.identity_id.slice(0, 8)}…
                  </option>
                ))}
              </select>
              {selectedAgent && (
                <Link
                  to={`/identities/${encodeURIComponent(selectedAgent)}`}
                  className="text-[10px] uppercase tracking-wider font-medium hover:underline"
                  style={{ color: 'var(--text-tertiary)' }}
                >
                  View identity →
                </Link>
              )}
            </div>
          </div>

          {selectedAgent ? (
            <ExplainRiskWaterfall identityId={selectedAgent} />
          ) : (
            <div className="rounded-xl border border-dashed p-6 text-center text-xs"
                 style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-tertiary)' }}>
              Pick an AI agent above to see its risk score decomposed.
            </div>
          )}
        </div>
      )}

      {tab === 'whatif' && (
        <div className="space-y-4">
          <div className="rounded-xl border p-4"
               style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
            <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
              Architectural projection of what a remediation would buy you.
              Argus replays the scoring chain WITHOUT a role you select and
              shows the new score, the signals that would clear, and which
              persisted attack paths the removal would invalidate. The role is
              never deleted — this is a read-only projection.
            </p>
          </div>
          <WhatIfSimulator />
        </div>
      )}

      {tab === 'executive' && (
        <div className="space-y-4">
          <div className="rounded-xl border p-4"
               style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
            <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
              A board-ready one-paragraph narrative pulled from the persisted
              board scorecard snapshot. Argus only renders the trend chip when
              two real snapshots exist in the 30-day window — no fabricated
              deltas.
            </p>
          </div>
          <ExecutiveSummary />
        </div>
      )}

      {tab === 'whoreaches' && (
        <div className="space-y-4">
          <div className="rounded-xl border p-4"
               style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
            <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
              Cross-identity reach analysis. Pick a data classification and
              Argus reports the human / SP / AI / OAuth cohort that can reach
              it, the common path, and the estimated record exposure. When
              counts are unknown Argus reports{' '}
              <span className="font-mono">—</span>, never a fabricated number.
            </p>
          </div>
          <WhoCanReach />
        </div>
      )}

      {/* Footer — all Argus layers live */}
      <div className="mt-8 text-[10px] leading-relaxed" style={{ color: 'var(--text-tertiary)' }}>
        <span className="font-semibold uppercase tracking-wider">Argus layer status:</span>
        {' '}
        <span style={{ color: '#10b981' }}>
          ✓ L1 NL · ✓ L2 Reason · ✓ L3 Investigate · ✓ L4 Recommend · ✓ L5 Explain ·
          ✓ L6 What-If · ✓ L7 Executive · ✓ XGRAPH
        </span>
        {' — '}
        all live under AG-184 EPIC.
      </div>
    </div>
  );
}

function TabButton({
  active, onClick, label, sublabel,
}: { active: boolean; onClick: () => void; label: string; sublabel: string }) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-2 -mb-px border-b-2 transition text-left flex-shrink-0 ${
        active ? 'border-violet-500' : 'border-transparent hover:border-violet-500/30'
      }`}
    >
      <div className={`text-sm font-semibold ${active ? '' : 'opacity-70'}`}
           style={{ color: active ? '#a78bfa' : 'var(--text-secondary)' }}>
        {label}
      </div>
      <div className="text-[10px] whitespace-nowrap" style={{ color: 'var(--text-tertiary)' }}>
        {sublabel}
      </div>
    </button>
  );
}
