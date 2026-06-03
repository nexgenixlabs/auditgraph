import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { ExplainRiskWaterfall } from '../components/argus/ExplainRiskWaterfall';
import { AttackPathInvestigator } from '../components/argus/AttackPathInvestigator';
import { useConnection } from '../contexts/ConnectionContext';

/**
 * Argus — AI Identity Security Analyst (AG-184 EPIC root page).
 *
 * Hosts the layer surfaces shipped so far:
 *   - Layer 5 (AG-189): Explain Why — risk-score waterfall
 *   - Layer 3 (AG-187): Attack Path Investigator — natural-language chain query
 *
 * Layers 1/2/4/6/7/XGRAPH will land in follow-up sessions.
 * Argus is positioned as an analyst, not a chatbot — the chat panel
 * (CopilotPanel) remains the conversational surface; this page is the
 * structured-output home for the layers that benefit from rich UI.
 */

interface AIAgentOption {
  identity_id: string;
  display_name: string;
}

type Tab = 'investigate' | 'explain';

export default function Argus() {
  const [tab, setTab] = useState<Tab>('investigate');
  const [selectedAgent, setSelectedAgent] = useState<string>('');
  const [agentOptions, setAgentOptions] = useState<AIAgentOption[]>([]);
  const [optionsLoading, setOptionsLoading] = useState(false);
  const { withConnection, selectedConnectionId } = useConnection();

  useEffect(() => {
    // Only fetch the agent list when the user is on the Explain tab —
    // saves a request for the default Investigate landing.
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

      {/* Tab strip */}
      <div className="flex gap-2 border-b mb-5" style={{ borderColor: 'var(--border-default)' }}>
        <TabButton
          active={tab === 'investigate'}
          onClick={() => setTab('investigate')}
          label="Investigate Attack Path"
          sublabel="Layer 3 — natural-language chain query"
        />
        <TabButton
          active={tab === 'explain'}
          onClick={() => setTab('explain')}
          label="Explain Risk Score"
          sublabel="Layer 5 — auditor-grade contribution waterfall"
        />
        <div className="ml-auto flex items-center gap-2 pb-2">
          <Link
            to="/copilot-history"
            className="text-[10px] uppercase tracking-wider font-medium hover:underline"
            style={{ color: 'var(--text-tertiary)' }}
            title="Conversational Argus (chat-style) remains in the Copilot panel"
          >
            Open Conversational Argus →
          </Link>
        </div>
      </div>

      {/* Active tab body */}
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

      {/* Footer — which Argus layers are live and which are queued */}
      <div className="mt-8 text-[10px] leading-relaxed" style={{ color: 'var(--text-tertiary)' }}>
        <span className="font-semibold uppercase tracking-wider">Argus layer status:</span>
        {' '}
        <span style={{ color: '#10b981' }}>✓ L3 (Investigate)</span>
        {' · '}
        <span style={{ color: '#10b981' }}>✓ L5 (Explain Why)</span>
        {' · '}
        L1 NL Investigation · L2 Reasoning · L4 Board Advisor · L6 What-If · L7 Storytelling · XGRAPH —
        all queued under AG-184 EPIC.
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
      className={`px-4 py-2 -mb-px border-b-2 transition text-left ${
        active ? 'border-violet-500' : 'border-transparent hover:border-violet-500/30'
      }`}
    >
      <div className={`text-sm font-semibold ${active ? '' : 'opacity-70'}`}
           style={{ color: active ? '#a78bfa' : 'var(--text-secondary)' }}>
        {label}
      </div>
      <div className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
        {sublabel}
      </div>
    </button>
  );
}
