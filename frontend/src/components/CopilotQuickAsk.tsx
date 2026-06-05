/**
 * CopilotQuickAsk — front-and-center AI Copilot surface (AG-Hero-3).
 *
 * Per founder feedback 2026-05-30: "AI Copilot is buried but is the
 * differentiator." This component pulls the Copilot out of the slide-out
 * drawer into a prominent prompt bar + 6 pre-built quick-ask chips that
 * sit at the top of the Executive Posture (CISO landing) page.
 *
 * Each chip opens the existing CopilotPanel with an initialQuestion. The
 * Copilot service already exists (Phase 79); this is presentation only.
 *
 * Design language: matches Wiz / Cortex CIQ / Snyk Aladdin — premium
 * gradient bar with sparkle iconography. The chips telegraph what kinds
 * of questions the Copilot can answer (so users don't have to guess).
 */
import React, { useState } from 'react';
import { useCopilot } from '../contexts/CopilotContext';

/** Curated quick-ask prompts. Tuned for CISO triage value per session. */
const QUICK_ASKS: Array<{ label: string; question: string; icon: string }> = [
  {
    label: 'Biggest risk right now',
    question: 'What is my biggest identity risk right now? Show the top 3 with one-line explanations and proposed fixes.',
    icon: 'M13 10V3L4 14h7v7l9-11h-7z',
  },
  {
    label: 'Production secrets access',
    question: 'Show me every identity that can access production Key Vault secrets, ranked by privilege. Include credentials and last activity.',
    icon: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z',
  },
  {
    label: 'Dormant admins to disable',
    question: 'Which privileged identities are dormant (no activity 90+ days) and should be disabled today? Order by risk.',
    icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z',
  },
  {
    label: 'SOC 2 CC6 evidence',
    question: 'Generate an evidence summary for SOC 2 Common Criteria CC6 (Logical Access). List each control, the identities mapped to it, and where compliance is at risk.',
    icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z',
  },
  {
    label: 'vs. industry peers',
    question: 'How does my identity posture compare to peers in my industry? Highlight where I am above and below median, with recommendations.',
    icon: 'M3 3v18h18M7 14l4-4 4 4 6-6',
  },
  {
    label: 'What changed this week',
    question: 'What changed in my identity environment in the last 7 days that matters? Show new privileged identities, drift events, anomalies, and resolved items.',
    icon: 'M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15',
  },
];

interface CopilotQuickAskProps {
  /** Optional context — e.g. when surfaced on identity detail, prefill the
   *  "this identity" perspective so quick-asks scope to the open record. */
  contextLabel?: string;
  contextId?: string;
  /** Compact mode: 3 chips instead of 6, tighter layout — for sub-pages. */
  compact?: boolean;
}

export function CopilotQuickAsk({ contextLabel, contextId, compact = false }: CopilotQuickAskProps) {
  const { openCopilot } = useCopilot();
  const [inputValue, setInputValue] = useState('');

  const handleSubmit = (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!inputValue.trim()) return;
    openCopilot({
      initialQuestion: inputValue.trim(),
      contextLabel,
      contextId,
    });
    setInputValue('');
  };

  const chips = compact ? QUICK_ASKS.slice(0, 3) : QUICK_ASKS;

  return (
    <div
      className="rounded-xl p-4 mb-4 relative overflow-hidden"
      style={{
        background:
          'linear-gradient(135deg, rgba(99, 102, 241, 0.08) 0%, rgba(168, 85, 247, 0.08) 50%, rgba(236, 72, 153, 0.06) 100%)',
        border: '1px solid var(--border-indigo, rgba(99, 102, 241, 0.25))',
      }}
    >
      {/* Subtle sparkle/gradient orb in background */}
      <div
        aria-hidden
        className="absolute top-0 right-0 w-32 h-32 opacity-20 blur-2xl pointer-events-none"
        style={{ background: 'radial-gradient(circle, rgba(168, 85, 247, 0.8) 0%, transparent 70%)' }}
      />

      {/* Header */}
      <div className="flex items-center justify-between mb-3 relative">
        <div className="flex items-center gap-2">
          <div
            className="w-7 h-7 rounded-lg flex items-center justify-center"
            style={{ background: 'linear-gradient(135deg, #6366f1, #a855f7)' }}
          >
            <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
          </div>
          <div>
            <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
              AuditGraph Argus
            </h3>
            <p className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
              Argus sees what your logs miss — answers cite evidence
            </p>
          </div>
        </div>
        <span
          className="text-[9px] uppercase tracking-wider font-bold px-2 py-0.5 rounded-full"
          style={{
            color: 'var(--accent-indigo, #6366f1)',
            background: 'rgba(99, 102, 241, 0.12)',
            border: '1px solid rgba(99, 102, 241, 0.25)',
          }}
        >
          AI
        </span>
      </div>

      {/* Prompt input */}
      <form onSubmit={handleSubmit} className="relative mb-3">
        <input
          type="text"
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          placeholder={contextLabel
            ? `Ask about ${contextLabel}...`
            : 'Ask anything about your identity posture...'}
          className="w-full pl-4 pr-12 py-2.5 text-sm rounded-lg border focus:outline-none focus:ring-2 transition-all"
          style={{
            background: 'var(--bg-elevated, rgba(255,255,255,0.05))',
            borderColor: 'var(--border-primary)',
            color: 'var(--text-primary)',
          }}
        />
        <button
          type="submit"
          disabled={!inputValue.trim()}
          className="absolute right-1.5 top-1/2 -translate-y-1/2 px-3 py-1 rounded-md text-xs font-semibold transition-all disabled:opacity-40"
          style={{
            background: inputValue.trim()
              ? 'linear-gradient(135deg, #6366f1, #a855f7)'
              : 'var(--bg-secondary)',
            color: '#fff',
          }}
          title="Send to Copilot (or pick a quick-ask below)"
        >
          Ask →
        </button>
      </form>

      {/* Quick-ask chips */}
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-[10px] uppercase tracking-wider font-semibold mr-1" style={{ color: 'var(--text-tertiary)' }}>
          Try:
        </span>
        {chips.map((chip, idx) => (
          <button
            key={idx}
            onClick={() => openCopilot({ initialQuestion: chip.question, contextLabel, contextId })}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium transition-all hover:scale-105"
            style={{
              background: 'var(--bg-elevated, rgba(255,255,255,0.05))',
              border: '1px solid var(--border-primary)',
              color: 'var(--text-secondary)',
            }}
            title={chip.question}
          >
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" style={{ color: 'var(--accent-indigo, #6366f1)' }}>
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={chip.icon} />
            </svg>
            {chip.label}
          </button>
        ))}
      </div>
    </div>
  );
}

export default CopilotQuickAsk;
