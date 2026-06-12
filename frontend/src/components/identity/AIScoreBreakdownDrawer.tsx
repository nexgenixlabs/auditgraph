/**
 * AI Governance Score breakdown drawer (2026-06-11)
 *
 * Mirrors ScoreBreakdownDrawer (Identity Security Score) but uses the AI
 * factor list. Per peer review: "Score=63. Customer question: how did you
 * get 63? Need score composition."
 */
import React, { useEffect, useState } from 'react';
import { computeAiScoreBreakdown, type AiScoreBreakdownInput, type AiScoreFactor } from '../../utils/aiScoreBreakdown';

export interface AIScoreBreakdownDrawerProps {
  open: boolean;
  onClose: () => void;
  headlineScore: number;
  input: AiScoreBreakdownInput;
}

function tone(s: number): { color: string; label: string } {
  if (s >= 80) return { color: '#34d399', label: 'Strong' };
  if (s >= 60) return { color: '#a3e635', label: 'Good' };
  if (s >= 40) return { color: '#fb923c', label: 'Elevated' };
  return            { color: '#f87171', label: 'Critical' };
}

export function AIScoreBreakdownDrawer({ open, onClose, headlineScore, input }: AIScoreBreakdownDrawerProps) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);
  if (!open) return null;

  const { factors, total } = computeAiScoreBreakdown(input);
  const t = tone(headlineScore);
  const reconcileDelta = headlineScore - total;

  return (
    <div className="fixed inset-0 z-50 flex items-stretch justify-end bg-black/60 backdrop-blur-sm"
      onClick={onClose}
      role="dialog" aria-modal="true" aria-label="AI Governance Score breakdown">
      <div className="w-full max-w-[640px] bg-slate-900 border-l border-white/10 overflow-y-auto"
        onClick={e => e.stopPropagation()}>

        <header className="sticky top-0 z-10 bg-slate-900/95 backdrop-blur border-b border-white/10 px-6 py-4 flex items-start justify-between gap-3">
          <div>
            <h2 className="text-lg font-bold text-white">AI Governance Score</h2>
            <p className="text-[11px] text-slate-400 mt-0.5">
              AuditGraph Methodology v1 · NIST AI RMF 1.0 + ISO 42001 anchored · architecture-derived
            </p>
          </div>
          <button onClick={onClose}
            aria-label="Close"
            className="text-slate-400 hover:text-white text-xl leading-none w-8 h-8 rounded-lg hover:bg-slate-800 flex items-center justify-center transition">
            ×
          </button>
        </header>

        <div className="px-6 py-5">
          <div className="rounded-xl border p-5 flex items-center justify-between gap-5"
            style={{ background: `${t.color}10`, borderColor: `${t.color}40` }}>
            <div>
              <p className="text-[10px] uppercase tracking-wider font-bold text-slate-400">Current Score</p>
              <p className="text-6xl font-bold font-mono leading-none mt-2" style={{ color: t.color }}>{headlineScore}</p>
              <p className="text-[11px] text-slate-500 mt-1">of 100 · <span className="font-semibold" style={{ color: t.color }}>{t.label}</span></p>
            </div>
            <div className="text-right text-[11px] text-slate-400 max-w-[200px]">
              <p className="font-semibold text-slate-300 mb-1">What does this mean?</p>
              <p className="leading-relaxed">
                {headlineScore >= 80 && 'AI governance leads peer organizations. Maintain controls.'}
                {headlineScore >= 60 && headlineScore < 80 && 'Solid foundation with a small number of governance gaps.'}
                {headlineScore >= 40 && headlineScore < 60 && 'Multiple high-impact gaps. Prioritize the lowest-scoring factors below.'}
                {headlineScore < 40 && 'Critical AI exposure. At least three governance factors require immediate attention.'}
              </p>
            </div>
          </div>
        </div>

        <div className="px-6 pb-4 space-y-3">
          {factors.map(f => <AIFactorRow key={f.key} factor={f} totalAgents={input.totalAgents} />)}
        </div>

        {/* V2.9 (2026-06-12) — same Raw → Adjustment → Final framing as
            the Identity Score drawer. Tells the truth about the gap so a
            customer sees defensible math instead of a contradictory pair
            of numbers. */}
        <div className="px-6 py-4 border-t border-white/10 bg-slate-950/50 space-y-1.5">
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-400">Per-factor weighted sum</span>
            <span className="font-mono text-slate-300">{total}</span>
          </div>
          {reconcileDelta !== 0 && (
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Posture-rollup adjustment</span>
              <span className={`font-mono ${reconcileDelta < 0 ? 'text-rose-300' : 'text-emerald-300'}`}>
                {reconcileDelta > 0 ? '+' : ''}{reconcileDelta}
              </span>
            </div>
          )}
          <div className="flex items-center justify-between text-sm pt-1.5 mt-1 border-t border-slate-700/60">
            <span className="font-semibold text-white">Headline score</span>
            <span className="font-mono font-bold text-white">{headlineScore} / 100</span>
          </div>
          {reconcileDelta !== 0 && (
            <p className="text-[10px] text-slate-500 leading-relaxed pt-2">
              The per-factor weighted sum approximates the score from the 6 governance signals shown above.
              The headline ({headlineScore}) comes from the canonical AI posture rollup, which incorporates per-agent classification confidence and policy attestation not yet exposed as standalone factors.
              The {Math.abs(reconcileDelta)}-pt gap is the rollup's adjustment over the simple weighted sum.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

function AIFactorRow({ factor, totalAgents }: { factor: AiScoreFactor; totalAgents: number }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="rounded-lg bg-slate-800/40 border border-slate-700/40 p-3.5">
      <div className="flex items-baseline justify-between mb-2">
        <div className="flex items-baseline gap-2 min-w-0">
          <h3 className="text-sm font-semibold text-white truncate">{factor.label}</h3>
          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-900/80 text-slate-400 border border-slate-700/60 flex-shrink-0">
            {factor.weight}% weight
          </span>
        </div>
        {/* V2.11 (2026-06-12) — units + "Max risk" badge per peer review.
            Same fix as Identity drawer. */}
        <div className="text-right flex-shrink-0 flex items-baseline gap-2">
          {factor.contribution === 0 && factor.subScore < 50 && (
            <span className="text-[8px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded-sm bg-rose-500/15 text-rose-300 border border-rose-500/40">
              Max risk
            </span>
          )}
          <div>
            <span className="text-base font-mono font-bold" style={{ color: factor.color }}>
              {factor.contribution}
            </span>
            <span className="text-[10px] text-slate-500 ml-1">pts of {factor.weight}</span>
          </div>
        </div>
      </div>
      <div className="flex items-baseline justify-between mb-1">
        <span className="text-[10px] text-slate-500">
          Factor health: <strong className="font-mono" style={{ color: factor.color }}>{factor.subScore}%</strong>
        </span>
        <span className="text-[10px] text-slate-600">
          Headline contribution: {factor.contribution} / {factor.weight}
        </span>
      </div>
      <div className="h-1.5 rounded-full bg-slate-900 overflow-hidden mb-2">
        <div className="h-full rounded-full transition-all"
          style={{ width: `${factor.subScore}%`, background: factor.color }} />
      </div>
      <p className="text-[11px] text-slate-300 leading-relaxed">{factor.signalDetail}</p>
      {/* V2.10 (2026-06-12) — executive impact line. Surfaces the inverse
          count + the business consequence so a CISO sees the stat AS a
          board concern, not as raw data. Only renders for under-healthy
          factors (sub-score < 75) to avoid doomifying good news. */}
      {factor.executiveImpact && (
        <p className="text-[11px] mt-2 pl-2.5 py-1.5 rounded-r border-l-2 leading-relaxed"
          style={{
            color: '#fda4af',
            background: 'rgba(244, 63, 94, 0.08)',
            borderColor: factor.color,
          }}>
          <span className="font-semibold">Impact:</span> {factor.executiveImpact}
        </p>
      )}
      <button onClick={() => setExpanded(e => !e)}
        className="text-[10px] text-slate-500 hover:text-slate-300 mt-1.5 inline-flex items-center gap-1">
        <span>{expanded ? '▾' : '▸'}</span>
        <span>Why this is weighted {factor.weight}%</span>
      </button>
      {expanded && (
        <p className="text-[10px] text-slate-400 leading-relaxed mt-1.5 pl-3 border-l border-slate-700/60">
          {factor.citation}
        </p>
      )}
    </div>
  );
}
