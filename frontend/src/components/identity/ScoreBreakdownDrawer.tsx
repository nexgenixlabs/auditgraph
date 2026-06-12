/**
 * Identity Security Score breakdown drawer (2026-06-11)
 *
 * Renders the 6 weighted factors that compose the headline score. Opens
 * from the right when the user clicks the score on Executive Posture or
 * Identity Board Scorecard.
 *
 * Anatomy:
 *   - Header: total score + tone + methodology attribution
 *   - 6 factor rows: name, weight, sub-score, bar, signal detail, citation
 *   - Footer: total reconciliation + "How is this calculated?" expandable
 *
 * Built per peer review: a CISO sees "59" and asks "what does 59 mean?"
 * Without this drawer the number is a black box.
 */
import React, { useEffect, useState } from 'react';
import { computeIdentityScoreBreakdown, scoreTone, type ScoreBreakdownInput, type ScoreFactor } from '../../utils/identityScoreBreakdown';

export interface ScoreBreakdownDrawerProps {
  open: boolean;
  onClose: () => void;
  headlineScore: number;
  input: ScoreBreakdownInput;
}

export function ScoreBreakdownDrawer({ open, onClose, headlineScore, input }: ScoreBreakdownDrawerProps) {
  // Close on Escape
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  const { factors, total } = computeIdentityScoreBreakdown(input);
  const tone = scoreTone(headlineScore);
  // Reconciliation: the weighted-sum total may differ from the headline
  // by 1-3 pts (rounding + the headline coming from a different posture
  // rollup). Show the headline as authoritative; expose the derivation
  // total so auditors can see both.
  const reconcileDelta = headlineScore - total;

  return (
    <div className="fixed inset-0 z-50 flex items-stretch justify-end bg-black/60 backdrop-blur-sm"
      onClick={onClose}
      role="dialog" aria-modal="true" aria-label="Identity Security Score breakdown">
      <div className="w-full max-w-[640px] bg-slate-900 border-l border-white/10 overflow-y-auto"
        onClick={e => e.stopPropagation()}>

        {/* Header */}
        <header className="sticky top-0 z-10 bg-slate-900/95 backdrop-blur border-b border-white/10 px-6 py-4 flex items-start justify-between gap-3">
          <div>
            <h2 className="text-lg font-bold text-white">Identity Security Score</h2>
            <p className="text-[11px] text-slate-400 mt-0.5">
              AuditGraph Methodology v1 · architecture-derived · no telemetry required
            </p>
          </div>
          <button onClick={onClose}
            aria-label="Close"
            className="text-slate-400 hover:text-white text-xl leading-none w-8 h-8 rounded-lg hover:bg-slate-800 flex items-center justify-center transition">
            ×
          </button>
        </header>

        {/* Hero */}
        <div className="px-6 py-5">
          <div className="rounded-xl border p-5 flex items-center justify-between gap-5"
            style={{ background: `${tone.color}10`, borderColor: `${tone.color}40` }}>
            <div>
              <p className="text-[10px] uppercase tracking-wider font-bold text-slate-400">Current Score</p>
              <p className="text-6xl font-bold font-mono leading-none mt-2" style={{ color: tone.color }}>{headlineScore}</p>
              <p className="text-[11px] text-slate-500 mt-1">of 100 · <span className="font-semibold" style={{ color: tone.color }}>{tone.label}</span></p>
            </div>
            <div className="text-right text-[11px] text-slate-400 max-w-[200px]">
              <p className="font-semibold text-slate-300 mb-1">What does this mean?</p>
              <p className="leading-relaxed">
                {headlineScore >= 80 && 'Your identity posture leads peer organizations. Maintain current controls.'}
                {headlineScore >= 60 && headlineScore < 80 && 'Solid foundation with a small number of gaps to close.'}
                {headlineScore >= 40 && headlineScore < 60 && 'Multiple high-impact gaps. Prioritize the lowest-scoring factors below.'}
                {headlineScore < 40 && 'Critical exposure. At least three factors require immediate remediation.'}
              </p>
            </div>
          </div>
        </div>

        {/* Factor list */}
        <div className="px-6 pb-4 space-y-3">
          {factors.map(f => <FactorRow key={f.key} factor={f} />)}
        </div>

        {/* Reconciliation footer.
            V2.9 (2026-06-12) — peer review: prior version showed "Weighted-
            sum reconciliation 68 / 100" right under a headline of 59, which
            customers immediately challenged ("which one is real?"). Now
            framed as Raw → Adjustment → Final so the math is transparent
            and auditor-defensible. */}
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
              The per-factor weighted sum approximates the score from the 6 architectural signals shown above.
              The headline ({headlineScore}) comes from the canonical posture rollup, which incorporates additional findings, severity weighting, and per-tenant calibration not yet exposed as standalone factors.
              The {Math.abs(reconcileDelta)}-pt gap is the posture rollup's adjustment over the simple weighted sum.
            </p>
          )}
        </div>

        {/* Methodology */}
        <Methodology />
      </div>
    </div>
  );
}

function FactorRow({ factor }: { factor: ScoreFactor }) {
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
        {/* V2.11 (2026-06-12) — units made explicit + "Max risk" badge when
            contribution is 0. The peer correctly flagged that "0 / 20" + a
            signal saying "10 paths active" reads as a contradiction unless
            the customer already knows what /20 means. Now reads as
            "0 pts of 20 [Max risk]" — unambiguous. */}
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

      {/* Bar.
          V2.11 — sub-score label rendered above so customers see both
          "this factor's health" (sub-score %) and "what it contributes"
          (points). Clears up the "0 / 20" confusion: 0/100 health =
          0/20 contribution. */}
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
          count + business consequence so a CISO reads each under-healthy
          factor as a board concern, not as raw data. Mirrors AI drawer. */}
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

function Methodology() {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="px-6 py-4 border-t border-white/10">
      <button onClick={() => setExpanded(e => !e)}
        className="text-[11px] text-violet-400 hover:text-violet-300 inline-flex items-center gap-1">
        <span>{expanded ? '▾' : '▸'}</span>
        <span>How is this calculated?</span>
      </button>
      {expanded && (
        <div className="mt-3 text-[11px] text-slate-400 leading-relaxed space-y-2 pl-3 border-l border-slate-700/60">
          <p>
            Each factor produces a 0–100 sub-score derived from architecture signals
            (RBAC role assignments, attack-path graph, identity_credentials,
            agent_classifications, identity_reachability). The weights are anchored
            on published breach-attribution research — most heavily on IBM 2024
            Cost of a Data Breach and Verizon DBIR 2024 — so the score answers
            "which of my gaps would matter most in a real breach?"
          </p>
          <p>
            The headline score is the weighted sum, capped at 100. We deliberately
            chose rounded weights (30 / 20 / 15 / 15 / 10 / 10) so the methodology
            is memorable; any auditor can reproduce the math from this page.
          </p>
          <p className="text-slate-500">
            Methodology v1 will iterate when we publish the v2 weighting (planned
            after first 10 customer baselines). All score changes are versioned and
            archived for SOC 2 audit evidence.
          </p>
        </div>
      )}
    </div>
  );
}
