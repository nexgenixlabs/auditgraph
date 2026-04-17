import React, { useMemo } from 'react';
import type { CISOViewModel } from '../../utils/cisoViewModel';
import type { PostureV31Response } from '../../utils/cisoViewModel';
import { DN, ScoreRing } from '../dashboard/ciso-shared';
import { STATUS_DOT, STATUS_TEXT_CLS, CONFIDENCE_CLS, POSTURE_STATUS_COLOR, POSTURE_STATUS_BORDER, POSTURE_STATUS_LABEL, POSTURE_STATUS_TEXT, POSTURE_CONFIDENCE_COLOR, postureBandFromScore } from '../../constants/cisoColors';

// ── Narrative helpers (legacy VM path) ───────────────────────

const RISK_LEVEL_LABEL: Record<string, string> = {
  critical: 'Critical', high: 'High', moderate: 'Moderate', low: 'Low',
};

const VERDICT_LINE: Record<string, string> = {
  low: 'Your identity environment is secure',
  moderate: 'Your identity environment has exploitable gaps',
  high: 'Your identity environment is actively exposed',
  critical: 'Your identity environment faces imminent breach risk',
};

function driverToRiskFocus(title: string, count: number): string {
  const n = count;
  const s = n !== 1 ? 's' : '';
  const ies = n !== 1 ? 'ies' : 'y';
  const map: Record<string, string> = {
    'Dormant Privileged Accounts': `${n} account${s} still retain unnecessary admin access`,
    'Ghost Identities': `${n} disabled account${s} still hold live access to resources`,
    'Unowned Service Principals': `${n} service account${s} operate with no one accountable`,
    'Excess Privilege': `${n} identit${ies} hold access they never use`,
    'External Guest Privilege': `${n} external user${s} carry privileged access into your environment`,
  };
  return map[title] || `${n} identit${ies} carry elevated risk`;
}

function driverToActionHint(title: string): string {
  const map: Record<string, string> = {
    'Dormant Privileged Accounts': 'Removing them eliminates most misuse risk',
    'Ghost Identities': 'Revoking their access closes hidden backdoors',
    'Unowned Service Principals': 'Assigning owners restores accountability',
    'Excess Privilege': 'Scoping their roles shrinks the blast radius',
    'External Guest Privilege': 'Restricting them reduces supply-chain exposure',
  };
  return map[title] || 'Addressing this strengthens your overall posture';
}

function buildInsightLines(vm: CISOViewModel): {
  verdict: string;
  riskFocus: string | null;
  actionHint: string | null;
} {
  const verdict = VERDICT_LINE[vm.status] || 'Identity posture data unavailable';
  const topDriver = vm.top_risk_drivers[0];
  const riskFocus = topDriver ? driverToRiskFocus(topDriver.title, topDriver.count) : null;
  const actionHint = topDriver ? driverToActionHint(topDriver.title) : null;
  return { verdict, riskFocus, actionHint };
}

// ── NarrativePanel (legacy VM) ───────────────────────────────

export function NarrativePanel({ vm }: { vm: CISOViewModel }) {
  const { verdict, riskFocus, actionHint } = useMemo(() => buildInsightLines(vm), [vm]);

  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex flex-col justify-center overflow-hidden"
         title="Executive posture verdict based on identity risk analysis">
      <div className="flex items-center gap-2 mb-1">
        <span className="relative flex h-2 w-2 flex-shrink-0">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75" style={{ backgroundColor: STATUS_DOT[vm.status] || '#4a6080' }} />
          <span className="relative inline-flex rounded-full h-2 w-2" style={{ backgroundColor: STATUS_DOT[vm.status] || '#4a6080' }} />
        </span>
        <span className={`text-xs font-semibold leading-none truncate ${STATUS_TEXT_CLS[vm.status] || 'text-[#4a6080]'}`}>
          {RISK_LEVEL_LABEL[vm.status] || 'No Data'}
        </span>
      </div>
      <p className="text-xs text-gray-300 truncate">{verdict}</p>
      {riskFocus && <p className="text-xs text-gray-400 truncate mt-0.5">{riskFocus}</p>}
      {actionHint && <p className="text-xs text-gray-500 truncate mt-0.5">{actionHint}</p>}
    </div>
  );
}

// ── NarrativeBanner (v3.1 — Block 1) ────────────────────────

export function NarrativeBanner({ data }: { data: PostureV31Response }) {
  const borderCls = POSTURE_STATUS_BORDER[data.posture_status] || 'border-l-[#4a6080]';
  const statusColor = POSTURE_STATUS_COLOR[data.posture_status] || '#4a6080';

  return (
    <div className={`bg-[#111827] border border-white/5 ${borderCls} border-l-2 rounded-lg p-3 h-full flex flex-col justify-center overflow-hidden`}
         title="Server-rendered executive narrative">
      <div className="flex items-center gap-2 mb-1">
        <span className="relative flex h-2 w-2 flex-shrink-0">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75" style={{ backgroundColor: statusColor }} />
          <span className="relative inline-flex rounded-full h-2 w-2" style={{ backgroundColor: statusColor }} />
        </span>
        <span className={`text-xs font-semibold leading-none truncate ${POSTURE_STATUS_TEXT[data.posture_status] || 'text-[#4a6080]'}`}>
          {POSTURE_STATUS_LABEL[data.posture_status] || 'Unknown'}
        </span>
      </div>
      <p className="text-xs text-gray-300 line-clamp-3" style={{ whiteSpace: 'pre-line' }}>{data.narrative_text}</p>
    </div>
  );
}

// ── PostureScoreHero (v3.1 — Block 2) ────────────────────────

export function PostureScoreHero({ data }: { data: PostureV31Response }) {
  const score = data.posture_score ?? 0;
  const delta = data.score_delta;
  const statusColor = POSTURE_STATUS_COLOR[data.posture_status] || '#4a6080';
  const cov = data.coverage || { cloud_label: 'None', sub_count: 0, coverage_pct: 0, confidence_level: 'low' as const };
  const band = postureBandFromScore(score);

  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex items-center gap-3 overflow-hidden"
         title="Composite security posture score">
      {/* Score ring */}
      <DN navigateTo="/risk-monitoring">
        <div className="flex-shrink-0 cursor-pointer" title={
          score >= 90 ? 'Grade A \u2014 top posture tier'
          : score >= 80 ? 'Grade B \u2014 strong posture'
          : score >= 70 ? 'Grade C \u2014 moderate posture'
          : score >= 60 ? 'Grade D \u2014 posture needs attention'
          : 'Grade F \u2014 critical posture issues'
        }>
          <ScoreRing score={score} size={68} strokeWidth={5} color={statusColor} />
        </div>
      </DN>

      {/* Score context */}
      <div className="flex-1 min-w-0">
        <div className="text-xs text-gray-400 uppercase tracking-wider font-medium mb-1 truncate">Posture Score</div>
        <div className="flex items-baseline gap-1.5">
          <span className="text-xl font-semibold text-gray-100 leading-none font-mono">{score.toFixed(0)}</span>
          <span className={`text-xs font-medium ${band.textCls}`}>&nbsp;&middot; {band.label}</span>
          {delta == null ? null : delta === 0 ? (
            <span className="text-xs text-gray-500 flex-shrink-0">&rarr; No change</span>
          ) : delta > 0 ? (
            <span className="text-xs font-medium flex-shrink-0 text-emerald-400">
              &#9650; +{(data.posture_change_pct ?? Math.abs(delta)).toFixed(1)}% since last scan
            </span>
          ) : (
            <span className="text-xs font-medium flex-shrink-0 text-[#f59e0b]">
              &#9660; &minus;{(data.posture_change_pct ?? Math.abs(delta)).toFixed(1)}% since last scan
            </span>
          )}
        </div>
        {data.projected && data.projected.score_improvement > 0 && (
          <p style={{ fontSize: 10, fontWeight: 500, color: 'var(--teal, #24A2A1)', marginTop: 2 }}>
            After applying top {data.projected.actions_applied} actions: {data.projected.score} &middot; {postureBandFromScore(data.projected.score).label} ({data.projected.status})
          </p>
        )}
        {/* Coverage inline */}
        <div className="flex items-center gap-2 mt-1">
          <span className="text-xs text-gray-400">{cov.cloud_label}</span>
          <span className="text-xs text-gray-600">&middot;</span>
          <span className="text-xs text-gray-500">{cov.sub_count} subscription{cov.sub_count !== 1 ? 's' : ''}</span>
          <div className="flex-1 h-1 bg-[#1e2d4a] rounded-full max-w-[60px]">
            <div className="h-1 rounded-full transition-all" style={{ width: `${cov.coverage_pct}%`, backgroundColor: POSTURE_CONFIDENCE_COLOR[cov.confidence_level] || '#4a6080' }} />
          </div>
          <span className="text-xs capitalize" style={{ color: POSTURE_CONFIDENCE_COLOR[cov.confidence_level] || '#4a6080' }}>
            Confidence: {cov.confidence_level}
          </span>
        </div>
      </div>
    </div>
  );
}

// ── RiskScorePanel (legacy VM) ───────────────────────────────

export function RiskScorePanel({ vm }: { vm: CISOViewModel }) {
  const score = vm.agirs_display.score;
  const trend = vm.trend_history;
  const band = postureBandFromScore(score ?? 0);

  const delta = useMemo(() => {
    if (!trend.available || trend.posture_scores.length < 2) return null;
    const scores = trend.posture_scores;
    const prev = scores[scores.length - 2];
    const curr = scores[scores.length - 1];
    if (prev === 0) return null;
    const pctChange = ((curr - prev) / prev) * 100;
    return { value: Math.abs(pctChange), direction: pctChange >= 0 ? 'up' as const : 'down' as const };
  }, [trend]);

  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex items-center gap-3 overflow-hidden"
         title="Aggregate Identity Risk Score — composite security posture metric">
      <DN navigateTo={vm.agirs_display.nav}>
        <div className="flex-shrink-0 animate-[pulse_3s_ease-in-out_infinite]" style={{ animationDuration: '3s' }}>
          {score != null ? (
            <ScoreRing score={score} size={68} strokeWidth={5} />
          ) : (
            <div className="w-[68px] h-[68px] rounded-full border-2 border-[#1e2d4a] flex items-center justify-center">
              <span className="text-xs text-gray-500">N/A</span>
            </div>
          )}
        </div>
      </DN>
      <div className="flex-1 min-w-0">
        <div className="text-xs text-gray-400 uppercase tracking-wider font-medium mb-1 truncate">Posture Score</div>
        <div className="flex items-baseline gap-1.5">
          {score != null ? (
            <span className="text-xl font-semibold text-gray-100 leading-none font-mono">{score.toFixed(0)}</span>
          ) : (
            <span className="text-xl font-semibold text-gray-500 leading-none">—</span>
          )}
          <span className={`text-xs font-medium ${band.textCls}`}>&nbsp;&middot; {band.label}</span>
          {delta && (
            <span className={`text-xs font-medium flex-shrink-0 ${delta.direction === 'up' ? 'text-emerald-400' : 'text-red-400'}`}>
              {delta.direction === 'up' ? '↑' : '↓'}{delta.value.toFixed(1)}%
            </span>
          )}
        </div>
        <span className={`text-xs font-medium ${STATUS_TEXT_CLS[vm.risk_exposure.level] || 'text-gray-500'}`}>
          {RISK_LEVEL_LABEL[vm.risk_exposure.level] || 'Unknown'}
        </span>
        <DN navigateTo={vm.risk_exposure.nav}>
          <div className="text-xs text-gray-400 truncate mt-0.5">
            <span className="font-mono text-gray-300">{vm.risk_exposure.count}</span> at risk of {vm.monitored.identities.toLocaleString()}
          </div>
        </DN>
      </div>
    </div>
  );
}

// ── ConfidencePanel (legacy VM) ──────────────────────────────

export function ConfidencePanel({ vm, inventorySubscriptions, inventoryLastScan }: {
  vm: CISOViewModel;
  inventorySubscriptions?: number;
  inventoryLastScan?: string;
}) {
  const coveragePct = vm.coverage_pct || (vm.data_confidence === 'high' ? 100 : vm.data_confidence === 'medium' ? 75 : 40);
  const confidenceLabel = vm.data_confidence === 'high'
    ? 'Based on full environment analysis'
    : vm.data_confidence === 'medium'
    ? 'Based on partial environment data'
    : 'Limited data available';

  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex flex-col justify-center overflow-hidden"
         title="Data coverage indicates how much of your environment has been analyzed">
      <div className="flex items-baseline gap-1.5">
        <span className={`text-xl font-semibold leading-none font-mono ${CONFIDENCE_CLS[vm.data_confidence] || 'text-gray-500'}`}>
          {coveragePct}%
        </span>
        <span className="text-xs text-gray-400">coverage</span>
      </div>
      <p className="text-xs text-gray-500 truncate mb-1">{confidenceLabel}</p>
      <div className="space-y-1 text-xs">
        <div className="flex justify-between items-center">
          <span className="text-gray-400 truncate">Subscriptions</span>
          <span className="font-mono text-gray-300 flex-shrink-0">{inventorySubscriptions ?? vm?.monitored?.subscriptions ?? '\u2014'}</span>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-gray-400 truncate">Identities</span>
          <span className="font-mono text-gray-300 flex-shrink-0">{vm.monitored.identities.toLocaleString()}</span>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-gray-400 truncate">Last scan</span>
          <span className="font-mono text-gray-300 flex-shrink-0 truncate ml-2 max-w-[80px] text-right">{inventoryLastScan ?? vm?.last_updated ?? '\u2014'}</span>
        </div>
      </div>
    </div>
  );
}

// ── Default export (backwards compat) ────────────────────────

export default function ExecutiveSummaryHero({ vm }: { vm: CISOViewModel }) {
  return (
    <div className="grid grid-cols-12 gap-3 h-[120px]">
      <div className="col-span-5"><NarrativePanel vm={vm} /></div>
      <div className="col-span-4"><RiskScorePanel vm={vm} /></div>
      <div className="col-span-3"><ConfidencePanel vm={vm} /></div>
    </div>
  );
}
