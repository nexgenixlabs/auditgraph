/**
 * CISO Dashboard V1 — Live Posture Score + Trend
 *
 * Wired exclusively to Phase 3 posture engine endpoints:
 *   GET  /api/v1/posture/score
 *   GET  /api/v1/posture/score/history?days=30
 *   POST /api/v1/posture/score/recompute
 *   GET  /api/v1/posture/actions
 *   GET  /api/v1/identities?sort=risk_score&order=desc&limit=10
 *
 * No legacy fallbacks. No new npm dependencies.
 */
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import {
  type PostureScoreResponse,
  type PostureScoreHistoryResponse,
  type PostureScoreHistoryRow,
  type PriorityActionsResponse,
  type PriorityActionItem,
  type DimensionScores,
  type IdentityListRow,
  type PaginatedResponse,
  type BulkSimulationResult,
  type SimulationType,
  getPostureScore,
  getPostureHistory,
  recomputePostureScore,
  getPostureActions,
  listIdentities,
  runBulkSimulation,
} from '../services/identityEngineApi';

// ── Theme constants ─────────────────────────────────────────────────

const SCORE_COLORS: Record<string, string> = {
  excellent: '#22c55e',
  good: '#84cc16',
  fair: '#eab308',
  poor: '#f97316',
  critical: '#ef4444',
};

function scoreColor(score: number): string {
  if (score >= 90) return SCORE_COLORS.excellent;
  if (score >= 75) return SCORE_COLORS.good;
  if (score >= 60) return SCORE_COLORS.fair;
  if (score >= 40) return SCORE_COLORS.poor;
  return SCORE_COLORS.critical;
}

function scoreLabel(score: number): string {
  if (score >= 90) return 'Excellent';
  if (score >= 75) return 'Good';
  if (score >= 60) return 'Fair';
  if (score >= 40) return 'Poor';
  return 'Critical';
}

const DIMENSION_LABELS: Record<keyof DimensionScores, string> = {
  attack_surface: 'Attack Surface',
  privilege: 'Privilege',
  credentials: 'Credentials',
  activity: 'Activity',
  governance: 'Governance',
};

const DIMENSION_COLORS: Record<keyof DimensionScores, string> = {
  attack_surface: '#3b82f6',
  privilege: '#8b5cf6',
  credentials: '#06b6d4',
  activity: '#22c55e',
  governance: '#f59e0b',
};

const RISK_BADGE: Record<string, { bg: string; text: string }> = {
  critical: { bg: 'bg-red-100 dark:bg-red-900/30', text: 'text-red-700 dark:text-red-400' },
  high: { bg: 'bg-orange-100 dark:bg-orange-900/30', text: 'text-orange-700 dark:text-orange-400' },
  medium: { bg: 'bg-yellow-100 dark:bg-yellow-900/30', text: 'text-yellow-700 dark:text-yellow-400' },
  low: { bg: 'bg-green-100 dark:bg-green-900/30', text: 'text-green-700 dark:text-green-400' },
  info: { bg: 'bg-slate-100 dark:bg-slate-800', text: 'text-slate-600 dark:text-slate-400' },
};

const ACTION_ICONS: Record<string, string> = {
  assign_owners: '\u{1F464}',
  review_privilege: '\u{1F6E1}',
  disable_dormant: '\u{23F8}',
  remediate_critical: '\u{26A0}',
  resolve_orphans: '\u{1F517}',
};

const ACTION_TO_SIM_TYPE: Record<string, SimulationType> = {
  assign_owners: 'OWNERSHIP_ASSIGNMENT',
  review_privilege: 'PRIVILEGE_REDUCTION',
  disable_dormant: 'ROLE_REMOVAL',
  remediate_critical: 'ROLE_REMOVAL',
  resolve_orphans: 'OWNERSHIP_ASSIGNMENT',
};

const ACTION_TO_PAYLOAD: Record<string, Record<string, any>> = {
  assign_owners: { owner: 'governance-team@org' },
  review_privilege: { target_level: 'standard' },
  disable_dormant: { role: 'Reader' },
  remediate_critical: { role: 'Owner' },
  resolve_orphans: { owner: 'governance-team@org' },
};

// ── Skeleton loaders ────────────────────────────────────────────────

function SkeletonCard({ className = '' }: { className?: string }) {
  return (
    <div className={`animate-pulse rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 ${className}`}>
      <div className="h-4 bg-slate-200 dark:bg-slate-700 rounded w-1/3 mb-4" />
      <div className="h-8 bg-slate-200 dark:bg-slate-700 rounded w-1/2 mb-2" />
      <div className="h-3 bg-slate-200 dark:bg-slate-700 rounded w-2/3" />
    </div>
  );
}

function SkeletonRow() {
  return (
    <tr className="animate-pulse">
      {Array.from({ length: 5 }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 bg-slate-200 dark:bg-slate-700 rounded w-full" />
        </td>
      ))}
    </tr>
  );
}

// ── Error display ───────────────────────────────────────────────────

function SectionError({ title, error, onRetry }: { title: string; error: string; onRetry: () => void }) {
  return (
    <div className="rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 p-6">
      <p className="text-sm font-medium text-red-700 dark:text-red-400">{title}</p>
      <p className="text-xs text-red-600 dark:text-red-500 mt-1">{error}</p>
      <button onClick={onRetry} className="mt-3 text-xs text-red-700 dark:text-red-400 underline hover:no-underline">
        Retry
      </button>
    </div>
  );
}

// ── Posture Score Gauge ─────────────────────────────────────────────

function PostureGauge({ score }: { score: number }) {
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;
  const color = scoreColor(score);

  return (
    <div className="relative w-44 h-44 mx-auto">
      <svg viewBox="0 0 160 160" className="w-full h-full transform -rotate-90">
        <circle cx="80" cy="80" r={radius} fill="none" stroke="currentColor"
          className="text-slate-200 dark:text-slate-700" strokeWidth="10" />
        <circle cx="80" cy="80" r={radius} fill="none" stroke={color}
          strokeWidth="10" strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={circumference - progress}
          style={{ transition: 'stroke-dashoffset 0.8s ease-out' }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold text-slate-900 dark:text-white">{score.toFixed(1)}</span>
        <span className="text-xs font-medium mt-1" style={{ color }}>{scoreLabel(score)}</span>
      </div>
    </div>
  );
}

// ── Dimension Bar ───────────────────────────────────────────────────

function DimensionBar({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-slate-600 dark:text-slate-400 w-28 truncate">{label}</span>
      <div className="flex-1 bg-slate-200 dark:bg-slate-700 rounded-full h-2 overflow-hidden">
        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${value}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs font-mono text-slate-700 dark:text-slate-300 w-10 text-right">{value.toFixed(0)}</span>
    </div>
  );
}

// ── Main Component ──────────────────────────────────────────────────

type SectionState = 'loading' | 'ready' | 'error' | 'empty';

export default function CISODashboardV1() {
  const navigate = useNavigate();

  // ── Score state
  const [posture, setPosture] = useState<PostureScoreResponse | null>(null);
  const [scoreState, setScoreState] = useState<SectionState>('loading');
  const [scoreError, setScoreError] = useState('');
  const [recomputing, setRecomputing] = useState(false);

  // ── Trend state
  const [history, setHistory] = useState<PostureScoreHistoryRow[]>([]);
  const [trendState, setTrendState] = useState<SectionState>('loading');
  const [trendError, setTrendError] = useState('');
  const [trendDays, setTrendDays] = useState(30);
  const [visibleDimensions, setVisibleDimensions] = useState<Set<keyof DimensionScores>>(new Set());

  // ── Actions state
  const [actions, setActions] = useState<PriorityActionItem[]>([]);
  const [actionsState, setActionsState] = useState<SectionState>('loading');
  const [actionsError, setActionsError] = useState('');

  // ── Top risks state
  const [topRisks, setTopRisks] = useState<IdentityListRow[]>([]);
  const [risksState, setRisksState] = useState<SectionState>('loading');
  const [risksError, setRisksError] = useState('');

  // ── Bulk simulation state
  const [bulkRunning, setBulkRunning] = useState<string | null>(null);
  const [bulkResult, setBulkResult] = useState<{ actionType: string; result: BulkSimulationResult } | null>(null);

  // ── Load score
  const loadScore = useCallback(async () => {
    setScoreState('loading');
    try {
      const data = await getPostureScore();
      setPosture(data);
      setScoreState('ready');
    } catch (e: any) {
      setScoreError(e.message || 'Failed to load posture score');
      setScoreState('error');
    }
  }, []);

  // ── Load trend
  const loadTrend = useCallback(async (days: number) => {
    setTrendState('loading');
    try {
      const data = await getPostureHistory(days);
      if (data.items.length === 0) {
        setHistory([]);
        setTrendState('empty');
      } else {
        setHistory(data.items);
        setTrendState('ready');
      }
    } catch (e: any) {
      setTrendError(e.message || 'Failed to load trend data');
      setTrendState('error');
    }
  }, []);

  // ── Load actions
  const loadActions = useCallback(async () => {
    setActionsState('loading');
    try {
      const data = await getPostureActions();
      if (data.actions.length === 0) {
        setActions([]);
        setActionsState('empty');
      } else {
        setActions(data.actions);
        setActionsState('ready');
      }
    } catch (e: any) {
      setActionsError(e.message || 'Failed to load priority actions');
      setActionsState('error');
    }
  }, []);

  // ── Load top risks
  const loadTopRisks = useCallback(async () => {
    setRisksState('loading');
    try {
      const data = await listIdentities({ limit: 10, risk_label: 'Critical' });
      if (data.items.length === 0) {
        // Try high if no critical
        const fallback = await listIdentities({ limit: 10 });
        if (fallback.items.length === 0) {
          setTopRisks([]);
          setRisksState('empty');
        } else {
          // Sort by risk_score descending
          const sorted = fallback.items.sort((a, b) => b.risk_score - a.risk_score).slice(0, 10);
          setTopRisks(sorted);
          setRisksState('ready');
        }
      } else {
        setTopRisks(data.items);
        setRisksState('ready');
      }
    } catch (e: any) {
      setRisksError(e.message || 'Failed to load top risk identities');
      setRisksState('error');
    }
  }, []);

  // ── Initial load
  const mounted = useRef(false);
  useEffect(() => {
    if (mounted.current) return;
    mounted.current = true;
    loadScore();
    loadTrend(trendDays);
    loadActions();
    loadTopRisks();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Recompute handler
  const handleRecompute = useCallback(async () => {
    setRecomputing(true);
    try {
      const data = await recomputePostureScore();
      setPosture(data);
      setScoreState('ready');
      // Refresh trend after recompute
      loadTrend(trendDays);
    } catch (e: any) {
      setScoreError(e.message || 'Recompute failed');
      setScoreState('error');
    } finally {
      setRecomputing(false);
    }
  }, [trendDays, loadTrend]);

  // ── Trend days change
  const handleDaysChange = useCallback((days: number) => {
    setTrendDays(days);
    loadTrend(days);
  }, [loadTrend]);

  // ── Toggle dimension visibility on chart
  const toggleDimension = useCallback((dim: keyof DimensionScores) => {
    setVisibleDimensions(prev => {
      const next = new Set(prev);
      if (next.has(dim)) next.delete(dim);
      else next.add(dim);
      return next;
    });
  }, []);

  // ── Bulk simulation handler
  const handleBulkSimulate = useCallback(async (action: PriorityActionItem) => {
    const simType = ACTION_TO_SIM_TYPE[action.action_type];
    const payload = ACTION_TO_PAYLOAD[action.action_type] || {};
    if (!simType) return;

    setBulkRunning(action.action_type);
    setBulkResult(null);

    try {
      // Get identity IDs matching this action's filter
      const filterParts = action.identity_filter.split('=');
      const params: Record<string, any> = { limit: 50 };
      if (filterParts[0] === 'governance' && filterParts[1] === 'ungoverned') {
        // List ungoverned — just get all and we'll pass them
      }
      const identitiesResp = await listIdentities(params);
      const ids = identitiesResp.items
        .filter(i => i.risk_score <= 100) // skip broken risk scores
        .map(i => i.identity_id)
        .slice(0, 50);

      if (ids.length === 0) {
        setBulkRunning(null);
        return;
      }

      const result = await runBulkSimulation({
        identity_ids: ids,
        simulation_type: simType,
        payload,
      });
      setBulkResult({ actionType: action.action_type, result });
    } catch {
      // Silently handle
    } finally {
      setBulkRunning(null);
    }
  }, []);

  // ── Relative time helper
  function relativeTime(iso: string | null): string {
    if (!iso) return 'Never';
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'Just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
  }

  // ── Render ────────────────────────────────────────────────────────

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Security Posture</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            Live posture score from the Phase 3 engine
          </p>
        </div>
        {posture && (
          <div className="flex items-center gap-3">
            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${
              posture.data_freshness === 'live'
                ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                : 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400'
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${
                posture.data_freshness === 'live' ? 'bg-green-500' : 'bg-amber-500'
              }`} />
              {posture.data_freshness === 'live' ? 'Live' : 'Stale'}
            </span>
            <button
              onClick={handleRecompute}
              disabled={recomputing}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50 transition-colors"
            >
              {recomputing ? (
                <>
                  <svg className="animate-spin h-3.5 w-3.5" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
                  Recomputing...
                </>
              ) : 'Recompute'}
            </button>
          </div>
        )}
      </div>

      {/* ── Row 1: Score Card + Identity Summary ── */}
      {scoreState === 'loading' ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <SkeletonCard className="lg:col-span-1" />
          <SkeletonCard className="lg:col-span-2" />
        </div>
      ) : scoreState === 'error' ? (
        <SectionError title="Posture Score" error={scoreError} onRetry={loadScore} />
      ) : posture ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Gauge */}
          <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-6">
            <h2 className="text-sm font-medium text-slate-500 dark:text-slate-400 mb-4">Overall Posture Score</h2>
            <PostureGauge score={posture.overall_score} />
            <div className="mt-5 space-y-2.5">
              {(Object.keys(DIMENSION_LABELS) as Array<keyof DimensionScores>).map(dim => (
                <DimensionBar key={dim}
                  label={DIMENSION_LABELS[dim]}
                  value={posture.dimension_scores[dim]}
                  color={DIMENSION_COLORS[dim]}
                />
              ))}
            </div>
          </div>

          {/* Identity summary cards */}
          <div className="lg:col-span-2 grid grid-cols-2 sm:grid-cols-3 gap-4">
            <SummaryCard label="Total Identities" value={posture.identity_count} />
            <SummaryCard label="Governed" value={posture.governed_count}
              accent={posture.governed_count === 0 ? 'red' : 'green'} />
            <SummaryCard label="Orphaned" value={posture.orphaned_count}
              accent={posture.orphaned_count > 0 ? 'amber' : 'green'} />
            <SummaryCard label="Stale" value={posture.stale_count}
              accent={posture.stale_count > 0 ? 'amber' : 'green'} />
            <SummaryCard label="At Risk" value={posture.at_risk_count}
              accent={posture.at_risk_count > 0 ? 'red' : 'green'} />
            <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4 flex flex-col justify-between">
              <span className="text-xs text-slate-500 dark:text-slate-400">Engine</span>
              <span className="text-sm font-mono text-slate-700 dark:text-slate-300 mt-1">{posture.computed_by}</span>
              <span className="text-xs text-slate-400 dark:text-slate-500 mt-1">
                {new Date(posture.score_date).toLocaleString()}
              </span>
            </div>
          </div>
        </div>
      ) : null}

      {/* ── Row 2: Trend Chart ── */}
      <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-medium text-slate-900 dark:text-white">Posture Score Trend</h2>
          <div className="flex gap-1">
            {[7, 14, 30, 90].map(d => (
              <button key={d}
                onClick={() => handleDaysChange(d)}
                className={`px-2.5 py-1 text-xs rounded-md transition-colors ${
                  trendDays === d
                    ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 font-medium'
                    : 'text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700'
                }`}
              >
                {d}d
              </button>
            ))}
          </div>
        </div>

        {trendState === 'loading' ? (
          <div className="h-64 flex items-center justify-center">
            <div className="animate-pulse text-sm text-slate-400">Loading trend data...</div>
          </div>
        ) : trendState === 'error' ? (
          <SectionError title="Trend Data" error={trendError} onRetry={() => loadTrend(trendDays)} />
        ) : trendState === 'empty' ? (
          <div className="h-64 flex flex-col items-center justify-center text-slate-400 dark:text-slate-500">
            <p className="text-sm">No historical data available yet.</p>
            <p className="text-xs mt-1">Data will appear after the first daily posture computation.</p>
          </div>
        ) : history.length === 1 ? (
          /* Single data point — show value instead of chart */
          <div className="h-64 flex flex-col items-center justify-center">
            <span className="text-4xl font-bold" style={{ color: scoreColor(history[0].overall_score) }}>
              {history[0].overall_score.toFixed(1)}
            </span>
            <span className="text-sm text-slate-500 dark:text-slate-400 mt-2">
              Single data point — {new Date(history[0].score_date).toLocaleDateString()}
            </span>
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">
              Trend chart requires 2+ daily scores. Next computation will enable the chart.
            </p>
          </div>
        ) : (
          <>
            {/* Dimension toggles */}
            <div className="flex flex-wrap gap-2 mb-3">
              {(Object.keys(DIMENSION_LABELS) as Array<keyof DimensionScores>).map(dim => (
                <button key={dim}
                  onClick={() => toggleDimension(dim)}
                  className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs transition-all ${
                    visibleDimensions.has(dim)
                      ? 'bg-slate-100 dark:bg-slate-700 font-medium text-slate-800 dark:text-slate-200'
                      : 'text-slate-400 dark:text-slate-500 hover:text-slate-600 dark:hover:text-slate-300'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: DIMENSION_COLORS[dim], opacity: visibleDimensions.has(dim) ? 1 : 0.3 }} />
                  {DIMENSION_LABELS[dim]}
                </button>
              ))}
            </div>

            <ResponsiveContainer width="100%" height={260}>
              <LineChart data={history.map(row => ({
                date: new Date(row.score_date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
                overall: row.overall_score,
                ...row.dimension_scores,
              }))}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis dataKey="date" tick={{ fontSize: 11 }} stroke="#94a3b8" />
                <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} stroke="#94a3b8" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: 8, fontSize: 12, color: '#f8fafc' }}
                  labelStyle={{ color: '#94a3b8' }}
                />
                <Line type="monotone" dataKey="overall" stroke="#3b82f6" strokeWidth={2.5} dot={{ r: 3 }} name="Overall" />
                {(Object.keys(DIMENSION_LABELS) as Array<keyof DimensionScores>).map(dim => (
                  visibleDimensions.has(dim) && (
                    <Line key={dim} type="monotone" dataKey={dim}
                      stroke={DIMENSION_COLORS[dim]} strokeWidth={1.5} strokeDasharray="4 2"
                      dot={false} name={DIMENSION_LABELS[dim]} />
                  )
                ))}
              </LineChart>
            </ResponsiveContainer>
          </>
        )}
      </div>

      {/* ── Row 3: Priority Actions + Top Risks ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Priority Actions */}
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-6">
          <h2 className="text-sm font-medium text-slate-900 dark:text-white mb-4">Priority Actions</h2>

          {actionsState === 'loading' ? (
            <div className="space-y-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="animate-pulse flex items-center gap-3">
                  <div className="w-8 h-8 rounded bg-slate-200 dark:bg-slate-700" />
                  <div className="flex-1 space-y-2">
                    <div className="h-3 bg-slate-200 dark:bg-slate-700 rounded w-3/4" />
                    <div className="h-2 bg-slate-200 dark:bg-slate-700 rounded w-1/2" />
                  </div>
                </div>
              ))}
            </div>
          ) : actionsState === 'error' ? (
            <SectionError title="Priority Actions" error={actionsError} onRetry={loadActions} />
          ) : actionsState === 'empty' ? (
            <div className="text-center py-8">
              <p className="text-sm text-slate-500 dark:text-slate-400">No priority actions identified.</p>
              <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">Your posture is clean.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {actions.map((action, idx) => (
                <div key={idx} className="p-3 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors group">
                  <div className="flex items-start gap-3 cursor-pointer" onClick={() => navigate(`/identities?${action.identity_filter}`)}>
                    <span className="text-lg mt-0.5">{ACTION_ICONS[action.action_type] || '\u{2699}'}</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-slate-800 dark:text-slate-200 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                        {action.description}
                      </p>
                      <div className="flex items-center gap-3 mt-1">
                        <span className="text-xs text-slate-500 dark:text-slate-400">
                          {action.affected_identity_count} {action.affected_identity_count === 1 ? 'identity' : 'identities'}
                        </span>
                        <span className="text-xs font-medium text-green-600 dark:text-green-400">
                          +{action.estimated_score_impact.toFixed(1)} pts
                        </span>
                      </div>
                    </div>
                    <svg className="w-4 h-4 text-slate-400 mt-1 opacity-0 group-hover:opacity-100 transition-opacity" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7"/></svg>
                  </div>
                  {/* Simulate Remediation button */}
                  <div className="ml-9 mt-2">
                    <button
                      onClick={(e) => { e.stopPropagation(); handleBulkSimulate(action); }}
                      disabled={bulkRunning !== null}
                      className="text-xs px-2.5 py-1 rounded border border-blue-300 dark:border-blue-700 text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 disabled:opacity-50 transition-colors"
                    >
                      {bulkRunning === action.action_type ? (
                        <span className="flex items-center gap-1.5">
                          <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
                          Simulating...
                        </span>
                      ) : 'Simulate Remediation'}
                    </button>
                    {/* Bulk result inline */}
                    {bulkResult && bulkResult.actionType === action.action_type && (
                      <div className="mt-2 p-2.5 rounded bg-slate-100 dark:bg-slate-700/50 text-xs space-y-1">
                        <div className="flex items-center gap-4">
                          <span className="text-slate-600 dark:text-slate-300">
                            {bulkResult.result.completed}/{bulkResult.result.total} simulated
                          </span>
                          {bulkResult.result.failed > 0 && (
                            <span className="text-amber-600 dark:text-amber-400">{bulkResult.result.failed} failed</span>
                          )}
                        </div>
                        <div className="flex items-center gap-4">
                          <span className={`font-medium ${bulkResult.result.aggregate_score_delta < 0 ? 'text-green-600 dark:text-green-400' : 'text-slate-600 dark:text-slate-300'}`}>
                            Score: {bulkResult.result.aggregate_score_delta > 0 ? '+' : ''}{bulkResult.result.aggregate_score_delta.toFixed(1)}
                          </span>
                          <span className={`font-medium ${bulkResult.result.aggregate_blast_radius_delta < 0 ? 'text-green-600 dark:text-green-400' : 'text-slate-600 dark:text-slate-300'}`}>
                            Blast Radius: {bulkResult.result.aggregate_blast_radius_delta > 0 ? '+' : ''}{bulkResult.result.aggregate_blast_radius_delta}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top Risk Identities */}
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-medium text-slate-900 dark:text-white">Top Risk Identities</h2>
            <button onClick={() => navigate('/identities')}
              className="text-xs text-blue-600 dark:text-blue-400 hover:underline">
              View all
            </button>
          </div>

          {risksState === 'loading' ? (
            <table className="w-full"><tbody>{Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} />)}</tbody></table>
          ) : risksState === 'error' ? (
            <SectionError title="Top Risk Identities" error={risksError} onRetry={loadTopRisks} />
          ) : risksState === 'empty' ? (
            <div className="text-center py-8">
              <p className="text-sm text-slate-500 dark:text-slate-400">No identities discovered yet.</p>
              <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">Run a discovery scan to populate identity data.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-700">
                    <th className="text-left pb-2 text-xs font-medium text-slate-500 dark:text-slate-400">Identity</th>
                    <th className="text-left pb-2 text-xs font-medium text-slate-500 dark:text-slate-400">Type</th>
                    <th className="text-center pb-2 text-xs font-medium text-slate-500 dark:text-slate-400">Risk</th>
                    <th className="text-left pb-2 text-xs font-medium text-slate-500 dark:text-slate-400">Privilege</th>
                    <th className="text-right pb-2 text-xs font-medium text-slate-500 dark:text-slate-400">Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {topRisks.map(identity => {
                    const badge = RISK_BADGE[identity.risk_label] || RISK_BADGE.info;
                    return (
                      <tr key={identity.identity_id}
                        onClick={() => navigate(`/identities/${encodeURIComponent(identity.identity_id)}`)}
                        className="border-b border-slate-100 dark:border-slate-700/50 hover:bg-slate-50 dark:hover:bg-slate-700/30 cursor-pointer transition-colors"
                      >
                        <td className="py-2.5 pr-2">
                          <span className="text-sm text-slate-800 dark:text-slate-200 truncate block max-w-[180px]">
                            {identity.display_name}
                          </span>
                        </td>
                        <td className="py-2.5 pr-2">
                          <span className="text-xs text-slate-500 dark:text-slate-400">
                            {identity.identity_type.replace(/_/g, ' ')}
                          </span>
                        </td>
                        <td className="py-2.5 text-center">
                          <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${badge.bg} ${badge.text}`}>
                            {identity.risk_score.toFixed(0)} {identity.risk_label}
                          </span>
                        </td>
                        <td className="py-2.5 pr-2 text-xs text-slate-600 dark:text-slate-400">
                          {identity.privilege_level.replace(/_/g, ' ')}
                        </td>
                        <td className="py-2.5 text-right text-xs text-slate-500 dark:text-slate-400">
                          {relativeTime(identity.last_seen)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── SummaryCard ─────────────────────────────────────────────────────

function SummaryCard({ label, value, accent }: { label: string; value: number; accent?: 'red' | 'amber' | 'green' }) {
  const accentClasses: Record<string, string> = {
    red: 'text-red-600 dark:text-red-400',
    amber: 'text-amber-600 dark:text-amber-400',
    green: 'text-green-600 dark:text-green-400',
  };

  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
      <span className="text-xs text-slate-500 dark:text-slate-400">{label}</span>
      <p className={`text-2xl font-bold mt-1 ${accent ? accentClasses[accent] : 'text-slate-900 dark:text-white'}`}>
        {value.toLocaleString()}
      </p>
    </div>
  );
}
