import React, { useEffect, useState } from 'react';

interface StageTimingEntry {
  started: number;
  elapsed: number;
}

interface LiveFinding {
  identity_id?: string;
  display_name?: string;
  identity_type?: string;
  risk_level?: 'critical' | 'high' | 'medium' | 'low' | string;
  risk_score_cvss?: number;
  headline?: string;
  discovered_at_offset_s?: number;
}

interface SnapshotJob {
  id: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  stage: string | null;
  progress: number;
  identities_discovered: number;
  resources_discovered: number;
  subscriptions_discovered: number;
  retry_count: number;
  error_message?: string;
  started_at?: string;
  completed_at?: string;
  duration_seconds?: number;
  connection_label?: string;
  connection_cloud?: string;
  stage_timings?: Record<string, StageTimingEntry>;
  estimated_remaining_seconds?: number | null;
  // AG-PS — Progressive Scan: real-time risk breakdown + top findings
  // streamed from the scan engine as identities classify. Updated at
  // ~60% mark (post-risk-analysis). When empty the panel doesn't render.
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  live_findings?: LiveFinding[];
}

interface Props {
  /** Connection ID to poll. If null, polls /api/discovery/status for any active job. */
  connectionId?: number | null;
  connectionLabel?: string;
  connectionCloud?: string;
  onClose: () => void;
  onComplete: () => void;
}

const PHASES = [
  { key: 'initializing',              label: 'Initializing',               icon: '⚙️',  threshold: 5 },
  { key: 'discovering_subscriptions', label: 'Discovering Subscriptions',  icon: '☁️',  threshold: 8 },
  { key: 'discovering_roles',         label: 'Discovering Roles',          icon: '🔑',  threshold: 18 },
  { key: 'discovering_identities',    label: 'Discovering Identities',     icon: '👤',  threshold: 25 },
  { key: 'analyzing_risk',            label: 'Analyzing Risk',             icon: '⚠️',  threshold: 48 },
  { key: 'saving_identities',         label: 'Saving Identities',          icon: '💾',  threshold: 60 },
  { key: 'discovering_resources',     label: 'Discovering Resources',      icon: '🗄️',  threshold: 68 },
  { key: 'discovering_apps',          label: 'App Registrations',          icon: '📋',  threshold: 80 },
  { key: 'finalizing',                label: 'Finalizing',                 icon: '✅',  threshold: 92 },
] as const;

const STAGE_ALIAS: Record<string, string> = {
  discovering_rbac: 'discovering_roles',
};

function resolveStage(raw: string | null): string | null {
  if (!raw) return null;
  return STAGE_ALIAS[raw] || raw;
}

function getPhaseIndex(stage: string | null): number {
  const resolved = resolveStage(stage);
  if (!resolved) return -1;
  return PHASES.findIndex(p => p.key === resolved);
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}m ${s}s`;
}

export function DiscoveryProgressModal({
  connectionId,
  connectionLabel = 'Discovery',
  connectionCloud = 'azure',
  onClose,
  onComplete,
}: Props) {
  const [job, setJob] = useState<SnapshotJob | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const [completed, setCompleted] = useState(false);
  const [failed, setFailed] = useState(false);
  // Track if we ever saw a running job (to distinguish "not started yet" from "completed")
  const [sawRunning, setSawRunning] = useState(false);

  // Poll job status
  useEffect(() => {
    let cancelled = false;
    let pollCount = 0;

    const poll = async () => {
      pollCount++;
      try {
        if (connectionId) {
          // Poll specific connection
          const r = await fetch(`/api/discovery/jobs/${connectionId}`);
          if (!r.ok || cancelled) return;
          const d = await r.json();
          if (d.active_job) {
            setJob(d.active_job);
            setSawRunning(true);
            if (d.active_job.status === 'failed') setFailed(true);
          } else if (sawRunning || pollCount > 3) {
            // Job left the active set → completed. Adopt the finalized job
            // record so we show the real identities_discovered count (the last
            // in-flight poll still had 0 before the final metrics write).
            if (d.last_job) setJob(d.last_job);
            if (d.last_job?.status === 'failed') setFailed(true);
            else setCompleted(true);
          }
        } else {
          // Poll org-level status for any active job
          const r = await fetch('/api/discovery/status');
          if (!r.ok || cancelled) return;
          const d = await r.json();
          // Check jobs array for any active
          const activeJob = (d.jobs || []).find(
            (j: any) => j.status === 'queued' || j.status === 'running'
          );
          if (activeJob) {
            setJob(activeJob);
            setSawRunning(true);
            if (activeJob.status === 'failed') setFailed(true);
          } else if (sawRunning || pollCount > 5) {
            // No active job → adopt the most recent (finalized) job so the
            // summary shows the real counts, not the last in-flight 0.
            const latest = (d.jobs || [])[0];
            if (latest) setJob(latest);
            if (latest?.status === 'failed') setFailed(true);
            else setCompleted(true);
          }
        }
      } catch { /* ignore */ }
    };

    poll();
    const interval = setInterval(poll, 2000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [connectionId, sawRunning]);

  // Elapsed timer
  useEffect(() => {
    if (completed || failed) return;
    const t = setInterval(() => setElapsed(e => e + 1), 1000);
    return () => clearInterval(t);
  }, [completed, failed]);

  // Freeze elapsed time at completion
  const [finalElapsed, setFinalElapsed] = useState<number | null>(null);
  useEffect(() => {
    if (completed && finalElapsed === null) {
      setFinalElapsed(job?.duration_seconds || elapsed);
    }
  }, [completed, finalElapsed, job?.duration_seconds, elapsed]);

  const currentStage = resolveStage(job?.stage || null);
  const currentPhaseIdx = getPhaseIndex(currentStage);
  const progress = completed ? 100 : (job?.progress || 0);
  const isRunning = job?.status === 'running';
  const identities = job?.identities_discovered || 0;
  const resources = job?.resources_discovered || 0;
  const subscriptions = job?.subscriptions_discovered || 0;
  const label = job?.connection_label || connectionLabel;
  const cloud = job?.connection_cloud || connectionCloud;
  const eta = job?.estimated_remaining_seconds;
  const stageTimings = job?.stage_timings || {};

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl w-full max-w-lg mx-4 overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200 dark:border-slate-700 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-gray-900 dark:text-white">
              {completed ? 'Scan Complete' : failed ? 'Snapshot Failed' : 'Capturing Snapshot'}
            </h2>
            <p className="text-xs text-gray-500 dark:text-slate-400 mt-0.5">
              {label} · {cloud.toUpperCase()}
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 dark:hover:text-slate-300 text-lg leading-none"
          >
            ×
          </button>
        </div>

        {/* Progress bar */}
        <div className="px-6 pt-4">
          <div className="flex items-center justify-between text-xs text-gray-500 dark:text-slate-400 mb-1.5">
            <span>{completed ? 'Complete' : failed ? 'Failed' : (currentStage ? PHASES.find(p => p.key === currentStage)?.label || currentStage : 'Queued')}</span>
            <span className="font-mono">{progress}%</span>
          </div>
          <div className="w-full bg-gray-200 dark:bg-slate-700 rounded-full h-2">
            <div
              className={`h-2 rounded-full transition-all duration-700 ease-out ${
                completed ? 'bg-green-500' : failed ? 'bg-red-500' : 'bg-blue-500'
              }`}
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        {/* Phase checklist */}
        <div className="px-6 py-4 space-y-1">
          {PHASES.map((phase, idx) => {
            const isDone = completed || (currentPhaseIdx > idx) || (progress >= phase.threshold + 8 && currentPhaseIdx >= idx);
            const isActive = !completed && !failed && currentPhaseIdx === idx;

            return (
              <div
                key={phase.key}
                className={`flex items-center gap-3 py-1.5 px-2 rounded-md transition-colors ${
                  isActive ? 'bg-blue-50 dark:bg-blue-900/20' : ''
                }`}
              >
                <span className="w-5 h-5 flex items-center justify-center text-sm flex-shrink-0">
                  {isDone ? (
                    <svg className="w-4 h-4 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                  ) : isActive ? (
                    <span className="w-3.5 h-3.5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <span className="w-3 h-3 rounded-full bg-gray-200 dark:bg-slate-600" />
                  )}
                </span>
                <span className={`text-sm flex-1 ${
                  isDone ? 'text-gray-500 dark:text-slate-400' :
                  isActive ? 'text-blue-700 dark:text-blue-400 font-medium' :
                  'text-gray-400 dark:text-slate-500'
                }`}>
                  {phase.icon} {phase.label}
                </span>
                {/* Per-phase elapsed time */}
                {(isDone || isActive) && stageTimings[phase.key] && (
                  <span className="text-[10px] font-mono text-gray-400 dark:text-slate-500 tabular-nums">
                    {formatDuration(Math.round(stageTimings[phase.key].elapsed))}
                  </span>
                )}
              </div>
            );
          })}
        </div>

        {/* Stats */}
        {(identities > 0 || resources > 0 || subscriptions > 0 || elapsed > 0) && (
          <div className="px-6 pb-3">
            <div className="flex flex-wrap gap-4 text-xs text-gray-500 dark:text-slate-400 border-t border-gray-100 dark:border-slate-700 pt-3">
              {subscriptions > 0 && (
                <div className="flex items-center gap-1">
                  <span className="font-medium text-gray-700 dark:text-slate-300">{subscriptions}</span>
                  <span>subscription{subscriptions !== 1 ? 's' : ''}</span>
                </div>
              )}
              {identities > 0 && (
                <div className="flex items-center gap-1">
                  <span className="font-medium text-gray-700 dark:text-slate-300">{identities}</span>
                  <span>identit{identities !== 1 ? 'ies' : 'y'}</span>
                </div>
              )}
              {resources > 0 && (
                <div className="flex items-center gap-1">
                  <span className="font-medium text-gray-700 dark:text-slate-300">{resources}</span>
                  <span>resource{resources !== 1 ? 's' : ''}</span>
                </div>
              )}
              <div className="flex items-center gap-1 ml-auto">
                <span className="font-mono">{formatDuration(job?.duration_seconds || elapsed)}</span>
                {!completed && !failed && eta != null && eta > 0 && (
                  <span className="text-blue-500 dark:text-blue-400 font-mono ml-2">
                    ~{formatDuration(eta)} left
                  </span>
                )}
              </div>
            </div>
          </div>
        )}

        {/* AG-PS — Progressive Scan: live risk breakdown chips. Appears as
            soon as the engine writes risk counts (around the 60% mark);
            stays visible through completion. Real counts from this scan. */}
        {((job?.critical_count || 0) + (job?.high_count || 0) + (job?.medium_count || 0) + (job?.low_count || 0)) > 0 && (
          <div className="px-6 pb-3">
            <div className="flex flex-wrap gap-2 text-[11px]">
              {(job?.critical_count || 0) > 0 && (
                <span className="px-2 py-0.5 rounded-full bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300 font-medium">
                  {job?.critical_count} critical
                </span>
              )}
              {(job?.high_count || 0) > 0 && (
                <span className="px-2 py-0.5 rounded-full bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300 font-medium">
                  {job?.high_count} high
                </span>
              )}
              {(job?.medium_count || 0) > 0 && (
                <span className="px-2 py-0.5 rounded-full bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300 font-medium">
                  {job?.medium_count} medium
                </span>
              )}
              {(job?.low_count || 0) > 0 && (
                <span className="px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300 font-medium">
                  {job?.low_count} low
                </span>
              )}
            </div>
          </div>
        )}

        {/* AG-PS — Live findings ticker: top critical+high identities as they
            classify. Sourced from real scan data (identity.risk_factors[0]
            description). Renders nothing pre-classification. */}
        {(job?.live_findings && job.live_findings.length > 0) && (
          <div className="px-6 pb-3">
            <div className="text-[10px] uppercase tracking-wider text-gray-500 dark:text-slate-400 mb-1.5 flex items-center gap-1.5">
              <svg className="w-3 h-3 text-red-500" fill="currentColor" viewBox="0 0 8 8"><circle cx="4" cy="4" r="4" /></svg>
              Live findings — top {job.live_findings.length} highest-risk
            </div>
            <div className="space-y-1 max-h-44 overflow-y-auto">
              {job.live_findings.map((f, i) => {
                const sevColor =
                  f.risk_level === 'critical' ? 'bg-red-500' :
                  f.risk_level === 'high'     ? 'bg-orange-500' :
                  f.risk_level === 'medium'   ? 'bg-amber-500' :
                  'bg-emerald-500';
                return (
                  <div key={i} className="flex items-center gap-2 text-[11px]">
                    <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${sevColor}`} />
                    {typeof f.discovered_at_offset_s === 'number' && (
                      <span className="font-mono text-gray-400 dark:text-slate-500 tabular-nums w-9 flex-shrink-0 text-right">
                        +{f.discovered_at_offset_s}s
                      </span>
                    )}
                    <span className="text-gray-700 dark:text-slate-200 truncate flex-1" title={f.display_name || ''}>
                      {f.display_name || f.identity_id}
                    </span>
                    <span className="text-gray-500 dark:text-slate-400 truncate max-w-[180px]" title={f.headline || ''}>
                      {f.headline}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Error message */}
        {failed && job?.error_message && (
          <div className="px-6 pb-3">
            <div className="bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 text-xs rounded-md p-3">
              {job.error_message.slice(0, 300)}
            </div>
          </div>
        )}

        {/* Retry info */}
        {job?.retry_count && job.retry_count > 0 && !completed && (
          <div className="px-6 pb-3">
            <div className="bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400 text-xs rounded-md p-2">
              Retry attempt {job.retry_count}
            </div>
          </div>
        )}

        {/* Completion summary */}
        {completed && (() => {
          // P0-A (2026-05-30): show the actionable vs Microsoft-managed split
          // when the backend provides it, so CISOs see the real number of
          // identities they need to govern (not the raw scan count which
          // includes ~1000+ Microsoft-internal service principals).
          const actionable = (job as any)?.identities_actionable as number | undefined;
          const msManaged = (job as any)?.identities_microsoft_managed as number | undefined;
          const haveSplit = typeof actionable === 'number' && typeof msManaged === 'number' && (actionable + msManaged) > 0;
          return (
            <div className="px-6 pb-3">
              <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800/40 rounded-lg px-4 py-3">
                <div className="flex items-center gap-2">
                  <svg className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                  <div>
                    <p className="text-sm font-medium text-green-800 dark:text-green-300">
                      Scan Complete — {haveSplit
                        ? `${actionable!.toLocaleString()} actionable identit${actionable === 1 ? 'y' : 'ies'}`
                        : `${identities.toLocaleString()} identit${identities !== 1 ? 'ies' : 'y'} discovered`}
                    </p>
                    {haveSplit && msManaged! > 0 && (
                      <p className="text-[11px] text-green-700 dark:text-green-400 mt-0.5">
                        {msManaged!.toLocaleString()} Microsoft-managed system identit{msManaged === 1 ? 'y' : 'ies'} filtered from dashboards
                      </p>
                    )}
                    <p className="text-xs text-green-700 dark:text-green-400 mt-0.5">
                      Total scan time: {formatDuration(finalElapsed ?? elapsed)}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          );
        })()}

        {/* Footer */}
        <div className="px-6 py-3 border-t border-gray-200 dark:border-slate-700 flex items-center justify-between">
          {completed ? (
            <>
              <button
                onClick={onClose}
                className="px-4 py-1.5 text-gray-600 dark:text-slate-400 text-xs font-medium hover:text-gray-800 dark:hover:text-slate-200 transition-colors"
              >
                Close
              </button>
              <button
                onClick={onComplete}
                className="px-4 py-1.5 bg-blue-600 text-white text-xs font-medium rounded-md hover:bg-blue-700 transition-colors"
              >
                View Results
              </button>
            </>
          ) : failed ? (
            <>
              <span className="text-xs text-red-500">Discovery failed</span>
              <button
                onClick={onClose}
                className="px-4 py-1.5 bg-gray-600 text-white text-xs font-medium rounded-md hover:bg-gray-700 transition-colors"
              >
                Close
              </button>
            </>
          ) : (
            <>
              <span className="text-xs text-gray-400 dark:text-slate-500">
                {isRunning ? 'Discovery in progress...' : 'Waiting to start...'}
              </span>
              <button
                onClick={onClose}
                className="px-4 py-1.5 text-gray-600 dark:text-slate-400 text-xs font-medium hover:text-gray-800 dark:hover:text-slate-200 transition-colors"
              >
                Run in Background
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
