import React, { useEffect, useState } from 'react';

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
            // Job disappeared after running → completed
            setCompleted(true);
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
            setCompleted(true);
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

  // Auto-close after completion (3s delay)
  useEffect(() => {
    if (!completed) return;
    const t = setTimeout(() => onComplete(), 3000);
    return () => clearTimeout(t);
  }, [completed, onComplete]);

  const currentStage = resolveStage(job?.stage || null);
  const currentPhaseIdx = getPhaseIndex(currentStage);
  const progress = completed ? 100 : (job?.progress || 0);
  const isRunning = job?.status === 'running';
  const identities = job?.identities_discovered || 0;
  const resources = job?.resources_discovered || 0;
  const subscriptions = job?.subscriptions_discovered || 0;
  const label = job?.connection_label || connectionLabel;
  const cloud = job?.connection_cloud || connectionCloud;

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl w-full max-w-lg mx-4 overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200 dark:border-slate-700 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-gray-900 dark:text-white">
              {completed ? 'Snapshot Complete' : failed ? 'Snapshot Failed' : 'Capturing Snapshot'}
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
                <span className={`text-sm ${
                  isDone ? 'text-gray-500 dark:text-slate-400' :
                  isActive ? 'text-blue-700 dark:text-blue-400 font-medium' :
                  'text-gray-400 dark:text-slate-500'
                }`}>
                  {phase.icon} {phase.label}
                </span>
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
              </div>
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

        {/* Footer */}
        <div className="px-6 py-3 border-t border-gray-200 dark:border-slate-700 flex items-center justify-between">
          {completed ? (
            <>
              <span className="text-xs text-green-600 dark:text-green-400 font-medium">
                Snapshot captured successfully
              </span>
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
