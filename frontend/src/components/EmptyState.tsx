/**
 * AG-POLISH-A (2026-06-09) — Reusable EmptyState component.
 *
 * Every "no data yet" surface in the app should use this so the
 * customer always sees:
 *   1. What's missing (in their language, not ours)
 *   2. Why (architecture-derived signal we didn't see)
 *   3. What to do next (one clear action)
 *
 * Replaces ad-hoc "—" / "No data" hyphens that were the customer's
 * #1 source of "is this product broken?" confusion in pilot.
 */
import React from 'react';
import { Link } from 'react-router-dom';

interface EmptyStateProps {
  // Headline — one sentence in customer language.
  title: string;
  // Why this is empty — points the customer at the missing signal.
  description?: string;
  // Primary call-to-action (label + href).
  actionLabel?: string;
  actionHref?: string;
  onAction?: () => void;
  // Visual size: 'sm' for inline empty rows, 'lg' for full-page hero.
  size?: 'sm' | 'lg';
  // Severity vibe: 'info' (default), 'warning' (something might be misconfigured),
  //                'success' (truly nothing to fix).
  variant?: 'info' | 'warning' | 'success';
  // Optional icon override.
  icon?: React.ReactNode;
  // Optional secondary info — small grey line below action.
  hint?: string;
}

const VARIANT = {
  info:    { border: 'border-slate-700/40', bg: 'bg-slate-900/40', text: 'text-slate-300', accent: 'text-blue-400' },
  warning: { border: 'border-amber-700/40', bg: 'bg-amber-950/40',  text: 'text-amber-200', accent: 'text-amber-400' },
  success: { border: 'border-emerald-700/40', bg: 'bg-emerald-950/40', text: 'text-emerald-200', accent: 'text-emerald-400' },
} as const;

const DEFAULT_ICONS = {
  info: (
    <svg className="w-8 h-8" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
  warning: (
    <svg className="w-8 h-8" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
    </svg>
  ),
  success: (
    <svg className="w-8 h-8" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
};

export function EmptyState({
  title,
  description,
  actionLabel,
  actionHref,
  onAction,
  size = 'lg',
  variant = 'info',
  icon,
  hint,
}: EmptyStateProps) {
  const v = VARIANT[variant];
  const padding = size === 'sm' ? 'p-4' : 'p-10';
  const titleSize = size === 'sm' ? 'text-sm' : 'text-base';

  return (
    <div className={`rounded-xl border ${v.border} ${v.bg} ${padding} text-center max-w-2xl mx-auto`}>
      <div className={`${v.accent} mb-2 flex justify-center`}>
        {icon || DEFAULT_ICONS[variant]}
      </div>
      <h3 className={`${titleSize} font-semibold ${v.text}`}>{title}</h3>
      {description && (
        <p className="text-xs text-slate-400 mt-2 leading-relaxed max-w-md mx-auto">{description}</p>
      )}
      {(actionLabel && (actionHref || onAction)) && (
        <div className="mt-4">
          {actionHref ? (
            <Link to={actionHref}
                  className={`inline-block px-4 py-2 rounded-lg text-xs font-semibold bg-blue-600 text-white hover:bg-blue-700 transition`}>
              {actionLabel}
            </Link>
          ) : (
            <button onClick={onAction}
                    className={`px-4 py-2 rounded-lg text-xs font-semibold bg-blue-600 text-white hover:bg-blue-700 transition`}>
              {actionLabel}
            </button>
          )}
        </div>
      )}
      {hint && (
        <p className="text-[11px] text-slate-500 mt-2">{hint}</p>
      )}
    </div>
  );
}

// Convenience wrappers — most-common empty-state patterns named so
// callers don't have to think about variant/copy each time.

export function ScanPendingState({ title = 'Discovery scan pending' }: { title?: string }) {
  return (
    <EmptyState
      variant="info"
      title={title}
      description="This panel populates after your first discovery scan completes. AuditGraph derives identity posture from architecture — no telemetry needed — but the first scan has to walk your tenant once to build the graph."
      actionLabel="Trigger discovery"
      actionHref="/settings/connections"
      hint="Read-only · architecture-derived · no agent installed"
    />
  );
}

export function NoDataInScopeState({ title, subjects = 'identities' }: { title?: string; subjects?: string }) {
  return (
    <EmptyState
      variant="success"
      title={title || `No ${subjects} at risk`}
      description={`AuditGraph evaluated every ${subjects} in your tenant and didn't find any with this risk pattern. This is a good state — continue monitoring for drift.`}
    />
  );
}

export function NotConfiguredState({ what, configureHref = '/settings/connections' }: { what: string; configureHref?: string }) {
  return (
    <EmptyState
      variant="warning"
      title={`${what} not configured`}
      description={`This view needs ${what} to be enabled before it can populate. AuditGraph never auto-enables — your IAM admin makes the call.`}
      actionLabel="Configure now"
      actionHref={configureHref}
    />
  );
}

export default EmptyState;
