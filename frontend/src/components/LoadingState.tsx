/**
 * AG-POLISH-D (2026-06-10) — Reusable loading state component.
 *
 * Replaces ad-hoc "Loading..." plain text with a polished spinner
 * + contextual copy. Pattern matches EmptyState (variant + size).
 */
import React from 'react';

interface LoadingStateProps {
  // Optional headline — defaults to "Loading…"
  message?: string;
  // Optional sub-line that hints what's loading.
  detail?: string;
  // 'sm' (inline in tables/cards) or 'lg' (full-page hero).
  size?: 'sm' | 'lg';
  // Optional class for the wrapper.
  className?: string;
}

export function LoadingState({ message = 'Loading…', detail, size = 'lg', className }: LoadingStateProps) {
  const padding = size === 'sm' ? 'py-6' : 'py-12';
  const spinSize = size === 'sm' ? 'w-4 h-4' : 'w-6 h-6';
  const textSize = size === 'sm' ? 'text-xs' : 'text-sm';
  return (
    <div className={`text-center ${padding} ${className || ''}`}>
      <div className={`inline-block ${spinSize} border-2 border-blue-500 border-t-transparent rounded-full animate-spin`} />
      <div className={`${textSize} font-medium text-slate-400 mt-3`}>{message}</div>
      {detail && (
        <div className="text-[11px] text-slate-500 mt-1">{detail}</div>
      )}
    </div>
  );
}

// Skeleton variant for table rows — visually closer to what's actually
// going to render than a spinner. Used inside <tbody> as a single row.
export function TableSkeletonRow({ columns, count = 5 }: { columns: number; count?: number }) {
  return (
    <>
      {Array.from({ length: count }).map((_, i) => (
        <tr key={i} className="border-b border-slate-800/40">
          {Array.from({ length: columns }).map((_, j) => (
            <td key={j} className="px-3 py-3">
              <div className="h-3 bg-slate-700/40 rounded animate-pulse" style={{ width: `${60 + Math.random() * 30}%` }} />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}

export default LoadingState;
