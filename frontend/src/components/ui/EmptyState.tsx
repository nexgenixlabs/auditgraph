import React from 'react';

interface EmptyStateProps {
  /** Headline copy. Required. */
  title: string;
  /** Optional sub-copy explaining what to do. */
  description?: string;
  /** Optional icon (svg/jsx) shown above the title. */
  icon?: React.ReactNode;
  /** Optional action — call-to-action button or link. */
  action?: React.ReactNode;
  /** Compact mode for use inside table cells (no icon, smaller padding). */
  compact?: boolean;
  className?: string;
}

/**
 * EmptyState — single primitive for "nothing here yet" UX across the app.
 * Use the default (block) mode for full-page or full-section empty states;
 * use `compact` mode inside `<td colSpan=...>` for "no rows match filters"
 * inside tables. Colors come from dark-theme CSS variables so it never
 * leaks light-theme grey on top of dark surfaces.
 */
export default function EmptyState({
  title,
  description,
  icon,
  action,
  compact = false,
  className = '',
}: EmptyStateProps) {
  if (compact) {
    return (
      <div
        className={`text-center ${className}`}
        style={{ padding: '24px 16px', color: 'var(--text-tertiary)', fontSize: 13 }}
      >
        {title}
        {description && (
          <div style={{ marginTop: 4, fontSize: 12, color: 'var(--text-tertiary)' }}>{description}</div>
        )}
      </div>
    );
  }

  return (
    <div
      className={`flex flex-col items-center justify-center text-center ${className}`}
      style={{ padding: '48px 24px', color: 'var(--text-tertiary)' }}
    >
      {icon && (
        <div className="mb-3" style={{ color: 'var(--text-tertiary)', opacity: 0.6 }}>
          {icon}
        </div>
      )}
      <div style={{ color: 'var(--text-secondary)', fontWeight: 600, fontSize: 14, marginBottom: description ? 4 : 0 }}>
        {title}
      </div>
      {description && (
        <div style={{ color: 'var(--text-tertiary)', fontSize: 12, maxWidth: 380, lineHeight: 1.5 }}>
          {description}
        </div>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
