import React from 'react';

export interface FilterOption {
  label: string;
  value: string;
  count?: number;
}

export interface FilterGroup {
  key: string;
  label: string;
  options: FilterOption[];
  value: string | null;
}

interface FilterBarProps {
  filters: FilterGroup[];
  onFilterChange: (key: string, value: string | null) => void;
  /** Max visible filter pills (spec: 6) */
  maxVisible?: number;
  className?: string;
}

/**
 * Filter Bar — horizontal pill-based filter control.
 *
 * Spec: max 6 filter pills visible, overflow into "More" dropdown.
 * Each pill shows the active value or "All" label.
 */
export default function FilterBar({
  filters,
  onFilterChange,
  maxVisible = 6,
  className = '',
}: FilterBarProps) {
  const visibleFilters = filters.slice(0, maxVisible);

  return (
    <div className={`flex items-center gap-2 flex-wrap ${className}`}>
      {visibleFilters.map(filter => (
        <div key={filter.key} className="relative">
          <select
            value={filter.value || ''}
            onChange={e => onFilterChange(filter.key, e.target.value || null)}
            className="appearance-none text-xs font-medium px-3 py-1.5 pr-7 rounded-lg cursor-pointer"
            style={{
              backgroundColor: filter.value ? 'var(--accent-primary-bg)' : 'var(--bg-raised)',
              color: filter.value ? 'var(--accent-primary)' : 'var(--text-secondary)',
              border: `1px solid ${filter.value ? 'var(--border-focus)' : 'var(--border-default)'}`,
            }}
          >
            <option value="">{filter.label}: All</option>
            {filter.options.map(opt => (
              <option key={opt.value} value={opt.value}>
                {opt.label}{opt.count != null ? ` (${opt.count})` : ''}
              </option>
            ))}
          </select>
          {/* Chevron */}
          <svg
            className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 pointer-events-none"
            style={{ color: 'var(--text-muted)' }}
            fill="none" stroke="currentColor" viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      ))}

      {/* Active filter count + clear */}
      {filters.some(f => f.value) && (
        <button
          onClick={() => filters.forEach(f => onFilterChange(f.key, null))}
          className="text-xs px-2 py-1 rounded-lg transition-colors"
          style={{ color: 'var(--accent-primary)' }}
        >
          Clear filters
        </button>
      )}
    </div>
  );
}
