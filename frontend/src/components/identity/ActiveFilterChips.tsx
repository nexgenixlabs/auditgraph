/**
 * ActiveFilterChips — horizontal strip showing all active column filters
 * with one-click removal. Sits between the pill bar and the grid.
 */
import React from 'react';

export interface ActiveFilterChipsProps {
  /** Map of field → selected values */
  columnFilters: Record<string, string[]>;
  /** Human-readable label for each field key */
  fieldLabels: Record<string, string>;
  /** Remove a single value from a field filter */
  onRemove: (field: string, value: string) => void;
  /** Clear all column filters at once */
  onClearAll: () => void;
}

export default function ActiveFilterChips({
  columnFilters, fieldLabels, onRemove, onClearAll,
}: ActiveFilterChipsProps) {
  const entries = Object.entries(columnFilters).filter(([, vals]) => vals.length > 0);
  if (entries.length === 0) return null;

  return (
    <div className="flex items-center gap-1.5 flex-wrap px-1 py-1.5 text-xs">
      <span className="text-gray-400 text-[10px] uppercase tracking-wider mr-0.5">Filters:</span>
      {entries.map(([field, values]) =>
        values.map(v => (
          <span
            key={`${field}:${v}`}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-teal-50 text-teal-700 border border-teal-200"
          >
            <span className="text-[10px] text-teal-500">{fieldLabels[field] || field}:</span>
            <span className="font-medium">{v}</span>
            <button
              onClick={() => onRemove(field, v)}
              className="ml-0.5 text-teal-400 hover:text-teal-700 text-sm leading-none"
              aria-label={`Remove ${fieldLabels[field] || field}: ${v} filter`}
            >
              &times;
            </button>
          </span>
        )),
      )}
      <button
        onClick={onClearAll}
        className="text-[11px] text-gray-400 hover:text-gray-600 ml-1"
      >
        Clear all
      </button>
    </div>
  );
}
