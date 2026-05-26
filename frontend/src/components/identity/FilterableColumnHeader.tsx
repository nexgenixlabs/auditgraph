/**
 * FilterableColumnHeader — reusable sortable + filterable table header.
 *
 * Design philosophy (AG-162):
 *   Pills SEGMENT — fast taxonomy switches (All humans / Members / Guests / …)
 *   Column filters REFINE — narrow within current segment
 *   Advanced Query ESCAPES — cross-column logic the dropdowns can't express
 * All three layers coexist. None replaces the others.
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';

/* ── Types ─────────────────────────────────────────────────────────── */

export interface FilterOption {
  value: string;
  label: string;
  count?: number;
  /** Subtle suffix e.g. "· permission needed" */
  suffix?: string;
}

export interface FilterableColumnHeaderProps {
  label: string;
  field: string;
  options?: FilterOption[];
  sortable?: boolean;
  currentSortField: string;
  currentSortDir: 'asc' | 'desc';
  onSort: (field: string) => void;
  activeValues: string[];
  onFilterApply: (field: string, values: string[]) => void;
  /** Extra title/tooltip on the header */
  title?: string;
  /** Append after label (e.g. info icon) */
  labelSuffix?: React.ReactNode;
}

/* ── Component ─────────────────────────────────────────────────────── */

export default function FilterableColumnHeader({
  label, field, options, sortable = true,
  currentSortField, currentSortDir, onSort,
  activeValues, onFilterApply, title, labelSuffix,
}: FilterableColumnHeaderProps) {
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState<string[]>([]);
  const [search, setSearch] = useState('');
  const dropdownRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  // Sync pending with activeValues when dropdown opens
  useEffect(() => {
    if (open) {
      setPending([...activeValues]);
      setSearch('');
    }
  }, [open, activeValues]);

  // Click outside & ESC
  useEffect(() => {
    if (!open) return;
    const handleClick = (e: MouseEvent) => {
      if (
        dropdownRef.current && !dropdownRef.current.contains(e.target as Node) &&
        triggerRef.current && !triggerRef.current.contains(e.target as Node)
      ) setOpen(false);
    };
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { setOpen(false); triggerRef.current?.focus(); }
    };
    document.addEventListener('mousedown', handleClick);
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('mousedown', handleClick);
      document.removeEventListener('keydown', handleKey);
    };
  }, [open]);

  const toggle = useCallback((value: string) => {
    setPending(prev =>
      prev.includes(value) ? prev.filter(v => v !== value) : [...prev, value],
    );
  }, []);

  const apply = useCallback(() => {
    onFilterApply(field, pending);
    setOpen(false);
  }, [field, pending, onFilterApply]);

  const clear = useCallback(() => {
    onFilterApply(field, []);
    setOpen(false);
  }, [field, onFilterApply]);

  const handleKeyInOption = useCallback((e: React.KeyboardEvent, value: string) => {
    if (e.key === ' ') { e.preventDefault(); toggle(value); }
    if (e.key === 'Enter') { e.preventDefault(); apply(); }
  }, [toggle, apply]);

  const isFilterActive = activeValues.length > 0;
  const isSorted = currentSortField === field;
  const hasFilter = options && options.length > 0;

  const filteredOptions = (options || []).filter(
    o => !search || o.label.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <th
      className="px-2 py-2.5 relative whitespace-nowrap text-[10px] font-semibold uppercase tracking-wider text-gray-600"
      title={title}
    >
      <div className="flex items-center gap-0.5">
        {/* Label + sort */}
        {sortable ? (
          <span
            className="cursor-pointer select-none hover:text-blue-600 flex items-center gap-0.5"
            onClick={() => onSort(field)}
            aria-label={`Sort by ${label}, currently ${isSorted ? currentSortDir : 'unsorted'}`}
          >
            {label}{labelSuffix}
            <span className={`text-[10px] ${isSorted ? 'text-blue-600' : 'text-gray-400'}`}>
              {isSorted ? (currentSortDir === 'asc' ? '▲' : '▼') : '↕'}
            </span>
          </span>
        ) : (
          <span>{label}{labelSuffix}</span>
        )}

        {/* Filter funnel */}
        {hasFilter && (
          <button
            ref={triggerRef}
            onClick={() => setOpen(o => !o)}
            className={`p-0.5 rounded transition-colors ${
              isFilterActive
                ? 'text-teal-600 hover:text-teal-700'
                : 'text-gray-300 hover:text-gray-500'
            }`}
            aria-label={`Filter ${label}`}
            title={isFilterActive ? `Filtered: ${activeValues.length} selected` : `Filter ${label}`}
          >
            <svg className="w-2.5 h-2.5" viewBox="0 0 16 16" fill="currentColor">
              <path d="M1 2h14l-5 5.5v4.5l-4 2V7.5z" />
            </svg>
          </button>
        )}
      </div>

      {/* ── Dropdown ──────────────────────────────────────────────── */}
      {open && hasFilter && (
        <div
          ref={dropdownRef}
          className="absolute top-full left-0 mt-1.5 z-50 bg-white border border-gray-200 rounded-lg shadow-xl
                     min-w-[190px] max-h-[340px] flex flex-col text-left normal-case tracking-normal font-normal"
          role="listbox"
          aria-label={`Filter options for ${label}`}
        >
          {/* Triangle pointer */}
          <div className="absolute -top-[5px] left-3 w-2.5 h-2.5 bg-white border-l border-t border-gray-200 rotate-45" />

          {/* Search (6+ options) */}
          {(options?.length ?? 0) >= 6 && (
            <div className="px-2 pt-2 pb-1">
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search…"
                className="w-full px-2 py-1 text-xs border border-gray-200 rounded
                           focus:outline-none focus:ring-1 focus:ring-teal-400"
                autoFocus
              />
            </div>
          )}

          {/* Options list */}
          <div className="overflow-y-auto px-1 py-1 flex-1">
            {filteredOptions.map(opt => (
              <label
                key={opt.value}
                className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-gray-50
                           cursor-pointer text-xs select-none"
                role="option"
                aria-selected={pending.includes(opt.value)}
                tabIndex={0}
                onKeyDown={e => handleKeyInOption(e, opt.value)}
              >
                <input
                  type="checkbox"
                  checked={pending.includes(opt.value)}
                  onChange={() => toggle(opt.value)}
                  className="w-3.5 h-3.5 rounded text-teal-600 focus:ring-teal-500"
                  tabIndex={-1}
                />
                <span className="flex-1 text-gray-700 truncate">{opt.label}</span>
                {opt.suffix && (
                  <span className="text-[10px] text-gray-400 italic whitespace-nowrap">{opt.suffix}</span>
                )}
                {typeof opt.count === 'number' && (
                  <span className="text-[10px] text-gray-400 tabular-nums ml-auto">{opt.count}</span>
                )}
              </label>
            ))}
            {filteredOptions.length === 0 && (
              <div className="px-2 py-3 text-xs text-gray-400 text-center">No matches</div>
            )}
          </div>

          {/* Actions */}
          <div className="flex items-center justify-between border-t border-gray-100 px-2 py-1.5">
            <button
              onClick={clear}
              className="text-[11px] text-gray-500 hover:text-gray-700"
            >
              Clear
            </button>
            <button
              onClick={apply}
              className="px-3 py-1 text-[11px] font-medium bg-teal-600 text-white rounded
                         hover:bg-teal-700 transition-colors"
            >
              Apply
            </button>
          </div>
        </div>
      )}
    </th>
  );
}
