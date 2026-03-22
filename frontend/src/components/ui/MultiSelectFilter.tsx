import React, { useState, useRef, useEffect, useMemo, useCallback } from 'react';

export interface SelectOption {
  value: string;
  label: string;
  active?: boolean;
}

interface MultiSelectFilterProps {
  options: SelectOption[];
  selected: string[];
  onChange: (selected: string[]) => void;
  label?: string;
  placeholder?: string;
  searchable?: boolean;
  showSelectAll?: boolean;
}

/**
 * Excel-style multi-select dropdown with checkboxes, search, Select All.
 *
 * - Empty selection = "All" (no filter applied)
 * - 1–2 selected → shows labels
 * - >2 → shows first two labels + "+N"
 * - Select All checkbox toggles all visible options
 * - Search with debounce for large lists
 * - Dark theme via Tailwind classes (auto-remapped by [data-theme] CSS)
 */
export function MultiSelectFilter({
  options,
  selected,
  onChange,
  label,
  placeholder = 'Search…',
  searchable = true,
  showSelectAll = true,
}: MultiSelectFilterProps) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const ref = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  // Debounce search input (150ms)
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search), 150);
    return () => clearTimeout(t);
  }, [search]);

  // Close on outside click
  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as HTMLElement)) {
        setOpen(false);
        setSearch('');
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  // Auto-focus search when opened
  useEffect(() => {
    if (open && searchRef.current) {
      searchRef.current.focus();
    }
  }, [open]);

  const filtered = useMemo(() => {
    if (!debouncedSearch) return options;
    const q = debouncedSearch.toLowerCase();
    return options.filter(o => o.label.toLowerCase().includes(q) || o.value.toLowerCase().includes(q));
  }, [options, debouncedSearch]);

  const toggle = useCallback((value: string) => {
    const next = selected.includes(value)
      ? selected.filter(v => v !== value)
      : [...selected, value];
    onChange(next);
  }, [selected, onChange]);

  const handleSelectAll = useCallback(() => {
    const allFilteredValues = filtered.map(o => o.value);
    const allFilteredSelected = allFilteredValues.every(v => selected.includes(v));
    if (allFilteredSelected) {
      // Deselect all filtered items (keep items not in current filter)
      onChange(selected.filter(v => !allFilteredValues.includes(v)));
    } else {
      // Select all filtered items (merge with existing)
      const merged = new Set([...selected, ...allFilteredValues]);
      onChange(Array.from(merged));
    }
  }, [filtered, selected, onChange]);

  const handleClearAll = useCallback(() => {
    onChange([]);
    setOpen(false);
    setSearch('');
  }, [onChange]);

  // Display label logic
  const displayLabel = useMemo(() => {
    if (selected.length === 0 || selected.length === options.length) return 'All';
    const selectedLabels = selected
      .map(v => options.find(o => o.value === v)?.label || v)
      .slice(0, 2);
    const remainder = selected.length - selectedLabels.length;
    return remainder > 0
      ? `${selectedLabels.join(', ')} +${remainder}`
      : selectedLabels.join(', ');
  }, [selected, options]);

  const isActive = selected.length > 0 && selected.length < options.length;
  const allFilteredSelected = filtered.length > 0 && filtered.every(o => selected.includes(o.value));
  const someFilteredSelected = filtered.some(o => selected.includes(o.value));

  return (
    <div className="relative" ref={ref}>
      {/* Trigger button */}
      <button
        onClick={() => setOpen(!open)}
        className={`flex items-center gap-1.5 w-full px-3 py-1.5 text-sm border rounded-lg transition-all truncate ${
          isActive
            ? 'border-blue-500/50 bg-blue-500/10 text-blue-400'
            : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50'
        }`}
      >
        <span className="truncate flex-1 text-left">
          {label ? `${label}: ` : ''}{displayLabel}
        </span>
        <svg
          className={`w-3.5 h-3.5 flex-shrink-0 transition-transform ${open ? 'rotate-180' : ''}`}
          fill="none" stroke="currentColor" viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Dropdown panel */}
      {open && (
        <div className="absolute z-50 mt-1 w-72 bg-white border border-gray-200 rounded-xl shadow-2xl overflow-hidden"
          style={{ minWidth: '16rem' }}
        >
          {/* Search input */}
          {searchable && (
            <div className="p-2 border-b border-gray-100">
              <div className="relative">
                <svg className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
                <input
                  ref={searchRef}
                  type="text"
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder={placeholder}
                  className="w-full pl-7 pr-2.5 py-1.5 text-xs border border-gray-200 rounded-lg focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none bg-gray-50 text-gray-700"
                />
              </div>
            </div>
          )}

          {/* Select All + count */}
          {showSelectAll && (
            <div className="flex items-center justify-between px-3 py-1.5 border-b border-gray-100">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={allFilteredSelected}
                  ref={el => {
                    if (el) el.indeterminate = someFilteredSelected && !allFilteredSelected;
                  }}
                  onChange={handleSelectAll}
                  className="w-3.5 h-3.5 rounded border-gray-300 text-blue-600 focus:ring-blue-500 cursor-pointer"
                />
                <span className="text-xs text-gray-600 font-medium">Select All</span>
              </label>
              <span className="text-[10px] text-gray-400 tabular-nums">
                {selected.length} of {options.length}
              </span>
            </div>
          )}

          {/* Options list */}
          <div className="max-h-56 overflow-y-auto py-0.5">
            {filtered.length === 0 ? (
              <div className="px-3 py-4 text-center text-xs text-gray-400">No results</div>
            ) : filtered.map(opt => {
              const isChecked = selected.includes(opt.value);
              return (
                <label
                  key={opt.value}
                  className={`flex items-center gap-2.5 px-3 py-1.5 cursor-pointer transition-colors ${
                    isChecked ? 'bg-blue-50' : 'hover:bg-gray-50'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={isChecked}
                    onChange={() => toggle(opt.value)}
                    className="w-3.5 h-3.5 rounded border-gray-300 text-blue-600 focus:ring-blue-500 cursor-pointer"
                  />
                  <span className="text-xs text-gray-700 flex-1 truncate">{opt.label}</span>
                  {opt.active !== undefined && (
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold ${
                      opt.active ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'
                    }`}>
                      {opt.active ? 'Active' : 'Inactive'}
                    </span>
                  )}
                </label>
              );
            })}
          </div>

          {/* Footer: Clear all */}
          {selected.length > 0 && (
            <div className="flex items-center justify-center px-3 py-1.5 border-t border-gray-100 bg-gray-50">
              <button
                onClick={handleClearAll}
                className="text-xs text-blue-600 hover:text-blue-700 font-medium"
              >
                Clear all filters
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
