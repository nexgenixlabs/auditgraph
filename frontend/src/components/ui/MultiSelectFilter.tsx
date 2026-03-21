import React, { useState, useRef, useEffect, useMemo } from 'react';

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
}

export function MultiSelectFilter({ options, selected, onChange, label, placeholder = 'Filter...' }: MultiSelectFilterProps) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [localSelected, setLocalSelected] = useState<string[]>(selected);
  const ref = useRef<HTMLDivElement>(null);

  // Sync local state when props change
  useEffect(() => { setLocalSelected(selected); }, [selected]);

  // Close on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as HTMLElement)) {
        setOpen(false);
        setSearch('');
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const filtered = useMemo(() => {
    if (!search) return options;
    const q = search.toLowerCase();
    return options.filter(o => o.label.toLowerCase().includes(q) || o.value.toLowerCase().includes(q));
  }, [options, search]);

  const toggle = (value: string) => {
    setLocalSelected(prev =>
      prev.includes(value) ? prev.filter(v => v !== value) : [...prev, value]
    );
  };

  const handleApply = () => {
    onChange(localSelected);
    setOpen(false);
    setSearch('');
  };

  const handleClear = () => {
    setLocalSelected([]);
    onChange([]);
    setOpen(false);
    setSearch('');
  };

  const selectAll = () => setLocalSelected(filtered.map(o => o.value));
  const deselectAll = () => setLocalSelected([]);

  const buttonLabel = selected.length === 0
    ? (label || 'All')
    : selected.length === options.length
      ? (label || 'All')
      : `${selected.length} selected`;

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(!open)}
        className={`flex items-center gap-1.5 px-2.5 py-1.5 text-xs border rounded-md transition ${
          selected.length > 0 && selected.length < options.length
            ? 'border-blue-400 bg-blue-50 text-blue-700'
            : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50'
        }`}
      >
        <span>{label ? `${label}: ` : ''}{buttonLabel}</span>
        <svg className={`w-3 h-3 transition-transform ${open ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {open && (
        <div className="absolute z-30 mt-1 w-72 bg-white border border-gray-200 rounded-lg shadow-xl">
          {/* Search */}
          <div className="p-2 border-b border-gray-100">
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder={placeholder}
              className="w-full px-2.5 py-1.5 text-xs border border-gray-200 rounded-md focus:ring-1 focus:ring-blue-400 focus:border-blue-400 outline-none"
              autoFocus
            />
          </div>

          {/* Select All / Deselect All */}
          <div className="flex items-center justify-between px-3 py-1.5 border-b border-gray-100 text-[10px] text-gray-500">
            <span>{localSelected.length} of {options.length} selected</span>
            <div className="flex gap-2">
              <button onClick={selectAll} className="text-blue-600 hover:underline">All</button>
              <button onClick={deselectAll} className="text-blue-600 hover:underline">None</button>
            </div>
          </div>

          {/* Options list */}
          <div className="max-h-56 overflow-y-auto py-1">
            {filtered.length === 0 ? (
              <div className="px-3 py-4 text-center text-xs text-gray-400">No matches</div>
            ) : filtered.map(opt => (
              <label
                key={opt.value}
                className="flex items-center gap-2.5 px-3 py-1.5 hover:bg-gray-50 cursor-pointer"
              >
                <input
                  type="checkbox"
                  checked={localSelected.includes(opt.value)}
                  onChange={() => toggle(opt.value)}
                  className="w-3.5 h-3.5 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-xs text-gray-700 flex-1 truncate">{opt.label}</span>
                {opt.active !== undefined && (
                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold ${
                    opt.active
                      ? 'bg-green-100 text-green-700'
                      : 'bg-gray-100 text-gray-500'
                  }`}>
                    {opt.active ? 'Active' : 'Inactive'}
                  </span>
                )}
              </label>
            ))}
          </div>

          {/* Footer: Apply / Clear */}
          <div className="flex items-center justify-between px-3 py-2 border-t border-gray-100 bg-gray-50 rounded-b-lg">
            <button
              onClick={handleClear}
              className="text-xs text-gray-500 hover:text-gray-700"
            >
              Clear
            </button>
            <button
              onClick={handleApply}
              className="px-3 py-1 text-xs font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 transition"
            >
              Apply
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
