import React, { useEffect, useState, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { RISK_BADGE, getCategoryShortLabel } from '../constants/metrics';

interface SearchResult {
  identity_id: string;
  display_name: string;
  risk_level: string;
  identity_category: string;
}

interface SearchModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const SearchModal: React.FC<SearchModalProps> = ({ isOpen, onClose }) => {
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(0);

  // Focus input when modal opens
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
    } else {
      setQuery('');
      setResults([]);
      setSelectedIndex(0);
    }
  }, [isOpen]);

  // Debounced search
  const handleQueryChange = useCallback((value: string) => {
    setQuery(value);
    setSelectedIndex(0);
    if (timerRef.current) clearTimeout(timerRef.current);
    if (!value.trim()) {
      setResults([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    timerRef.current = setTimeout(async () => {
      try {
        const res = await fetch(`/api/identities?search=${encodeURIComponent(value)}&limit=8`);
        if (res.ok) {
          const data = await res.json();
          setResults(data.identities || []);
        }
      } catch { /* ignore */ }
      finally { setLoading(false); }
    }, 300);
  }, []);

  const handleSelect = (identityId: string) => {
    onClose();
    navigate(`/identities/${encodeURIComponent(identityId)}`);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex(prev => Math.min(prev + 1, results.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex(prev => Math.max(prev - 1, 0));
    } else if (e.key === 'Enter' && results.length > 0) {
      e.preventDefault();
      handleSelect(results[selectedIndex].identity_id);
    } else if (e.key === 'Escape') {
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-50 bg-black/40" onClick={onClose} />

      {/* Modal */}
      <div className="fixed top-[20%] left-1/2 -translate-x-1/2 w-full max-w-lg z-50">
        <div className="bg-white rounded-xl shadow-2xl border overflow-hidden">
          {/* Search input */}
          <div className="flex items-center gap-3 px-4 py-3 border-b">
            <svg className="w-5 h-5 text-gray-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={e => handleQueryChange(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Search identities by name or ID..."
              className="flex-1 text-sm text-gray-900 placeholder-gray-400 outline-none bg-transparent"
            />
            {loading && (
              <svg className="animate-spin h-4 w-4 text-gray-400" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
            )}
            <kbd className="hidden sm:inline-flex items-center px-1.5 py-0.5 text-[10px] font-mono text-gray-400 bg-gray-100 rounded border">
              ESC
            </kbd>
          </div>

          {/* Results */}
          <div className="max-h-80 overflow-y-auto">
            {!query.trim() ? (
              <div className="px-4 py-8 text-center text-sm text-gray-400">
                Type to search identities...
              </div>
            ) : !loading && results.length === 0 ? (
              <div className="px-4 py-8 text-center text-sm text-gray-400">
                No identities found for "{query}"
              </div>
            ) : (
              <div className="divide-y">
                {results.map((result, idx) => {
                  const badgeClass = RISK_BADGE[result.risk_level?.toLowerCase()] || 'bg-gray-100 text-gray-600';
                  return (
                    <button
                      key={result.identity_id}
                      onClick={() => handleSelect(result.identity_id)}
                      className={`w-full text-left px-4 py-3 flex items-center gap-3 transition ${
                        idx === selectedIndex ? 'bg-blue-50' : 'hover:bg-gray-50'
                      }`}
                    >
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium text-gray-900 truncate">
                          {result.display_name || result.identity_id}
                        </div>
                        <div className="text-xs text-gray-400 truncate font-mono">
                          {result.identity_id}
                        </div>
                      </div>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${badgeClass}`}>
                        {result.risk_level || 'unknown'}
                      </span>
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-gray-100 text-gray-600">
                        {getCategoryShortLabel(result.identity_category)}
                      </span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Footer hint */}
          <div className="border-t px-4 py-2 flex items-center gap-4 text-[10px] text-gray-400">
            <span className="flex items-center gap-1">
              <kbd className="px-1 py-0.5 bg-gray-100 rounded border font-mono">Up</kbd>
              <kbd className="px-1 py-0.5 bg-gray-100 rounded border font-mono">Down</kbd>
              navigate
            </span>
            <span className="flex items-center gap-1">
              <kbd className="px-1 py-0.5 bg-gray-100 rounded border font-mono">Enter</kbd>
              select
            </span>
            <span className="flex items-center gap-1">
              <kbd className="px-1 py-0.5 bg-gray-100 rounded border font-mono">Esc</kbd>
              close
            </span>
          </div>
        </div>
      </div>
    </>
  );
};

export default SearchModal;
