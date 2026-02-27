/**
 * Access Graph — Standalone access exploration page.
 *
 * Wraps AccessGraphTab with an identity search/selector so users can
 * explore any identity's access tree without navigating to IdentityDetail first.
 *
 * Phase 6: Access Explainability consolidation.
 */
import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import AccessGraphTab from '../components/graph/AccessGraphTab';

interface IdentityOption {
  identity_id: string;
  display_name: string;
  identity_category?: string;
}

export default function AccessGraph() {
  const { withConnection } = useConnection();
  const [searchParams, setSearchParams] = useSearchParams();
  const [selectedId, setSelectedId] = useState(searchParams.get('id') || '');
  const [search, setSearch] = useState('');
  const [results, setResults] = useState<IdentityOption[]>([]);
  const [searching, setSearching] = useState(false);
  const [showDropdown, setShowDropdown] = useState(false);

  // Debounced identity search
  useEffect(() => {
    if (search.length < 2) { setResults([]); return; }
    setSearching(true);
    const timer = setTimeout(() => {
      fetch(withConnection(`/api/identities?search=${encodeURIComponent(search)}&limit=10&hide_microsoft=true`))
        .then(r => r.ok ? r.json() : { identities: [] })
        .then(d => {
          setResults((d.identities || []).map((i: any) => ({
            identity_id: i.identity_id,
            display_name: i.display_name,
            identity_category: i.identity_category,
          })));
          setShowDropdown(true);
        })
        .catch(() => setResults([]))
        .finally(() => setSearching(false));
    }, 300);
    return () => clearTimeout(timer);
  }, [search, withConnection]);

  const selectIdentity = useCallback((id: string) => {
    setSelectedId(id);
    setShowDropdown(false);
    setSearch('');
    setSearchParams({ id }, { replace: true });
  }, [setSearchParams]);

  return (
    <div className="p-6 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Access Graph</h1>
          <p className="text-sm text-gray-500 dark:text-slate-400 mt-1">
            Visual exploration of identity access paths, role assignments, and resource scope
          </p>
        </div>
      </div>

      {/* Identity selector */}
      <div className="mb-6 relative max-w-md">
        <label className="block text-xs font-medium text-gray-600 dark:text-slate-400 mb-1">Select Identity</label>
        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          onFocus={() => results.length > 0 && setShowDropdown(true)}
          placeholder="Search by name or ID..."
          className="w-full text-sm border border-gray-300 dark:border-slate-600 rounded-lg px-3 py-2 bg-white dark:bg-slate-800 text-gray-800 dark:text-slate-200"
        />
        {searching && (
          <div className="absolute right-3 top-[30px] text-xs text-gray-400">Searching...</div>
        )}
        {showDropdown && results.length > 0 && (
          <div className="absolute z-20 w-full mt-1 bg-white dark:bg-slate-800 border border-gray-200 dark:border-slate-700 rounded-lg shadow-lg max-h-60 overflow-y-auto">
            {results.map(r => (
              <button
                key={r.identity_id}
                onClick={() => selectIdentity(r.identity_id)}
                className="w-full text-left px-3 py-2 hover:bg-blue-50 dark:hover:bg-slate-700 transition-colors"
              >
                <div className="text-sm font-medium text-gray-800 dark:text-slate-200">{r.display_name}</div>
                <div className="text-[10px] text-gray-400 dark:text-slate-500 font-mono">{r.identity_id.substring(0, 20)}... · {r.identity_category || 'unknown'}</div>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Graph area */}
      {selectedId ? (
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-gray-200 dark:border-slate-700 overflow-hidden" style={{ minHeight: 600 }}>
          <AccessGraphTab identityId={selectedId} />
        </div>
      ) : (
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-gray-200 dark:border-slate-700 flex items-center justify-center" style={{ minHeight: 400 }}>
          <div className="text-center">
            <div className="text-4xl mb-3 opacity-30">&#x1F50D;</div>
            <p className="text-sm text-gray-500 dark:text-slate-400">Search and select an identity above to visualize its access graph</p>
          </div>
        </div>
      )}
    </div>
  );
}
