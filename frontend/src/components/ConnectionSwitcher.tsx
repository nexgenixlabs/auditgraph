import React from 'react';
import { useConnection } from '../contexts/ConnectionContext';

export default function ConnectionSwitcher() {
  const { connections, selectedConnectionId, setSelectedConnectionId } = useConnection();

  // Only show when 2+ connections exist
  if (connections.length < 2) return null;

  return (
    <div className="flex items-center gap-2 px-4 py-2 bg-gray-50 dark:bg-slate-900 border-b border-gray-200 dark:border-slate-700 text-sm">
      <span className="text-gray-500 dark:text-slate-400 text-xs font-medium">Connection:</span>
      <button
        onClick={() => setSelectedConnectionId(null)}
        className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
          selectedConnectionId === null
            ? 'bg-blue-600 text-white'
            : 'bg-white dark:bg-slate-800 border border-gray-200 dark:border-slate-600 text-gray-700 dark:text-slate-300 hover:bg-gray-100 dark:hover:bg-slate-700'
        }`}
      >
        All
      </button>
      {connections.map(c => {
        const isCross = !!(c.metadata?.auto_discovered);
        return (
          <button
            key={c.id}
            onClick={() => setSelectedConnectionId(c.id)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors flex items-center ${
              selectedConnectionId === c.id
                ? (isCross ? 'bg-purple-600 text-white' : 'bg-blue-600 text-white')
                : 'bg-white dark:bg-slate-800 border border-gray-200 dark:border-slate-600 text-gray-700 dark:text-slate-300 hover:bg-gray-100 dark:hover:bg-slate-700'
            }`}
          >
            {isCross && <span className="inline-block w-1.5 h-1.5 rounded-full bg-purple-400 mr-1.5" />}
            {c.label}
          </button>
        );
      })}
    </div>
  );
}
