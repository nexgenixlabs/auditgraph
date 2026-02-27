import React from 'react';
import { WIDGET_GROUPS, getWidgetMeta } from './widgetRegistry';
import type { WidgetPref } from './widgetRegistry';

interface CustomizePanelProps {
  open: boolean;
  onClose: () => void;
  widgets: WidgetPref[];
  toggleWidget: (id: string) => void;
  moveWidget: (id: string, direction: 'up' | 'down') => void;
  save: () => Promise<boolean>;
  reset: () => Promise<void>;
  saving: boolean;
  dirty: boolean;
}

export default function CustomizePanel({
  open, onClose, widgets, toggleWidget, moveWidget, save, reset, saving, dirty,
}: CustomizePanelProps) {
  if (!open) return null;

  const handleSave = async () => {
    await save();
  };

  const handleReset = async () => {
    await reset();
  };

  // Group widgets by their registry group, preserving current order
  const grouped = WIDGET_GROUPS.map(g => ({
    ...g,
    items: widgets.filter(w => {
      const meta = getWidgetMeta(w.id);
      return meta?.group === g.key;
    }),
  })).filter(g => g.items.length > 0);

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-40 bg-black/30" onClick={onClose} />

      {/* Panel */}
      <div className="fixed inset-y-0 right-0 z-50 w-full max-w-sm bg-white shadow-lg border-l flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Customize Dashboard</h3>
            <p className="text-xs text-gray-500 mt-0.5">Toggle visibility and reorder widgets</p>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-gray-100 text-gray-400 hover:text-gray-600 transition"
          >
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Widget list */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
          {grouped.map(group => (
            <div key={group.key}>
              <div className="text-[10px] font-semibold uppercase tracking-wider text-gray-400 mb-2">
                {group.label}
              </div>
              <div className="space-y-1">
                {group.items.map(w => {
                  const meta = getWidgetMeta(w.id);
                  if (!meta) return null;
                  const globalIdx = widgets.findIndex(x => x.id === w.id);
                  return (
                    <div
                      key={w.id}
                      className={`flex items-center gap-2 px-3 py-2 rounded-lg border transition ${
                        w.visible
                          ? 'bg-white border-gray-200'
                          : 'bg-gray-50 border-gray-100 opacity-60'
                      }`}
                    >
                      {/* Toggle */}
                      <button
                        onClick={() => toggleWidget(w.id)}
                        className={`relative inline-flex h-4 w-7 items-center rounded-full transition-colors flex-shrink-0 ${
                          w.visible ? 'bg-blue-500' : 'bg-gray-300'
                        }`}
                      >
                        <span className={`inline-block h-3 w-3 transform rounded-full bg-white transition-transform ${
                          w.visible ? 'translate-x-3.5' : 'translate-x-0.5'
                        }`} />
                      </button>

                      {/* Label */}
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium text-gray-800 truncate">{meta.label}</div>
                        <div className="text-[10px] text-gray-400 truncate">{meta.description}</div>
                      </div>

                      {/* Move arrows */}
                      <div className="flex flex-col gap-0.5 flex-shrink-0">
                        <button
                          onClick={() => moveWidget(w.id, 'up')}
                          disabled={globalIdx === 0}
                          className={`p-0.5 rounded text-gray-400 transition ${
                            globalIdx === 0
                              ? 'opacity-30 cursor-not-allowed'
                              : 'hover:bg-gray-200 hover:text-gray-600'
                          }`}
                        >
                          <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
                          </svg>
                        </button>
                        <button
                          onClick={() => moveWidget(w.id, 'down')}
                          disabled={globalIdx === widgets.length - 1}
                          className={`p-0.5 rounded text-gray-400 transition ${
                            globalIdx === widgets.length - 1
                              ? 'opacity-30 cursor-not-allowed'
                              : 'hover:bg-gray-200 hover:text-gray-600'
                          }`}
                        >
                          <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="border-t px-5 py-3 flex items-center justify-between">
          <button
            onClick={handleReset}
            disabled={saving}
            className="text-sm text-gray-500 hover:text-gray-700 transition"
          >
            Reset to Default
          </button>
          <button
            onClick={handleSave}
            disabled={saving || !dirty}
            className={`px-4 py-2 text-sm font-medium text-white rounded-lg transition ${
              saving || !dirty
                ? 'bg-gray-400 cursor-not-allowed'
                : 'bg-blue-600 hover:bg-blue-700'
            }`}
          >
            {saving ? 'Saving...' : 'Save Layout'}
          </button>
        </div>
      </div>
    </>
  );
}
