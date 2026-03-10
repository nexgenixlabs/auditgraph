import React from 'react';
import type { SettingsData } from './types';

export interface AdvancedTabProps {
  isSuperAdmin: boolean;
  retention: {
    retention_enabled: string;
    retention_discovery_days: string;
    retention_drift_days: string;
    retention_activity_days: string;
    retention_anomalies_days: string;
    retention_soar_days: string;
    retention_notifications_days: string;
  };
  setRetention: React.Dispatch<React.SetStateAction<{
    retention_enabled: string;
    retention_discovery_days: string;
    retention_drift_days: string;
    retention_activity_days: string;
    retention_anomalies_days: string;
    retention_soar_days: string;
    retention_notifications_days: string;
  }>>;
  retentionMsg: { type: 'success' | 'error'; text: string } | null;
  retentionSaving: boolean;
  handleRetentionSave: () => void;
  cleanupRunning: boolean;
  cleanupResult: { total: number; deleted: Record<string, number> } | null;
  handleManualCleanup: () => void;
  storageStats: {
    total_size_mb: number;
    row_counts: Record<string, number>;
    oldest_records: Record<string, string | null>;
  } | null;
  settings: SettingsData | null;
  update: (key: keyof SettingsData, value: string) => void;
}

export function AdvancedTab({
  isSuperAdmin,
  retention,
  setRetention,
  retentionMsg,
  retentionSaving,
  handleRetentionSave,
  cleanupRunning,
  cleanupResult,
  handleManualCleanup,
  storageStats,
  settings,
  update,
}: AdvancedTabProps) {
  return (
    <>
      {/* Section 12: Data Retention (Phase 72) — superadmin only */}
      {isSuperAdmin && <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
        <div>
          <div className="text-lg font-semibold text-gray-900">Data Retention</div>
          <p className="text-sm text-gray-500 mt-0.5">
            Configure how long historical data is kept. A daily cleanup job runs at 03:00 UTC.
          </p>
        </div>

        {retentionMsg && (
          <div className={`rounded-lg p-3 text-sm ${retentionMsg.type === 'success' ? 'bg-green-50 border border-green-200 text-green-700' : 'bg-red-50 border border-red-200 text-red-700'}`}>
            {retentionMsg.text}
          </div>
        )}

        {/* Enable toggle */}
        <div className="flex items-center justify-between">
          <div>
            <span className="text-sm font-medium text-gray-700">Enable Automatic Cleanup</span>
            <p className="text-xs text-gray-400">When enabled, old data is automatically deleted on schedule</p>
          </div>
          <button
            type="button"
            onClick={() => setRetention(prev => ({ ...prev, retention_enabled: prev.retention_enabled === 'true' ? 'false' : 'true' }))}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              retention.retention_enabled === 'true' ? 'bg-blue-600' : 'bg-gray-300'
            }`}
          >
            <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
              retention.retention_enabled === 'true' ? 'translate-x-6' : 'translate-x-1'
            }`} />
          </button>
        </div>

        {/* Retention periods */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Snapshots (days)</label>
            <input
              type="number" min={7} max={3650}
              value={retention.retention_discovery_days}
              onChange={e => setRetention(prev => ({ ...prev, retention_discovery_days: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            {storageStats && <p className="text-xs text-gray-400 mt-1">{storageStats.row_counts?.discovery_runs ?? 0} snapshots stored</p>}
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Drift Reports (days)</label>
            <input
              type="number" min={7} max={3650}
              value={retention.retention_drift_days}
              onChange={e => setRetention(prev => ({ ...prev, retention_drift_days: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            {storageStats && <p className="text-xs text-gray-400 mt-1">{storageStats.row_counts?.drift_reports ?? 0} reports stored</p>}
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Activity Log (days)</label>
            <input
              type="number" min={7} max={3650}
              value={retention.retention_activity_days}
              onChange={e => setRetention(prev => ({ ...prev, retention_activity_days: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            {storageStats && <p className="text-xs text-gray-400 mt-1">{storageStats.row_counts?.activity_log ?? 0} entries stored</p>}
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Anomalies (days)</label>
            <input
              type="number" min={7} max={3650}
              value={retention.retention_anomalies_days}
              onChange={e => setRetention(prev => ({ ...prev, retention_anomalies_days: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            <p className="text-xs text-gray-400 mt-1">Only resolved anomalies are cleaned</p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">SOAR Actions (days)</label>
            <input
              type="number" min={7} max={3650}
              value={retention.retention_soar_days}
              onChange={e => setRetention(prev => ({ ...prev, retention_soar_days: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            {storageStats && <p className="text-xs text-gray-400 mt-1">{storageStats.row_counts?.soar_actions ?? 0} actions stored</p>}
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Notifications (days)</label>
            <input
              type="number" min={7} max={3650}
              value={retention.retention_notifications_days}
              onChange={e => setRetention(prev => ({ ...prev, retention_notifications_days: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            {storageStats && <p className="text-xs text-gray-400 mt-1">{storageStats.row_counts?.notifications ?? 0} notifications stored</p>}
          </div>
        </div>

        {/* Storage summary */}
        {storageStats && (
          <div className="bg-gray-50 rounded-lg p-3 border border-gray-200">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-gray-700">Database Size</span>
              <span className="text-sm font-bold text-gray-900">{storageStats.total_size_mb} MB</span>
            </div>
            {Object.entries(storageStats.oldest_records).some(([, v]) => v) && (
              <div className="mt-2 text-xs text-gray-500 space-y-0.5">
                {Object.entries(storageStats.oldest_records).map(([table, oldest]) => oldest && (
                  <div key={table} className="flex justify-between">
                    <span>{table.replace(/_/g, ' ')}</span>
                    <span>oldest: {new Date(oldest).toLocaleDateString()}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Cleanup result */}
        {cleanupResult && (
          <div className="bg-green-50 border border-green-200 rounded-lg p-3">
            <p className="text-sm font-medium text-green-700">Cleanup complete: {cleanupResult.total} records deleted</p>
            {cleanupResult.total > 0 && (
              <div className="mt-1 text-xs text-green-600 space-y-0.5">
                {Object.entries(cleanupResult.deleted).map(([table, count]) => count > 0 && (
                  <div key={table}>{table.replace(/_/g, ' ')}: {count}</div>
                ))}
              </div>
            )}
          </div>
        )}

        <div className="flex items-center gap-3">
          <button
            onClick={handleRetentionSave}
            disabled={retentionSaving}
            className={`px-4 py-2 rounded-lg text-sm font-medium text-white transition ${
              retentionSaving ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'
            }`}
          >
            {retentionSaving ? 'Saving...' : 'Save Retention Policy'}
          </button>
          <button
            onClick={handleManualCleanup}
            disabled={cleanupRunning}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition border ${
              cleanupRunning ? 'bg-gray-100 text-gray-400 border-gray-200 cursor-not-allowed' : 'bg-white text-red-600 border-red-200 hover:bg-red-50'
            }`}
          >
            {cleanupRunning ? 'Cleaning...' : 'Run Cleanup Now'}
          </button>
        </div>
      </div>}

      {/* Section 13: AI Security Copilot (Phase 79) */}
      <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center">
            <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
          </div>
          <div>
            <div className="text-lg font-semibold text-gray-900">AI Security Copilot</div>
            <div className="text-xs text-gray-500">AI-powered security assistant</div>
          </div>
        </div>

        <div className="bg-indigo-50 border border-indigo-200 rounded-lg px-4 py-3 text-xs text-indigo-700">
          AI Copilot powered by AuditGraph AI. The Security Copilot answers questions about your security posture using live AuditGraph data as context.
          Available on Trial and Pro plans.
        </div>
      </div>
    </>
  );
}
