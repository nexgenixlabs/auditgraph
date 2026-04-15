import React from 'react';

export interface IntegrationsTabProps {
  ticketingRef: React.RefObject<HTMLDivElement | null>;
  IntegrationsSection: React.ComponentType;
  TicketingSection: React.ComponentType<{ ticketingRef: React.RefObject<HTMLDivElement | null> }>;
  p2Telemetry: {
    p2_telemetry_enabled: string;
    retention_signin_events_days: string;
    retention_workload_anomalies_days: string;
  };
  setP2Telemetry: React.Dispatch<React.SetStateAction<{
    p2_telemetry_enabled: string;
    retention_signin_events_days: string;
    retention_workload_anomalies_days: string;
  }>>;
  p2Saving: boolean;
  p2Msg: { type: 'success' | 'error'; text: string } | null;
  handleP2TelemetrySave: () => void;
}

export function IntegrationsTab({
  ticketingRef,
  IntegrationsSection,
  TicketingSection,
  p2Telemetry,
  setP2Telemetry,
  p2Saving,
  p2Msg,
  handleP2TelemetrySave,
}: IntegrationsTabProps) {
  return (
    <>
      {/* Section 14: Integrations (Phase 83) */}
      <IntegrationsSection />

      {/* Ticketing Integration */}
      <TicketingSection ticketingRef={ticketingRef} />

      {/* Section 15: P2 Telemetry */}
      <div className="bg-white dark:bg-slate-900 rounded-xl border border-gray-200 dark:border-slate-700 p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-semibold text-gray-900 dark:text-white">P2 Telemetry Pipeline</h3>
            <p className="text-xs text-gray-500 dark:text-slate-400 mt-0.5">
              Ingest Entra ID P2 service principal sign-in logs for behavioral analysis
            </p>
          </div>
          <button
            onClick={() => setP2Telemetry(prev => ({ ...prev, p2_telemetry_enabled: prev.p2_telemetry_enabled === 'true' ? 'false' : 'true' }))}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition ${
              p2Telemetry.p2_telemetry_enabled === 'true' ? 'bg-emerald-500' : 'bg-gray-300 dark:bg-slate-600'
            }`}>
            <span className={`inline-block h-4 w-4 rounded-full bg-white shadow transition-transform ${
              p2Telemetry.p2_telemetry_enabled === 'true' ? 'translate-x-6' : 'translate-x-1'
            }`} />
          </button>
        </div>

        <div className="rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800/40 p-3">
          <p className="text-xs text-blue-700 dark:text-blue-300">
            Optional enhanced telemetry. Requires <code className="px-1 py-0.5 rounded bg-blue-100 dark:bg-blue-900/40 text-[10px]">AuditLog.Read.All</code> permission on the registered app.
            When enabled, sign-in logs supplement the core log-independent analysis with behavioral anomaly detection.
          </p>
        </div>

        {p2Telemetry.p2_telemetry_enabled === 'true' && (
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">
                Sign-In Events Retention (days)
              </label>
              <input
                type="number"
                min="30"
                max="365"
                value={p2Telemetry.retention_signin_events_days}
                onChange={e => setP2Telemetry(prev => ({ ...prev, retention_signin_events_days: e.target.value }))}
                className="w-full rounded-lg border border-gray-300 dark:border-slate-600 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-gray-900 dark:text-white"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">
                Anomaly Retention (days)
              </label>
              <input
                type="number"
                min="30"
                max="730"
                value={p2Telemetry.retention_workload_anomalies_days}
                onChange={e => setP2Telemetry(prev => ({ ...prev, retention_workload_anomalies_days: e.target.value }))}
                className="w-full rounded-lg border border-gray-300 dark:border-slate-600 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-gray-900 dark:text-white"
              />
            </div>
          </div>
        )}

        <div className="flex items-center gap-3">
          <button
            onClick={handleP2TelemetrySave}
            disabled={p2Saving}
            className={`px-4 py-2 rounded-lg text-sm font-medium text-white transition ${
              p2Saving ? 'bg-gray-400 cursor-not-allowed' : 'bg-emerald-600 hover:bg-emerald-700'
            }`}>
            {p2Saving ? 'Saving...' : 'Save P2 Settings'}
          </button>
          {p2Msg && (
            <span className={`text-xs font-medium ${p2Msg.type === 'success' ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
              {p2Msg.text}
            </span>
          )}
        </div>
      </div>
    </>
  );
}
