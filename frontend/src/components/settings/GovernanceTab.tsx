import React from 'react';
import type { SoarPlaybookData } from './types';

export interface GovernanceTabProps {
  soarPlaybooks: SoarPlaybookData[];
  openSoarModal: (pb?: SoarPlaybookData) => void;
  handleToggleSoar: (pb: SoarPlaybookData) => void;
  handleSoarTest: (id: number) => void;
  handleSoarDelete: (id: number) => void;
  soarDeleteConfirm: number | null;
  setSoarDeleteConfirm: (id: number | null) => void;
  testingSoarId: number | null;
  soarTestResult: Record<string, unknown> | null;
  SOAR_TRIGGER_LABELS: Record<string, string>;
  SOAR_ACTION_LABELS: Record<string, string>;
  SOAR_INTEGRATION_LABELS: Record<string, string>;
  saGov: {
    sa_gov_max_credential_age_days: string;
    sa_gov_attestation_interval_days: string;
    sa_gov_dormant_threshold_days: string;
    sa_gov_require_owner: string;
  };
  setSaGov: React.Dispatch<React.SetStateAction<{
    sa_gov_max_credential_age_days: string;
    sa_gov_attestation_interval_days: string;
    sa_gov_dormant_threshold_days: string;
    sa_gov_require_owner: string;
  }>>;
  saGovMsg: { type: 'success' | 'error'; text: string } | null;
  saGovSaving: boolean;
  handleSaGovSave: () => void;
}

export function GovernanceTab({
  soarPlaybooks,
  openSoarModal,
  handleToggleSoar,
  handleSoarTest,
  handleSoarDelete,
  soarDeleteConfirm,
  setSoarDeleteConfirm,
  testingSoarId,
  soarTestResult,
  SOAR_TRIGGER_LABELS,
  SOAR_ACTION_LABELS,
  SOAR_INTEGRATION_LABELS,
  saGov,
  setSaGov,
  saGovMsg,
  saGovSaving,
  handleSaGovSave,
}: GovernanceTabProps) {
  return (
    <>
      {/* Section 10: SOAR Playbooks */}
      <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-lg font-semibold text-gray-900">SOAR Playbooks</div>
            <p className="text-sm text-gray-500 mt-0.5">
              Automated response playbooks triggered by security events
            </p>
          </div>
          <button
            onClick={() => openSoarModal()}
            disabled={soarPlaybooks.length >= 20}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
              soarPlaybooks.length >= 20
                ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                : 'bg-blue-600 text-white hover:bg-blue-700'
            }`}
          >
            + Add Playbook
          </button>
        </div>

        {soarPlaybooks.length === 0 ? (
          <div className="text-sm text-gray-400 text-center py-6 border border-dashed rounded-lg">
            No SOAR playbooks configured. Add one to automate security responses.
          </div>
        ) : (
          <div className="space-y-3">
            {soarPlaybooks.map(pb => (
              <div key={pb.id} className="border rounded-lg px-4 py-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 min-w-0 flex-1">
                    <button
                      onClick={() => handleToggleSoar(pb)}
                      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors flex-shrink-0 ${
                        pb.enabled ? 'bg-green-500' : 'bg-gray-300'
                      }`}
                    >
                      <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                        pb.enabled ? 'translate-x-4' : 'translate-x-0.5'
                      }`} />
                    </button>
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-medium text-gray-900 truncate">{pb.name}</div>
                      {pb.description && (
                        <div className="text-xs text-gray-400 truncate">{pb.description}</div>
                      )}
                    </div>
                  </div>

                  <div className="hidden sm:flex items-center gap-1.5 mx-3 flex-shrink-0">
                    <span className="px-1.5 py-0.5 bg-amber-50 text-amber-700 text-[10px] font-medium rounded">
                      {SOAR_TRIGGER_LABELS[pb.trigger_type] || pb.trigger_type}
                    </span>
                    <span className="text-gray-300 text-[10px]">&rarr;</span>
                    <span className="px-1.5 py-0.5 bg-blue-50 text-blue-700 text-[10px] font-medium rounded">
                      {SOAR_ACTION_LABELS[pb.action_type] || pb.action_type}
                    </span>
                    <span className="px-1.5 py-0.5 bg-gray-100 text-gray-600 text-[10px] font-medium rounded">
                      {SOAR_INTEGRATION_LABELS[pb.integration] || pb.integration}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className="text-xs text-gray-400">
                      {pb.trigger_count}x
                      {pb.last_triggered_at && (
                        <> &middot; {new Date(pb.last_triggered_at).toLocaleDateString()}</>
                      )}
                    </span>
                    <button
                      onClick={() => handleSoarTest(pb.id)}
                      disabled={testingSoarId === pb.id}
                      className="px-2 py-1 text-xs font-medium text-gray-600 bg-gray-100 hover:bg-gray-200 rounded transition"
                    >
                      {testingSoarId === pb.id ? 'Testing...' : 'Test'}
                    </button>
                    <button
                      onClick={() => openSoarModal(pb)}
                      className="px-2 py-1 text-xs font-medium text-blue-600 bg-blue-50 hover:bg-blue-100 rounded transition"
                    >
                      Edit
                    </button>
                    {soarDeleteConfirm === pb.id ? (
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => handleSoarDelete(pb.id)}
                          className="px-2 py-1 text-xs font-medium text-white bg-red-600 hover:bg-red-700 rounded transition"
                        >
                          Confirm
                        </button>
                        <button
                          onClick={() => setSoarDeleteConfirm(null)}
                          className="px-2 py-1 text-xs font-medium text-gray-600 bg-gray-100 hover:bg-gray-200 rounded transition"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => setSoarDeleteConfirm(pb.id)}
                        className="px-2 py-1 text-xs font-medium text-red-600 bg-red-50 hover:bg-red-100 rounded transition"
                      >
                        Delete
                      </button>
                    )}
                  </div>
                </div>

                {/* Test result inline */}
                {soarTestResult && (soarTestResult as Record<string, unknown>).playbook_id === pb.id && (
                  <div className="mt-2 p-2 bg-gray-50 rounded border text-xs">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`w-2 h-2 rounded-full ${(soarTestResult as Record<string, unknown>).would_match ? 'bg-green-500' : 'bg-yellow-500'}`} />
                      <span className="font-medium text-gray-700">
                        {(soarTestResult as Record<string, unknown>).would_match ? 'Would trigger' : 'Would NOT trigger'}
                      </span>
                      {!(soarTestResult as Record<string, unknown>).cooldown_ok && (
                        <span className="text-orange-600">(cooldown active)</span>
                      )}
                    </div>
                    <div className="text-gray-500">{(soarTestResult as Record<string, unknown>).summary as string}</div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        <p className="text-xs text-gray-400">
          Maximum 20 playbooks. Playbooks are evaluated automatically after snapshots detect anomalies, drift, or risk changes.
          Cooldown prevents duplicate actions.
        </p>
      </div>

      {/* Section 11: Service Account Governance (Phase 63) */}
      <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
        <div>
          <div className="text-lg font-semibold text-gray-900">Service Account Governance</div>
          <p className="text-sm text-gray-500 mt-0.5">
            Configure governance policies for non-human identities (service principals, managed identities).
          </p>
        </div>

        {saGovMsg && (
          <div className={`rounded-lg p-3 text-sm ${saGovMsg.type === 'success' ? 'bg-green-50 border border-green-200 text-green-700' : 'bg-red-50 border border-red-200 text-red-700'}`}>
            {saGovMsg.text}
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Max Credential Age (days)</label>
            <input
              type="number"
              min={1}
              max={3650}
              value={saGov.sa_gov_max_credential_age_days}
              onChange={e => setSaGov(prev => ({ ...prev, sa_gov_max_credential_age_days: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            <p className="text-xs text-gray-400 mt-1">Credentials older than this are flagged</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Attestation Interval (days)</label>
            <input
              type="number"
              min={1}
              max={365}
              value={saGov.sa_gov_attestation_interval_days}
              onChange={e => setSaGov(prev => ({ ...prev, sa_gov_attestation_interval_days: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            <p className="text-xs text-gray-400 mt-1">How often owners must re-attest</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Dormant Threshold (days)</label>
            <input
              type="number"
              min={1}
              max={365}
              value={saGov.sa_gov_dormant_threshold_days}
              onChange={e => setSaGov(prev => ({ ...prev, sa_gov_dormant_threshold_days: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            <p className="text-xs text-gray-400 mt-1">No sign-in within this = dormant</p>
          </div>
        </div>

        <div className="flex items-center justify-between max-w-xs">
          <label className="text-sm font-medium text-gray-700">Require Owner</label>
          <button
            type="button"
            onClick={() => setSaGov(prev => ({ ...prev, sa_gov_require_owner: prev.sa_gov_require_owner === 'true' ? 'false' : 'true' }))}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              saGov.sa_gov_require_owner === 'true' ? 'bg-blue-600' : 'bg-gray-300'
            }`}
          >
            <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
              saGov.sa_gov_require_owner === 'true' ? 'translate-x-6' : 'translate-x-1'
            }`} />
          </button>
        </div>
        <p className="text-xs text-gray-400 -mt-2">Unowned service accounts flagged as non-compliant</p>

        <button
          onClick={handleSaGovSave}
          disabled={saGovSaving}
          className={`px-4 py-2 rounded-lg text-sm font-medium text-white transition ${
            saGovSaving ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'
          }`}
        >
          {saGovSaving ? 'Saving...' : 'Save Governance Policy'}
        </button>
      </div>
    </>
  );
}
