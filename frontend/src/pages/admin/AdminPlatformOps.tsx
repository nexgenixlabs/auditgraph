import React, { useState } from 'react';
import { api } from '../../services/apiClient';

interface OpCard {
  id: string;
  label: string;
  description: string;
  endpoint: string;
  danger: boolean;
}

const OPS: OpCard[] = [
  {
    id: 'flush-cache',
    label: 'Flush Cache',
    description: 'Clear all graph visualization cache and reset in-memory metrics collector. Safe operation with no data loss.',
    endpoint: '/admin/platform/flush-cache',
    danger: false,
  },
  {
    id: 'rebuild-graphs',
    label: 'Rebuild All Graphs',
    description: 'Rebuild graph visualization cache for all enabled tenants. Runs in background. May take several minutes for large datasets.',
    endpoint: '/admin/platform/rebuild-graphs',
    danger: false,
  },
  {
    id: 'restart-workers',
    label: 'Restart Workers',
    description: 'Stop and restart the APScheduler background worker. In-flight jobs will be cancelled. Use with caution.',
    endpoint: '/admin/platform/restart-workers',
    danger: true,
  },
];

export default function AdminPlatformOps() {
  const [modal, setModal] = useState<OpCard | null>(null);
  const [confirmText, setConfirmText] = useState('');
  const [reason, setReason] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ success: boolean; message: string } | null>(null);

  async function execute() {
    if (!modal) return;
    setLoading(true);
    setResult(null);
    try {
      const data = await api.post(modal.endpoint, { reason });
      setResult({ success: true, message: (data as Record<string, string>).message || 'Operation completed' });
      setModal(null);
      setConfirmText('');
      setReason('');
    } catch (err: unknown) {
      setResult({ success: false, message: err instanceof Error ? err.message : 'Operation failed' });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-xl font-bold text-gray-900">Platform Operations</h2>
        <p className="text-sm text-gray-500 mt-0.5">System-level maintenance and operational actions</p>
      </div>

      {result && (
        <div className={`border rounded-lg p-3 text-sm ${
          result.success ? 'bg-green-50 border-green-200 text-green-700' : 'bg-red-50 border-red-200 text-red-700'
        }`}>
          {result.message}
          <button onClick={() => setResult(null)} className="ml-2 opacity-60 hover:opacity-100">&times;</button>
        </div>
      )}

      <div className="grid grid-cols-3 gap-4">
        {OPS.map(op => (
          <div key={op.id} className="bg-white border border-gray-200 rounded-lg p-5 flex flex-col">
            <div className="flex items-center gap-2 mb-2">
              <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                op.danger ? 'bg-red-100' : 'bg-blue-100'
              }`}>
                <svg className={`w-4 h-4 ${op.danger ? 'text-red-600' : 'text-blue-600'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  {op.id === 'flush-cache' && <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />}
                  {op.id === 'rebuild-graphs' && <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />}
                  {op.id === 'restart-workers' && <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />}
                </svg>
              </div>
              <h3 className="text-sm font-bold text-gray-900">{op.label}</h3>
            </div>
            <p className="text-xs text-gray-500 flex-1 mb-4">{op.description}</p>
            <button
              onClick={() => setModal(op)}
              className={`w-full py-2 rounded-lg text-sm font-medium transition ${
                op.danger
                  ? 'bg-red-600 text-white hover:bg-red-700'
                  : 'bg-blue-600 text-white hover:bg-blue-700'
              }`}
            >
              {op.label}
            </button>
          </div>
        ))}
      </div>

      {/* Confirmation modal */}
      {modal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
          <div className="bg-white rounded-xl shadow-xl border border-gray-200 w-full max-w-md p-6">
            <h3 className="text-sm font-bold text-gray-900 mb-2">{modal.label}</h3>
            <p className="text-xs text-gray-600 mb-4">{modal.description}</p>
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Reason</label>
                <input
                  value={reason}
                  onChange={e => setReason(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
                  placeholder="Why are you performing this action?"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  Type <span className="font-mono font-bold">CONFIRM</span> to proceed
                </label>
                <input
                  value={confirmText}
                  onChange={e => setConfirmText(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
                  placeholder="CONFIRM"
                />
              </div>
            </div>
            <div className="flex gap-2 mt-4">
              <button
                onClick={execute}
                disabled={loading || !reason.trim() || confirmText !== 'CONFIRM'}
                className={`px-4 py-2 text-white text-sm rounded-lg disabled:opacity-40 disabled:cursor-not-allowed ${
                  modal.danger ? 'bg-red-600 hover:bg-red-700' : 'bg-blue-600 hover:bg-blue-700'
                }`}
              >
                {loading ? 'Processing...' : 'Execute'}
              </button>
              <button
                onClick={() => { setModal(null); setConfirmText(''); setReason(''); }}
                className="px-4 py-2 bg-gray-100 text-gray-700 text-sm rounded-lg hover:bg-gray-200"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
