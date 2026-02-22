import React from 'react';
import { useNavigate } from 'react-router-dom';

interface RemediationProgressProps {
  open: number;
  acknowledged: number;
  completed: number;
  skipped: number;
  total: number;
  completion_pct: number;
}

export default function RemediationProgress({
  open, acknowledged, completed, skipped, total, completion_pct,
}: RemediationProgressProps) {
  const navigate = useNavigate();
  if (total === 0) {
    return (
      <div className="bg-white border rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <svg className="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
          </svg>
          <div className="text-sm font-semibold text-gray-900">Remediation Progress</div>
        </div>
        <div className="text-sm text-gray-400 italic">
          No remediation actions tracked yet
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white border rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <svg className="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
          </svg>
          <div className="text-sm font-semibold text-gray-900">Remediation Progress</div>
        </div>
        <span className="text-xs font-bold text-green-600">{completion_pct}%</span>
      </div>

      {/* Progress bar */}
      <div className="w-full bg-gray-200 rounded-full h-2 mb-4">
        <div
          className="bg-green-500 h-2 rounded-full transition-all"
          style={{ width: `${completion_pct}%` }}
        />
      </div>

      {/* Status breakdown */}
      <div className="grid grid-cols-2 gap-2">
        <StatusItem label="Open" count={open} color="text-gray-600" bg="bg-gray-50" onClick={() => navigate('/identities?remediation_status=open')} />
        <StatusItem label="Acknowledged" count={acknowledged} color="text-blue-600" bg="bg-blue-50" onClick={() => navigate('/identities?remediation_status=acknowledged')} />
        <StatusItem label="Completed" count={completed} color="text-green-600" bg="bg-green-50" onClick={() => navigate('/identities?remediation_status=completed')} />
        <StatusItem label="Skipped" count={skipped} color="text-yellow-700" bg="bg-yellow-50" onClick={() => navigate('/identities?remediation_status=skipped')} />
      </div>
    </div>
  );
}

function StatusItem({ label, count, color, bg, onClick }: { label: string; count: number; color: string; bg: string; onClick?: () => void }) {
  return (
    <button onClick={onClick} className={`flex items-center justify-between p-2 rounded-lg ${bg} w-full text-left hover:opacity-80 transition cursor-pointer`}>
      <span className="text-xs text-gray-700">{label}</span>
      <span className={`text-sm font-bold ${color}`}>{count}</span>
    </button>
  );
}
