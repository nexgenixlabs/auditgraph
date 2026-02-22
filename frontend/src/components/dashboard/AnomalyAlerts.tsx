import React from 'react';
import { useNavigate } from 'react-router-dom';

interface Anomaly {
  id: number;
  anomaly_type: string;
  severity: string;
  identity_id?: string;
  identity_name?: string;
  title: string;
  description: string;
  created_at?: string;
}

interface AnomalyAlertsProps {
  anomalies: Anomaly[];
  unresolvedCount: number;
  loading?: boolean;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-400',
  low: 'bg-blue-400',
};

const TYPE_LABELS: Record<string, string> = {
  permission_escalation: 'Permission Escalation',
  risk_score_spike: 'Risk Spike',
  dormant_reactivation: 'Dormant Reactivation',
  credential_surge: 'Credential Surge',
  off_hours_pim: 'Off-Hours PIM',
  excessive_pim_usage: 'Excessive PIM',
};

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export default function AnomalyAlerts({ anomalies, unresolvedCount, loading }: AnomalyAlertsProps) {
  const navigate = useNavigate();

  if (loading) {
    return (
      <div className="bg-white rounded-xl border border-gray-200 p-5">
        <div className="flex items-center gap-2 mb-4">
          <svg className="w-5 h-5 text-amber-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
          </svg>
          <h3 className="text-sm font-semibold text-gray-900">Anomaly Alerts</h3>
        </div>
        <div className="animate-pulse space-y-3">
          {[1, 2, 3].map(i => (
            <div key={i} className="h-8 bg-gray-100 rounded" />
          ))}
        </div>
      </div>
    );
  }

  if (!anomalies || anomalies.length === 0) {
    return (
      <div className="bg-white rounded-xl border border-gray-200 p-5">
        <div className="flex items-center gap-2 mb-4">
          <svg className="w-5 h-5 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <h3 className="text-sm font-semibold text-gray-900">Anomaly Alerts</h3>
        </div>
        <div className="text-center py-4">
          <svg className="w-8 h-8 text-green-400 mx-auto mb-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
          <p className="text-sm text-gray-500">No anomalies detected</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <svg className="w-5 h-5 text-amber-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
          </svg>
          <h3 className="text-sm font-semibold text-gray-900">Anomaly Alerts</h3>
          {unresolvedCount > 0 && (
            <span className="px-1.5 py-0.5 text-[10px] font-bold bg-red-100 text-red-700 rounded-full">
              {unresolvedCount}
            </span>
          )}
        </div>
      </div>

      <div className="space-y-2">
        {anomalies.map(a => (
          <div key={a.id} onClick={() => a.identity_id ? navigate(`/identities/${a.identity_id}`) : undefined} className={`flex items-start gap-2 p-2 rounded-lg hover:bg-gray-50 transition-colors${a.identity_id ? ' cursor-pointer' : ''}`}>
            <span className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${SEVERITY_COLORS[a.severity] || 'bg-gray-400'}`} />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5">
                <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-gray-100 text-gray-600 whitespace-nowrap">
                  {TYPE_LABELS[a.anomaly_type] || a.anomaly_type}
                </span>
                {!!a.identity_name && (
                  <span className="text-xs text-gray-700 font-medium truncate">{a.identity_name}</span>
                )}
              </div>
              <p className="text-[11px] text-gray-500 mt-0.5 line-clamp-1">{a.description}</p>
            </div>
            {!!a.created_at && (
              <span className="text-[10px] text-gray-400 whitespace-nowrap flex-shrink-0 mt-0.5">
                {timeAgo(a.created_at)}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
