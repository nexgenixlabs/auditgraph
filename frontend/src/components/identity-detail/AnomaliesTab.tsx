import React from 'react';
import {
  type IdentityDetailsResponse,
  riskBadge,
  formatDate,
  DataSource,
} from './types';

interface AnomaliesTabProps {
  anomalyData: { anomalies: any[]; count: number } | null;
  anomalyLoading: boolean;
  data: IdentityDetailsResponse;
}

export function AnomaliesTab({ anomalyData, anomalyLoading, data }: AnomaliesTabProps) {
  return (
    <div className="space-y-4">
      {anomalyLoading ? (
        <div className="animate-pulse space-y-3">
          <div className="h-16 bg-gray-100 rounded-xl" />
          <div className="h-16 bg-gray-100 rounded-xl" />
          <div className="h-16 bg-gray-100 rounded-xl" />
        </div>
      ) : !anomalyData || anomalyData.anomalies.length === 0 ? (
        <div className="text-center py-8">
          <svg className="w-12 h-12 text-green-300 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
          <p className="text-sm text-gray-500">No anomalies detected for this identity in the current snapshot.</p>
          <p className="text-xs text-gray-400 mt-2">Source: AuditGraph anomaly engine</p>
        </div>
      ) : (
        anomalyData.anomalies.map((a: any) => {
          const severityColors: Record<string, string> = {
            critical: 'border-red-300 bg-red-50',
            high: 'border-orange-300 bg-orange-50',
            medium: 'border-yellow-300 bg-yellow-50',
            low: 'border-blue-300 bg-blue-50',
          };
          const dotColors: Record<string, string> = {
            critical: 'bg-red-500',
            high: 'bg-orange-500',
            medium: 'bg-yellow-400',
            low: 'bg-blue-400',
          };
          const typeLabels: Record<string, string> = {
            permission_escalation: 'Permission Escalation',
            risk_score_spike: 'Risk Spike',
            dormant_reactivation: 'Dormant Reactivation',
            credential_surge: 'Credential Surge',
            off_hours_pim: 'Off-Hours PIM',
            excessive_pim_usage: 'Excessive PIM',
            ghost_identity: 'Ghost Identity',
          };
          return (
            <div key={a.id} className={`rounded-xl border p-4 ${severityColors[a.severity] || 'border-gray-200 bg-gray-50'}`}>
              <div className="flex items-start gap-3">
                <span className={`w-3 h-3 rounded-full mt-1 flex-shrink-0 ${dotColors[a.severity] || 'bg-gray-400'}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-semibold uppercase text-gray-500">
                      {typeLabels[a.anomaly_type] || a.anomaly_type}
                    </span>
                    <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${
                      a.severity === 'critical' ? 'bg-red-200 text-red-800' :
                      a.severity === 'high' ? 'bg-orange-200 text-orange-800' :
                      a.severity === 'medium' ? 'bg-yellow-200 text-yellow-800' :
                      'bg-blue-200 text-blue-800'
                    }`}>
                      {a.severity}
                    </span>
                    {!!a.resolved && (
                      <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-green-100 text-green-700">Resolved</span>
                    )}
                  </div>
                  <h4 className="text-sm font-medium text-gray-900">{a.title}</h4>
                  <p className="text-xs text-gray-600 mt-1">{a.description}</p>
                  {!!a.details && (
                    <details className="mt-2">
                      <summary className="text-[11px] text-gray-500 cursor-pointer hover:text-gray-700">View details</summary>
                      <pre className="mt-1 text-[10px] text-gray-500 bg-white/70 rounded p-2 overflow-auto max-h-32">
                        {JSON.stringify(a.details, null, 2)}
                      </pre>
                    </details>
                  )}
                  {!!a.created_at && (
                    <p className="text-[10px] text-gray-400 mt-2">
                      Detected: {new Date(a.created_at).toLocaleString()}
                    </p>
                  )}
                </div>
              </div>
            </div>
          );
        })
      )}
    </div>
  );
}
