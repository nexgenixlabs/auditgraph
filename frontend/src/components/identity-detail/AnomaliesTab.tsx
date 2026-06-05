import React from 'react';
import {
  type IdentityDetailsResponse,
  riskBadge,
  formatDate,
  DataSource,
} from './types';
import StatusBadge from '../ui/StatusBadge';
import EmptyState from '../ui/EmptyState';
import { SEVERITY_HEX } from '../../constants/riskScoring';

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
        <EmptyState
          title="No anomalies detected"
          description="The AuditGraph anomaly engine ran on the current snapshot and found no unusual behavior for this identity. Anomalies include permission escalation, dormant reactivation, credential surges, and off-hours PIM activation."
          icon={
            <svg className="w-10 h-10 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          }
        />
      ) : (
        anomalyData.anomalies.map((a: any) => {
          // Severity-tinted card border/bg — colors come from the canonical
          // SEVERITY_HEX so they match badges and charts elsewhere.
          const sev = (['critical', 'high', 'medium', 'low'].includes(a.severity) ? a.severity : 'low') as 'critical' | 'high' | 'medium' | 'low';
          const tint = SEVERITY_HEX[sev];
          const typeLabels: Record<string, string> = {
            permission_escalation: 'Permission Escalation',
            risk_score_spike: 'Risk Spike',
            dormant_reactivation: 'Dormant Reactivation',
            credential_surge: 'Credential Surge',
            off_hours_pim: 'Off-Hours PIM',
            excessive_pim_usage: 'Excessive PIM',
            ghost_identity: 'Ghost Identity',
            mover_stale_access: 'Mover — Stale Access',
            ai_agent_runaway: 'AI Agent — Runaway',
            new_ai_agent_behavior: 'AI Agent — New Behavior',
            excessive_api_permission: 'Excessive API Permission',
            new_oauth_grant: 'New OAuth Grant',
            new_high_risk_identity: 'New High-Risk Identity',
          };
          return (
            <div
              key={a.id}
              className="rounded-xl border p-4"
              style={{ borderColor: `${tint}55`, backgroundColor: `${tint}11` }}
            >
              <div className="flex items-start gap-3">
                <span className="w-3 h-3 rounded-full mt-1 flex-shrink-0" style={{ backgroundColor: tint }} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-semibold uppercase text-gray-500">
                      {typeLabels[a.anomaly_type] || a.anomaly_type}
                    </span>
                    <StatusBadge variant={sev} size="xs">{a.severity}</StatusBadge>
                    {!!a.resolved && (
                      <StatusBadge variant="low" size="xs">Resolved</StatusBadge>
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
