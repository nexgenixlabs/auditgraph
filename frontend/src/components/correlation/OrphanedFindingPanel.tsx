import React, { useState } from 'react';

// ─── Types ────────────────────────────────────────────────────────

interface FindingDetail {
  id: number;
  severity: string;
  privileged_upn: string;
  regular_upn: string;
  azure_roles: string[];
  role_count: number;
  highest_role_privilege: string | null;
  days_since_regular_disabled: number | null;
  subscription_count: number;
  compliance_reference: string | null;
  has_activity_after_disable: boolean;
  days_out_of_compliance: number;
  status: string;
  human_name: string | null;
  department: string | null;
  remediation_commands: Record<string, string> | null;
  regular_account_upn: string | null;
  regular_account_enabled: boolean | null;
  privileged_account_upn: string | null;
  privileged_account_enabled: boolean | null;
  regular_risk_score: number | null;
  privileged_risk_score: number | null;
  privileged_risk_level: string | null;
  privileged_last_sign_in: string | null;
  regular_link_id?: number | null;
  privileged_link_id?: number | null;
}

interface Props {
  detail: FindingDetail;
  onClose: () => void;
  onAction: (findingId: number, action: 'acknowledge' | 'remediate' | 'suppress') => void;
  isAdmin: boolean;
}

// ─── Constants ───────────────────────────────────────────────────

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-green-100 text-green-700',
};

const STATUS_BADGE: Record<string, string> = {
  open: 'bg-red-100 text-red-700',
  acknowledged: 'bg-yellow-100 text-yellow-700',
  remediated: 'bg-green-100 text-green-700',
  suppressed: 'bg-gray-100 text-gray-500',
};

type CmdTab = 'azure_cli' | 'powershell' | 'graph_api';

const CMD_TAB_LABELS: Record<CmdTab, string> = {
  azure_cli: 'Azure CLI',
  powershell: 'PowerShell',
  graph_api: 'Graph API',
};

// ─── Component ───────────────────────────────────────────────────

export default function OrphanedFindingPanel({ detail, onClose, onAction, isAdmin }: Props) {
  const [cmdTab, setCmdTab] = useState<CmdTab>('azure_cli');
  const [copied, setCopied] = useState(false);

  const commands = detail.remediation_commands || {};
  const currentCmd = commands[cmdTab] || '';

  const handleCopy = () => {
    navigator.clipboard.writeText(currentCmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-y-0 right-0 w-[480px] bg-white border-l border-gray-200 shadow-xl z-50 flex flex-col">
      {/* Header */}
      <div className="bg-gray-50 border-b border-gray-200 px-5 py-4 flex items-center justify-between flex-shrink-0">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEVERITY_BADGE[detail.severity] || 'bg-gray-100 text-gray-500'}`}>
              {detail.severity}
            </span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${STATUS_BADGE[detail.status] || 'bg-gray-100 text-gray-500'}`}>
              {detail.status}
            </span>
          </div>
          <p className="text-sm font-bold text-gray-900 mt-1 truncate">{detail.privileged_upn}</p>
          {detail.human_name && (
            <p className="text-[10px] text-gray-500">{detail.human_name}{detail.department ? ` · ${detail.department}` : ''}</p>
          )}
        </div>
        <button onClick={onClose} className="p-1 hover:bg-gray-200 rounded flex-shrink-0 ml-2">
          <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {/* Info Grid */}
        <div className="grid grid-cols-2 gap-3">
          <div className="bg-gray-50 rounded-lg p-3">
            <div className="text-[10px] text-gray-500 uppercase font-medium">Regular UPN</div>
            <div className="text-xs font-medium text-gray-900 mt-0.5 truncate">{detail.regular_upn}</div>
            {detail.regular_account_enabled != null && (
              <span className={`text-[10px] ${detail.regular_account_enabled ? 'text-green-600' : 'text-red-600'}`}>
                {detail.regular_account_enabled ? 'Enabled' : 'Disabled'}
              </span>
            )}
          </div>
          <div className="bg-gray-50 rounded-lg p-3">
            <div className="text-[10px] text-gray-500 uppercase font-medium">Days Disabled</div>
            <div className="text-xs font-medium text-gray-900 mt-0.5">{detail.days_since_regular_disabled ?? '—'}</div>
          </div>
          <div className="bg-gray-50 rounded-lg p-3">
            <div className="text-[10px] text-gray-500 uppercase font-medium">Roles</div>
            <div className="text-xs font-medium text-gray-900 mt-0.5">{detail.role_count}</div>
          </div>
          <div className="bg-gray-50 rounded-lg p-3">
            <div className="text-[10px] text-gray-500 uppercase font-medium">Subscriptions</div>
            <div className="text-xs font-medium text-gray-900 mt-0.5">{detail.subscription_count}</div>
          </div>
          <div className="bg-gray-50 rounded-lg p-3">
            <div className="text-[10px] text-gray-500 uppercase font-medium">Highest Role</div>
            <div className="text-xs font-medium text-gray-900 mt-0.5 truncate">{detail.highest_role_privilege || '—'}</div>
          </div>
          <div className="bg-gray-50 rounded-lg p-3">
            <div className="text-[10px] text-gray-500 uppercase font-medium">Compliance</div>
            <div className="text-xs font-medium text-gray-900 mt-0.5 truncate">{detail.compliance_reference || '—'}</div>
          </div>
        </div>

        {/* Risk Info */}
        {detail.privileged_risk_level && (
          <div className="flex items-center gap-3 text-xs">
            <span className="text-gray-500">Privileged Risk:</span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${SEVERITY_BADGE[detail.privileged_risk_level] || 'bg-gray-100 text-gray-500'}`}>
              {detail.privileged_risk_level} ({detail.privileged_risk_score})
            </span>
            {detail.has_activity_after_disable && (
              <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-100 text-red-700">Activity After Disable</span>
            )}
          </div>
        )}

        {/* Compliance Detail */}
        {detail.days_out_of_compliance > 0 && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-3">
            <p className="text-xs text-red-700 font-medium">
              {detail.days_out_of_compliance} day{detail.days_out_of_compliance !== 1 ? 's' : ''} out of compliance
            </p>
            <p className="text-[10px] text-red-600 mt-0.5">{detail.compliance_reference}</p>
          </div>
        )}

        {/* Azure Roles */}
        {detail.azure_roles?.length > 0 && (
          <div>
            <h4 className="text-xs font-semibold text-gray-900 mb-2">Azure Roles ({detail.azure_roles.length})</h4>
            <div className="flex flex-wrap gap-1">
              {detail.azure_roles.map((role, i) => (
                <span key={i} className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-blue-50 text-blue-700 border border-blue-200">
                  {role}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Remediation Commands */}
        {Object.keys(commands).length > 0 && (
          <div>
            <h4 className="text-xs font-semibold text-gray-900 mb-2">Remediation Commands</h4>
            <div className="flex gap-1 mb-2">
              {(Object.keys(CMD_TAB_LABELS) as CmdTab[]).map(t => (
                commands[t] ? (
                  <button
                    key={t}
                    onClick={() => setCmdTab(t)}
                    className={`px-2.5 py-1 text-[10px] font-medium rounded transition-colors ${
                      cmdTab === t
                        ? 'bg-gray-900 text-white'
                        : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                    }`}
                  >
                    {CMD_TAB_LABELS[t]}
                  </button>
                ) : null
              ))}
            </div>
            {currentCmd && (
              <div className="relative">
                <pre className="bg-gray-900 text-green-400 rounded-lg p-3 text-[10px] leading-relaxed overflow-x-auto max-h-48 font-mono whitespace-pre-wrap">
                  {currentCmd}
                </pre>
                <button
                  onClick={handleCopy}
                  className="absolute top-2 right-2 px-2 py-1 text-[10px] bg-gray-700 text-gray-300 rounded hover:bg-gray-600"
                >
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>
            )}
          </div>
        )}

        {/* Last Sign-in */}
        {detail.privileged_last_sign_in && (
          <p className="text-[10px] text-gray-400">
            Privileged account last sign-in: {new Date(detail.privileged_last_sign_in).toLocaleString()}
          </p>
        )}
      </div>

      {/* Footer Actions */}
      {isAdmin && detail.status === 'open' && (
        <div className="border-t border-gray-200 px-5 py-3 flex items-center gap-2 flex-shrink-0">
          <button
            onClick={() => onAction(detail.id, 'acknowledge')}
            className="px-3 py-1.5 text-xs font-medium bg-yellow-50 text-yellow-700 border border-yellow-200 rounded-md hover:bg-yellow-100"
          >
            Acknowledge
          </button>
          <button
            onClick={() => onAction(detail.id, 'remediate')}
            className="px-3 py-1.5 text-xs font-medium bg-green-50 text-green-700 border border-green-200 rounded-md hover:bg-green-100"
          >
            Remediate
          </button>
          <button
            onClick={() => onAction(detail.id, 'suppress')}
            className="px-3 py-1.5 text-xs font-medium bg-gray-50 text-gray-600 border border-gray-200 rounded-md hover:bg-gray-100"
          >
            Suppress
          </button>
        </div>
      )}
      {detail.status !== 'open' && (
        <div className="border-t border-gray-200 px-5 py-3 flex-shrink-0">
          <span className={`px-2 py-1 rounded text-xs font-semibold ${STATUS_BADGE[detail.status] || 'bg-gray-100 text-gray-500'}`}>
            {detail.status.charAt(0).toUpperCase() + detail.status.slice(1)}
          </span>
        </div>
      )}
    </div>
  );
}
