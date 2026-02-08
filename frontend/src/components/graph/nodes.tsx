import React from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';

const riskBorder: Record<string, string> = {
  critical: 'border-red-500 bg-red-50',
  high: 'border-orange-500 bg-orange-50',
  medium: 'border-yellow-500 bg-yellow-50',
  low: 'border-green-500 bg-green-50',
  info: 'border-blue-400 bg-blue-50',
};

const riskText: Record<string, string> = {
  critical: 'text-red-700',
  high: 'text-orange-700',
  medium: 'text-yellow-700',
  low: 'text-green-700',
  info: 'text-blue-600',
};

const roleBadgeColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  low: 'bg-green-100 text-green-700 border-green-200',
  info: 'bg-blue-100 text-blue-600 border-blue-200',
};

interface RoleData {
  name: string;
  risk_level: string;
}

function InlineRoleBadges({ roles }: { roles: RoleData[] }) {
  if (!roles || roles.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1 mt-1.5">
      {roles.map((r, i) => (
        <span
          key={i}
          className={`text-[9px] px-1.5 py-0.5 rounded border font-semibold ${
            roleBadgeColors[r.risk_level] || 'bg-gray-100 text-gray-600 border-gray-200'
          }`}
        >
          {r.name}
        </span>
      ))}
    </div>
  );
}

// Central identity node
export function IdentityNode({ data }: NodeProps) {
  const colors = riskBorder[data.risk_level as string] || 'border-blue-500 bg-blue-50';
  return (
    <div
      title={`${data.label}\nRisk: ${(data.risk_level as string || 'unknown').toUpperCase()} (${data.risk_score} pts)${data.category ? `\nCategory: ${data.category}` : ''}`}
      className={`px-5 py-3 rounded-xl border-2 shadow-lg ${colors} min-w-[180px] max-w-[240px]`}
    >
      <Handle type="target" position={Position.Left} className="!bg-gray-400" />
      <div className="flex items-center gap-2 mb-1">
        <svg className="w-4 h-4 text-gray-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
        </svg>
        <span className="font-bold text-sm text-gray-900 truncate">{data.label as string}</span>
      </div>
      <div className="flex items-center gap-2 text-[10px]">
        <span className={`font-bold uppercase ${riskText[data.risk_level as string] || 'text-gray-500'}`}>
          {(data.risk_level as string || 'unknown').toUpperCase()}
        </span>
        <span className="text-gray-400">{data.risk_score as number} pts</span>
        {!!data.category && <span className="text-gray-400 truncate">{data.category as string}</span>}
      </div>
      <Handle type="source" position={Position.Right} className="!bg-gray-400" />
      <Handle type="source" position={Position.Bottom} id="bottom" className="!bg-gray-400" />
    </div>
  );
}

// Risk summary (executive mode)
export function RiskSummaryNode({ data }: NodeProps) {
  const colors = riskBorder[data.risk_level as string] || 'border-red-500 bg-red-50';
  return (
    <div
      title={`${data.label}${data.detail ? `\n${data.detail}` : ''}`}
      className={`px-4 py-3 rounded-lg border-2 ${colors} max-w-[260px] shadow-md`}
    >
      <Handle type="target" position={Position.Left} className="!bg-red-400" />
      <div className="flex items-center gap-1.5 mb-1">
        <svg className="w-4 h-4 text-red-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <span className="text-xs font-semibold text-gray-900">{data.label as string}</span>
      </div>
      {!!data.detail && <div className="text-[10px] text-gray-600 ml-5.5">{data.detail as string}</div>}
    </div>
  );
}

// Blast radius (executive mode)
export function BlastRadiusNode({ data }: NodeProps) {
  return (
    <div
      title={`Blast Radius: ${data.label}`}
      className="px-4 py-3 rounded-lg border-2 border-purple-400 bg-purple-50 max-w-[260px] shadow-md"
    >
      <Handle type="target" position={Position.Left} className="!bg-purple-400" />
      <div className="flex items-center gap-1.5 mb-0.5">
        <svg className="w-4 h-4 text-purple-600 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        <span className="text-[10px] font-bold text-purple-700 uppercase">Blast Radius</span>
      </div>
      <div className="text-xs font-medium text-gray-900 ml-5.5">{data.label as string}</div>
    </div>
  );
}

// Owner node
export function OwnerNode({ data }: NodeProps) {
  return (
    <div
      title={`Owner: ${data.label}${data.upn ? `\n${data.upn}` : ''}`}
      className="px-4 py-2.5 rounded-full border-2 border-green-400 bg-green-50 shadow-sm max-w-[200px]"
    >
      <Handle type="source" position={Position.Right} className="!bg-green-400" />
      <div className="flex items-center gap-1.5">
        <svg className="w-3.5 h-3.5 text-green-600 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5.121 17.804A13.937 13.937 0 0112 16c2.5 0 4.847.655 6.879 1.804M15 10a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
        <div className="min-w-0">
          <div className="text-xs font-semibold text-gray-900 truncate">{data.label as string}</div>
          {!!data.upn && <div className="text-[9px] text-gray-500 truncate">{data.upn as string}</div>}
        </div>
      </div>
    </div>
  );
}

// Federated trust node
export function FederatedTrustNode({ data }: NodeProps) {
  const trustColor = (data.trust_risk as string) === 'high' ? 'border-amber-500 bg-amber-50' : 'border-amber-300 bg-amber-50';
  return (
    <div
      title={`Federated Trust: ${data.label}${data.subject ? `\nSubject: ${data.subject}` : ''}${data.trust_risk ? `\nRisk: ${(data.trust_risk as string).toUpperCase()}` : ''}`}
      className={`px-4 py-2.5 rounded-full border-2 border-dashed ${trustColor} shadow-sm max-w-[220px]`}
    >
      <Handle type="source" position={Position.Right} className="!bg-amber-400" />
      <div className="flex items-center gap-1.5">
        <svg className="w-3.5 h-3.5 text-amber-600 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
        </svg>
        <div className="min-w-0">
          <div className="text-xs font-semibold text-gray-900 truncate">{data.label as string}</div>
          {!!data.subject && <div className="text-[9px] text-gray-500 truncate">{data.subject as string}</div>}
        </div>
      </div>
    </div>
  );
}

// Role node (technical mode)
export function RoleNode({ data }: NodeProps) {
  const colors = riskBorder[data.risk_level as string] || 'border-gray-300 bg-gray-50';
  const typeLabel = (data.role_type as string) === 'entra' ? 'Entra' : 'RBAC';
  return (
    <div
      title={`${data.label}\nType: ${typeLabel}\nRisk: ${(data.risk_level as string || 'low').toUpperCase()}${data.scope ? `\nScope: ${data.scope}` : ''}`}
      className={`px-3 py-2 rounded-lg border ${colors} shadow-sm max-w-[200px]`}
    >
      <Handle type="target" position={Position.Left} className="!bg-gray-400" />
      <div className="flex items-center gap-1.5">
        <span className="text-xs font-semibold text-gray-900 truncate">{data.label as string}</span>
      </div>
      <div className="flex items-center gap-1.5 mt-0.5">
        <span className="text-[9px] px-1 py-0.5 rounded bg-gray-200 text-gray-600 font-medium">{typeLabel}</span>
        <span className={`text-[9px] font-bold uppercase ${riskText[data.risk_level as string] || 'text-gray-500'}`}>
          {(data.risk_level as string || 'low').toUpperCase()}
        </span>
      </div>
      <Handle type="source" position={Position.Right} className="!bg-gray-400" />
    </div>
  );
}

// Credential node (technical mode)
export function CredentialNode({ data }: NodeProps) {
  const riskColor: Record<string, string> = {
    critical: 'border-red-500 bg-red-50',
    high: 'border-orange-400 bg-orange-50',
    medium: 'border-yellow-400 bg-yellow-50',
    low: 'border-green-400 bg-green-50',
  };
  const colors = riskColor[data.exposure_risk as string] || 'border-gray-300 bg-gray-50';
  const typeIcons: Record<string, string> = { secret: 'Key', certificate: 'Cert', federated: 'Fed' };
  return (
    <div
      title={`${data.label}\nType: ${(typeIcons[data.credential_type as string] || data.credential_type) as string}${data.status ? `\nStatus: ${data.status}` : ''}${data.exposure_risk ? `\nExposure: ${(data.exposure_risk as string).toUpperCase()}` : ''}`}
      className={`px-3 py-2 rounded-lg border ${colors} shadow-sm max-w-[150px]`}
    >
      <Handle type="target" position={Position.Top} className="!bg-gray-400" />
      <div className="flex items-center gap-1">
        <svg className="w-3 h-3 text-gray-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
        </svg>
        <span className="text-[10px] font-semibold text-gray-900 truncate">{data.label as string}</span>
      </div>
      <div className="flex items-center gap-1 mt-0.5 text-[9px]">
        <span className="px-1 py-0.5 rounded bg-gray-200 text-gray-600 font-medium">
          {typeIcons[data.credential_type as string] || data.credential_type as string}
        </span>
        {!!data.status && (
          <span className={`font-medium ${
            data.status === 'expired' ? 'text-red-600' :
            data.status === 'expiring_soon' ? 'text-orange-600' : 'text-green-600'
          }`}>{data.status as string}</span>
        )}
      </div>
    </div>
  );
}

// Permission node (Graph API permissions + app role assignments)
export function PermissionNode({ data }: NodeProps) {
  const colors = riskBorder[data.risk_level as string] || 'border-gray-300 bg-gray-50';
  const typeLabel = (data.permission_type as string) === 'app_role' ? 'App Role' : 'Graph API';
  return (
    <div
      title={`${data.label}\nType: ${typeLabel}\nResource: ${data.resource || 'N/A'}\nRisk: ${(data.risk_level as string || 'info').toUpperCase()}`}
      className={`px-3 py-2 rounded-lg border ${colors} shadow-sm max-w-[220px]`}
    >
      <Handle type="target" position={Position.Left} className="!bg-gray-400" />
      <div className="flex items-center gap-1.5">
        <svg className="w-3 h-3 text-gray-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        <span className="text-[10px] font-semibold text-gray-900 truncate">{data.label as string}</span>
      </div>
      <div className="flex items-center gap-1.5 mt-0.5">
        <span className="text-[9px] px-1 py-0.5 rounded bg-indigo-100 text-indigo-700 font-medium">{typeLabel}</span>
        {!!data.resource && <span className="text-[9px] text-gray-500 truncate">{data.resource as string}</span>}
      </div>
    </div>
  );
}

// Scope node (technical mode)
export function ScopeNode({ data }: NodeProps) {
  return (
    <div
      title={`${data.full_scope || data.label}\nType: ${data.scope_type || 'scope'}`}
      className="px-3 py-2 rounded border border-dashed border-gray-400 bg-gray-50 shadow-sm max-w-[260px]"
    >
      <Handle type="target" position={Position.Left} className="!bg-gray-400" />
      <div className="flex items-center gap-1">
        <svg className="w-3 h-3 text-gray-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
        </svg>
        <span className="text-[10px] font-medium text-gray-700 truncate">{data.label as string}</span>
      </div>
      <div className="text-[9px] text-gray-500 mt-0.5 ml-4">{data.scope_type as string}</div>
    </div>
  );
}

// Subscription node (ARM hierarchy) — roles rendered inline
export function SubscriptionNode({ data }: NodeProps) {
  const roles = (data.roles as RoleData[]) || [];
  return (
    <div
      title={`Subscription: ${data.full_id || data.label}${roles.length ? '\nRoles: ' + roles.map(r => r.name).join(', ') : ''}`}
      className="px-4 py-2.5 rounded-lg border-2 border-blue-400 bg-blue-50 shadow-sm max-w-[260px]"
    >
      <Handle type="target" position={Position.Left} className="!bg-blue-400" />
      <div className="flex items-center gap-2">
        <svg className="w-4 h-4 text-blue-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
        </svg>
        <div className="min-w-0">
          <div className="text-[9px] font-bold text-blue-600 uppercase">Subscription</div>
          <div className="text-xs font-medium text-gray-900 truncate">{data.label as string}</div>
        </div>
      </div>
      <InlineRoleBadges roles={roles} />
      <Handle type="source" position={Position.Right} className="!bg-blue-400" />
    </div>
  );
}

// Resource group node (ARM hierarchy) — roles rendered inline
export function ResourceGroupNode({ data }: NodeProps) {
  const roles = (data.roles as RoleData[]) || [];
  return (
    <div
      title={`Resource Group: ${data.label}${roles.length ? '\nRoles: ' + roles.map(r => r.name).join(', ') : ''}`}
      className="px-3 py-2 rounded-lg border border-gray-300 bg-gray-50 shadow-sm max-w-[240px]"
    >
      <Handle type="target" position={Position.Left} className="!bg-gray-400" />
      <div className="flex items-center gap-1.5">
        <svg className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
        </svg>
        <div className="min-w-0">
          <div className="text-[9px] font-bold text-gray-500 uppercase">Resource Group</div>
          <div className="text-xs font-medium text-gray-900 truncate">{data.label as string}</div>
        </div>
      </div>
      <InlineRoleBadges roles={roles} />
      <Handle type="source" position={Position.Right} className="!bg-gray-400" />
    </div>
  );
}

// Resource node (ARM hierarchy) — roles rendered inline
export function ResourceNode({ data }: NodeProps) {
  const roles = (data.roles as RoleData[]) || [];
  return (
    <div
      title={`${data.full_type || data.resource_type}: ${data.label}${roles.length ? '\nRoles: ' + roles.map(r => r.name).join(', ') : ''}`}
      className="px-3 py-2 rounded border border-dashed border-purple-300 bg-purple-50 shadow-sm max-w-[240px]"
    >
      <Handle type="target" position={Position.Left} className="!bg-purple-300" />
      <div className="flex items-center gap-1.5">
        <svg className="w-3 h-3 text-purple-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
        </svg>
        <div className="min-w-0">
          <div className="text-[9px] text-purple-600 font-medium">{data.resource_type as string}</div>
          <div className="text-[10px] font-semibold text-gray-900 truncate">{data.label as string}</div>
        </div>
      </div>
      <InlineRoleBadges roles={roles} />
    </div>
  );
}

// Entra directory node — roles rendered inline
export function EntraDirectoryNode({ data }: NodeProps) {
  const roles = (data.roles as RoleData[]) || [];
  return (
    <div
      title={`Entra ID Directory\nRoles: ${roles.map(r => r.name).join(', ') || 'None'}`}
      className="px-4 py-2.5 rounded-lg border-2 border-indigo-400 bg-indigo-50 shadow-sm max-w-[260px]"
    >
      <Handle type="target" position={Position.Left} className="!bg-indigo-400" />
      <div className="flex items-center gap-2">
        <svg className="w-4 h-4 text-indigo-600 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        <div>
          <div className="text-xs font-bold text-indigo-700">Entra Directory</div>
        </div>
      </div>
      <InlineRoleBadges roles={roles} />
    </div>
  );
}

export const nodeTypes = {
  identity: IdentityNode,
  risk_summary: RiskSummaryNode,
  blast_radius: BlastRadiusNode,
  owner: OwnerNode,
  federated_trust: FederatedTrustNode,
  role: RoleNode,
  permission: PermissionNode,
  credential: CredentialNode,
  scope: ScopeNode,
  subscription: SubscriptionNode,
  resource_group: ResourceGroupNode,
  resource: ResourceNode,
  entra_directory: EntraDirectoryNode,
};
