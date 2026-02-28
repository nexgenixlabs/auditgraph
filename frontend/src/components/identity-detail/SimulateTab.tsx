import React from 'react';
import {
  type IdentityDetailsResponse,
  riskBadge,
  DataSource,
} from './types';
import { safeLower } from '../../constants/metrics';

// ─── Types ──────────────────────────────────────────────────────────

interface SimulationResult {
  current: { risk_score: number; risk_level: string; risk_reasons: string[] };
  simulated: { risk_score: number; risk_level: string; risk_reasons: string[] };
  delta: number;
  level_change: string;
  removed_reasons: string[];
  added_reasons: string[];
}

// ─── Props ──────────────────────────────────────────────────────────

interface SimulateTabProps {
  identity: IdentityDetailsResponse['identity'];
  data: IdentityDetailsResponse;
  simRemovedRoles: Set<string>;
  setSimRemovedRoles: React.Dispatch<React.SetStateAction<Set<string>>>;
  simRemovedPerms: Set<string>;
  setSimRemovedPerms: React.Dispatch<React.SetStateAction<Set<string>>>;
  simAddedRoles: { role_name: string; role_type: string; scope_type: string }[];
  setSimAddedRoles: React.Dispatch<React.SetStateAction<{ role_name: string; role_type: string; scope_type: string }[]>>;
  simAddedPerms: { permission_name: string; risk_level: string }[];
  setSimAddedPerms: React.Dispatch<React.SetStateAction<{ permission_name: string; risk_level: string }[]>>;
  simResult: SimulationResult | null;
  setSimResult: React.Dispatch<React.SetStateAction<SimulationResult | null>>;
  simulating: boolean;
  simAddRoleOpen: boolean;
  setSimAddRoleOpen: React.Dispatch<React.SetStateAction<boolean>>;
  simAddPermOpen: boolean;
  setSimAddPermOpen: React.Dispatch<React.SetStateAction<boolean>>;
  simNewRole: { role_name: string; role_type: string; scope_type: string };
  setSimNewRole: React.Dispatch<React.SetStateAction<{ role_name: string; role_type: string; scope_type: string }>>;
  simNewPerm: { permission_name: string; risk_level: string };
  setSimNewPerm: React.Dispatch<React.SetStateAction<{ permission_name: string; risk_level: string }>>;
  runSimulation: () => void;
  resetSimulation: () => void;
}

// ─── SimulateTab ────────────────────────────────────────────────────

export function SimulateTab({
  identity,
  data,
  simRemovedRoles,
  setSimRemovedRoles,
  simRemovedPerms,
  setSimRemovedPerms,
  simAddedRoles,
  setSimAddedRoles,
  simAddedPerms,
  setSimAddedPerms,
  simResult,
  setSimResult,
  simulating,
  simAddRoleOpen,
  setSimAddRoleOpen,
  simAddPermOpen,
  setSimAddPermOpen,
  simNewRole,
  setSimNewRole,
  simNewPerm,
  setSimNewPerm,
  runSimulation,
  resetSimulation,
}: SimulateTabProps) {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-bold text-gray-900">What-If Risk Simulation</h3>
          <p className="text-xs text-gray-500 mt-0.5">Toggle roles and permissions to see how the risk score would change.</p>
        </div>
        <button onClick={resetSimulation} className="px-3 py-1.5 text-xs font-medium rounded-lg border border-gray-300 text-gray-600 hover:bg-gray-50 transition">
          Reset
        </button>
      </div>

      {/* Score comparison cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-gray-50 rounded-xl p-4 border">
          <div className="text-xs font-semibold text-gray-500 uppercase mb-1">Current</div>
          <div className="text-3xl font-bold text-gray-900">{simResult?.current?.risk_score ?? identity?.risk_score ?? '—'}</div>
          <div className="mt-1">{riskBadge(simResult?.current?.risk_level ?? identity?.risk_level)}</div>
        </div>
        <div className={`rounded-xl p-4 border ${simResult ? 'bg-blue-50 border-blue-200' : 'bg-gray-50'}`}>
          <div className="text-xs font-semibold text-blue-600 uppercase mb-1">Simulated</div>
          <div className="text-3xl font-bold text-gray-900">{simResult?.simulated?.risk_score ?? '—'}</div>
          {simResult && <div className="mt-1">{riskBadge(simResult.simulated.risk_level)}</div>}
          {!simResult && <div className="text-xs text-gray-400 mt-2">Click "Simulate" to compute</div>}
        </div>
        <div className={`rounded-xl p-4 border ${simResult ? (simResult.delta < 0 ? 'bg-green-50 border-green-200' : simResult.delta > 0 ? 'bg-red-50 border-red-200' : 'bg-gray-50') : 'bg-gray-50'}`}>
          <div className="text-xs font-semibold text-gray-500 uppercase mb-1">Delta</div>
          {simResult ? (
            <>
              <div className={`text-3xl font-bold ${simResult.delta < 0 ? 'text-green-700' : simResult.delta > 0 ? 'text-red-700' : 'text-gray-500'}`}>
                {simResult.delta > 0 ? '+' : ''}{simResult.delta}
              </div>
              <div className="text-xs text-gray-500 mt-1">{simResult.level_change}</div>
            </>
          ) : (
            <div className="text-3xl font-bold text-gray-300">—</div>
          )}
        </div>
      </div>

      {/* Roles section */}
      <div className="border rounded-xl overflow-hidden">
        <div className="bg-gray-50 px-4 py-3 border-b flex items-center justify-between">
          <div className="text-sm font-semibold text-gray-700">Roles ({(data?.roles?.length || 0) + simAddedRoles.length - simRemovedRoles.size} active)</div>
          <button
            onClick={() => setSimAddRoleOpen(!simAddRoleOpen)}
            className="px-2.5 py-1 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition"
          >
            + Add Role
          </button>
        </div>
        <div className="divide-y max-h-64 overflow-y-auto">
          {(data?.roles || []).map((r: any, idx: number) => {
            const key = r.role_name || `role-${idx}`;
            const removed = simRemovedRoles.has(key);
            return (
              <label key={`existing-${idx}`} className={`flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-gray-50 transition ${removed ? 'opacity-50 line-through' : ''}`}>
                <input
                  type="checkbox"
                  checked={!removed}
                  onChange={() => {
                    setSimRemovedRoles(prev => {
                      const next = new Set(prev);
                      if (next.has(key)) next.delete(key); else next.add(key);
                      return next;
                    });
                    setSimResult(null);
                  }}
                  className="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <div className="flex-1 min-w-0">
                  <span className="text-sm text-gray-900">{r.role_name}</span>
                  <span className={`ml-2 px-1.5 py-0.5 rounded text-[10px] font-medium ${
                    safeLower(r.role_type) === 'entra' ? 'bg-purple-100 text-purple-700' : 'bg-blue-100 text-blue-700'
                  }`}>
                    {(r.role_type || 'azure').toUpperCase()}
                  </span>
                  {r.scope && <span className="ml-1 text-[10px] text-gray-400 font-mono truncate">{r.scope}</span>}
                </div>
                {removed && <span className="text-xs font-medium text-red-500">removed</span>}
              </label>
            );
          })}
          {simAddedRoles.map((r, idx) => (
            <div key={`added-${idx}`} className="flex items-center gap-3 px-4 py-2.5 bg-green-50">
              <div className="w-4 h-4 rounded bg-green-500 flex items-center justify-center">
                <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M12 4v16m8-8H4" />
                </svg>
              </div>
              <div className="flex-1 min-w-0">
                <span className="text-sm text-green-800 font-medium">{r.role_name}</span>
                <span className={`ml-2 px-1.5 py-0.5 rounded text-[10px] font-medium ${
                  r.role_type === 'entra' ? 'bg-purple-100 text-purple-700' : 'bg-blue-100 text-blue-700'
                }`}>
                  {r.role_type.toUpperCase()}
                </span>
                <span className="ml-1 text-[10px] text-gray-400">{r.scope_type}</span>
              </div>
              <button
                onClick={() => { setSimAddedRoles(prev => prev.filter((_, i) => i !== idx)); setSimResult(null); }}
                className="text-xs text-red-500 hover:text-red-700 font-medium"
              >
                Remove
              </button>
            </div>
          ))}
          {(data?.roles?.length || 0) === 0 && simAddedRoles.length === 0 && (
            <div className="px-4 py-6 text-center text-sm text-gray-400">No roles assigned</div>
          )}
        </div>
        {simAddRoleOpen && (
          <div className="border-t bg-blue-50 px-4 py-3">
            <div className="flex items-end gap-2">
              <div className="flex-1">
                <label className="text-[10px] font-medium text-gray-600 block mb-1">Role Name</label>
                <input
                  type="text"
                  value={simNewRole.role_name}
                  onChange={e => setSimNewRole(prev => ({...prev, role_name: e.target.value}))}
                  placeholder="e.g. Reader, Contributor"
                  className="w-full px-2.5 py-1.5 text-sm border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
              </div>
              <div>
                <label className="text-[10px] font-medium text-gray-600 block mb-1">Type</label>
                <select
                  value={simNewRole.role_type}
                  onChange={e => setSimNewRole(prev => ({...prev, role_type: e.target.value}))}
                  className="px-2.5 py-1.5 text-sm border rounded-lg focus:ring-2 focus:ring-blue-500"
                >
                  <option value="azure">Azure RBAC</option>
                  <option value="entra">Entra ID</option>
                </select>
              </div>
              <div>
                <label className="text-[10px] font-medium text-gray-600 block mb-1">Scope</label>
                <select
                  value={simNewRole.scope_type}
                  onChange={e => setSimNewRole(prev => ({...prev, scope_type: e.target.value}))}
                  className="px-2.5 py-1.5 text-sm border rounded-lg focus:ring-2 focus:ring-blue-500"
                >
                  <option value="subscription">Subscription</option>
                  <option value="resource_group">Resource Group</option>
                  <option value="resource">Resource</option>
                  <option value="management_group">Management Group</option>
                </select>
              </div>
              <button
                onClick={() => {
                  if (!simNewRole.role_name.trim()) return;
                  setSimAddedRoles(prev => [...prev, {...simNewRole}]);
                  setSimNewRole({role_name: '', role_type: 'azure', scope_type: 'subscription'});
                  setSimAddRoleOpen(false);
                  setSimResult(null);
                }}
                className="px-3 py-1.5 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition"
              >
                Add
              </button>
              <button
                onClick={() => setSimAddRoleOpen(false)}
                className="px-3 py-1.5 text-sm font-medium rounded-lg border border-gray-300 text-gray-600 hover:bg-gray-50 transition"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Permissions section */}
      <div className="border rounded-xl overflow-hidden">
        <div className="bg-gray-50 px-4 py-3 border-b flex items-center justify-between">
          <div className="text-sm font-semibold text-gray-700">Graph API Permissions ({(data?.graph_permissions?.length || 0) + simAddedPerms.length - simRemovedPerms.size} active)</div>
          <button
            onClick={() => setSimAddPermOpen(!simAddPermOpen)}
            className="px-2.5 py-1 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition"
          >
            + Add Permission
          </button>
        </div>
        <div className="divide-y max-h-48 overflow-y-auto">
          {(data?.graph_permissions || []).map((p: any, idx: number) => {
            const key = p.permission_name || `perm-${idx}`;
            const removed = simRemovedPerms.has(key);
            return (
              <label key={`existing-perm-${idx}`} className={`flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-gray-50 transition ${removed ? 'opacity-50 line-through' : ''}`}>
                <input
                  type="checkbox"
                  checked={!removed}
                  onChange={() => {
                    setSimRemovedPerms(prev => {
                      const next = new Set(prev);
                      if (next.has(key)) next.delete(key); else next.add(key);
                      return next;
                    });
                    setSimResult(null);
                  }}
                  className="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <div className="flex-1 min-w-0">
                  <span className="text-sm text-gray-900 font-mono">{p.permission_name}</span>
                  {p.consent_type && (
                    <span className={`ml-2 px-1.5 py-0.5 rounded text-[10px] font-medium ${
                      p.consent_type === 'Application' ? 'bg-red-100 text-red-700' : 'bg-gray-100 text-gray-600'
                    }`}>
                      {p.consent_type}
                    </span>
                  )}
                </div>
                {removed && <span className="text-xs font-medium text-red-500">removed</span>}
              </label>
            );
          })}
          {simAddedPerms.map((p, idx) => (
            <div key={`added-perm-${idx}`} className="flex items-center gap-3 px-4 py-2.5 bg-green-50">
              <div className="w-4 h-4 rounded bg-green-500 flex items-center justify-center">
                <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M12 4v16m8-8H4" />
                </svg>
              </div>
              <div className="flex-1 min-w-0">
                <span className="text-sm text-green-800 font-medium font-mono">{p.permission_name}</span>
                <span className={`ml-2 px-1.5 py-0.5 rounded text-[10px] font-medium ${
                  p.risk_level === 'high' ? 'bg-red-100 text-red-700' : p.risk_level === 'medium' ? 'bg-yellow-100 text-yellow-700' : 'bg-gray-100 text-gray-600'
                }`}>
                  {p.risk_level}
                </span>
              </div>
              <button
                onClick={() => { setSimAddedPerms(prev => prev.filter((_, i) => i !== idx)); setSimResult(null); }}
                className="text-xs text-red-500 hover:text-red-700 font-medium"
              >
                Remove
              </button>
            </div>
          ))}
          {(data?.graph_permissions?.length || 0) === 0 && simAddedPerms.length === 0 && (
            <div className="px-4 py-6 text-center text-sm text-gray-400">No Graph API permissions</div>
          )}
        </div>
        {simAddPermOpen && (
          <div className="border-t bg-blue-50 px-4 py-3">
            <div className="flex items-end gap-2">
              <div className="flex-1">
                <label className="text-[10px] font-medium text-gray-600 block mb-1">Permission Name</label>
                <input
                  type="text"
                  value={simNewPerm.permission_name}
                  onChange={e => setSimNewPerm(prev => ({...prev, permission_name: e.target.value}))}
                  placeholder="e.g. Mail.Read, Files.ReadWrite.All"
                  className="w-full px-2.5 py-1.5 text-sm border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
              </div>
              <div>
                <label className="text-[10px] font-medium text-gray-600 block mb-1">Risk Level</label>
                <select
                  value={simNewPerm.risk_level}
                  onChange={e => setSimNewPerm(prev => ({...prev, risk_level: e.target.value}))}
                  className="px-2.5 py-1.5 text-sm border rounded-lg focus:ring-2 focus:ring-blue-500"
                >
                  <option value="high">High (Write/ReadWrite)</option>
                  <option value="medium">Medium (Read)</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <button
                onClick={() => {
                  if (!simNewPerm.permission_name.trim()) return;
                  setSimAddedPerms(prev => [...prev, {...simNewPerm}]);
                  setSimNewPerm({permission_name: '', risk_level: 'medium'});
                  setSimAddPermOpen(false);
                  setSimResult(null);
                }}
                className="px-3 py-1.5 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition"
              >
                Add
              </button>
              <button
                onClick={() => setSimAddPermOpen(false)}
                className="px-3 py-1.5 text-sm font-medium rounded-lg border border-gray-300 text-gray-600 hover:bg-gray-50 transition"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Simulate button */}
      <div className="flex items-center gap-3">
        <button
          onClick={runSimulation}
          disabled={simulating}
          className="px-6 py-2.5 rounded-xl font-semibold text-sm bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 transition flex items-center gap-2"
        >
          {simulating ? (
            <>
              <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none">
                <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" className="opacity-25" />
                <path d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" fill="currentColor" className="opacity-75" />
              </svg>
              Simulating...
            </>
          ) : (
            <>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
              Simulate
            </>
          )}
        </button>
        {(simRemovedRoles.size > 0 || simAddedRoles.length > 0 || simRemovedPerms.size > 0 || simAddedPerms.length > 0) && !simResult && (
          <span className="text-xs text-amber-600 font-medium">
            {simRemovedRoles.size + simRemovedPerms.size} removed, {simAddedRoles.length + simAddedPerms.length} added — click Simulate to see impact
          </span>
        )}
      </div>

      {/* Risk reasons comparison */}
      {simResult && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="border rounded-xl p-4">
            <div className="text-xs font-semibold text-gray-500 uppercase mb-2">Current Risk Reasons</div>
            <div className="space-y-1.5">
              {(simResult.current.risk_reasons || []).map((r, i) => {
                const isRemoved = (simResult.removed_reasons || []).includes(r);
                return (
                  <div key={i} className={`text-xs px-2 py-1.5 rounded ${isRemoved ? 'bg-red-50 text-red-700 line-through' : 'bg-gray-50 text-gray-700'}`}>
                    {r}
                    {isRemoved && <span className="ml-1 font-semibold text-red-500 no-underline">(removed)</span>}
                  </div>
                );
              })}
              {(simResult.current.risk_reasons || []).length === 0 && (
                <div className="text-xs text-gray-400">No risk factors</div>
              )}
            </div>
          </div>
          <div className="border rounded-xl p-4 border-blue-200">
            <div className="text-xs font-semibold text-blue-600 uppercase mb-2">Simulated Risk Reasons</div>
            <div className="space-y-1.5">
              {(simResult.simulated.risk_reasons || []).map((r, i) => {
                const isNew = (simResult.added_reasons || []).includes(r);
                return (
                  <div key={i} className={`text-xs px-2 py-1.5 rounded ${isNew ? 'bg-green-50 text-green-700' : 'bg-gray-50 text-gray-700'}`}>
                    {r}
                    {isNew && <span className="ml-1 font-semibold text-green-600">(new)</span>}
                  </div>
                );
              })}
              {(simResult.simulated.risk_reasons || []).length === 0 && (
                <div className="text-xs text-gray-400">No risk factors</div>
              )}
            </div>
          </div>
        </div>
      )}

      <DataSource label="AuditGraph Risk Simulation" apiSource="What-if analysis engine (no changes applied)" collectedAt={data?.evidence?.collected_at} />
    </div>
  );
}
