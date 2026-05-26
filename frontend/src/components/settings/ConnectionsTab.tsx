import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { maskCredential } from '../../utils/maskCredential';
import { DiscoveryProgressModal } from './DiscoveryProgressModal';
import type {
  SettingsData,
  StatusData,
  OrgCloudConfig,
  CloudConnection,
  ConnectionTestResult,
} from './types';

export interface ConnectionsTabProps {
  settings: SettingsData | null;
  status: StatusData | null;
  cloudConfig: OrgCloudConfig | null;
  cloudConnections: CloudConnection[];
  isAdmin: boolean;
  orgStage: string;
  primaryCloud: string | null;
  addingCloud: boolean;
  setAddingCloud: (v: boolean) => void;
  maskCredentials: boolean;
  setMaskCredentials: (v: boolean) => void;
  showAddWizard: boolean;
  setShowAddWizard: (v: boolean) => void;
  wizardStep: number;
  setWizardStep: (v: number) => void;
  wizardCloud: string;
  setWizardCloud: (v: string) => void;
  wizardLabel: string;
  setWizardLabel: (v: string) => void;
  wizardAzureDirectoryId: string;
  setWizardAzureDirectoryId: (v: string) => void;
  wizardClientId: string;
  setWizardClientId: (v: string) => void;
  wizardClientSecret: string;
  setWizardClientSecret: (v: string) => void;
  wizardRegion: string;
  setWizardRegion: (v: string) => void;
  wizardTesting: boolean;
  wizardTestResult: ConnectionTestResult | null;
  wizardSaving: boolean;
  scanningConnId: number | null;
  activeJobs: Record<number, any>;
  connectionTestResult: ConnectionTestResult | null;
  testingConnection: boolean;
  unlocking: boolean;
  handleWizardTest: () => void;
  handleWizardSave: () => void;
  resetWizard: () => void;
  handleDeleteConnection: (connId: number) => void;
  removingConnId: number | null;
  handleRunScan: (connId: number) => void;
  fetchConnections: () => void;
  handleUpdateDiscoverySettings: (connId: number, enabled: boolean, intervalMinutes: number) => void;
  handleTestConnection: () => void;
  handleSaveAndUnlock: () => void;
  update: (key: keyof SettingsData, value: string) => void;
  setError: (v: string | null) => void;
  setSuccess: (v: string | null) => void;
  cloudSectionRef: React.RefObject<HTMLDivElement | null>;
}

interface AKSCluster {
  id: number;
  cluster_name: string;
  resource_group: string;
  layer2_scan_enabled: boolean;
}

function AKSDeepScanSection({ isAdmin, setError, setSuccess }: {
  isAdmin: boolean;
  setError: (v: string | null) => void;
  setSuccess: (v: string | null) => void;
}) {
  const [clusters, setClusters] = useState<AKSCluster[]>([]);
  const [expanded, setExpanded] = useState(false);
  const [toggling, setToggling] = useState<number | null>(null);

  const fetchClusters = useCallback(async () => {
    try {
      const res = await fetch('/api/aks-clusters');
      if (res.ok) {
        const data = await res.json();
        setClusters(data.clusters || []);
      }
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { fetchClusters(); }, [fetchClusters]);

  if (clusters.length === 0) return null;

  const handleToggle = async (clusterId: number, enabled: boolean) => {
    setToggling(clusterId);
    try {
      const res = await fetch(`/api/aks-clusters/${clusterId}/layer2`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      });
      if (res.ok) {
        setSuccess(`Deep scan ${enabled ? 'enabled' : 'disabled'} — activates on next discovery run`);
        fetchClusters();
      } else {
        const data = await res.json().catch(() => ({}));
        setError(data.error || 'Failed to toggle deep scan');
      }
    } catch { setError('Failed to toggle deep scan'); }
    setToggling(null);
  };

  return (
    <div className="bg-white rounded-xl border shadow-sm p-6">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-2 text-sm font-medium text-gray-700 hover:text-blue-600 transition w-full"
      >
        <span className={`transition-transform ${expanded ? 'rotate-90' : ''}`}>&#9654;</span>
        AKS Deep Scan
        <span className="text-xs text-gray-400 ml-1">({clusters.length} cluster{clusters.length !== 1 ? 's' : ''})</span>
      </button>
      {expanded && (
        <div className="mt-3 space-y-2">
          <p className="text-xs text-gray-500">Kubernetes API access required. Reads ClusterRoleBindings only.</p>
          {clusters.map(c => (
            <div key={c.id} className="flex items-center justify-between py-2 px-3 rounded-lg bg-gray-50">
              <div>
                <span className="text-sm font-medium text-gray-800">{c.cluster_name}</span>
                <span className="text-xs text-gray-400 ml-2">{c.resource_group}</span>
              </div>
              {isAdmin && (
                <button
                  onClick={() => handleToggle(c.id, !c.layer2_scan_enabled)}
                  disabled={toggling === c.id}
                  className={`px-3 py-1 text-xs font-medium rounded-full transition ${
                    c.layer2_scan_enabled
                      ? 'bg-green-100 text-green-700 hover:bg-green-200'
                      : 'bg-gray-200 text-gray-600 hover:bg-gray-300'
                  } ${toggling === c.id ? 'opacity-50' : ''}`}
                >
                  {c.layer2_scan_enabled ? 'Deep Scan ON' : 'Deep Scan OFF'}
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

interface DatabricksWorkspace {
  id: number;
  workspace_name: string;
  workspace_url: string;
  layer2_scan_enabled: boolean;
}

function DatabricksConnectorSection({ isAdmin, setError, setSuccess }: {
  isAdmin: boolean;
  setError: (v: string | null) => void;
  setSuccess: (v: string | null) => void;
}) {
  const [workspaces, setWorkspaces] = useState<DatabricksWorkspace[]>([]);
  const [expanded, setExpanded] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [wsUrl, setWsUrl] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message?: string; error?: string } | null>(null);
  const [saving, setSaving] = useState(false);
  const [selectedWsId, setSelectedWsId] = useState<number | null>(null);

  const fetchWorkspaces = useCallback(async () => {
    try {
      const res = await fetch('/api/analytics-workspaces?page_size=100');
      if (res.ok) {
        const data = await res.json();
        setWorkspaces(data.workspaces || []);
      }
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { fetchWorkspaces(); }, [fetchWorkspaces]);

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await fetch('/api/analytics/databricks/test-connection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ workspace_url: wsUrl, client_id: clientId, client_secret: clientSecret }),
      });
      const data = await res.json();
      setTestResult(data);
    } catch { setTestResult({ success: false, error: 'Connection failed' }); }
    setTesting(false);
  };

  const handleSave = async () => {
    if (!selectedWsId) { setError('Select a workspace first'); return; }
    setSaving(true);
    try {
      const res = await fetch('/api/analytics/databricks/connector', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ workspace_id: selectedWsId, client_id: clientId, client_secret: clientSecret }),
      });
      if (res.ok) {
        setSuccess('Layer 2 enabled — activates on next discovery run');
        setShowModal(false);
        setWsUrl(''); setClientId(''); setClientSecret(''); setTestResult(null); setSelectedWsId(null);
        fetchWorkspaces();
      } else {
        const data = await res.json().catch(() => ({}));
        setError(data.error || 'Failed to save connector');
      }
    } catch { setError('Failed to save connector'); }
    setSaving(false);
  };

  if (workspaces.length === 0) return null;

  return (
    <>
      <div className="bg-white rounded-xl border shadow-sm p-6">
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex items-center gap-2 text-sm font-medium text-gray-700 hover:text-blue-600 transition w-full"
        >
          <span className={`transition-transform ${expanded ? 'rotate-90' : ''}`}>&#9654;</span>
          Databricks Workspaces
          <span className="text-xs text-gray-400 ml-1">({workspaces.length} workspace{workspaces.length !== 1 ? 's' : ''})</span>
        </button>
        {expanded && (
          <div className="mt-3 space-y-2">
            <p className="text-xs text-gray-500">Connect a service principal to enable PAT inventory and admin user scanning.</p>
            {workspaces.map(w => (
              <div key={w.id} className="flex items-center justify-between py-2 px-3 rounded-lg bg-gray-50">
                <div>
                  <span className="text-sm font-medium text-gray-800">{w.workspace_name}</span>
                  <span className="text-xs text-gray-400 ml-2">{w.workspace_url}</span>
                </div>
                <span className={`px-3 py-1 text-xs font-medium rounded-full ${
                  w.layer2_scan_enabled ? 'bg-green-100 text-green-700' : 'bg-gray-200 text-gray-600'
                }`}>
                  {w.layer2_scan_enabled ? 'Layer 2 ON' : 'Layer 2 OFF'}
                </span>
              </div>
            ))}
            {isAdmin && (
              <button
                onClick={() => setShowModal(true)}
                className="mt-2 px-4 py-2 text-sm font-medium text-blue-600 bg-blue-50 rounded-lg hover:bg-blue-100 transition"
              >
                + Add Databricks Connector
              </button>
            )}
          </div>
        )}
      </div>
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-md space-y-4">
            <h3 className="text-lg font-semibold text-gray-900">Connect Databricks Workspace</h3>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Workspace</label>
              <select
                value={selectedWsId ?? ''}
                onChange={e => { setSelectedWsId(Number(e.target.value)); const ws = workspaces.find(w => w.id === Number(e.target.value)); if (ws) setWsUrl(ws.workspace_url); }}
                className="w-full px-3 py-2 border rounded-lg text-sm"
              >
                <option value="">Select workspace...</option>
                {workspaces.filter(w => !w.layer2_scan_enabled).map(w => (
                  <option key={w.id} value={w.id}>{w.workspace_name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Client ID</label>
              <input type="text" value={clientId} onChange={e => setClientId(e.target.value)}
                className="w-full px-3 py-2 border rounded-lg text-sm" placeholder="Application (client) ID" />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Client Secret</label>
              <input type="password" value={clientSecret} onChange={e => setClientSecret(e.target.value)}
                className="w-full px-3 py-2 border rounded-lg text-sm" placeholder="Client secret value" />
            </div>
            {testResult && (
              <div className={`text-sm px-3 py-2 rounded-lg ${testResult.success ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'}`}>
                {testResult.success ? testResult.message : testResult.error}
              </div>
            )}
            <div className="flex gap-3 justify-end">
              <button onClick={() => { setShowModal(false); setTestResult(null); }}
                className="px-4 py-2 text-sm text-gray-600 hover:text-gray-800">Cancel</button>
              <button onClick={handleTest} disabled={!wsUrl || !clientId || !clientSecret || testing}
                className="px-4 py-2 text-sm font-medium bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 disabled:opacity-50">
                {testing ? 'Testing...' : 'Test Connection'}
              </button>
              <button onClick={handleSave} disabled={!testResult?.success || saving}
                className="px-4 py-2 text-sm font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50">
                {saving ? 'Saving...' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function ADOConnectorSection({ isAdmin, setError, setSuccess }: {
  isAdmin: boolean;
  setError: (v: string | null) => void;
  setSuccess: (v: string | null) => void;
}) {
  const [showModal, setShowModal] = useState(false);
  const [orgUrl, setOrgUrl] = useState('');
  const [pat, setPat] = useState('');
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; org_name?: string; project_count?: number; service_connection_count?: number; error?: string } | null>(null);
  const [saving, setSaving] = useState(false);

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await fetch('/api/devops/ado/test-connection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ organization_url: orgUrl, pat }),
      });
      const data = await res.json();
      setTestResult(data);
    } catch { setTestResult({ success: false, error: 'Connection failed' }); }
    setTesting(false);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await fetch('/api/devops/ado/connector', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ organization_url: orgUrl, pat }),
      });
      if (res.ok) {
        setSuccess('Azure DevOps connected — service connections will be scanned on next run');
        setShowModal(false);
        setOrgUrl(''); setPat(''); setTestResult(null);
      } else {
        const data = await res.json().catch(() => ({}));
        setError(data.error || 'Failed to save connector');
      }
    } catch { setError('Failed to save connector'); }
    setSaving(false);
  };

  if (!isAdmin) return null;

  return (
    <>
      <div className="bg-white rounded-xl border shadow-sm p-6">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="text-sm font-medium text-gray-700">Azure DevOps</h4>
            <p className="text-xs text-gray-400">Connect to scan service connections and PATs</p>
          </div>
          <button
            onClick={() => setShowModal(true)}
            className="px-4 py-2 text-sm font-medium text-blue-600 bg-blue-50 rounded-lg hover:bg-blue-100 transition"
          >
            + Connect Azure DevOps
          </button>
        </div>
      </div>
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-md space-y-4">
            <h3 className="text-lg font-semibold text-gray-900">Connect Azure DevOps</h3>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Organization URL</label>
              <input type="text" value={orgUrl} onChange={e => setOrgUrl(e.target.value)}
                className="w-full px-3 py-2 border rounded-lg text-sm" placeholder="https://dev.azure.com/mycompany" />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Personal Access Token</label>
              <input type="password" value={pat} onChange={e => setPat(e.target.value)}
                className="w-full px-3 py-2 border rounded-lg text-sm" placeholder="PAT value" />
              <p className="text-xs text-gray-400 mt-1">Required: Service Connections (Read). Optional: Tokens (Read) for PAT inventory.</p>
            </div>
            {testResult && (
              <div className={`text-sm px-3 py-2 rounded-lg ${testResult.success ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'}`}>
                {testResult.success
                  ? `Connected to ${testResult.org_name} — ${testResult.project_count} projects, ${testResult.service_connection_count} service connections`
                  : testResult.error}
              </div>
            )}
            <div className="flex gap-3 justify-end">
              <button onClick={() => { setShowModal(false); setTestResult(null); }}
                className="px-4 py-2 text-sm text-gray-600 hover:text-gray-800">Cancel</button>
              <button onClick={handleTest} disabled={!orgUrl || !pat || testing}
                className="px-4 py-2 text-sm font-medium bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 disabled:opacity-50">
                {testing ? 'Testing...' : 'Test Connection'}
              </button>
              <button onClick={handleSave} disabled={!testResult?.success || saving}
                className="px-4 py-2 text-sm font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50">
                {saving ? 'Saving...' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export function ConnectionsTab({
  settings,
  status,
  cloudConfig,
  cloudConnections,
  isAdmin,
  orgStage,
  primaryCloud,
  addingCloud,
  setAddingCloud,
  maskCredentials,
  setMaskCredentials,
  showAddWizard,
  setShowAddWizard,
  wizardStep,
  setWizardStep,
  wizardCloud,
  setWizardCloud,
  wizardLabel,
  setWizardLabel,
  wizardAzureDirectoryId,
  setWizardAzureDirectoryId,
  wizardClientId,
  setWizardClientId,
  wizardClientSecret,
  setWizardClientSecret,
  wizardRegion,
  setWizardRegion,
  wizardTesting,
  wizardTestResult,
  wizardSaving,
  scanningConnId,
  activeJobs,
  connectionTestResult,
  testingConnection,
  unlocking,
  handleWizardTest,
  handleWizardSave,
  resetWizard,
  handleDeleteConnection,
  removingConnId,
  handleRunScan,
  fetchConnections,
  handleUpdateDiscoverySettings,
  handleTestConnection,
  handleSaveAndUnlock,
  update,
  setError,
  setSuccess,
  cloudSectionRef,
}: ConnectionsTabProps) {
  const STAGE_LABELS: Record<string, string> = {
    initializing: 'Initializing...',
    discovering_subscriptions: 'Discovering subscriptions...',
    discovering_roles: 'Discovering roles...',
    discovering_identities: 'Discovering identities...',
    analyzing_risk: 'Analyzing risk...',
    saving_identities: 'Saving identities...',
    discovering_rbac: 'Discovering RBAC roles...',
    discovering_resources: 'Discovering resources...',
    discovering_apps: 'Discovering app registrations...',
    finalizing: 'Finalizing snapshot...',
  };

  // Modal state: which connection ID is showing the progress modal
  const [modalConnId, setModalConnId] = useState<number | null>(null);
  const modalConn = modalConnId ? cloudConnections.find(c => c.id === modalConnId) : null;

  // Purge data state for auth_failed connections
  const [purgingConnId, setPurgingConnId] = useState<number | null>(null);

  function handleScanWithModal(connId: number) {
    handleRunScan(connId);
    setModalConnId(connId);
  }

  async function handlePurgeData(connId: number) {
    if (!window.confirm('Clear all stale discovery data for this connection? The connection will remain so you can re-authenticate and re-scan.')) return;
    setPurgingConnId(connId);
    try {
      const res = await fetch(`/api/client/connections/${connId}/purge-data`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await res.json();
      if (res.ok && data.purged) {
        setSuccess?.(`Cleared ${data.data_removed?.total_deleted || 0} rows of stale data`);
        fetchConnections();
      } else {
        setError?.(data.error || 'Purge failed');
      }
    } catch {
      setError?.('Network error during data purge');
    } finally {
      setPurgingConnId(null);
    }
  }

  return (
    <>
          {/* Section 2: Cloud Connections */}
          <div ref={cloudSectionRef} id="cloud-connections" className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-lg font-semibold text-gray-900">Cloud Connections</div>
                <p className="text-xs text-gray-500">Configure cloud provider credentials for identity snapshots.</p>
              </div>
              {isAdmin && (
                <button
                  onClick={() => { resetWizard(); setShowAddWizard(true); }}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 text-white text-xs font-medium rounded-lg hover:bg-blue-700 transition"
                >
                  <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                  </svg>
                  Add Connection
                </button>
              )}
            </div>

            {/* Summary Strip */}
            {cloudConnections.length > 0 && (
              <div className="flex gap-4 text-xs">
                <span className="text-gray-500">Connections: <span className="font-semibold text-gray-800">{cloudConnections.length}</span></span>
                <span className="text-gray-500">Active Subs: <span className="font-semibold text-gray-800">{cloudConnections.reduce((s, c) => s + (c.sub_count || 0), 0)}</span></span>
                {cloudConnections.reduce((s, c) => s + (c.discovered_count || 0), 0) > 0 && (
                  <span className="text-amber-600 font-semibold">Discovered: {cloudConnections.reduce((s, c) => s + (c.discovered_count || 0), 0)}</span>
                )}
                {(() => {
                  const tenantCount = new Set(
                    cloudConnections.filter(c => c.cloud === 'azure').map(c => c.azure_directory_id).filter(Boolean)
                  ).size;
                  return tenantCount > 1 ? (
                    <span className="text-purple-600 font-semibold">{tenantCount} Azure Tenants</span>
                  ) : null;
                })()}
              </div>
            )}

            {/* FIX1C: Provider-Grouped Connections List with Tenant Sub-Grouping */}
            {cloudConnections.length > 0 && (() => {
              const isAutoDiscovered = (conn: CloudConnection): boolean => {
                return !!(conn.metadata?.auto_discovered);
              };

              const PROVIDERS = [
                { key: 'azure', label: 'Azure', color: 'blue', bgClass: 'bg-blue-100 text-blue-700', borderClass: 'border-blue-200' },
                { key: 'aws', label: 'AWS', color: 'orange', bgClass: 'bg-orange-100 text-orange-700', borderClass: 'border-orange-200' },
                { key: 'gcp', label: 'GCP', color: 'red', bgClass: 'bg-red-100 text-red-600', borderClass: 'border-red-200' },
              ];
              const grouped = PROVIDERS.map(p => ({
                ...p,
                connections: cloudConnections.filter(c => c.cloud === p.key),
              })).filter(g => g.connections.length > 0);

              const renderConnectionCard = (conn: CloudConnection, isCrossTenant: boolean) => (
                <div key={conn.id} className={`border-2 rounded-xl p-4 transition ${
                  isCrossTenant ? (
                    conn.status === 'connected' ? 'border-l-4 border-l-purple-400 border-green-200 bg-green-50/30' :
                    conn.status === 'auth_failed' ? 'border-l-4 border-l-purple-400 border-red-300 bg-red-50/40' :
                    conn.status === 'failed' ? 'border-l-4 border-l-purple-400 border-red-200 bg-red-50/30' :
                    'border-l-4 border-l-purple-400 border-purple-200 bg-purple-50/20'
                  ) : (
                    conn.status === 'connected' ? 'border-green-200 bg-green-50/30' :
                    conn.status === 'auth_failed' ? 'border-red-300 bg-red-50/40' :
                    conn.status === 'failed' ? 'border-red-200 bg-red-50/30' :
                    'border-gray-200 bg-gray-50/30'
                  )
                }`}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-semibold text-gray-800">{conn.label}</span>
                          {conn.label === 'Primary' && (
                            <span className="px-1.5 py-0.5 bg-blue-100 text-blue-700 text-[9px] font-bold rounded">PRIMARY</span>
                          )}
                          {isAutoDiscovered(conn) && (
                            <span className="px-1.5 py-0.5 bg-purple-100 text-purple-700 text-[9px] font-bold rounded">CROSS-TENANT</span>
                          )}
                          {isAutoDiscovered(conn) && conn.status === 'pending' && (
                            <span className="px-1.5 py-0.5 bg-amber-100 text-amber-700 text-[9px] font-medium rounded">DISCOVERED</span>
                          )}
                        </div>
                        {conn.azure_directory_id && (
                          <div className="text-[10px] text-gray-400 font-mono">{conn.azure_directory_id.slice(0, 8)}...</div>
                        )}
                        {isAutoDiscovered(conn) && conn.metadata?.discovered_via_label && (
                          <div className="text-[10px] text-purple-500 mt-0.5 flex items-center gap-1">
                            <svg className="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                            </svg>
                            Discovered via <span className="font-semibold">{conn.metadata.discovered_via_label}</span>
                          </div>
                        )}
                        <div className="text-[10px] text-gray-500 mt-0.5">
                          {conn.sub_count || 0} active subs
                          {conn.last_discovery_at ? ` · Last snapshot: ${new Date(conn.last_discovery_at).toLocaleDateString()}` : ' · No snapshot yet'}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`flex items-center gap-1 text-[10px] font-semibold ${
                        conn.status === 'connected' ? 'text-green-600' :
                        conn.status === 'auth_failed' ? 'text-red-600' :
                        conn.status === 'failed' ? 'text-red-600' :
                        'text-gray-400'
                      }`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          conn.status === 'connected' ? 'bg-green-500' :
                          conn.status === 'auth_failed' ? 'bg-red-500 animate-pulse' :
                          conn.status === 'failed' ? 'bg-red-500' :
                          'bg-gray-400'
                        }`} />
                        {conn.status === 'connected' ? 'Connected' :
                         conn.status === 'auth_failed' ? 'Credential Expired' :
                         conn.status === 'failed' ? 'Failed' : 'Pending'}
                      </span>
                      {isAdmin && conn.status === 'auth_failed' && (
                        <>
                          <span className="text-[10px] text-red-600 font-semibold">
                            Update secret below & re-test
                          </span>
                          <button
                            onClick={() => handlePurgeData(conn.id)}
                            disabled={purgingConnId === conn.id}
                            className="text-[10px] text-amber-600 hover:text-amber-800 font-medium disabled:opacity-50"
                          >
                            {purgingConnId === conn.id ? 'Clearing...' : 'Clear Stale Data'}
                          </button>
                        </>
                      )}
                      {isAdmin && conn.status === 'connected' && (
                        <button
                          onClick={() => handleScanWithModal(conn.id)}
                          disabled={scanningConnId === conn.id || !!activeJobs[conn.id]}
                          className="text-[10px] text-blue-500 hover:text-blue-700 font-medium disabled:opacity-50"
                        >
                          {scanningConnId === conn.id ? 'Starting...' :
                           activeJobs[conn.id] ? 'Scanning...' : 'Capture Snapshot'}
                        </button>
                      )}
                      {isAdmin && (
                        <button
                          onClick={() => handleDeleteConnection(conn.id)}
                          disabled={removingConnId === conn.id}
                          className="text-[10px] text-red-400 hover:text-red-600 font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {removingConnId === conn.id ? 'Removing...' : 'Remove'}
                        </button>
                      )}
                    </div>
                  </div>
                  {/* Phase 3+4: Snapshot job progress bar with retry info */}
                  {activeJobs[conn.id] && ['queued', 'running'].includes(activeJobs[conn.id].status) && (
                    <div className="mt-2 cursor-pointer" onClick={() => setModalConnId(conn.id)} title="Click for details">
                      <div className="flex items-center justify-between text-[10px] text-gray-500 mb-1">
                        <span>
                          {STAGE_LABELS[activeJobs[conn.id].stage] || 'Queued...'}
                          {activeJobs[conn.id].retry_count > 0 && (
                            <span className="ml-1.5 text-amber-500 font-medium">
                              (retry {activeJobs[conn.id].retry_count})
                            </span>
                          )}
                        </span>
                        <span>{activeJobs[conn.id].progress}%</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-1.5">
                        <div
                          className="bg-blue-500 h-1.5 rounded-full transition-all duration-500"
                          style={{ width: `${activeJobs[conn.id].progress}%` }}
                        />
                      </div>
                      {(activeJobs[conn.id].identities_discovered > 0 || activeJobs[conn.id].resources_discovered > 0) && (
                        <div className="flex gap-3 mt-1 text-[9px] text-gray-400">
                          {activeJobs[conn.id].identities_discovered > 0 && (
                            <span>{activeJobs[conn.id].identities_discovered} identities</span>
                          )}
                          {activeJobs[conn.id].resources_discovered > 0 && (
                            <span>{activeJobs[conn.id].resources_discovered} resources</span>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                  {/* Phase 5: Continuous Discovery toggle */}
                  {isAdmin && conn.status === 'connected' && (
                    <div className="mt-2 flex items-center gap-3 text-[10px]">
                      <label className="flex items-center gap-1.5 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={!!conn.discovery_enabled}
                          onChange={(e) => handleUpdateDiscoverySettings(
                            conn.id, e.target.checked,
                            conn.discovery_interval_minutes || 360
                          )}
                          className="w-3 h-3 rounded border-gray-300 text-blue-500 focus:ring-blue-500"
                        />
                        <span className="text-gray-600">Auto-refresh</span>
                      </label>
                      {conn.discovery_enabled && (
                        <select
                          value={conn.discovery_interval_minutes || 360}
                          onChange={(e) => handleUpdateDiscoverySettings(
                            conn.id, true, parseInt(e.target.value)
                          )}
                          className="text-[10px] border border-gray-200 rounded px-1.5 py-0.5 text-gray-600 bg-white"
                        >
                          <option value={60}>Every 1 hour</option>
                          <option value={120}>Every 2 hours</option>
                          <option value={360}>Every 6 hours</option>
                          <option value={720}>Every 12 hours</option>
                          <option value={1440}>Every 24 hours</option>
                        </select>
                      )}
                      {conn.last_snapshot_completed_at && (
                        <span className="text-gray-400">
                          Last: {new Date(conn.last_snapshot_completed_at).toLocaleString()}
                        </span>
                      )}
                    </div>
                  )}
                  {/* Discovered subscriptions warning */}
                  {(conn.discovered_count || 0) > 0 && (
                    <div className="mt-2 flex items-center gap-2 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 text-xs text-amber-700">
                      <svg className="w-3.5 h-3.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                      </svg>
                      <span>{conn.discovered_count} subscription(s) discovered — </span>
                      <Link to="/subscriptions" className="font-semibold hover:text-amber-800 hover:opacity-80">activate on Subscriptions page</Link>
                    </div>
                  )}
                </div>
              );

              return (
                <div className="space-y-4">
                  {grouped.map(({ key, label, bgClass, connections }) => {
                    const ownConns = connections.filter(c => !isAutoDiscovered(c));
                    const crossConns = connections.filter(c => isAutoDiscovered(c));
                    const hasBothSections = ownConns.length > 0 && crossConns.length > 0;

                    return (
                      <div key={key} className="space-y-2">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-xs font-bold ${bgClass}`}>{label}</span>
                          <span className="text-[10px] text-gray-400">{connections.length} connection{connections.length !== 1 ? 's' : ''}</span>
                        </div>

                        {/* YOUR TENANT sub-section */}
                        {ownConns.length > 0 && (
                          <>
                            {hasBothSections && (
                              <div className="flex items-center gap-2 pt-1">
                                <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Your Tenant</span>
                                <div className="flex-1 h-px bg-gray-200" />
                              </div>
                            )}
                            {ownConns.map(conn => renderConnectionCard(conn, false))}
                          </>
                        )}

                        {/* CROSS-TENANT ACCESS sub-section */}
                        {crossConns.length > 0 && (
                          <>
                            {hasBothSections && (
                              <div className="flex items-center gap-2 pt-1">
                                <span className="text-[10px] font-semibold text-purple-600 uppercase tracking-wider">Cross-Tenant Access</span>
                                <div className="flex-1 h-px bg-purple-200" />
                              </div>
                            )}
                            {crossConns.map(conn => renderConnectionCard(conn, true))}
                          </>
                        )}
                      </div>
                    );
                  })}
                </div>
              );
            })()}

            {/* Add Connection Wizard Modal */}
            {showAddWizard && (
              <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={() => setShowAddWizard(false)}>
                <div className="bg-white rounded-2xl shadow-lg w-full max-w-lg overflow-hidden" onClick={e => e.stopPropagation()}>
                  {/* Wizard Header */}
                  <div className="bg-slate-900 px-6 py-4 flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-bold text-white">Add Cloud Connection</h3>
                      <p className="text-[10px] text-slate-400 mt-0.5">Step {wizardStep + 1} of 4</p>
                    </div>
                    <button onClick={() => setShowAddWizard(false)} className="text-slate-400 hover:text-white text-lg">&times;</button>
                  </div>

                  {/* Step indicator */}
                  <div className="px-6 pt-4">
                    <div className="flex gap-1.5">
                      {['Cloud', 'Credentials', 'Test', 'Confirm'].map((s, i) => (
                        <div key={s} className="flex-1">
                          <div className={`h-1 rounded-full transition ${i <= wizardStep ? 'bg-blue-500' : 'bg-gray-200'}`} />
                          <div className={`text-[9px] mt-1 ${i <= wizardStep ? 'text-blue-600 font-semibold' : 'text-gray-400'}`}>{s}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="p-6 space-y-4">
                    {/* Step 0: Select Cloud */}
                    {wizardStep === 0 && (
                      <div className="space-y-3">
                        <p className="text-sm text-gray-600">Select the cloud provider for this connection.</p>
                        {[
                          { key: 'azure', label: 'Azure / Entra ID', desc: 'Microsoft Azure cloud and Entra directory', color: 'blue' },
                          { key: 'aws', label: 'AWS', desc: 'Amazon Web Services', color: 'orange' },
                        ].map(c => (
                          <button
                            key={c.key}
                            onClick={() => setWizardCloud(c.key)}
                            className={`w-full text-left border-2 rounded-xl p-4 transition ${
                              wizardCloud === c.key ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:border-gray-300'
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <div>
                                <div className="text-sm font-semibold text-gray-800">{c.label}</div>
                                <div className="text-[10px] text-gray-500">{c.desc}</div>
                              </div>
                              {wizardCloud === c.key && (
                                <svg className="w-5 h-5 text-blue-500" fill="currentColor" viewBox="0 0 20 20">
                                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                                </svg>
                              )}
                            </div>
                          </button>
                        ))}
                        <div className="flex justify-end pt-2">
                          <button onClick={() => setWizardStep(1)} className="px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700">
                            Next
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Step 1: Enter Credentials */}
                    {wizardStep === 1 && (
                      <div className="space-y-3">
                        <p className="text-sm text-gray-600">
                          {wizardCloud === 'aws' ? 'Enter your AWS IAM credentials.' : 'Enter your Azure service principal credentials.'}
                        </p>
                        <div>
                          <label className="block text-xs font-medium text-gray-700 mb-1">Connection Name</label>
                          <input
                            value={wizardLabel}
                            onChange={e => setWizardLabel(e.target.value)}
                            placeholder={wizardCloud === 'aws' ? 'e.g., Production AWS Account' : 'e.g., Production Entra Directory'}
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500"
                          />
                        </div>
                        {wizardCloud === 'azure' && (
                          <>
                            <div>
                              <label className="block text-xs font-medium text-gray-700 mb-1">Entra Directory ID</label>
                              <input
                                value={wizardAzureDirectoryId}
                                onChange={e => setWizardAzureDirectoryId(e.target.value)}
                                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500"
                              />
                            </div>
                            <div>
                              <label className="block text-xs font-medium text-gray-700 mb-1">Application (Client) ID</label>
                              <input
                                value={wizardClientId}
                                onChange={e => setWizardClientId(e.target.value)}
                                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500"
                              />
                            </div>
                            <div>
                              <label className="block text-xs font-medium text-gray-700 mb-1">Client Secret</label>
                              <input
                                type="password"
                                value={wizardClientSecret}
                                onChange={e => setWizardClientSecret(e.target.value)}
                                placeholder="Enter client secret"
                                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500"
                              />
                            </div>
                          </>
                        )}
                        {wizardCloud === 'aws' && (
                          <>
                            <div>
                              <label className="block text-xs font-medium text-gray-700 mb-1">Access Key ID</label>
                              <input
                                value={wizardClientId}
                                onChange={e => setWizardClientId(e.target.value)}
                                placeholder="e.g. your AWS access key"
                                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500"
                              />
                            </div>
                            <div>
                              <label className="block text-xs font-medium text-gray-700 mb-1">Secret Access Key</label>
                              <input
                                type="password"
                                value={wizardClientSecret}
                                onChange={e => setWizardClientSecret(e.target.value)}
                                placeholder="Enter secret access key"
                                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500"
                              />
                            </div>
                            <div>
                              <label className="block text-xs font-medium text-gray-700 mb-1">Region</label>
                              <select
                                value={wizardRegion}
                                onChange={e => setWizardRegion(e.target.value)}
                                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500"
                              >
                                <option value="us-east-1">US East (N. Virginia)</option>
                                <option value="us-west-2">US West (Oregon)</option>
                                <option value="eu-west-1">EU (Ireland)</option>
                                <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                              </select>
                            </div>
                          </>
                        )}
                        <div className="flex justify-between pt-2">
                          <button onClick={() => setWizardStep(0)} className="px-4 py-2 text-sm text-gray-500 hover:text-gray-700">Back</button>
                          <button
                            onClick={() => setWizardStep(2)}
                            disabled={!wizardLabel || (wizardCloud === 'azure'
                              ? (!wizardAzureDirectoryId || !wizardClientId || !wizardClientSecret)
                              : (!wizardClientId || !wizardClientSecret))}
                            className="px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed"
                          >
                            Next: Test Connection
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Step 2: Test Connection */}
                    {wizardStep === 2 && (
                      <div className="space-y-4">
                        <p className="text-sm text-gray-600">
                          {wizardCloud === 'aws' ? 'Verify that AuditGraph can connect to your AWS account.' : 'Verify that AuditGraph can connect to your Entra directory.'}
                        </p>
                        <div className="bg-gray-50 rounded-lg p-4 space-y-2 text-xs">
                          <div className="flex justify-between"><span className="text-gray-500">Cloud</span><span className="font-semibold text-gray-800">{wizardCloud.toUpperCase()}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Name</span><span className="font-semibold text-gray-800">{wizardLabel}</span></div>
                          {wizardCloud === 'azure' && (
                            <div className="flex justify-between"><span className="text-gray-500">Directory</span><span className="font-mono text-gray-700">{wizardAzureDirectoryId.slice(0, 12)}...</span></div>
                          )}
                          {wizardCloud === 'aws' && (
                            <div className="flex justify-between"><span className="text-gray-500">Region</span><span className="font-semibold text-gray-800">{wizardRegion}</span></div>
                          )}
                        </div>
                        {wizardTestResult && (
                          <div className={`rounded-lg p-3 text-sm ${
                            wizardTestResult.status === 'success' ? 'bg-green-50 border border-green-200 text-green-700' :
                            'bg-red-50 border border-red-200 text-red-700'
                          }`}>
                            {wizardTestResult.message}
                            {wizardTestResult.subscriptions && wizardTestResult.subscriptions.length > 0 && (
                              <div className="mt-2 space-y-1">
                                {wizardTestResult.subscriptions.map(sub => (
                                  <div key={sub.id} className="flex items-center gap-2 text-xs">
                                    <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                                    <span className="font-medium">{sub.name}</span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        )}
                        <div className="flex justify-between pt-2">
                          <button onClick={() => setWizardStep(1)} className="px-4 py-2 text-sm text-gray-500 hover:text-gray-700">Back</button>
                          <button
                            onClick={handleWizardTest}
                            disabled={wizardTesting}
                            className="px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 disabled:opacity-40"
                          >
                            {wizardTesting ? 'Testing...' : 'Test Connection'}
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Step 3: Confirm & Save */}
                    {wizardStep === 3 && (
                      <div className="space-y-4">
                        <div className="bg-green-50 border border-green-200 rounded-lg p-4 text-center">
                          <svg className="w-10 h-10 text-green-500 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                          </svg>
                          <div className="text-sm font-semibold text-green-800">Connection Verified</div>
                          <p className="text-xs text-green-600 mt-1">Ready to save this connection.</p>
                        </div>
                        <div className="bg-gray-50 rounded-lg p-4 space-y-2 text-xs">
                          <div className="flex justify-between"><span className="text-gray-500">Name</span><span className="font-semibold text-gray-800">{wizardLabel}</span></div>
                          <div className="flex justify-between"><span className="text-gray-500">Cloud</span><span className="font-semibold text-gray-800">{wizardCloud.toUpperCase()}</span></div>
                          {wizardCloud === 'azure' && (
                            <div className="flex justify-between"><span className="text-gray-500">Directory ID</span><span className="font-mono text-gray-700">{wizardAzureDirectoryId.slice(0, 12)}...</span></div>
                          )}
                          {wizardCloud === 'aws' && (
                            <div className="flex justify-between"><span className="text-gray-500">Region</span><span className="font-semibold text-gray-800">{wizardRegion}</span></div>
                          )}
                          {wizardTestResult?.subscriptions && (
                            <div className="flex justify-between">
                              <span className="text-gray-500">{wizardCloud === 'aws' ? 'Account' : 'Subscriptions'}</span>
                              <span className="font-semibold text-gray-800">{wizardTestResult.subscriptions.length} found</span>
                            </div>
                          )}
                        </div>
                        <div className="flex justify-between pt-2">
                          <button onClick={() => setWizardStep(2)} className="px-4 py-2 text-sm text-gray-500 hover:text-gray-700">Back</button>
                          <button
                            onClick={handleWizardSave}
                            disabled={wizardSaving}
                            className="px-4 py-2 bg-green-600 text-white text-sm rounded-lg hover:bg-green-700 disabled:opacity-40"
                          >
                            {wizardSaving ? 'Saving...' : 'Save Connection'}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {orgStage === 'locked' && (
              <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 flex items-start gap-3">
                <svg className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div>
                  <div className="text-sm font-semibold text-blue-800">Connect Your Cloud Provider</div>
                  <p className="text-xs text-blue-700 mt-0.5">
                    Your administrator has enabled <strong className="font-semibold">{primaryCloud ? primaryCloud.charAt(0).toUpperCase() + primaryCloud.slice(1) : 'your cloud provider'}</strong> for your organization.
                    Add your connector credentials below to start monitoring.
                  </p>
                </div>
              </div>
            )}

            {/* Legacy credential form — only show when no cloud connections exist */}
            {cloudConnections.length === 0 && (!isAdmin ? (
              <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 text-sm text-gray-600">
                Contact your organization administrator to configure cloud credentials.
              </div>
            ) : (
              <div className="space-y-5">
                {/* Azure */}
                {cloudConfig?.cloud_providers?.azure?.enabled ? (() => {
                  const hasCredentials = !!(settings?.azure_directory_id || settings?.azure_client_id);
                  const showForm = hasCredentials || addingCloud;
                  return showForm ? (
                  <div className="space-y-3">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-blue-700">Azure</span>
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-blue-50 text-blue-600 border border-blue-200">
                        {cloudConfig.cloud_providers.azure.plan || 'enabled'}
                      </span>
                      {status?.azure_configured && (
                        <span className="flex items-center gap-1 text-[10px] text-green-600 font-medium">
                          <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                          Connected
                        </span>
                      )}
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Entra Directory ID</label>
                      <input
                        type="text"
                        value={maskCredentials && status?.azure_configured ? maskCredential(settings?.azure_directory_id || '') : (settings?.azure_directory_id || '')}
                        onChange={e => update('azure_directory_id' as keyof SettingsData, e.target.value)}
                        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        className="w-full max-w-lg px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Application (Client) ID</label>
                      <input
                        type="text"
                        value={maskCredentials && status?.azure_configured ? maskCredential(settings?.azure_client_id || '') : (settings?.azure_client_id || '')}
                        onChange={e => update('azure_client_id' as keyof SettingsData, e.target.value)}
                        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        className="w-full max-w-lg px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Client Secret</label>
                      <input
                        type="password"
                        value={settings?.azure_client_secret || ''}
                        onChange={e => update('azure_client_secret' as keyof SettingsData, e.target.value)}
                        placeholder="Enter client secret"
                        className="w-full max-w-lg px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      />
                      <p className="text-[10px] text-gray-400 mt-1">Secret is masked after saving. Clear and re-enter to change.</p>
                    </div>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={maskCredentials}
                        onChange={e => setMaskCredentials(e.target.checked)}
                        className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                      />
                      <span className="text-xs text-gray-500">Mask credential IDs (recommended)</span>
                    </label>

                    <div className="flex items-center gap-3 pt-1">
                      <button
                        onClick={handleTestConnection}
                        disabled={testingConnection || !settings?.azure_directory_id || !settings?.azure_client_id || !settings?.azure_client_secret}
                        className={`px-4 py-2 text-sm font-medium rounded-lg transition ${
                          testingConnection || !settings?.azure_directory_id || !settings?.azure_client_id || !settings?.azure_client_secret
                            ? 'bg-gray-200 text-gray-400 cursor-not-allowed'
                            : 'bg-blue-50 text-blue-700 border border-blue-200 hover:bg-blue-100'
                        }`}
                      >
                        {testingConnection ? 'Testing...' : 'Test Connection'}
                      </button>
                      {!hasCredentials && (
                        <button
                          onClick={() => setAddingCloud(false)}
                          className="px-4 py-2 text-sm font-medium text-gray-500 hover:text-gray-700 transition"
                        >
                          Cancel
                        </button>
                      )}
                      {connectionTestResult && (
                        <span className={`text-sm ${connectionTestResult.status === 'success' ? 'text-green-600' : 'text-red-600'}`}>
                          {connectionTestResult.message}
                        </span>
                      )}
                    </div>

                    {connectionTestResult?.status === 'success' && connectionTestResult.subscriptions && connectionTestResult.subscriptions.length > 0 && (
                      <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                        <div className="text-xs font-semibold text-green-700 mb-1">Discovered Subscriptions</div>
                        <div className="space-y-1">
                          {connectionTestResult.subscriptions.map(sub => (
                            <div key={sub.id} className="text-xs text-green-800 flex items-center gap-2">
                              <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                              <span className="font-medium">{sub.name}</span>
                              <span className="text-green-600 font-mono text-[10px]">{sub.id}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {orgStage === 'locked' && connectionTestResult?.status === 'success' && (
                      <button
                        type="button"
                        onClick={handleSaveAndUnlock}
                        disabled={unlocking}
                        className="w-full py-3 text-sm font-semibold text-white bg-green-600 rounded-lg hover:bg-green-700 disabled:opacity-50 transition flex items-center justify-center gap-2"
                      >
                        {unlocking ? (
                          <>
                            <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                            Saving & Capturing First Snapshot...
                          </>
                        ) : (
                          <>
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            Save &amp; Capture First Snapshot
                          </>
                        )}
                      </button>
                    )}

                    {orgStage !== 'locked' && (
                      <p className="text-xs text-gray-400">
                        Credentials are saved with the global &quot;Save Settings&quot; button below.
                      </p>
                    )}
                  </div>
                ) : (
                  /* Empty state — no credentials yet */
                  <div className="border border-dashed border-gray-300 rounded-xl p-6 text-center">
                    <div className="flex items-center justify-center gap-2 mb-2">
                      <svg className="w-6 h-6 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 00-9.78 2.096A4.001 4.001 0 003 15z" />
                      </svg>
                      <span className="text-sm font-semibold text-gray-800">Azure</span>
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-blue-50 text-blue-600 border border-blue-200">Primary</span>
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-medium bg-amber-50 text-amber-600 border border-amber-200">Not Connected</span>
                    </div>
                    <p className="text-xs text-gray-500 mb-4">No cloud credentials configured. Connect your Azure environment to start capturing snapshots.</p>
                    <button
                      onClick={() => setAddingCloud(true)}
                      className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 transition"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                      </svg>
                      Add Cloud Connection
                    </button>
                  </div>
                );
                })() : (
                  <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 flex items-center gap-3">
                    <div className="text-sm font-medium text-gray-600">Azure</div>
                    <span className="text-xs text-gray-400">Not enabled. Contact your AuditGraph administrator to enable this provider.</span>
                  </div>
                )}

                {/* AWS */}
                {cloudConfig?.cloud_providers?.aws?.enabled ? (
                  <div className="space-y-3">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-orange-700">AWS</span>
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-orange-50 text-orange-600 border border-orange-200">
                        {cloudConfig.cloud_providers.aws.plan || 'enabled'}
                      </span>
                      {settings?.aws_access_key_id && (
                        <>
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-orange-50 text-orange-600">IAM Access Key</span>
                          <span className="flex items-center gap-1 text-[10px] text-green-600 font-medium">
                            <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                            Configured
                          </span>
                        </>
                      )}
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Access Key ID</label>
                      <input
                        type="text"
                        value={settings?.aws_access_key_id || ''}
                        onChange={e => update('aws_access_key_id' as keyof SettingsData, e.target.value)}
                        placeholder="e.g. your AWS access key"
                        className="w-full max-w-lg px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Secret Access Key</label>
                      <input
                        type="password"
                        value={settings?.aws_secret_access_key || ''}
                        onChange={e => update('aws_secret_access_key' as keyof SettingsData, e.target.value)}
                        placeholder="Enter secret access key"
                        className="w-full max-w-lg px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      />
                      <p className="text-[10px] text-gray-400 mt-1">Secret is masked after saving. Clear and re-enter to change.</p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Default Region</label>
                      <select
                        value={settings?.aws_region || 'us-east-1'}
                        onChange={e => update('aws_region' as keyof SettingsData, e.target.value)}
                        className="w-full max-w-lg px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      >
                        <option value="us-east-1">US East (N. Virginia)</option>
                        <option value="us-east-2">US East (Ohio)</option>
                        <option value="us-west-1">US West (N. California)</option>
                        <option value="us-west-2">US West (Oregon)</option>
                        <option value="eu-west-1">EU (Ireland)</option>
                        <option value="eu-west-2">EU (London)</option>
                        <option value="eu-central-1">EU (Frankfurt)</option>
                        <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                        <option value="ap-southeast-2">Asia Pacific (Sydney)</option>
                        <option value="ap-northeast-1">Asia Pacific (Tokyo)</option>
                      </select>
                    </div>

                    <p className="text-xs text-gray-400">
                      Credentials are saved with the global &quot;Save Settings&quot; button below.
                    </p>
                  </div>
                ) : cloudConfig ? (
                  <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 flex items-center gap-3">
                    <div className="text-sm font-medium text-gray-600">AWS</div>
                    <span className="text-xs text-gray-400">Not enabled. Contact your AuditGraph administrator to enable this provider.</span>
                  </div>
                ) : null}

                {/* GCP */}
                {cloudConfig?.cloud_providers?.gcp?.enabled ? (
                  <div className="space-y-3">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-red-600">GCP</span>
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-red-50 text-red-500 border border-red-200">
                        {cloudConfig.cloud_providers.gcp.plan || 'enabled'}
                      </span>
                      {settings?.gcp_project_id && (
                        <>
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-red-50 text-red-600">Service Account</span>
                          <span className="flex items-center gap-1 text-[10px] text-green-600 font-medium">
                            <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                            Configured
                          </span>
                        </>
                      )}
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Project ID</label>
                      <input
                        type="text"
                        value={settings?.gcp_project_id || ''}
                        onChange={e => update('gcp_project_id' as keyof SettingsData, e.target.value)}
                        placeholder="my-project-123456"
                        className="w-full max-w-lg px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Service Account JSON Key</label>
                      <textarea
                        value={settings?.gcp_service_account_json || ''}
                        onChange={e => update('gcp_service_account_json' as keyof SettingsData, e.target.value)}
                        placeholder='{"type": "service_account", "project_id": "...", ...}'
                        rows={4}
                        className="w-full max-w-lg px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      />
                      <p className="text-[10px] text-gray-400 mt-1">Paste the full JSON key file contents. Stored encrypted.</p>
                    </div>

                    <p className="text-xs text-gray-400">
                      Credentials are saved with the global &quot;Save Settings&quot; button below.
                    </p>
                  </div>
                ) : cloudConfig ? (
                  <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 flex items-center gap-3">
                    <div className="text-sm font-medium text-gray-600">GCP</div>
                    <span className="text-xs text-gray-400">Not enabled. Contact your AuditGraph administrator to enable this provider.</span>
                  </div>
                ) : null}
              </div>
            ))}
          </div>

          {/* Section 3: Snapshot Schedule */}
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div className="text-lg font-semibold text-gray-900">Snapshot Schedule</div>

            {/* Status indicators */}
            <div className="flex items-center gap-6 text-sm">
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${status?.azure_configured ? 'bg-green-500' : 'bg-red-500'}`} />
                <span className="text-gray-600">
                  Azure: {status?.azure_configured ? 'Connected' : 'Not configured'}
                </span>
                {status?.azure_configured && (
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-blue-50 text-blue-600">Service Principal</span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${status?.scheduler_running ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
                <span className="text-gray-600">
                  Scheduler: {status?.scheduler_running ? 'Running' : 'Stopped'}
                </span>
              </div>
              {status?.next_run && (
                <span className="text-gray-400 text-xs">
                  Next snapshot: {new Date(status.next_run).toLocaleString()}
                </span>
              )}
              <button
                onClick={async () => {
                  try {
                    const res = await fetch('/api/runs/trigger', { method: 'POST' });
                    if (res.ok) setSuccess('Snapshot capture triggered');
                    else setError('Failed to trigger snapshot');
                  } catch { setError('Failed to trigger snapshot'); }
                }}
                className="ml-auto px-3 py-1.5 text-xs font-medium text-blue-600 border border-blue-300 rounded-lg hover:bg-blue-50 transition"
              >
                Capture Now
              </button>
            </div>

            {/* Interval selector */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Snapshot Interval
              </label>
              <div className="flex gap-3">
                {['6', '12', '24'].map(val => (
                  <button
                    key={val}
                    onClick={() => update('discovery_interval_hours', val)}
                    className={`px-4 py-2 rounded-lg text-sm font-medium border transition ${
                      settings?.discovery_interval_hours === val
                        ? 'bg-blue-600 text-white border-blue-600'
                        : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                    }`}
                  >
                    Every {val} hours
                  </button>
                ))}
              </div>
              <p className="text-xs text-gray-400 mt-2">
                How often a snapshot is captured from your Azure environment. Takes effect on next scheduler restart.
              </p>
            </div>
          </div>
          {/* Section 4: AKS Deep Scan (Layer 2) */}
          <AKSDeepScanSection isAdmin={isAdmin} setError={setError} setSuccess={setSuccess} />
          {/* Section 5: Databricks Connector (Layer 2) */}
          <DatabricksConnectorSection isAdmin={isAdmin} setError={setError} setSuccess={setSuccess} />
          {/* Section 6: Azure DevOps Connector */}
          <ADOConnectorSection isAdmin={isAdmin} setError={setError} setSuccess={setSuccess} />
      {/* Discovery Progress Modal */}
      {modalConnId && modalConn && (
        <DiscoveryProgressModal
          connectionId={modalConnId}
          connectionLabel={modalConn.label || modalConn.cloud || 'Connection'}
          connectionCloud={modalConn.cloud || 'azure'}
          onClose={() => setModalConnId(null)}
          onComplete={() => { setModalConnId(null); fetchConnections(); }}
        />
      )}
    </>
  );
}
