import React from 'react';
import { maskCredential } from '../../utils/maskCredential';
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
  connectionTestResult: ConnectionTestResult | null;
  testingConnection: boolean;
  unlocking: boolean;
  handleWizardTest: () => void;
  handleWizardSave: () => void;
  resetWizard: () => void;
  handleDeleteConnection: (connId: number) => void;
  handleRunScan: (connId: number) => void;
  handleTestConnection: () => void;
  handleSaveAndUnlock: () => void;
  update: (key: keyof SettingsData, value: string) => void;
  setError: (v: string | null) => void;
  setSuccess: (v: string | null) => void;
  cloudSectionRef: React.RefObject<HTMLDivElement | null>;
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
  connectionTestResult,
  testingConnection,
  unlocking,
  handleWizardTest,
  handleWizardSave,
  resetWizard,
  handleDeleteConnection,
  handleRunScan,
  handleTestConnection,
  handleSaveAndUnlock,
  update,
  setError,
  setSuccess,
  cloudSectionRef,
}: ConnectionsTabProps) {
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
              </div>
            )}

            {/* FIX1C: Provider-Grouped Connections List */}
            {cloudConnections.length > 0 && (() => {
              const PROVIDERS = [
                { key: 'azure', label: 'Azure', color: 'blue', bgClass: 'bg-blue-100 text-blue-700', borderClass: 'border-blue-200' },
                { key: 'aws', label: 'AWS', color: 'orange', bgClass: 'bg-orange-100 text-orange-700', borderClass: 'border-orange-200' },
                { key: 'gcp', label: 'GCP', color: 'red', bgClass: 'bg-red-100 text-red-600', borderClass: 'border-red-200' },
              ];
              const grouped = PROVIDERS.map(p => ({
                ...p,
                connections: cloudConnections.filter(c => c.cloud === p.key),
              })).filter(g => g.connections.length > 0);

              return (
                <div className="space-y-4">
                  {grouped.map(({ key, label, bgClass, borderClass, connections }) => (
                    <div key={key} className="space-y-2">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-xs font-bold ${bgClass}`}>{label}</span>
                        <span className="text-[10px] text-gray-400">{connections.length} connection{connections.length !== 1 ? 's' : ''}</span>
                      </div>
                      {connections.map(conn => (
                        <div key={conn.id} className={`border-2 rounded-xl p-4 transition ${
                          conn.status === 'connected' ? 'border-green-200 bg-green-50/30' :
                          conn.status === 'failed' ? 'border-red-200 bg-red-50/30' :
                          'border-gray-200 bg-gray-50/30'
                        }`}>
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                              <div>
                                <div className="flex items-center gap-2">
                                  <span className="text-sm font-semibold text-gray-800">{conn.label}</span>
                                  {conn.label === 'Primary' && (
                                    <span className="px-1.5 py-0.5 bg-blue-100 text-blue-700 text-[9px] font-bold rounded">PRIMARY</span>
                                  )}
                                </div>
                                {conn.azure_directory_id && (
                                  <div className="text-[10px] text-gray-400 font-mono">{conn.azure_directory_id.slice(0, 8)}...</div>
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
                                conn.status === 'failed' ? 'text-red-600' :
                                'text-gray-400'
                              }`}>
                                <span className={`w-1.5 h-1.5 rounded-full ${
                                  conn.status === 'connected' ? 'bg-green-500' :
                                  conn.status === 'failed' ? 'bg-red-500' :
                                  'bg-gray-400'
                                }`} />
                                {conn.status === 'connected' ? 'Connected' :
                                 conn.status === 'failed' ? 'Failed' : 'Pending'}
                              </span>
                              {isAdmin && conn.status === 'connected' && (
                                <button
                                  onClick={() => handleRunScan(conn.id)}
                                  disabled={scanningConnId === conn.id}
                                  className="text-[10px] text-blue-500 hover:text-blue-700 font-medium disabled:opacity-50"
                                >
                                  {scanningConnId === conn.id ? 'Starting...' : 'Capture Snapshot'}
                                </button>
                              )}
                              {isAdmin && (
                                <button
                                  onClick={() => handleDeleteConnection(conn.id)}
                                  className="text-[10px] text-red-400 hover:text-red-600 font-medium"
                                >
                                  Remove
                                </button>
                              )}
                            </div>
                          </div>
                          {/* Discovered subscriptions warning */}
                          {(conn.discovered_count || 0) > 0 && (
                            <div className="mt-2 flex items-center gap-2 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 text-xs text-amber-700">
                              <svg className="w-3.5 h-3.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                              </svg>
                              <span>{conn.discovered_count} subscription(s) discovered — </span>
                              <a href="/subscriptions" className="font-semibold underline hover:text-amber-800">activate on Subscriptions page</a>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ))}
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
                          { key: 'gcp', label: 'GCP', desc: 'Google Cloud Platform (coming soon)', color: 'red', disabled: true },
                        ].map(c => (
                          <button
                            key={c.key}
                            disabled={c.disabled}
                            onClick={() => setWizardCloud(c.key)}
                            className={`w-full text-left border-2 rounded-xl p-4 transition ${
                              c.disabled ? 'opacity-50 cursor-not-allowed border-gray-200' :
                              wizardCloud === c.key ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:border-gray-300'
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <div>
                                <div className="text-sm font-semibold text-gray-800">{c.label}</div>
                                <div className="text-[10px] text-gray-500">{c.desc}</div>
                              </div>
                              {wizardCloud === c.key && !c.disabled && (
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
                                placeholder="AKIA..."
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

            {!isAdmin ? (
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
                        placeholder="AKIAIOSFODNN7EXAMPLE"
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
            )}
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
    </>
  );
}
