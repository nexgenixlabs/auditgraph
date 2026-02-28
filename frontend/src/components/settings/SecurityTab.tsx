import React from 'react';
import type { ApiKeyData } from './types';

export interface SecurityTabProps {
  apiKeys: ApiKeyData[];
  apiKeyError: string | null;
  setApiKeyError: (error: string | null) => void;
  openApiKeyModal: (key?: ApiKeyData) => void;
  handleToggleApiKey: (key: ApiKeyData) => void;
  apiKeyDeleteConfirm: number | null;
  setApiKeyDeleteConfirm: (id: number | null) => void;
  handleApiKeyDelete: (id: number) => void;
  ssoConfig: {
    sso_enabled: string;
    sso_idp_entity_id: string;
    sso_idp_sso_url: string;
    sso_idp_slo_url: string;
    sso_idp_x509_cert: string;
    sso_role_mapping: string;
    sso_default_role: string;
    sso_jit_enabled: string;
    sso_force_sso: string;
  };
  setSsoConfig: React.Dispatch<React.SetStateAction<{
    sso_enabled: string;
    sso_idp_entity_id: string;
    sso_idp_sso_url: string;
    sso_idp_slo_url: string;
    sso_idp_x509_cert: string;
    sso_role_mapping: string;
    sso_default_role: string;
    sso_jit_enabled: string;
    sso_force_sso: string;
  }>>;
  ssoMessage: { type: 'success' | 'error'; text: string } | null;
  ssoMetadataUrl: string;
  setSsoMetadataUrl: (url: string) => void;
  ssoParsing: boolean;
  ssoSaving: boolean;
  ssoSpInfo: { sp_entity_id: string; sp_acs_url: string; sp_metadata_url: string };
  ssoRoleMappings: { group: string; role: string }[];
  setSsoRoleMappings: React.Dispatch<React.SetStateAction<{ group: string; role: string }[]>>;
  handleSsoParseMetadata: () => void;
  handleSsoSave: () => void;
}

export function SecurityTab({
  apiKeys,
  apiKeyError,
  setApiKeyError,
  openApiKeyModal,
  handleToggleApiKey,
  apiKeyDeleteConfirm,
  setApiKeyDeleteConfirm,
  handleApiKeyDelete,
  ssoConfig,
  setSsoConfig,
  ssoMessage,
  ssoMetadataUrl,
  setSsoMetadataUrl,
  ssoParsing,
  ssoSaving,
  ssoSpInfo,
  ssoRoleMappings,
  setSsoRoleMappings,
  handleSsoParseMetadata,
  handleSsoSave,
}: SecurityTabProps) {
  return (
    <>
      {/* Section 8: API Keys */}
      <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-lg font-semibold text-gray-900">API Keys</div>
            <p className="text-sm text-gray-500 mt-0.5">
              Manage programmatic access keys for integrations and automations
            </p>
          </div>
          <button
            onClick={() => openApiKeyModal()}
            className="px-4 py-2 rounded-lg text-sm font-medium bg-blue-600 text-white hover:bg-blue-700 transition"
          >
            + Create API Key
          </button>
        </div>

        {apiKeyError && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">
            {apiKeyError}
            <button onClick={() => setApiKeyError(null)} className="ml-2 font-medium underline">Dismiss</button>
          </div>
        )}

        {apiKeys.length === 0 ? (
          <p className="text-sm text-gray-400 py-4 text-center">No API keys configured</p>
        ) : (
          <div className="space-y-2">
            {apiKeys.map(k => (
              <div key={k.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg border">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center text-xs font-bold text-purple-600">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                        d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                    </svg>
                  </div>
                  <div>
                    <div className="text-sm font-medium text-gray-900 flex items-center gap-2">
                      {k.name}
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium uppercase ${
                        k.role === 'admin' ? 'bg-red-50 text-red-700' :
                        k.role === 'security_admin' ? 'bg-amber-50 text-amber-700' :
                        k.role === 'compliance' ? 'bg-green-50 text-green-700' :
                        'bg-blue-50 text-blue-700'
                      }`}>
                        {k.role === 'security_admin' ? 'Security Admin' : k.role}
                      </span>
                      {!k.enabled && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-yellow-50 text-yellow-700">DISABLED</span>
                      )}
                    </div>
                    <div className="text-xs text-gray-500">
                      <span className="font-mono">{k.key_prefix}{'****'}</span>
                      {' '}&middot; {k.usage_count} request{k.usage_count !== 1 ? 's' : ''}
                      {k.last_used_at && <> &middot; Last used {new Date(k.last_used_at).toLocaleDateString()}</>}
                      {k.expires_at && <> &middot; Expires {new Date(k.expires_at).toLocaleDateString()}</>}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleToggleApiKey(k)}
                    className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                      k.enabled ? 'bg-green-500' : 'bg-gray-300'
                    }`}
                    title={k.enabled ? 'Disable key' : 'Enable key'}
                  >
                    <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                      k.enabled ? 'translate-x-4' : 'translate-x-0.5'
                    }`} />
                  </button>
                  <button
                    onClick={() => openApiKeyModal(k)}
                    className="px-2 py-1 text-xs text-blue-600 hover:bg-blue-50 rounded transition"
                  >
                    Edit
                  </button>
                  {apiKeyDeleteConfirm === k.id ? (
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => handleApiKeyDelete(k.id)}
                        className="px-2 py-1 text-xs text-white bg-red-600 hover:bg-red-700 rounded transition"
                      >
                        Confirm
                      </button>
                      <button
                        onClick={() => setApiKeyDeleteConfirm(null)}
                        className="px-2 py-1 text-xs text-gray-600 hover:bg-gray-100 rounded transition"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => setApiKeyDeleteConfirm(k.id)}
                      className="px-2 py-1 text-xs text-red-600 hover:bg-red-50 rounded transition"
                    >
                      Delete
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        <p className="text-xs text-gray-400">
          API keys authenticate requests via <code className="bg-gray-100 px-1 rounded">X-API-Key</code> header or Bearer token with <code className="bg-gray-100 px-1 rounded">ag_</code> prefix.
          Keys inherit the assigned role's permissions.
        </p>
      </div>

      {/* Section 9: SSO/SAML Configuration (Phase 54) */}
      <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-lg font-semibold text-gray-900">SSO / SAML</div>
            <p className="text-sm text-gray-500 mt-0.5">Configure SAML 2.0 Single Sign-On with your identity provider</p>
          </div>
          <button
            onClick={() => setSsoConfig(prev => ({ ...prev, sso_enabled: prev.sso_enabled === 'true' ? 'false' : 'true' }))}
            className={`relative inline-flex h-5 w-9 items-center rounded-full transition ${ssoConfig.sso_enabled === 'true' ? 'bg-blue-600' : 'bg-gray-300'}`}
          >
            <span className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition ${ssoConfig.sso_enabled === 'true' ? 'translate-x-[18px]' : 'translate-x-[3px]'}`} />
          </button>
        </div>

        {ssoMessage && (
          <div className={`p-3 rounded-lg text-sm ${ssoMessage.type === 'success' ? 'bg-green-50 border border-green-200 text-green-700' : 'bg-red-50 border border-red-200 text-red-700'}`}>
            {ssoMessage.text}
          </div>
        )}

        {/* Quick Setup Presets */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
          <div className="text-xs font-semibold text-blue-700 mb-2">Quick Setup</div>
          <div className="flex gap-2">
            <button
              onClick={() => {
                const tid = prompt('Enter your Azure AD Tenant ID (GUID):');
                if (tid) setSsoMetadataUrl(`https://login.microsoftonline.com/${tid}/federationmetadata/2007-06/federationmetadata.xml`);
              }}
              className="px-3 py-1.5 bg-blue-100 text-blue-700 text-xs font-medium rounded-lg hover:bg-blue-200 transition"
            >
              Azure AD / Entra ID
            </button>
            <button
              onClick={() => setSsoMetadataUrl('')}
              className="px-3 py-1.5 bg-gray-100 text-gray-600 text-xs font-medium rounded-lg hover:bg-gray-200 transition"
            >
              Okta
            </button>
            <button
              onClick={() => setSsoMetadataUrl('')}
              className="px-3 py-1.5 bg-gray-100 text-gray-600 text-xs font-medium rounded-lg hover:bg-gray-200 transition"
            >
              Other SAML 2.0
            </button>
          </div>
        </div>

        {/* IdP Metadata URL shortcut */}
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">IdP Metadata URL</label>
          <div className="flex gap-2">
            <input
              value={ssoMetadataUrl}
              onChange={e => setSsoMetadataUrl(e.target.value)}
              className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm"
              placeholder="https://login.microsoftonline.com/.../federationmetadata/2007-06/federationmetadata.xml"
            />
            <button
              onClick={handleSsoParseMetadata}
              disabled={ssoParsing || !ssoMetadataUrl}
              className="px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 disabled:opacity-40 transition whitespace-nowrap"
            >
              {ssoParsing ? 'Parsing...' : 'Fetch & Parse'}
            </button>
          </div>
          <p className="text-[10px] text-gray-400 mt-1">Auto-fills the fields below from your IdP's metadata endpoint</p>
        </div>

        {/* Manual IdP config fields */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">IdP Entity ID</label>
            <input
              value={ssoConfig.sso_idp_entity_id}
              onChange={e => setSsoConfig(prev => ({ ...prev, sso_idp_entity_id: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
              placeholder="https://sts.windows.net/..."
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">SSO URL</label>
            <input
              value={ssoConfig.sso_idp_sso_url}
              onChange={e => setSsoConfig(prev => ({ ...prev, sso_idp_sso_url: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
              placeholder="https://login.microsoftonline.com/.../saml2"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">SLO URL (Optional)</label>
            <input
              value={ssoConfig.sso_idp_slo_url}
              onChange={e => setSsoConfig(prev => ({ ...prev, sso_idp_slo_url: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
              placeholder="https://login.microsoftonline.com/.../saml2"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Default Role</label>
            <select
              value={ssoConfig.sso_default_role}
              onChange={e => setSsoConfig(prev => ({ ...prev, sso_default_role: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
            >
              <option value="compliance">Compliance</option>
              <option value="reader">Reader</option>
              <option value="admin">Admin</option>
            </select>
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">X.509 Certificate (PEM)</label>
          <textarea
            value={ssoConfig.sso_idp_x509_cert}
            onChange={e => setSsoConfig(prev => ({ ...prev, sso_idp_x509_cert: e.target.value }))}
            rows={3}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg text-xs font-mono"
            placeholder="MIIDpDCCA..."
          />
        </div>

        {/* SP Information (read-only) */}
        {ssoSpInfo.sp_entity_id && (
          <div className="bg-gray-50 rounded-lg p-3 space-y-1">
            <div className="text-xs font-semibold text-gray-700 mb-1">Service Provider Information (copy to your IdP)</div>
            <div className="flex items-center gap-2 text-xs">
              <span className="text-gray-500 w-24">Entity ID:</span>
              <code className="text-gray-800 bg-white px-2 py-0.5 rounded border text-[11px] flex-1">{ssoSpInfo.sp_entity_id}</code>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="text-gray-500 w-24">ACS URL:</span>
              <code className="text-gray-800 bg-white px-2 py-0.5 rounded border text-[11px] flex-1">{ssoSpInfo.sp_acs_url}</code>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="text-gray-500 w-24">Metadata:</span>
              <code className="text-gray-800 bg-white px-2 py-0.5 rounded border text-[11px] flex-1">{ssoSpInfo.sp_metadata_url}</code>
            </div>
          </div>
        )}

        {/* Role Mapping */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-medium text-gray-600">Role Mapping (IdP Group → AuditGraph Role)</label>
            <button
              onClick={() => setSsoRoleMappings(prev => [...prev, { group: '', role: 'compliance' }])}
              className="text-xs text-blue-600 hover:underline"
            >
              + Add Mapping
            </button>
          </div>
          {ssoRoleMappings.length === 0 && (
            <p className="text-xs text-gray-400 py-2">No role mappings configured. All SSO users will get the default role.</p>
          )}
          {ssoRoleMappings.map((m, i) => (
            <div key={i} className="flex items-center gap-2 mb-1.5">
              <input
                value={m.group}
                onChange={e => {
                  const updated = [...ssoRoleMappings];
                  updated[i] = { ...m, group: e.target.value };
                  setSsoRoleMappings(updated);
                }}
                className="flex-1 px-3 py-1.5 border border-gray-300 rounded-lg text-sm"
                placeholder="IdP Group Name"
              />
              <span className="text-xs text-gray-400">&rarr;</span>
              <select
                value={m.role}
                onChange={e => {
                  const updated = [...ssoRoleMappings];
                  updated[i] = { ...m, role: e.target.value };
                  setSsoRoleMappings(updated);
                }}
                className="px-3 py-1.5 border border-gray-300 rounded-lg text-sm"
              >
                <option value="compliance">Compliance</option>
                <option value="reader">Reader</option>
                <option value="admin">Admin</option>
              </select>
              <button
                onClick={() => setSsoRoleMappings(prev => prev.filter((_, j) => j !== i))}
                className="text-red-400 hover:text-red-600 text-xs px-1"
              >
                ×
              </button>
            </div>
          ))}
        </div>

        {/* Toggle options */}
        <div className="flex items-center gap-6">
          <label className="flex items-center gap-2 text-sm text-gray-700">
            <button
              onClick={() => setSsoConfig(prev => ({ ...prev, sso_jit_enabled: prev.sso_jit_enabled === 'true' ? 'false' : 'true' }))}
              className={`relative inline-flex h-4 w-7 items-center rounded-full transition ${ssoConfig.sso_jit_enabled === 'true' ? 'bg-blue-600' : 'bg-gray-300'}`}
            >
              <span className={`inline-block h-3 w-3 rounded-full bg-white transition ${ssoConfig.sso_jit_enabled === 'true' ? 'translate-x-[14px]' : 'translate-x-[2px]'}`} />
            </button>
            JIT User Provisioning
          </label>
          <label className="flex items-center gap-2 text-sm text-gray-700">
            <button
              onClick={() => setSsoConfig(prev => ({ ...prev, sso_force_sso: prev.sso_force_sso === 'true' ? 'false' : 'true' }))}
              className={`relative inline-flex h-4 w-7 items-center rounded-full transition ${ssoConfig.sso_force_sso === 'true' ? 'bg-red-600' : 'bg-gray-300'}`}
            >
              <span className={`inline-block h-3 w-3 rounded-full bg-white transition ${ssoConfig.sso_force_sso === 'true' ? 'translate-x-[14px]' : 'translate-x-[2px]'}`} />
            </button>
            Force SSO (disable local login)
          </label>
        </div>
        {ssoConfig.sso_force_sso === 'true' && (
          <p className="text-xs text-red-500">Warning: Enabling Force SSO will prevent local credential login for all non-superadmin users in this tenant.</p>
        )}

        <button
          onClick={handleSsoSave}
          disabled={ssoSaving}
          className="px-6 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-40 transition"
        >
          {ssoSaving ? 'Saving...' : 'Save SSO Settings'}
        </button>
      </div>
    </>
  );
}
