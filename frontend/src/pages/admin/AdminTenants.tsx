import React, { useEffect, useState, useCallback } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import {
  ADDON_PRICING, BASE_FEATURES, COMING_SOON_FEATURES, ENTERPRISE_BUNDLES,
  CLOUD_LABELS, ACCOUNT_TIER_LABELS,
  SUBSCRIPTION_TERMS, getTermDiscount, getTermLabel,
  SUB_RATES_CENTS,
  formatCents,
  type CloudConfig,
} from '../../constants/pricing';

interface Tenant {
  id: number;
  name: string;
  slug: string;
  plan: string;
  enabled: boolean;
  user_count: number;
  created_at: string;
  license_activated_at: string | null;
  license_expires_at: string | null;
  subscription_term: number;
  settings?: Record<string, unknown>;
}

interface ProvisionForm {
  admin_username: string;
  admin_display_name: string;
  admin_password: string;
}

const DEFAULT_CLOUD_CONFIG: CloudConfig = {
  cloud_providers: {
    azure: { enabled: true, plan: 'pro' },
    aws: { enabled: false, plan: null },
    gcp: { enabled: false, plan: null },
  },
  addons: {
    extended_retention: false,
    additional_users_5pack: false,
  },
};

function formatDate(iso: string | null): string {
  if (!iso) return '\u2014';
  return new Date(iso).toLocaleDateString();
}

function licenseStatus(t: Tenant): { label: string; color: string } {
  if (!t.license_activated_at) return { label: 'Not Activated', color: 'text-gray-400' };
  if (t.license_expires_at) {
    const days = Math.ceil((new Date(t.license_expires_at).getTime() - Date.now()) / 86400000);
    if (days < 0) return { label: 'Expired', color: 'text-red-600' };
    if (days < 30) return { label: `${days}d left`, color: 'text-yellow-600' };
  }
  return { label: 'Active', color: 'text-green-600' };
}

export default function AdminTenants() {
  const { switchTenant, user } = useAuth();
  const portalRole = user?.portal_role;
  const isSuperadmin = portalRole === 'superadmin';
  const canWrite = portalRole === 'superadmin' || portalRole === 'poweradmin';
  const isReadOnly = !canWrite;
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [showProvision, setShowProvision] = useState<number | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState<Tenant | null>(null);
  const [deleteConfirmName, setDeleteConfirmName] = useState('');
  const [showEdit, setShowEdit] = useState<Tenant | null>(null);
  const [editForm, setEditForm] = useState({ name: '' });
  const [logoFile, setLogoFile] = useState<File | null>(null);
  const [logoPreview, setLogoPreview] = useState<string | null>(null);
  const [uploadingLogo, setUploadingLogo] = useState(false);
  const [provisionForm, setProvisionForm] = useState<ProvisionForm>({ admin_username: '', admin_display_name: '', admin_password: '' });
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [showConfigure, setShowConfigure] = useState<Tenant | null>(null);
  const [configForm, setConfigForm] = useState<CloudConfig>(DEFAULT_CLOUD_CONFIG);
  const [configTerm, setConfigTerm] = useState(0);
  const [configSaving, setConfigSaving] = useState(false);
  const [tenantBilling, setTenantBilling] = useState<{
    billing: { platform_fee_cents: number; subscription_total_cents: number; net_monthly_cents: number; active_count: number; subscriptions_by_cloud: Record<string, { count: number; revenue_cents: number }> };
    subscriptions: Array<{ cloud: string; rate_cents: number; monitored: boolean }>;
  } | null>(null);

  const fetchTenants = useCallback(() => {
    fetch('/api/tenants')
      .then(r => {
        if (!r.ok) throw new Error(`Failed to load tenants (${r.status})`);
        return r.json();
      })
      .then(d => setTenants(d.tenants || []))
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load tenants'))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { fetchTenants(); }, [fetchTenants]);

  async function handleProvision(tenantId: number) {
    setError(null);
    try {
      const res = await fetch(`/api/tenants/${tenantId}/provision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(provisionForm),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to provision tenant');
      setSuccess(data.message || 'Tenant provisioned successfully');
      setShowProvision(null);
      setProvisionForm({ admin_username: '', admin_display_name: '', admin_password: '' });
      fetchTenants();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to provision');
    }
  }

  async function toggleEnabled(t: Tenant) {
    try {
      await fetch(`/api/tenants/${t.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !t.enabled }),
      });
      fetchTenants();
    } catch { /* ignore */ }
  }

  async function changePlan(t: Tenant, plan: string) {
    try {
      await fetch(`/api/admin/tenants/${t.id}/plan`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plan }),
      });
      fetchTenants();
    } catch { /* ignore */ }
  }

  async function handleDelete() {
    if (!showDeleteConfirm) return;
    setError(null);
    try {
      const res = await fetch(`/api/tenants/${showDeleteConfirm.id}`, { method: 'DELETE' });
      const text = await res.text();
      let data: Record<string, string> = {};
      try { data = JSON.parse(text); } catch { /* non-JSON response */ }
      if (!res.ok) throw new Error(data.error || `Failed to delete tenant (${res.status})`);
      setSuccess(`Tenant "${showDeleteConfirm.name}" deleted successfully`);
      setShowDeleteConfirm(null);
      setDeleteConfirmName('');
      fetchTenants();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete tenant');
    }
  }

  async function handleEdit() {
    if (!showEdit) return;
    setError(null);
    try {
      const res = await fetch(`/api/tenants/${showEdit.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: editForm.name }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to update tenant');
      setSuccess(`Tenant updated successfully`);
      setShowEdit(null);
      fetchTenants();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update tenant');
    }
  }

  function handleLogoSelect(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 500 * 1024) {
      setError('Logo must be under 500KB');
      return;
    }
    if (!['image/png', 'image/jpeg', 'image/svg+xml'].includes(file.type)) {
      setError('Logo must be PNG, JPEG, or SVG');
      return;
    }
    setLogoFile(file);
    const reader = new FileReader();
    reader.onload = () => setLogoPreview(reader.result as string);
    reader.readAsDataURL(file);
  }

  async function handleLogoUpload(tenantId: number) {
    if (!logoFile) return;
    setUploadingLogo(true);
    try {
      const reader = new FileReader();
      const dataUrl = await new Promise<string>((resolve) => {
        reader.onload = () => resolve(reader.result as string);
        reader.readAsDataURL(logoFile);
      });
      const res = await fetch(`/api/tenants/${tenantId}/logo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ logo: dataUrl }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to upload logo');
      }
      setSuccess('Logo uploaded');
      setLogoFile(null);
      setLogoPreview(null);
      fetchTenants();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to upload logo');
    } finally {
      setUploadingLogo(false);
    }
  }

  async function handleLogoDelete(tenantId: number) {
    try {
      const res = await fetch(`/api/tenants/${tenantId}/logo`, { method: 'DELETE' });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to delete logo');
      }
      setSuccess('Logo removed');
      fetchTenants();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete logo');
    }
  }

  function openConfigure(t: Tenant) {
    const settings = (t.settings || {}) as Record<string, unknown>;
    const cp = (settings.cloud_providers || DEFAULT_CLOUD_CONFIG.cloud_providers) as CloudConfig['cloud_providers'];
    const addons = (settings.addons || DEFAULT_CLOUD_CONFIG.addons) as CloudConfig['addons'];
    setConfigForm({ cloud_providers: { ...DEFAULT_CLOUD_CONFIG.cloud_providers, ...cp }, addons: { ...DEFAULT_CLOUD_CONFIG.addons, ...addons } });
    setConfigTerm(t.subscription_term || 0);
    setShowConfigure(t);
    setTenantBilling(null);
    // Fetch billing data for this tenant
    fetch(`/api/admin/tenants/${t.id}/billing`)
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data) setTenantBilling(data); })
      .catch(() => {});
  }

  async function handleSaveConfig() {
    if (!showConfigure) return;
    setConfigSaving(true);
    setError(null);
    try {
      const existingSettings = (showConfigure.settings || {}) as Record<string, unknown>;
      const mergedSettings = {
        ...existingSettings,
        cloud_providers: configForm.cloud_providers,
        addons: configForm.addons,
      };
      const payload: Record<string, unknown> = { settings: mergedSettings, subscription_term: configTerm };
      if (configTerm > 0 && !showConfigure.license_activated_at) {
        payload.license_activated_at = new Date().toISOString();
      }
      const res = await fetch(`/api/tenants/${showConfigure.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to save configuration');
      setSuccess(`Cloud configuration saved for "${showConfigure.name}"`);
      setShowConfigure(null);
      fetchTenants();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to save configuration');
    } finally {
      setConfigSaving(false);
    }
  }

  function toggleCloudProvider(provider: string) {
    setConfigForm(prev => {
      const current = prev.cloud_providers[provider] || { enabled: false, plan: null };
      const newEnabled = !current.enabled;
      return {
        ...prev,
        cloud_providers: {
          ...prev.cloud_providers,
          [provider]: {
            enabled: newEnabled,
            plan: newEnabled ? (current.plan || 'pro') : null,
          },
        },
      };
    });
  }

  function setCloudPlan(provider: string, plan: string) {
    setConfigForm(prev => ({
      ...prev,
      cloud_providers: {
        ...prev.cloud_providers,
        [provider]: { ...prev.cloud_providers[provider], plan },
      },
    }));
  }

  function toggleAddon(addon: string) {
    setConfigForm(prev => ({
      ...prev,
      addons: { ...prev.addons, [addon]: !prev.addons[addon] },
    }));
  }

  const isProvisioned = (t: Tenant) => {
    const s = t.settings;
    return s && typeof s === 'object' && (s as Record<string, unknown>).provisioned === true;
  };

  const configPlan = showConfigure?.plan || 'pro';
  const isEnterprise = configPlan === 'enterprise';
  const termDiscount = getTermDiscount(configTerm);
  const enterpriseBundles = ENTERPRISE_BUNDLES[configTerm] || [];

  if (loading) return <div className="flex items-center justify-center h-64 text-gray-400">Loading tenants...</div>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900">Tenant Management</h2>
          <p className="text-sm text-gray-500 mt-0.5">{tenants.length} organizations</p>
        </div>
        {canWrite && (
          <p className="text-xs text-gray-500">
            To create a new tenant, use the{' '}
            <a href="/admin/onboarding" className="text-blue-600 hover:text-blue-700 underline">Onboarding</a> tab.
          </p>
        )}
      </div>

      {/* Status messages */}
      {error && <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">{error}<button onClick={() => setError(null)} className="ml-2 text-red-500">&times;</button></div>}
      {success && <div className="bg-green-50 border border-green-200 rounded-lg p-3 text-sm text-green-700">{success}<button onClick={() => setSuccess(null)} className="ml-2 text-green-500">&times;</button></div>}

      {/* Provision modal */}
      {showProvision !== null && (
        <div className="bg-white border border-blue-200 rounded-lg p-6 shadow-sm">
          <h3 className="text-sm font-semibold text-gray-800 mb-3">Provision Tenant — Create Admin User</h3>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Admin Username</label>
              <input value={provisionForm.admin_username} onChange={e => setProvisionForm(p => ({ ...p, admin_username: e.target.value }))} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="admin" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Display Name</label>
              <input value={provisionForm.admin_display_name} onChange={e => setProvisionForm(p => ({ ...p, admin_display_name: e.target.value }))} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="John Admin" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Password</label>
              <input type="password" value={provisionForm.admin_password} onChange={e => setProvisionForm(p => ({ ...p, admin_password: e.target.value }))} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="Min 8 characters" />
            </div>
            <div className="col-span-3 flex gap-2">
              <button onClick={() => handleProvision(showProvision)} disabled={!provisionForm.admin_username || !provisionForm.admin_display_name || provisionForm.admin_password.length < 8} className="px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed">Provision</button>
              <button onClick={() => setShowProvision(null)} className="px-4 py-2 bg-gray-100 text-gray-700 text-sm rounded-lg hover:bg-gray-200">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirmation modal */}
      {showDeleteConfirm && (
        <div className="bg-white border border-red-200 rounded-lg p-6 shadow-sm">
          <h3 className="text-sm font-semibold text-red-700 mb-2">Delete Organization</h3>
          <p className="text-xs text-gray-600 mb-3">
            This will permanently delete <span className="font-semibold">{showDeleteConfirm.name}</span> and all associated data including users, discovery runs, and settings. This action cannot be undone.
          </p>
          <div className="mb-3">
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Type <span className="font-mono font-bold">{showDeleteConfirm.name}</span> to confirm
            </label>
            <input
              value={deleteConfirmName}
              onChange={e => setDeleteConfirmName(e.target.value)}
              className="w-full max-w-xs px-3 py-2 border border-gray-300 rounded-lg text-sm"
              placeholder="Organization name"
            />
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleDelete}
              disabled={deleteConfirmName.trim() !== showDeleteConfirm.name.trim()}
              className="px-4 py-2 bg-red-600 text-white text-sm rounded-lg hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Delete Permanently
            </button>
            <button
              onClick={() => { setShowDeleteConfirm(null); setDeleteConfirmName(''); }}
              className="px-4 py-2 bg-gray-100 text-gray-700 text-sm rounded-lg hover:bg-gray-200"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Edit tenant modal */}
      {showEdit && (
        <div className="bg-white border border-gray-200 rounded-lg p-6 shadow-sm">
          <h3 className="text-sm font-semibold text-gray-800 mb-3">Edit Organization</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Name</label>
              <input
                value={editForm.name}
                onChange={e => setEditForm({ name: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Slug (read-only)</label>
              <input
                value={showEdit.slug}
                readOnly
                className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm bg-gray-50 text-gray-500 cursor-not-allowed"
              />
            </div>
            {/* Logo upload */}
            <div className="col-span-2">
              <label className="block text-xs font-medium text-gray-600 mb-1">Organization Logo</label>
              <div className="flex items-center gap-3 flex-wrap">
                {!!(logoPreview || (showEdit.settings as Record<string, unknown> | undefined)?.logo_url) && (
                  <img
                    src={logoPreview || String((showEdit.settings as Record<string, unknown>)?.logo_url || '')}
                    alt="Logo"
                    className="w-10 h-10 rounded-lg object-cover border border-gray-200"
                  />
                )}
                <input
                  type="file"
                  accept="image/png,image/jpeg,image/svg+xml"
                  onChange={handleLogoSelect}
                  className="text-xs text-gray-600 file:mr-2 file:py-1 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-medium file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100"
                />
                {!!logoFile && (
                  <button
                    onClick={() => handleLogoUpload(showEdit.id)}
                    disabled={uploadingLogo}
                    className="px-3 py-1 bg-blue-600 text-white text-xs rounded-lg hover:bg-blue-700 disabled:opacity-40"
                  >
                    {uploadingLogo ? 'Uploading...' : 'Upload'}
                  </button>
                )}
                {!logoFile && !!(showEdit.settings as Record<string, unknown> | undefined)?.logo_url && (
                  <button
                    onClick={() => handleLogoDelete(showEdit.id)}
                    className="px-3 py-1 bg-red-50 text-red-600 text-xs rounded-lg hover:bg-red-100"
                  >
                    Remove
                  </button>
                )}
              </div>
              <p className="text-[10px] text-gray-400 mt-1">PNG, JPEG, or SVG. Max 500KB.</p>
            </div>
            <div className="col-span-2 flex gap-2">
              <button
                onClick={handleEdit}
                disabled={!editForm.name.trim()}
                className="px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Save Changes
              </button>
              <button onClick={() => { setShowEdit(null); setLogoFile(null); setLogoPreview(null); }} className="px-4 py-2 bg-gray-100 text-gray-700 text-sm rounded-lg hover:bg-gray-200">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Cloud Configuration Panel */}
      {showConfigure && (
        <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden">
          {/* Client Info Header */}
          <div className="bg-slate-900 px-6 py-4 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white">{showConfigure.name}</h3>
              <p className="text-xs text-slate-400 mt-0.5">{showConfigure.slug}.auditgraph.io</p>
            </div>
            <div className="text-right">
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${isEnterprise ? 'bg-purple-500/20 text-purple-300' : 'bg-blue-500/20 text-blue-300'}`}>
                  {configPlan.toUpperCase()}
                </span>
                <span className="text-lg font-bold text-white">
                  {tenantBilling ? formatCents(tenantBilling.billing.net_monthly_cents) : '$0'}
                  <span className="text-xs font-normal text-slate-400">/mo</span>
                </span>
              </div>
              {tenantBilling ? (
                <div className="text-[10px] text-slate-400">
                  {formatCents(tenantBilling.billing.platform_fee_cents)} platform + {tenantBilling.billing.active_count} sub{tenantBilling.billing.active_count !== 1 ? 's' : ''}
                </div>
              ) : (
                <div className="text-[10px] text-slate-400">Loading billing...</div>
              )}
            </div>
            <button onClick={() => setShowConfigure(null)} className="text-slate-400 hover:text-white text-lg leading-none ml-4">&times;</button>
          </div>

          <div className="p-6">
            {/* Cloud Providers */}
            <div className="mb-6">
              <h4 className="text-xs font-semibold text-gray-700 uppercase tracking-wider mb-3">Cloud Providers</h4>
              <div className="space-y-3">
                {Object.entries(CLOUD_LABELS).map(([key, meta]) => {
                  const cfg = configForm.cloud_providers[key] || { enabled: false, plan: null };
                  const cloudBillingData = tenantBilling?.billing.subscriptions_by_cloud[key];
                  const subCount = cloudBillingData?.count ?? 0;
                  return (
                    <div key={key} className={`border-2 rounded-xl p-4 transition ${cfg.enabled ? 'border-blue-300 bg-blue-50/30' : 'border-gray-200 bg-gray-50/30'}`}>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <span className={`px-2 py-0.5 rounded text-xs font-bold ${meta.bg} ${meta.color}`}>{meta.label}</span>
                          <span className="text-xs text-gray-500">{meta.description}</span>
                        </div>
                        <button
                          onClick={() => toggleCloudProvider(key)}
                          className={`relative w-11 h-6 rounded-full transition-colors shrink-0 ${cfg.enabled ? 'bg-blue-500' : 'bg-gray-300'}`}
                        >
                          <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${cfg.enabled ? 'translate-x-5' : ''}`} />
                        </button>
                      </div>
                      {cfg.enabled && (
                        <div className="mt-3">
                          <div className="flex items-center justify-between px-3 py-2 border border-blue-400 bg-blue-50 rounded-lg">
                            {isEnterprise ? (
                              <>
                                <span className="text-xs font-semibold text-purple-700">Included in Enterprise</span>
                                <span className="text-[10px] font-bold text-green-600 uppercase tracking-wider">Included</span>
                              </>
                            ) : (
                              <>
                                <span className="text-xs font-semibold text-blue-700">{subCount} subscription{subCount !== 1 ? 's' : ''} monitored</span>
                                <span className="text-xs font-bold text-blue-700">
                                  {cloudBillingData ? formatCents(cloudBillingData.revenue_cents) : '$0'}/mo
                                  <span className="text-[10px] font-normal text-gray-400"> @ {formatCents(SUB_RATES_CENTS[key] ?? 6900)}/sub</span>
                                </span>
                              </>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Base Features (included with Pro+) */}
            <div className="mb-6">
              <h4 className="text-xs font-semibold text-gray-700 uppercase tracking-wider mb-3">Included with Pro & Enterprise</h4>
              <div className="space-y-2">
                {Object.entries(BASE_FEATURES).map(([key, feat]) => (
                  <div key={key} className="flex items-center justify-between border-2 border-green-200 bg-green-50/30 rounded-xl px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div className="w-5 h-5 rounded flex items-center justify-center bg-green-500 text-white">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" /></svg>
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-gray-800">{feat.label}</div>
                        <div className="text-[10px] text-gray-500">{feat.description}</div>
                      </div>
                    </div>
                    <span className="text-[10px] font-bold text-green-600 uppercase tracking-wider">Included</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Paid Add-Ons (Pro only — Enterprise includes all) */}
            <div className="mb-6">
              <h4 className="text-xs font-semibold text-gray-700 uppercase tracking-wider mb-3">
                {isEnterprise ? 'Add-Ons (Included with Enterprise)' : 'Paid Add-Ons'}
              </h4>
              <div className="space-y-2">
                {Object.entries(ADDON_PRICING).map(([key, addon]) => {
                  const enabled = configForm.addons[key] || false;
                  return (
                    <div
                      key={key}
                      className={`flex items-center justify-between border-2 rounded-xl px-4 py-3 transition ${
                        isEnterprise
                          ? 'border-green-200 bg-green-50/30'
                          : enabled ? 'border-green-300 bg-green-50/30' : 'border-gray-200'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <div className={`w-5 h-5 rounded flex items-center justify-center ${
                          isEnterprise || enabled ? 'bg-green-500 text-white' : 'bg-gray-200 text-gray-400'
                        }`}>
                          {isEnterprise || enabled ? (
                            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" /></svg>
                          ) : (
                            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
                          )}
                        </div>
                        <div>
                          <div className="text-xs font-semibold text-gray-800">{addon.label}</div>
                          <div className="text-[10px] text-gray-500">{addon.description}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        {isEnterprise ? (
                          <span className="text-[10px] font-bold text-green-600 uppercase tracking-wider">Included</span>
                        ) : (
                          <>
                            <span className={`text-xs font-bold ${enabled ? 'text-green-700' : 'text-gray-400'}`}>+${addon.price}/mo</span>
                            <button
                              onClick={() => toggleAddon(key)}
                              className={`relative w-11 h-6 rounded-full transition-colors shrink-0 ${enabled ? 'bg-green-500' : 'bg-gray-300'}`}
                            >
                              <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${enabled ? 'translate-x-5' : ''}`} />
                            </button>
                          </>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Coming Soon */}
            <div className="mb-6">
              <h4 className="text-xs font-semibold text-gray-700 uppercase tracking-wider mb-3">Coming Soon</h4>
              <div className="space-y-2">
                {Object.entries(COMING_SOON_FEATURES).map(([key, feat]) => (
                  <div key={key} className="flex items-center justify-between border-2 border-gray-200 bg-gray-50/50 rounded-xl px-4 py-3 opacity-60">
                    <div className="flex items-center gap-3">
                      <div className="w-5 h-5 rounded flex items-center justify-center bg-gray-300 text-gray-500">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-gray-500">{feat.label}</div>
                        <div className="text-[10px] text-gray-400">{feat.description}</div>
                      </div>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold text-gray-500 bg-gray-200 uppercase tracking-wider">Soon</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Subscription Term */}
          <div className="px-6 pb-2">
            <h4 className="text-xs font-semibold text-gray-700 uppercase tracking-wider mb-3">Subscription Term</h4>
            <div className="flex gap-2">
              {SUBSCRIPTION_TERMS.map(t => (
                <button
                  key={t.value}
                  onClick={() => setConfigTerm(t.value)}
                  className={`flex-1 px-3 py-2.5 border-2 rounded-lg text-center transition ${
                    configTerm === t.value
                      ? 'border-blue-500 bg-blue-50'
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                >
                  <div className={`text-xs font-semibold ${configTerm === t.value ? 'text-blue-700' : 'text-gray-700'}`}>{t.label}</div>
                  {t.discount > 0 ? (
                    <div className="text-[10px] font-semibold text-green-600 mt-0.5">{t.discount * 100}% off</div>
                  ) : (
                    <div className="text-[10px] text-gray-400 mt-0.5">No discount</div>
                  )}
                </button>
              ))}
            </div>
            {/* Enterprise term bundles */}
            {isEnterprise && enterpriseBundles.length > 0 && (
              <div className="mt-3 bg-purple-50 border border-purple-200 rounded-lg px-4 py-2.5">
                <div className="text-[10px] font-semibold text-purple-700 uppercase tracking-wider mb-1">Enterprise {getTermLabel(configTerm)} Bundle</div>
                <div className="flex flex-wrap gap-2">
                  {enterpriseBundles.map(b => (
                    <span key={b} className="px-2 py-0.5 bg-purple-100 text-purple-700 rounded text-[10px] font-semibold">{b}</span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Per-Subscription Billing Summary */}
          {!!tenantBilling && (
            <div className="px-6 pb-4">
              <h4 className="text-xs font-semibold text-gray-700 uppercase tracking-wider mb-3">Subscription Billing</h4>
              <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-gray-600">Platform Fee</span>
                  <span className="font-semibold text-gray-900">{formatCents(tenantBilling.billing.platform_fee_cents)}/mo</span>
                </div>
                {Object.entries(tenantBilling.billing.subscriptions_by_cloud).map(([cloud, data]) => (
                  <div key={cloud} className="flex items-center justify-between text-xs">
                    <span className="text-gray-600">{cloud.toUpperCase()} ({data.count} sub{data.count !== 1 ? 's' : ''})</span>
                    <span className="font-semibold text-gray-900">{formatCents(data.revenue_cents)}/mo</span>
                  </div>
                ))}
                {tenantBilling.billing.active_count === 0 && (
                  <div className="text-[10px] text-gray-400">No active subscriptions</div>
                )}
                <div className="border-t border-gray-200 pt-2 mt-2 flex items-center justify-between">
                  <span className="text-xs font-semibold text-gray-700">Net Monthly</span>
                  <span className="text-sm font-bold text-gray-900">{formatCents(tenantBilling.billing.net_monthly_cents)}/mo</span>
                </div>
              </div>
            </div>
          )}

          {/* Dark Billing Summary Card */}
          <div className="bg-gradient-to-r from-slate-900 to-slate-800 px-6 py-5">
            {/* Line items from billing API */}
            <div className="space-y-1.5 mb-3">
              {tenantBilling ? (
                <>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-300">Platform Fee ({configPlan})</span>
                    <span className="text-white font-semibold">{formatCents(tenantBilling.billing.platform_fee_cents)}/mo</span>
                  </div>
                  {Object.entries(tenantBilling.billing.subscriptions_by_cloud).map(([cloud, data]) => (
                    <div key={cloud} className="flex items-center justify-between text-xs">
                      <span className="text-slate-300">{CLOUD_LABELS[cloud]?.label || cloud.toUpperCase()} ({data.count} sub{data.count !== 1 ? 's' : ''})</span>
                      <span className="text-white font-semibold">{formatCents(data.revenue_cents)}/mo</span>
                    </div>
                  ))}
                  {Object.entries(configForm.addons).map(([key, enabled]) => {
                    if (!enabled) return null;
                    const addon = ADDON_PRICING[key];
                    if (!addon) return null;
                    return (
                      <div key={key} className="flex items-center justify-between text-xs">
                        <span className="text-slate-300">{addon.label}</span>
                        <span className="text-white font-semibold">+${addon.price}/mo</span>
                      </div>
                    );
                  })}
                </>
              ) : (
                <div className="text-xs text-slate-400">Loading billing data...</div>
              )}
            </div>

            <div className="border-t border-slate-700 pt-3 space-y-2">
              {configTerm === 0 ? (
                <div className="flex items-center justify-between">
                  <span className="text-sm font-bold text-white">Monthly Total</span>
                  <div className="text-right">
                    <span className="text-xl font-extrabold text-white">
                      {tenantBilling ? formatCents(tenantBilling.billing.net_monthly_cents) : '$0'}/mo
                    </span>
                    <div className="text-[10px] text-slate-400">excl. applicable taxes</div>
                  </div>
                </div>
              ) : (
                <>
                  {tenantBilling && (
                    <>
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-slate-400">Gross Monthly</span>
                        <span className="text-xs text-slate-400 line-through">{formatCents(tenantBilling.billing.net_monthly_cents)}/mo</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-slate-300">Discounted <span className="text-green-400">({termDiscount * 100}% off)</span></span>
                        <span className="text-sm font-semibold text-white">{formatCents(Math.round(tenantBilling.billing.net_monthly_cents * (1 - termDiscount)))}/mo</span>
                      </div>
                      <div className="flex items-center justify-between mt-2 pt-2 border-t border-slate-700">
                        <div>
                          <span className="text-sm font-bold text-white">{getTermLabel(configTerm)} Contract</span>
                          <div className="text-[10px] text-slate-400">{configTerm * 12} months</div>
                        </div>
                        <div className="text-right">
                          <span className="text-xl font-extrabold text-cyan-400">
                            {formatCents(Math.round(tenantBilling.billing.net_monthly_cents * (1 - termDiscount)) * configTerm * 12)}
                          </span>
                          <div className="text-[10px] text-slate-400">excl. applicable taxes</div>
                        </div>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-slate-400">Total savings over {configTerm}yr{configTerm > 1 ? 's' : ''}</span>
                        <span className="text-xs font-semibold text-green-400">
                          {formatCents(Math.round(tenantBilling.billing.net_monthly_cents * termDiscount) * configTerm * 12)}
                        </span>
                      </div>
                    </>
                  )}
                </>
              )}
            </div>

            <button
              onClick={handleSaveConfig}
              disabled={configSaving}
              className="w-full mt-4 py-2.5 bg-gradient-to-r from-blue-500 to-cyan-500 text-white text-sm font-bold rounded-lg hover:from-blue-600 hover:to-cyan-600 disabled:opacity-50 transition"
            >
              {configSaving ? 'Saving...' : 'Save & Apply Changes'}
            </button>
          </div>
        </div>
      )}

      {/* Tenant table */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <table className="min-w-full text-left text-xs">
          <thead className="bg-gray-50 border-b border-gray-200 text-gray-600 uppercase tracking-wider font-medium">
            <tr>
              <th className="px-4 py-2.5">Name</th>
              <th className="px-4 py-2.5">Slug</th>
              <th className="px-4 py-2.5">Plan</th>
              <th className="px-4 py-2.5">Term</th>
              <th className="px-4 py-2.5">Clouds</th>
              <th className="px-4 py-2.5">Users</th>
              <th className="px-4 py-2.5">Status</th>
              <th className="px-4 py-2.5">License Activated</th>
              <th className="px-4 py-2.5">License Expiry</th>
              <th className="px-4 py-2.5">Created</th>
              <th className="px-4 py-2.5">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {tenants.map(t => {
              const settings = (t.settings || {}) as Record<string, unknown>;
              const cp = (settings.cloud_providers || {}) as Record<string, { enabled: boolean; plan: string | null }>;
              const enabledClouds = Object.entries(cp).filter(([, v]) => v.enabled).map(([k]) => k);
              const cloudsToShow = enabledClouds.length > 0 ? enabledClouds : ['azure'];
              const ls = licenseStatus(t);
              return (
                <tr key={t.id} className="hover:bg-gray-50/60">
                  <td className="px-4 py-2.5 font-medium text-gray-900">{t.name}</td>
                  <td className="px-4 py-2.5 text-gray-600 font-mono">{t.slug}</td>
                  <td className="px-4 py-2.5">
                    <select value={t.plan} onChange={e => changePlan(t, e.target.value)} disabled={isReadOnly} className={`text-xs border border-gray-200 rounded px-1.5 py-0.5 ${isReadOnly ? 'opacity-60 cursor-not-allowed' : ''}`}>
                      {Object.entries(ACCOUNT_TIER_LABELS).map(([key, meta]) => (
                        <option key={key} value={key}>{meta.label}</option>
                      ))}
                    </select>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                      t.subscription_term > 0 ? 'bg-blue-50 text-blue-700' : 'bg-gray-100 text-gray-500'
                    }`}>{getTermLabel(t.subscription_term || 0)}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex gap-1 flex-wrap">
                      {cloudsToShow.map(cloud => {
                        const meta = CLOUD_LABELS[cloud];
                        return meta ? (
                          <span key={cloud} className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${meta.bg} ${meta.color}`}>{meta.label}</span>
                        ) : null;
                      })}
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-gray-700">{t.user_count}</td>
                  <td className="px-4 py-2.5">
                    {canWrite ? (
                      <button onClick={() => toggleEnabled(t)} className={`px-2 py-0.5 rounded text-[10px] font-semibold transition ${t.enabled ? 'bg-green-100 text-green-700 hover:bg-green-200' : 'bg-red-100 text-red-700 hover:bg-red-200'}`}>
                        {t.enabled ? 'Active' : 'Disabled'}
                      </button>
                    ) : (
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${t.enabled ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                        {t.enabled ? 'Active' : 'Disabled'}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-gray-500">{formatDate(t.license_activated_at)}</td>
                  <td className="px-4 py-2.5">
                    <div>
                      <span className={`text-[10px] font-semibold ${ls.color}`}>{ls.label}</span>
                      {t.license_expires_at && (
                        <div className="text-[9px] text-gray-400">{formatDate(t.license_expires_at)}</div>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-gray-500">{formatDate(t.created_at)}</td>
                  <td className="px-4 py-2.5">
                    {isReadOnly ? (
                      <span className="text-[10px] text-gray-400 font-medium">Read-only</span>
                    ) : (
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => openConfigure(t)}
                          className="text-[10px] text-indigo-600 hover:text-indigo-700 hover:underline font-medium"
                          title="Configure cloud providers & add-ons"
                        >
                          Configure
                        </button>
                        <button
                          disabled
                          className="text-[10px] text-gray-400 font-medium cursor-not-allowed"
                          title="Coming soon"
                        >
                          View As
                        </button>
                        {isSuperadmin && t.slug !== 'default' && (
                          <button
                            onClick={() => setShowDeleteConfirm(t)}
                            className="text-[10px] text-red-500 hover:text-red-700 hover:underline font-medium"
                            title="Delete organization"
                          >
                            Delete
                          </button>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
