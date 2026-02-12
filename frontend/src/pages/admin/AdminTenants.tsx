import React, { useEffect, useState, useCallback } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import {
  CLOUD_PRICING, ADDON_PRICING, BASE_FEATURES, COMING_SOON_FEATURES,
  CLOUD_LABELS, PLAN_TIERS, ACCOUNT_TIER_LABELS,
  ANNUAL_DISCOUNT, calculateMonthlyTotal, calculateCloudBaseTotal, calculateAddonTotal,
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
  settings?: Record<string, unknown>;
}

interface ProvisionForm {
  admin_username: string;
  admin_display_name: string;
  admin_password: string;
}

const DEFAULT_CLOUD_CONFIG: CloudConfig = {
  cloud_providers: {
    azure: { enabled: true, plan: 'starter' },
    aws: { enabled: false, plan: null },
    gcp: { enabled: false, plan: null },
  },
  addons: {
    extended_retention: false,
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
  const [showCreate, setShowCreate] = useState(false);
  const [showProvision, setShowProvision] = useState<number | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState<Tenant | null>(null);
  const [deleteConfirmName, setDeleteConfirmName] = useState('');
  const [showEdit, setShowEdit] = useState<Tenant | null>(null);
  const [editForm, setEditForm] = useState({ name: '' });
  const [createForm, setCreateForm] = useState({ name: '', slug: '', plan: 'pro' });
  const [provisionForm, setProvisionForm] = useState<ProvisionForm>({ admin_username: '', admin_display_name: '', admin_password: '' });
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [showConfigure, setShowConfigure] = useState<Tenant | null>(null);
  const [configForm, setConfigForm] = useState<CloudConfig>(DEFAULT_CLOUD_CONFIG);
  const [configSaving, setConfigSaving] = useState(false);

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

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const res = await fetch('/api/tenants', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(createForm),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to create tenant');
      setSuccess(`Tenant "${data.tenant.name}" created successfully`);
      setShowCreate(false);
      setCreateForm({ name: '', slug: '', plan: 'pro' });
      fetchTenants();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create tenant');
    }
  }

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
      // Auto-set license_activated_at when activating a paid plan
      const payload: Record<string, unknown> = { plan };
      if ((plan === 'pro' || plan === 'enterprise' || plan === 'trial') && !t.license_activated_at) {
        payload.license_activated_at = new Date().toISOString();
      }
      await fetch(`/api/tenants/${t.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      fetchTenants();
    } catch { /* ignore */ }
  }

  function handleViewAs(t: Tenant) {
    switchTenant(t.id, t.name);
    window.location.href = '/';
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

  function openConfigure(t: Tenant) {
    const settings = (t.settings || {}) as Record<string, unknown>;
    const cp = (settings.cloud_providers || DEFAULT_CLOUD_CONFIG.cloud_providers) as CloudConfig['cloud_providers'];
    const addons = (settings.addons || DEFAULT_CLOUD_CONFIG.addons) as CloudConfig['addons'];
    setConfigForm({ cloud_providers: { ...DEFAULT_CLOUD_CONFIG.cloud_providers, ...cp }, addons: { ...DEFAULT_CLOUD_CONFIG.addons, ...addons } });
    setShowConfigure(t);
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
      const res = await fetch(`/api/tenants/${showConfigure.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ settings: mergedSettings }),
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
            plan: newEnabled ? (current.plan || 'starter') : null,
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

  const monthlyTotal = calculateMonthlyTotal(configForm);
  const cloudBase = calculateCloudBaseTotal(configForm);
  const addonBase = calculateAddonTotal(configForm);
  const annualTotal = monthlyTotal * 12 * (1 - ANNUAL_DISCOUNT);
  const annualSavings = monthlyTotal * 12 * ANNUAL_DISCOUNT;

  if (loading) return <div className="flex items-center justify-center h-64 text-gray-400">Loading tenants...</div>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900">Tenant Management</h2>
          <p className="text-sm text-gray-500 mt-0.5">{tenants.length} organizations</p>
        </div>
        {canWrite && (
          <button onClick={() => setShowCreate(true)} className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 transition">
            Create Tenant
          </button>
        )}
      </div>

      {/* Status messages */}
      {error && <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">{error}<button onClick={() => setError(null)} className="ml-2 text-red-500">&times;</button></div>}
      {success && <div className="bg-green-50 border border-green-200 rounded-lg p-3 text-sm text-green-700">{success}<button onClick={() => setSuccess(null)} className="ml-2 text-green-500">&times;</button></div>}

      {/* Create modal */}
      {showCreate && (
        <div className="bg-white border border-gray-200 rounded-lg p-6 shadow-sm">
          <h3 className="text-sm font-semibold text-gray-800 mb-3">New Tenant</h3>
          <form onSubmit={handleCreate} className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Name</label>
              <input value={createForm.name} onChange={e => setCreateForm(p => ({ ...p, name: e.target.value }))} required className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="Acme Corp" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Slug (URL)</label>
              <input value={createForm.slug} onChange={e => setCreateForm(p => ({ ...p, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-_]/g, '') }))} required className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="acme-corp" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Plan</label>
              <select value={createForm.plan} onChange={e => setCreateForm(p => ({ ...p, plan: e.target.value }))} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm">
                <option value="free">Free</option>
                <option value="trial">Trial</option>
                <option value="pro">Pro</option>
                <option value="enterprise">Enterprise</option>
              </select>
            </div>
            <div className="col-span-3 flex gap-2">
              <button type="submit" className="px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700">Create</button>
              <button type="button" onClick={() => setShowCreate(false)} className="px-4 py-2 bg-gray-100 text-gray-700 text-sm rounded-lg hover:bg-gray-200">Cancel</button>
            </div>
          </form>
        </div>
      )}

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
            <div className="col-span-2 flex gap-2">
              <button
                onClick={handleEdit}
                disabled={!editForm.name.trim()}
                className="px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Save Changes
              </button>
              <button onClick={() => setShowEdit(null)} className="px-4 py-2 bg-gray-100 text-gray-700 text-sm rounded-lg hover:bg-gray-200">Cancel</button>
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
              <div className="text-lg font-bold text-white">${monthlyTotal.toLocaleString()}<span className="text-xs font-normal text-slate-400">/mo</span></div>
              <div className="text-[10px] text-slate-400">Base: ${cloudBase.toLocaleString()} + Add-ons: ${addonBase.toLocaleString()}</div>
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
                  const pricing = CLOUD_PRICING[key];
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
                        <div className="mt-3 flex gap-3">
                          {PLAN_TIERS.map(tier => (
                            <label
                              key={tier}
                              className={`flex-1 flex items-center justify-between px-3 py-2 border rounded-lg cursor-pointer transition ${cfg.plan === tier ? 'border-blue-400 bg-blue-50' : 'border-gray-200 hover:border-gray-300'}`}
                            >
                              <div className="flex items-center gap-2">
                                <input
                                  type="radio"
                                  name={`plan-${key}`}
                                  checked={cfg.plan === tier}
                                  onChange={() => setCloudPlan(key, tier)}
                                  className="w-3.5 h-3.5 text-blue-600"
                                />
                                <span className="text-xs font-semibold text-gray-700 capitalize">{tier}</span>
                              </div>
                              <span className={`text-xs font-bold ${cfg.plan === tier ? 'text-blue-700' : 'text-gray-500'}`}>${pricing[tier]}/mo</span>
                            </label>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Base Features (included with Pro+) */}
            <div className="mb-6">
              <h4 className="text-xs font-semibold text-gray-700 uppercase tracking-wider mb-3">Included with Pro</h4>
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

            {/* Paid Add-Ons */}
            <div className="mb-6">
              <h4 className="text-xs font-semibold text-gray-700 uppercase tracking-wider mb-3">Paid Add-Ons</h4>
              <div className="space-y-2">
                {Object.entries(ADDON_PRICING).map(([key, addon]) => {
                  const enabled = configForm.addons[key] || false;
                  return (
                    <div
                      key={key}
                      className={`flex items-center justify-between border-2 rounded-xl px-4 py-3 transition ${enabled ? 'border-green-300 bg-green-50/30' : 'border-gray-200'}`}
                    >
                      <div className="flex items-center gap-3">
                        <div className={`w-5 h-5 rounded flex items-center justify-center ${enabled ? 'bg-green-500 text-white' : 'bg-gray-200 text-gray-400'}`}>
                          {enabled ? (
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
                        <span className={`text-xs font-bold ${enabled ? 'text-green-700' : 'text-gray-400'}`}>+${addon.price}/mo</span>
                        <button
                          onClick={() => toggleAddon(key)}
                          className={`relative w-11 h-6 rounded-full transition-colors shrink-0 ${enabled ? 'bg-green-500' : 'bg-gray-300'}`}
                        >
                          <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${enabled ? 'translate-x-5' : ''}`} />
                        </button>
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

          {/* Dark Billing Summary Card */}
          <div className="bg-gradient-to-r from-slate-900 to-slate-800 px-6 py-5">
            {/* Line items */}
            <div className="space-y-1.5 mb-3">
              {Object.entries(configForm.cloud_providers).map(([key, pCfg]) => {
                if (!pCfg.enabled || !pCfg.plan) return null;
                const price = CLOUD_PRICING[key]?.[pCfg.plan] ?? 0;
                return (
                  <div key={key} className="flex items-center justify-between text-xs">
                    <span className="text-slate-300">{CLOUD_LABELS[key]?.label} ({pCfg.plan})</span>
                    <span className="text-white font-semibold">${price.toLocaleString()}/mo</span>
                  </div>
                );
              })}
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
            </div>

            <div className="border-t border-slate-700 pt-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold text-white">Total Monthly</span>
                <span className="text-xl font-extrabold text-white">${monthlyTotal.toLocaleString()}/mo</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-400">Annual (15% discount)</span>
                <div className="text-right">
                  <span className="text-sm font-bold text-cyan-400">${Math.round(annualTotal).toLocaleString()}/yr</span>
                  <span className="text-[10px] text-green-400 ml-2">Save ${Math.round(annualSavings).toLocaleString()}</span>
                </div>
              </div>
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
              <th className="px-4 py-2.5">Clouds</th>
              <th className="px-4 py-2.5">Users</th>
              <th className="px-4 py-2.5">Status</th>
              <th className="px-4 py-2.5">License</th>
              <th className="px-4 py-2.5">Provisioned</th>
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
                  <td className="px-4 py-2.5">
                    <div>
                      <span className={`text-[10px] font-semibold ${ls.color}`}>{ls.label}</span>
                      {t.license_expires_at && (
                        <div className="text-[9px] text-gray-400">{formatDate(t.license_expires_at)}</div>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    {isProvisioned(t) ? (
                      <span className="text-[10px] text-green-600 font-semibold">Yes</span>
                    ) : canWrite ? (
                      <button onClick={() => setShowProvision(t.id)} className="text-[10px] text-blue-600 hover:underline font-semibold">Provision</button>
                    ) : (
                      <span className="text-[10px] text-gray-400 font-semibold">No</span>
                    )}
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
                          onClick={() => { setShowEdit(t); setEditForm({ name: t.name }); }}
                          className="text-[10px] text-gray-600 hover:text-blue-600 hover:underline font-medium"
                          title="Edit organization"
                        >
                          Edit
                        </button>
                        {canWrite && (
                          <button onClick={() => handleViewAs(t)} className="text-[10px] text-blue-600 hover:underline font-medium" title={`Switch context to ${t.name}`}>
                            View As
                          </button>
                        )}
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
