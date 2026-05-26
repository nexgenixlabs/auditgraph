import React, { useEffect, useState, useCallback } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import {
  ADDON_PRICING, BASE_FEATURES,
  CLOUD_LABELS, ACCOUNT_TIER_LABELS, PLATFORM_FEE_CENTS,
  SUBSCRIPTION_TERMS, getTermDiscount, getTermLabel,
  SUB_RATES_CENTS,
  formatCents,
  type CloudConfig,
} from '../../constants/pricing';
import { api, ApiError } from '../../services/apiClient';
import { TIME_MS } from '../../constants/metrics';

interface Tenant {
  id: number;
  name: string;
  slug: string;
  plan: string;
  enabled: boolean;
  billing_status?: string;
  user_count: number;
  created_at: string;
  license_activated_at: string | null;
  license_expires_at: string | null;
  subscription_term: number;
  settings?: Record<string, unknown>;
  tax_label?: string;
  tax_rate?: number;
  tax_id?: string;
  tax_exempt?: boolean;
  tax_notes?: string;
  payment_terms?: number;
  billing_company?: string;
  billing_address_line1?: string;
  billing_address_line2?: string;
  billing_city?: string;
  billing_state?: string;
  billing_postal_code?: string;
  billing_country?: string;
  billing_email?: string;
}

interface TaxBillingForm {
  tax_label: string;
  tax_rate: number;
  tax_id: string;
  tax_exempt: boolean;
  tax_notes: string;
  payment_terms: number;
  billing_company: string;
  billing_address_line1: string;
  billing_address_line2: string;
  billing_city: string;
  billing_state: string;
  billing_postal_code: string;
  billing_country: string;
  billing_email: string;
}

const DEFAULT_TAX_BILLING: TaxBillingForm = {
  tax_label: 'Tax',
  tax_rate: 0,
  tax_id: '',
  tax_exempt: false,
  tax_notes: '',
  payment_terms: 30,
  billing_company: '',
  billing_address_line1: '',
  billing_address_line2: '',
  billing_city: '',
  billing_state: '',
  billing_postal_code: '',
  billing_country: '',
  billing_email: '',
};

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
    const days = Math.ceil((new Date(t.license_expires_at).getTime() - Date.now()) / TIME_MS.DAY);
    if (days < 0) return { label: 'Expired', color: 'text-red-600' };
    if (days < 30) return { label: `${days}d left`, color: 'text-yellow-600' };
  }
  return { label: 'Active', color: 'text-green-600' };
}

export default function AdminTenants() {
  const { switchOrganization, user } = useAuth();
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
  const [planConfirm, setPlanConfirm] = useState<{ tenant: Tenant; newPlan: string } | null>(null);
  const [taxBillingForm, setTaxBillingForm] = useState<TaxBillingForm>(DEFAULT_TAX_BILLING);
  const [tenantBilling, setTenantBilling] = useState<{
    billing: { platform_fee_cents: number; subscription_total_cents: number; net_monthly_cents: number; active_count: number; subscriptions_by_cloud: Record<string, { count: number; revenue_cents: number }> };
    subscriptions: Array<{ cloud: string; rate_cents: number; monitored: boolean }>;
  } | null>(null);
  const [opsDropdown, setOpsDropdown] = useState<number | null>(null);
  const [opsModal, setOpsModal] = useState<{ tenant: Tenant; action: string; label: string; description: string; requireConfirm?: boolean } | null>(null);
  const [opsReason, setOpsReason] = useState('');
  const [opsConfirm, setOpsConfirm] = useState('');
  const [opsLoading, setOpsLoading] = useState(false);
  const [configRootUsername, setConfigRootUsername] = useState<string | null>(null);
  const [resetRootModal, setResetRootModal] = useState<{ orgId: number; orgName: string; currentUsername: string } | null>(null);
  const [resetRootUsername, setResetRootUsername] = useState('');
  const [resetRootLoading, setResetRootLoading] = useState(false);
  const [showRootTempPassword, setShowRootTempPassword] = useState<string | null>(null);

  const fetchTenants = useCallback(() => {
    api.get('/clients')
      .then(d => setTenants(d.tenants || []))
      .catch((err: any) => setError(err instanceof ApiError ? err.message : 'Failed to load clients'))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { fetchTenants(); }, [fetchTenants]);

  async function handleProvision(orgId: number) {
    setError(null);
    try {
      const data = await api.post(`/clients/${orgId}/provision`, provisionForm);
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
      await api.put(`/clients/${t.id}`, { enabled: !t.enabled });
      fetchTenants();
    } catch { /* ignore */ }
  }

  function changePlan(t: Tenant, plan: string) {
    if (plan === t.plan) return;
    setPlanConfirm({ tenant: t, newPlan: plan });
  }

  async function confirmPlanChange() {
    if (!planConfirm) return;
    try {
      await api.put(`/admin/clients/${planConfirm.tenant.id}/plan`, { plan: planConfirm.newPlan });
      setPlanConfirm(null);
      fetchTenants();
    } catch { /* ignore */ }
  }

  async function handleDelete() {
    if (!showDeleteConfirm) return;
    setError(null);
    try {
      await api.del(`/clients/${showDeleteConfirm.id}`);
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
      await api.put(`/clients/${showEdit.id}`, { name: editForm.name });
      setSuccess(`Tenant updated successfully`);
      setShowEdit(null);
      fetchTenants();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update tenant');
    }
  }

  async function executeOps() {
    if (!opsModal) return;
    setOpsLoading(true);
    setError(null);
    try {
      const body: Record<string, string> = { reason: opsReason };
      if (opsModal.requireConfirm) body.confirm = opsConfirm;
      await api.post(`/admin/tenants/${opsModal.tenant.id}/${opsModal.action}`, body);
      setSuccess(`${opsModal.label} completed for ${opsModal.tenant.name}`);
      setOpsModal(null);
      setOpsReason('');
      setOpsConfirm('');
      fetchTenants();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : `Failed: ${opsModal.label}`);
    } finally {
      setOpsLoading(false);
    }
  }

  async function openResetRootModal(t: Tenant) {
    setOpsDropdown(null);
    setError(null);
    try {
      const data = await api.get(`/users?organization_id=${t.id}`);
      const users = data.users || [];
      const root = users.find((u: any) => u.role === 'admin');
      setResetRootModal({ orgId: t.id, orgName: t.name, currentUsername: root?.username || '(none)' });
      setResetRootUsername('');
    } catch {
      setError('Failed to fetch root user for this tenant');
    }
  }

  async function executeResetRoot() {
    if (!resetRootModal) return;
    setResetRootLoading(true);
    setError(null);
    try {
      const body: Record<string, string> = {};
      if (resetRootUsername.trim()) body.new_username = resetRootUsername.trim();
      const data = await api.post(`/admin/clients/${resetRootModal.orgId}/reset-root-user`, body);
      setResetRootModal(null);
      setShowRootTempPassword(data.temp_password);
      if (data.username) setConfigRootUsername(data.username);
      setSuccess(data.message || 'Root user credentials reset');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to reset root user');
    } finally {
      setResetRootLoading(false);
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

  async function handleLogoUpload(orgId: number) {
    if (!logoFile) return;
    setUploadingLogo(true);
    try {
      const reader = new FileReader();
      const dataUrl = await new Promise<string>((resolve) => {
        reader.onload = () => resolve(reader.result as string);
        reader.readAsDataURL(logoFile);
      });
      await api.post(`/clients/${orgId}/logo`, { logo: dataUrl });
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

  async function handleLogoDelete(orgId: number) {
    try {
      await api.del(`/clients/${orgId}/logo`);
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
    setTaxBillingForm({
      tax_label: t.tax_label || 'Tax',
      tax_rate: t.tax_rate || 0,
      tax_id: t.tax_id || '',
      tax_exempt: t.tax_exempt || false,
      tax_notes: t.tax_notes || '',
      payment_terms: t.payment_terms || 30,
      billing_company: t.billing_company || '',
      billing_address_line1: t.billing_address_line1 || '',
      billing_address_line2: t.billing_address_line2 || '',
      billing_city: t.billing_city || '',
      billing_state: t.billing_state || '',
      billing_postal_code: t.billing_postal_code || '',
      billing_country: t.billing_country || '',
      billing_email: t.billing_email || '',
    });
    setShowConfigure(t);
    setTenantBilling(null);
    setConfigRootUsername(null);
    // Fetch billing data for this tenant
    api.get(`/admin/clients/${t.id}/billing`)
      .then(data => { if (data) setTenantBilling(data); })
      .catch(() => {});
    // Fetch root admin username
    api.get(`/users?organization_id=${t.id}`)
      .then(data => {
        const root = (data.users || []).find((u: any) => u.role === 'admin');
        setConfigRootUsername(root?.username || null);
      })
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
      const payload: Record<string, unknown> = {
        settings: mergedSettings,
        subscription_term: configTerm,
        ...taxBillingForm,
      };
      if (configTerm > 0 && !showConfigure.license_activated_at) {
        payload.license_activated_at = new Date().toISOString();
      }
      await api.put(`/clients/${showConfigure.id}`, payload);
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
  const termDiscount = getTermDiscount(configTerm);

  if (loading) return <div className="flex items-center justify-center h-64 text-gray-400">Loading clients...</div>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900">Client Management</h2>
          <p className="text-sm text-gray-500 mt-0.5">{tenants.length} organizations</p>
        </div>
        {canWrite && (
          <p className="text-xs text-gray-500">
            To create a new client, use the{' '}
            <a href="/admin/onboarding" className="text-blue-600 hover:text-blue-700 hover:opacity-80">Onboarding</a> tab.
          </p>
        )}
      </div>

      {/* Status messages */}
      {error && <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">{error}<button onClick={() => setError(null)} className="ml-2 text-red-500">&times;</button></div>}
      {success && <div className="bg-green-50 border border-green-200 rounded-lg p-3 text-sm text-green-700">{success}<button onClick={() => setSuccess(null)} className="ml-2 text-green-500">&times;</button></div>}

      {/* Provision modal */}
      {showProvision !== null && (
        <div className="bg-white border border-blue-200 rounded-lg p-6 shadow-sm">
          <h3 className="text-sm font-semibold text-gray-800 mb-3">Provision Client — Create Admin User</h3>
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
            This will permanently delete <span className="font-semibold">{showDeleteConfirm.name}</span> and all associated data including users, snapshots, and settings. This action cannot be undone.
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

      {/* Operations confirmation modal */}
      {opsModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
          <div className="bg-white rounded-xl shadow-xl border border-gray-200 w-full max-w-md p-6">
            <h3 className="text-sm font-bold text-gray-900 mb-2">{opsModal.label}</h3>
            <p className="text-xs text-gray-600 mb-4">{opsModal.description}</p>
            <p className="text-xs text-gray-500 mb-3">Target: <span className="font-semibold">{opsModal.tenant.name}</span></p>
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Reason</label>
                <input
                  value={opsReason}
                  onChange={e => setOpsReason(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
                  placeholder="Reason for this action"
                />
              </div>
              {opsModal.requireConfirm && (
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">
                    Type <span className="font-mono font-bold">{opsModal.tenant.name}</span> to confirm
                  </label>
                  <input
                    value={opsConfirm}
                    onChange={e => setOpsConfirm(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
                    placeholder="Tenant name"
                  />
                </div>
              )}
            </div>
            <div className="flex gap-2 mt-4">
              <button
                onClick={executeOps}
                disabled={opsLoading || !opsReason.trim() || (opsModal.requireConfirm && opsConfirm.trim() !== opsModal.tenant.name.trim())}
                className={`px-4 py-2 text-white text-sm rounded-lg disabled:opacity-40 disabled:cursor-not-allowed ${
                  opsModal.action === 'reset-discovery' || opsModal.action === 'disable'
                    ? 'bg-red-600 hover:bg-red-700' : 'bg-blue-600 hover:bg-blue-700'
                }`}
              >
                {opsLoading ? 'Processing...' : 'Confirm'}
              </button>
              <button
                onClick={() => { setOpsModal(null); setOpsReason(''); setOpsConfirm(''); }}
                className="px-4 py-2 bg-gray-100 text-gray-700 text-sm rounded-lg hover:bg-gray-200"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reset Root User modal */}
      {resetRootModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
          <div className="bg-white rounded-xl shadow-xl border border-gray-200 w-full max-w-md p-6">
            <h3 className="text-sm font-bold text-gray-900 mb-2">Reset Root User Credentials</h3>
            <p className="text-xs text-gray-600 mb-4">Reset the root admin credentials for <span className="font-semibold">{resetRootModal.orgName}</span>. A temporary password will be generated.</p>
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Current username</label>
                <div className="px-3 py-2 bg-gray-50 border border-gray-200 rounded-lg text-sm text-gray-700 font-mono">{resetRootModal.currentUsername}</div>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">New username (optional)</label>
                <input
                  value={resetRootUsername}
                  onChange={e => setResetRootUsername(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
                  placeholder="Leave blank to keep current username"
                />
              </div>
            </div>
            <div className="flex gap-2 mt-4">
              <button
                onClick={executeResetRoot}
                disabled={resetRootLoading || (resetRootUsername.trim().length > 0 && resetRootUsername.trim().length < 3)}
                className="px-4 py-2 text-white text-sm rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {resetRootLoading ? 'Resetting...' : 'Reset Credentials'}
              </button>
              <button
                onClick={() => { setResetRootModal(null); setResetRootUsername(''); }}
                className="px-4 py-2 bg-gray-100 text-gray-700 text-sm rounded-lg hover:bg-gray-200"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Root user temp password display */}
      {showRootTempPassword && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowRootTempPassword(null)}>
          <div className="bg-white rounded-xl shadow-xl w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
            <h2 className="text-lg font-bold text-gray-900 mb-2">Temporary Password</h2>
            <p className="text-sm text-gray-500 mb-4">
              This password is shown only once. The user will be required to change it on next login.
            </p>
            <div className="bg-gray-50 border border-gray-200 rounded-lg p-3 font-mono text-sm break-all select-all">
              {showRootTempPassword}
            </div>
            <div className="flex gap-2 mt-4">
              <button
                onClick={() => {
                  navigator.clipboard.writeText(showRootTempPassword);
                  setSuccess('Password copied to clipboard');
                }}
                className="flex-1 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 transition"
              >
                Copy to Clipboard
              </button>
              <button
                onClick={() => setShowRootTempPassword(null)}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Plan change confirmation modal */}
      {planConfirm && (() => {
        const oldPlan = planConfirm.tenant.plan;
        const newPlan = planConfirm.newPlan;
        const oldFee = PLATFORM_FEE_CENTS[oldPlan] ?? 0;
        const newFee = PLATFORM_FEE_CENTS[newPlan] ?? 0;
        const feeDelta = newFee - oldFee;
        const isDowngrade = (oldPlan === 'pro') && (['free', 'trial'].includes(newPlan));
        const oldLabel = ACCOUNT_TIER_LABELS[oldPlan]?.label || oldPlan;
        const newLabel = ACCOUNT_TIER_LABELS[newPlan]?.label || newPlan;
        return (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
            <div className="bg-white rounded-xl shadow-xl border border-gray-200 w-full max-w-md p-6">
              <h3 className="text-sm font-bold text-gray-900 mb-4">Confirm Plan Change</h3>
              <div className="flex items-center justify-center gap-3 mb-4">
                <span className={`px-3 py-1 rounded-lg text-xs font-bold ${
                  ACCOUNT_TIER_LABELS[oldPlan]?.bg || 'bg-gray-100'
                } ${ACCOUNT_TIER_LABELS[oldPlan]?.color || 'text-gray-700'}`}>{oldLabel}</span>
                <svg className="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                </svg>
                <span className={`px-3 py-1 rounded-lg text-xs font-bold ${
                  ACCOUNT_TIER_LABELS[newPlan]?.bg || 'bg-gray-100'
                } ${ACCOUNT_TIER_LABELS[newPlan]?.color || 'text-gray-700'}`}>{newLabel}</span>
              </div>
              <div className="bg-gray-50 rounded-lg p-3 mb-4 space-y-1.5 text-xs">
                <div className="flex justify-between">
                  <span className="text-gray-500">Current platform fee</span>
                  <span className="font-semibold text-gray-700">{formatCents(oldFee)}/mo</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">New platform fee</span>
                  <span className="font-semibold text-gray-900">{formatCents(newFee)}/mo</span>
                </div>
                <div className="border-t border-gray-200 pt-1.5 flex justify-between">
                  <span className="text-gray-500">Delta</span>
                  <span className={`font-bold ${feeDelta > 0 ? 'text-blue-600' : feeDelta < 0 ? 'text-green-600' : 'text-gray-500'}`}>
                    {feeDelta > 0 ? '+' : ''}{formatCents(feeDelta)}/mo
                  </span>
                </div>
              </div>
              {isDowngrade && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-3 mb-4 text-xs text-red-700">
                  Downgrading from <strong>{oldLabel}</strong> to <strong>{newLabel}</strong> will reduce platform features. The tenant will lose access to paid capabilities immediately.
                </div>
              )}
              <div className="flex gap-2 justify-end">
                <button
                  onClick={() => setPlanConfirm(null)}
                  className="px-4 py-2 bg-gray-100 text-gray-700 text-sm rounded-lg hover:bg-gray-200"
                >
                  Cancel
                </button>
                <button
                  onClick={confirmPlanChange}
                  className={`px-4 py-2 text-white text-sm font-semibold rounded-lg ${
                    isDowngrade ? 'bg-red-600 hover:bg-red-700' : 'bg-blue-600 hover:bg-blue-700'
                  }`}
                >
                  {isDowngrade ? 'Confirm Downgrade' : 'Confirm Change'}
                </button>
              </div>
            </div>
          </div>
        );
      })()}

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
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-300">
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
            {/* Root Administrator */}
            <div className="mb-6">
              <h4 className="text-xs font-semibold text-gray-700 uppercase tracking-wider mb-3">Root Administrator</h4>
              <div className="flex items-center justify-between border border-gray-200 rounded-lg px-4 py-3">
                <div className="min-w-0">
                  <div className="text-[10px] text-gray-500 mb-0.5">Username</div>
                  <div className="text-sm font-mono text-gray-800 truncate">
                    {configRootUsername || <span className="text-gray-400 italic">No admin user provisioned</span>}
                  </div>
                </div>
                {configRootUsername && canWrite && (
                  <div className="flex items-center gap-2 shrink-0 ml-4">
                    <button
                      onClick={async () => {
                        setError(null);
                        try {
                          const data = await api.post(`/admin/clients/${showConfigure!.id}/reset-root-user`, {});
                          setShowRootTempPassword(data.temp_password);
                          setSuccess(data.message || 'Password reset');
                        } catch (err: unknown) {
                          setError(err instanceof Error ? err.message : 'Failed to reset password');
                        }
                      }}
                      className="px-3 py-1.5 text-[11px] font-medium text-red-700 bg-red-50 border border-red-200 rounded-lg hover:bg-red-100 transition"
                    >
                      Reset Password
                    </button>
                    <button
                      onClick={() => {
                        setResetRootModal({ orgId: showConfigure!.id, orgName: showConfigure!.name, currentUsername: configRootUsername });
                        setResetRootUsername('');
                      }}
                      className="px-3 py-1.5 text-[11px] font-medium text-blue-700 bg-blue-50 border border-blue-200 rounded-lg hover:bg-blue-100 transition"
                    >
                      Change Username
                    </button>
                  </div>
                )}
              </div>
            </div>

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
                            <span className="text-xs font-semibold text-blue-700">{subCount} subscription{subCount !== 1 ? 's' : ''} monitored</span>
                            <span className="text-xs font-bold text-blue-700">
                              {cloudBillingData ? formatCents(cloudBillingData.revenue_cents) : '$0'}/mo
                              <span className="text-[10px] font-normal text-gray-400"> @ {formatCents(SUB_RATES_CENTS[key] ?? 6900)}/sub</span>
                            </span>
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
                      className={`flex items-center justify-between border-2 rounded-xl px-4 py-3 transition ${
                        enabled ? 'border-green-300 bg-green-50/30' : 'border-gray-200'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <div className={`w-5 h-5 rounded flex items-center justify-center ${
                          enabled ? 'bg-green-500 text-white' : 'bg-gray-200 text-gray-400'
                        }`}>
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

          {/* Tax & Billing Address */}
          <div className="px-6 py-4 border-t border-gray-200">
            <h4 className="text-xs font-bold text-gray-800 uppercase tracking-wider mb-3">Tax & Billing</h4>
            <div className="grid grid-cols-3 gap-3 mb-3">
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-0.5">Tax Label</label>
                <input
                  type="text"
                  value={taxBillingForm.tax_label}
                  onChange={e => setTaxBillingForm(p => ({ ...p, tax_label: e.target.value }))}
                  placeholder="Tax / GST / VAT"
                  className="w-full text-xs border border-gray-200 rounded px-2 py-1.5"
                />
              </div>
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-0.5">Tax Rate (%)</label>
                <input
                  type="number"
                  value={taxBillingForm.tax_rate}
                  onChange={e => setTaxBillingForm(p => ({ ...p, tax_rate: parseFloat(e.target.value) || 0 }))}
                  min={0} max={100} step={0.01}
                  className="w-full text-xs border border-gray-200 rounded px-2 py-1.5"
                />
              </div>
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-0.5">Tax ID</label>
                <input
                  type="text"
                  value={taxBillingForm.tax_id}
                  onChange={e => setTaxBillingForm(p => ({ ...p, tax_id: e.target.value }))}
                  placeholder="ABN / EIN / GST#"
                  className="w-full text-xs border border-gray-200 rounded px-2 py-1.5"
                />
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3 mb-3">
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={taxBillingForm.tax_exempt}
                  onChange={e => setTaxBillingForm(p => ({ ...p, tax_exempt: e.target.checked }))}
                  className="rounded border-gray-300"
                />
                <label className="text-xs text-gray-700">Tax Exempt</label>
              </div>
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-0.5">Payment Terms</label>
                <select
                  value={taxBillingForm.payment_terms}
                  onChange={e => setTaxBillingForm(p => ({ ...p, payment_terms: parseInt(e.target.value) }))}
                  className="w-full text-xs border border-gray-200 rounded px-2 py-1.5"
                >
                  <option value={15}>Net 15</option>
                  <option value={30}>Net 30</option>
                  <option value={45}>Net 45</option>
                  <option value={60}>Net 60</option>
                </select>
              </div>
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-0.5">Billing Email</label>
                <input
                  type="email"
                  value={taxBillingForm.billing_email}
                  onChange={e => setTaxBillingForm(p => ({ ...p, billing_email: e.target.value }))}
                  placeholder="billing@company.com"
                  className="w-full text-xs border border-gray-200 rounded px-2 py-1.5"
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-0.5">Billing Company</label>
                <input
                  type="text"
                  value={taxBillingForm.billing_company}
                  onChange={e => setTaxBillingForm(p => ({ ...p, billing_company: e.target.value }))}
                  className="w-full text-xs border border-gray-200 rounded px-2 py-1.5"
                />
              </div>
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-0.5">Country</label>
                <input
                  type="text"
                  value={taxBillingForm.billing_country}
                  onChange={e => setTaxBillingForm(p => ({ ...p, billing_country: e.target.value }))}
                  className="w-full text-xs border border-gray-200 rounded px-2 py-1.5"
                />
              </div>
            </div>
            <div className="grid grid-cols-1 gap-3 mt-3">
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-0.5">Address Line 1</label>
                <input
                  type="text"
                  value={taxBillingForm.billing_address_line1}
                  onChange={e => setTaxBillingForm(p => ({ ...p, billing_address_line1: e.target.value }))}
                  className="w-full text-xs border border-gray-200 rounded px-2 py-1.5"
                />
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3 mt-3">
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-0.5">City</label>
                <input
                  type="text"
                  value={taxBillingForm.billing_city}
                  onChange={e => setTaxBillingForm(p => ({ ...p, billing_city: e.target.value }))}
                  className="w-full text-xs border border-gray-200 rounded px-2 py-1.5"
                />
              </div>
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-0.5">State</label>
                <input
                  type="text"
                  value={taxBillingForm.billing_state}
                  onChange={e => setTaxBillingForm(p => ({ ...p, billing_state: e.target.value }))}
                  className="w-full text-xs border border-gray-200 rounded px-2 py-1.5"
                />
              </div>
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-0.5">Postal Code</label>
                <input
                  type="text"
                  value={taxBillingForm.billing_postal_code}
                  onChange={e => setTaxBillingForm(p => ({ ...p, billing_postal_code: e.target.value }))}
                  className="w-full text-xs border border-gray-200 rounded px-2 py-1.5"
                />
              </div>
            </div>
          </div>

          {/* Dark Billing Summary Card */}
          <div className="bg-gray-900 px-6 py-5">
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
              className="w-full mt-4 py-2.5 bg-blue-600 text-white text-sm font-bold rounded-lg hover:bg-blue-700 disabled:opacity-50 transition"
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
                    <div className="flex items-center gap-1">
                      {canWrite ? (
                        <button onClick={() => toggleEnabled(t)} className={`px-2 py-0.5 rounded text-[10px] font-semibold transition ${t.enabled ? 'bg-green-100 text-green-700 hover:bg-green-200' : 'bg-red-100 text-red-700 hover:bg-red-200'}`}>
                          {t.enabled ? 'Active' : 'Disabled'}
                        </button>
                      ) : (
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${t.enabled ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                          {t.enabled ? 'Active' : 'Disabled'}
                        </span>
                      )}
                      {t.billing_status === 'suspended' && (
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-100 text-amber-700">Suspended</span>
                      )}
                    </div>
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
                        {/* Operations dropdown */}
                        <div className="relative">
                          <button
                            onClick={() => setOpsDropdown(opsDropdown === t.id ? null : t.id)}
                            className="text-[10px] text-gray-500 hover:text-gray-700 font-medium px-1.5 py-0.5 rounded hover:bg-gray-100"
                          >
                            Ops &#9662;
                          </button>
                          {opsDropdown === t.id && (
                            <div className="absolute right-0 top-full mt-1 w-48 bg-white border border-gray-200 rounded-lg shadow-lg z-50 py-1">
                              <button onClick={() => { setOpsDropdown(null); setOpsModal({ tenant: t, action: 'snapshot', label: 'Trigger Snapshot', description: 'Start a new discovery run for this tenant.' }); }} className="w-full text-left px-3 py-1.5 text-xs text-gray-700 hover:bg-gray-50">Trigger Snapshot</button>
                              <button onClick={() => { setOpsDropdown(null); setOpsModal({ tenant: t, action: 'rebuild-graph', label: 'Rebuild Graph', description: 'Clear and rebuild graph visualization cache.' }); }} className="w-full text-left px-3 py-1.5 text-xs text-gray-700 hover:bg-gray-50">Rebuild Graph</button>
                              <button onClick={() => openResetRootModal(t)} className="w-full text-left px-3 py-1.5 text-xs text-gray-700 hover:bg-gray-50">Reset Root User</button>
                              <button onClick={() => { setOpsDropdown(null); setOpsModal({ tenant: t, action: 'disable', label: 'Disable Tenant', description: 'Disable this tenant. Users will lose access.' }); }} className="w-full text-left px-3 py-1.5 text-xs text-orange-700 hover:bg-orange-50">Disable Tenant</button>
                              <button onClick={() => { setOpsDropdown(null); setOpsModal({ tenant: t, action: 'suspend', label: 'Suspend Billing', description: 'Suspend billing. Data stays, billing pauses.' }); }} className="w-full text-left px-3 py-1.5 text-xs text-orange-700 hover:bg-orange-50">Suspend Billing</button>
                              {isSuperadmin && (
                                <button onClick={() => { setOpsDropdown(null); setOpsModal({ tenant: t, action: 'reset-discovery', label: 'Reset Discovery', description: 'Delete ALL discovery data for this tenant. This cannot be undone.', requireConfirm: true }); }} className="w-full text-left px-3 py-1.5 text-xs text-red-700 hover:bg-red-50 border-t border-gray-100">Reset Discovery Data</button>
                              )}
                            </div>
                          )}
                        </div>
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
