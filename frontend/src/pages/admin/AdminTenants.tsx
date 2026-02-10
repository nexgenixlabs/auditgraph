import React, { useEffect, useState, useCallback } from 'react';
import { useAuth } from '../../contexts/AuthContext';

interface Tenant {
  id: number;
  name: string;
  slug: string;
  plan: string;
  enabled: boolean;
  user_count: number;
  created_at: string;
  settings?: Record<string, unknown>;
}

interface ProvisionForm {
  admin_username: string;
  admin_display_name: string;
  admin_password: string;
}

export default function AdminTenants() {
  const { switchTenant } = useAuth();
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [showProvision, setShowProvision] = useState<number | null>(null);
  const [createForm, setCreateForm] = useState({ name: '', slug: '', plan: 'pro' });
  const [provisionForm, setProvisionForm] = useState<ProvisionForm>({ admin_username: '', admin_display_name: '', admin_password: '' });
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const fetchTenants = useCallback(() => {
    fetch('/api/tenants')
      .then(r => r.json())
      .then(d => setTenants(d.tenants || []))
      .catch(() => {})
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
      await fetch(`/api/tenants/${t.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plan }),
      });
      fetchTenants();
    } catch { /* ignore */ }
  }

  function handleViewAs(t: Tenant) {
    switchTenant(t.id, t.name);
    window.location.href = '/';
  }

  const isProvisioned = (t: Tenant) => {
    const s = t.settings;
    return s && typeof s === 'object' && (s as Record<string, unknown>).provisioned === true;
  };

  if (loading) return <div className="flex items-center justify-center h-64 text-gray-400">Loading tenants...</div>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900">Tenant Management</h2>
          <p className="text-sm text-gray-500 mt-0.5">{tenants.length} organizations</p>
        </div>
        <button onClick={() => setShowCreate(true)} className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 transition">
          Create Tenant
        </button>
      </div>

      {/* Status messages */}
      {error && <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">{error}<button onClick={() => setError(null)} className="ml-2 text-red-500">×</button></div>}
      {success && <div className="bg-green-50 border border-green-200 rounded-lg p-3 text-sm text-green-700">{success}<button onClick={() => setSuccess(null)} className="ml-2 text-green-500">×</button></div>}

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

      {/* Tenant table */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <table className="min-w-full text-left text-xs">
          <thead className="bg-gray-50 border-b border-gray-200 text-gray-600 uppercase tracking-wider font-medium">
            <tr>
              <th className="px-4 py-2.5">Name</th>
              <th className="px-4 py-2.5">Slug</th>
              <th className="px-4 py-2.5">Plan</th>
              <th className="px-4 py-2.5">Users</th>
              <th className="px-4 py-2.5">Status</th>
              <th className="px-4 py-2.5">Provisioned</th>
              <th className="px-4 py-2.5">Created</th>
              <th className="px-4 py-2.5">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {tenants.map(t => (
              <tr key={t.id} className="hover:bg-gray-50/60">
                <td className="px-4 py-2.5 font-medium text-gray-900">{t.name}</td>
                <td className="px-4 py-2.5 text-gray-600 font-mono">{t.slug}</td>
                <td className="px-4 py-2.5">
                  <select value={t.plan} onChange={e => changePlan(t, e.target.value)} className="text-xs border border-gray-200 rounded px-1.5 py-0.5">
                    <option value="free">Free</option>
                    <option value="pro">Pro</option>
                    <option value="enterprise">Enterprise</option>
                  </select>
                </td>
                <td className="px-4 py-2.5 text-gray-700">{t.user_count}</td>
                <td className="px-4 py-2.5">
                  <button onClick={() => toggleEnabled(t)} className={`px-2 py-0.5 rounded text-[10px] font-semibold transition ${t.enabled ? 'bg-green-100 text-green-700 hover:bg-green-200' : 'bg-red-100 text-red-700 hover:bg-red-200'}`}>
                    {t.enabled ? 'Active' : 'Disabled'}
                  </button>
                </td>
                <td className="px-4 py-2.5">
                  {isProvisioned(t) ? (
                    <span className="text-[10px] text-green-600 font-semibold">Yes</span>
                  ) : (
                    <button onClick={() => setShowProvision(t.id)} className="text-[10px] text-blue-600 hover:underline font-semibold">Provision</button>
                  )}
                </td>
                <td className="px-4 py-2.5 text-gray-500">{t.created_at ? new Date(t.created_at).toLocaleDateString() : '—'}</td>
                <td className="px-4 py-2.5">
                  <button onClick={() => handleViewAs(t)} className="text-[10px] text-blue-600 hover:underline font-medium" title={`Switch context to ${t.name}`}>
                    View As
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
