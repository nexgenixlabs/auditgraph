import React, { useState } from 'react';

const STEPS = ['Organization', 'Admin User', 'Review', 'Complete'];

interface TenantForm {
  name: string;
  slug: string;
  plan: string;
}

interface AdminForm {
  admin_username: string;
  admin_display_name: string;
  admin_password: string;
}

export default function AdminOnboarding() {
  const [step, setStep] = useState(0);
  const [tenantForm, setTenantForm] = useState<TenantForm>({ name: '', slug: '', plan: 'pro' });
  const [adminForm, setAdminForm] = useState<AdminForm>({ admin_username: '', admin_display_name: '', admin_password: '' });
  const [createdTenantId, setCreatedTenantId] = useState<number | null>(null);
  const [createdTenantSlug, setCreatedTenantSlug] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [processing, setProcessing] = useState(false);

  async function handleCreateTenant() {
    setError(null);
    setProcessing(true);
    try {
      const res = await fetch('/api/tenants', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(tenantForm),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to create tenant');
      setCreatedTenantId(data.tenant.id);
      setCreatedTenantSlug(data.tenant.slug);
      setStep(1);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed');
    } finally {
      setProcessing(false);
    }
  }

  async function handleProvision() {
    if (!createdTenantId) return;
    setError(null);
    setProcessing(true);
    try {
      const res = await fetch(`/api/tenants/${createdTenantId}/provision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(adminForm),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to provision');
      setStep(3); // Complete
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed');
    } finally {
      setProcessing(false);
    }
  }

  const portalUrl = `${createdTenantSlug}.auditgraph.ai`;

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold text-gray-900">Client Onboarding</h2>
        <p className="text-sm text-gray-500 mt-0.5">Set up a new organization in 4 steps</p>
      </div>

      {/* Step indicator */}
      <div className="flex items-center gap-2">
        {STEPS.map((s, i) => (
          <React.Fragment key={s}>
            <div className={`flex items-center gap-1.5 ${i <= step ? 'text-blue-600' : 'text-gray-400'}`}>
              <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold border-2 ${
                i < step ? 'bg-blue-600 border-blue-600 text-white' :
                i === step ? 'border-blue-600 text-blue-600' :
                'border-gray-300 text-gray-400'
              }`}>
                {i < step ? '✓' : i + 1}
              </div>
              <span className="text-xs font-medium">{s}</span>
            </div>
            {i < STEPS.length - 1 && <div className={`flex-1 h-0.5 ${i < step ? 'bg-blue-600' : 'bg-gray-200'}`} />}
          </React.Fragment>
        ))}
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">
          {error}
          <button onClick={() => setError(null)} className="ml-2 text-red-500">×</button>
        </div>
      )}

      {/* Step 0: Organization */}
      {step === 0 && (
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <h3 className="text-sm font-semibold text-gray-800 mb-4">Organization Details</h3>
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Organization Name</label>
              <input value={tenantForm.name} onChange={e => setTenantForm(p => ({ ...p, name: e.target.value }))} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="Acme Corporation" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">URL Slug</label>
              <div className="flex items-center gap-1">
                <input value={tenantForm.slug} onChange={e => setTenantForm(p => ({ ...p, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-_]/g, '') }))} className="w-48 px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono" placeholder="acme" />
                <span className="text-sm text-gray-500">.auditgraph.ai</span>
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Plan</label>
              <div className="flex gap-3">
                {['free', 'pro', 'enterprise'].map(p => (
                  <label key={p} className={`flex items-center gap-2 px-4 py-2.5 border rounded-lg cursor-pointer transition ${
                    tenantForm.plan === p ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:border-gray-300'
                  }`}>
                    <input type="radio" name="plan" value={p} checked={tenantForm.plan === p} onChange={() => setTenantForm(prev => ({ ...prev, plan: p }))} className="sr-only" />
                    <span className={`text-sm font-medium capitalize ${tenantForm.plan === p ? 'text-blue-700' : 'text-gray-700'}`}>{p}</span>
                  </label>
                ))}
              </div>
            </div>
            <button onClick={handleCreateTenant} disabled={!tenantForm.name || !tenantForm.slug || processing} className="px-6 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed transition">
              {processing ? 'Creating...' : 'Create Organization'}
            </button>
          </div>
        </div>
      )}

      {/* Step 1: Admin User */}
      {step === 1 && (
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <h3 className="text-sm font-semibold text-gray-800 mb-4">Create Admin User for {tenantForm.name}</h3>
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Username</label>
              <input value={adminForm.admin_username} onChange={e => setAdminForm(p => ({ ...p, admin_username: e.target.value }))} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="admin" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Display Name</label>
              <input value={adminForm.admin_display_name} onChange={e => setAdminForm(p => ({ ...p, admin_display_name: e.target.value }))} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="John Admin" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Password (min 8 characters)</label>
              <input type="password" value={adminForm.admin_password} onChange={e => setAdminForm(p => ({ ...p, admin_password: e.target.value }))} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="Secure password" />
            </div>
            <div className="flex gap-2">
              <button onClick={() => setStep(2)} disabled={!adminForm.admin_username || !adminForm.admin_display_name || adminForm.admin_password.length < 8} className="px-6 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed transition">
                Review
              </button>
              <button onClick={() => setStep(0)} className="px-4 py-2 bg-gray-100 text-gray-700 text-sm rounded-lg hover:bg-gray-200">Back</button>
            </div>
          </div>
        </div>
      )}

      {/* Step 2: Review */}
      {step === 2 && (
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <h3 className="text-sm font-semibold text-gray-800 mb-4">Review & Confirm</h3>
          <div className="space-y-3 mb-6">
            <div className="flex justify-between py-2 border-b border-gray-100">
              <span className="text-sm text-gray-500">Organization</span>
              <span className="text-sm font-medium text-gray-800">{tenantForm.name}</span>
            </div>
            <div className="flex justify-between py-2 border-b border-gray-100">
              <span className="text-sm text-gray-500">URL</span>
              <span className="text-sm font-mono text-blue-600">{portalUrl}</span>
            </div>
            <div className="flex justify-between py-2 border-b border-gray-100">
              <span className="text-sm text-gray-500">Plan</span>
              <span className="text-sm font-medium text-gray-800 capitalize">{tenantForm.plan}</span>
            </div>
            <div className="flex justify-between py-2 border-b border-gray-100">
              <span className="text-sm text-gray-500">Admin Username</span>
              <span className="text-sm font-medium text-gray-800">{adminForm.admin_username}</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-sm text-gray-500">Admin Name</span>
              <span className="text-sm font-medium text-gray-800">{adminForm.admin_display_name}</span>
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={handleProvision} disabled={processing} className="px-6 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-40 transition">
              {processing ? 'Provisioning...' : 'Confirm & Provision'}
            </button>
            <button onClick={() => setStep(1)} className="px-4 py-2 bg-gray-100 text-gray-700 text-sm rounded-lg hover:bg-gray-200">Back</button>
          </div>
        </div>
      )}

      {/* Step 3: Complete */}
      {step === 3 && (
        <div className="bg-white border border-green-200 rounded-lg p-6 text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-green-100 text-green-600 text-2xl mb-4">✓</div>
          <h3 className="text-lg font-bold text-gray-900 mb-2">Organization Provisioned!</h3>
          <p className="text-sm text-gray-600 mb-4">
            <strong>{tenantForm.name}</strong> is ready. Share the credentials below with the client.
          </p>
          <div className="bg-gray-50 rounded-lg p-4 text-left max-w-sm mx-auto space-y-2 mb-4">
            <div className="flex justify-between text-sm">
              <span className="text-gray-500">Portal URL:</span>
              <span className="font-mono text-blue-600">{portalUrl}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-500">Username:</span>
              <span className="font-medium">{adminForm.admin_username}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-500">Password:</span>
              <span className="font-medium text-gray-400">(as set during provisioning)</span>
            </div>
          </div>
          <button
            onClick={() => {
              const text = `Portal: ${portalUrl}\nUsername: ${adminForm.admin_username}`;
              navigator.clipboard.writeText(text);
            }}
            className="px-4 py-2 bg-gray-100 text-gray-700 text-sm rounded-lg hover:bg-gray-200 transition mb-3"
          >
            Copy Credentials
          </button>
          <div className="mt-4">
            <button onClick={() => { setStep(0); setCreatedTenantId(null); setCreatedTenantSlug(''); }} className="text-sm text-blue-600 hover:underline">
              Onboard Another Client
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
