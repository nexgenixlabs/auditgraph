import React, { useState } from 'react';
import { SUBSCRIPTION_TERMS } from '../../constants/pricing';
import { api, ApiError } from '../../services/apiClient';

const RESERVED_SLUGS = new Set([
  'admin', 'api', 'www', 'app', 'portal', 'login', 'auth', 'sso',
  'status', 'docs', 'help', 'support', 'billing', 'dashboard', 'health',
  'metrics', 'system', 'internal', 'test', 'staging', 'dev', 'prod',
]);

const INDUSTRIES = [
  'Financial Services', 'Healthcare', 'Technology', 'Manufacturing',
  'Retail', 'Government', 'Education', 'Energy & Utilities',
  'Telecommunications', 'Media & Entertainment', 'Legal', 'Other',
];

const COMPLIANCE_FRAMEWORKS = [
  'SOC 2', 'ISO 27001', 'HIPAA', 'PCI DSS', 'NIST CSF',
  'GDPR', 'FedRAMP', 'CIS Controls', 'SOX', 'None / Not Sure',
];

interface OnboardingForm {
  name: string;
  slug: string;
  plan: string;
  subscription_term: number;
  industry: string;
  compliance_framework: string;
  primary_cloud: string;
  root_username: string;
  root_email: string;
  root_password: string;
}

function generatePassword(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%';
  let pw = '';
  for (let i = 0; i < 16; i++) pw += chars[Math.floor(Math.random() * chars.length)];
  return pw;
}

export default function AdminOnboarding() {
  const [form, setForm] = useState<OnboardingForm>({
    name: '', slug: '', plan: 'pro', subscription_term: 1,
    industry: '', compliance_framework: '',
    primary_cloud: 'azure',
    root_username: '', root_email: '', root_password: '',
  });
  const [error, setError] = useState<string | null>(null);
  const [processing, setProcessing] = useState(false);
  const [success, setSuccess] = useState(false);
  const [createdSlug, setCreatedSlug] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState(false);

  const slugError = form.slug && RESERVED_SLUGS.has(form.slug)
    ? `"${form.slug}" is a reserved slug`
    : null;

  const canSubmit =
    form.name.trim() &&
    form.slug.trim() &&
    !slugError &&
    form.root_username.trim().length >= 3 &&
    form.root_email.trim() &&
    form.root_password.length >= 12;

  function handleNameChange(name: string) {
    const slug = name.toLowerCase().replace(/[^a-z0-9]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
    setForm(p => ({ ...p, name, slug }));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit || slugError) return;
    setError(null);
    setProcessing(true);
    try {
      const data = await api.post('/clients', form);
      setCreatedSlug(data.tenant.slug);
      setSuccess(true);
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : err instanceof Error ? err.message : 'Failed to create client');
    } finally {
      setProcessing(false);
    }
  }

  function handleCopyCredentials() {
    const text = `Portal: ${createdSlug}.auditgraph.ai\nUsername: ${form.root_username}\nPassword: ${form.root_password}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function handleReset() {
    setForm({
      name: '', slug: '', plan: 'pro', subscription_term: 1,
      industry: '', compliance_framework: '',
      primary_cloud: 'azure',
      root_username: '', root_email: '', root_password: '',
    });
    setSuccess(false);
    setCreatedSlug('');
    setCopied(false);
    setShowPassword(false);
  }

  // Success state
  if (success) {
    return (
      <div className="max-w-2xl mx-auto space-y-6">
        <div className="bg-gray-900 border border-green-700 rounded-xl p-8 text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-green-900/50 text-green-400 text-2xl mb-4">{'\u2713'}</div>
          <h3 className="text-lg font-bold text-white mb-2">Organization Created!</h3>
          <p className="text-sm text-gray-300 mb-1">
            <strong className="text-white">{form.name}</strong> is ready at <span className="font-mono text-blue-400">{createdSlug}.auditgraph.ai</span>
          </p>
          <p className="text-xs text-amber-400 mb-5">The root user will be prompted to change their password on first login.</p>

          <div className="bg-gray-800 rounded-lg p-4 text-left max-w-sm mx-auto space-y-2 mb-5">
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Portal URL:</span>
              <span className="font-mono text-blue-400">{createdSlug}.auditgraph.ai</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Username:</span>
              <span className="font-medium text-white">{form.root_username}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Password:</span>
              <span className="font-medium font-mono text-xs text-white">{form.root_password}</span>
            </div>
          </div>

          <button
            onClick={handleCopyCredentials}
            className="px-5 py-2 bg-gradient-to-r from-blue-500 to-cyan-500 text-white text-sm font-medium rounded-lg hover:from-blue-600 hover:to-cyan-600 transition"
          >
            {copied ? 'Copied!' : 'Copy Credentials'}
          </button>

          <div className="mt-5 flex items-center justify-center gap-4">
            <a href="/admin/tenants" className="text-sm text-blue-400 hover:text-blue-300 hover:underline">
              View Clients
            </a>
            <button onClick={handleReset} className="text-sm text-gray-400 hover:text-white hover:underline">
              Onboard Another
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white">Client Onboarding</h2>
        <p className="text-sm text-gray-400 mt-0.5">Create a new organization with a single form</p>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded-lg p-3 text-sm text-red-300">
          {error}
          <button onClick={() => setError(null)} className="ml-2 text-red-400 hover:text-red-300">&times;</button>
        </div>
      )}

      <form onSubmit={handleSubmit} className="bg-gray-900 border border-gray-700 rounded-xl divide-y divide-gray-700">
        {/* Section 1: Organization Details */}
        <div className="p-6 space-y-4">
          <div className="flex items-center gap-2">
            <svg className="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
            </svg>
            <h3 className="text-xs font-semibold text-blue-400 uppercase tracking-wider">Organization Details</h3>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="block text-xs font-medium text-gray-400 mb-1">Organization Name</label>
              <input
                value={form.name}
                onChange={e => handleNameChange(e.target.value)}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-sm text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="Acme Corporation"
                required
              />
            </div>
            <div className="col-span-2">
              <label className="block text-xs font-medium text-gray-400 mb-1">URL Slug</label>
              <div className="flex items-center gap-1">
                <input
                  value={form.slug}
                  onChange={e => setForm(p => ({ ...p, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-_]/g, '') }))}
                  className={`w-48 px-3 py-2 bg-gray-800 border rounded-lg text-sm font-mono text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 ${slugError ? 'border-red-500' : 'border-gray-600'}`}
                  placeholder="acme"
                  required
                />
                <span className="text-sm text-gray-500">.auditgraph.ai</span>
              </div>
              {slugError && <p className="text-xs text-red-400 mt-1">{slugError}</p>}
            </div>
          </div>
        </div>

        {/* Section 2: Plan */}
        <div className="p-6 space-y-4">
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Plan</h3>
          <div className="flex gap-3">
            {['free', 'trial', 'pro', 'enterprise'].map(p => (
              <label key={p} className={`flex items-center gap-2 px-5 py-2.5 border rounded-lg cursor-pointer transition ${
                form.plan === p ? 'bg-blue-600 text-white border-blue-600' : 'border-gray-600 text-gray-300 hover:border-gray-500'
              }`}>
                <input type="radio" name="plan" value={p} checked={form.plan === p} onChange={() => setForm(prev => ({ ...prev, plan: p }))} className="sr-only" />
                <span className="text-sm font-medium capitalize">{p}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Section 3: Subscription Term */}
        {(form.plan === 'pro' || form.plan === 'enterprise') && (
          <div className="p-6 space-y-4">
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Subscription Term</h3>
            <div className="flex gap-3">
              {SUBSCRIPTION_TERMS.map(t => (
                <label key={t.value} className={`flex items-center justify-between px-5 py-2.5 border rounded-lg cursor-pointer transition ${
                  form.subscription_term === t.value ? 'border-blue-500 text-blue-400' : 'border-gray-600 text-gray-400 hover:border-gray-500'
                }`}>
                  <input type="radio" name="term" value={t.value} checked={form.subscription_term === t.value} onChange={() => setForm(prev => ({ ...prev, subscription_term: t.value }))} className="sr-only" />
                  <div>
                    <span className="text-sm font-medium">{t.label}</span>
                    {t.discount > 0 && <span className="ml-1.5 text-[10px] font-semibold text-green-400">{t.discount * 100}% off</span>}
                  </div>
                </label>
              ))}
            </div>
          </div>
        )}

        {/* Section 4: Industry & Compliance */}
        <div className="p-6 space-y-4">
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Industry & Compliance</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1">Industry</label>
              <select
                value={form.industry}
                onChange={e => setForm(p => ({ ...p, industry: e.target.value }))}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-sm text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="">Select industry...</option>
                {INDUSTRIES.map(i => <option key={i} value={i}>{i}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1">Primary Compliance Framework</label>
              <select
                value={form.compliance_framework}
                onChange={e => setForm(p => ({ ...p, compliance_framework: e.target.value }))}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-sm text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="">Select framework...</option>
                {COMPLIANCE_FRAMEWORKS.map(f => <option key={f} value={f}>{f}</option>)}
              </select>
            </div>
          </div>
        </div>

        {/* Section 5: Cloud Providers */}
        <div className="p-6 space-y-4">
          <div className="flex items-center gap-2">
            <svg className="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 00-9.78 2.096A4.001 4.001 0 003 15z" />
            </svg>
            <h3 className="text-xs font-semibold text-purple-400 uppercase tracking-wider">Primary Cloud Provider</h3>
          </div>
          <p className="text-xs text-gray-500">Select the primary cloud provider for this organization. Additional providers can be enabled later.</p>
          <div className="grid grid-cols-3 gap-3">
            {[
              { key: 'azure', label: 'Azure' },
              { key: 'aws', label: 'AWS' },
              { key: 'gcp', label: 'GCP' },
            ].map(cloud => (
              <label
                key={cloud.key}
                className={`relative flex flex-col items-center gap-2 px-4 py-5 border-2 rounded-xl cursor-pointer transition ${
                  form.primary_cloud === cloud.key
                    ? 'border-blue-500 bg-blue-900/20'
                    : 'border-gray-600 hover:border-gray-500'
                }`}
              >
                <input
                  type="radio"
                  name="primary_cloud"
                  value={cloud.key}
                  checked={form.primary_cloud === cloud.key}
                  onChange={() => setForm(p => ({ ...p, primary_cloud: cloud.key }))}
                  className="sr-only"
                />
                <svg className={`w-8 h-8 ${form.primary_cloud === cloud.key ? 'text-blue-400' : 'text-gray-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 00-9.78 2.096A4.001 4.001 0 003 15z" />
                </svg>
                <span className={`text-sm font-semibold ${form.primary_cloud === cloud.key ? 'text-white' : 'text-gray-400'}`}>
                  {cloud.label}
                </span>
                {form.primary_cloud === cloud.key && (
                  <>
                    <span className="absolute top-2 right-2 w-5 h-5 rounded-full bg-blue-600 text-white flex items-center justify-center text-xs">{'\u2713'}</span>
                    <span className="absolute top-2 left-2 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-amber-500 text-gray-900">PRIMARY</span>
                  </>
                )}
              </label>
            ))}
          </div>
        </div>

        {/* Section 6: Root User Account */}
        <div className="p-6 space-y-4 border-t border-amber-600/50">
          <div className="flex items-center gap-2">
            <svg className="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <h3 className="text-xs font-semibold text-amber-400 uppercase tracking-wider">Root User Account</h3>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-amber-500 text-gray-900">Required</span>
          </div>
          <div className="bg-amber-900/30 border border-amber-700 rounded-lg px-4 py-3 text-xs text-amber-300 flex items-start gap-2">
            <svg className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
            These credentials will be shared with the client. The user will be required to change their password on first login.
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1">Username</label>
              <input
                value={form.root_username}
                onChange={e => setForm(p => ({ ...p, root_username: e.target.value.toLowerCase().replace(/\s/g, '') }))}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-sm text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="admin"
                required
                minLength={3}
              />
              {form.root_username && form.root_username.length < 3 && (
                <p className="text-[10px] text-red-400 mt-1">Min 3 characters</p>
              )}
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1">Email</label>
              <input
                type="email"
                value={form.root_email}
                onChange={e => setForm(p => ({ ...p, root_email: e.target.value }))}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-sm text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="admin@company.com"
                required
              />
            </div>
            <div className="col-span-2">
              <label className="block text-xs font-medium text-gray-400 mb-1">Password (min 12 characters)</label>
              <div className="flex gap-2">
                <div className="flex-1 relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={form.root_password}
                    onChange={e => setForm(p => ({ ...p, root_password: e.target.value }))}
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-sm font-mono text-white placeholder-gray-500 pr-10 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Secure password"
                    required
                    minLength={12}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-300"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      {showPassword ? (
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L3 3m6.878 6.878L21 21" />
                      ) : (
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                      )}
                    </svg>
                  </button>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    const pw = generatePassword();
                    setForm(p => ({ ...p, root_password: pw }));
                    setShowPassword(true);
                  }}
                  className="px-3 py-2 bg-gray-700 text-gray-300 text-xs font-medium rounded-lg hover:bg-gray-600 transition whitespace-nowrap"
                >
                  Generate
                </button>
                {form.root_password && (
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(form.root_password);
                    }}
                    className="px-3 py-2 bg-gray-700 text-gray-300 text-xs font-medium rounded-lg hover:bg-gray-600 transition"
                  >
                    Copy
                  </button>
                )}
              </div>
              {form.root_password && form.root_password.length < 12 && (
                <p className="text-[10px] text-red-400 mt-1">Min 12 characters</p>
              )}
            </div>
          </div>
        </div>

        {/* Submit */}
        <div className="p-6 flex items-center gap-3">
          <button
            type="submit"
            disabled={!canSubmit || processing}
            className="px-8 py-2.5 bg-gradient-to-r from-blue-500 to-cyan-500 text-white text-sm font-medium rounded-lg hover:from-blue-600 hover:to-cyan-600 disabled:opacity-40 disabled:cursor-not-allowed transition"
          >
            {processing ? 'Creating Organization...' : 'Create Organization'}
          </button>
          <button
            type="button"
            onClick={handleReset}
            className="px-4 py-2.5 text-gray-400 hover:text-white border border-gray-600 rounded-lg text-sm transition"
          >
            Reset
          </button>
        </div>
      </form>
    </div>
  );
}
