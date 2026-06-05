import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useOrganization } from '../contexts/TenantContext';
import { api, ApiError } from '../services/apiClient';

export default function ForgotPassword() {
  const navigate = useNavigate();
  const { orgSlug, resolvedOrganization } = useOrganization();
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const body: Record<string, string> = { email };
      const slug = orgSlug || resolvedOrganization?.slug;
      if (slug) body.tenant_slug = slug;

      await api.post('/auth/forgot-password', body);
      setSent(true);
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : err instanceof Error ? err.message : 'Request failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-slate-900">
      <div className="w-full max-w-md px-4">
        <div className="text-center mb-8">
          <img src="/auditgraph_icon.png" alt="AuditGraph" className="w-16 h-16 object-contain mb-4 mx-auto" />
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Reset Password</h1>
          <p className="text-sm text-gray-500 dark:text-slate-400 mt-1">
            Enter your email to receive a password reset link
          </p>
        </div>

        <div className="bg-white dark:bg-slate-800 rounded-xl border border-gray-200 dark:border-slate-700 shadow-sm p-8 space-y-5">
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">
              {error}
            </div>
          )}

          {sent ? (
            <div className="text-center space-y-3">
              <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-green-100 text-green-600 mb-2">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <p className="text-sm text-gray-700 dark:text-slate-300">
                If an account exists with this email, you'll receive a password reset link.
              </p>
              <p className="text-xs text-gray-500">
                Check your email and follow the instructions to reset your password.
              </p>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-5">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">Email Address</label>
                <input
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  autoFocus
                  autoComplete="email"
                  required
                  className="w-full px-3 py-2 border border-gray-300 dark:border-slate-600 rounded-lg text-sm bg-white dark:bg-slate-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="you@company.com"
                />
              </div>

              <button
                type="submit"
                disabled={loading || !email}
                className={`w-full py-2.5 rounded-lg text-sm font-medium text-white transition ${
                  loading || !email
                    ? 'bg-gray-400 cursor-not-allowed'
                    : 'bg-blue-600 hover:bg-blue-700'
                }`}
              >
                {loading ? 'Sending...' : 'Send Reset Link'}
              </button>
            </form>
          )}

          <div className="text-center pt-2">
            <button
              onClick={() => navigate('/login')}
              className="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 transition"
            >
              Back to Login
            </button>
          </div>
        </div>

        <p className="text-center text-xs text-gray-400 mt-6">
          Enterprise Identity Risk Intelligence
        </p>
      </div>
    </div>
  );
}
