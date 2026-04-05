import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export default function AcceptInvitation() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token') || '';
  const navigate = useNavigate();
  const { login } = useAuth();

  const [loading, setLoading] = useState(true);
  const [valid, setValid] = useState(false);
  const [invitation, setInvitation] = useState<{
    email: string;
    role: string;
    org_name: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Form state
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!token) {
      setError('No invitation token provided');
      setLoading(false);
      return;
    }
    fetch(`/api/auth/validate-invitation?token=${encodeURIComponent(token)}`)
      .then(r => r.json())
      .then(data => {
        if (data.valid) {
          setValid(true);
          setInvitation({ email: data.email, role: data.role, org_name: data.org_name });
        } else {
          setError(data.error || 'Invalid or expired invitation');
        }
      })
      .catch(() => setError('Failed to validate invitation'))
      .finally(() => setLoading(false));
  }, [token]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (password.length < 12) {
      setError('Password must be at least 12 characters');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (!displayName.trim()) {
      setError('Display name is required');
      return;
    }

    setSubmitting(true);
    try {
      const res = await fetch('/api/auth/accept-invitation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, display_name: displayName.trim(), password }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Failed to accept invitation');
        setSubmitting(false);
        return;
      }

      // Phase S1: Cookies set by server response — no localStorage needed
      if (data.access_token) {
        navigate('/');
        window.location.reload();
      }
    } catch {
      setError('Network error');
    }
    setSubmitting(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center px-4">
      <div className="w-full max-w-md bg-white rounded-2xl shadow-2xl p-8">
        <div className="text-center mb-6">
          <h1 className="text-2xl font-bold text-gray-900">Accept Invitation</h1>
          {invitation && (
            <p className="text-sm text-gray-500 mt-2">
              You've been invited to join <strong className="text-gray-900">{invitation.org_name}</strong> as a{' '}
              <span className="text-blue-600 font-medium">{invitation.role}</span>
            </p>
          )}
        </div>

        {loading && (
          <div className="text-center py-8 text-gray-500">Validating invitation...</div>
        )}

        {!loading && !valid && (
          <div className="text-center py-8">
            <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-red-100 flex items-center justify-center">
              <svg className="w-8 h-8 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </div>
            <p className="text-red-600 font-medium">{error || 'Invalid invitation'}</p>
            <button
              onClick={() => navigate('/login')}
              className="mt-4 text-sm text-blue-600 hover:text-blue-800"
            >
              Go to Login
            </button>
          </div>
        )}

        {!loading && valid && invitation && (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
              <input
                value={invitation.email}
                disabled
                className="w-full px-3 py-2 border rounded-lg text-sm bg-gray-50 text-gray-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Display Name</label>
              <input
                value={displayName}
                onChange={e => setDisplayName(e.target.value)}
                autoFocus
                className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="Your full name"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="Minimum 12 characters"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Confirm Password</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
                className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>

            {error && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">{error}</div>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="w-full py-2.5 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-40 transition"
            >
              {submitting ? 'Creating Account...' : 'Create Account & Join'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
