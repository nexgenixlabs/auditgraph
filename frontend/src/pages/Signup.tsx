import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { TIER_LIMITS } from '../constants/pricing';

type SignupStep = 'info' | 'plan';
type PlanChoice = 'free' | 'trial';

export default function Signup() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [orgName, setOrgName] = useState('');
  const [plan, setPlan] = useState<PlanChoice>('trial');
  const [step, setStep] = useState<SignupStep>('info');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const infoValid =
    /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(email.trim()) &&
    password.length >= 8 &&
    password === confirmPassword &&
    orgName.trim().length >= 2;

  function handleContinue(e: React.FormEvent) {
    e.preventDefault();
    if (!infoValid) return;
    setError(null);
    setStep('plan');
  }

  async function handleSubmit() {
    if (!infoValid) return;
    setLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email.trim().toLowerCase(),
          password,
          organization_name: orgName.trim(),
          plan,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || 'Signup failed');
        return;
      }

      // Log in the user (use the auth context)
      await login(email.trim().toLowerCase(), password);

      // Redirect to onboarding wizard
      navigate('/onboarding', { state: { fromSignup: true } });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Signup failed. Please try again.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  const freeLimits = TIER_LIMITS.free;
  const trialLimits = TIER_LIMITS.trial;

  return (
    <div className="min-h-screen bg-slate-900 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-white">AuditGraph</h1>
          <p className="text-sm text-slate-300 mt-1 font-medium">
            Identity Security Graph
          </p>
          <p className="text-[11px] text-slate-500 mt-0.5">
            For Human, Non-Human, and AI Identities · agentless · read-only
          </p>
          <p className="text-sm text-slate-400 mt-3">
            {step === 'info' ? 'Create your account' : 'Choose your plan'}
          </p>
        </div>

        {/* Card */}
        <div className="bg-slate-800 border border-slate-700 rounded-2xl p-8">
          {error && (
            <div className="mb-4 p-3 rounded-lg bg-red-900/30 border border-red-700 text-red-300 text-sm">
              {error}
            </div>
          )}

          {/* ─── STEP 1: Basic Info ─── */}
          {step === 'info' && (
            <form onSubmit={handleContinue} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Organization Name</label>
                <input
                  type="text"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  placeholder="e.g., Contoso Ltd"
                  className="w-full px-4 py-2.5 bg-slate-900 border border-slate-600 rounded-lg text-sm text-white placeholder-slate-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                  autoFocus
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Email</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="admin@company.com"
                  className="w-full px-4 py-2.5 bg-slate-900 border border-slate-600 rounded-lg text-sm text-white placeholder-slate-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Password</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Min 8 characters"
                  className="w-full px-4 py-2.5 bg-slate-900 border border-slate-600 rounded-lg text-sm text-white placeholder-slate-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Confirm Password</label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Repeat password"
                  className="w-full px-4 py-2.5 bg-slate-900 border border-slate-600 rounded-lg text-sm text-white placeholder-slate-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                />
                {confirmPassword && password !== confirmPassword && (
                  <p className="text-xs text-red-400 mt-1">Passwords do not match</p>
                )}
              </div>

              <button
                type="submit"
                disabled={!infoValid}
                className="w-full py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Continue
              </button>
            </form>
          )}

          {/* ─── STEP 2: Plan Selection ─── */}
          {step === 'plan' && (
            <div className="space-y-4">
              {/* Back link */}
              <button
                onClick={() => setStep('info')}
                className="text-xs text-slate-400 hover:text-slate-300 flex items-center gap-1"
              >
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                </svg>
                Back
              </button>

              <p className="text-sm text-slate-300">
                Choose a plan for <span className="font-medium text-white">{orgName}</span>
              </p>

              {/* Free Plan Card */}
              <button
                type="button"
                onClick={() => setPlan('free')}
                className={`w-full text-left rounded-xl border-2 p-4 transition-all ${
                  plan === 'free'
                    ? 'border-blue-500 bg-blue-500/10'
                    : 'border-slate-600 bg-slate-900 hover:border-slate-500'
                }`}
              >
                <div className="flex items-start gap-3">
                  <div className={`mt-0.5 w-4 h-4 rounded-full border-2 flex items-center justify-center flex-shrink-0 ${
                    plan === 'free' ? 'border-blue-500' : 'border-slate-500'
                  }`}>
                    {plan === 'free' && <div className="w-2 h-2 rounded-full bg-blue-500" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-semibold text-white">Free</div>
                    <div className="mt-2 space-y-1 text-xs text-slate-400">
                      <div>{freeLimits.max_identities} identities</div>
                      <div>{freeLimits.max_subscriptions} subscriptions</div>
                      <div>No expiry</div>
                      <div>Community support</div>
                    </div>
                  </div>
                </div>
              </button>

              {/* Trial Plan Card */}
              <button
                type="button"
                onClick={() => setPlan('trial')}
                className={`w-full text-left rounded-xl border-2 p-4 transition-all ${
                  plan === 'trial'
                    ? 'border-blue-500 bg-blue-500/10'
                    : 'border-slate-600 bg-slate-900 hover:border-slate-500'
                }`}
              >
                <div className="flex items-start gap-3">
                  <div className={`mt-0.5 w-4 h-4 rounded-full border-2 flex items-center justify-center flex-shrink-0 ${
                    plan === 'trial' ? 'border-blue-500' : 'border-slate-500'
                  }`}>
                    {plan === 'trial' && <div className="w-2 h-2 rounded-full bg-blue-500" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-white">Trial</span>
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-blue-500/20 text-blue-400">Recommended</span>
                    </div>
                    <div className="mt-2 space-y-1 text-xs text-slate-400">
                      <div>Unlimited identities</div>
                      <div>Unlimited subscriptions</div>
                      <div>Full platform access</div>
                      <div>{trialLimits.trial_days} days &middot; No credit card</div>
                    </div>
                  </div>
                </div>
              </button>

              {/* Submit */}
              <button
                onClick={handleSubmit}
                disabled={loading}
                className="w-full py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    Creating account...
                  </>
                ) : (
                  'Create Account'
                )}
              </button>
            </div>
          )}

          {/* Login link */}
          <div className="mt-6 text-center">
            <span className="text-sm text-slate-500">Already have an account? </span>
            <Link to="/login" className="text-sm text-blue-400 hover:text-blue-300">
              Sign in
            </Link>
          </div>

          {/* Terms */}
          <p className="mt-4 text-center text-[11px] text-slate-600">
            By signing up, you agree to the{' '}
            <Link to="/terms" className="text-slate-500 hover:text-slate-400 hover:opacity-80">Terms of Service</Link>
            {' '}and{' '}
            <Link to="/privacy" className="text-slate-500 hover:text-slate-400 hover:opacity-80">Privacy Policy</Link>
            .
          </p>
          <p className="mt-2 text-center text-[11px] text-slate-600">
            See our{' '}
            <Link to="/trust" className="text-slate-500 hover:text-slate-400 hover:opacity-80">Trust Center</Link>
            {' '}for compliance posture, security architecture, and audit-document requests.
          </p>
        </div>
      </div>
    </div>
  );
}
