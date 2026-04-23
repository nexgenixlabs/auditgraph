import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

interface TrialBannerProps {
  plan: string;
  trialExpiresAt: string | null;
}

function daysUntil(iso: string): number {
  const now = new Date();
  const expires = new Date(iso);
  return Math.ceil((expires.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
}

export function TrialBanner({ plan, trialExpiresAt }: TrialBannerProps) {
  const navigate = useNavigate();

  if (plan !== 'trial' || !trialExpiresAt) return null;

  const daysLeft = daysUntil(trialExpiresAt);

  // Only show banner when 7 days or fewer remain
  if (daysLeft > 7) return null;

  const expired = daysLeft <= 0;
  const urgent = daysLeft <= 3;

  return (
    <div
      className={`flex items-center justify-between px-4 py-2 text-xs font-medium ${
        expired
          ? 'bg-red-600 text-white'
          : urgent
            ? 'bg-amber-500 text-white'
            : 'bg-amber-100 text-amber-900 dark:bg-amber-900/40 dark:text-amber-200'
      }`}
      style={{ paddingLeft: 'var(--sidebar-width, 220px)' }}
    >
      <span>
        {expired
          ? 'Your trial has ended. Upgrade to continue scanning.'
          : `Your trial ends in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}. Upgrade to Pro to keep full access.`}
      </span>
      <button
        onClick={() => navigate('/billing')}
        className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
          expired || urgent
            ? 'bg-white/20 hover:bg-white/30 text-white'
            : 'bg-amber-600 hover:bg-amber-700 text-white'
        }`}
      >
        Upgrade Now
      </button>
    </div>
  );
}

interface TrialExpiredModalProps {
  open: boolean;
  onClose: () => void;
}

export function TrialExpiredModal({ open, onClose }: TrialExpiredModalProps) {
  const navigate = useNavigate();
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (open) setVisible(true);
  }, [open]);

  if (!visible) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-xl max-w-sm w-full mx-4 p-6 text-center">
        <div className="w-12 h-12 bg-red-100 dark:bg-red-900/30 rounded-full flex items-center justify-center mx-auto mb-4">
          <svg className="w-6 h-6 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
          </svg>
        </div>
        <h3 className="text-lg font-bold text-gray-900 dark:text-white">Trial Ended</h3>
        <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">
          Your trial has ended. Upgrade to continue scanning.
        </p>
        <div className="mt-5 flex gap-3">
          <button
            onClick={() => { setVisible(false); onClose(); }}
            className="flex-1 py-2 px-3 rounded-lg border border-gray-300 dark:border-slate-600 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-slate-700 transition-colors"
          >
            View existing data
          </button>
          <button
            onClick={() => { setVisible(false); onClose(); navigate('/billing'); }}
            className="flex-1 py-2 px-3 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold transition-colors"
          >
            Upgrade Now
          </button>
        </div>
      </div>
    </div>
  );
}
