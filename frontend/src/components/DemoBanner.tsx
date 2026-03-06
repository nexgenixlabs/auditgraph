import React from 'react';
import { useAuth } from '../contexts/AuthContext';

export default function DemoBanner() {
  const { isDemo } = useAuth();
  if (!isDemo) return null;

  return (
    <div
      className="fixed top-0 left-0 right-0 z-[9999] flex items-center justify-center gap-2 px-4 py-1.5 text-xs font-medium"
      style={{
        background: 'linear-gradient(90deg, #f59e0b 0%, #d97706 100%)',
        color: '#fff',
      }}
    >
      <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
          d="M13 16h-1v-4h-1m1-4h.01M12 2a10 10 0 100 20 10 10 0 000-20z" />
      </svg>
      Demo Environment &mdash; simulated security data
    </div>
  );
}
