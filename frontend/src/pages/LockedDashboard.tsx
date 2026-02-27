import React from 'react';
import { useNavigate } from 'react-router-dom';

export default function LockedDashboard() {
  const navigate = useNavigate();

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 relative">
      {/* Blurred placeholder cards */}
      <div className="filter blur-sm pointer-events-none select-none">
        <h2 className="text-2xl font-bold text-gray-900 mb-6">Identity Risk Overview</h2>
        <div className="grid grid-cols-4 gap-4 mb-6">
          {['Total Identities', 'Critical', 'High', 'Snapshots'].map(label => (
            <div key={label} className="bg-white rounded-xl border border-gray-200 p-5">
              <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">{label}</div>
              <div className="text-2xl font-bold text-gray-300 mt-1">&mdash;</div>
            </div>
          ))}
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-white rounded-xl border border-gray-200 p-6 h-48" />
          <div className="bg-white rounded-xl border border-gray-200 p-6 h-48" />
        </div>
      </div>

      {/* Overlay card */}
      <div className="absolute inset-0 flex items-center justify-center z-10">
        <div className="bg-white rounded-2xl border border-gray-200 shadow-xl p-8 max-w-md text-center">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-amber-100 text-amber-600 mb-4">
            <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h3 className="text-lg font-bold text-gray-900 mb-2">Cloud Authentication Required</h3>
          <p className="text-sm text-gray-600 mb-5">
            Before you can start monitoring identities, you need to connect your cloud provider credentials.
            Go to Settings to configure your cloud connection and capture your first snapshot.
          </p>
          <button
            onClick={() => navigate('/settings/connections')}
            className="px-6 py-2.5 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 transition"
          >
            Go to Settings
          </button>
        </div>
      </div>
    </div>
  );
}
