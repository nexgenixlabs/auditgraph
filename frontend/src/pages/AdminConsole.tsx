import React from 'react';
import { Routes, Route, Link, useLocation, Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { AdminOverview, AdminTenants, AdminOnboarding, AdminMonitoring } from './admin';

const NAV_ITEMS = [
  { path: '', label: 'Overview', icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6' },
  { path: 'tenants', label: 'Tenants', icon: 'M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4' },
  { path: 'onboarding', label: 'Onboarding', icon: 'M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z' },
  { path: 'monitoring', label: 'Monitoring', icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z' },
];

export default function AdminConsole() {
  const { isSuperAdmin } = useAuth();
  const location = useLocation();

  if (!isSuperAdmin) {
    return <Navigate to="/" replace />;
  }

  const currentPath = location.pathname.replace('/admin', '').replace(/^\//, '');

  return (
    <div className="flex min-h-[calc(100vh-5rem)]">
      {/* Sidebar */}
      <div className="w-56 bg-gray-900 text-white flex-shrink-0">
        <div className="p-4 border-b border-gray-700">
          <h2 className="text-sm font-bold text-white">Admin Console</h2>
          <p className="text-[10px] text-gray-400 mt-0.5">Platform Management</p>
        </div>
        <nav className="p-2 space-y-0.5">
          {NAV_ITEMS.map(item => {
            const isActive = item.path === ''
              ? currentPath === '' || currentPath === '/'
              : currentPath.startsWith(item.path);
            return (
              <Link
                key={item.path}
                to={`/admin${item.path ? `/${item.path}` : ''}`}
                className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition ${
                  isActive
                    ? 'bg-blue-600 text-white font-medium'
                    : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                }`}
              >
                <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={item.icon} />
                </svg>
                {item.label}
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Content */}
      <div className="flex-1 bg-gray-50 p-6 overflow-y-auto">
        <Routes>
          <Route index element={<AdminOverview />} />
          <Route path="tenants" element={<AdminTenants />} />
          <Route path="onboarding" element={<AdminOnboarding />} />
          <Route path="monitoring" element={<AdminMonitoring />} />
        </Routes>
      </div>
    </div>
  );
}
