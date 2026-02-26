import React, { useEffect, useRef, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { useConnection } from '../../contexts/ConnectionContext';
import { CLOUD_BRAND } from '../../constants/design';
import ThemeToggle from './ThemeToggle';

interface TopBarProps {
  onSearchOpen: () => void;
  onCopilotOpen?: () => void;
}

const ROLE_COLORS: Record<string, string> = {
  admin: 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  reader: 'bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  compliance: 'bg-gray-100 text-gray-600 dark:bg-slate-700 dark:text-slate-300',
};

const CLOUD_BRAND_DOT: Record<string, string> = {
  azure: CLOUD_BRAND.azure,
  aws: CLOUD_BRAND.aws,
  gcp: CLOUD_BRAND.gcp,
};

const TopBar: React.FC<TopBarProps> = ({ onSearchOpen, onCopilotOpen }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout, isSuperAdmin, activeTenantId, activeTenantName, switchTenant } = useAuth();
  const { connections, selectedConnectionId, setSelectedConnectionId } = useConnection();
  const [unreadCount, setUnreadCount] = useState(0);
  const [tenantDropdownOpen, setTenantDropdownOpen] = useState(false);
  const [scopeDropdownOpen, setScopeDropdownOpen] = useState(false);
  const [tenantsList, setTenantsList] = useState<{ id: number; name: string }[]>([]);
  const scopeRef = useRef<HTMLDivElement>(null);

  const isMac = typeof navigator !== 'undefined' && /Mac/.test(navigator.userAgent);

  // Notification stats polling
  useEffect(() => {
    let mounted = true;
    async function fetchStats() {
      try {
        const res = await fetch('/api/notifications/stats');
        if (res.ok && mounted) {
          const data = await res.json();
          setUnreadCount(data.unread || 0);
        }
      } catch { /* ignore */ }
    }
    fetchStats();
    const interval = setInterval(fetchStats, 60000);
    return () => { mounted = false; clearInterval(interval); };
  }, []);

  // Tenant list for superadmin switcher
  useEffect(() => {
    if (!isSuperAdmin) return;
    fetch('/api/clients')
      .then(r => r.ok ? r.json() : null)
      .then(d => d && setTenantsList(d.tenants || []))
      .catch(() => {});
  }, [isSuperAdmin]);

  const isActive = (path: string) => location.pathname.startsWith(path);

  return (
    <header className="topbar-glass fixed top-0 left-0 right-0 h-14 bg-white border-b border-gray-200 z-40 flex items-center px-4">
      {/* Left: Logo & Brand */}
      <Link to="/" className="flex items-center gap-2.5 hover:opacity-80 transition mr-6">
        <img
          src="/auditgraph-logo.png"
          alt="AuditGraph Logo"
          className="h-8 w-auto"
        />
        <div className="leading-tight">
          <span className="text-base font-bold text-gray-900 dark:text-white">AuditGraph</span>
          <p className="text-[10px] text-gray-400 dark:text-slate-500 font-medium">
            {user?.tenant_name || 'Map. Monitor. Secure.'}
          </p>
        </div>
      </Link>

      {/* Scope Selector (only when 2+ connections) */}
      {connections.length >= 2 && (() => {
        const selected = connections.find(c => c.id === selectedConnectionId);
        const brandColor = selected ? CLOUD_BRAND_DOT[selected.cloud] || CLOUD_BRAND.azure : undefined;
        return (
          <div className="relative" ref={scopeRef}>
            <button
              onClick={() => setScopeDropdownOpen(!scopeDropdownOpen)}
              style={brandColor ? { borderLeftColor: brandColor, borderLeftWidth: 3 } : undefined}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-gray-100 dark:bg-slate-800 text-gray-700 dark:text-slate-300 hover:bg-gray-200 dark:hover:bg-slate-700 border border-gray-200 dark:border-slate-600 transition"
            >
              {selected && (
                <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: brandColor }} />
              )}
              <span>{selected ? selected.label : 'All Connections'}</span>
              <svg className="w-3 h-3 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            {scopeDropdownOpen && (
              <>
                <div className="fixed inset-0 z-40" onClick={() => setScopeDropdownOpen(false)} />
                <div className="absolute left-0 mt-1 w-52 bg-white dark:bg-slate-800 border border-gray-200 dark:border-slate-600 rounded-lg shadow-lg z-50 py-1">
                  <button
                    onClick={() => { setSelectedConnectionId(null); setScopeDropdownOpen(false); }}
                    className={`w-full text-left px-3 py-2 text-xs hover:bg-gray-50 dark:hover:bg-slate-700 transition flex items-center gap-2 ${
                      selectedConnectionId === null ? 'font-bold text-blue-700 dark:text-blue-300' : 'text-gray-700 dark:text-slate-300'
                    }`}
                  >
                    All Connections
                  </button>
                  {connections.map(c => {
                    const dotColor = CLOUD_BRAND_DOT[c.cloud] || CLOUD_BRAND.azure;
                    return (
                      <button
                        key={c.id}
                        onClick={() => { setSelectedConnectionId(c.id); setScopeDropdownOpen(false); }}
                        className={`w-full text-left px-3 py-2 text-xs hover:bg-gray-50 dark:hover:bg-slate-700 transition flex items-center gap-2 ${
                          selectedConnectionId === c.id ? 'font-bold text-blue-700 dark:text-blue-300' : 'text-gray-700 dark:text-slate-300'
                        }`}
                      >
                        <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: dotColor }} />
                        {c.label}
                      </button>
                    );
                  })}
                </div>
              </>
            )}
          </div>
        );
      })()}

      {/* Center: Search */}
      <div className="flex-1 flex justify-center">
        <button
          onClick={onSearchOpen}
          className="flex items-center gap-2 px-4 py-1.5 rounded-lg text-sm text-gray-400 bg-gray-100 dark:bg-slate-800 hover:bg-gray-200 dark:hover:bg-slate-700 transition border border-gray-200 dark:border-slate-600 w-64"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <span className="text-xs">Search identities...</span>
          <span className="ml-auto text-[10px] text-gray-300 dark:text-slate-500">{isMac ? '\u2318' : 'Ctrl+'}K</span>
        </button>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-1">
        {/* Theme toggle (Sentinel / Arctic) */}
        <ThemeToggle />

        {/* Copilot button */}
        {onCopilotOpen && (
          <button
            onClick={onCopilotOpen}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-indigo-600 dark:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-900/30 border border-indigo-200 dark:border-indigo-700 transition"
            title="Security Copilot"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
            <span className="text-xs font-medium">AI Copilot</span>
          </button>
        )}

        {/* Notification bell */}
        <button
          onClick={() => navigate('/notifications')}
          className={`p-2 rounded-lg transition relative ${
            isActive('/notifications') ? 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400' : 'text-gray-500 dark:text-slate-400 hover:bg-gray-100 dark:hover:bg-slate-800'
          }`}
          title="Notifications"
        >
          <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
          </svg>
          {unreadCount > 0 && (
            <span className="absolute -top-0.5 -right-0.5 bg-red-500 text-white text-[10px] font-bold rounded-full min-w-[16px] h-[16px] flex items-center justify-center px-1">
              {unreadCount > 99 ? '99+' : unreadCount}
            </span>
          )}
        </button>

        {/* Tenant Switcher (superadmin only) */}
        {isSuperAdmin && (
          <div className="relative">
            <button
              onClick={() => setTenantDropdownOpen(!tenantDropdownOpen)}
              className="flex items-center gap-1 px-2 py-1.5 rounded-lg text-xs font-medium bg-purple-50 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 hover:bg-purple-100 dark:hover:bg-purple-900/50 border border-purple-200 dark:border-purple-700 transition"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
              </svg>
              <span>{activeTenantName || 'All Clients'}</span>
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            {tenantDropdownOpen && (
              <>
                <div className="fixed inset-0 z-40" onClick={() => setTenantDropdownOpen(false)} />
                <div className="absolute right-0 mt-1 w-52 bg-white dark:bg-slate-800 border border-gray-200 dark:border-slate-600 rounded-lg shadow-lg z-50 py-1">
                  <button
                    onClick={() => { switchTenant(null); setTenantDropdownOpen(false); }}
                    className={`w-full text-left px-3 py-2 text-xs hover:bg-gray-50 dark:hover:bg-slate-700 transition ${!activeTenantId ? 'font-bold text-purple-700 dark:text-purple-300' : 'text-gray-700 dark:text-slate-300'}`}
                  >
                    All Clients (no filter)
                  </button>
                  {tenantsList.map(t => (
                    <button
                      key={t.id}
                      onClick={() => { switchTenant(t.id, t.name); setTenantDropdownOpen(false); }}
                      className={`w-full text-left px-3 py-2 text-xs hover:bg-gray-50 dark:hover:bg-slate-700 transition ${activeTenantId === t.id ? 'font-bold text-purple-700 dark:text-purple-300' : 'text-gray-700 dark:text-slate-300'}`}
                    >
                      {t.name}
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        )}

        {/* User menu */}
        {user && (
          <div className="flex items-center gap-2 ml-1 pl-2 border-l border-gray-200 dark:border-slate-700">
            <span className="text-xs text-gray-500 dark:text-slate-400">
              {user.display_name}
              <span className={`ml-1 px-1.5 py-0.5 rounded text-[10px] font-medium uppercase ${ROLE_COLORS[user.role] || ROLE_COLORS.compliance}`}>
                {user.role}
              </span>
            </span>
            <button
              onClick={() => { logout(); navigate('/login'); }}
              className="p-1.5 rounded-lg text-gray-400 hover:text-red-500 hover:bg-gray-100 dark:hover:bg-slate-800 transition"
              title="Sign out"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
            </button>
          </div>
        )}
      </div>
    </header>
  );
};

export default TopBar;
