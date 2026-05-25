import React, { useEffect, useRef, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { useConnection } from '../../contexts/ConnectionContext';
import { CLOUD_BRAND } from '../../constants/design';

interface TopBarProps {
  onSearchOpen: () => void;
  onCopilotOpen?: () => void;
}

const CLOUD_BRAND_DOT: Record<string, string> = {
  azure: CLOUD_BRAND.azure,
  aws: CLOUD_BRAND.aws,
  gcp: CLOUD_BRAND.gcp,
};

const TopBar: React.FC<TopBarProps> = ({ onSearchOpen, onCopilotOpen }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout, isSuperAdmin, activeOrgId, activeOrgName, switchOrganization, isImpersonating, exitImpersonation } = useAuth();
  const { connections, selectedConnectionId, setSelectedConnectionId } = useConnection();
  const [unreadCount, setUnreadCount] = useState(0);
  const [orgDropdownOpen, setOrgDropdownOpen] = useState(false);
  const [scopeDropdownOpen, setScopeDropdownOpen] = useState(false);
  const [orgsList, setOrgsList] = useState<{ id: number; name: string }[]>([]);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const scopeRef = useRef<HTMLDivElement>(null);
  const userRef = useRef<HTMLDivElement>(null);

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

  // Organization list for superadmin switcher
  useEffect(() => {
    if (!isSuperAdmin) return;
    fetch('/api/clients')
      .then(r => r.ok ? r.json() : null)
      .then(d => d && setOrgsList(d.organizations || []))
      .catch(() => {});
  }, [isSuperAdmin]);

  const isActive = (path: string) => location.pathname.startsWith(path);

  return (
    <>
    {/* Phase 1B: Impersonation banner */}
    {isImpersonating && (
      <div className="fixed top-0 left-0 right-0 z-50 flex items-center justify-center gap-3 px-4 py-1.5 text-xs font-medium"
        style={{ backgroundColor: '#b45309', color: '#fff' }}>
        <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.072 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
        <span>Impersonating {user?.org_name || 'org'} as {user?.role || 'admin'}</span>
        <button
          onClick={exitImpersonation}
          className="px-2 py-0.5 rounded text-xs font-semibold transition-colors"
          style={{ backgroundColor: 'rgba(255,255,255,0.2)', color: '#fff' }}
          onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.3)')}
          onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.2)')}
        >
          Exit Impersonation
        </button>
      </div>
    )}
    <header
      className="topbar-glass fixed top-0 left-0 right-0 z-40 flex items-center px-4 gap-3"
      style={{ height: 'var(--header-height, 56px)', marginTop: isImpersonating ? '32px' : '0' }}
    >
      {/* Logo & Brand */}
      <Link to="/" className="flex items-center gap-2.5 hover:opacity-80 transition-opacity mr-2 flex-shrink-0">
        <img
          src="/auditgraph_icon.png"
          alt="AuditGraph"
          className="h-7 w-7 object-contain rounded"
        />
        <div className="leading-tight hidden sm:block">
          <span className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>AuditGraph</span>
          <p className="text-[10px] font-medium" style={{ color: 'var(--text-muted)' }}>
            {user?.org_name || 'Identity Risk OS'}
          </p>
        </div>
      </Link>

      {/* Scope Selector (only when 2+ connections) */}
      {connections.length >= 2 && (() => {
        const selected = connections.find(c => c.id === selectedConnectionId);
        const brandColor = selected ? CLOUD_BRAND_DOT[selected.cloud] || CLOUD_BRAND.azure : undefined;
        return (
          <div className="relative flex-shrink-0" ref={scopeRef}>
            <button
              onClick={() => setScopeDropdownOpen(!scopeDropdownOpen)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition-colors"
              style={{
                ...(brandColor ? { borderLeftColor: brandColor, borderLeftWidth: 2 } : {}),
                backgroundColor: 'var(--bg-raised)',
                color: 'var(--text-secondary)',
                border: '1px solid var(--border-default)',
              }}
            >
              {selected && (
                <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: brandColor }} />
              )}
              <span>{selected ? selected.label : 'All Connections'}</span>
              <svg className="w-3 h-3" style={{ color: 'var(--text-muted)' }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            {scopeDropdownOpen && (
              <>
                <div className="fixed inset-0 z-40" onClick={() => setScopeDropdownOpen(false)} />
                <div
                  className="absolute left-0 mt-1 w-52 rounded-lg shadow-lg z-50 py-1"
                  style={{ backgroundColor: 'var(--bg-raised)', border: '1px solid var(--border-default)' }}
                >
                  <button
                    onClick={() => { setSelectedConnectionId(null); setScopeDropdownOpen(false); }}
                    className="w-full text-left px-3 py-2 text-xs transition-colors flex items-center gap-2"
                    style={{
                      color: selectedConnectionId === null ? 'var(--accent-primary)' : 'var(--text-secondary)',
                      fontWeight: selectedConnectionId === null ? 600 : 400,
                    }}
                    onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--bg-hover)')}
                    onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}
                  >
                    All Connections
                  </button>
                  {connections.map(c => {
                    const dotColor = CLOUD_BRAND_DOT[c.cloud] || CLOUD_BRAND.azure;
                    return (
                      <button
                        key={c.id}
                        onClick={() => { setSelectedConnectionId(c.id); setScopeDropdownOpen(false); }}
                        className="w-full text-left px-3 py-2 text-xs transition-colors flex items-center gap-2"
                        style={{
                          color: selectedConnectionId === c.id ? 'var(--accent-primary)' : 'var(--text-secondary)',
                          fontWeight: selectedConnectionId === c.id ? 600 : 400,
                        }}
                        onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--bg-hover)')}
                        onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}
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

      {/* Omni-Search */}
      <div className="flex-1 flex justify-center max-w-md mx-auto">
        <button
          onClick={onSearchOpen}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm w-full transition-colors"
          style={{
            backgroundColor: 'var(--bg-raised)',
            color: 'var(--text-muted)',
            border: '1px solid var(--border-default)',
          }}
        >
          <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <span className="text-xs flex-1 text-left">Search identities, resources, policies...</span>
          <kbd
            className="text-[10px] px-1.5 py-0.5 rounded font-mono"
            style={{ backgroundColor: 'var(--bg-elevated)', color: 'var(--text-muted)', border: '1px solid var(--border-default)' }}
          >
            {isMac ? '\u2318' : 'Ctrl+'}K
          </kbd>
        </button>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-1 flex-shrink-0">
        {/* Intelligence / Copilot button */}
        {onCopilotOpen && (
          <button
            onClick={onCopilotOpen}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg transition-colors"
            style={{
              color: 'var(--accent-indigo)',
              backgroundColor: 'var(--tint-indigo)',
              border: '1px solid var(--border-indigo)',
            }}
            title="Intelligence"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
            <span className="text-xs font-medium hidden lg:inline">Intelligence</span>
          </button>
        )}

        {/* Notification bell */}
        <button
          onClick={() => navigate('/notifications')}
          className="p-2 rounded-lg transition-colors relative"
          style={{
            color: isActive('/notifications') ? 'var(--accent-primary)' : 'var(--text-tertiary)',
            backgroundColor: isActive('/notifications') ? 'var(--tint-blue)' : 'transparent',
          }}
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

        {/* Organization Switcher (superadmin only) */}
        {isSuperAdmin && (
          <div className="relative">
            <button
              onClick={() => setOrgDropdownOpen(!orgDropdownOpen)}
              className="flex items-center gap-1 px-2 py-1.5 rounded-lg text-xs font-medium transition-colors"
              style={{
                backgroundColor: 'var(--tint-purple)',
                color: 'var(--accent-purple)',
                border: '1px solid var(--border-purple)',
              }}
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
              </svg>
              <span className="hidden md:inline">{activeOrgName || 'All Clients'}</span>
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            {orgDropdownOpen && (
              <>
                <div className="fixed inset-0 z-40" onClick={() => setOrgDropdownOpen(false)} />
                <div
                  className="absolute right-0 mt-1 w-52 rounded-lg shadow-lg z-50 py-1"
                  style={{ backgroundColor: 'var(--bg-raised)', border: '1px solid var(--border-default)' }}
                >
                  <button
                    onClick={() => { switchOrganization(null); setOrgDropdownOpen(false); }}
                    className="w-full text-left px-3 py-2 text-xs transition-colors"
                    style={{
                      color: !activeOrgId ? 'var(--accent-purple)' : 'var(--text-secondary)',
                      fontWeight: !activeOrgId ? 600 : 400,
                    }}
                    onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--bg-hover)')}
                    onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}
                  >
                    All Clients (no filter)
                  </button>
                  {orgsList.map(t => (
                    <button
                      key={t.id}
                      onClick={() => { switchOrganization(t.id, t.name); setOrgDropdownOpen(false); }}
                      className="w-full text-left px-3 py-2 text-xs transition-colors"
                      style={{
                        color: activeOrgId === t.id ? 'var(--accent-purple)' : 'var(--text-secondary)',
                        fontWeight: activeOrgId === t.id ? 600 : 400,
                      }}
                      onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--bg-hover)')}
                      onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}
                    >
                      {t.name}
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        )}

        {/* User Avatar & Menu */}
        {user && (
          <div className="relative" ref={userRef}>
            <button
              onClick={() => setUserMenuOpen(!userMenuOpen)}
              className="flex items-center gap-2 ml-1 pl-2 border-l py-1 rounded-r-lg transition-colors"
              style={{ borderColor: 'var(--border-subtle)' }}
            >
              {/* Avatar circle */}
              <div
                className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-semibold"
                style={{ backgroundColor: 'var(--accent-primary-bg)', color: 'var(--accent-primary)' }}
              >
                {(user.display_name || 'U').charAt(0).toUpperCase()}
              </div>
              {/* Name (hidden on small screens) */}
              <span className="text-xs hidden md:block" style={{ color: 'var(--text-secondary)' }}>
                {user.display_name}
              </span>
              <svg className="w-3 h-3" style={{ color: 'var(--text-muted)' }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>

            {userMenuOpen && (
              <>
                <div className="fixed inset-0 z-40" onClick={() => setUserMenuOpen(false)} />
                <div
                  className="absolute right-0 mt-1 w-48 rounded-lg shadow-lg z-50 py-1"
                  style={{ backgroundColor: 'var(--bg-raised)', border: '1px solid var(--border-default)' }}
                >
                  <div className="px-3 py-2 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
                    <p className="text-xs font-medium" style={{ color: 'var(--text-primary)' }}>{user.display_name}</p>
                    <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-muted)' }}>
                      {user.role?.toUpperCase()}
                    </p>
                  </div>
                  <button
                    onClick={() => { setUserMenuOpen(false); navigate('/settings/general'); }}
                    className="w-full text-left px-3 py-2 text-xs transition-colors"
                    style={{ color: 'var(--text-secondary)' }}
                    onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--bg-hover)')}
                    onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}
                  >
                    Settings
                  </button>
                  <button
                    onClick={() => { logout(); navigate('/login'); setUserMenuOpen(false); }}
                    className="w-full text-left px-3 py-2 text-xs transition-colors"
                    style={{ color: 'var(--accent-danger)' }}
                    onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--bg-hover)')}
                    onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}
                  >
                    Sign out
                  </button>
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </header>
    </>
  );
};

export default TopBar;
