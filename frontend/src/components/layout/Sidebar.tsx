import React, { useState, useMemo } from 'react';
import { Link, useLocation } from 'react-router-dom';

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
  matchExact?: boolean;
}

interface NavSubGroup {
  label: string;
  icon: React.ReactNode;
  items: (NavItem | NavSubGroup)[];
  defaultOpen?: boolean;
  brandColor?: string;
  navigateTo?: string;
}

function isSubGroup(item: NavItem | NavSubGroup): item is NavSubGroup {
  return 'items' in item;
}

interface NavGroup {
  label: string;
  items: (NavItem | NavSubGroup)[];
  adminOnly?: boolean;
  superadminOnly?: boolean;
  extra?: React.ReactNode;
}

interface SidebarProps {
  isAdmin: boolean;
  isSuperAdmin: boolean;
  locked?: boolean;
  canManageConnections?: boolean;
}

// ── Nav icons ─────────────────────────────────────────────────────
const riskPostureIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" /></svg>;
const riskMonitorIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>;
const remediationIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z" /></svg>;
const inventoryIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" /></svg>;
const nonHumanIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>;
const guestIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" /></svg>;
const attackSurfaceIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z" /></svg>;
const governanceIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>;
const roleOptIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v3m0 0v3m0-3h3m-3 0H7" /></svg>;
const accessReviewIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" /></svg>;
const secretsIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg>;
const storageIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" /></svg>;
const complianceIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>;
const evidenceIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>;
const driftIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" /></svg>;
const activityIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>;
const reportsIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>;
const settingsIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" /></svg>;
const billingIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" /></svg>;
const sourcesIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 00-9.78 2.096A4.001 4.001 0 003 15z" /></svg>;
const scoringIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" /></svg>;
const policyIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>;
const integrationIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg>;
const securityIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>;
const execReportIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>;
const auditReportIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" /></svg>;
const scheduledIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>;

const Sidebar: React.FC<SidebarProps> = ({ isAdmin, isSuperAdmin, locked }) => {
  const location = useLocation();
  const [openSubGroups, setOpenSubGroups] = useState<Record<string, boolean>>({});

  const navGroups: NavGroup[] = useMemo(() => {
    const groups: NavGroup[] = [
      {
        label: 'Overview',
        items: [
          { to: '/', label: 'Risk Posture', matchExact: true, icon: riskPostureIcon },
          { to: '/dashboard', label: 'Risk Monitoring', icon: riskMonitorIcon },
        ],
      },
      {
        label: 'Remediation',
        items: [
          { to: '/remediation', label: 'Remediation Center', icon: remediationIcon },
        ],
      },
      {
        label: 'Identity Exposure',
        items: [
          { to: '/identities', label: 'Identity Inventory', icon: inventoryIcon },
          { to: '/workload-identities', label: 'Non-Human Identities', icon: nonHumanIcon },
          { to: '/identities?identity_category=guest', label: 'External & Guest', icon: guestIcon },
          { to: '/data-security', label: 'Identity Attack Surface', icon: attackSurfaceIcon },
        ],
      },
      {
        label: 'Governance & Control',
        items: [
          { to: '/service-accounts', label: 'Governance Coverage', icon: governanceIcon },
          { to: '/role-mining', label: 'Role Optimization', icon: roleOptIcon },
          { to: '/access-reviews', label: 'Access Reviews', icon: accessReviewIcon },
        ],
      },
      {
        label: 'Data & Secrets',
        items: [
          { to: '/resources?resource_type=key_vault', label: 'Secrets & Key Mgmt', icon: secretsIcon },
          { to: '/resources?resource_type=storage_account', label: 'Storage & Data Exposure', icon: storageIcon },
        ],
      },
      {
        label: 'Compliance',
        items: [
          { to: '/compliance', label: 'Frameworks & Controls', icon: complianceIcon },
          { to: '/exports', label: 'Evidence Center', icon: evidenceIcon },
        ],
      },
      {
        label: 'Operations',
        items: [
          { to: '/drift', label: 'Drift & Changes', icon: driftIcon },
          { to: '/activity', label: 'Activity Log', icon: activityIcon },
        ],
      },
      {
        label: 'Reporting',
        items: [
          { to: '/reports?type=executive', label: 'Executive Reports', icon: execReportIcon },
          { to: '/reports?type=audit', label: 'Auditor Reports', icon: auditReportIcon },
          { to: '/reports?type=scheduled', label: 'Scheduled Reports', icon: scheduledIcon },
        ],
      },
      {
        label: 'Administration',
        adminOnly: true,
        items: [
          { to: '/settings/general', label: 'Organization', icon: settingsIcon },
          { to: '/settings/connections', label: 'Identity Sources', icon: sourcesIcon },
          { to: '/integration-guide', label: 'Integration Guide', icon: sourcesIcon },
          { to: '/settings/scoring', label: 'Risk Scoring', icon: scoringIcon },
          { to: '/settings/governance', label: 'Governance Policies', icon: policyIcon },
          { to: '/settings/integrations', label: 'Integrations', icon: integrationIcon },
          { to: '/settings/security', label: 'Security & SSO', icon: securityIcon },
          { to: '/subscriptions', label: 'Billing', icon: billingIcon },
        ],
      },
    ];
    return groups;
  }, []);

  const toggleSubGroup = (key: string) => {
    setOpenSubGroups(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const isActive = (to: string, exact?: boolean) => {
    const [path, query] = to.split('?');
    if (query) {
      return location.pathname === path && location.search === '?' + query;
    }
    if (exact) return location.pathname === path && !location.search;
    return location.pathname === path || location.pathname.startsWith(path + '/');
  };

  const renderNavItem = (item: NavItem, depth: number = 0, brandColor?: string) => {
    const isSettings = item.to.startsWith('/settings');
    const active = isSettings ? location.pathname.startsWith('/settings') && location.pathname === item.to.split('?')[0] : isActive(item.to, item.matchExact);
    const isLocked = locked && !isSettings;
    const paddingLeft = depth === 0 ? 'px-3' : depth === 1 ? 'pl-8 pr-3' : depth === 2 ? 'pl-12 pr-3' : 'pl-16 pr-3';
    const activeStyle: React.CSSProperties = active
      ? { borderLeft: `3px solid ${brandColor || 'var(--accent-primary)'}`, backgroundColor: 'var(--nav-item-active-bg)' }
      : {};
    return (
      <li key={item.to}>
        <Link
          to={isLocked ? '#' : item.to}
          onClick={isLocked ? (e: React.MouseEvent) => e.preventDefault() : undefined}
          style={activeStyle}
          className={`flex items-center gap-2.5 ${paddingLeft} py-1.5 rounded-md text-sm transition-colors ${
            isLocked ? 'opacity-40 pointer-events-none' :
            active
              ? 'text-blue-700 dark:text-blue-300 font-medium'
              : 'text-gray-600 dark:text-slate-300 hover:bg-gray-50 dark:hover:bg-slate-800 hover:text-gray-900 dark:hover:text-white'
          }`}
        >
          <span className={active ? 'text-blue-600 dark:text-blue-400' : 'text-gray-400 dark:text-slate-500'}>
            {item.icon}
          </span>
          {item.label}
          {locked && isSettings && (
            <span className="ml-auto w-1.5 h-1.5 rounded-full bg-amber-500" />
          )}
        </Link>
      </li>
    );
  };

  const renderSubGroup = (subGroup: NavSubGroup, depth: number = 0, parentKey: string = '', parentBrandColor?: string) => {
    const groupKey = parentKey ? `${parentKey} > ${subGroup.label}` : subGroup.label;
    const isOpen = openSubGroups[groupKey] ?? subGroup.defaultOpen ?? false;
    const brandColor = subGroup.brandColor || parentBrandColor;
    const paddingLeft = depth === 0 ? 'px-3' : depth === 1 ? 'pl-8 pr-3' : 'pl-12 pr-3';

    return (
      <li key={groupKey}>
        <button
          onClick={() => toggleSubGroup(groupKey)}
          className={`w-full flex items-center gap-2.5 ${paddingLeft} py-1.5 rounded-md text-sm transition-colors ${
            depth === 0
              ? 'text-gray-700 dark:text-slate-200 hover:bg-gray-50 dark:hover:bg-slate-800 font-medium'
              : 'text-gray-600 dark:text-slate-300 hover:bg-gray-50 dark:hover:bg-slate-800 hover:text-gray-900 dark:hover:text-white'
          }`}
        >
          <span className="text-gray-400 dark:text-slate-500">
            {subGroup.icon}
          </span>
          {subGroup.label}
          <svg
            className={`w-3.5 h-3.5 ml-auto text-gray-400 dark:text-slate-500 transition-transform duration-200 ${isOpen ? 'rotate-90' : ''}`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
        </button>
        {isOpen && subGroup.items.length > 0 && (
          <ul className="mt-0.5 space-y-0.5">
            {subGroup.items.map(item =>
              isSubGroup(item)
                ? renderSubGroup(item, depth + 1, groupKey, brandColor)
                : renderNavItem(item, depth + 1, brandColor)
            )}
          </ul>
        )}
      </li>
    );
  };

  return (
    <aside className="fixed left-0 top-14 bottom-0 w-60 border-r border-gray-200 overflow-y-auto z-30" style={{ backgroundColor: 'var(--bg-sidebar)' }}>
      <nav className="py-4 px-3 space-y-5">
        {navGroups.map(group => {
          if (group.adminOnly && !isAdmin) return null;
          if (group.superadminOnly && !isSuperAdmin) return null;

          return (
            <div key={group.label}>
              <h3 className="px-3 mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-gray-400 dark:text-slate-500">
                {group.label}
              </h3>
              <ul className="space-y-0.5">
                {group.items.map(item =>
                  isSubGroup(item) ? renderSubGroup(item) : renderNavItem(item)
                )}
              </ul>
            </div>
          );
        })}
      </nav>
    </aside>
  );
};

export default Sidebar;
