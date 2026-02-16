import React, { useState, useEffect, useMemo } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';

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

interface CloudProviderConfig {
  enabled: boolean;
  plan: string | null;
}

interface TenantConfig {
  cloud_providers: Record<string, CloudProviderConfig>;
  addons: Record<string, boolean>;
}

// Cloud provider brand colors
const CLOUD_BRAND_COLORS: Record<string, string> = {
  Azure: '#0078D4',
  AWS: '#FF9900',
  GCP: '#4285F4',
};

// Cloud provider icons
const azureIcon = (
  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 00-9.78 2.096A4.001 4.001 0 003 15z" /></svg>
);
const awsIcon = (
  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 00-9.78 2.096A4.001 4.001 0 003 15z" /></svg>
);
const gcpIcon = (
  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 00-9.78 2.096A4.001 4.001 0 003 15z" /></svg>
);

// Static nav icons
const overviewIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" /></svg>;
const dashboardIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z" /></svg>;
const allIdentitiesIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" /></svg>;
const spnIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>;
const appRegIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>;
const humanIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>;
const guestIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" /></svg>;
const managedIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" /></svg>;
const storageIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" /></svg>;
const keyVaultIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg>;
const resourcesIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>;
const addIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" /></svg>;

const Sidebar: React.FC<SidebarProps> = ({ isAdmin, isSuperAdmin, locked, canManageConnections }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const [openSubGroups, setOpenSubGroups] = useState<Record<string, boolean>>({
    'Azure': true,
    'Azure > All Identities': true,
  });
  const [cloudConfig, setCloudConfig] = useState<TenantConfig | null>(null);

  useEffect(() => {
    fetch('/api/tenant/config')
      .then(r => { if (!r.ok) throw new Error(); return r.json(); })
      .then(data => setCloudConfig({
        cloud_providers: data.cloud_providers,
        addons: data.addons,
      }))
      .catch(() => {
        setCloudConfig({
          cloud_providers: {
            azure: { enabled: true, plan: 'pro' },
            aws: { enabled: false, plan: null },
            gcp: { enabled: false, plan: null },
          },
          addons: {},
        });
      });
  }, []);

  const isAzureEnabled = cloudConfig?.cloud_providers?.azure?.enabled ?? true;
  const isAwsEnabled = cloudConfig?.cloud_providers?.aws?.enabled ?? false;
  const isGcpEnabled = cloudConfig?.cloud_providers?.gcp?.enabled ?? false;

  const navGroups: NavGroup[] = useMemo(() => {
    // Build cloud provider nodes
    const cloudItems: (NavItem | NavSubGroup)[] = [];

    if (isAzureEnabled) {
      cloudItems.push({
        label: 'Azure',
        icon: azureIcon,
        defaultOpen: true,
        brandColor: CLOUD_BRAND_COLORS.Azure,
        items: [
          {
            label: 'All Identities',
            icon: allIdentitiesIcon,
            navigateTo: '/identities?cloud=azure',
            defaultOpen: true,
            items: [
              { to: '/spns', label: 'Service Principals', icon: spnIcon },
              { to: '/app-registrations', label: 'App Registrations', icon: appRegIcon },
              { to: '/identities?cloud=azure&identity_category=human_user', label: 'Human Users', icon: humanIcon },
              { to: '/identities?cloud=azure&identity_category=guest', label: 'Guest Users', icon: guestIcon },
              { to: '/identities?cloud=azure&identity_category=managed_identity_user', label: 'Managed Identities', icon: managedIcon },
            ],
          } as NavSubGroup,
          {
            label: 'Resources',
            icon: resourcesIcon,
            defaultOpen: false,
            items: [
              { to: '/resources?resource_type=storage_account', label: 'Storage Accounts', icon: storageIcon },
              { to: '/resources?resource_type=key_vault', label: 'Key Vaults', icon: keyVaultIcon },
            ],
          } as NavSubGroup,
        ],
      });
    }

    if (isAwsEnabled) {
      cloudItems.push({
        label: 'AWS',
        icon: awsIcon,
        defaultOpen: false,
        brandColor: CLOUD_BRAND_COLORS.AWS,
        items: [
          {
            label: 'All Identities',
            icon: allIdentitiesIcon,
            navigateTo: '/identities?cloud=aws',
            defaultOpen: false,
            items: [
              { to: '/identities?cloud=aws', label: 'IAM Users & Roles', icon: humanIcon },
            ],
          } as NavSubGroup,
          {
            label: 'Resources',
            icon: resourcesIcon,
            defaultOpen: false,
            items: [],
          } as NavSubGroup,
        ],
      });
    }

    if (isGcpEnabled) {
      cloudItems.push({
        label: 'GCP',
        icon: gcpIcon,
        defaultOpen: false,
        brandColor: CLOUD_BRAND_COLORS.GCP,
        items: [
          {
            label: 'All Identities',
            icon: allIdentitiesIcon,
            navigateTo: '/identities?cloud=gcp',
            defaultOpen: false,
            items: [
              { to: '/identities?cloud=gcp', label: 'Service Accounts', icon: spnIcon },
            ],
          } as NavSubGroup,
          {
            label: 'Resources',
            icon: resourcesIcon,
            defaultOpen: false,
            items: [],
          } as NavSubGroup,
        ],
      });
    }

    // "Add Cloud Provider" link (admin/security_admin only)
    if (canManageConnections) {
      cloudItems.push({ to: '/settings#cloud-connections', label: '+ Add Cloud Provider', icon: addIcon });
    }

    const groups: NavGroup[] = [
      {
        label: 'Overview',
        items: [
          { to: '/', label: 'Overview', matchExact: true, icon: overviewIcon },
          { to: '/dashboard', label: 'Dashboard', icon: dashboardIcon },
        ],
      },
      {
        label: 'Public Cloud',
        items: cloudItems,
      },
      {
        label: 'Compliance',
        items: [
          { to: '/compliance', label: 'Compliance', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg> },
          { to: '/access-reviews', label: 'Access Reviews', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" /></svg> },
        ],
      },
      {
        label: 'Governance',
        items: [
          { to: '/role-mining', label: 'Role Mining', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v3m0 0v3m0-3h3m-3 0H7" /></svg> },
          { to: '/service-accounts', label: 'Identity Governance', icon: spnIcon },
          { to: '/groups', label: 'Identity Groups', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg> },
          { to: '/identities/compare', label: 'Comparison', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" /></svg> },
        ],
      },
      {
        label: 'Operations',
        items: [
          { to: '/drift', label: 'Drift', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" /></svg> },
          { to: '/activity', label: 'Activity Log', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> },
          { to: '/reports', label: 'Reports', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg> },
          { to: '/exports', label: 'Exports', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg> },
        ],
      },
      {
        label: 'Billing',
        adminOnly: true,
        items: [
          { to: '/subscriptions', label: 'Subscriptions', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" /></svg> },
        ],
      },
      {
        label: 'Administration',
        adminOnly: true,
        items: [
          { to: '/settings', label: 'Settings', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" /></svg> },
        ],
      },
    ];

    return groups;
  }, [isAzureEnabled, isAwsEnabled, isGcpEnabled, canManageConnections]);

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
    const active = isActive(item.to, item.matchExact);
    const isSettings = item.to === '/settings';
    const isLocked = locked && !isSettings;
    const paddingLeft = depth === 0 ? 'px-3' : depth === 1 ? 'pl-8 pr-3' : depth === 2 ? 'pl-12 pr-3' : 'pl-16 pr-3';
    const activeStyle = brandColor && active
      ? { borderLeft: `3px solid ${brandColor}` }
      : undefined;
    return (
      <li key={item.to}>
        <Link
          to={isLocked ? '#' : item.to}
          onClick={isLocked ? (e: React.MouseEvent) => e.preventDefault() : undefined}
          style={activeStyle}
          className={`flex items-center gap-2.5 ${paddingLeft} py-1.5 rounded-md text-sm transition-colors ${
            isLocked ? 'opacity-40 pointer-events-none' :
            active
              ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300 font-medium'
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

    const labelStyle = brandColor && depth === 0
      ? { color: brandColor }
      : undefined;

    const handleClick = () => {
      // If navigateTo is set, navigate AND toggle
      if (subGroup.navigateTo) {
        navigate(subGroup.navigateTo);
        if (!isOpen) {
          setOpenSubGroups(prev => ({ ...prev, [groupKey]: true }));
        } else {
          toggleSubGroup(groupKey);
        }
      } else {
        toggleSubGroup(groupKey);
      }
    };

    return (
      <li key={groupKey}>
        <button
          onClick={handleClick}
          style={labelStyle}
          className={`w-full flex items-center gap-2.5 ${paddingLeft} py-1.5 rounded-md text-sm transition-colors ${
            depth === 0
              ? 'text-gray-700 dark:text-slate-200 hover:bg-gray-50 dark:hover:bg-slate-800 font-medium'
              : 'text-gray-600 dark:text-slate-300 hover:bg-gray-50 dark:hover:bg-slate-800 hover:text-gray-900 dark:hover:text-white'
          }`}
        >
          <span className="text-gray-400 dark:text-slate-500" style={brandColor && depth === 0 ? { color: brandColor } : undefined}>
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
    <aside className="fixed left-0 top-14 bottom-0 w-60 bg-white dark:bg-slate-950 border-r border-gray-200 dark:border-slate-700 overflow-y-auto z-30">
      <nav className="py-4 px-3 space-y-5">
        {navGroups.map(group => {
          if (group.adminOnly && !isAdmin) return null;
          if (group.superadminOnly && !isSuperAdmin) return null;

          return (
            <div key={group.label}>
              <h3 className="px-3 mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-gray-400 dark:text-slate-500">
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
