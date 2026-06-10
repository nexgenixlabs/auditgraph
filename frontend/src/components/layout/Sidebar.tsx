import React, { useState, useMemo } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';


interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
  matchExact?: boolean;
  // Optional: additional path prefixes that should keep this nav item
  // highlighted as active. Used when one sidebar entry hosts a tabbed page
  // that switches between sibling routes (e.g. /reports + /exports).
  matchPrefixes?: string[];
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
  color?: string;
}

interface SidebarProps {
  isAdmin: boolean;
  isSuperAdmin: boolean;
  locked?: boolean;
  canManageConnections?: boolean;
}

// ── Nav icons (Lucide-style, 18px) ─────────────────────────────────

const icon = (d: string) => (
  <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" strokeWidth={1.8} viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
    <path d={d} />
  </svg>
);

// Command Center
const dashboardIcon = icon('M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6');
const monitorIcon = icon('M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z');

// Identity
const identityIcon = icon('M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z');
const nonHumanIcon = icon('M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z');
const guestIcon = icon('M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z');
const attackIcon = icon('M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z');

// Access Explainability
const accessGraphIcon = icon('M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1');
const effectiveAccessIcon = icon('M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z');
const sensitiveDataIcon = icon('M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4');

// Governance
const governanceIcon = icon('M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z');
const roleOptIcon = icon('M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v3m0 0v3m0-3h3m-3 0H7');
const accessReviewIcon = icon('M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4');

// Remediation
const remediationIcon = icon('M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z');
const findingsIcon = icon('M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z');

// Data Security
const secretsIcon = icon('M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z');
const storageIcon = icon('M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4');

// Compliance
const complianceIcon = icon('M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z');

// Operations
const driftIcon = icon('M13 7h8m0 0v8m0-8l-8 8-4-4-6 6');
const activityIcon = icon('M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z');
const reportsIcon = icon('M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z');

// Settings
const settingsIcon = icon('M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4');

// AI Agents (Lucide "Bot" — distinct robot head shape)
const agentBotIcon = (
  <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" strokeWidth={1.8} viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 8V4H8" />
    <rect x="4" y="8" width="16" height="12" rx="2" />
    <path d="M2 14h2" />
    <path d="M20 14h2" />
    <path d="M15 13v2" />
    <path d="M9 13v2" />
  </svg>
);

// Connectors
const connectorsIcon = icon('M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01');

// Billing
const billingIcon = icon('M17 9V7a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2m2 4h10a2 2 0 002-2v-6a2 2 0 00-2-2H9a2 2 0 00-2 2v6a2 2 0 002 2zm7-5a2 2 0 11-4 0 2 2 0 014 0z');

// Feature gate: set to true to reveal pages that require data to be populated
const SHOW_ADVANCED_FEATURES = false;

// ── Sidebar Component ─────────────────────────────────────────────

const Sidebar: React.FC<SidebarProps> = ({ isAdmin, isSuperAdmin, locked }) => {
  const location = useLocation();
  const { isDemo } = useAuth();
  const [collapsed, setCollapsed] = useState(false);
  const [openSubGroups, setOpenSubGroups] = useState<Record<string, boolean>>({});
  const navGroups: NavGroup[] = useMemo(() => {
    const groups: NavGroup[] = [
      // ============================================================
      // 2026-06-05 IA pivot v3 (locked after peer review v4):
      //   Brand:    "Identity Security Graph"
      //   Headline: "See Every Identity. Understand Every Risk."
      //   Sub:      "Identity Security for the AI Era"
      //   Model:    AI is a SUBTYPE of NHI, not a peer.
      // 9-section navigation:
      //   1. Command Center
      //   2. Identity Security        (Human + NHI + AI via filter)
      //   3. Graph Intelligence       (was "Identity & Access" + Multi-Hop)
      //   4. Attack Surface
      //   5. AI Security              (AI WORKLOAD only — no identities)
      //   6. Argus
      //   7. Governance & Assurance   (merged Board + Observability + Evidence)
      //   8. Platform
      //   9. Billing
      // All URLs preserved — this is a label/group change only.
      // ============================================================
      {
        label: 'Command Center',
        color: '#2563eb',
        items: [
          { to: '/', label: 'Executive Posture', matchExact: true, icon: dashboardIcon },
          { to: '/board-scorecard', label: 'Board Scorecard', icon: identityIcon },
          { to: '/command-center', label: 'Live Operations', icon: monitorIcon },
          { to: '/dashboard', label: 'Risk Monitoring', icon: monitorIcon },
          { to: '/drift-analysis', label: 'Drift Analysis', icon: driftIcon },
          { to: '/security-findings', label: 'Findings', icon: findingsIcon },
          { to: '/remediation', label: 'Remediation Plan', icon: remediationIcon },
          { to: '/remediation-queue', label: 'Change Control Center', icon: remediationIcon },
        ],
      },
      {
        // AG-PHASE1-IA (2026-06-09): peer-review pivot to "Identity
        // Security Graph platform for Human, Non-Human, and AI
        // Identities". Identity is now the spine with three first-class
        // identity-type subsections, each with its own depth. Same
        // routes — labels and grouping change. AI demoted from peer
        // category to NHI subtype, matching the buyer mental model
        // ("show me all non-humans" is the CISO's first question).
        label: 'Identity',
        color: '#8b5cf6',
        items: [
          {
            label: 'Human',
            icon: identityIcon,
            brandColor: '#3b82f6',
            navigateTo: '/human/inventory',
            items: [
              { to: '/human/inventory',                    label: 'Inventory',         icon: identityIcon },
              { to: '/human/access',                       label: 'Access',            icon: effectiveAccessIcon },
              { to: '/identity-trust?type=human',          label: 'Trust',             icon: roleOptIcon },
              { to: '/lifecycle?type=human',               label: 'Lifecycle',         icon: identityIcon },
              { to: '/human/governance',                   label: 'Governance',        icon: identityIcon },
              { to: '/identity-security/pim?type=human',   label: 'PIM',               icon: roleOptIcon },
              { to: '/identity-security/entra-role-activity', label: 'Role Activity',  icon: roleOptIcon },
              { to: '/attack-paths?source_type=human',     label: 'Attack Paths',      icon: findingsIcon },
            ],
          },
          {
            label: 'Non-Human',
            icon: nonHumanIcon,
            brandColor: '#f97316',
            navigateTo: '/nhi',
            items: [
              { to: '/nhi',                                label: 'Inventory',         icon: nonHumanIcon },
              { to: '/nhi/access',                         label: 'Access',            icon: effectiveAccessIcon },
              { to: '/nhi/trust',                          label: 'Trust',             icon: roleOptIcon },
              { to: '/nhi/lifecycle',                      label: 'Lifecycle',         icon: identityIcon },
              { to: '/nhi/governance',                     label: 'Governance',        icon: identityIcon },
              { to: '/nhi/secrets',                        label: 'Secrets',           icon: secretsIcon },
              { to: '/nhi/ownership',                      label: 'Ownership',         icon: identityIcon },
              { to: '/nhi/attack-paths',                   label: 'Attack Paths',      icon: findingsIcon },
            ],
          },
          {
            label: 'AI Identity',
            icon: agentBotIcon,
            brandColor: '#a78bfa',
            navigateTo: '/ai-inventory',
            items: [
              { to: '/ai-inventory',                       label: 'Inventory',         icon: agentBotIcon },
              { to: '/ai-access',                          label: 'Access',            icon: effectiveAccessIcon },
              { to: '/identity-trust?type=ai',             label: 'Trust',             icon: roleOptIcon },
              { to: '/lifecycle?type=ai',                  label: 'Lifecycle',         icon: agentBotIcon },
              { to: '/ai-governance',                      label: 'Governance',        icon: agentBotIcon },
              { to: '/attack-paths?source_type=ai',        label: 'Attack Paths',      icon: findingsIcon },
            ],
          },
          // Universal / fallback — all identities together
          { to: '/identity-explorer', label: 'All Identities', icon: identityIcon },
          { to: '/ownership',         label: 'Ownership Center', icon: identityIcon },
        ],
      },
      {
        // AG-PHASE1-GRAPH (2026-06-09): Graph Intelligence becomes the
        // moat surface. Multi-Hop XGRAPH renamed to "Identity Exposure
        // Graph" so it stops reading AI-only (it isn't — the engine
        // handles any identity type's transitive reach).
        label: 'Graph Intelligence',
        color: '#0891b2',
        items: [
          // AG-PHASE6 (2026-06-09): Unified Identity Graph at the top
          // — this is the patent moat the peer reviewer named gold.
          { to: '/unified-graph', label: 'Unified Identity Graph', icon: identityIcon },
          { to: '/identity-graph', label: 'Identity Graph', icon: identityIcon },
          { to: '/access-graph',   label: 'Access Graph',   icon: accessGraphIcon },
          // Renamed from "Multi-Hop XGRAPH". Same route preserved for
          // back-compat deep links. The engine is identity-type-agnostic
          // — humans + NHIs + AI all chain in one graph.
          { to: '/ai-attack-paths/multi-hop', label: 'Identity Exposure Graph', icon: roleOptIcon },
          ...(SHOW_ADVANCED_FEATURES ? [{ to: '/effective-access', label: 'Effective Access Explorer', icon: effectiveAccessIcon }] : []),
          ...(SHOW_ADVANCED_FEATURES ? [{ to: '/sensitive-access', label: 'Sensitive Data Access', icon: sensitiveDataIcon }] : []),
          { to: '/role-mining', label: 'Role Optimization', icon: roleOptIcon },
        ],
      },
      {
        // AG-PHASE1-EXPOSURE (2026-06-09): renamed "Attack Surface" to
        // "Exposure Management" — matches the CISO vocabulary the peer
        // reviewer flagged. Executives buy exposure management, not
        // attack surface tooling.
        label: 'Exposure Management',
        color: '#dc2626',
        items: [
          { to: '/attack-paths',                label: 'Attack Paths',     icon: findingsIcon },
          { to: '/blast-radius',                label: 'Blast Radius',     icon: attackIcon },
          { to: '/ai-access/data-reachability', label: 'Data Reachability', icon: effectiveAccessIcon },
          { to: '/attack-simulator',            label: 'Attack Simulator',  icon: attackIcon },
        ],
      },
      {
        // AG-IA-P3 (2026-06-10): Renamed to AI Workload Security to be
        // honest — these surfaces are AI-runtime-specific (model registry,
        // AI threat scenarios, AI supply chain). Issue #21 from founder
        // review: prior label "Workload Security" implied cross-cutting
        // but the contents are AI-only.
        label: 'AI Workload Security',
        color: '#a78bfa',
        items: [
          { to: '/ai-runtime',                    label: 'Runtime',           icon: agentBotIcon },
          { to: '/ai-runtime/model-registry',     label: 'Model Registry',    icon: agentBotIcon },
          { to: '/ai-runtime/supply-chain',       label: 'Supply Chain',      icon: agentBotIcon },
          { to: '/ai-runtime/threat-connectors',  label: 'Threat Connectors', icon: agentBotIcon },
          { to: '/ai-findings',                   label: 'Findings',          icon: roleOptIcon },
          { to: '/ai-risk',                       label: 'AI Threat Scenarios', icon: roleOptIcon },
        ],
      },
      {
        // Argus — cross-cutting analyst (humans + NHIs + AI + workload)
        label: 'Argus',
        color: '#a78bfa',
        items: [
          { to: '/argus', label: 'Argus Analyst', icon: agentBotIcon },
        ],
      },
      {
        // AG-PHASE1-GOVERNANCE (2026-06-09): cross-identity-type
        // governance lives here. Per-type Governance/PIM links remain
        // available inside their Identity sub-sections.
        label: 'Governance & Assurance',
        color: '#ca8a04',
        items: [
          { to: '/compliance-posture', label: 'Compliance Posture', icon: complianceIcon },
          { to: '/compliance', label: 'Compliance Evidence', icon: complianceIcon },
          { to: '/access-reviews', label: 'Access Reviews', icon: accessReviewIcon },
          { to: '/ai-runtime/activity', label: 'AI Activity Timeline', icon: activityIcon },
          // AG-WK7.A: Peer Benchmarking — network-effect moat
          { to: '/peer-benchmarking', label: 'Peer Benchmarking', icon: roleOptIcon },
          { to: '/reports', label: 'Reports & Exports', icon: reportsIcon, matchPrefixes: ['/reports', '/exports'] },
        ],
      },
      {
        label: 'Platform',
        color: '#64748b',
        items: [
          ...(isAdmin ? [{ to: '/settings/connections', label: 'Connectors', icon: connectorsIcon }] : []),
          ...(isAdmin ? [{ to: '/organization/users', label: 'Team Members', icon: identityIcon }] : []),
          { to: '/activity', label: 'Audit Log', icon: activityIcon },
          ...(isAdmin ? [{ to: '/settings/general', label: 'Organization Settings', icon: settingsIcon }] : []),
        ],
      },
      ...(isAdmin ? [{
        label: 'Billing',
        color: '#059669',
        items: [
          { to: '/billing', label: 'Billing Overview', icon: billingIcon },
          { to: '/subscriptions', label: 'Subscriptions', icon: connectorsIcon },
        ],
      }] : []),
    ];
    return groups;
  }, [isAdmin]);

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

  const w = collapsed ? 'w-14' : 'w-[220px]';

  const renderNavItem = (item: NavItem, depth: number = 0, sectionColor?: string) => {
    const isSettings = item.to.startsWith('/settings');
    const prefixActive = !!item.matchPrefixes?.some(p => location.pathname === p || location.pathname.startsWith(p + '/'));
    const active = isSettings
      ? location.pathname.startsWith('/settings') && location.pathname === item.to.split('?')[0]
      : isActive(item.to, item.matchExact) || prefixActive;
    const isLocked = locked && !isSettings;

    return (
      <li key={item.to}>
        <Link
          to={isLocked ? '#' : item.to}
          onClick={isLocked ? (e: React.MouseEvent) => e.preventDefault() : undefined}
          className={`flex items-center gap-2.5 px-3 py-[7px] rounded-lg text-[13px] transition-all duration-100 ${
            isLocked ? 'opacity-30 pointer-events-none' :
            active
              ? 'font-medium'
              : 'hover:bg-[var(--bg-elevated)]'
          }`}
          style={active ? {
            backgroundColor: 'var(--nav-item-active-bg)',
            color: sectionColor || 'var(--accent-primary)',
            borderLeft: collapsed ? 'none' : `2px solid ${sectionColor || 'var(--accent-primary)'}`,
            paddingLeft: collapsed ? '12px' : '10px',
          } : {
            color: 'var(--nav-item)',
          }}
          title={collapsed ? item.label : undefined}
        >
          <span className="flex-shrink-0" style={active ? { color: sectionColor || 'var(--accent-primary)' } : { color: 'var(--text-tertiary)' }}>
            {item.icon}
          </span>
          {!collapsed && <span className="truncate">{item.label}</span>}
          {locked && isSettings && !collapsed && (
            <span className="ml-auto w-1.5 h-1.5 rounded-full bg-amber-500 flex-shrink-0" />
          )}
        </Link>
      </li>
    );
  };

  const renderSubGroup = (subGroup: NavSubGroup, depth: number = 0, parentKey: string = '', sectionColor?: string) => {
    const groupKey = parentKey ? `${parentKey} > ${subGroup.label}` : subGroup.label;
    const isOpen = openSubGroups[groupKey] ?? subGroup.defaultOpen ?? false;

    return (
      <li key={groupKey}>
        <button
          onClick={() => toggleSubGroup(groupKey)}
          className="w-full flex items-center gap-2.5 px-3 py-[7px] rounded-lg text-[13px] transition-colors hover:bg-[var(--bg-elevated)]"
          style={{ color: 'var(--text-secondary)' }}
        >
          <span style={{ color: 'var(--text-tertiary)' }}>{subGroup.icon}</span>
          {!collapsed && (
            <>
              <span className="truncate font-medium">{subGroup.label}</span>
              <svg
                className={`w-3 h-3 ml-auto transition-transform duration-150 ${isOpen ? 'rotate-90' : ''}`}
                style={{ color: 'var(--text-muted)' }}
                fill="none" stroke="currentColor" viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
            </>
          )}
        </button>
        {isOpen && !collapsed && subGroup.items.length > 0 && (
          <ul className="mt-0.5 ml-3 space-y-0.5 border-l border-[var(--border-subtle)] pl-2">
            {subGroup.items.map(item =>
              isSubGroup(item)
                ? renderSubGroup(item, depth + 1, groupKey, sectionColor)
                : renderNavItem(item, depth + 1, sectionColor)
            )}
          </ul>
        )}
      </li>
    );
  };

  return (
    <aside
      className={`fixed left-0 bottom-0 ${w} border-r flex flex-col transition-all duration-200 z-30`}
      style={{
        top: 'var(--header-height, 56px)',
        backgroundColor: 'var(--bg-deep)',
        borderColor: 'var(--border-subtle)',
      }}
    >
      {/* Main nav area */}
      <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-4">
        {navGroups.map(group => {
          if (group.adminOnly && !isAdmin) return null;
          if (group.superadminOnly && !isSuperAdmin) return null;

          return (
            <div key={group.label}>
              {!collapsed && (
                <h3
                  className="px-3 mb-1 text-[10px] font-semibold uppercase tracking-[0.08em]"
                  style={{ color: group.color || 'var(--text-muted)' }}
                >
                  {group.label}
                </h3>
              )}
              {collapsed && (
                <div className="w-full flex justify-center mb-1">
                  <div className="w-4 h-px" style={{ backgroundColor: group.color || 'var(--border-default)' }} />
                </div>
              )}
              <ul className="space-y-0.5">
                {group.items.map(item =>
                  isSubGroup(item) ? renderSubGroup(item, 0, '', group.color) : renderNavItem(item, 0, group.color)
                )}
              </ul>
            </div>
          );
        })}
      </nav>

      {/* Bottom section: Demo badge + Collapse toggle */}
      <div className="border-t px-2 py-2 space-y-1" style={{ borderColor: 'var(--border-subtle)' }}>
        {isDemo && !collapsed && (
          <div className="px-3 pb-0.5" style={{ fontSize: 11, color: 'var(--color-text-tertiary, #6b7280)' }}>
            Demo mode &middot; simulated data
          </div>
        )}
        {/* Collapse toggle */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="w-full flex items-center gap-2.5 px-3 py-[7px] rounded-lg text-[13px] transition-colors hover:bg-[var(--bg-elevated)]"
          style={{ color: 'var(--text-muted)' }}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          <svg
            className={`w-[18px] h-[18px] transition-transform duration-200 ${collapsed ? 'rotate-180' : ''}`}
            fill="none" stroke="currentColor" strokeWidth={1.8} viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round"
          >
            <path d="M11 19l-7-7 7-7m8 14l-7-7 7-7" />
          </svg>
          {!collapsed && <span>Collapse</span>}
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
