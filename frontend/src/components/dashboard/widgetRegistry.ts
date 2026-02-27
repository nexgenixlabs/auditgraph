export interface WidgetMeta {
  id: string;
  label: string;
  description: string;
  group: 'stats' | 'charts' | 'monitoring' | 'compliance';
  defaultVisible: boolean;
  colSpan: 1 | 2 | 3;
}

export const WIDGET_REGISTRY: WidgetMeta[] = [
  { id: 'stats_cards',          label: 'Stats Cards',          description: 'Total identities, critical, high, snapshots',         group: 'stats',      defaultVisible: true,  colSpan: 3 },
  { id: 'risk_trend_chart',     label: 'Risk Trend Chart',     description: 'Historical risk level trends across snapshots',        group: 'charts',     defaultVisible: true,  colSpan: 2 },
  { id: 'role_usage_chart',     label: 'Role Usage Chart',     description: 'Active vs inactive role assignments',                  group: 'charts',     defaultVisible: true,  colSpan: 1 },
  { id: 'risk_velocity_chart',  label: 'Risk Escalation Tracker', description: 'Risk level transitions between snapshots',           group: 'charts',     defaultVisible: true,  colSpan: 3 },
  { id: 'cloud_context_banner', label: 'Cloud Context',        description: 'Monitored cloud accounts and subscriptions',           group: 'monitoring', defaultVisible: true,  colSpan: 3 },
  { id: 'posture_score',        label: 'Posture Score',        description: 'Overall security posture grade',                       group: 'monitoring', defaultVisible: true,  colSpan: 1 },
  { id: 'credential_health',    label: 'Credential Health',    description: 'Expired, expiring, and healthy credentials',           group: 'monitoring', defaultVisible: true,  colSpan: 1 },
  { id: 'quick_actions',        label: 'Quick Actions',        description: 'One-click remediation shortcuts',                      group: 'monitoring', defaultVisible: true,  colSpan: 1 },
  { id: 'recent_changes',       label: 'Recent Changes',       description: 'New identities, removals, permission drift',           group: 'monitoring', defaultVisible: true,  colSpan: 1 },
  { id: 'anomaly_alerts',       label: 'Anomaly Alerts',       description: 'Detected unusual identity behavior',                   group: 'monitoring', defaultVisible: true,  colSpan: 1 },
  { id: 'soar_activity',        label: 'SOAR Activity',        description: 'Automated playbook execution history',                 group: 'monitoring', defaultVisible: true,  colSpan: 1 },
  { id: 'risk_heat_map',        label: 'Risk Heat Map',        description: 'Category-by-risk-level heat matrix',                   group: 'charts',     defaultVisible: true,  colSpan: 2 },
  { id: 'risk_donut_chart',     label: 'Risk Donut Chart',     description: 'Risk distribution donut with drill-down',              group: 'charts',     defaultVisible: true,  colSpan: 1 },
  { id: 'compliance_scorecard', label: 'Compliance Scorecard', description: 'Framework compliance scores',                          group: 'compliance', defaultVisible: true,  colSpan: 2 },
  { id: 'conditional_access',   label: 'Conditional Access',   description: 'Azure conditional access policy coverage',             group: 'compliance', defaultVisible: true,  colSpan: 1 },
  { id: 'remediation_progress', label: 'Remediation Progress', description: 'Open/completed remediation actions',                   group: 'compliance', defaultVisible: true,  colSpan: 1 },
  { id: 'sa_governance',        label: 'SA Governance',        description: 'Service account governance compliance status',          group: 'monitoring', defaultVisible: true,  colSpan: 1 },
  { id: 'platform_health',      label: 'Platform Health',      description: 'API health, uptime, and database latency',              group: 'monitoring', defaultVisible: true,  colSpan: 1 },
  { id: 'expiry_tracker',       label: 'Expiry Tracker',       description: 'Key Vault secrets, keys & certificates expiry status',  group: 'monitoring', defaultVisible: true,  colSpan: 1 },
  { id: 'resource_overview',    label: 'Resource Overview',    description: 'Azure Storage & Key Vault counts, risk, and compliance', group: 'monitoring', defaultVisible: true,  colSpan: 1 },
];

export interface WidgetPref {
  id: string;
  visible: boolean;
}

export const DEFAULT_WIDGET_ORDER: WidgetPref[] =
  WIDGET_REGISTRY.map(w => ({ id: w.id, visible: w.defaultVisible }));

export function getWidgetMeta(id: string): WidgetMeta | undefined {
  return WIDGET_REGISTRY.find(w => w.id === id);
}

/**
 * Merge saved preferences with the registry.
 * - Preserves saved order and visibility for known widgets.
 * - Appends new widgets (added after user last saved) at the end with defaultVisible.
 * - Removes saved widgets that no longer exist in the registry.
 */
export function mergePreferences(
  saved: WidgetPref[] | null | undefined,
): WidgetPref[] {
  if (!saved || !Array.isArray(saved) || saved.length === 0) {
    return DEFAULT_WIDGET_ORDER;
  }

  const knownIds = new Set(WIDGET_REGISTRY.map(w => w.id));
  const seenIds = new Set<string>();

  const merged: WidgetPref[] = saved
    .filter(s => {
      if (!knownIds.has(s.id)) return false;
      seenIds.add(s.id);
      return true;
    })
    .map(s => ({ id: s.id, visible: !!s.visible }));

  // Append new widgets not in saved prefs
  for (const w of WIDGET_REGISTRY) {
    if (!seenIds.has(w.id)) {
      merged.push({ id: w.id, visible: w.defaultVisible });
    }
  }

  return merged;
}

export const WIDGET_GROUPS: Array<{ key: string; label: string }> = [
  { key: 'stats', label: 'Stats' },
  { key: 'charts', label: 'Charts' },
  { key: 'monitoring', label: 'Monitoring' },
  { key: 'compliance', label: 'Compliance' },
];
