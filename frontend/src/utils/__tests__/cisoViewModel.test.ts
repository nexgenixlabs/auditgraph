import { buildCISOViewModel, buildEmptyCISOViewModel, groupFindingsIntoDrivers, summarizeBlastRadius, buildActionStatements, fmtPct } from '../cisoViewModel';

describe('buildCISOViewModel', () => {
  // ── Test 1: No data ──
  it('returns no_data status when both inputs are null', () => {
    const vm = buildCISOViewModel(null, null);
    expect(vm.status).toBe('no_data');
    expect(vm.status_label).toBe('NO DATA');
    expect(vm.top_risk_drivers).toEqual([]);
    expect(vm.immediate_actions).toEqual([]);
    expect(vm.blast_radius.identity_name).toBeNull();
    expect(vm.trend).toBeNull();
    expect(vm.data_origin).toBe('no_data');
  });

  // ── Test 2: Healthy tenant (all counts 0) ──
  it('returns low status with no exposures for healthy tenant', () => {
    const riskData = {
      data_origin: 'tenant_scan',
      agirs: { score: 92, tier: 'A', delta: 0 },
      risk_counts: {
        ghost_accounts: 0,
        dormant_privileged: 0,
        orphaned_spns: 0,
        over_privileged: 0,
        external_exposure: 0,
      },
      identity_counts: { total: 50, customer: 45, microsoft: 5 },
      exposure: { subscriptions: 3 },
      dangerous_identities: [],
    };
    const attackData = {
      data_integrity: { last_scan: new Date().toISOString(), confidence: 'High' },
      total_identities: 50,
    };

    const vm = buildCISOViewModel(riskData, attackData);
    expect(vm.status).toBe('low');
    expect(vm.status_label).toBe('LOW RISK');
    expect(vm.status_reason).toContain('No significant identity exposures detected');
    expect(vm.top_risk_drivers).toHaveLength(0);
    expect(vm.immediate_actions).toHaveLength(0);
    expect(vm.monitored.identities).toBe(45); // customer only, excludes microsoft
    expect(vm.monitored.subscriptions).toBe(3);
    expect(vm.data_confidence).toBe('high');
    expect(vm.data_origin).toBe('tenant_scan');
    expect(vm.trend).toBe('stable');
    expect(vm.total_identities).toBe(45); // customer only, excludes microsoft
    expect(vm.risk_exposure).toEqual({ count: 0, pct: 0, level: 'low', nav: '/identities?risk=critical,high' });
    expect(vm.confidence_reason).toContain('Full scan completed');
  });

  // ── Test 3: Mixed risk — correct driver ordering and narrative ──
  it('orders drivers by severity: critical first, then high', () => {
    const riskData = {
      data_origin: 'tenant_scan',
      agirs: { score: 45, tier: 'D', delta: -3 },
      risk_counts: {
        ghost_accounts: 4,
        dormant_privileged: 7,
        orphaned_spns: 12,
        over_privileged: 5,
        external_exposure: 3,
      },
      identity_counts: { total: 100 },
      exposure: { subscriptions: 5, key_vaults: 3, storage_accounts: 8 },
      dangerous_identities: [{
        id: 42,
        identity_id: 'spn-abc-123',
        display_name: 'deploy-prod-spn',
        subscription_count: 5,
        total_role_count: 22,
        resource_group_count: 15,
        key_risk_factors: ['Owner role', 'multi-subscription'],
      }],
    };

    const vm = buildCISOViewModel(riskData, null);

    // Status should be high (score 45 → >= 40, < 60)
    expect(vm.status).toBe('high');
    expect(vm.status_label).toBe('HIGH RISK');

    // Drivers: 2 critical (ghost_accounts, dormant_privileged) + 3 high
    expect(vm.top_risk_drivers.length).toBe(5);
    expect(vm.top_risk_drivers[0].severity).toBe('critical');
    expect(vm.top_risk_drivers[1].severity).toBe('critical');
    expect(vm.top_risk_drivers[2].severity).toBe('high');

    // Narrative interpolation with percentage
    const dormantDriver = vm.top_risk_drivers.find(d => d.title === 'Dormant Privileged Accounts');
    expect(dormantDriver).toBeDefined();
    expect(dormantDriver!.count).toBe(7);
    expect(dormantDriver!.pct).toBe(7); // 7/100 = 7%
    expect(dormantDriver!.narrative).toContain('7 accounts');
    expect(dormantDriver!.narrative).toContain('7%');

    // status_reason includes exposure percentage
    expect(vm.status_reason).toContain('2 critical');
    expect(vm.status_reason).toContain('3 high-risk');
    expect(vm.status_reason).toContain('at risk');

    // Risk exposure metric
    expect(vm.risk_exposure.count).toBe(31); // 4+7+12+5+3
    expect(vm.risk_exposure.pct).toBe(31); // 31/100
    expect(vm.risk_exposure.level).toBe('critical'); // >= 20%

    // Trend (delta -3 → declining)
    expect(vm.trend).toBe('declining');
  });

  // ── Test 4: Blast radius with top identity ──
  it('builds blast radius consequences from top dangerous identity', () => {
    const riskData = {
      data_origin: 'tenant_scan',
      agirs: { score: 55, tier: 'C', delta: 2 },
      risk_counts: {},
      identity_counts: { total: 30 },
      exposure: { subscriptions: 8, key_vaults: 5, storage_accounts: 12 },
      dangerous_identities: [{
        id: 99,
        identity_id: 'user-xyz',
        display_name: 'admin@contoso.com',
        subscription_count: 6,
        total_role_count: 25,
        resource_group_count: 20,
        key_risk_factors: ['Owner role', 'Global Administrator'],
      }],
    };

    const vm = buildCISOViewModel(riskData, null);

    expect(vm.blast_radius.level).toBe('critical'); // subs >= 5
    expect(vm.blast_radius.identity_name).toBe('admin@contoso.com');
    expect(vm.blast_radius.identity_id).toBe(99);
    expect(vm.blast_radius.identity_string_id).toBe('user-xyz');
    expect(vm.blast_radius.summary).toContain('admin@contoso.com');
    expect(vm.blast_radius.consequences.length).toBeGreaterThan(0);
    expect(vm.blast_radius.consequences.some(c => c.includes('subscription'))).toBe(true);
    expect(vm.blast_radius.consequences.some(c => c.includes('Key Vault'))).toBe(true);
    expect(vm.blast_radius.consequences.some(c => c.includes('IAM'))).toBe(true);
    expect(vm.blast_radius.consequences.some(c => c.includes('storage account'))).toBe(true);
  });

  // ── Test 5: Trend direction ──
  it('maps positive delta to improving, negative to declining', () => {
    const mkData = (delta: number | null) => ({
      data_origin: 'tenant_scan',
      agirs: { score: 70, tier: 'B', delta },
      risk_counts: {},
      identity_counts: { total: 10 },
      exposure: {},
      dangerous_identities: [],
    });

    expect(buildCISOViewModel(mkData(5), null).trend).toBe('improving');
    expect(buildCISOViewModel(mkData(-2), null).trend).toBe('declining');
    expect(buildCISOViewModel(mkData(0), null).trend).toBe('stable');
    expect(buildCISOViewModel(mkData(null), null).trend).toBeNull();
  });

  // ── Test 6: Driver count cap (max 5) ──
  it('caps risk drivers at 5', () => {
    // All 5 non-zero → exactly 5 (the map only has 5 keys anyway)
    const riskData = {
      data_origin: 'tenant_scan',
      agirs: { score: 30, tier: 'F', delta: null },
      risk_counts: {
        ghost_accounts: 10,
        dormant_privileged: 8,
        orphaned_spns: 15,
        over_privileged: 20,
        external_exposure: 5,
      },
      identity_counts: { total: 200 },
      exposure: {},
      dangerous_identities: [],
    };

    const vm = buildCISOViewModel(riskData, null);
    expect(vm.top_risk_drivers.length).toBeLessThanOrEqual(5);
  });

  // ── Test 7: Action count cap (max 4) ──
  it('caps immediate actions at 4', () => {
    const riskData = {
      data_origin: 'tenant_scan',
      agirs: { score: 30, tier: 'F', delta: null },
      risk_counts: {
        ghost_accounts: 10,
        dormant_privileged: 8,
        orphaned_spns: 15,
        over_privileged: 20,
        external_exposure: 5,
      },
      identity_counts: { total: 200 },
      exposure: {},
      dangerous_identities: [],
    };

    const vm = buildCISOViewModel(riskData, null);
    expect(vm.immediate_actions.length).toBeLessThanOrEqual(4);
    // Each action should have a nav link
    vm.immediate_actions.forEach(a => {
      expect(a.nav).toBeTruthy();
      expect(a.action).toBeTruthy();
    });
  });

  // ── Test 8: buildEmptyCISOViewModel ──
  it('buildEmptyCISOViewModel returns valid defaults', () => {
    const vm = buildEmptyCISOViewModel();
    expect(vm.status).toBe('no_data');
    expect(vm.monitored.identities).toBe(0);
    expect(vm.total_identities).toBe(0);
    expect(vm.risk_exposure).toEqual({ count: 0, pct: 0, level: 'low', nav: '/identities' });
    expect(vm.top_risk_drivers).toEqual([]);
    expect(vm.immediate_actions).toEqual([]);
    expect(vm.blast_radius.level).toBe('low');
    expect(vm.business_impact).toEqual([]);
    expect(vm.system_assessment).toBe('');
    expect(vm.confidence_reason).toBe('');
    expect(vm.snapshot.risk_distribution).toEqual([]);
    expect(vm.snapshot.identity_types).toEqual([]);
    expect(vm.data_origin).toBe('no_data');
    expect(vm.total_identities_nav).toBe('/identities');
    expect(vm.agirs_display.nav).toBe('/identities');
  });

  // ── Test 9: AGIRS score thresholds ──
  it('maps AGIRS score to correct status tiers', () => {
    const mkData = (score: number) => ({
      data_origin: 'tenant_scan',
      agirs: { score, tier: 'X', delta: null },
      risk_counts: {},
      identity_counts: { total: 10 },
      exposure: {},
      dangerous_identities: [],
    });

    expect(buildCISOViewModel(mkData(95), null).status).toBe('low');
    expect(buildCISOViewModel(mkData(80), null).status).toBe('low');
    expect(buildCISOViewModel(mkData(79), null).status).toBe('moderate');
    expect(buildCISOViewModel(mkData(60), null).status).toBe('moderate');
    expect(buildCISOViewModel(mkData(59), null).status).toBe('high');
    expect(buildCISOViewModel(mkData(40), null).status).toBe('high');
    expect(buildCISOViewModel(mkData(39), null).status).toBe('critical');
    expect(buildCISOViewModel(mkData(0), null).status).toBe('critical');
  });

  // ── Test 10: SSOT percentages in snapshot ──
  it('computes pct on risk_distribution and identity_types', () => {
    const riskData = {
      data_origin: 'tenant_scan',
      agirs: { score: 50, tier: 'C', delta: null },
      risk_counts: {
        ghost_accounts: 5,
        dormant_privileged: 10,
        orphaned_spns: 15,
        over_privileged: 0,
        external_exposure: 0,
      },
      identity_counts: { total: 200, human: 80, nhi: 120 },
      exposure: { subscriptions: 2 },
      dangerous_identities: [],
      attack_surface: { external: 10 },
    };

    const vm = buildCISOViewModel(riskData, null);

    // risk_distribution should have pct
    const critDist = vm.snapshot.risk_distribution.find(d => d.level === 'critical');
    expect(critDist).toBeDefined();
    expect(critDist!.count).toBe(15); // ghost(5) + dormant(10)
    expect(critDist!.pct).toBe(7.5); // 15/200 = 7.5%

    // identity_types should have pct
    const humans = vm.snapshot.identity_types.find(t => t.type === 'Human');
    expect(humans).toBeDefined();
    expect(humans!.pct).toBe(40); // 80/200 = 40%
  });

  // ── Test 11: Risk exposure level thresholds ──
  it('maps risk_exposure.pct to correct level', () => {
    const mkData = (ghost: number, dormant: number, total: number) => ({
      data_origin: 'tenant_scan',
      agirs: { score: 60, tier: 'C', delta: null },
      risk_counts: { ghost_accounts: ghost, dormant_privileged: dormant },
      identity_counts: { total },
      exposure: {},
      dangerous_identities: [],
    });

    // 25% → critical
    const vm1 = buildCISOViewModel(mkData(15, 10, 100), null);
    expect(vm1.risk_exposure.level).toBe('critical');

    // 12% → high
    const vm2 = buildCISOViewModel(mkData(6, 6, 100), null);
    expect(vm2.risk_exposure.level).toBe('high');

    // 7% → moderate
    const vm3 = buildCISOViewModel(mkData(4, 3, 100), null);
    expect(vm3.risk_exposure.level).toBe('moderate');

    // 3% → low
    const vm4 = buildCISOViewModel(mkData(2, 1, 100), null);
    expect(vm4.risk_exposure.level).toBe('low');
  });

  // ── Test 12: Percentage in narratives ──
  it('includes percentage in driver narratives', () => {
    const riskData = {
      data_origin: 'tenant_scan',
      agirs: { score: 50, tier: 'C', delta: null },
      risk_counts: { ghost_accounts: 3 },
      identity_counts: { total: 60 },
      exposure: {},
      dangerous_identities: [],
    };

    const vm = buildCISOViewModel(riskData, null);
    const driver = vm.top_risk_drivers[0];
    expect(driver.pct).toBe(5); // 3/60 = 5%
    expect(driver.narrative).toContain('5%');
  });

  // ── Test 13: Percentage in action text ──
  it('includes percentage in action text', () => {
    const riskData = {
      data_origin: 'tenant_scan',
      agirs: { score: 50, tier: 'C', delta: null },
      risk_counts: { orphaned_spns: 8 },
      identity_counts: { total: 200 },
      exposure: {},
      dangerous_identities: [],
    };

    const vm = buildCISOViewModel(riskData, null);
    expect(vm.immediate_actions[0].action).toContain('4%'); // 8/200 = 4%
  });

  // ── Test 14: Nav fields populated for every clickable number ──
  it('populates nav URLs on risk_exposure, risk_distribution, identity_categories, agirs, and total_identities', () => {
    const riskData = {
      data_origin: 'tenant_scan',
      agirs: { score: 50, tier: 'C', delta: null },
      risk_counts: {
        ghost_accounts: 5,
        dormant_privileged: 10,
        orphaned_spns: 15,
        over_privileged: 0,
        external_exposure: 3,
      },
      identity_counts: { total: 200, customer: 180, human: 80, nhi: 60, service_principal: 40, managed_identity_system: 10, managed_identity_user: 10, guest: 20 },
      exposure: { subscriptions: 2 },
      dangerous_identities: [],
    };

    const vm = buildCISOViewModel(riskData, null);

    // risk_exposure nav
    expect(vm.risk_exposure.nav).toBe('/identities?risk=critical,high');

    // total_identities_nav
    expect(vm.total_identities_nav).toBe('/identities');

    // agirs_display nav
    expect(vm.agirs_display.nav).toBe('/identities');

    // risk_distribution nav per level
    vm.snapshot.risk_distribution.forEach(d => {
      expect(d.nav).toContain('risk_level=');
    });
    const critDist = vm.snapshot.risk_distribution.find(d => d.level === 'critical');
    if (critDist) expect(critDist.nav).toBe('/identities?risk_level=critical');
    const highDist = vm.snapshot.risk_distribution.find(d => d.level === 'high');
    if (highDist) expect(highDist.nav).toBe('/identities?risk_level=high');

    // identity_categories nav
    expect(vm.identity_categories.length).toBeGreaterThan(0);
    const humanCat = vm.identity_categories.find(c => c.label === 'Human Identities');
    expect(humanCat?.nav).toBe('/identities?identity_category=human_user');
    const spnCat = vm.identity_categories.find(c => c.label === 'Non-Human / SPNs');
    expect(spnCat?.nav).toBe('/workload-identities?type=spn');
    const guestCat = vm.identity_categories.find(c => c.label === 'Guest Users');
    expect(guestCat?.nav).toBe('/identities?identity_category=guest');
  });
});

describe('fmtPct', () => {
  it('formats percentages correctly', () => {
    expect(fmtPct(0)).toBe('0%');
    expect(fmtPct(4.2)).toBe('4.2%');
    expect(fmtPct(100)).toBe('100%');
    expect(fmtPct(0.05)).toBe('<0.1%');
  });
});

describe('groupFindingsIntoDrivers', () => {
  it('returns empty array for no findings', () => {
    expect(groupFindingsIntoDrivers([])).toEqual([]);
  });

  it('groups by rule_type and counts', () => {
    const findings = [
      { rule_type: 'over_privileged', severity: 'high' },
      { rule_type: 'over_privileged', severity: 'high' },
      { rule_type: 'over_privileged', severity: 'medium' },
      { rule_type: 'dormant_identity', severity: 'medium' },
      { rule_type: 'dormant_identity', severity: 'medium' },
    ];
    const result = groupFindingsIntoDrivers(findings);
    expect(result).toHaveLength(2);
    expect(result[0]).toEqual({ title: 'Over-Privileged Identities', count: 3, severity: 'high' });
    expect(result[1]).toEqual({ title: 'Dormant Identity', count: 2, severity: 'medium' });
  });

  it('picks highest severity in group', () => {
    const findings = [
      { rule_type: 'credential_risk', severity: 'low' },
      { rule_type: 'credential_risk', severity: 'critical' },
      { rule_type: 'credential_risk', severity: 'medium' },
    ];
    const result = groupFindingsIntoDrivers(findings);
    expect(result).toHaveLength(1);
    expect(result[0].severity).toBe('critical');
    expect(result[0].count).toBe(3);
  });

  it('sorts by severity first, then count descending', () => {
    const findings = [
      { rule_type: 'dormant_identity', severity: 'medium' },
      { rule_type: 'dormant_identity', severity: 'medium' },
      { rule_type: 'dormant_identity', severity: 'medium' },
      { rule_type: 'over_privileged', severity: 'high' },
      { rule_type: 'credential_risk', severity: 'high' },
      { rule_type: 'credential_risk', severity: 'high' },
      { rule_type: 'zombie_identity', severity: 'critical' },
    ];
    const result = groupFindingsIntoDrivers(findings);
    expect(result[0].severity).toBe('critical');
    expect(result[1].severity).toBe('high');
    expect(result[1].count).toBe(2); // credential_risk (2) before over_privileged (1)
    expect(result[2].severity).toBe('high');
    expect(result[2].count).toBe(1);
    expect(result[3].severity).toBe('medium');
  });

  it('limits to top 5', () => {
    const types = ['a', 'b', 'c', 'd', 'e', 'f', 'g'];
    const findings = types.map(t => ({ rule_type: t, severity: 'high' }));
    const result = groupFindingsIntoDrivers(findings);
    expect(result).toHaveLength(5);
  });

  it('title-cases unknown categories', () => {
    const findings = [{ rule_type: 'some_custom_rule', severity: 'low' }];
    const result = groupFindingsIntoDrivers(findings);
    expect(result[0].title).toBe('Some Custom Rule');
  });
});

describe('summarizeBlastRadius', () => {
  it('returns no-blast-radius message when both counts are zero', () => {
    expect(summarizeBlastRadius({
      role_count: 0, subscription_count: 0, scope_summary: [],
    })).toBe('This identity has no significant blast radius.');
  });

  it('includes subscriptions and roles with privileged role callout', () => {
    const result = summarizeBlastRadius({
      role_count: 4, subscription_count: 2, scope_summary: ['Owner', 'Reader'],
    });
    expect(result).toBe('If compromised, this identity can access 2 subscriptions and 4 roles including Owner.');
  });

  it('lists multiple privileged roles', () => {
    const result = summarizeBlastRadius({
      role_count: 6, subscription_count: 3,
      scope_summary: ['Owner', 'Contributor', 'Reader', 'Global Administrator'],
    });
    expect(result).toContain('access 3 subscriptions');
    expect(result).toContain('6 roles including Owner, Contributor, Global Administrator');
  });

  it('omits privileged callout when no privileged roles present', () => {
    const result = summarizeBlastRadius({
      role_count: 2, subscription_count: 1, scope_summary: ['Reader', 'Monitoring Reader'],
    });
    expect(result).toBe('If compromised, this identity can access 1 subscription and 2 roles.');
  });

  it('handles roles only (no subscriptions)', () => {
    const result = summarizeBlastRadius({
      role_count: 3, subscription_count: 0, scope_summary: ['Contributor'],
    });
    expect(result).toBe('If compromised, this identity can 3 roles including Contributor.');
  });

  it('handles subscriptions only (no roles)', () => {
    const result = summarizeBlastRadius({
      role_count: 0, subscription_count: 5, scope_summary: [],
    });
    expect(result).toBe('If compromised, this identity can access 5 subscriptions.');
  });

  it('handles singular subscription and role', () => {
    const result = summarizeBlastRadius({
      role_count: 1, subscription_count: 1, scope_summary: ['Owner'],
    });
    expect(result).toContain('1 subscription');
    expect(result).toContain('1 role including Owner');
    expect(result).not.toContain('subscriptions');
    expect(result).not.toContain('roles');
  });

  it('handles empty scope_summary gracefully', () => {
    const result = summarizeBlastRadius({
      role_count: 3, subscription_count: 2, scope_summary: [],
    });
    expect(result).toBe('If compromised, this identity can access 2 subscriptions and 3 roles.');
  });
});

describe('buildActionStatements', () => {
  it('returns empty array for no findings', () => {
    expect(buildActionStatements([])).toEqual([]);
  });

  it('groups findings and produces action per category', () => {
    const findings = [
      { rule_type: 'over_privileged', severity: 'high' },
      { rule_type: 'over_privileged', severity: 'high' },
      { rule_type: 'orphaned_spn', severity: 'high' },
      { rule_type: 'orphaned_spn', severity: 'high' },
      { rule_type: 'orphaned_spn', severity: 'high' },
    ];
    const result = buildActionStatements(findings);
    expect(result).toHaveLength(2);
    expect(result).toContain('Assign owners to 3 orphaned service principals');
    expect(result).toContain('Remove unused roles from 2 identities');
  });

  it('sorts by severity then count', () => {
    const findings = [
      { rule_type: 'dormant_identity', severity: 'low' },
      { rule_type: 'dormant_identity', severity: 'low' },
      { rule_type: 'dormant_identity', severity: 'low' },
      { rule_type: 'ghost_accounts', severity: 'critical' },
      { rule_type: 'expired_credential', severity: 'high' },
      { rule_type: 'expired_credential', severity: 'high' },
    ];
    const result = buildActionStatements(findings);
    expect(result[0]).toBe('Remove roles from 1 ghost account');
    expect(result[1]).toBe('Rotate 2 expired credentials');
    expect(result[2]).toBe('Review 3 dormant identities');
  });

  it('limits to 5 actions', () => {
    const types = ['over_privileged', 'orphaned_spn', 'ghost_accounts', 'expired_credential', 'zombie_identity', 'dormant_identity', 'credential_risk'];
    const findings = types.map(t => ({ rule_type: t, severity: 'high' }));
    const result = buildActionStatements(findings);
    expect(result).toHaveLength(5);
  });

  it('uses fallback for unknown categories', () => {
    const findings = [
      { rule_type: 'custom_check', severity: 'medium' },
      { rule_type: 'custom_check', severity: 'medium' },
    ];
    const result = buildActionStatements(findings);
    expect(result).toEqual(['Address 2 custom check findings']);
  });

  it('handles singular counts correctly', () => {
    const findings = [
      { rule_type: 'over_privileged', severity: 'high' },
      { rule_type: 'zombie_identity', severity: 'medium' },
      { rule_type: 'expired_credential', severity: 'high' },
    ];
    const result = buildActionStatements(findings);
    expect(result).toContain('Remove unused roles from 1 identity');
    expect(result).toContain('Investigate 1 zombie identity');
    expect(result).toContain('Rotate 1 expired credential');
  });

  it('covers all known rule types', () => {
    const types = [
      'dormant_privileged', 'ghost_accounts', 'disabled_account_active_role',
      'orphaned_spn', 'over_privileged', 'external_exposure',
      'expired_credential', 'zombie_identity', 'privilege_escalation',
      'nhi_security', 'dormant_identity', 'excessive_permissions',
      'credential_risk', 'high_privilege_identity',
    ];
    const findings = types.map(t => ({ rule_type: t, severity: 'high' }));
    const result = buildActionStatements(findings);
    // All should produce statements, capped at 5
    expect(result).toHaveLength(5);
    result.forEach(s => {
      expect(s).not.toContain('finding'); // known types should not use fallback
    });
  });
});
