/**
 * Sprint B.5 (2026-06-11) — Exposure Tab
 *
 * Peer-review gap: exposure signals were scattered across 4-5 tabs.
 *   - MFA status lived inside Overview chip
 *   - CA coverage lived inside Compliance
 *   - Owner status lived inside Ownership + Overview
 *   - Standing-privileged lived inside PIM finding callout
 *   - Sensitive-data-reachable lived inside Sensitive Access
 *
 * This tab consolidates all five into one investigative narrative panel — the
 * single "is this identity exposed?" question a CISO can answer in one read.
 *
 * Each row:
 *   - State chip (PASS / WARN / FAIL)
 *   - Signal title + plain-English explanation
 *   - Evidence (the actual derived fact, not a marketing string)
 *   - "Fix this" CTA → jumps to the right remediation
 *
 * Pure derivation — no new backend endpoint. Reads from the existing
 * identity/data/effectiveScope props.
 */
import React from 'react';
import type { IdentityDetailsResponse, TabId } from './types';

type State = 'pass' | 'warn' | 'fail' | 'unknown';

interface SignalRow {
  key: string;
  title: string;
  state: State;
  evidence: string;
  explanation: string;
  fixCta?: { label: string; tab: TabId };
}

const STATE_META: Record<State, { color: string; bg: string; border: string; label: string; icon: string }> = {
  pass:    { color: '#10b981', bg: 'bg-emerald-50', border: 'border-emerald-200', label: 'Pass',    icon: 'M9 12l2 2 4-4' },
  warn:    { color: '#f59e0b', bg: 'bg-amber-50',   border: 'border-amber-200',   label: 'Warn',    icon: 'M12 9v2m0 4h.01' },
  fail:    { color: '#ef4444', bg: 'bg-red-50',     border: 'border-red-200',     label: 'Fail',    icon: 'M6 18L18 6M6 6l12 12' },
  unknown: { color: '#94a3b8', bg: 'bg-slate-50',   border: 'border-slate-200',   label: 'Unknown', icon: 'M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01' },
};

function deriveExposureRows(identity: any, data: IdentityDetailsResponse | null, effectiveScope: { subscriptions: string[]; tenantWide: boolean }): SignalRow[] {
  const rows: SignalRow[] = [];
  const isHuman = identity?.identity_category === 'human_user' || identity?.identity_category === 'guest';

  // 1) MFA Coverage
  const mfa = String(identity?.mfa_status || (identity as any)?.mfa_status || '').toLowerCase();
  const caEnforced = !!(identity?.ca_mfa_enforced ?? (identity as any)?.ca_mfa_enforced);
  if (isHuman) {
    if (mfa === 'enforced' || mfa === 'enrolled') {
      rows.push({
        key: 'mfa',
        title: 'MFA Enrollment',
        state: 'pass',
        evidence: 'Microsoft Graph reports user has MFA authentication methods registered.',
        explanation: 'Human user has at least one strong authentication method registered. Credential theft alone cannot reach this account.',
      });
    } else if (mfa === 'not_enrolled') {
      rows.push({
        key: 'mfa',
        title: 'MFA Enrollment',
        state: 'fail',
        evidence: 'Microsoft Graph reports zero strong authentication methods.',
        explanation: 'Password is the only barrier. A stolen credential signs the attacker into every role this identity holds. Privileged identities without MFA are the #1 breach vector (Verizon DBIR 2024).',
        fixCta: { label: 'View remediation actions', tab: 'remediation' as TabId },
      });
    } else {
      rows.push({
        key: 'mfa',
        title: 'MFA Enrollment',
        state: 'unknown',
        evidence: 'MFA status not yet collected for this identity.',
        explanation: 'Run discovery again or grant the AuthenticationMethod.Read.All Graph scope to determine enrollment state.',
      });
    }

    // 2) Conditional Access policy coverage
    if (caEnforced) {
      rows.push({
        key: 'ca',
        title: 'Conditional Access Coverage',
        state: 'pass',
        evidence: 'At least one enabled CA policy targets this identity and enforces MFA on sign-in.',
        explanation: 'Policy-enforced MFA holds even if the user uninstalls the authenticator. Strongest control.',
      });
    } else {
      rows.push({
        key: 'ca',
        title: 'Conditional Access Coverage',
        state: 'warn',
        evidence: 'No enabled CA policy enforcing MFA covers this identity in the current snapshot.',
        explanation: 'MFA enrollment is useful only if a policy enforces its use on risky sign-ins. Without CA, users can bypass MFA on legacy auth protocols.',
        fixCta: { label: 'Review CA policy coverage', tab: 'compliance' as TabId },
      });
    }
  }

  // 3) Ownership
  const hasOwner = !!(identity?.owner_display_name || (identity?.owner_count ?? 0) > 0);
  if (hasOwner) {
    rows.push({
      key: 'owner',
      title: 'Accountable Owner',
      state: 'pass',
      evidence: `Owner of record: ${identity?.owner_display_name || `${identity?.owner_count} owner(s)`}.`,
      explanation: 'A human owner can attest the access, rotate credentials, or decommission the identity. No abandoned accountability gap.',
    });
  } else {
    rows.push({
      key: 'owner',
      title: 'Accountable Owner',
      state: isHuman ? 'warn' : 'fail',
      evidence: 'No appOwners record returned by Microsoft Graph for this identity.',
      explanation: isHuman
        ? 'Manager / accountable owner not mapped. Recommended for access reviews.'
        : 'NHIs without owners cannot be rotated, reviewed, or decommissioned. Default-CRITICAL until proven safe — this is the canonical "ghost SPN" risk.',
      fixCta: { label: 'Assign owner', tab: 'ownership' as TabId },
    });
  }

  // 4) Standing privileged access
  const isPriv = identity?.privilege_level === 'Privileged' || identity?.privilege_level === 'Highly Privileged'
              || (identity as any)?.privilege_level === 'Privileged' || (identity as any)?.privilege_level === 'Highly Privileged';
  const pimEligible = (identity as any)?.pim_eligible_count ?? 0;
  const hasPermanent = !!((identity as any)?.has_permanent_assignment);
  if (isPriv && pimEligible === 0) {
    rows.push({
      key: 'standing_priv',
      title: 'Standing Privileged Roles',
      state: 'fail',
      evidence: `Privileged identity with ${pimEligible} PIM-eligible assignments — all access is permanently active.`,
      explanation: 'Microsoft best practice (Zero Trust) and NIST AC-6 (Least Privilege) require privileged roles to be JIT-activated, not standing. Standing roles widen the breach window from minutes to permanent.',
      fixCta: { label: 'Convert to PIM-eligible', tab: 'pim' as TabId },
    });
  } else if (isPriv && pimEligible > 0 && hasPermanent) {
    rows.push({
      key: 'standing_priv',
      title: 'Standing Privileged Roles',
      state: 'warn',
      evidence: `Has PIM-eligible assignments (${pimEligible}) but also holds permanent assignments alongside.`,
      explanation: 'Mixed assignment model defeats the JIT-activation guarantee. Audit which roles are permanent and move them to PIM-eligible.',
      fixCta: { label: 'Review PIM tab', tab: 'pim' as TabId },
    });
  } else if (isPriv && pimEligible > 0) {
    rows.push({
      key: 'standing_priv',
      title: 'Standing Privileged Roles',
      state: 'pass',
      evidence: `All ${pimEligible} privileged role(s) are PIM-eligible.`,
      explanation: 'Access requires explicit JIT activation with time-bounded approval. Zero-Trust compliant.',
    });
  }

  // 5) Sensitive-data reachability (PHI / PCI / PII)
  const br: any = (data as any)?.blast_radius || {};
  const sensTotal = br.total_sensitive || 0;
  const byClass = br.by_classification || {};
  if (sensTotal === 0) {
    rows.push({
      key: 'reach',
      title: 'Sensitive-Data Reachability',
      state: 'pass',
      evidence: 'No RBAC path to PHI / PCI / PII classified resources detected.',
      explanation: 'Identity\'s role assignments do not grant access to any resources tagged with regulated data classifications.',
    });
  } else {
    const parts: string[] = [];
    if (byClass.PHI) parts.push(`${byClass.PHI} PHI`);
    if (byClass.PCI) parts.push(`${byClass.PCI} PCI`);
    if (byClass.PII) parts.push(`${byClass.PII} PII`);
    rows.push({
      key: 'reach',
      title: 'Sensitive-Data Reachability',
      state: 'fail',
      evidence: `${sensTotal} classified resource(s) reachable: ${parts.join(' · ') || 'mixed classifications'}.`,
      explanation: 'A compromise of this identity exposes regulated data. HIPAA §164.312 / PCI-DSS Req 7 / GDPR Art 32 all require quarterly access review.',
      fixCta: { label: 'View sensitive access', tab: 'sensitive_access' as TabId },
    });
  }

  // 6) Tenant-wide scope
  if (effectiveScope.tenantWide) {
    rows.push({
      key: 'tenant_wide',
      title: 'Tenant-Wide Scope',
      state: 'fail',
      evidence: 'Holds at least one role assigned at "/" (root) or tenant-wide directory scope.',
      explanation: 'Tenant-wide assignments grant the role across every subscription, resource, and directory object. The blast-radius is your entire Azure footprint.',
      fixCta: { label: 'Scope down via access graph', tab: 'access_graph' as TabId },
    });
  } else if (effectiveScope.subscriptions.length > 1) {
    rows.push({
      key: 'multi_sub',
      title: 'Multi-Subscription Spread',
      state: 'warn',
      evidence: `Role assignments span ${effectiveScope.subscriptions.length} subscriptions.`,
      explanation: 'Multi-subscription access expands blast radius and complicates lateral-movement containment. Consider per-subscription identities for production isolation.',
      fixCta: { label: 'View scope graph', tab: 'access_graph' as TabId },
    });
  }

  return rows;
}

interface Props {
  identity: any;
  data: IdentityDetailsResponse | null;
  effectiveScope: { subscriptions: string[]; resourceGroups: string[]; tenantWide: boolean; entraScopes: string[] };
  onJumpToTab: (tab: TabId) => void;
}

export default function ExposureTab({ identity, data, effectiveScope, onJumpToTab }: Props) {
  const rows = deriveExposureRows(identity, data, effectiveScope);
  const failCount = rows.filter(r => r.state === 'fail').length;
  const warnCount = rows.filter(r => r.state === 'warn').length;
  const passCount = rows.filter(r => r.state === 'pass').length;
  const totalChecked = rows.length;

  const summaryColor = failCount > 0 ? '#ef4444' : warnCount > 0 ? '#f59e0b' : '#10b981';
  const summaryLabel = failCount > 0 ? 'High Exposure' : warnCount > 0 ? 'Moderate Exposure' : 'Low Exposure';

  return (
    <div className="p-6 space-y-4">
      {/* Summary strip */}
      <div className="bg-white border rounded-2xl p-4">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div>
            <div className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Exposure Assessment</div>
            <div className="flex items-baseline gap-3 mt-1">
              <span className="text-2xl font-bold" style={{ color: summaryColor }}>{summaryLabel}</span>
              <span className="text-xs text-gray-500">{totalChecked} signals checked</span>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-center">
              <div className="text-xl font-bold text-red-600">{failCount}</div>
              <div className="text-[9px] uppercase tracking-wider text-gray-500">Fail</div>
            </div>
            <div className="text-center">
              <div className="text-xl font-bold text-amber-600">{warnCount}</div>
              <div className="text-[9px] uppercase tracking-wider text-gray-500">Warn</div>
            </div>
            <div className="text-center">
              <div className="text-xl font-bold text-emerald-600">{passCount}</div>
              <div className="text-[9px] uppercase tracking-wider text-gray-500">Pass</div>
            </div>
          </div>
        </div>
      </div>

      {/* Signal rows */}
      <div className="space-y-2">
        {rows.map(row => {
          const meta = STATE_META[row.state];
          return (
            <div key={row.key} className={`border rounded-xl p-4 ${meta.bg} ${meta.border}`}>
              <div className="flex items-start gap-4">
                <div className="flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center"
                  style={{ background: `${meta.color}22`, color: meta.color }}>
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={meta.icon} />
                  </svg>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase"
                      style={{ background: `${meta.color}22`, color: meta.color }}>{meta.label}</span>
                    <span className="text-sm font-semibold text-gray-900">{row.title}</span>
                  </div>
                  <div className="text-xs text-gray-700 mb-1">{row.explanation}</div>
                  <div className="text-[11px] text-gray-500 italic">{row.evidence}</div>
                </div>
                {row.fixCta && (
                  <button onClick={() => onJumpToTab(row.fixCta!.tab)}
                    className="flex-shrink-0 px-3 py-1.5 rounded-lg text-xs font-semibold text-indigo-700 bg-white border border-indigo-200 hover:bg-indigo-50 transition">
                    {row.fixCta.label} →
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      <div className="text-[10px] text-gray-400 italic text-center pt-2">
        All signals derived from architecture (RBAC + CA + classification metadata) — no log-dependence.
      </div>
    </div>
  );
}
