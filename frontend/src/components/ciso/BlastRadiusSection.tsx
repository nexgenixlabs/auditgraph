import React from 'react';
import type { CISOViewModel, PostureV31Response } from '../../utils/cisoViewModel';
import { DN } from '../dashboard/ciso-shared';

// ── Blast Radius Card (legacy VM) ────────────────────────────

function buildImpactLines(consequences: string[]): string[] {
  const raw = consequences.join('\n');
  const lines: string[] = [];

  const subMatch = raw.match(/Control (\d+) of (\d+)/);
  if (subMatch) {
    const reached = parseInt(subMatch[1], 10);
    const total = parseInt(subMatch[2], 10);
    lines.push(
      reached >= total
        ? `Full control of ${total === 1 ? 'the entire subscription' : `all ${total} subscriptions`}`
        : `Full control of ${reached} of ${total} production subscriptions`
    );
  }

  const kvMatch = raw.match(/Access (\d+) Key Vault/);
  const saMatch = raw.match(/(\d+) storage account/);
  const kvCount = kvMatch ? parseInt(kvMatch[1], 10) : 0;
  const saCount = saMatch ? parseInt(saMatch[1], 10) : 0;
  if (kvCount > 0 || saCount > 0) {
    const parts: string[] = [];
    if (kvCount > 0) parts.push(`${kvCount} Key Vault${kvCount !== 1 ? 's' : ''}`);
    if (saCount > 0) parts.push(`${saCount} storage account${saCount !== 1 ? 's' : ''}`);
    lines.push(`Access to sensitive resources (${parts.join(', ')})`);
  }
  if (/Modify IAM/i.test(raw) && lines.length < 2) {
    lines.push('Escalate privileges and establish persistent access');
  }
  const rgMatch = raw.match(/Reach (\d+) resource group/);
  if (rgMatch && lines.length < 2) {
    lines.push(`Traverse ${rgMatch[1]} production resource groups`);
  }
  if (lines.length === 0 && consequences.length > 0) {
    lines.push(consequences[0].replace(/Azure\s+/gi, ''));
  }
  return lines.slice(0, 2);
}

export function BlastRadiusCard({ vm }: { vm: CISOViewModel }) {
  const br = vm.blast_radius;
  const hasIdentity = !!br.identity_name;
  const impacts = hasIdentity ? buildImpactLines(br.consequences) : [];

  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex flex-col overflow-hidden hover:border-white/10 hover:scale-[1.01] transition"
         title={hasIdentity ? `Highest risk: ${br.identity_name}` : 'No high-risk identities'}>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-gray-400 uppercase tracking-wider font-medium">Blast Radius</span>
        {hasIdentity && (
          <DN navigateTo={`/identities/${br.identity_string_id || br.identity_id}`}>
            <span className="text-xs text-gray-500 truncate max-w-[120px] cursor-pointer hover:text-gray-300 transition">{br.identity_name}</span>
          </DN>
        )}
      </div>
      {hasIdentity ? (
        <>
          <span className="text-xs font-semibold text-gray-300 mb-1">If compromised:</span>
          <div className="space-y-0.5 min-w-0">
            {impacts.map((line, i) => (
              <p key={i} className="text-xs text-gray-400 truncate">
                <span className="text-red-400/70 mr-1">•</span>{line}
              </p>
            ))}
          </div>
        </>
      ) : (
        <p className="text-xs text-gray-400 mt-auto">No identities with high-impact access detected</p>
      )}
    </div>
  );
}

// ── v3.1 Blast Radius Card ───────────────────────────────────

export function BlastRadiusCardV31({ data }: { data: PostureV31Response }) {
  const br = data.blast_radius;
  if (!br) {
    return (
      <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex flex-col overflow-hidden hover:border-white/10 transition">
        <span className="text-xs text-gray-400 uppercase tracking-wider font-medium mb-1">Blast Radius</span>
        <p className="text-xs text-gray-400 mt-auto">No identities with high-impact access detected</p>
      </div>
    );
  }

  // Compress the previous wall-of-roles into a counted bullet so the card reads
  // at-a-glance. exploitation_text is the comma-joined role list when the
  // backend has many roles to enumerate; the full text remains available on
  // hover via the container's title attribute (below).
  const exploitText = br.exploitation_text || '';
  const roleItems = exploitText.split(/,\s*/).map(s => s.trim()).filter(Boolean);
  const roleCount = roleItems.length;

  const tierNum = (br.role_tier || '').replace('T', '');
  const impactColor = tierNum <= '1' ? '#e8465a' : tierNum === '2' ? '#FF7216' : '#6b7280';

  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex flex-col overflow-hidden hover:border-white/10 hover:scale-[1.01] transition"
         title={exploitText}>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-gray-400 uppercase tracking-wider font-medium"
              title="Worst-case impact if this identity is compromised"
              style={{ cursor: 'help', borderBottom: '1px dotted currentColor' }}>
          Blast Radius
        </span>
        <div className="flex items-center gap-2 min-w-0 max-w-[60%] justify-end">
          <DN navigateTo={`/identities/${br.identity_string_id || br.identity_id}`}>
            <span className="text-xs text-gray-500 truncate cursor-pointer hover:text-gray-300 transition">{br.identity_name}</span>
          </DN>
          {!!br.more_count && br.more_count > 0 && (
            <span className="text-[10px] font-mono text-gray-500 shrink-0">+{br.more_count} more</span>
          )}
        </div>
      </div>
      <span className="text-xs font-semibold text-gray-300 mb-1 mt-1">If compromised:</span>
      <div className="space-y-0.5">
        {br.scope_string && (
          <p className="text-xs text-gray-400 truncate">
            <span className="text-red-400/70 mr-1">•</span>{br.scope_string}
          </p>
        )}
        {br.role_tier && (
          <p className="text-xs text-gray-400 truncate">
            <span className="text-red-400/70 mr-1">•</span>Tier {br.role_tier} access
          </p>
        )}
        {roleCount > 3 ? (
          <p className="text-xs text-gray-400 truncate" title={exploitText}>
            <span className="text-red-400/70 mr-1">•</span>
            Grants <span className="font-mono text-gray-300">{roleCount}</span> privileged role{roleCount === 1 ? '' : 's'}
          </p>
        ) : exploitText ? (
          <p className="text-xs text-gray-500 truncate" title={exploitText}>{exploitText}</p>
        ) : null}
      </div>
      {br.impact_label && (
        <p className="text-[11px] font-medium mt-auto pt-1.5" style={{ color: impactColor }}>
          Impact: {br.impact_label}
        </p>
      )}
    </div>
  );
}

// ── Attack Path Card (legacy VM) ─────────────────────────────

function actorLabel(cat: string): string {
  if (cat.includes('human')) return 'User';
  if (cat.includes('guest')) return 'Guest';
  if (cat.includes('service_principal')) return 'Service Account';
  if (cat.includes('managed_identity')) return 'Managed Identity';
  return 'Identity';
}

function extractRole(sub: string): string {
  const parts = sub.split(' · ');
  if (parts.length >= 2) return parts[1];
  return 'Elevated Access';
}

function blastTarget(label: string): string {
  const m = label.match(/^Blast:\s*(.+)$/i);
  if (!m) return 'Resources';
  const val = m[1].trim();
  if (/^\d+\s*subs?$/i.test(val)) return val.replace(/subs?$/i, 'Subscriptions');
  if (/sub-wide/i.test(val)) return 'Full Subscription';
  if (/^\d+\s*RGs?$/i.test(val)) return val.replace(/RGs?$/i, 'Resource Groups');
  if (/RG scope/i.test(val)) return 'Resource Group';
  return 'Local Resources';
}

function impactLine(verdict: string, blastLabel: string): string {
  const isSub = /subs?|sub-wide/i.test(blastLabel);
  const isMultiSub = /^\d/.test(blastLabel.replace(/^Blast:\s*/i, '')) && isSub;
  const outcomes: Record<string, string> = {
    ORPHANED: isMultiSub ? 'Allows untracked escalation across subscriptions' : 'Enables unauthorized access with no accountability',
    GHOST: 'Can be reactivated to bypass access controls',
    GHOST_MSI: 'Allows silent execution without human oversight',
    STALE: isSub ? 'Allows privilege escalation across subscriptions' : 'Can be exploited to access critical resources',
    AT_RISK: isSub ? 'Enables lateral movement into production workloads' : 'Can be used to extract sensitive data',
    CRED_RISK: 'Enables credential-based compromise of downstream systems',
    NEEDS_REVIEW: 'May allow unauthorized access to sensitive resources',
  };
  return outcomes[verdict] || 'Enables unauthorized access to critical resources';
}

export function AttackPathCard({ vm }: { vm: CISOViewModel }) {
  const finding = vm.findings[0];
  const count = vm.findings.length;

  if (!finding) {
    return (
      <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex flex-col overflow-hidden hover:border-white/10 hover:scale-[1.01] transition">
        <span className="text-xs text-gray-400 uppercase tracking-wider font-medium mb-1">Attack Path</span>
        <p className="text-xs text-gray-400 mt-auto">No escalation paths currently detected</p>
      </div>
    );
  }

  const actor = actorLabel(finding.prefill?.identity_category || '');
  const role = extractRole(finding.sub);
  const target = blastTarget(finding.blast_label);
  const chain = `${actor} → ${role} → ${target}`;
  const impact = impactLine(finding.verdict, finding.blast_label);

  return (
    <DN navigateTo={finding.nav} prefill={finding.prefill}>
      <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex flex-col overflow-hidden hover:border-white/10 hover:scale-[1.01] transition cursor-pointer">
        <div className="flex items-center justify-between mb-1">
          <span className="text-xs text-gray-400 uppercase tracking-wider font-medium">Attack Path</span>
          {count > 1 && <span className="text-xs font-mono text-gray-500">+{count - 1}</span>}
        </div>
        <p className="text-xs font-semibold text-gray-200 truncate">{chain}</p>
        <p className="text-xs text-gray-400 truncate mt-auto">{impact}</p>
      </div>
    </DN>
  );
}

// ── v3.1 Attack Path Card ────────────────────────────────────

// Interpretation line for top path — executive-readable
function pathInterpretation(desc: string, pathType?: string): string {
  const d = (desc || '').toLowerCase();
  if (d.includes('owner'))
    return 'Direct Owner access grants full control across the subscription \u2014 IAM and resources';
  if (d.includes('user access administrator'))
    return 'Can grant any role to any identity — privilege escalation vector';
  if (d.includes('contributor'))
    return 'Can create, modify, and delete all resources in the subscription';
  if (d.includes('global administrator') || d.includes('privileged role'))
    return 'Tenant-wide administrative control over all directory objects';
  if (pathType === 'ownership_chain')
    return 'Indirect escalation through owned service principal credentials';
  if (pathType === 'pim_abuse')
    return 'Can activate privileged role through PIM — just-in-time escalation';
  return 'Privileged access to subscription resources';
}

export function AttackPathCardV31({ data }: { data: PostureV31Response }) {
  const paths = data.attack_paths;
  if (!paths || paths.length === 0) {
    const totalIds = data.identity_risk?.total ?? 0;
    const subCount = data.coverage?.sub_count ?? 0;
    return (
      <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex flex-col overflow-hidden hover:border-white/10 transition">
        <span className="text-xs text-gray-400 uppercase tracking-wider font-medium mb-1">Privilege Exposure</span>
        <div className="border-l-2 border-[#22C55E] pl-3 mt-2">
          <div className="flex items-center gap-1.5">
            <span className="text-[13px] text-[#22C55E]">&#10003;</span>
            <span className="text-xs font-medium text-gray-200">No privilege escalation paths detected</span>
          </div>
          <p className="text-[11px] text-gray-500 mt-0.5">
            Analyzed {totalIds.toLocaleString()} identities across {subCount} subscription{subCount !== 1 ? 's' : ''} — no confirmed privilege escalation chains found
          </p>
        </div>
      </div>
    );
  }

  const top = paths[0];
  const totalPaths = data.attack_path_total ?? paths.length;
  const sourceCount = data.attack_path_source_count ?? 0;
  const chain = top.description
    ? top.description
    : `${top.actor || 'Identity'} → Tier ${top.role_tier || '?'} → ${top.target || 'resource'}`;
  const navId = top.identity_string_id || (top.identity_id != null ? String(top.identity_id) : '');

  // Determine if the top path is a single-hop direct privilege vs multi-hop escalation
  const isDirect = top.path_type === 'lateral_movement' || top.path_type === 'direct_escalation'
    || (top.path_type && !top.path_type.includes('chain'));
  const headerLabel = isDirect ? 'Top Privilege Exposure' : 'Top Escalation Path';
  const typeBadge = isDirect ? 'Direct' : 'Multi-hop';
  const typeBadgeColor = isDirect ? 'rgba(245,158,11,0.15)' : 'rgba(232,70,90,0.15)';
  const typeBadgeText = isDirect ? '#f59e0b' : '#e8465a';
  const interpretation = pathInterpretation(top.description || '', top.path_type);

  // Path composition breakdown
  const criticalCount = paths.filter(p => p.severity === 'critical').length;
  const highCount = paths.filter(p => p.severity === 'high').length;
  const mediumCount = paths.filter(p => p.severity === 'medium').length;
  const compParts: string[] = [];
  if (criticalCount > 0) compParts.push(`${criticalCount} critical`);
  if (highCount > 0) compParts.push(`${highCount} high`);
  if (mediumCount > 0) compParts.push(`${mediumCount} medium`);
  const compositionLine = totalPaths > 0 ? `Across ${totalPaths} paths (${compParts.join(', ')})` : null;

  // Severity-based left border
  const borderColor = top.severity === 'critical' ? 'rgba(232,70,90,0.6)'
    : top.severity === 'high' ? 'rgba(245,158,11,0.5)' : undefined;

  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex flex-col overflow-hidden hover:border-white/10 transition"
         style={borderColor ? { borderLeftWidth: 3, borderLeftColor: borderColor, borderLeftStyle: 'solid' } : undefined}>
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-400 uppercase tracking-wider font-medium">{headerLabel}</span>
          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded" style={{ background: typeBadgeColor, color: typeBadgeText }}>{typeBadge}</span>
          {top.severity === 'critical' && (
            <span style={{ background: 'rgba(232,70,90,0.15)', color: '#E8465A', fontSize: 10, fontWeight: 600, fontFamily: 'var(--mono)', padding: '3px 9px', borderRadius: '5px' }}>CRITICAL</span>
          )}
          {top.severity === 'high' && (
            <span style={{ background: 'rgba(245,158,11,0.15)', color: '#F59E0B', fontSize: 10, fontWeight: 600, fontFamily: 'var(--mono)', padding: '3px 9px', borderRadius: '5px' }}>HIGH</span>
          )}
        </div>
        {totalPaths > 1 && (
          <span className="text-[10px] font-mono text-gray-500">+{totalPaths - 1} more path{totalPaths - 1 !== 1 ? 's' : ''}</span>
        )}
      </div>
      <p style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-primary, #E6EDF3)', marginBottom: 2 }}>{interpretation}</p>
      <DN navigateTo={navId ? `/attack-paths?highlight=${navId}` : '/attack-paths'}>
        <p className="truncate cursor-pointer hover:underline transition" style={{ fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--text-muted, #484F58)' }}>{chain}</p>
      </DN>
      {compositionLine && (
        <p style={{ fontSize: 10, color: 'var(--text-muted, #484F58)', fontStyle: 'italic', marginTop: 4 }}>{compositionLine}</p>
      )}
      {sourceCount > 0 && (
        <p className="font-medium mt-1" style={{ fontSize: 12, color: '#FF7216' }}>
          <span style={{ fontStyle: 'normal' }}>{'\u26A0'} </span>
          {sourceCount} identit{sourceCount !== 1 ? 'ies' : 'y'} have paths to full subscription control
        </p>
      )}
      {totalPaths > 0 && (
        <DN navigateTo="/attack-paths">
          <p className="cursor-pointer hover:underline mt-auto pt-1" style={{ fontSize: 11, fontWeight: 500, color: 'var(--teal, #24A2A1)' }}>
            View all {totalPaths} paths →
          </p>
        </DN>
      )}
    </div>
  );
}

// ── Identity Risk Card (legacy VM) ───────────────────────────

function buildIdentityInsight(vm: CISOViewModel): { primary: string; secondary: string } {
  const total = vm.total_identities;
  const atRisk = vm.risk_exposure.count;
  if (total === 0) return { primary: 'No identities monitored', secondary: '' };
  const primary = atRisk > 0 ? `${atRisk} identit${atRisk !== 1 ? 'ies' : 'y'} at risk` : 'No identities at risk';
  const nhiLabels = new Set(['Non-Human / SPNs', 'System MSIs', 'User-Assigned MSIs']);
  const nhiCount = vm.identity_categories.filter(c => nhiLabels.has(c.label)).reduce((s, c) => s + c.count, 0);
  const nhiPct = Math.round((nhiCount / total) * 100);
  if (nhiPct > 0) return { primary, secondary: `${nhiPct}% are machine identities` };
  if (atRisk > 0) return { primary, secondary: `${(Math.round(vm.risk_exposure.pct * 10) / 10)}% of identities exposed` };
  return { primary, secondary: `${total.toLocaleString()} identities monitored` };
}

export function IdentityRiskCard({ vm }: { vm: CISOViewModel }) {
  const { primary, secondary } = buildIdentityInsight(vm);
  return (
    <DN navigateTo={vm.risk_exposure.nav}>
      <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex flex-col overflow-hidden hover:border-white/10 hover:scale-[1.01] transition cursor-pointer">
        <span className="text-xs text-gray-400 uppercase tracking-wider font-medium mb-1">Identity Risk</span>
        <p className="text-xs font-semibold text-gray-200 truncate">{primary}</p>
        {secondary && <p className="text-xs text-gray-400 truncate mt-auto">{secondary}</p>}
      </div>
    </DN>
  );
}

// ── v3.1 Identity Risk Card ──────────────────────────────────

export function IdentityRiskCardV31({ data }: { data: PostureV31Response }) {
  const ir = data.identity_risk;
  const total = ir.total;
  const rows = [
    { label: 'Dormant privileged identities', count: ir.dormant, filter: 'dormant' },
    { label: 'Ghost identities (access not revoked)', count: ir.ghost, filter: 'ghost' },
    { label: 'Unowned service principals', count: ir.unowned_nhi, filter: 'unowned_nhi' },
  ].filter(r => r.count > 0).sort((a, b) => b.count - a.count);

  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex flex-col overflow-hidden hover:border-white/10 hover:scale-[1.01] transition">
      <span className="text-xs text-gray-400 uppercase tracking-wider font-medium mb-1">Identity Risk</span>
      {total === 0 ? (
        <p className="text-xs text-gray-400 mt-auto">No identities monitored</p>
      ) : rows.length === 0 ? (
        <>
          <p className="text-xs font-semibold text-emerald-400">No identities at risk</p>
          <p className="text-xs text-gray-400 mt-auto">{total.toLocaleString()} monitored · {ir.machine_pct}% machine</p>
        </>
      ) : (
        <>
          <div className="space-y-0.5 flex-1">
            {rows.map((r, i) => (
              <DN key={r.filter} navigateTo={`/identities?filter=${r.filter}`}>
                <div className={`flex items-center justify-between text-xs cursor-pointer hover:bg-white/[0.02] rounded px-1 -mx-1 ${i === 0 ? 'font-medium text-gray-200' : 'text-gray-400'}`}>
                  <span className="truncate mr-2">
                    {i === 0 && <span className="text-[9px] font-semibold uppercase tracking-wider text-[#f59e0b] mr-1">Primary Risk:</span>}
                    <span className={i === 0 ? 'text-[11px]' : ''}>{r.label}</span>
                  </span>
                  <span className="font-mono text-gray-300 flex-shrink-0">{r.count}</span>
                </div>
              </DN>
            ))}
          </div>
          <p className="text-xs text-gray-500 mt-auto">{ir.machine_pct}% machine identities</p>
        </>
      )}
    </div>
  );
}

// ── Default export (backwards compat) ────────────────────────

export default function BlastRadiusSection({ vm }: { vm: CISOViewModel }) {
  return (
    <div className="grid grid-cols-3 gap-3 h-[140px]">
      <BlastRadiusCard vm={vm} />
      <AttackPathCard vm={vm} />
      <IdentityRiskCard vm={vm} />
    </div>
  );
}
