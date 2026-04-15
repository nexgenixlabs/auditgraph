import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import { shouldShowRemediation } from '../utils/displayHelpers';
import { SnapshotContextHeader } from '../components/ui/SnapshotContextHeader';

// ─── Theme constants ───
const R = {
  surface: 'var(--bg-secondary)',
  surfaceBorder: 'var(--border-default)',
  text: 'var(--text-primary)',
  textSecondary: 'var(--text-secondary)',
  textMuted: 'var(--text-tertiary)',
  accent: '#8B5CF6',
  status: {
    new: '#FF6D00', planned: '#42A5F5', in_progress: '#FFB300',
    verified: '#4ADE80', closed: '#94A3B8',
  } as Record<string, string>,
  priority: { critical: '#FF1744', high: '#FF6D00', medium: '#FFB300', low: '#4ADE80' } as Record<string, string>,
};

interface RemediationAction {
  id: number;
  title: string;
  description: string;
  risk_reduction: number;
  affected_count: number;
  blast_radius: string;
  automation_ready: boolean;
  confidence: number;
  status: string;
  priority: string;
  identity_id?: string;
  identity_name?: string;
  playbook_id?: number;
  playbook_name?: string;
  created_at?: string;
  source?: string;
  action_type?: string;
  role_name?: string;
  scope?: string;
  roles?: string[];
}

interface RemediationStats {
  open: number;
  critical: number;
  in_progress: number;
  completed_this_week: number;
}

interface PlaybookRef {
  id: number;
  name: string;
  trigger_type: string;
  enabled: boolean;
}

const STATUS_OPTIONS = ['all', 'new', 'planned', 'in_progress', 'verified', 'closed'];
const PRIORITY_OPTIONS = ['all', 'critical', 'high', 'medium', 'low'];

// ── Script generation (PowerShell + Azure CLI) ──
function generateScript(a: RemediationAction, format: 'powershell' | 'azure_cli' | 'terraform_note'): string {
  const name = a.identity_name || '(unknown)';
  const objId = a.identity_id || '';
  const roleRaw = a.role_name || '';
  const scope = a.scope || '';
  const auditId = String(a.id).slice(0, 8);

  // Split comma-separated roles into individual entries
  const roles = roleRaw.split(',').map(r => r.trim()).filter(Boolean);

  // For actions that require role/scope, fail with helpful error if missing
  const roleRequired = ['reduce_privilege', 'remove_rbac_role', 'privilege_drift_reduce_privilege', 'access_review'];
  if (a.action_type && roleRequired.includes(a.action_type) && (roles.length === 0 || !scope)) {
    if (format === 'terraform_note') return '# Role data unavailable — run a new discovery scan.';
    if (format === 'powershell') return (
      `# ERROR: Role/scope data not available in AuditGraph.\n` +
      `# Run a new discovery scan to populate role data, then regenerate.\n` +
      `# Identity: ${name}\n` +
      `#\n` +
      `# To manually find roles for this identity:\n` +
      `Get-AzRoleAssignment -ObjectId "${objId}" | Format-Table RoleDefinitionName, Scope`
    );
    return (
      `# ERROR: Role/scope data not available.\n` +
      `# az role assignment list --assignee "${objId}" -o table`
    );
  }

  const roleDisplay = roles.join(', ');

  if (format === 'terraform_note') {
    if (a.action_type === 'reduce_privilege') {
      const tfLines = roles.map(r => `#   role_definition_name = "${r}"`).join('\n');
      return `# Terraform: Remove azurerm_role_assignment block(s):\n${tfLines}\n#   principal_id = "${objId}"\n#   scope = "${scope}"\n# Then: terraform plan && terraform apply`;
    }
    if (a.action_type === 'disable_identity') return '# Terraform: Set account_enabled = false on the azuread_user resource.';
    if (a.action_type === 'remove_identity') return '# Terraform: Remove the azuread_service_principal and azuread_application resources.';
    if (a.action_type === 'rotate_credential') return '# Terraform: Update the azuread_application_password resource end_date.';
    return `# No Terraform guidance for action: ${a.action_type}`;
  }

  const ps = format === 'powershell';

  if (a.action_type === 'reduce_privilege') {
    if (ps) {
      const psBlocks = roles.map((r, i) =>
`# --- Role ${i + 1}/${roles.length}: ${r} ---
$existing${i} = Get-AzRoleAssignment \`
  -ObjectId "${objId}" \`
  -RoleDefinitionName "${r}" \`
  -Scope "${scope}" \`
  -ErrorAction SilentlyContinue

if ($existing${i}) {
  Write-Host "Removing ${r} from ${name}..." -ForegroundColor Cyan
  Remove-AzRoleAssignment \`
    -ObjectId "${objId}" \`
    -RoleDefinitionName "${r}" \`
    -Scope "${scope}"
  Write-Host "Removed ${r}" -ForegroundColor Green
} else {
  Write-Host "${r} not found — may already be removed" -ForegroundColor Yellow
}`).join('\n\n');

      return `# ============================================
# AuditGraph Trust AI — Remove RBAC Role(s)
# Identity:  ${name}
# Roles:     ${roleDisplay}  (${roles.length} role(s))
# Scope:     ${scope}
# Audit ID:  ${auditId}
# ============================================

Connect-AzAccount

${psBlocks}

# Verify all removals
Write-Host "\`nRemaining assignments at this scope:" -ForegroundColor Cyan
Get-AzRoleAssignment -ObjectId "${objId}" |
  Where-Object {$_.Scope -eq "${scope}"} |
  Select-Object RoleDefinitionName, Scope`;
    }

    // Azure CLI
    const cliBlocks = roles.map(r =>
`# Remove ${r}
ASSIGN_ID=$(az role assignment list \\
  --assignee "${objId}" --role "${r}" \\
  --scope "${scope}" --query "[0].id" -o tsv)
[ -n "$ASSIGN_ID" ] && az role assignment delete --ids "$ASSIGN_ID" \\
  && echo "Removed ${r}" || echo "${r} not found"`).join('\n\n');

    return `# AuditGraph — Remove RBAC Role(s) (Azure CLI)
# Identity: ${name} | Roles: ${roleDisplay}

${cliBlocks}

# Verify:
az role assignment list --assignee "${objId}" \\
  --scope "${scope}" -o table`;
  }

  if (a.action_type === 'rotate_credential') {
    return ps
? `# AuditGraph Trust AI — Rotate Credential
# Identity: ${name} (${objId}) | Audit ID: ${auditId}

Connect-MgGraph -Scopes "Application.ReadWrite.All"

$app = Get-MgApplication -Filter "appId eq '${objId}'"

# Remove expired credentials
$app.PasswordCredentials | Where-Object { $_.EndDateTime -lt (Get-Date) } | ForEach-Object {
  Remove-MgApplicationPassword -ApplicationId $app.Id -KeyId $_.KeyId
  Write-Host "Removed expired: $($_.DisplayName)" -ForegroundColor Yellow
}

# Add new credential (90-day expiry)
$newCred = Add-MgApplicationPassword -ApplicationId $app.Id \`
  -PasswordCredential @{
    DisplayName = "AuditGraph-Rotated-$(Get-Date -Format yyyyMMdd)"
    EndDateTime = (Get-Date).AddDays(90)
  }

Write-Host "New secret: $($newCred.SecretText)" -ForegroundColor Red`
: `# AuditGraph — Rotate Credentials (Azure CLI)
APP_ID=$(az ad sp show --id "${objId}" --query appId -o tsv)
az ad app credential list --id "$APP_ID" -o table
az ad app credential reset --id "$APP_ID" --years 1`;
  }

  if (a.action_type === 'remove_identity') {
    return ps
? `# AuditGraph Trust AI — Remove Orphaned SPN
# Identity: ${name} (${objId}) | Audit ID: ${auditId}

Connect-AzAccount

$spn = Get-AzADServicePrincipal -DisplayName "${name}"

# Remove all role assignments first
Get-AzRoleAssignment -ObjectId $spn.Id | ForEach-Object {
  Write-Host "Removing: $($_.RoleDefinitionName) at $($_.Scope)"
  Remove-AzRoleAssignment -ObjectId $spn.Id \`
    -RoleDefinitionName $_.RoleDefinitionName -Scope $_.Scope
}

# Remove the service principal
Remove-AzADServicePrincipal -ObjectId $spn.Id -Confirm
Write-Host "SPN removed. Audit ID: ${auditId}" -ForegroundColor Green`
: `# AuditGraph — Remove Orphaned SPN (Azure CLI)
az role assignment list --assignee "${objId}" --query "[].id" -o tsv | \\
  xargs -I {} az role assignment delete --ids {}
az ad sp delete --id "${objId}"`;
  }

  if (a.action_type === 'access_review') {
    return ps
? `# AuditGraph Trust AI — Access Review
# Identity: ${name} (${objId}) | Roles: ${roleDisplay} | Audit ID: ${auditId}

Connect-MgGraph -Scopes "AccessReview.ReadWrite.All"

# List all role assignments for review
Get-AzRoleAssignment -ObjectId "${objId}" | Format-Table RoleDefinitionName, Scope

# Check Entra directory roles
Get-MgDirectoryRole | ForEach-Object {
  $members = Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id
  if ($members.Id -contains "${objId}") {
    Write-Host "Entra role: $($_.DisplayName)" -ForegroundColor Yellow
  }
}

Write-Host "ACTION: Verify business justification for all privileged roles" -ForegroundColor Red`
: `# AuditGraph — Access Review (Azure CLI)
az role assignment list --assignee "${objId}" -o table
# Remove as needed:
# az role assignment delete --assignee "${objId}" --role "<RoleName>" --scope "<Scope>"`;
  }

  if (a.action_type === 'break_attack_path') {
    return ps
? `# AuditGraph Trust AI — Break Attack Path
# Identity: ${name} (${objId}) | Audit ID: ${auditId}

Connect-AzAccount

$escalation = Get-AzRoleAssignment -ObjectId "${objId}" | Where-Object {
  $_.RoleDefinitionName -in @(
    "Owner", "User Access Administrator", "Contributor",
    "Privileged Role Administrator", "Global Administrator"
  )
}
$escalation | Format-Table RoleDefinitionName, Scope

# Remove broadest-scope privileged role (weakest link)
$weakest = $escalation | Sort-Object { $_.Scope.Length } | Select-Object -First 1
if ($weakest) {
  Write-Host "Removing: $($weakest.RoleDefinitionName) at $($weakest.Scope)" -ForegroundColor Yellow
  Remove-AzRoleAssignment \`
    -ObjectId "${objId}" \`
    -RoleDefinitionName $weakest.RoleDefinitionName \`
    -Scope $weakest.Scope
  Write-Host "Attack path broken." -ForegroundColor Green
}`
: `# AuditGraph — Break Attack Path (Azure CLI)
az role assignment list --assignee "${objId}" \\
  --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor']" -o table
# Remove the broadest-scope assignment:
# az role assignment delete --assignee "${objId}" --role "<RoleName>" --scope "<Scope>"`;
  }

  if (a.action_type === 'disable_identity') {
    return ps
? `# AuditGraph Trust AI — Disable Stale Identity
# Identity: ${name} (${objId}) | Audit ID: ${auditId}

Connect-MgGraph -Scopes "User.ReadWrite.All"

# Disable the account
Update-MgUser -UserId "${objId}" -AccountEnabled:$false

# Remove all privileged role assignments
Get-AzRoleAssignment -ObjectId "${objId}" | ForEach-Object {
  Remove-AzRoleAssignment -ObjectId "${objId}" \`
    -RoleDefinitionName $_.RoleDefinitionName -Scope $_.Scope
}

$user = Get-MgUser -UserId "${objId}" -Property AccountEnabled
Write-Host "Account enabled: $($user.AccountEnabled)"`
: `# AuditGraph — Disable Identity (Azure CLI)
az ad user update --id "${objId}" --account-enabled false
az role assignment list --assignee "${objId}" --query "[].id" -o tsv | \\
  xargs -I {} az role assignment delete --ids {}`;
  }

  // Fallback
  return ps
    ? `# AuditGraph — ${a.action_type || 'Remediation'}\n# Identity: ${name}\n# No automated script for this action type.\n# Review AuditGraph recommendations and apply manually.`
    : `# No Azure CLI script for action: ${a.action_type}`;
}

export default function RemediationCenter() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { withConnection, selectedConnectionId } = useConnection();

  const [showTicketModal, setShowTicketModal] = useState(false);
  const [showPreviewModal, setShowPreviewModal] = useState(false);
  const [scriptTab, setScriptTab] = useState<'powershell' | 'azure_cli' | 'terraform_note'>('powershell');
  const [scriptCopied, setScriptCopied] = useState(false);

  const [stats, setStats] = useState<RemediationStats>({ open: 0, critical: 0, in_progress: 0, completed_this_week: 0 });
  const [actions, setActions] = useState<RemediationAction[]>([]);
  const [playbooks, setPlaybooks] = useState<PlaybookRef[]>([]);
  const [loading, setLoading] = useState(true);
  const [isGenerating, setIsGenerating] = useState(false);
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') || 'all');
  const [priorityFilter, setPriorityFilter] = useState(searchParams.get('priority') || 'all');
  const [selectedAction, setSelectedAction] = useState<RemediationAction | null>(null);
  const [msExcludedCount, setMsExcludedCount] = useState(0);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [generatedRes, playbookRes] = await Promise.all([
        fetch(withConnection('/api/remediation/generated')),
        fetch(withConnection('/api/soar/playbooks')),
      ]);

      // Primary source: auto-generated remediations from risk tables
      const genData = generatedRes.ok ? await generatedRes.json() : { actions: [], stats: {} };
      setMsExcludedCount(genData.microsoft_excluded_count || 0);

      setPlaybooks((playbookRes.ok ? (await playbookRes.json()).playbooks || [] : []).map((p: any) => ({
        id: p.id, name: p.name, trigger_type: p.trigger_type, enabled: p.enabled,
      })));

      // Single source of truth: generated_remediations table only
      const remediations: RemediationAction[] = (genData.actions || []).map((a: any) => ({
        id: a.id,
        title: a.title || 'Remediation Action',
        description: a.description || '',
        risk_reduction: a.risk_reduction || 0,
        affected_count: a.affected_count || 1,
        blast_radius: a.blast_radius || 'unknown',
        automation_ready: a.automation_ready ?? false,
        confidence: a.confidence || 0,
        status: a.status || 'new',
        priority: a.priority || 'medium',
        identity_id: a.identity_id,
        identity_name: a.identity_name,
        playbook_id: a.playbook_id,
        playbook_name: a.playbook_name,
        created_at: a.created_at,
        action_type: a.action_type,
        role_name: a.role_name,
        scope: a.scope,
        roles: a.roles,
      }));

      // Auto-generate if empty
      if (remediations.length === 0 && !isGenerating) {
        triggerGeneration();
        return;
      }

      setActions(remediations);

      // Use backend-computed stats (authoritative, from generated_remediations table)
      setStats({
        open: genData.stats?.open ?? remediations.filter(a => ['new', 'planned', 'in_progress'].includes(a.status)).length,
        critical: genData.stats?.critical ?? remediations.filter(a => a.priority === 'critical').length,
        in_progress: genData.stats?.in_progress ?? remediations.filter(a => a.status === 'in_progress').length,
        completed_this_week: genData.stats?.completed_this_week ?? 0,
      });
    } catch {
      // silent
    } finally {
      setLoading(false);
    }
  }, [withConnection, selectedConnectionId]); // eslint-disable-line react-hooks/exhaustive-deps

  const triggerGeneration = useCallback(async () => {
    setIsGenerating(true);
    try {
      await fetch(withConnection('/api/remediation/generate'), { method: 'POST' });
      // Re-fetch after generation
      const res = await fetch(withConnection('/api/remediation/generated'));
      if (res.ok) {
        const data = await res.json();
        const generated = (data.actions || []).map((a: any) => ({
          id: a.id, title: a.title || 'Remediation Action', description: a.description || '',
          risk_reduction: a.risk_reduction || 0, affected_count: a.affected_count || 1,
          blast_radius: a.blast_radius || 'unknown', automation_ready: a.automation_ready ?? false,
          confidence: a.confidence || 0, status: a.status || 'new', priority: a.priority || 'medium',
          identity_id: a.identity_id, identity_name: a.identity_name,
          playbook_id: a.playbook_id, playbook_name: a.playbook_name, created_at: a.created_at,
          action_type: a.action_type, role_name: a.role_name, scope: a.scope, roles: a.roles,
        }));
        setActions(generated);
        setStats({
          open: generated.filter((a: RemediationAction) => ['new', 'planned', 'in_progress'].includes(a.status)).length,
          critical: generated.filter((a: RemediationAction) => a.priority === 'critical').length,
          in_progress: generated.filter((a: RemediationAction) => a.status === 'in_progress').length,
          completed_this_week: 0,
        });
      }
    } catch { /* silent */ }
    finally { setIsGenerating(false); }
  }, [withConnection]);

  const updateStatus = useCallback(async (actionId: number, newStatus: string) => {
    // Optimistic update
    setActions(prev => prev.map(a => a.id === actionId ? { ...a, status: newStatus } : a));
    try {
      await fetch(withConnection(`/api/remediation/generated/${actionId}`), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      });
    } catch { /* revert on error would go here */ }
  }, [withConnection]);

  useEffect(() => { fetchData(); }, [fetchData]);

  // Sync filter from URL
  useEffect(() => {
    const s = searchParams.get('status');
    if (s && STATUS_OPTIONS.includes(s)) setStatusFilter(s);
  }, [searchParams]);

  const filtered = actions.filter(a => {
    // Hide items with 0% confidence AND 0 risk reduction
    if (!shouldShowRemediation({ confidence: a.confidence, riskReduction: a.risk_reduction })) return false;
    if (statusFilter !== 'all' && a.status !== statusFilter) return false;
    if (priorityFilter !== 'all' && a.priority !== priorityFilter) return false;
    return true;
  });

  const summaryCards: { label: string; value: number; color: string; filterVal: string }[] = [
    { label: 'Open Remediations', value: stats.open, color: '#42A5F5', filterVal: 'new' },
    { label: 'Critical Priority', value: stats.critical, color: '#FF1744', filterVal: 'critical' },
    { label: 'In Progress', value: stats.in_progress, color: '#FFB300', filterVal: 'in_progress' },
    { label: 'Completed This Week', value: stats.completed_this_week, color: '#4ADE80', filterVal: 'closed' },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-4">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold" style={{ color: R.text }}>Remediation Center</h2>
        <p className="text-sm mt-1" style={{ color: R.textSecondary }}>
          Prioritized remediation actions with risk reduction scoring and automation readiness
        </p>
        <SnapshotContextHeader />
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {summaryCards.map(card => (
          <button
            key={card.label}
            onClick={() => setStatusFilter(card.filterVal)}
            className="rounded-xl border p-5 text-left transition hover:shadow-md cursor-pointer"
            style={{ backgroundColor: R.surface, borderColor: R.surfaceBorder }}
          >
            <p className="text-xs font-medium uppercase tracking-wider" style={{ color: R.textMuted }}>
              {card.label}
            </p>
            <p className="text-3xl font-bold mt-2" style={{ color: card.color }}>
              {loading ? '—' : card.value.toLocaleString()}
            </p>
          </button>
        ))}
      </div>

      {/* Microsoft exclusion banner */}
      {msExcludedCount > 0 && (
        <div
          className="flex items-center gap-3 rounded-lg border px-4 py-3"
          style={{
            backgroundColor: 'rgba(59, 130, 246, 0.06)',
            borderColor: 'rgba(59, 130, 246, 0.2)',
          }}
        >
          <svg className="w-4 h-4 flex-shrink-0" style={{ color: '#60A5FA' }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
            <span className="font-semibold" style={{ color: '#60A5FA' }}>
              {msExcludedCount} Microsoft/system {msExcludedCount === 1 ? 'identity' : 'identities'}
            </span>{' '}
            automatically excluded to prevent unsafe remediation actions.
          </p>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1.5">
          <span className="text-xs font-medium" style={{ color: R.textMuted }}>Status:</span>
          {STATUS_OPTIONS.map(s => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                statusFilter === s
                  ? 'text-white'
                  : 'border text-gray-600 dark:text-slate-300 hover:bg-gray-100 dark:hover:bg-slate-800'
              }`}
              style={statusFilter === s ? {
                backgroundColor: s === 'all' ? '#64748B' : (R.status[s] || '#64748B'),
              } : { borderColor: R.surfaceBorder }}
            >
              {s === 'all' ? 'All' : s.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase())}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-xs font-medium" style={{ color: R.textMuted }}>Priority:</span>
          {PRIORITY_OPTIONS.map(p => (
            <button
              key={p}
              onClick={() => setPriorityFilter(p)}
              className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                priorityFilter === p
                  ? 'text-white'
                  : 'border text-gray-600 dark:text-slate-300 hover:bg-gray-100 dark:hover:bg-slate-800'
              }`}
              style={priorityFilter === p ? {
                backgroundColor: p === 'all' ? '#64748B' : (R.priority[p] || '#64748B'),
              } : { borderColor: R.surfaceBorder }}
            >
              {p === 'all' ? 'All' : p.charAt(0).toUpperCase() + p.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Main content: table + optional detail panel */}
      <div className="flex gap-4">
        {/* Table */}
        <div className={`flex-1 min-w-0 rounded-xl border overflow-hidden ${selectedAction ? 'max-w-[calc(100%-420px)]' : ''}`}
          style={{ backgroundColor: R.surface, borderColor: R.surfaceBorder }}>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b" style={{ borderColor: R.surfaceBorder }}>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: R.textMuted }}>Action</th>
                  <th className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider" style={{ color: R.textMuted }}>Priority</th>
                  <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wider" style={{ color: R.textMuted }}>Risk Reduction</th>
                  <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wider" style={{ color: R.textMuted }}>Affected</th>
                  <th className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider" style={{ color: R.textMuted }}>Blast Radius</th>
                  <th className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider" style={{ color: R.textMuted }}>Automation</th>
                  <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wider relative group" style={{ color: R.textMuted }}>
                    AI Confidence
                    <span className="ml-1 cursor-help" title="AI-generated confidence score: ≥85% High (green), 65-84% Medium (amber), <65% Low (orange)">&#9432;</span>
                  </th>
                  <th className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider" style={{ color: R.textMuted }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {loading || isGenerating ? (
                  <tr><td colSpan={8} className="px-4 py-12 text-center" style={{ color: R.textMuted }}>
                    <div className="animate-spin h-6 w-6 border-2 border-blue-600 border-t-transparent rounded-full mx-auto" />
                    {isGenerating && <p className="mt-2 text-xs">Generating remediation actions...</p>}
                  </td></tr>
                ) : filtered.length === 0 ? (
                  <tr><td colSpan={8} className="px-4 py-12 text-center" style={{ color: R.textMuted }}>No remediation actions found</td></tr>
                ) : filtered.map(a => (
                  <tr
                    key={a.id}
                    onClick={() => setSelectedAction(a)}
                    className="border-b cursor-pointer transition-colors hover:bg-gray-50 dark:hover:bg-slate-800/50"
                    style={{ borderColor: R.surfaceBorder }}
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="font-medium" style={{ color: R.text }}>{a.title}</span>
                        {a.source && (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-medium bg-indigo-50 text-indigo-600 dark:bg-indigo-900/30 dark:text-indigo-300 whitespace-nowrap">
                            {a.source.replace('_', ' ')}
                          </span>
                        )}
                      </div>
                      {a.identity_name && (
                        <div className="text-xs mt-0.5">
                          {a.identity_id ? (
                            <span
                              onClick={(e) => { e.stopPropagation(); navigate(`/identities/${a.identity_id}`); }}
                              style={{ color: '#60A5FA', cursor: 'pointer', opacity: 0.9 }}
                              title="View identity details"
                            >
                              {a.identity_name}
                            </span>
                          ) : (
                            <span style={{ color: R.textMuted }}>{a.identity_name}</span>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3 text-center">
                      <span className="px-2 py-0.5 rounded-full text-xs font-medium" style={{
                        backgroundColor: `${R.priority[a.priority] || '#64748B'}18`,
                        color: R.priority[a.priority] || '#64748B',
                      }}>
                        {a.priority.charAt(0).toUpperCase() + a.priority.slice(1)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right font-mono font-bold" style={{ color: '#4ADE80' }}>
                      +{a.risk_reduction}
                    </td>
                    <td className="px-4 py-3 text-right font-mono" style={{ color: R.text }}>
                      {a.affected_count}
                    </td>
                    <td className="px-4 py-3 text-center">
                      <span className="px-2 py-0.5 rounded-full text-xs font-medium" style={{
                        backgroundColor: a.blast_radius === 'high' ? 'rgba(255,23,68,0.12)' : a.blast_radius === 'medium' ? 'rgba(255,179,0,0.12)' : 'rgba(74,222,128,0.12)',
                        color: a.blast_radius === 'high' ? '#FF1744' : a.blast_radius === 'medium' ? '#FFB300' : '#4ADE80',
                      }}>
                        {a.blast_radius}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-center">
                      {a.automation_ready ? (
                        <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300">Ready</span>
                      ) : (
                        <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-500 dark:bg-slate-700 dark:text-slate-400">Manual</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right font-mono" style={{ color: a.confidence === 0 ? 'var(--text-muted)' : a.confidence >= 85 ? '#4ADE80' : a.confidence >= 65 ? '#FFB300' : '#FF6D00' }}>
                      {a.confidence}%
                    </td>
                    <td className="px-4 py-3 text-center" onClick={e => e.stopPropagation()}>
                      <select
                        value={a.status}
                        onChange={e => updateStatus(a.id, e.target.value)}
                        className="text-xs font-medium rounded px-2 py-1 cursor-pointer border"
                        style={{
                          background: 'transparent',
                          borderColor: R.status[a.status] || '#64748B',
                          color: R.status[a.status] || '#64748B',
                        }}
                      >
                        <option value="new">New</option>
                        <option value="planned">Planned</option>
                        <option value="in_progress">In Progress</option>
                        <option value="verified">Verified</option>
                        <option value="closed">Closed</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Detail Panel */}
        {selectedAction && (
          <div className="w-[400px] flex-shrink-0 rounded-xl border overflow-y-auto" style={{
            backgroundColor: R.surface, borderColor: R.surfaceBorder, maxHeight: 'calc(100vh - 240px)',
          }}>
            <div className="p-5 space-y-5">
              {/* Header */}
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="font-bold text-lg" style={{ color: R.text }}>{selectedAction.title}</h3>
                  {selectedAction.playbook_name && (
                    <p className="text-xs mt-1" style={{ color: R.textMuted }}>Playbook: {selectedAction.playbook_name}</p>
                  )}
                </div>
                <button onClick={() => setSelectedAction(null)} className="p-1 rounded hover:bg-gray-100 dark:hover:bg-slate-800">
                  <svg className="w-4 h-4" style={{ color: R.textMuted }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              {/* Identity name link */}
              {selectedAction.identity_name && selectedAction.identity_id && (
                <p className="text-sm" style={{ color: R.textSecondary }}>
                  Identity:{' '}
                  <span
                    onClick={() => navigate(`/identities/${selectedAction.identity_id}`)}
                    style={{ color: R.accent, cursor: 'pointer', opacity: 0.9 }}
                  >
                    {selectedAction.identity_name}
                  </span>
                </p>
              )}

              {/* Description */}
              {selectedAction.description && (
                <p className="text-sm" style={{ color: R.textSecondary }}>{selectedAction.description}</p>
              )}

              {/* Metrics */}
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg p-3 border" style={{ borderColor: R.surfaceBorder }}>
                  <p className="text-[10px] uppercase tracking-wider" style={{ color: R.textMuted }}>Risk Reduction</p>
                  <p className="text-xl font-bold" style={{ color: '#4ADE80' }}>+{selectedAction.risk_reduction}</p>
                </div>
                <div className="rounded-lg p-3 border" style={{ borderColor: R.surfaceBorder }}>
                  <p className="text-[10px] uppercase tracking-wider" style={{ color: R.textMuted }}>AI Confidence</p>
                  <p className="text-xl font-bold" style={{ color: selectedAction.confidence >= 85 ? '#4ADE80' : selectedAction.confidence >= 65 ? '#FFB300' : '#FF6D00' }}>{selectedAction.confidence}%</p>
                </div>
                <div className="rounded-lg p-3 border" style={{ borderColor: R.surfaceBorder }}>
                  <p className="text-[10px] uppercase tracking-wider" style={{ color: R.textMuted }}>Affected</p>
                  <p className="text-xl font-bold" style={{ color: R.text }}>{selectedAction.affected_count}</p>
                </div>
                <div className="rounded-lg p-3 border" style={{ borderColor: R.surfaceBorder }}>
                  <p className="text-[10px] uppercase tracking-wider" style={{ color: R.textMuted }}>Status</p>
                  <p className="text-sm font-bold" style={{ color: R.status[selectedAction.status] || '#64748B' }}>
                    {selectedAction.status.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase())}
                  </p>
                </div>
              </div>

              {/* Identity link */}
              {selectedAction.identity_id && (
                <button
                  onClick={() => navigate(`/identities/${selectedAction.identity_id}`)}
                  className="w-full px-4 py-2.5 rounded-lg border text-sm font-medium transition hover:shadow-sm"
                  style={{ borderColor: R.surfaceBorder, color: R.accent }}
                >
                  View Identity Detail
                </button>
              )}

              {/* Action buttons */}
              <div className="flex gap-2">
                <button
                  onClick={() => setShowTicketModal(true)}
                  className="flex-1 px-4 py-2 rounded-lg text-xs font-medium text-white transition hover:opacity-90"
                  style={{ backgroundColor: R.accent }}
                >
                  Create Ticket
                </button>
                <button
                  onClick={() => { setScriptTab('powershell'); setScriptCopied(false); setShowPreviewModal(true); }}
                  className="flex-1 px-4 py-2 rounded-lg text-xs font-medium border transition hover:bg-gray-50 dark:hover:bg-slate-800"
                  style={{ borderColor: R.surfaceBorder, color: R.text }}
                >
                  Preview Script
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Playbooks reference */}
      {playbooks.length > 0 && (
        <div className="rounded-xl border p-5" style={{ backgroundColor: R.surface, borderColor: R.surfaceBorder }}>
          <h3 className="text-sm font-semibold mb-3" style={{ color: R.text }}>Available Playbooks</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {playbooks.map(pb => (
              <div key={pb.id} className="rounded-lg border px-4 py-3 flex items-center justify-between" style={{ borderColor: R.surfaceBorder }}>
                <div>
                  <p className="text-sm font-medium" style={{ color: R.text }}>{pb.name}</p>
                  <p className="text-xs" style={{ color: R.textMuted }}>{pb.trigger_type}</p>
                </div>
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${
                  pb.enabled ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300' : 'bg-gray-100 text-gray-500 dark:bg-slate-700 dark:text-slate-400'
                }`}>
                  {pb.enabled ? 'Active' : 'Disabled'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Create Ticket Modal ── */}
      {showTicketModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ backdropFilter: 'blur(4px)' }}>
          <div className="absolute inset-0 bg-black/50" onClick={() => setShowTicketModal(false)} />
          <div className="relative w-full max-w-md rounded-xl border shadow-2xl p-6" style={{ backgroundColor: R.surface, borderColor: R.surfaceBorder }}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold" style={{ color: R.text }}>Connect Ticketing System</h3>
              <button onClick={() => setShowTicketModal(false)} className="p-1 rounded hover:bg-gray-100 dark:hover:bg-slate-800">
                <svg className="w-5 h-5" style={{ color: R.textMuted }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <p className="text-sm mb-5" style={{ color: R.textSecondary }}>
              Connect your ticketing system to automatically create remediation tickets from AuditGraph findings.
            </p>
            <div className="space-y-3">
              {[
                { name: 'ServiceNow', icon: '🔧', desc: 'ITSM & incident management' },
                { name: 'Jira', icon: '📋', desc: 'Issue tracking & project management' },
                { name: 'Azure DevOps', icon: '⚡', desc: 'Boards & work items' },
                { name: 'PagerDuty', icon: '🔔', desc: 'Incident response & alerting' },
              ].map(t => (
                <button
                  key={t.name}
                  className="w-full flex items-center gap-3 p-3 rounded-lg border text-left transition hover:shadow-sm hover:border-purple-300 dark:hover:border-purple-600"
                  style={{ borderColor: R.surfaceBorder }}
                  onClick={() => {
                    setShowTicketModal(false);
                    navigate('/settings#integrations');
                  }}
                >
                  <span className="text-2xl">{t.icon}</span>
                  <div>
                    <p className="text-sm font-semibold" style={{ color: R.text }}>{t.name}</p>
                    <p className="text-xs" style={{ color: R.textMuted }}>{t.desc}</p>
                  </div>
                  <span className="ml-auto text-xs px-2 py-0.5 rounded-full bg-gray-100 dark:bg-slate-700" style={{ color: R.textMuted }}>
                    Configure
                  </span>
                </button>
              ))}
            </div>
            <p className="text-xs mt-4" style={{ color: R.textMuted }}>
              Configure integrations in Settings to enable one-click ticket creation.
            </p>
          </div>
        </div>
      )}

      {/* ── Preview Script Modal (tabbed: PowerShell / Azure CLI / Terraform Notes) ── */}
      {showPreviewModal && selectedAction && (() => {
        const currentScript = generateScript(selectedAction, scriptTab);
        return (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ backdropFilter: 'blur(4px)' }}>
          <div className="absolute inset-0 bg-black/50" onClick={() => { setShowPreviewModal(false); setScriptTab('powershell'); }} />
          <div className="relative w-full max-w-[720px] rounded-xl shadow-2xl flex flex-col" style={{ backgroundColor: '#1E293B', border: '1px solid rgba(255,255,255,0.1)', maxHeight: '80vh' }}>
            {/* Header */}
            <div className="flex items-center justify-between p-4 border-b" style={{ borderColor: 'rgba(255,255,255,0.08)' }}>
              <div>
                <h3 className="text-[15px] font-semibold" style={{ color: '#F1F5F9' }}>Preview Remediation Script</h3>
                <p className="text-xs mt-0.5" style={{ color: '#64748B' }}>
                  {selectedAction.identity_name} — {(selectedAction.action_type || '').replace(/_/g, ' ')}
                  {selectedAction.role_name && <span> — {selectedAction.role_name}</span>}
                </p>
              </div>
              <button onClick={() => { setShowPreviewModal(false); setScriptTab('powershell'); }} style={{ background: 'none', border: 'none', color: '#94A3B8', cursor: 'pointer', fontSize: 20, lineHeight: 1 }}>✕</button>
            </div>
            {/* Warning banner */}
            <div className="mx-5 mt-3 px-3.5 py-2 rounded-md text-xs" style={{ backgroundColor: 'rgba(217,119,6,0.1)', border: '1px solid rgba(217,119,6,0.3)', color: '#FDE68A' }}>
              Review carefully before executing. This script will modify Azure IAM configuration.
            </div>
            {/* Tabs */}
            <div className="flex gap-1 px-5 pt-3 pb-0" style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
              {([
                { key: 'powershell' as const, label: 'PowerShell' },
                { key: 'azure_cli' as const, label: 'Azure CLI' },
                { key: 'terraform_note' as const, label: 'Terraform Notes' },
              ]).map(t => (
                <button key={t.key} onClick={() => setScriptTab(t.key)} className="text-[13px] px-3.5 py-1.5 rounded-t-md" style={{
                  background: scriptTab === t.key ? '#0F172A' : 'transparent',
                  border: scriptTab === t.key ? '1px solid rgba(255,255,255,0.1)' : '1px solid transparent',
                  borderBottom: 'none',
                  color: scriptTab === t.key ? '#F1F5F9' : '#94A3B8',
                  cursor: 'pointer', fontWeight: scriptTab === t.key ? 500 : 400,
                }}>{t.label}</button>
              ))}
            </div>
            {/* Code area */}
            <pre className="flex-1 overflow-auto m-0 px-5 py-4 text-xs leading-relaxed" style={{ backgroundColor: '#0F172A', color: '#7DD3FC', fontFamily: 'Courier New, monospace', whiteSpace: 'pre', minHeight: 280 }}>
              {currentScript}
            </pre>
            {/* Footer */}
            <div className="flex justify-end gap-2 p-3" style={{ borderTop: '1px solid rgba(255,255,255,0.08)' }}>
              <button
                onClick={() => { navigator.clipboard.writeText(currentScript); setScriptCopied(true); setTimeout(() => setScriptCopied(false), 2000); }}
                className="px-4 py-2 rounded-md text-[13px] font-medium"
                style={{ background: scriptCopied ? 'rgba(22,163,74,0.2)' : 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)', color: scriptCopied ? '#86EFAC' : '#E2E8F0', cursor: 'pointer' }}
              >
                {scriptCopied ? '✓ Copied!' : 'Copy to Clipboard'}
              </button>
              {scriptTab !== 'terraform_note' && (
                <button
                  onClick={() => {
                    const ext = scriptTab === 'powershell' ? 'ps1' : 'sh';
                    const blob = new Blob([currentScript], { type: 'text/plain' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url; a.download = `auditgraph-remediation-${selectedAction.id}.${ext}`;
                    a.click(); URL.revokeObjectURL(url);
                  }}
                  className="px-4 py-2 rounded-md text-[13px] font-medium"
                  style={{ background: 'rgba(37,99,235,0.2)', border: '1px solid rgba(37,99,235,0.4)', color: '#93C5FD', cursor: 'pointer' }}
                >
                  Download .{scriptTab === 'powershell' ? 'ps1' : 'sh'}
                </button>
              )}
            </div>
          </div>
        </div>
        );
      })()}
    </div>
  );
}
