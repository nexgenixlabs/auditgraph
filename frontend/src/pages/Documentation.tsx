import React, { useState } from 'react';
import { Link } from 'react-router-dom';

type DocSection = {
  title: string;
  icon: string;
  items: { title: string; content: string }[];
};

const DOCS: DocSection[] = [
  {
    title: 'Getting Started',
    icon: 'M13 10V3L4 14h7v7l9-11h-7z',
    items: [
      {
        title: 'Quick Start Guide',
        content: `1. **Create your organization** — Log in to the portal and complete the onboarding wizard.\n2. **Connect a cloud provider** — Go to Settings > Identity Sources and add your Azure AD credentials (Client ID, Client Secret, Tenant ID).\n3. **Required Azure Permissions** — The app registration needs:\n   - \`Directory.Read.All\` (Application) — Read identities and groups\n   - \`RoleManagement.Read.Directory\` (Application) — Read PIM eligible assignments\n   - \`Policy.Read.All\` (Application) — Read Conditional Access policies\n   - \`AuditLog.Read.All\` (Application) — Read sign-in and audit logs\n   - Azure RBAC \`Reader\` on target subscriptions\n4. **Capture your first snapshot** — Click "Capture Snapshot" in the Dashboard or wait for the scheduled snapshot.\n5. **Review results** — Check the Risk Posture dashboard for critical findings.`,
      },
      {
        title: 'Understanding Risk Scores',
        content: `Every identity receives a risk score from 0 (minimal) to 100 (critical).\n\n**Score Ranges:**\n- **0-25 (Low):** Normal operational risk\n- **26-50 (Medium):** Elevated risk, review recommended\n- **51-75 (High):** Significant risk, remediation needed\n- **76-100 (Critical):** Immediate action required\n\n**Scoring Factors:**\n- Privilege level (Owner/Contributor roles add risk)\n- Credential health (expired secrets, no MFA)\n- Activity status (dormant accounts with high privileges)\n- Blast radius (number of subscriptions/resources accessible)\n- External exposure (guest/federated identities)\n\nCustom risk rules can be configured in Settings > Risk Scoring.`,
      },
      {
        title: 'Identity Categories',
        content: `AuditGraph classifies identities into six categories:\n\n- **Human Users** — Interactive users with Azure AD accounts\n- **Service Principals** — Application identities (custom SPNs)\n- **System Managed Identities** — Azure-assigned identities for resources\n- **User Managed Identities** — Customer-created managed identities\n- **Guest Users** — External/B2B collaboration accounts\n- **Microsoft Internal** — First-party Microsoft service accounts\n\nEach category has different risk thresholds and remediation playbooks.`,
      },
    ],
  },
  {
    title: 'Features',
    icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2',
    items: [
      {
        title: 'Risk Posture Dashboard',
        content: `The main dashboard provides:\n\n- **Posture Score** — Weighted security score based on all identity risks\n- **Credential Health** — Expired, expiring, and missing credentials\n- **Risk Heat Map** — Category × severity distribution matrix\n- **Compliance Scorecard** — Framework compliance percentages\n- **Conditional Access** — MFA coverage and policy gaps\n- **Recent Changes** — Latest drift events and configuration changes`,
      },
      {
        title: 'Access Reviews',
        content: `Create certification campaigns to review and approve/revoke identity access.\n\n1. Navigate to **Access Reviews** in the sidebar\n2. Click **Create Review** and configure scope (all identities, specific categories, or high-risk only)\n3. Assign reviewers and set a due date\n4. Reviewers approve or revoke each identity's access\n5. Bulk decisions are supported for efficiency\n6. Export review results as evidence for auditors`,
      },
      {
        title: 'Compliance Frameworks',
        content: `AuditGraph evaluates your identity posture against:\n\n- **SOC 2 Type II** — Trust services criteria (CC6.1-CC6.8)\n- **ISO 27001** — Information security controls (A.9)\n- **NIST 800-53** — Access control family (AC-2 through AC-25)\n- **CIS Azure Benchmark** — Identity and access management controls\n- **HIPAA Security Rule** — Access control standards (164.312)\n- **PCI DSS v4.0** — Requirement 7 & 8\n\nEnable/disable frameworks in Settings > Compliance. Export evidence packages in JSON (GRC-compatible) or ZIP format from the Evidence Center.`,
      },
      {
        title: 'SOAR Integration',
        content: `Automate remediation with Security Orchestration:\n\n- **Playbooks** — Define conditions and actions (disable identity, remove role, flag for review)\n- **Triggers** — Auto-execute on anomaly detection or drift events\n- **Cooldowns** — Prevent action storms with configurable cooldown periods\n- **Dry Run** — Test playbooks before enabling live execution\n- **Integrations** — Slack/Teams alerts, ServiceNow tickets, custom webhooks`,
      },
    ],
  },
  {
    title: 'Administration',
    icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z',
    items: [
      {
        title: 'User Management',
        content: `AuditGraph supports four client roles:\n\n| Role | Access |\n|------|--------|\n| **Admin** | Full access: settings, users, snapshots, exports, remediation |\n| **Security Admin** | Snapshots, remediation, exports — no user/org management |\n| **Compliance** | Read access + compliance reports and exports |\n| **Reader** | Read-only access to all dashboards and reports |\n\nManage users in **Settings > User Management**. Admins can create, edit, and disable user accounts.`,
      },
      {
        title: 'SSO / SAML Configuration',
        content: `Configure Single Sign-On for your organization:\n\n1. Go to **Settings > Security & SSO**\n2. Select your IdP (Azure AD, Okta, or custom SAML 2.0)\n3. Enter your IdP Metadata URL\n4. Map IdP groups to AuditGraph roles\n5. Enable **Force SSO** to require all users authenticate via your IdP\n\nJIT (Just-In-Time) provisioning automatically creates accounts on first SSO login.`,
      },
      {
        title: 'API Keys',
        content: `Generate API keys for programmatic access:\n\n1. Go to **Settings > API Keys**\n2. Click **Create API Key** and select the role scope\n3. Copy the key immediately (it's shown only once)\n4. Use the key in requests via \`X-API-Key\` header or \`Bearer ag_...\` authorization\n\nAPI keys support the same role-based access control as user accounts. Usage is tracked and keys can be disabled or deleted at any time.`,
      },
      {
        title: 'Data Retention',
        content: `Configure retention periods in **Settings > Data Retention**:\n\n| Data Type | Default | Configurable |\n|-----------|---------|-------------|\n| Snapshots | 90 days | Yes |\n| Drift Reports | 90 days | Yes |\n| Activity Logs | 365 days | Yes |\n| Anomalies | 180 days | Yes |\n| SOAR Actions | 90 days | Yes |\n| Notifications | 30 days | Yes |\n\nCleanup runs automatically at 03:00 UTC daily. Manual cleanup is available in Settings.`,
      },
    ],
  },
  {
    title: 'API Reference',
    icon: 'M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z',
    items: [
      {
        title: 'Authentication',
        content: `**Login:**\n\`\`\`\nPOST /api/auth/login\n{ "username": "...", "password": "...", "portal": "client" }\n→ { "access_token": "...", "refresh_token": "...", "user": {...} }\n\`\`\`\n\n**Refresh:**\n\`\`\`\nPOST /api/auth/refresh\n{ "refresh_token": "..." }\n→ { "access_token": "...", "refresh_token": "..." }\n\`\`\`\n\n**API Key Auth:**\nInclude \`X-API-Key: ag_...\` header in all requests.\n\nRate limits: 5 login attempts per minute per IP, 10 token refreshes per minute.`,
      },
      {
        title: 'Core Endpoints',
        content: `**Identity Endpoints:**\n- \`GET /api/identities\` — List identities (paginated, filterable)\n- \`GET /api/identities/:id\` — Full identity detail\n- \`POST /api/identities/query\` — Advanced query builder\n- \`GET /api/identities/:id/graph-data\` — Access graph visualization\n\n**Risk & Compliance:**\n- \`GET /api/stats\` — Latest run summary\n- \`GET /api/dashboard/posture\` — Posture score and credential health\n- \`GET /api/dashboard/compliance\` — Compliance scorecard\n- \`GET /api/compliance/frameworks\` — Framework details\n\n**Snapshots & Drift:**\n- \`GET /api/runs\` — Snapshot history\n- \`POST /api/runs/trigger\` — Trigger snapshot capture\n- \`GET /api/drift/latest\` — Latest drift report\n- \`GET /api/drift/history\` — Drift timeline`,
      },
      {
        title: 'Export Endpoints',
        content: `**Report Exports:**\n- \`GET /api/export/csv\` — Identity list as CSV\n- \`GET /api/export/pdf-full\` — Full audit report PDF\n- \`GET /api/export/pdf-executive\` — Executive summary PDF\n- \`GET /api/export/compliance\` — Compliance report\n- \`GET /api/export/evidence-json\` — GRC evidence package (JSON)\n- \`GET /api/export/evidence-zip\` — Complete evidence archive (ZIP)\n\nAll export endpoints require admin, security_admin, or compliance role.`,
      },
    ],
  },
];

export default function Documentation() {
  const [activeSection, setActiveSection] = useState(0);
  const [activeItem, setActiveItem] = useState(0);

  const section = DOCS[activeSection];
  const item = section.items[activeItem];

  return (
    <div className="min-h-screen bg-ob-surface text-gray-300">
      <div className="max-w-7xl mx-auto px-6 py-12">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-3xl font-bold text-white">Documentation</h1>
            <p className="text-sm text-gray-500 mt-1">AuditGraph Platform Guide</p>
          </div>
          <Link to="/" className="text-sm text-blue-400 hover:text-blue-300 transition">
            Back to Dashboard
          </Link>
        </div>

        <div className="flex gap-6">
          {/* Sidebar Navigation */}
          <div className="w-64 flex-shrink-0">
            <nav className="space-y-1">
              {DOCS.map((sec, si) => (
                <div key={si}>
                  <button
                    onClick={() => { setActiveSection(si); setActiveItem(0); }}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition ${
                      si === activeSection
                        ? 'bg-blue-600/20 text-blue-400'
                        : 'text-gray-400 hover:text-white hover:bg-gray-800/50'
                    }`}
                  >
                    <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={sec.icon} />
                    </svg>
                    {sec.title}
                  </button>
                  {si === activeSection && (
                    <div className="ml-6 mt-1 space-y-0.5">
                      {sec.items.map((itm, ii) => (
                        <button
                          key={ii}
                          onClick={() => setActiveItem(ii)}
                          className={`w-full text-left px-3 py-1.5 rounded text-xs transition ${
                            ii === activeItem
                              ? 'text-blue-400 bg-blue-600/10'
                              : 'text-gray-500 hover:text-gray-300'
                          }`}
                        >
                          {itm.title}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </nav>

            <div className="mt-8 border-t border-gray-800 pt-4 space-y-2">
              <Link to="/trust" className="block text-xs text-gray-500 hover:text-gray-300 transition">
                Trust Center
              </Link>
              <Link to="/privacy" className="block text-xs text-gray-500 hover:text-gray-300 transition">
                Privacy Policy
              </Link>
              <Link to="/terms" className="block text-xs text-gray-500 hover:text-gray-300 transition">
                Terms of Service
              </Link>
            </div>
          </div>

          {/* Content */}
          <div className="flex-1 bg-gray-900/50 border border-gray-800 rounded-xl p-8 min-h-[600px]">
            <h2 className="text-xl font-bold text-white mb-1">{item.title}</h2>
            <p className="text-xs text-gray-500 mb-6">{section.title}</p>
            <div className="prose prose-sm prose-invert max-w-none">
              {item.content.split('\n').map((line, i) => {
                if (line.startsWith('```')) return null;
                if (line.startsWith('# ')) return <h1 key={i} className="text-lg font-bold text-white mt-4 mb-2">{line.slice(2)}</h1>;
                if (line.startsWith('## ')) return <h2 key={i} className="text-base font-semibold text-white mt-4 mb-2">{line.slice(3)}</h2>;
                if (line.startsWith('**') && line.endsWith('**')) return <p key={i} className="font-semibold text-gray-200 mt-3 mb-1">{line.slice(2, -2)}</p>;

                // Table rendering
                if (line.startsWith('|') && line.endsWith('|')) {
                  const cells = line.split('|').filter(Boolean).map(c => c.trim());
                  if (cells.every(c => c.match(/^[-]+$/))) return null;
                  const isHeader = i > 0 && item.content.split('\n')[i + 1]?.match(/^\|[-| ]+\|$/);
                  return (
                    <div key={i} className="flex gap-4 py-1">
                      {cells.map((cell, ci) => (
                        <span key={ci} className={`flex-1 text-xs ${isHeader || ci === 0 ? 'font-semibold text-gray-200' : 'text-gray-400'}`}>
                          {cell.replace(/\*\*/g, '')}
                        </span>
                      ))}
                    </div>
                  );
                }

                // List items
                if (line.startsWith('- ')) {
                  const text = line.slice(2);
                  return (
                    <div key={i} className="flex gap-2 ml-2 mb-1">
                      <span className="text-gray-600 mt-1">-</span>
                      <span className="text-gray-400 text-xs">{text.replace(/\*\*(.*?)\*\*/g, '$1').replace(/`(.*?)`/g, '$1')}</span>
                    </div>
                  );
                }

                // Numbered items
                const numMatch = line.match(/^(\d+)\. (.*)/);
                if (numMatch) {
                  return (
                    <div key={i} className="flex gap-2 ml-2 mb-1">
                      <span className="text-blue-400 text-xs font-mono w-4">{numMatch[1]}.</span>
                      <span className="text-gray-400 text-xs">{numMatch[2].replace(/\*\*(.*?)\*\*/g, '$1').replace(/`(.*?)`/g, '$1')}</span>
                    </div>
                  );
                }

                // Code blocks
                if (line.startsWith('`') && line.endsWith('`') && line.length > 2) {
                  return <code key={i} className="block bg-gray-800 px-3 py-1 rounded text-xs text-green-400 font-mono my-1">{line.slice(1, -1)}</code>;
                }

                if (!line.trim()) return <div key={i} className="h-2" />;

                return <p key={i} className="text-gray-400 text-xs mb-1">{line.replace(/\*\*(.*?)\*\*/g, '$1').replace(/`(.*?)`/g, '$1')}</p>;
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
