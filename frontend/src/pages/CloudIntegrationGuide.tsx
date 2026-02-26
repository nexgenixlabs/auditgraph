import React, { useState } from 'react';

type CloudProvider = 'azure' | 'aws' | 'gcp';

interface StepItem {
  title: string;
  description: string;
  code?: string;
}

const AZURE_STEPS: StepItem[] = [
  {
    title: 'Create an App Registration in Entra ID',
    description: 'Go to Azure Portal > Entra ID > App registrations > New registration. Name it "AuditGraph Service Principal".',
  },
  {
    title: 'Grant API Permissions',
    description: 'Under API permissions, add the following Microsoft Graph Application permissions:',
    code: 'Directory.Read.All\nRoleManagement.Read.Directory\nPolicy.Read.All\nAuditLog.Read.All',
  },
  {
    title: 'Grant Admin Consent',
    description: 'Click "Grant admin consent for <your org>" to activate the permissions. A Global Admin or Privileged Role Administrator is required.',
  },
  {
    title: 'Create a Client Secret',
    description: 'Go to Certificates & secrets > New client secret. Copy the Value immediately — it will not be shown again.',
  },
  {
    title: 'Assign RBAC Reader Role',
    description: 'Go to your subscriptions > Access control (IAM) > Add role assignment. Assign "Reader" role to the App Registration for each subscription you want AuditGraph to monitor.',
    code: 'az role assignment create \\\n  --assignee <app-client-id> \\\n  --role Reader \\\n  --scope /subscriptions/<sub-id>',
  },
  {
    title: 'Enter Credentials in AuditGraph',
    description: 'Navigate to Settings > Connections and enter: Directory (Tenant) ID, Application (Client) ID, Client Secret Value.',
  },
  {
    title: 'Test & Run First Scan',
    description: 'Click "Test Connection" to verify connectivity. Once confirmed, trigger your first discovery scan.',
  },
];

const AWS_STEPS: StepItem[] = [
  {
    title: 'Create an IAM Role for AuditGraph',
    description: 'In the AWS Console, go to IAM > Roles > Create role. Select "Another AWS account" as the trusted entity.',
  },
  {
    title: 'Attach Read-Only Policies',
    description: 'Attach the following AWS managed policies:',
    code: 'arn:aws:iam::aws:policy/SecurityAudit\narn:aws:iam::aws:policy/IAMReadOnlyAccess\narn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess',
  },
  {
    title: 'Configure External ID',
    description: 'Set the External ID to your AuditGraph tenant ID. This prevents confused deputy attacks.',
  },
  {
    title: 'Enter Role ARN in AuditGraph',
    description: 'Copy the Role ARN and enter it in Settings > Connections > Add AWS Connection.',
    code: 'arn:aws:iam::<account-id>:role/AuditGraphReader',
  },
];

const GCP_STEPS: StepItem[] = [
  {
    title: 'Create a Service Account',
    description: 'In GCP Console, go to IAM & Admin > Service Accounts > Create Service Account. Name it "auditgraph-reader".',
  },
  {
    title: 'Grant Viewer Role',
    description: 'Assign the "Viewer" role at the organization or project level.',
    code: 'gcloud projects add-iam-policy-binding <project-id> \\\n  --member="serviceAccount:auditgraph-reader@<project>.iam.gserviceaccount.com" \\\n  --role="roles/viewer"',
  },
  {
    title: 'Create and Download Key',
    description: 'Create a JSON key for the service account and upload it in AuditGraph Settings > Connections.',
  },
];

const CLOUD_CONFIGS: Record<CloudProvider, { label: string; color: string; borderColor: string; steps: StepItem[] }> = {
  azure: { label: 'Microsoft Azure', color: 'text-blue-400', borderColor: 'border-blue-500', steps: AZURE_STEPS },
  aws: { label: 'Amazon Web Services', color: 'text-orange-400', borderColor: 'border-orange-500', steps: AWS_STEPS },
  gcp: { label: 'Google Cloud', color: 'text-green-400', borderColor: 'border-green-500', steps: GCP_STEPS },
};

export default function CloudIntegrationGuide() {
  const [activeCloud, setActiveCloud] = useState<CloudProvider>('azure');
  const config = CLOUD_CONFIGS[activeCloud];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Cloud Integration Guide</h1>
        <p className="text-sm text-gray-400 mt-1">Step-by-step instructions for connecting your cloud environment</p>
      </div>

      {/* Cloud selector tabs */}
      <div className="flex gap-2">
        {(Object.keys(CLOUD_CONFIGS) as CloudProvider[]).map(key => {
          const cfg = CLOUD_CONFIGS[key];
          const active = activeCloud === key;
          const comingSoon = key !== 'azure';
          return (
            <button
              key={key}
              onClick={() => setActiveCloud(key)}
              className={`px-5 py-2.5 rounded-lg text-sm font-medium border-2 transition ${
                active
                  ? `${cfg.borderColor} bg-gray-800 text-white`
                  : 'border-gray-700 text-gray-400 hover:border-gray-600'
              }`}
            >
              {cfg.label}
              {comingSoon && <span className="ml-2 text-[9px] px-1.5 py-0.5 rounded bg-gray-700 text-gray-400 uppercase font-bold">Preview</span>}
            </button>
          );
        })}
      </div>

      {/* Prerequisites */}
      <div className="bg-blue-900/20 border border-blue-700 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-blue-400 mb-2">Prerequisites</h3>
        <ul className="text-xs text-blue-300 space-y-1 list-disc ml-4">
          {activeCloud === 'azure' && (
            <>
              <li>Azure subscription with Global Administrator or Application Administrator access</li>
              <li>Ability to grant admin consent for Microsoft Graph API permissions</li>
              <li>Subscription Owner/User Access Administrator to assign RBAC roles</li>
            </>
          )}
          {activeCloud === 'aws' && (
            <>
              <li>AWS account with IAM administrative access</li>
              <li>Ability to create IAM roles and policies</li>
            </>
          )}
          {activeCloud === 'gcp' && (
            <>
              <li>GCP project with Organization Administrator access</li>
              <li>Ability to create service accounts and manage IAM</li>
            </>
          )}
        </ul>
      </div>

      {/* Steps */}
      <div className="space-y-4">
        {config.steps.map((step, i) => (
          <div key={i} className="bg-ob-raised border border-gray-700 rounded-lg p-5">
            <div className="flex items-start gap-4">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold shrink-0 ${
                activeCloud === 'azure' ? 'bg-blue-600' :
                activeCloud === 'aws' ? 'bg-orange-600' :
                'bg-green-600'
              } text-white`}>
                {i + 1}
              </div>
              <div className="flex-1">
                <h4 className="text-sm font-semibold text-white">{step.title}</h4>
                <p className="text-xs text-gray-400 mt-1">{step.description}</p>
                {step.code && (
                  <pre className="mt-3 p-3 bg-gray-900 border border-gray-700 rounded-lg text-xs font-mono text-green-400 overflow-x-auto">
                    {step.code}
                  </pre>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Permissions summary */}
      {activeCloud === 'azure' && (
        <div className="bg-ob-raised border border-gray-700 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-white mb-3">Required Permissions Summary</h3>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-gray-400 border-b border-gray-700">
                <th className="pb-2 text-left font-medium">Permission</th>
                <th className="pb-2 text-left font-medium">Type</th>
                <th className="pb-2 text-left font-medium">Purpose</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              <tr><td className="py-2 text-blue-300 font-mono">Directory.Read.All</td><td className="py-2 text-gray-400">Application</td><td className="py-2 text-gray-400">Read users, groups, service principals</td></tr>
              <tr><td className="py-2 text-blue-300 font-mono">RoleManagement.Read.Directory</td><td className="py-2 text-gray-400">Application</td><td className="py-2 text-gray-400">Read PIM eligible/active assignments</td></tr>
              <tr><td className="py-2 text-blue-300 font-mono">Policy.Read.All</td><td className="py-2 text-gray-400">Application</td><td className="py-2 text-gray-400">Read Conditional Access policies</td></tr>
              <tr><td className="py-2 text-blue-300 font-mono">AuditLog.Read.All</td><td className="py-2 text-gray-400">Application</td><td className="py-2 text-gray-400">Read sign-in/audit logs (P2 telemetry)</td></tr>
              <tr><td className="py-2 text-blue-300 font-mono">Reader (RBAC)</td><td className="py-2 text-gray-400">Subscription</td><td className="py-2 text-gray-400">Read ARM resources, role assignments</td></tr>
            </tbody>
          </table>
        </div>
      )}

      {/* Help link */}
      <div className="text-center pt-4">
        <p className="text-xs text-gray-500">
          Need help? Contact{' '}
          <a href="mailto:support@auditgraph.ai" className="text-blue-400 hover:underline">support@auditgraph.ai</a>
        </p>
      </div>
    </div>
  );
}
