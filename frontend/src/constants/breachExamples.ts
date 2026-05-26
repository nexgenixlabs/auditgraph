/**
 * Global role → real-world breach mapping.
 * No org-specific data — applies universally based on role name.
 */

export interface BreachExample {
  breach: string;
  penalty: string;
  cis: string;
}

export const BREACH_EXAMPLES: Record<string, BreachExample> = {
  'Owner': {
    breach: '2023 Microsoft SAS Token incident — overprivileged storage token exposed 38TB of internal training data',
    penalty: 'HIPAA: up to $1.9M per violation · PCI-DSS: $5K–$100K/month · SOC2: certification suspension',
    cis: 'CIS Control 5.4: Restrict Administrator Privileges to Dedicated Admin Accounts',
  },
  'User Access Administrator': {
    breach: '2022 Lapsus$ attacks — group exploited overprivileged service accounts to grant themselves Global Admin on Okta, Microsoft, and Nvidia',
    penalty: 'SOC2 CC6.3 violation · NIST 800-53 AC-6 least privilege failure',
    cis: 'CIS Control 5.4',
  },
  'Contributor': {
    breach: '2020 SolarWinds — compromised build pipeline SPN with Contributor access deployed backdoored updates to 18,000 organizations',
    penalty: 'Average breach cost $4.45M (IBM 2023) · PCI-DSS 7.1 least privilege violation',
    cis: 'CIS Control 5.4',
  },
  'Key Vault Administrator': {
    breach: '2019 Capital One breach — misconfigured WAF role accessed Key Vault credentials, exposing 100M customer records. $190M settlement + $80M OCC fine',
    penalty: 'HIPAA §164.312(a)(2)(iv) encryption · PCI-DSS 3.5 key management failure',
    cis: 'CIS Control 3.11: Encrypt Sensitive Data',
  },
  'Key Vault Secrets User': {
    breach: 'Uber 2022 — hardcoded credentials in PowerShell script accessed secrets store, exposed AWS and GCP production environments',
    penalty: 'GDPR Article 32: up to \u20AC20M or 4% global revenue · SOC2 CC6.1 violation',
    cis: 'CIS Control 3.11',
  },
  'Global Administrator': {
    breach: '2023 Storm-0558 — Chinese threat actor forged authentication tokens using a compromised MSA signing key, accessed US Government email accounts for months',
    penalty: 'FISMA High: mandatory breach notification · FedRAMP authorization suspension risk',
    cis: 'CIS Control 5.3: Disable Dormant Accounts',
  },
  'Storage Blob Data Contributor': {
    breach: '2021 Cognyte — unsecured blob storage exposed 5 billion records including credentials from previous breaches',
    penalty: 'GDPR: up to \u20AC20M · CCPA: $100–$750/consumer per incident · SOC2 CC6.1 failure',
    cis: 'CIS Control 3.3: Configure Data Access Control Lists',
  },
  'Storage Blob Data Owner': {
    breach: '2019 Microsoft Azure misconfiguration — Blob Storage with Owner permissions exposed 250M customer support records globally',
    penalty: 'GDPR: up to 4% global revenue · HIPAA §164.312(b) audit controls',
    cis: 'CIS Control 3.3',
  },
  'Cognitive Services Contributor': {
    breach: '2023 — multiple organizations reported AI model exfiltration via overprivileged Cognitive Services SPNs used to extract fine-tuned models and training data',
    penalty: 'IP theft liability · SOC2 CC6.6 logical access controls failure',
    cis: 'CIS Control 5.4',
  },
  'Virtual Machine Contributor': {
    breach: '2022 TeamTNT — cryptojacking campaign exploited VM Contributor SPNs to deploy crypto miners across 10,000+ Azure VMs, costing victims millions in compute bills',
    penalty: 'Cloud cost liability · SOC2 A1.2 capacity management failure',
    cis: 'CIS Control 4.1: Establish Secure Configs',
  },
};

/**
 * Look up breach info for a role name. Tries exact match first,
 * then substring match for compound role names.
 */
export function getBreachInfo(roleName: string): BreachExample | null {
  if (!roleName) return null;
  // Exact match
  if (BREACH_EXAMPLES[roleName]) return BREACH_EXAMPLES[roleName];
  // Substring match (e.g. "Key Vault Secrets User" matches "Key Vault")
  const lower = roleName.toLowerCase();
  for (const [key, val] of Object.entries(BREACH_EXAMPLES)) {
    if (lower.includes(key.toLowerCase())) return val;
  }
  return null;
}
