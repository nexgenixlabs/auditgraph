/**
 * Compliance Framework Mapping — maps risk categories to framework controls.
 */

export interface ComplianceFrameworkRef {
  framework: 'SOC2' | 'CIS' | 'HIPAA' | 'NIST';
  control: string;
}

export interface RiskComplianceMapping {
  frameworks: ComplianceFrameworkRef[];
}

const MAPPING: Record<string, RiskComplianceMapping> = {
  dormant_privileged: {
    frameworks: [
      { framework: 'SOC2', control: 'CC6.1' },
      { framework: 'SOC2', control: 'CC6.3' },
      { framework: 'CIS', control: '1.1' },
      { framework: 'HIPAA', control: '164.312(a)(1)' },
      { framework: 'NIST', control: 'AC-2' },
    ],
  },
  expiring_credentials: {
    frameworks: [
      { framework: 'SOC2', control: 'CC6.1' },
      { framework: 'CIS', control: '1.4' },
      { framework: 'HIPAA', control: '164.312(d)' },
      { framework: 'NIST', control: 'IA-5' },
    ],
  },
  unowned_spns: {
    frameworks: [
      { framework: 'SOC2', control: 'CC6.1' },
      { framework: 'HIPAA', control: '164.312(a)(1)' },
      { framework: 'NIST', control: 'AC-2' },
    ],
  },
  unused_credentials: {
    frameworks: [
      { framework: 'SOC2', control: 'CC6.1' },
      { framework: 'SOC2', control: 'CC6.3' },
      { framework: 'CIS', control: '1.3' },
      { framework: 'HIPAA', control: '164.312(d)' },
      { framework: 'NIST', control: 'IA-5' },
    ],
  },
  mfa_not_enforced: {
    frameworks: [
      { framework: 'SOC2', control: 'CC6.1' },
      { framework: 'SOC2', control: 'CC6.6' },
      { framework: 'CIS', control: '1.2' },
      { framework: 'HIPAA', control: '164.312(d)' },
      { framework: 'NIST', control: 'IA-2' },
    ],
  },
  excessive_privilege: {
    frameworks: [
      { framework: 'SOC2', control: 'CC6.1' },
      { framework: 'SOC2', control: 'CC6.3' },
      { framework: 'CIS', control: '1.1' },
      { framework: 'HIPAA', control: '164.312(a)(1)' },
      { framework: 'NIST', control: 'AC-6' },
    ],
  },
  guest_admin_access: {
    frameworks: [
      { framework: 'SOC2', control: 'CC6.1' },
      { framework: 'SOC2', control: 'CC6.2' },
      { framework: 'CIS', control: '1.4' },
      { framework: 'HIPAA', control: '164.312(a)(1)' },
      { framework: 'NIST', control: 'AC-2' },
    ],
  },
  secret_older_365d: {
    frameworks: [
      { framework: 'SOC2', control: 'CC6.1' },
      { framework: 'CIS', control: '1.4' },
      { framework: 'HIPAA', control: '164.312(d)' },
      { framework: 'NIST', control: 'IA-5' },
    ],
  },
  no_owner_assigned: {
    frameworks: [
      { framework: 'SOC2', control: 'CC6.1' },
      { framework: 'HIPAA', control: '164.312(a)(1)' },
      { framework: 'NIST', control: 'AC-2' },
    ],
  },
  public_storage_exposure: {
    frameworks: [
      { framework: 'SOC2', control: 'CC6.1' },
      { framework: 'SOC2', control: 'CC6.7' },
      { framework: 'HIPAA', control: '164.312(a)(1)' },
      { framework: 'NIST', control: 'AC-3' },
    ],
  },
};

/**
 * Get compliance framework references for a risk category.
 * Returns unique framework names (deduped).
 */
export function getComplianceMapping(riskCategory: string): ComplianceFrameworkRef[] {
  return MAPPING[riskCategory]?.frameworks || [];
}

/**
 * Get unique framework names for a risk category.
 */
export function getFrameworkNames(riskCategory: string): string[] {
  const refs = getComplianceMapping(riskCategory);
  return Array.from(new Set(refs.map(r => r.framework)));
}

/**
 * Get all known risk categories.
 */
export function getAllRiskCategories(): string[] {
  return Object.keys(MAPPING);
}
