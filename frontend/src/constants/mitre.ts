/**
 * MITRE ATT&CK technique mappings for attack path types and privileged roles.
 */

export interface MitreTechnique {
  id: string;
  tactic: string;
  name: string;
  url: string;
}

export const MITRE_TECHNIQUES: Record<string, MitreTechnique> = {
  direct_escalation:       { id: 'T1078',     tactic: 'Privilege Escalation', name: 'Valid Accounts',           url: 'https://attack.mitre.org/techniques/T1078/' },
  ownership_chain:         { id: 'T1098',     tactic: 'Persistence',          name: 'Account Manipulation',     url: 'https://attack.mitre.org/techniques/T1098/' },
  pim_abuse:               { id: 'T1078.004', tactic: 'Privilege Escalation', name: 'Cloud Accounts',           url: 'https://attack.mitre.org/techniques/T1078/004/' },
  lateral_movement:        { id: 'T1021',     tactic: 'Lateral Movement',     name: 'Remote Services',          url: 'https://attack.mitre.org/techniques/T1021/' },
  credential_exposure:     { id: 'T1552',     tactic: 'Credential Access',    name: 'Unsecured Credentials',    url: 'https://attack.mitre.org/techniques/T1552/' },
  sensitive_data_exposure: { id: 'T1530',     tactic: 'Collection',           name: 'Data from Cloud Storage',  url: 'https://attack.mitre.org/techniques/T1530/' },
  external_identity_risk:  { id: 'T1199',     tactic: 'Initial Access',       name: 'Trusted Relationship',     url: 'https://attack.mitre.org/techniques/T1199/' },
};

export const ROLE_MITRE: Record<string, string> = {
  'Owner':                     'T1098.003',
  'Contributor':               'T1098.003',
  'User Access Administrator': 'T1098.003',
  'Global Administrator':      'T1078.004',
  'Key Vault Secrets Officer': 'T1552.001',
};

export function getMitreTechnique(type: string): MitreTechnique | null {
  return MITRE_TECHNIQUES[type] || null;
}

/** Collect unique MITRE techniques from a list of escalation types */
export function collectMitreTags(types: string[]): MitreTechnique[] {
  const seen = new Set<string>();
  const results: MitreTechnique[] = [];
  for (const t of types) {
    const tech = MITRE_TECHNIQUES[t];
    if (tech && !seen.has(tech.id)) {
      seen.add(tech.id);
      results.push(tech);
    }
  }
  return results;
}
