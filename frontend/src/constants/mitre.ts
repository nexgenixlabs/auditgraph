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

// ─── AG-177: AI Identity Attack Graph technique catalog ────────────────
// These IDs are the canonical references used by the backend
// `enrich_path_node_with_mitre` helper. Frontend lookups by ID return
// the display payload for chip rendering.
export const MITRE_BY_ID: Record<string, MitreTechnique> = {
  'T1078':     { id: 'T1078',     tactic: 'Privilege Escalation', name: 'Valid Accounts',           url: 'https://attack.mitre.org/techniques/T1078/' },
  'T1078.004': { id: 'T1078.004', tactic: 'Privilege Escalation', name: 'Cloud Accounts',           url: 'https://attack.mitre.org/techniques/T1078/004/' },
  'T1098':     { id: 'T1098',     tactic: 'Persistence',          name: 'Account Manipulation',     url: 'https://attack.mitre.org/techniques/T1098/' },
  'T1098.003': { id: 'T1098.003', tactic: 'Persistence',          name: 'Additional Cloud Roles',   url: 'https://attack.mitre.org/techniques/T1098/003/' },
  'T1552':     { id: 'T1552',     tactic: 'Credential Access',    name: 'Unsecured Credentials',    url: 'https://attack.mitre.org/techniques/T1552/' },
  'T1552.001': { id: 'T1552.001', tactic: 'Credential Access',    name: 'Credentials In Files',     url: 'https://attack.mitre.org/techniques/T1552/001/' },
  'T1555.006': { id: 'T1555.006', tactic: 'Credential Access',    name: 'Cloud Secrets Mgmt Stores',url: 'https://attack.mitre.org/techniques/T1555/006/' },
  'T1530':     { id: 'T1530',     tactic: 'Collection',           name: 'Data from Cloud Storage',  url: 'https://attack.mitre.org/techniques/T1530/' },
  'T1041':     { id: 'T1041',     tactic: 'Exfiltration',         name: 'Exfil Over C2 Channel',    url: 'https://attack.mitre.org/techniques/T1041/' },
  'T1567':     { id: 'T1567',     tactic: 'Exfiltration',         name: 'Exfil to Web Service',     url: 'https://attack.mitre.org/techniques/T1567/' },
  'T1199':     { id: 'T1199',     tactic: 'Initial Access',       name: 'Trusted Relationship',     url: 'https://attack.mitre.org/techniques/T1199/' },
  'T1606.001': { id: 'T1606.001', tactic: 'Credential Access',    name: 'Forge Web Credentials',    url: 'https://attack.mitre.org/techniques/T1606/001/' },
  'T1021':     { id: 'T1021',     tactic: 'Lateral Movement',     name: 'Remote Services',          url: 'https://attack.mitre.org/techniques/T1021/' },
};

/** Lookup by technique ID (e.g. "T1552.001"). */
export function getMitreTechniqueById(id: string): MitreTechnique | null {
  return MITRE_BY_ID[id] || null;
}

/** Collect + dedupe MITRE techniques from a list of IDs (backend-tagged). */
export function collectMitreByIds(ids: string[]): MitreTechnique[] {
  const seen = new Set<string>();
  const results: MitreTechnique[] = [];
  for (const id of ids || []) {
    const tech = MITRE_BY_ID[id];
    if (tech && !seen.has(tech.id)) {
      seen.add(tech.id);
      results.push(tech);
    }
  }
  return results;
}
