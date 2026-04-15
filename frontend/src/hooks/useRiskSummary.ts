import { useState, useEffect } from 'react';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';

export interface RiskPillar {
  weight: number;
  risk_pct: number;
  score_impact: number;
  severity: string;
  affected_count: number;
}

export interface RiskSummaryFull {
  agirs: {
    score: number;
    tier: string;
    status: string;
    grade: string;
    delta: number | null;
    pillars: Record<string, RiskPillar>;
  };
  identity_risk_score: number;
  hiri: {
    score: number | null;
    human_count: number;
    h1_ghost: number;
    h2_dormant_priv: number;
    h3_over_priv: number;
    h4_ext_guest: number;
    h5_zombie: number;
  } | null;
  nhiri: {
    score: number | null;
    nhi_count: number;
    phantom_breakdown: {
      orphaned?: number;
      dormant?: number;
      zombie_nhi?: number;
      expired_creds?: number;
      ownerless_apps?: number;
    };
  } | null;
  gei: {
    score: number | null;
    components: Array<{ name: string; score: number; configured: boolean }>;
  } | null;
  risk_counts: {
    ghost_accounts: number;
    orphaned_spns: number;
    over_privileged: number;
    dormant_privileged: number;
    high_blast_radius: number;
    external_exposure: number;
  };
  identity_counts: {
    total: number;
    customer: number;
    microsoft: number;
    human: number;
    nhi: number;
  };
  exposure: {
    total_resources: number;
    storage_accounts: number;
    key_vaults: number;
    subscriptions: number;
    privileged_roles: number;
  };
  attack_paths: {
    total: number;
    open: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    affected_identities: number;
  };
  blast_radius: {
    severity: string;
    top_identity_name: string | null;
    top_identity_id: number | null;
    description: string;
  };
  dangerous_identities: Array<{
    id: number;
    display_name: string;
    identity_category: string;
    blast_radius_score: number;
    risk_score: number;
    tier: string;
    key_risk_factors: string[];
  }>;
  previous: {
    agirs: number | null;
    hiri: number | null;
    nhiri: number | null;
    gei: number | null;
  };
  attack_surface: {
    total: number;
    privileged: number;
    machine: number;
    external: number;
  };
  top_risks: Array<{
    id: string;
    label: string;
    count: number;
    severity: string;
    score_improvement: number;
  }>;
  computed_at: string | null;
  source: string;
}

export function useRiskSummary() {
  const { withConnection, selectedConnectionId } = useConnection();
  const { activeOrgId } = useAuth();
  const [data, setData] = useState<RiskSummaryFull | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetch(withConnection('/api/risk/summary/full'))
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (!cancelled) setData(d); })
      .catch(() => { if (!cancelled) setData(null); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId, activeOrgId]);

  return { data, loading };
}
