import { useState, useEffect } from 'react';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';

export interface RiskSummary {
  agirs: { score: number; tier: string } | null;
  identity_risk_score: number | null;
  ghost_accounts: number;
  orphaned_spns: number;
  over_privileged: number;
  dormant_privileged: number;
  high_blast_radius: number;
  attack_paths: number;
  identity_counts: { total: number; customer: number; microsoft: number };
}

export interface ExposureSummary {
  total_resources: number;
  storage_accounts: number;
  key_vaults: number;
  subscriptions: number;
  privileged_roles: number;
}

export interface AttackPathCount {
  total: number;
  open: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  affected_identities: number;
}

export interface CanonicalMetrics {
  risk: RiskSummary | null;
  exposure: ExposureSummary | null;
  attackPaths: AttackPathCount | null;
  loading: boolean;
}

export function useCanonicalMetrics(): CanonicalMetrics {
  const { withConnection, selectedConnectionId } = useConnection();
  const { activeOrgId } = useAuth();
  const [risk, setRisk] = useState<RiskSummary | null>(null);
  const [exposure, setExposure] = useState<ExposureSummary | null>(null);
  const [attackPaths, setAttackPaths] = useState<AttackPathCount | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      const [riskRes, expRes, apRes] = await Promise.all([
        fetch(withConnection('/api/risk/summary')).catch(() => null),
        fetch(withConnection('/api/exposure/summary')).catch(() => null),
        fetch(withConnection('/api/attack-paths/count')).catch(() => null),
      ]);
      if (cancelled) return;
      setRisk(riskRes?.ok ? await riskRes.json().catch(() => null) : null);
      setExposure(expRes?.ok ? await expRes.json().catch(() => null) : null);
      setAttackPaths(apRes?.ok ? await apRes.json().catch(() => null) : null);
      setLoading(false);
    }
    load();
    return () => { cancelled = true; };
  }, [selectedConnectionId, activeOrgId]);

  return { risk, exposure, attackPaths, loading };
}
