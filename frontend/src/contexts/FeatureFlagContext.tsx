import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

interface FeatureFlags {
  ai_agent_governance: boolean;
  [key: string]: boolean;
}

interface FeatureFlagContextValue {
  flags: FeatureFlags;
  loading: boolean;
  /** Force-refresh flags from the server. */
  refresh: () => void;
}

const DEFAULT_FLAGS: FeatureFlags = { ai_agent_governance: false };

const FeatureFlagContext = createContext<FeatureFlagContextValue>({
  flags: DEFAULT_FLAGS,
  loading: true,
  refresh: () => {},
});

export function FeatureFlagProvider({ children }: { children: React.ReactNode }) {
  const [flags, setFlags] = useState<FeatureFlags>(DEFAULT_FLAGS);
  const [loading, setLoading] = useState(true);

  const fetchFlags = useCallback(() => {
    setLoading(true);
    fetch('/api/tenant/config')
      .then(r => (r.ok ? r.json() : null))
      .then(cfg => {
        if (cfg?.feature_flags) {
          setFlags(prev => ({ ...prev, ...cfg.feature_flags }));
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { fetchFlags(); }, [fetchFlags]);

  return (
    <FeatureFlagContext.Provider value={{ flags, loading, refresh: fetchFlags }}>
      {children}
    </FeatureFlagContext.Provider>
  );
}

export function useFeatureFlags(): FeatureFlagContextValue {
  return useContext(FeatureFlagContext);
}

export function useFeatureFlag(key: keyof FeatureFlags): boolean {
  const { flags } = useContext(FeatureFlagContext);
  return !!flags[key];
}
