import React, { createContext, useContext, useState, useCallback } from 'react';

export interface CopilotState {
  open: boolean;
  contextType?: 'identity' | 'resource' | 'posture' | 'attack_path';
  contextId?: string;
  contextLabel?: string;
  initialQuestion?: string;
}

interface CopilotContextValue {
  state: CopilotState;
  openCopilot: (opts?: Partial<Omit<CopilotState, 'open'>>) => void;
  closeCopilot: () => void;
}

const CopilotContext = createContext<CopilotContextValue>({
  state: { open: false },
  openCopilot: () => {},
  closeCopilot: () => {},
});

export function CopilotProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<CopilotState>({ open: false });

  const openCopilot = useCallback((opts?: Partial<Omit<CopilotState, 'open'>>) => {
    setState({
      open: true,
      contextType: opts?.contextType,
      contextId: opts?.contextId,
      contextLabel: opts?.contextLabel,
      initialQuestion: opts?.initialQuestion,
    });
  }, []);

  const closeCopilot = useCallback(() => {
    setState({ open: false });
  }, []);

  return (
    <CopilotContext.Provider value={{ state, openCopilot, closeCopilot }}>
      {children}
    </CopilotContext.Provider>
  );
}

export function useCopilot() {
  return useContext(CopilotContext);
}
