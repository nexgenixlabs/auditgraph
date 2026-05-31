import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';

// ── Types ───────────────────────────────────────────────────────

type ToastType = 'success' | 'error' | 'info';

/** Optional action button rendered on the right side of a toast.
 *  Polish-tier upgrade 2026-05-31: makes "Failed — Retry" / "Started — View" possible. */
interface ToastAction {
  label: string;
  onClick: () => void;
}

interface Toast {
  id: string;
  message: string;
  type: ToastType;
  createdAt: number;
  action?: ToastAction;
}

interface ToastContextValue {
  addToast: (message: string, type?: ToastType, action?: ToastAction) => void;
}

// ── Context ─────────────────────────────────────────────────────

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

// ── Toast Item ──────────────────────────────────────────────────

const ICON_PATHS: Record<ToastType, string> = {
  success: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z',
  error: 'M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z',
  info: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
};

const TYPE_STYLES: Record<ToastType, string> = {
  success: 'bg-green-50 border-green-200 text-green-800 dark:bg-green-900/30 dark:border-green-700 dark:text-green-200',
  error: 'bg-red-50 border-red-200 text-red-800 dark:bg-red-900/30 dark:border-red-700 dark:text-red-200',
  info: 'bg-blue-50 border-blue-200 text-blue-800 dark:bg-blue-900/30 dark:border-blue-700 dark:text-blue-200',
};

function ToastItem({ toast, onDismiss }: { toast: Toast; onDismiss: (id: string) => void }) {
  const [visible, setVisible] = useState(false);
  const [exiting, setExiting] = useState(false);

  const duration = toast.type === 'error' ? 6000 : 4000;

  useEffect(() => {
    const frame = requestAnimationFrame(() => setVisible(true));
    return () => cancelAnimationFrame(frame);
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => {
      setExiting(true);
      setTimeout(() => onDismiss(toast.id), 300);
    }, duration);
    return () => clearTimeout(timer);
  }, [toast.id, duration, onDismiss]);

  const handleDismiss = () => {
    setExiting(true);
    setTimeout(() => onDismiss(toast.id), 300);
  };

  return (
    <div
      className={`
        pointer-events-auto w-80 border rounded-xl px-4 py-3 shadow-lg
        flex items-start gap-3
        transition-all duration-300 ease-in-out
        ${TYPE_STYLES[toast.type]}
        ${visible && !exiting ? 'translate-x-0 opacity-100' : 'translate-x-full opacity-0'}
      `}
    >
      <svg className="w-5 h-5 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={ICON_PATHS[toast.type]} />
      </svg>
      <div className="flex-1 text-sm font-medium">{toast.message}</div>
      {/* Optional action button — turns "Failed" into "Failed — Retry" */}
      {toast.action && (
        <button
          onClick={() => { toast.action!.onClick(); handleDismiss(); }}
          className="flex-shrink-0 px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide bg-white/40 hover:bg-white/60 dark:bg-white/10 dark:hover:bg-white/20 transition-colors border border-current/20"
        >
          {toast.action.label}
        </button>
      )}
      <button
        onClick={handleDismiss}
        className="flex-shrink-0 opacity-60 hover:opacity-100 transition-opacity"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>
    </div>
  );
}

// ── Provider ────────────────────────────────────────────────────

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = useCallback((message: string, type: ToastType = 'info', action?: ToastAction) => {
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2);
    setToasts(prev => [...prev, { id, message, type, createdAt: Date.now(), action }]);
  }, []);

  const removeToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ addToast }}>
      {children}
      <div
        className="fixed top-4 right-4 z-[60] flex flex-col gap-3 pointer-events-none"
        role="status"
        aria-live="polite"
      >
        {toasts.map(toast => (
          <ToastItem key={toast.id} toast={toast} onDismiss={removeToast} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

// ── Hook ────────────────────────────────────────────────────────

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
}
