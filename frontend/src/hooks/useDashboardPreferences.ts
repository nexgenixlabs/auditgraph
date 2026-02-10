import { useState, useEffect, useCallback } from 'react';
import { DEFAULT_WIDGET_ORDER, mergePreferences } from '../components/dashboard/widgetRegistry';
import type { WidgetPref } from '../components/dashboard/widgetRegistry';

export function useDashboardPreferences() {
  const [widgets, setWidgets] = useState<WidgetPref[]>(DEFAULT_WIDGET_ORDER);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);

  // Fetch on mount
  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const res = await fetch('/api/dashboard/preferences');
        if (res.ok) {
          const data = await res.json();
          if (!cancelled) {
            const merged = mergePreferences(data.preferences?.widgets ?? null);
            setWidgets(merged);
          }
        }
      } catch { /* use defaults */ }
      finally { if (!cancelled) setLoading(false); }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  const toggleWidget = useCallback((id: string) => {
    setWidgets(prev => prev.map(w => w.id === id ? { ...w, visible: !w.visible } : w));
    setDirty(true);
  }, []);

  const moveWidget = useCallback((id: string, direction: 'up' | 'down') => {
    setWidgets(prev => {
      const idx = prev.findIndex(w => w.id === id);
      if (idx < 0) return prev;
      const swapIdx = direction === 'up' ? idx - 1 : idx + 1;
      if (swapIdx < 0 || swapIdx >= prev.length) return prev;
      const next = [...prev];
      [next[idx], next[swapIdx]] = [next[swapIdx], next[idx]];
      return next;
    });
    setDirty(true);
  }, []);

  const save = useCallback(async () => {
    setSaving(true);
    try {
      const res = await fetch('/api/dashboard/preferences', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ widgets }),
      });
      if (res.ok) {
        setDirty(false);
        return true;
      }
      return false;
    } catch { return false; }
    finally { setSaving(false); }
  }, [widgets]);

  const reset = useCallback(async () => {
    setSaving(true);
    try {
      await fetch('/api/dashboard/preferences', { method: 'DELETE' });
      setWidgets(DEFAULT_WIDGET_ORDER);
      setDirty(false);
    } catch { /* ignore */ }
    finally { setSaving(false); }
  }, []);

  return { widgets, loading, saving, dirty, toggleWidget, moveWidget, save, reset };
}
