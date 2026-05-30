import React from 'react';
import { Link, useLocation } from 'react-router-dom';

/**
 * Shared tab strip for the Reports + Exports pair (P1 nav consolidation Win 3).
 * The two pages do different things (PDF audit reports vs CSV/JSON data exports)
 * but users think of them as one capability, so the nav collapsed to a single
 * "Reports & Exports" entry. This component lets users switch between them
 * without going back to the sidebar.
 *
 * URLs are preserved: /reports and /exports both keep their existing routes
 * and components — this is purely a navigation affordance dropped at the top
 * of each page.
 */
export default function ReportsExportsTabs() {
  const { pathname } = useLocation();
  const active = pathname.startsWith('/exports') ? 'exports' : 'reports';

  const tabClass = (key: 'reports' | 'exports') =>
    `px-4 py-2 text-sm font-medium rounded-md transition-colors ${
      active === key
        ? 'bg-blue-600 text-white shadow-sm'
        : 'text-slate-500 hover:text-slate-700 hover:bg-slate-100 dark:text-slate-400 dark:hover:text-slate-200 dark:hover:bg-slate-800'
    }`;

  return (
    <div className="flex items-center gap-1 rounded-lg p-1 w-fit bg-slate-100 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-700">
      <Link to="/reports" className={tabClass('reports')}>PDF Reports</Link>
      <Link to="/exports" className={tabClass('exports')}>Data Exports</Link>
    </div>
  );
}
