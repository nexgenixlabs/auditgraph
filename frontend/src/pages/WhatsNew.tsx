/**
 * AG-POLISH-DEMO (2026-06-10) — "What's New" landing page.
 *
 * Doubles as a demo aid: when a prospect lands on /whats-new, they
 * see every patent-track moat at a glance with a one-click drill-in.
 * Also serves as internal release notes / sales enablement asset.
 */
import React from 'react';
import { Link } from 'react-router-dom';

interface NewFeature {
  date: string;
  title: string;
  bullet: string;
  route: string;
  routeLabel: string;
  badge: 'PATENT' | 'NEW' | 'MOAT' | 'POLISH';
}

const FEATURES: NewFeature[] = [
  {
    date: '2026-06-10',
    title: 'Unified Identity Graph',
    bullet:
      'A single graph spanning Human → Non-Human → AI Agent → Model → Classified Data. ' +
      'No competitor surfaces this end-to-end chain today. The moat.',
    route: '/unified-graph',
    routeLabel: 'Open Unified Identity Graph',
    badge: 'PATENT',
  },
  {
    date: '2026-06-10',
    title: 'NHI Inventory — the SailPoint-killer numbers page',
    bullet:
      'Every non-human identity in your tenant in one pane. SPN / MI / Workload / CI/CD / AI Agent ' +
      'counts, hygiene gaps (unowned / dormant / critical / expired secrets / federated only), ' +
      'one-click drill-downs.',
    route: '/nhi',
    routeLabel: 'Open NHI Inventory',
    badge: 'NEW',
  },
  {
    date: '2026-06-10',
    title: 'Identity Exposure Graph (was Multi-Hop XGRAPH)',
    bullet:
      'Transitive identity → data reachability. Patent-track. Renamed from "Multi-Hop XGRAPH" — ' +
      'engine is identity-type agnostic (humans + NHIs + AI all chain in one graph).',
    route: '/ai-attack-paths/multi-hop',
    routeLabel: 'Open Identity Exposure Graph',
    badge: 'MOAT',
  },
  {
    date: '2026-06-10',
    title: 'Scope-aware Identity Trust + Lifecycle',
    bullet:
      'One 9-dimension Trust engine powers Human / NHI / AI views via ?type= param. Same for ' +
      'JML lifecycle. Zero engine duplication.',
    route: '/identity-trust?type=nhi',
    routeLabel: 'Try NHI Trust Score',
    badge: 'NEW',
  },
  {
    date: '2026-06-10',
    title: 'NHI Attack Paths — CI/CD chains',
    bullet:
      'GitHub Actions → SPN → Key Vault → Storage → PHI in one query. Source-type filter ' +
      'recognises federated workload identities (GitHub Actions / Azure DevOps / Terraform Cloud).',
    route: '/attack-paths?source_type=cicd',
    routeLabel: 'See CI/CD Attack Paths',
    badge: 'PATENT',
  },
  {
    date: '2026-06-10',
    title: 'New NHI risk signals',
    bullet:
      'unverified_federated_origin (permissive OIDC subject pattern) + ci_cd_with_owner_role ' +
      '(GitHub Actions identity with subscription Owner). Both feed the Supply Chain dim ' +
      'of NHI Trust Score.',
    route: '/identity-trust?type=nhi',
    routeLabel: 'See in NHI Trust',
    badge: 'NEW',
  },
  {
    date: '2026-06-10',
    title: 'Identity Security Graph rebrand',
    bullet:
      'AuditGraph is now positioned as "Identity Security Graph for Human, Non-Human, and ' +
      'AI Identities — agentless, read-only, architecture-derived." AI demoted from peer ' +
      'category to NHI subtype, matching the CISO buying motion.',
    route: '/',
    routeLabel: 'Back to Executive Posture',
    badge: 'NEW',
  },
];

const BADGE_STYLE: Record<NewFeature['badge'], { bg: string; text: string; border: string; label: string }> = {
  PATENT: { bg: 'bg-emerald-950/40', text: 'text-emerald-300', border: 'border-emerald-700/40', label: 'PATENT-TRACK' },
  MOAT:   { bg: 'bg-violet-950/40',  text: 'text-violet-300',  border: 'border-violet-700/40',  label: 'MOAT' },
  NEW:    { bg: 'bg-blue-950/40',    text: 'text-blue-300',    border: 'border-blue-700/40',    label: 'NEW' },
  POLISH: { bg: 'bg-slate-800/40',   text: 'text-slate-300',   border: 'border-slate-600/40',   label: 'POLISH' },
};

export default function WhatsNew() {
  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-5">
      <div>
        <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider font-bold text-gray-500">
          <span className="text-emerald-400">AuditGraph</span>
          <span>·</span>
          <span>What&apos;s New</span>
        </div>
        <h1 className="text-2xl font-bold text-slate-100 mt-1">What&apos;s New in AuditGraph</h1>
        <p className="text-sm text-slate-400 max-w-3xl mt-1">
          Latest features in the Identity Security Graph platform — patent-track moats,
          NHI surface area, scope-aware engines, and CI/CD attack chain detection.
        </p>
      </div>

      {/* Feature timeline */}
      <div className="space-y-3">
        {FEATURES.map((f, i) => {
          const b = BADGE_STYLE[f.badge];
          return (
            <div key={i} className={`rounded-xl border ${b.border} ${b.bg} p-4 hover:scale-[1.005] transition`}>
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-[9px] font-bold uppercase tracking-wider ${b.text} px-1.5 py-0.5 rounded`}
                          style={{ background: 'rgba(255,255,255,0.04)' }}>
                      {b.label}
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">{f.date}</span>
                  </div>
                  <h3 className="text-base font-semibold text-slate-100">{f.title}</h3>
                  <p className="text-sm text-slate-400 mt-1 leading-relaxed">{f.bullet}</p>
                </div>
                <Link
                  to={f.route}
                  className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 text-slate-200 border border-slate-700 hover:bg-slate-700 transition whitespace-nowrap flex-shrink-0"
                >
                  {f.routeLabel} →
                </Link>
              </div>
            </div>
          );
        })}
      </div>

      <div className="text-[11px] text-slate-500 leading-relaxed border-t border-white/5 pt-4">
        <p>
          <strong className="text-slate-400">Provisional patent claim (2026-06-09):</strong>{' '}
          A method for computing an identity-to-data exposure graph by joining role assignments
          across Entra Directory Roles, Azure RBAC, Microsoft Graph API permissions,
          OAuth consent grants, federated identity credentials, and AI model deployments —
          without requiring write access, agent installation, or runtime telemetry.
        </p>
      </div>
    </div>
  );
}
