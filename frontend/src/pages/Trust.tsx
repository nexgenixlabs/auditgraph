import React from 'react';
import { Link } from 'react-router-dom';
import { COLORS } from '../constants/ciso';

/**
 * AuditGraph Trust Center — public page.
 *
 * Mirrors the content of `docs-site/content/trust.md` so the product app and
 * marketing/docs site stay in sync. Truthful by design: SOC 2 Type II is in
 * progress (Q3 2026 target); ISO 27001 is planned; HIPAA BAA and DPA are
 * available on request.
 */
export default function Trust() {
  return (
    <div className="min-h-screen bg-ob-surface text-gray-300">
      <div className="max-w-4xl mx-auto px-6 py-12">
        {/* Header */}
        <div className="flex items-start justify-between mb-8 gap-4">
          <div>
            <div
              className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md text-[11px] font-medium mb-3 border"
              style={{
                backgroundColor: 'rgba(14, 165, 233, 0.12)',
                color: '#7dd3fc',
                borderColor: 'rgba(14, 165, 233, 0.35)',
              }}
            >
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              AuditGraph Trust
            </div>
            <h1 className="text-3xl font-bold text-white">Trust Center</h1>
            <p className="text-sm text-gray-500 mt-1">Last updated: June 1, 2026</p>
          </div>
          <Link to="/" className="text-sm text-blue-400 hover:text-blue-300 transition whitespace-nowrap">
            Back to Dashboard
          </Link>
        </div>

        {/* Intro */}
        <div
          className="rounded-lg border p-5 mb-10"
          style={{
            backgroundColor: COLORS.surfaceAlt,
            borderColor: COLORS.border,
          }}
        >
          <p className="text-sm leading-relaxed">
            AuditGraph is built by NexgenixLabs to help security teams understand identity risk in their
            own cloud. We hold ourselves to the same standards we apply to your environment. This page
            consolidates our compliance posture, security architecture, sub-processors, and how to
            request audit artifacts.
          </p>
        </div>

        <div className="space-y-12 text-sm leading-relaxed">
          {/* 1. Compliance posture */}
          <section>
            <h2 className="text-lg font-semibold text-white mb-4">Compliance posture</h2>
            <div className="overflow-x-auto -mx-2 sm:mx-0">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="text-gray-400 border-b" style={{ borderColor: COLORS.border }}>
                    <th className="py-2 pr-4 font-medium">Program</th>
                    <th className="py-2 pr-4 font-medium">Status</th>
                    <th className="py-2 font-medium">How to obtain</th>
                  </tr>
                </thead>
                <tbody className="text-gray-300">
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top font-medium text-white">SOC 2 Type II</td>
                    <td className="py-3 pr-4 align-top">
                      Type 1 attestation Q2 2026; Type II observation period underway, full report Q3 2026 target
                    </td>
                    <td className="py-3 align-top">
                      Available under NDA via{' '}
                      <a href="mailto:security@auditgraph.ai" className="text-blue-400 hover:text-blue-300">
                        security@auditgraph.ai
                      </a>
                    </td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top font-medium text-white">ISO 27001</td>
                    <td className="py-3 pr-4 align-top">Planned</td>
                    <td className="py-3 align-top">Roadmap available on request</td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top font-medium text-white">HIPAA</td>
                    <td className="py-3 pr-4 align-top">
                      Business Associate Agreement available on request for customers with PHI in scope
                    </td>
                    <td className="py-3 align-top">
                      <a href="mailto:compliance@auditgraph.ai" className="text-blue-400 hover:text-blue-300">
                        compliance@auditgraph.ai
                      </a>
                    </td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top font-medium text-white">GDPR</td>
                    <td className="py-3 pr-4 align-top">Data Processing Addendum available on request</td>
                    <td className="py-3 align-top">
                      <a href="mailto:compliance@auditgraph.ai" className="text-blue-400 hover:text-blue-300">
                        compliance@auditgraph.ai
                      </a>
                    </td>
                  </tr>
                  <tr>
                    <td className="py-3 pr-4 align-top font-medium text-white">CIS Foundations Benchmark</td>
                    <td className="py-3 pr-4 align-top">
                      AuditGraph's own platform alignment is documented; controls map maintained internally
                    </td>
                    <td className="py-3 align-top">Customer copy on request</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p className="mt-4 text-xs text-gray-500">
              Our SOC 2 control catalog covers 35 controls across Security (CC6), Availability (A1),
              Confidentiality (C1), Processing Integrity (PI1), Monitoring (CC7), Change Management
              (CC8), and Risk Assessment (CC3). 33 of 35 are fully satisfied, 2 are in partial status
              with documented compensating controls — all tracked against the Q3 2026 Type II target.
            </p>
            <p className="mt-2 text-xs text-gray-500">
              We do not overstate certification. Where a program is "planned" or "in progress," we say so.
            </p>
          </section>

          {/* 2. Security architecture */}
          <section>
            <h2 className="text-lg font-semibold text-white mb-3">Security architecture</h2>
            <p>
              AuditGraph follows a <strong className="text-white">Zero Trust</strong> model. Every
              request is authenticated, authorized, and explicitly scoped to both{' '}
              <code className="text-xs px-1 py-0.5 rounded" style={{ backgroundColor: COLORS.surfaceAlt }}>
                organization_id
              </code>{' '}
              (tenant) and{' '}
              <code className="text-xs px-1 py-0.5 rounded" style={{ backgroundColor: COLORS.surfaceAlt }}>
                cloud_connection_id
              </code>{' '}
              (connector). Trust is never inherited from network position, prior session, or shared infrastructure.
            </p>

            <h3 className="text-sm font-semibold text-gray-200 mt-5 mb-2">Defense-in-depth layers</h3>
            <ol className="list-decimal pl-6 space-y-1">
              <li><strong className="text-white">Network</strong> — HTTPS/TLS, HSTS, security headers, CORS allowlist</li>
              <li><strong className="text-white">Authentication</strong> — JWT (portal-specific signing keys), OIDC, SAML, API Keys (SHA-256 hashed, <code className="text-xs">ag_</code> prefix)</li>
              <li><strong className="text-white">Authorization</strong> — Role-Based Access Control (8 roles), portal-scoped permissions, feature flags</li>
              <li><strong className="text-white">Tenant isolation</strong> — PostgreSQL Row-Level Security on every tenant-scoped table, dual DB user pattern (app user has NOBYPASSRLS, admin user is reserved for system-level DDL)</li>
              <li><strong className="text-white">Data protection</strong> — Field-level encryption (Fernet / MultiFernet) for application secrets, structured log redaction for tokens and credentials</li>
              <li><strong className="text-white">API protection</strong> — Rate limiting on authentication endpoints, request size limits, input validation, idempotency keys for mutating operations</li>
              <li><strong className="text-white">Operational safety</strong> — Circuit breakers on outbound calls, retry-with-backoff on cloud APIs, security event logging</li>
            </ol>

            <h3 className="text-sm font-semibold text-gray-200 mt-5 mb-2">Tenant isolation specifics</h3>
            <ul className="list-disc pl-6 space-y-1">
              <li>44 of 54 application tables carry <code className="text-xs">tenant_id NOT NULL</code> with strict RLS policies. No null-context bypass — every query must declare a tenant context.</li>
              <li>A trigger (<code className="text-xs">trg_auto_tenant_id</code>) auto-populates <code className="text-xs">tenant_id</code> from session context on insert and raises if both context and explicit value are absent.</li>
              <li>Cross-tenant access by a superadmin is gated by an explicit <code className="text-xs">X-Tenant-Id</code> header override and logged to the activity audit trail.</li>
              <li>The host-to-tenant guard in <code className="text-xs">auth_middleware</code> verifies the subdomain slug against the JWT's tenant claim on every request.</li>
            </ul>
          </section>

          {/* 3. Encryption */}
          <section>
            <h2 className="text-lg font-semibold text-white mb-4">Encryption</h2>
            <div className="overflow-x-auto -mx-2 sm:mx-0">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="text-gray-400 border-b" style={{ borderColor: COLORS.border }}>
                    <th className="py-2 pr-4 font-medium">Surface</th>
                    <th className="py-2 font-medium">Standard</th>
                  </tr>
                </thead>
                <tbody className="text-gray-300">
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top font-medium text-white">Data at rest (database)</td>
                    <td className="py-3 align-top">AES-256 via PostgreSQL transparent disk encryption (Azure Database for PostgreSQL)</td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top font-medium text-white">Application secrets</td>
                    <td className="py-3 align-top">Fernet (AES-128 in CBC mode + HMAC-SHA256) with MultiFernet key rotation</td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top font-medium text-white">Data in transit</td>
                    <td className="py-3 align-top">TLS 1.2+ enforced on every endpoint; HSTS preload-eligible policy</td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top font-medium text-white">Production secret store</td>
                    <td className="py-3 align-top">Azure Key Vault, RBAC-scoped, no secret material exported to logs or backups</td>
                  </tr>
                  <tr>
                    <td className="py-3 pr-4 align-top font-medium text-white">Customer-provided cloud credentials</td>
                    <td className="py-3 align-top">Read-only scopes only; encrypted at rest; never exported</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          {/* 4. Penetration testing */}
          <section>
            <h2 className="text-lg font-semibold text-white mb-3">Penetration testing</h2>
            <ul className="list-disc pl-6 space-y-1">
              <li><strong className="text-white">Frequency:</strong> annual third-party penetration test plus continuous internal scanning</li>
              <li><strong className="text-white">Most recent external test:</strong> 2026-05-08</li>
              <li><strong className="text-white">Findings:</strong> all findings tracked in our remediation register with severity, owner, and target close date; executive summary available on request (NDA)</li>
              <li><strong className="text-white">Continuous scanning:</strong> quarterly internal red-team exercises, SAST + container image scanning on every PR via the <code className="text-xs">pr-gate.yml</code> and <code className="text-xs">container-infra-scan.yml</code> workflows, secret scanning on every commit</li>
            </ul>
            <p className="mt-3">
              To request the executive summary:{' '}
              <a href="mailto:security@auditgraph.ai" className="text-blue-400 hover:text-blue-300">
                security@auditgraph.ai
              </a>.
            </p>
          </section>

          {/* 5. Incident response */}
          <section>
            <h2 className="text-lg font-semibold text-white mb-3">Incident response</h2>
            <p>
              We maintain a documented Incident Response Plan with a severity matrix (Sev-0 through
              Sev-3), defined escalation paths, and customer-notification SLAs.
            </p>

            <div className="overflow-x-auto -mx-2 sm:mx-0 mt-4">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="text-gray-400 border-b" style={{ borderColor: COLORS.border }}>
                    <th className="py-2 pr-4 font-medium">Event</th>
                    <th className="py-2 font-medium">Customer notification SLA</th>
                  </tr>
                </thead>
                <tbody className="text-gray-300">
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top">Confirmed data exposure affecting customer data</td>
                    <td className="py-3 align-top font-medium" style={{ color: COLORS.danger }}>Within 24 hours</td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top">Confirmed security breach (no data exposure yet confirmed)</td>
                    <td className="py-3 align-top font-medium" style={{ color: COLORS.warning }}>Within 72 hours</td>
                  </tr>
                  <tr>
                    <td className="py-3 pr-4 align-top">Sev-0 platform outage</td>
                    <td className="py-3 align-top font-medium" style={{ color: COLORS.warning }}>Status-page update within 15 minutes</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <ul className="list-disc pl-6 space-y-1 mt-4">
              <li><strong className="text-white">Monitoring:</strong> 24/7 on-call rotation, alerting on auth anomalies, RLS policy violations, scheduler failures, and outbound-error spikes</li>
              <li><strong className="text-white">Tabletop exercises:</strong> quarterly, covering credential compromise, ransomware against operational tooling, and supply-chain incidents</li>
              <li><strong className="text-white">Post-incident:</strong> every Sev-0 / Sev-1 incident produces a public-facing root-cause analysis when customer data or service is affected</li>
            </ul>

            <p className="mt-4">
              <strong className="text-white">Public incident archive:</strong> none to date.
            </p>
          </section>

          {/* 6. Vulnerability disclosure */}
          <section>
            <h2 className="text-lg font-semibold text-white mb-3">Vulnerability disclosure</h2>
            <p>We welcome coordinated disclosure from independent security researchers.</p>
            <ul className="list-disc pl-6 space-y-1 mt-3">
              <li>
                <strong className="text-white">Report to:</strong>{' '}
                <a href="mailto:security@auditgraph.ai" className="text-blue-400 hover:text-blue-300">
                  security@auditgraph.ai
                </a>{' '}
                (PGP key available on request)
              </li>
              <li><strong className="text-white">Coordinated-disclosure window:</strong> 90 days from acknowledgement; we will not pursue legal action against good-faith research that adheres to this window and does not exfiltrate customer data</li>
              <li><strong className="text-white">Acknowledgement target:</strong> within 2 business days of report receipt</li>
              <li><strong className="text-white">Hall of Fame:</strong> researchers who report verified findings are listed publicly (with permission) on our security page</li>
            </ul>
            <p className="mt-3 text-xs text-gray-500">
              In scope: <code className="text-xs">*.auditgraph.ai</code> web properties, public API, the
              docs site. Out of scope: third-party services we use (report directly to those vendors).
            </p>
          </section>

          {/* 7. Sub-processors */}
          <section>
            <h2 className="text-lg font-semibold text-white mb-3">Sub-processors</h2>
            <p>
              We use a small, deliberately chosen set of sub-processors. Customers are notified 30 days
              before any material change to this list.
            </p>
            <div className="overflow-x-auto -mx-2 sm:mx-0 mt-4">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="text-gray-400 border-b" style={{ borderColor: COLORS.border }}>
                    <th className="py-2 pr-4 font-medium">Sub-processor</th>
                    <th className="py-2 pr-4 font-medium">Purpose</th>
                    <th className="py-2 pr-4 font-medium">Customer data hosted</th>
                    <th className="py-2 font-medium">Region</th>
                  </tr>
                </thead>
                <tbody className="text-gray-300">
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top font-medium text-white">Microsoft Azure</td>
                    <td className="py-3 pr-4 align-top">Compute, Azure Database for PostgreSQL, Azure Key Vault, Azure Container Registry, Container Apps</td>
                    <td className="py-3 pr-4 align-top">All customer tenant data, metadata, audit logs</td>
                    <td className="py-3 align-top">US (Central US) primary; EU available on request</td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top font-medium text-white">Anthropic</td>
                    <td className="py-3 pr-4 align-top">Argus AI security analyst (optional; can be disabled per tenant)</td>
                    <td className="py-3 pr-4 align-top">Anonymized identity/role context for analyst queries — no PII, no credentials</td>
                    <td className="py-3 align-top">US</td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top font-medium text-white">Ollama (self-hosted alternative for Argus)</td>
                    <td className="py-3 pr-4 align-top">Open-source LLM provider, deployed in customer-controlled or AuditGraph-controlled compute</td>
                    <td className="py-3 pr-4 align-top">Same scope as Anthropic; never leaves the deployment boundary</td>
                    <td className="py-3 align-top">Customer-elected</td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top font-medium text-white">SendGrid</td>
                    <td className="py-3 pr-4 align-top">Transactional email (notifications, password reset, scheduled reports)</td>
                    <td className="py-3 pr-4 align-top">Customer email addresses, notification subject lines and excerpts</td>
                    <td className="py-3 align-top">US</td>
                  </tr>
                  <tr>
                    <td className="py-3 pr-4 align-top font-medium text-white">GitHub</td>
                    <td className="py-3 pr-4 align-top">Source code repository, CI/CD workflow execution</td>
                    <td className="py-3 pr-4 align-top">No customer data; product source and build artifacts only</td>
                    <td className="py-3 align-top">US</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p className="mt-4 text-xs text-gray-500">
              Argus AI analysis is <strong className="text-gray-300">opt-in per tenant</strong>. When
              disabled, no customer data is sent to any LLM provider.
            </p>
          </section>

          {/* 8. Customer data rights */}
          <section>
            <h2 className="text-lg font-semibold text-white mb-3">Customer data rights</h2>
            <div className="overflow-x-auto -mx-2 sm:mx-0">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="text-gray-400 border-b" style={{ borderColor: COLORS.border }}>
                    <th className="py-2 pr-4 font-medium">Right</th>
                    <th className="py-2 font-medium">How</th>
                  </tr>
                </thead>
                <tbody className="text-gray-300">
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top font-medium text-white">Access</td>
                    <td className="py-3 align-top">Self-serve export via the Evidence Center (JSON or CSV) at any time</td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top font-medium text-white">Correction</td>
                    <td className="py-3 align-top">
                      Update via Settings or contact{' '}
                      <a href="mailto:support@auditgraph.ai" className="text-blue-400 hover:text-blue-300">
                        support@auditgraph.ai
                      </a>
                    </td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top font-medium text-white">Deletion (account-wide)</td>
                    <td className="py-3 align-top">Settings → Data Lifecycle → Permanent deletion; all tenant data deleted within 30 days of confirmation</td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top font-medium text-white">Portability</td>
                    <td className="py-3 align-top">JSON or CSV export of all your identity, risk, run, and audit data</td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top font-medium text-white">Restriction</td>
                    <td className="py-3 align-top">Per-feature opt-outs (e.g., disable Argus, disable scheduled reports, disable email notifications)</td>
                  </tr>
                  <tr>
                    <td className="py-3 pr-4 align-top font-medium text-white">Residency</td>
                    <td className="py-3 align-top">US (Central US) default; EU region available on request for Enterprise plans</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p className="mt-4">
              You retain ownership of all data ingested from your cloud environments. We process it
              solely to provide the Service.
            </p>
          </section>

          {/* Request documents */}
          <section>
            <h2 className="text-lg font-semibold text-white mb-3">Request documents</h2>
            <p>
              The following artifacts are available to customers and prospects evaluating AuditGraph:
            </p>
            <div className="overflow-x-auto -mx-2 sm:mx-0 mt-4">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="text-gray-400 border-b" style={{ borderColor: COLORS.border }}>
                    <th className="py-2 pr-4 font-medium">Document</th>
                    <th className="py-2 font-medium">Access</th>
                  </tr>
                </thead>
                <tbody className="text-gray-300">
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top">SOC 2 Type 1 attestation report (Q2 2026)</td>
                    <td className="py-3 align-top">
                      NDA —{' '}
                      <a href="mailto:security@auditgraph.ai" className="text-blue-400 hover:text-blue-300">
                        security@auditgraph.ai
                      </a>
                    </td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top">Penetration test executive summary (most recent: 2026-05-08)</td>
                    <td className="py-3 align-top">
                      NDA —{' '}
                      <a href="mailto:security@auditgraph.ai" className="text-blue-400 hover:text-blue-300">
                        security@auditgraph.ai
                      </a>
                    </td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top">Data Processing Addendum (DPA)</td>
                    <td className="py-3 align-top">
                      <a href="mailto:compliance@auditgraph.ai" className="text-blue-400 hover:text-blue-300">
                        compliance@auditgraph.ai
                      </a>
                    </td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top">Business Associate Agreement (BAA, HIPAA)</td>
                    <td className="py-3 align-top">
                      <a href="mailto:compliance@auditgraph.ai" className="text-blue-400 hover:text-blue-300">
                        compliance@auditgraph.ai
                      </a>
                    </td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top">Security FAQ for vendor diligence</td>
                    <td className="py-3 align-top">
                      Public —{' '}
                      <a
                        href="https://docs.auditgraph.ai/#/security-vendor-faq"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-400 hover:text-blue-300"
                      >
                        docs.auditgraph.ai
                      </a>
                    </td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top">Information Security Policy (executive summary)</td>
                    <td className="py-3 align-top">On request</td>
                  </tr>
                  <tr>
                    <td className="py-3 pr-4 align-top">Sub-processor list</td>
                    <td className="py-3 align-top">This page; updated as changes occur</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          {/* Contact */}
          <section>
            <h2 className="text-lg font-semibold text-white mb-3">Contact</h2>
            <div className="overflow-x-auto -mx-2 sm:mx-0">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="text-gray-400 border-b" style={{ borderColor: COLORS.border }}>
                    <th className="py-2 pr-4 font-medium">Purpose</th>
                    <th className="py-2 font-medium">Address</th>
                  </tr>
                </thead>
                <tbody className="text-gray-300">
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top">Security disclosures and incident reports</td>
                    <td className="py-3 align-top">
                      <a href="mailto:security@auditgraph.ai" className="text-blue-400 hover:text-blue-300">
                        security@auditgraph.ai
                      </a>
                    </td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top">Privacy questions and data-subject requests</td>
                    <td className="py-3 align-top">
                      <a href="mailto:privacy@auditgraph.ai" className="text-blue-400 hover:text-blue-300">
                        privacy@auditgraph.ai
                      </a>
                    </td>
                  </tr>
                  <tr className="border-b" style={{ borderColor: COLORS.border }}>
                    <td className="py-3 pr-4 align-top">Compliance, audit artifacts, DPA / BAA requests</td>
                    <td className="py-3 align-top">
                      <a href="mailto:compliance@auditgraph.ai" className="text-blue-400 hover:text-blue-300">
                        compliance@auditgraph.ai
                      </a>
                    </td>
                  </tr>
                  <tr>
                    <td className="py-3 pr-4 align-top">General support</td>
                    <td className="py-3 align-top">
                      <a href="mailto:support@auditgraph.ai" className="text-blue-400 hover:text-blue-300">
                        support@auditgraph.ai
                      </a>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p className="mt-4 text-xs text-gray-500">
              We aim to acknowledge security reports within 2 business days and respond substantively within 5.
            </p>
          </section>
        </div>

        {/* Footer */}
        <div
          className="mt-12 pt-6 border-t flex flex-wrap items-center justify-between gap-3"
          style={{ borderColor: COLORS.border }}
        >
          <div className="text-xs text-gray-500">
            For security disclosures, contact{' '}
            <a href="mailto:security@auditgraph.ai" className="text-blue-400 hover:text-blue-300">
              security@auditgraph.ai
            </a>
            .
          </div>
          <div className="flex items-center gap-4 text-xs">
            <Link to="/privacy" className="text-gray-500 hover:text-gray-300 transition">Privacy</Link>
            <Link to="/terms" className="text-gray-500 hover:text-gray-300 transition">Terms</Link>
            <Link to="/" className="text-blue-400 hover:text-blue-300 transition">Back to Dashboard</Link>
          </div>
        </div>
      </div>
    </div>
  );
}
