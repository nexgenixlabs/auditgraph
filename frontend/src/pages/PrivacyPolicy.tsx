import React from 'react';
import { Link } from 'react-router-dom';

export default function PrivacyPolicy() {
  return (
    <div className="min-h-screen bg-[#0B1220] text-gray-300">
      <div className="max-w-4xl mx-auto px-6 py-12">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-3xl font-bold text-white">Privacy Policy</h1>
            <p className="text-sm text-gray-500 mt-1">Last updated: February 26, 2026</p>
          </div>
          <Link to="/" className="text-sm text-blue-400 hover:text-blue-300 transition">
            Back to Dashboard
          </Link>
        </div>

        <div className="space-y-8 text-sm leading-relaxed">
          <section>
            <h2 className="text-lg font-semibold text-white mb-3">1. Introduction</h2>
            <p>
              NexgenixLabs ("we", "us", "our") operates the AuditGraph identity risk management platform
              ("Service"). This Privacy Policy explains how we collect, use, disclose, and safeguard your
              information when you use our Service.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-white mb-3">2. Information We Collect</h2>
            <h3 className="text-sm font-semibold text-gray-200 mt-4 mb-2">2.1 Account Information</h3>
            <ul className="list-disc pl-6 space-y-1">
              <li>Name, email address, and organization name provided during registration</li>
              <li>Authentication credentials (stored as cryptographic hashes, never in plaintext)</li>
              <li>User role and permission assignments</li>
            </ul>

            <h3 className="text-sm font-semibold text-gray-200 mt-4 mb-2">2.2 Cloud Environment Data</h3>
            <ul className="list-disc pl-6 space-y-1">
              <li>Identity metadata from connected cloud providers (Azure AD, AWS IAM, GCP IAM)</li>
              <li>Role assignments, permission configurations, and access policies</li>
              <li>Sign-in logs and activity data (when P2 telemetry is enabled)</li>
              <li>Resource metadata (storage accounts, key vaults, subscriptions)</li>
            </ul>

            <h3 className="text-sm font-semibold text-gray-200 mt-4 mb-2">2.3 Usage Data</h3>
            <ul className="list-disc pl-6 space-y-1">
              <li>API request logs (endpoint, timestamp, response code)</li>
              <li>Feature usage analytics for product improvement</li>
              <li>Error reports and diagnostic information</li>
            </ul>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-white mb-3">3. How We Use Your Information</h2>
            <ul className="list-disc pl-6 space-y-1">
              <li>To provide and maintain the Service, including identity risk analysis and compliance reporting</li>
              <li>To detect security risks, anomalies, and compliance violations in your cloud environments</li>
              <li>To generate audit reports, evidence packages, and remediation recommendations</li>
              <li>To send notifications about critical security findings (configurable)</li>
              <li>To improve our algorithms and detection capabilities</li>
              <li>To comply with legal obligations</li>
            </ul>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-white mb-3">4. Data Security</h2>
            <ul className="list-disc pl-6 space-y-1">
              <li>All data is encrypted in transit (TLS 1.2+) and at rest (AES-256)</li>
              <li>Row-Level Security (RLS) enforces strict tenant isolation at the database level</li>
              <li>API authentication via JWT with automatic token rotation</li>
              <li>Rate limiting on authentication endpoints to prevent brute-force attacks</li>
              <li>Audit logging of all administrative actions</li>
              <li>Regular security assessments and penetration testing</li>
            </ul>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-white mb-3">5. Data Retention</h2>
            <p>
              We retain your data for as long as your account is active. Configurable retention policies
              allow you to set retention periods for discovery runs, drift reports, activity logs,
              anomalies, and SOAR actions (default: 90 days). Upon account termination, all tenant data
              is permanently deleted within 30 days.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-white mb-3">6. Data Sharing</h2>
            <p>We do not sell your data. We may share information only in these circumstances:</p>
            <ul className="list-disc pl-6 space-y-1 mt-2">
              <li>With cloud providers (Azure, AWS, GCP) as necessary to perform discovery scans using credentials you provide</li>
              <li>With third-party integrations you configure (Slack, Teams, SOAR, ticketing systems)</li>
              <li>As required by law, regulation, or legal process</li>
              <li>To protect the rights, property, or safety of our users or the public</li>
            </ul>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-white mb-3">7. Your Rights</h2>
            <ul className="list-disc pl-6 space-y-1">
              <li><strong>Access:</strong> Request a copy of your data via the Evidence Center export</li>
              <li><strong>Correction:</strong> Update your account information in Settings</li>
              <li><strong>Deletion:</strong> Request account and data deletion by contacting support</li>
              <li><strong>Portability:</strong> Export your data in JSON or CSV format at any time</li>
              <li><strong>Restriction:</strong> Disable specific data collection features in Settings</li>
            </ul>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-white mb-3">8. Compliance</h2>
            <p>
              AuditGraph is designed to support compliance with SOC 2 Type II, ISO 27001, NIST 800-53,
              CIS Benchmarks, and HIPAA security requirements. Our platform helps you demonstrate
              compliance through automated evidence collection and continuous monitoring.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-white mb-3">9. Contact</h2>
            <p>
              For privacy-related inquiries, contact us at{' '}
              <span className="text-blue-400">privacy@nexgenixlabs.com</span>.
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}
