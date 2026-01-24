import React, { useState } from 'react';

const RiskMethodology: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="mb-6">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 text-sm text-blue-600 hover:text-blue-800 font-medium"
      >
        <span className="text-lg">ℹ️</span>
        How are risks calculated? {isOpen ? '▼' : '▶'}
      </button>

      {isOpen && (
        <div className="mt-4 bg-blue-50 border border-blue-200 rounded-lg p-6">
          <h3 className="text-lg font-bold text-gray-900 mb-4">
            AuditGraph Risk Scoring Methodology
          </h3>

          <div className="space-y-4">
            {/* Framework */}
            <div>
              <h4 className="font-semibold text-gray-900 mb-2">📋 Framework:</h4>
              <p className="text-sm text-gray-700">
                Based on <strong>NIST Cybersecurity Framework</strong> and <strong>HIPAA Security Rule</strong> requirements 
                for access control (§164.308(a)(4)) and audit controls (§164.312(b)).
              </p>
            </div>

            {/* Risk Levels */}
            <div>
              <h4 className="font-semibold text-gray-900 mb-3">🎯 Risk Level Definitions:</h4>
              
              <div className="space-y-3">
                {/* Critical */}
                <div className="bg-red-50 border border-red-200 rounded p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="px-2 py-1 bg-red-600 text-white text-xs font-bold rounded">CRITICAL</span>
                    <span className="text-sm font-semibold text-gray-900">Score: 80-100</span>
                  </div>
                  <p className="text-sm text-gray-700 mb-2">
                    <strong>Immediate action required.</strong> High privilege accounts (Owner, Contributor, User Access Administrator) 
                    that are either:
                  </p>
                  <ul className="text-sm text-gray-700 ml-4 space-y-1">
                    <li>• Never used since creation (orphaned/forgotten)</li>
                    <li>• Dormant for 90+ days</li>
                    <li>• Missing proper governance (no owner/justification)</li>
                  </ul>
                  <p className="text-xs text-red-700 mt-2">
                    <strong>HIPAA Impact:</strong> Violates minimum necessary standard (§164.502(b)) and access review requirements (§164.308(a)(3))
                  </p>
                </div>

                {/* High */}
                <div className="bg-orange-50 border border-orange-200 rounded p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="px-2 py-1 bg-orange-500 text-white text-xs font-bold rounded">HIGH</span>
                    <span className="text-sm font-semibold text-gray-900">Score: 60-79</span>
                  </div>
                  <p className="text-sm text-gray-700 mb-2">
                    <strong>Review within 7 days.</strong> Elevated privileges that require monitoring:
                  </p>
                  <ul className="text-sm text-gray-700 ml-4 space-y-1">
                    <li>• Active high-privilege accounts (require justification)</li>
                    <li>• Recently inactive (30-90 days)</li>
                    <li>• Multiple high-privilege roles on single identity</li>
                  </ul>
                  <p className="text-xs text-orange-700 mt-2">
                    <strong>HIPAA Impact:</strong> Requires documented access justification and regular review
                  </p>
                </div>

                {/* Medium */}
                <div className="bg-yellow-50 border border-yellow-200 rounded p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="px-2 py-1 bg-yellow-500 text-white text-xs font-bold rounded">MEDIUM</span>
                    <span className="text-sm font-semibold text-gray-900">Score: 40-59</span>
                  </div>
                  <p className="text-sm text-gray-700 mb-2">
                    <strong>Monitor and right-size.</strong> Potentially over-privileged:
                  </p>
                  <ul className="text-sm text-gray-700 ml-4 space-y-1">
                    <li>• Reader role with limited usage</li>
                    <li>• Custom roles that may be too broad</li>
                    <li>• Service principals with expiring credentials (30-60 days)</li>
                  </ul>
                </div>

                {/* Low */}
                <div className="bg-green-50 border border-green-200 rounded p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="px-2 py-1 bg-green-600 text-white text-xs font-bold rounded">LOW</span>
                    <span className="text-sm font-semibold text-gray-900">Score: 20-39</span>
                  </div>
                  <p className="text-sm text-gray-700">
                    <strong>Routine monitoring.</strong> Reader-level access with normal usage patterns. Regular quarterly review recommended.
                  </p>
                </div>

                {/* Info */}
                <div className="bg-blue-50 border border-blue-200 rounded p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="px-2 py-1 bg-blue-600 text-white text-xs font-bold rounded">INFO</span>
                    <span className="text-sm font-semibold text-gray-900">Score: 0-19</span>
                  </div>
                  <p className="text-sm text-gray-700">
                    <strong>Informational.</strong> Properly scoped identities with appropriate access. Included for completeness.
                  </p>
                </div>
              </div>
            </div>

            {/* Scoring Factors */}
            <div>
              <h4 className="font-semibold text-gray-900 mb-2">⚖️ Scoring Factors:</h4>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="bg-white rounded p-2 border border-gray-200">
                  <strong>Privilege Level:</strong> +40 points for Owner, +30 for Contributor
                </div>
                <div className="bg-white rounded p-2 border border-gray-200">
                  <strong>Activity Status:</strong> +30 points if never used, +20 if dormant 90+ days
                </div>
                <div className="bg-white rounded p-2 border border-gray-200">
                  <strong>Credential Health:</strong> +15 points if expired or expiring soon
                </div>
                <div className="bg-white rounded p-2 border border-gray-200">
                  <strong>Governance:</strong> +15 points if orphaned (no owner)
                </div>
              </div>
            </div>

            {/* References */}
            <div className="pt-3 border-t border-blue-200">
              <p className="text-xs text-gray-600">
                <strong>References:</strong> NIST CSF (PR.AC-4, DE.CM-3), HIPAA §164.308(a)(3-4), 
                CIS Controls v8 (5.3, 6.1), Microsoft Azure Security Benchmark
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RiskMethodology;
