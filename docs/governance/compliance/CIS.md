# CIS Benchmark Compliance — AuditGraph

## Status: Stub (Phase 4B)

## Azure CIS Controls Assessed

### Identity & Access Management
- CIS 1.1: MFA enforcement tracking via Conditional Access policies
- CIS 1.3: Guest user access restrictions monitoring
- CIS 1.21: Custom role least-privilege analysis

### Storage Accounts
- CIS 3.1: Secure transfer required
- CIS 3.2: Storage account access keys audit
- CIS 3.7: Public access disabled
- CIS 3.8: Default network access deny
- CIS 3.9: Trusted Azure services access
- CIS 3.10: Private endpoint connections
- CIS 3.12: Soft delete enabled
- CIS 3.14: Diagnostic logging enabled

### Key Vaults
- CIS 8.1: Expiration date set on keys
- CIS 8.2: Expiration date set on secrets
- CIS 8.4: Soft delete enabled
- CIS 8.5: Purge protection enabled
- CIS 8.7: Private endpoint connections

## Evidence Artifacts
- Resource discovery: `azure_storage_accounts`, `azure_key_vaults` tables
- Compliance checks: `score_storage_account()`, `score_key_vault()`
- CIS mapping: `compliance_controls` table with framework references
