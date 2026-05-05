# AG-95: SSO & SAML Authentication Security

## Overview

**Ticket**: AG-95
**CVSS**: 9.1 (SAML Assertion Replay), 8.1 (SSO Code Brute-Force)
**Date**: 2026-04-28

Eliminates SAML assertion replay (CWE-294) and SSO one-time code brute-force
(CWE-307) attack surfaces. Introduces centralized SSO security module as SSOT.

### Compliance Mapping

| Standard | Reference | Control |
|----------|-----------|---------|
| CWE-294 | Authentication Bypass by Capture-Replay | AssertionReplayCache |
| CWE-287 | Improper Authentication | Secure SAML settings builder |
| CWE-307 | Improper Restriction of Excessive Authentication Attempts | Rate limiting + attempt tracking |
| CWE-345 | Insufficient Verification of Data Authenticity | wantAssertionsSigned, wantMessagesSigned |
| CWE-330 | Use of Insufficiently Random Values | secrets.token_urlsafe(36) = 288 bits |
| CWE-208 | Observable Timing Discrepancy | hmac.compare_digest |
| CWE-311 | Missing Encryption of Sensitive Data | wantNameIdEncrypted, wantAssertionsEncrypted |
| OWASP A02:2021 | Cryptographic Failures | Encryption defaults (AG-95-v2) |
| OWASP A07:2021 | Identification and Authentication Failures | All controls |
| NIST SP 800-63B | AAL2 replay resistance, federation encryption | Replay cache + encryption |
| SAML V2.0 §3.4 | NameID Confidentiality | wantNameIdEncrypted=True |
| SAML V2.0 §3.4.5.2 | Assertion one-time use | AssertionReplayCache |
| SAML V2.0 §6.2 | Assertion Encryption | wantAssertionsEncrypted=True |
| SAML V2.0 §6.4 | Algorithm requirements | SHA-256 signature + digest |

---

## Threat Model

### T1: SAML Assertion Replay (CVSS 9.1)
**Attack**: Attacker intercepts SAML response and replays it to ACS endpoint.
**Impact**: Full account takeover without credentials.
**Control**: `AssertionReplayCache` — assertion IDs are consumed atomically. Replay raises `AssertionReplayError` → 401.

### T2: SSO Code Brute-Force (CVSS 8.1)
**Attack**: Attacker guesses the one-time code in the redirect URL.
**Impact**: JWT token issuance for victim account.
**Control**: CSPRNG codes (288-bit entropy), HMAC-hashed storage, 5-attempt burn limit, IP-based rate limiting.

### T3: SSO Code Timing Attack (CVSS 5.3)
**Attack**: Attacker measures response time to infer partial code correctness.
**Impact**: Entropy reduction enabling brute-force.
**Control**: `hmac.compare_digest()` for constant-time comparison. HMAC context binding prevents cross-user replay.

### T4: Weak SAML Configuration (CVSS 7.5)
**Attack**: Unsigned assertions allow IdP impersonation / response forgery.
**Impact**: Arbitrary user authentication.
**Control**: `build_secure_saml_settings()` enforces strict mode, assertion signing, message signing, SHA-256 algorithms. `_assert_secure()` validates at construction time.

### T5: SAML Error Information Leak (CVSS 3.7)
**Attack**: Detailed SAML errors reveal IdP configuration to attacker.
**Impact**: Reconnaissance for targeted attacks.
**Control**: ACS returns generic `"SAML authentication failed"` (no error details).

### T6: SSO Code Credential Stuffing (CVSS 6.5)
**Attack**: High-volume attempts across multiple codes from distributed IPs.
**Impact**: Account compromise at scale.
**Control**: Per-code attempt limit (5 max), per-IP sliding-window rate limit (5/5min), CODE_TTL_SEC (300s).

---

## Controls Implemented

### C1: AssertionReplayCache
- In-memory, thread-safe (`threading.Lock`)
- Bounded: 100,000 entries max (capacity guard evicts oldest on overflow)
- TTL-based: entries expire at `NotOnOrAfter + skew_seconds` (default 5 min skew)
- Atomic: `consume()` checks + stores in single locked operation
- Location: `app/security/sso_security.py`

### C2: HMAC-SHA256 Code Hashing
- Codes generated with `secrets.token_urlsafe(36)` = 288 bits entropy
- Stored as `HMAC-SHA256(key, "sso:{user_id}:{code}")` — context-bound
- HMAC key derived from `SSO_HMAC_KEY` env var, or `JWT_SECRET` fallback
- Prevents cross-user / cross-purpose code reuse

### C3: Constant-Time Comparison
- `hmac.compare_digest()` on computed vs stored hash
- No early-exit timing oracle
- Applied in `consume_sso_auth_code()` database method

### C4: Rate Limiting & Attempt Tracking
- Per-code: `attempt_count` column, burns code at `MAX_ATTEMPTS_PER_CODE` (5)
- Per-IP: `SsoRateLimiter` sliding window (5 attempts per 5 min on token exchange)
- Route-level: `@rate_limit` on ACS (10/min) and token exchange (10/5min)

### C5: Secure SAML Settings Builder
- `build_secure_saml_settings()` produces hardened config
- Mandatory flags: `wantAssertionsSigned=True`, `wantMessagesSigned=True`, `rejectDeprecatedAlgorithm=True`
- Algorithms: `rsa-sha256` signature, `sha256` digest
- `_assert_secure()` validates at construction — raises `SamlConfigError` on violation

### C6: InResponseTo Binding
- `AuthnRequestCache` stores request IDs keyed by nonce embedded in RelayState
- ACS recovers request_id and passes to `process_response(request_id=...)`
- Prevents IdP-initiated response injection and assertion reuse across sessions

### C7: Structured Security Logging
- `_log_saml_event()` for SAML security events (replay, config errors)
- `_log_sso_code_event()` for code exchange events (rate limit, failures)
- Includes source_ip, request_id, event type

---

## Architecture

```
app/security/sso_security.py (SSOT)
├── SamlConfigError / SamlAuthError / AssertionReplayError
├── build_secure_saml_settings() + _assert_secure()
├── AssertionReplayCache (singleton: _replay_cache)
├── AuthnRequestCache (singleton: _authn_request_cache)
├── generate_code() + hash_code() + verify_code_constant_time()
├── SsoRateLimiter (singleton: _sso_limiter)
├── make_relay_state() + parse_relay_state()
└── Structured logging helpers

app/api/saml.py (thin wrapper)
└── build_saml_settings() → delegates to build_secure_saml_settings()

app/api/handlers.py (integration)
├── saml_login() → AuthnRequestCache + nonce in RelayState
├── saml_acs() → replay cache + InResponseTo validation
└── saml_token_exchange() → rate limiting + structured logging

app/database.py (storage)
├── create_sso_auth_code() → HMAC-hashed codes
└── consume_sso_auth_code() → constant-time comparison + attempt tracking
```

### SAML ACS Flow
```
Browser → IdP → POST /api/auth/saml/acs
  1. Parse RelayState → (slug, nonce)
  2. Recover AuthnRequest ID from cache (InResponseTo binding)
  3. process_response(request_id=...) — validates signature + InResponseTo
  4. consume(assertion_id) — replay cache (one-time use)
  5. Extract attributes → JIT provision → generate one-time code (HMAC-hashed)
  6. Redirect to /sso-callback?code=...
```

### Token Exchange Flow
```
Browser → POST /api/auth/saml/token {code: "..."}
  1. Rate limit check (IP-based)
  2. Fetch active codes from DB
  3. HMAC-SHA256(code, user_id, "sso") → compare_digest with stored hash
  4. Check attempt_count < MAX_ATTEMPTS
  5. Mark consumed → issue JWT tokens
```

---

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `SSO_HMAC_KEY` | (derived from JWT_SECRET) | HMAC key for code hashing |
| `JWT_SECRET` | (required) | Fallback for HMAC key derivation |

| Constant | Value | Location |
|----------|-------|----------|
| `CODE_TTL_SEC` | 300 (5 min) | sso_security.py |
| `MAX_ATTEMPTS_PER_CODE` | 5 | sso_security.py |
| `_MAX_ENTRIES` (replay) | 100,000 | AssertionReplayCache |
| `_MAX_ENTRIES` (authn) | 10,000 | AuthnRequestCache |
| `AUTHN_REQUEST_TTL` | 600 (10 min) | sso_security.py |

---

## Production Considerations

1. **Redis-backed replay cache** (AG-131): The in-memory `AssertionReplayCache` is NOT safe for multi-process (gunicorn workers). Use Redis with `SETNX` + TTL for production multi-worker deployments. Tracked separately as AG-131.
2. **HMAC key rotation**: Set `SSO_HMAC_KEY` explicitly. Rotate by setting new key — active codes with old key will fail gracefully (users retry SSO).
3. **Monitoring alerts**: Set up alerts on `saml_security: assertion_replay_detected` and `sso_code_security: sso_rate_limited` log events.
4. **Clock sync**: Ensure NTP sync between SP and IdP. The 5-minute skew tolerance in the replay cache handles minor drift.
5. **Boot validation**: `validate_saml_settings_at_boot()` runs at startup. Aborts in staging/production if any SSO-enabled org fails `_assert_secure()`. Logs `saml_settings_baseline` hash for SIEM drift detection.

---

## Encryption Defaults (AG-95-v2)

### Default Behavior
Both `wantNameIdEncrypted` and `wantAssertionsEncrypted` are **True** by default. This means:
- The SP requires the IdP to encrypt the NameID element
- The SP requires the IdP to encrypt the entire assertion

### Per-Org Override
Organizations whose IdP does not support encryption can request an override:
1. A **superadmin** sets `sso_accept_unencrypted_nameid=true` or `sso_accept_unencrypted_assertions=true` via POST /api/settings/sso
2. A `encryption_override_reason` field is **required** (string, non-empty)
3. An audit log entry is emitted: `event=saml_encryption_disabled`
4. Normal admins receive 403 when attempting this change

### SP Encryption Certificate
For IdPs to encrypt assertions, they need the SP's public encryption certificate. The SP certificate must be configured in `python3-saml` settings under `sp.x509cert`.

### IdP-Specific Setup

**Microsoft Entra ID (Azure AD)**
- App Registration → Token Configuration → Enable "Encrypt SAML assertions"
- Upload SP encryption certificate (X.509, PEM format)
- Docs: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/howto-saml-token-encryption

**Okta**
- Applications → Your App → General → SAML Settings → Edit
- Assertion Encryption: "Encrypted"
- Upload SP certificate under "Encryption Certificate"
- Docs: https://help.okta.com/en-us/content/topics/apps/apps_saml_assertion_encryption.htm

**Ping Identity / PingFederate**
- SP Connection → Credentials → Configure encryption certificate
- Assertion Encryption Policy: "Entire Assertion"

**OneLogin**
- Applications → Your App → SSO → SAML Encryption
- Enable "Encrypt Assertion" and upload SP cert

**Google Workspace (SAML apps)**
- Admin Console → Apps → Web and mobile → Your App → Service Provider Details
- Upload SP encryption certificate

### SP Certificate Rotation
1. Generate new SP key pair: `openssl req -x509 -nodes -days 730 -newkey rsa:2048 -keyout sp_new.key -out sp_new.crt`
2. Add new cert to SP config (python3-saml supports multiple certs during rotation)
3. Upload new cert to IdP (keep old cert active)
4. After IdP propagation (24h), remove old cert from SP config
5. Remove old cert from IdP
