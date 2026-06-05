# SAML/SSO Incident Response Runbook

**AG-95** | Last updated: 2026-04-28

---

## 1. Replay Attack Detected

### Symptoms
- Log: `saml_security: assertion_replay_detected`
- HTTP 401 responses on `/api/auth/saml/acs` for legitimate users

### Immediate Actions
1. Check replay cache size: The `AssertionReplayCache.size()` method indicates volume
2. Verify NTP clock sync between SP and IdP (skew > 5 min causes false positives)
3. Check if multiple gunicorn workers are running — in-memory cache is per-process

### Investigation
```bash
# Search logs for replay events
grep "assertion_replay_detected" /var/log/auditgraph/*.log | tail -50

# Correlate source IPs
grep "saml_security" /var/log/auditgraph/*.log | grep -oP '"source_ip": "\K[^"]+' | sort | uniq -c | sort -rn
```

### Resolution
- If false positive (clock drift): Increase `skew_seconds` parameter
- If genuine replay: Investigate source IPs for MitM indicators, check IdP audit logs
- If multi-worker issue: Deploy Redis-backed replay cache

---

## 2. Brute-Force Attempt

### Symptoms
- HTTP 429 on `/api/auth/saml/token`
- Log: `sso_code_security: sso_rate_limited`
- High `attempt_count` values in `sso_auth_codes` table

### Immediate Actions
1. Verify rate limiter is active (check `SsoRateLimiter` singleton)
2. Check for IP rotation (distributed attack bypasses per-IP limits)
3. Review `sso_auth_codes` for codes with `attempt_count >= 5` (burned codes)

### Investigation
```sql
-- Check for brute-force patterns
SELECT code, user_id, attempt_count, created_at, consumed_at
FROM sso_auth_codes
WHERE attempt_count > 1
ORDER BY created_at DESC
LIMIT 50;

-- Check for high-volume attempts from single IP
-- (requires structured log aggregation)
```

### Resolution
- Tighten rate limits if needed (currently 5/5min per IP)
- If distributed: Consider CAPTCHA on SSO callback
- Rotate `SSO_HMAC_KEY` if code compromise suspected

---

## 3. SSO Code Compromise

### Symptoms
- Code consumed from unexpected source IP
- User reports SSO login they didn't initiate
- Activity log shows `sso_login` from unfamiliar location

### Immediate Actions
1. Invalidate all active SSO codes:
   ```sql
   UPDATE sso_auth_codes SET consumed_at = NOW() WHERE consumed_at IS NULL;
   ```
2. Force re-authentication for affected user(s)
3. Check for redirect URL manipulation in IdP configuration

### Investigation
- Compare ACS source IP with token exchange source IP
- Review IdP audit logs for the relevant assertion
- Check if RelayState was tampered with

### Resolution
- Rotate `SSO_HMAC_KEY` environment variable
- Review IdP redirect URI allowlist
- Enable `wantAssertionsEncrypted` if transport encryption is insufficient

---

## 4. SAML Configuration Tampering

### Symptoms
- `SamlConfigError` in logs (from `_assert_secure()` validation)
- SSO stops working for a tenant
- Settings table shows unexpected `sso_*` changes

### Immediate Actions
1. Verify IdP X.509 certificate hasn't been replaced:
   ```sql
   SELECT key, value, updated_at FROM settings
   WHERE key = 'sso_idp_x509_cert' AND organization_id = <tenant_id>;
   ```
2. Check activity log for settings changes:
   ```sql
   SELECT * FROM activity_log
   WHERE action LIKE 'settings%' AND description LIKE '%sso%'
   ORDER BY created_at DESC LIMIT 20;
   ```

### Resolution
- Restore correct IdP certificate from IdP metadata URL
- Audit admin accounts that have settings write access
- Enable MFA for admin accounts

---

## 5. Recovery Procedures

### HMAC Key Rotation
1. Generate new key: `python3 -c "import secrets; print(secrets.token_hex(32))"`
2. Set `SSO_HMAC_KEY` environment variable to new value
3. Restart application — all active codes become invalid
4. Users will need to re-initiate SSO (transparent redirect)

### Cache Flush
- Restart the application process to clear in-memory caches
- For Redis-backed caches: `FLUSHDB` on the replay cache database

### Force Re-Authentication
```sql
-- Invalidate all active SSO codes
UPDATE sso_auth_codes SET consumed_at = NOW() WHERE consumed_at IS NULL;

-- Invalidate all refresh tokens (forces re-login)
UPDATE refresh_tokens SET revoked_at = NOW() WHERE revoked_at IS NULL;
```

### SP Encryption Certificate Rotation
The SP encryption certificate is separate from the SP signing certificate.
When rotating the encryption cert:

1. **Generate new key pair:**
   ```bash
   openssl req -x509 -nodes -days 730 -newkey rsa:2048 \
     -keyout sp_encrypt_new.key -out sp_encrypt_new.crt \
     -subj "/CN=auditgraph-sp-encrypt/O=AuditGraph"
   ```

2. **Deploy new cert to SP** (python3-saml supports dual certs during rotation):
   - Add `sp.x509certNew` in settings for transition period
   - SP will accept assertions encrypted with either cert

3. **Upload new cert to IdP** (keep old cert active for 24h):
   - Entra: Token Encryption → Upload new certificate
   - Okta: SAML Settings → Replace encryption certificate
   - Allow propagation time (IdP caches may take 1-24h)

4. **Remove old cert from SP** (after confirming IdP uses new cert):
   - Remove `sp.x509certNew`, move new cert to `sp.x509cert`
   - Remove old cert from IdP portal

5. **Verify:** Initiate SSO login, confirm assertion decryption succeeds.

---

## 6. Monitoring Queries

### Log Patterns
```bash
# Replay attacks
grep "assertion_replay_detected" /var/log/auditgraph/*.log

# Rate limiting events
grep "sso_rate_limited" /var/log/auditgraph/*.log

# Code exchange failures
grep "sso_code_exchange_failed" /var/log/auditgraph/*.log

# SAML config errors
grep "SamlConfigError" /var/log/auditgraph/*.log
```

### SQL Monitoring
```sql
-- Active codes older than 5 minutes (should be 0 — TTL is 300s)
SELECT COUNT(*) FROM sso_auth_codes
WHERE consumed_at IS NULL AND expires_at < NOW();

-- Codes with high attempt counts (brute-force indicator)
SELECT user_id, attempt_count, created_at
FROM sso_auth_codes
WHERE attempt_count >= 3
ORDER BY created_at DESC;

-- SSO login frequency by tenant (last 24h)
SELECT organization_id, COUNT(*) as sso_logins
FROM activity_log
WHERE action = 'sso_login' AND created_at > NOW() - INTERVAL '24 hours'
GROUP BY organization_id;
```
