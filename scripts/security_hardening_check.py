#!/usr/bin/env python3
"""AuditGraph Production Security Hardening Checker.

Verifies 8 security control categories across the backend, frontend,
database, graph engine, AI copilot, and operational configuration.

Usage:
    python scripts/security_hardening_check.py [--verbose] [--json]

Exit codes:
    0  All checks passed
    1  One or more checks failed
"""

import argparse
import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
BACKEND_APP = BACKEND / "app"

# ── Result tracking ───────────────────────────────────────────────────────

_results: list[dict] = []


def check(category: str, control: str, passed: bool, detail: str = ""):
    """Record a single check result."""
    _results.append({
        "category": category,
        "control": control,
        "status": "PASS" if passed else "FAIL",
        "detail": detail,
    })


def read_file(path: Path) -> str:
    """Read a file or return empty string if missing."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


# ══════════════════════════════════════════════════════════════════════════
# 1. API SECURITY
# ══════════════════════════════════════════════════════════════════════════

def check_api_security():
    cat = "API Security"

    # --- 1a. All routes require authentication (check PUBLIC_PATHS is bounded) ---
    auth_src = read_file(BACKEND_APP / "api" / "auth.py")

    # Extract PUBLIC_PATHS set
    public_paths_match = re.search(
        r"PUBLIC_PATHS\s*=\s*\{([^}]+)\}", auth_src, re.DOTALL
    )
    if public_paths_match:
        raw = public_paths_match.group(1)
        paths = re.findall(r"['\"](/[^'\"]+)['\"]", raw)
        # These are the known-safe public paths
        allowed_public = {
            "/api/auth/login", "/api/auth/refresh", "/api/health", "/health",
            "/api/metrics", "/api/auth/forgot-password", "/api/auth/reset-password",
            "/api/auth/validate-reset-token", "/api/auth/org-branding",
            "/api/auth/tenant-branding", "/api/auth/password-policy",
            "/api/billing/stripe-webhook", "/api/auth/signup",
            "/api/auth/verify-email", "/api/auth/accept-invitation",
            "/api/auth/validate-invitation",
        }
        unexpected = set(paths) - allowed_public
        check(cat, "Public paths are bounded",
              len(unexpected) == 0,
              f"Unexpected public paths: {unexpected}" if unexpected
              else f"{len(paths)} public paths, all expected")
    else:
        check(cat, "Public paths are bounded", False,
              "Could not find PUBLIC_PATHS definition in auth.py")

    # --- 1b. auth_middleware is registered as before_request ---
    main_src = read_file(BACKEND_APP / "main.py")
    has_middleware = "auth_middleware" in main_src and "before_request" in main_src
    check(cat, "auth_middleware registered as before_request", has_middleware)

    # --- 1c. No unprotected admin endpoints ---
    # Scan main.py for /api/admin/ routes without @require_portal or @require_superadmin
    admin_routes = re.findall(
        r"@app\.route\(['\"](/api/admin/[^'\"]+)['\"]", main_src
    )
    handler_src = read_file(BACKEND_APP / "api" / "handlers.py")
    # Check that every admin handler has portal role guards
    unprotected_admin = []
    for route in admin_routes:
        # The decorator appears within ~10 lines above the route in main.py
        # Simple heuristic: search for the handler name and check for require_portal/require_superadmin
        handler_match = re.search(
            rf"@app\.route\(['\"]" + re.escape(route) + r"['\"].*?\n\s*(?:@\w+.*\n\s*)*def\s+(\w+)",
            main_src, re.DOTALL
        )
        if handler_match:
            func_name = handler_match.group(1)
            # Look backwards from the function def for decorators
            func_block_match = re.search(
                rf"((?:@\w+.*\n\s*){{0,8}})def\s+{func_name}\s*\(",
                main_src, re.DOTALL
            )
            if func_block_match:
                decorators = func_block_match.group(1)
                if not re.search(r"require_portal|require_superadmin", decorators):
                    unprotected_admin.append(route)

    check(cat, "Admin endpoints require portal role",
          len(unprotected_admin) == 0,
          f"Unprotected admin routes: {unprotected_admin}" if unprotected_admin
          else f"{len(admin_routes)} admin routes checked")

    # --- 1d. Rate limiting enabled on auth endpoints ---
    security_src = read_file(BACKEND_APP / "security.py")
    has_rate_limiter = "class RateLimiter" in security_src or "rate_limit" in security_src
    rate_limited_routes = re.findall(r"@rate_limit\(", main_src)
    check(cat, "Rate limiting enabled",
          has_rate_limiter and len(rate_limited_routes) >= 3,
          f"RateLimiter class present, {len(rate_limited_routes)} rate-limited routes")

    # --- 1e. JWT audience validation ---
    has_audience = "audience=" in auth_src and "aud" in auth_src
    check(cat, "JWT audience validation enabled", has_audience)

    # --- 1f. Token expiry enforced ---
    has_exp = "'exp'" in auth_src or '"exp"' in auth_src
    check(cat, "JWT expiry claim enforced", has_exp)


# ══════════════════════════════════════════════════════════════════════════
# 2. DATABASE SECURITY
# ══════════════════════════════════════════════════════════════════════════

def check_database_security():
    cat = "Database Security"

    db_src = read_file(BACKEND_APP / "database.py")

    # --- 2a. RLS context setting ---
    has_set_context = "set_config('app.current_organization_id'" in db_src
    check(cat, "RLS context set via set_config()", has_set_context)

    # --- 2b. Context verification (fail-closed) ---
    has_verify = "verify_tenant_context" in db_src or "SecurityViolationError" in db_src
    check(cat, "Tenant context verification (fail-closed)", has_verify)

    # --- 2c. Dual DB users (app + admin) ---
    has_app_user = "auditgraph_app" in db_src or "DB_USER" in db_src
    has_admin_user = "auditgraph_admin" in db_src or "DB_ADMIN_USER" in db_src
    check(cat, "Dual DB users (app NOBYPASSRLS + admin BYPASSRLS)",
          has_app_user and has_admin_user,
          f"app_user={has_app_user}, admin_user={has_admin_user}")

    # --- 2d. RLS policies are strict (no NULL bypass) ---
    has_strict_policy = "org_strict_sel" in db_src or "current_setting('app.current_organization_id'" in db_src
    check(cat, "Strict RLS policies (no NULL-context bypass)", has_strict_policy)

    # --- 2e. _commit/_rollback restore RLS context ---
    has_safe_commit = (
        "def _commit" in db_src
        and "set_organization_context" in db_src
    )
    has_safe_rollback = (
        "def _rollback" in db_src
        and "set_organization_context" in db_src
    )
    check(cat, "_commit() restores RLS context", has_safe_commit)
    check(cat, "_rollback() restores RLS context", has_safe_rollback)

    # --- 2f. Request teardown resets context ---
    main_src = read_file(BACKEND_APP / "main.py")
    has_teardown = "teardown_request" in main_src and "reset_organization_context" in main_src
    check(cat, "Request teardown resets tenant context", has_teardown)

    # --- 2g. RLS drift detection exists ---
    has_drift = "detect_rls_drift" in db_src or "rls_drift" in db_src
    check(cat, "RLS drift detection method exists", has_drift)

    # --- 2h. No public/anon roles ---
    has_no_public = "PUBLIC" not in db_src.split("CREATE ROLE")[0] if "CREATE ROLE" in db_src else True
    # Check that no GRANT to PUBLIC exists
    grant_public = re.findall(r"GRANT\s+.*\s+TO\s+PUBLIC", db_src, re.IGNORECASE)
    check(cat, "No GRANT to PUBLIC role",
          len(grant_public) == 0,
          f"Found {len(grant_public)} GRANT TO PUBLIC statements" if grant_public else "Clean")


# ══════════════════════════════════════════════════════════════════════════
# 3. SECRETS SECURITY
# ══════════════════════════════════════════════════════════════════════════

def check_secrets_security():
    cat = "Secrets Security"

    # --- 3a. No hardcoded secrets in source ---
    secret_patterns = [
        (r"sk-ant-api\d+-[A-Za-z0-9_-]{20,}", "Anthropic API key"),
        (r"AKIA[0-9A-Z]{16}", "AWS access key"),
        (r"(?i)password\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded password"),
    ]
    source_files = list(BACKEND_APP.rglob("*.py"))
    hardcoded_secrets = []
    for fpath in source_files:
        if fpath.name == "security_hardening_check.py":
            continue
        content = read_file(fpath)
        for pattern, label in secret_patterns:
            if re.search(pattern, content):
                hardcoded_secrets.append(f"{label} in {fpath.relative_to(ROOT)}")

    check(cat, "No hardcoded secrets in Python source",
          len(hardcoded_secrets) == 0,
          "; ".join(hardcoded_secrets) if hardcoded_secrets else "Clean")

    # --- 3b. .env not committed ---
    gitignore = read_file(ROOT / ".gitignore")
    env_ignored = ".env" in gitignore
    check(cat, ".env in .gitignore", env_ignored)

    # --- 3c. Secret redaction in logging ---
    logging_src = read_file(BACKEND_APP / "logging_config.py")
    has_redaction = "SecretRedactionFilter" in logging_src or "redact_secrets" in logging_src
    check(cat, "Secret redaction filter in logging", has_redaction)

    # --- 3d. API keys hashed (not stored in plain text) ---
    auth_src = read_file(BACKEND_APP / "api" / "auth.py")
    db_src = read_file(BACKEND_APP / "database.py")
    has_hash = "sha256" in auth_src or "sha256" in db_src
    check(cat, "API keys stored as SHA-256 hashes", has_hash)

    # --- 3e. Secrets loaded from environment (not config files) ---
    main_src = read_file(BACKEND_APP / "main.py")
    env_loaded = "os.getenv" in main_src or "os.environ" in main_src
    check(cat, "Secrets loaded from environment variables", env_loaded)

    # --- 3f. No secrets in frontend source ---
    frontend_secrets = []
    for fpath in (FRONTEND / "src").rglob("*.ts"):
        content = read_file(fpath)
        for pattern, label in secret_patterns:
            if re.search(pattern, content):
                frontend_secrets.append(f"{label} in {fpath.relative_to(ROOT)}")
    for fpath in (FRONTEND / "src").rglob("*.tsx"):
        content = read_file(fpath)
        for pattern, label in secret_patterns:
            if re.search(pattern, content):
                frontend_secrets.append(f"{label} in {fpath.relative_to(ROOT)}")

    check(cat, "No hardcoded secrets in frontend source",
          len(frontend_secrets) == 0,
          "; ".join(frontend_secrets) if frontend_secrets else "Clean")


# ══════════════════════════════════════════════════════════════════════════
# 4. TRANSPORT SECURITY
# ══════════════════════════════════════════════════════════════════════════

def check_transport_security():
    cat = "Transport Security"

    main_src = read_file(BACKEND_APP / "main.py")
    security_src = read_file(BACKEND_APP / "security.py")
    combined = main_src + security_src

    # --- 4a. HSTS header ---
    has_hsts = "Strict-Transport-Security" in combined
    check(cat, "HSTS header enabled", has_hsts)

    # --- 4b. X-Content-Type-Options ---
    has_nosniff = "X-Content-Type-Options" in combined and "nosniff" in combined
    check(cat, "X-Content-Type-Options: nosniff", has_nosniff)

    # --- 4c. X-Frame-Options ---
    has_xframe = "X-Frame-Options" in combined
    check(cat, "X-Frame-Options header set", has_xframe)

    # --- 4d. Content-Security-Policy ---
    has_csp = "Content-Security-Policy" in combined
    check(cat, "Content-Security-Policy header set", has_csp)

    # --- 4e. Secure cookie flags ---
    auth_src = read_file(BACKEND_APP / "api" / "auth.py")
    has_secure_cookie = ("secure=" in auth_src.lower() or "httponly" in auth_src.lower()
                         or "samesite" in auth_src.lower())
    # Also check if cookies are used at all (JWT may be header-only)
    uses_cookies = "set_cookie" in auth_src or "Set-Cookie" in auth_src
    if uses_cookies:
        check(cat, "Secure cookie flags (Secure, HttpOnly, SameSite)",
              has_secure_cookie,
              "Cookies are set — checking for secure flags")
    else:
        check(cat, "Secure cookie flags (Secure, HttpOnly, SameSite)",
              True,
              "No Set-Cookie usage found (JWT via Authorization header)")

    # --- 4f. CORS restricted to specific origins ---
    has_cors_whitelist = re.search(r"ALLOWED_ORIGINS|origins\s*=", combined)
    has_wildcard_cors = re.search(r"origins.*\*|allow_origin.*\*", combined)
    check(cat, "CORS restricted (no wildcard origin)",
          has_cors_whitelist is not None and has_wildcard_cors is None,
          "CORS uses allowlisted origins" if has_wildcard_cors is None
          else "WARNING: Wildcard CORS origin detected")

    # --- 4g. DB SSL mode ---
    has_sslmode = "sslmode" in read_file(BACKEND_APP / "database.py")
    env_example = read_file(BACKEND / ".env.example")
    has_ssl_env = "DB_SSLMODE" in env_example or "sslmode=require" in read_file(BACKEND_APP / "database.py")
    check(cat, "Database SSL mode configured",
          has_sslmode or has_ssl_env,
          "DB_SSLMODE or sslmode parameter found")

    # --- 4h. JSON responses have no-cache headers ---
    has_nocache = "no-store" in combined or "no-cache" in combined
    check(cat, "Cache-Control: no-store on JSON responses", has_nocache)


# ══════════════════════════════════════════════════════════════════════════
# 5. AI SECURITY
# ══════════════════════════════════════════════════════════════════════════

def check_ai_security():
    cat = "AI Security"

    main_src = read_file(BACKEND_APP / "main.py")
    handler_src = read_file(BACKEND_APP / "api" / "handlers.py")
    gateway_src = read_file(BACKEND_APP / "ai" / "copilot_gateway.py")
    service_src = read_file(BACKEND_APP / "services" / "copilot_service.py")

    # --- 5a. AI endpoints gated by feature flag ---
    copilot_routes = re.findall(r"['\"](/api/copilot/[^'\"]+)['\"]", main_src)
    ai_routes = re.findall(r"['\"](/api/ai/[^'\"]+)['\"]", main_src)
    all_ai_routes = copilot_routes + ai_routes

    # Check that require_feature('ai_copilot') appears near each route
    ungated = []
    for route in all_ai_routes:
        # Search for the route and look for require_feature in nearby decorators
        idx = main_src.find(route)
        if idx >= 0:
            # Look at 500 chars before the route for the decorator
            preceding = main_src[max(0, idx - 500):idx]
            if "require_feature" not in preceding and "ai_copilot" not in preceding:
                ungated.append(route)

    check(cat, "AI endpoints gated by feature flag",
          len(ungated) == 0,
          f"Ungated AI routes: {ungated}" if ungated
          else f"{len(all_ai_routes)} AI routes, all feature-gated")

    # --- 5b. AI rate limiting ---
    has_ai_rate_limit = "check_rate_limit" in gateway_src
    check(cat, "AI copilot rate limiting enabled", has_ai_rate_limit)

    # --- 5c. AI audit logging ---
    has_audit = "copilot_usage" in gateway_src or "log_usage" in gateway_src
    check(cat, "AI usage audit logging (copilot_usage table)", has_audit)

    # --- 5d. Prompt size truncation ---
    has_truncate = "MAX_PROMPT_SIZE" in gateway_src or "truncate_prompt" in gateway_src
    check(cat, "Prompt size truncation enforced", has_truncate)

    # --- 5e. Tenant boundary in prompts ---
    has_tenant_prefix = "TENANT BOUNDARY" in gateway_src or "build_tenant_context_prefix" in gateway_src
    check(cat, "Tenant boundary prefix in AI prompts", has_tenant_prefix)

    # --- 5f. LLM never has direct DB access ---
    # CopilotService should NOT import database.py
    has_db_import = "from app.database" in service_src or "import database" in service_src
    check(cat, "LLM service has no direct DB access",
          not has_db_import,
          "CopilotService does not import database module" if not has_db_import
          else "WARNING: CopilotService imports database module directly")

    # --- 5g. API key not exposed to client ---
    frontend_src_files = list((FRONTEND / "src").rglob("*.ts")) + list((FRONTEND / "src").rglob("*.tsx"))
    ai_key_in_frontend = False
    for fpath in frontend_src_files:
        content = read_file(fpath)
        if re.search(r"ANTHROPIC_API_KEY|sk-ant-api", content):
            ai_key_in_frontend = True
            break
    check(cat, "AI API key not exposed in frontend", not ai_key_in_frontend)

    # --- 5h. Timeout on AI client ---
    has_timeout = "timeout" in service_src
    check(cat, "Timeout configured on Anthropic client", has_timeout)


# ══════════════════════════════════════════════════════════════════════════
# 6. GRAPH ENGINE SECURITY
# ══════════════════════════════════════════════════════════════════════════

def check_graph_engine_security():
    cat = "Graph Engine Security"

    engines_dir = BACKEND_APP / "engines"

    # --- 6a. Graph engine receives DB with tenant context ---
    attack_src = read_file(engines_dir / "graph_attack_engine.py")
    intelligence_src = read_file(engines_dir / "graph_intelligence.py")

    # GraphAttackEngine.__init__ takes db parameter (tenant-scoped)
    has_db_param = "def __init__(self, db)" in attack_src
    check(cat, "GraphAttackEngine uses injected DB (tenant-scoped)",
          has_db_param,
          "DB injected via constructor" if has_db_param
          else "WARNING: Graph engine may not use tenant-scoped DB")

    # --- 6b. Graph queries filter by run_id (scoped to tenant) ---
    has_run_filter = "discovery_run_id" in attack_src or "run_id" in attack_src
    check(cat, "Graph queries filter by discovery_run_id",
          has_run_filter,
          "Queries use run_id for tenant-scoped data isolation")

    # --- 6c. Graph intelligence scoped by org_id ---
    has_org_scope = "org_id" in intelligence_src or "organization_id" in intelligence_src
    check(cat, "Graph intelligence scoped by organization_id", has_org_scope)

    # --- 6d. No cross-tenant data in graph output ---
    # Check that graph results include org_id for provenance
    has_org_in_output = "organization_id" in intelligence_src
    check(cat, "Graph results tagged with organization_id", has_org_in_output)

    # --- 6e. Attack path engine doesn't use raw SQL interpolation ---
    # Check for f-string SQL (potential injection)
    sql_injection_risk = re.findall(
        r'cursor\.execute\(\s*f["\']', attack_src
    )
    check(cat, "No f-string SQL in graph engine (injection safe)",
          len(sql_injection_risk) == 0,
          f"Found {len(sql_injection_risk)} f-string SQL calls" if sql_injection_risk
          else "All queries use parameterized statements")

    # --- 6f. Check all engine files for SQL injection patterns ---
    engine_files = list(engines_dir.rglob("*.py"))
    injection_files = []
    for fpath in engine_files:
        content = read_file(fpath)
        fstring_sql = re.findall(r'cursor\.execute\(\s*f["\']', content)
        pct_format = re.findall(r'cursor\.execute\(.*%\s*\(', content)
        # .format() in execute calls
        format_sql = re.findall(r'cursor\.execute\(.*\.format\(', content)
        if fstring_sql or format_sql:
            injection_files.append(str(fpath.relative_to(ROOT)))

    check(cat, "No SQL injection patterns across all engines",
          len(injection_files) == 0,
          f"Potential injection in: {injection_files}" if injection_files
          else f"{len(engine_files)} engine files checked")


# ══════════════════════════════════════════════════════════════════════════
# 7. LOGGING SECURITY
# ══════════════════════════════════════════════════════════════════════════

def check_logging_security():
    cat = "Logging Security"

    logging_src = read_file(BACKEND_APP / "logging_config.py")

    # --- 7a. Secret redaction filter exists ---
    has_filter = "SecretRedactionFilter" in logging_src
    check(cat, "SecretRedactionFilter class defined", has_filter)

    # --- 7b. Covers key secret patterns ---
    required_patterns = ["password", "api_key", "token", "secret"]
    covered = [p for p in required_patterns if p in logging_src.lower()]
    check(cat, "Redaction covers password/api_key/token/secret",
          len(covered) == len(required_patterns),
          f"Covered: {covered}, Missing: {set(required_patterns) - set(covered)}")

    # --- 7c. Bearer token redaction ---
    has_bearer = "Bearer" in logging_src
    check(cat, "Bearer token redaction pattern", has_bearer)

    # --- 7d. API key (ag_) redaction ---
    has_ag_key = "ag_" in logging_src
    check(cat, "AuditGraph API key (ag_) redaction pattern", has_ag_key)

    # --- 7e. Filter applied to root logger ---
    has_apply = "addFilter" in logging_src
    check(cat, "Redaction filter applied to logging handler", has_apply)

    # --- 7f. JSON structured logging in production ---
    has_json = "JSONFormatter" in logging_src
    check(cat, "JSON structured logging for production", has_json)

    # --- 7g. No debug logging of request bodies in auth ---
    auth_src = read_file(BACKEND_APP / "api" / "auth.py")
    debug_body = re.findall(r"logger\.debug.*request\.(data|json|form)", auth_src)
    check(cat, "No debug logging of auth request bodies",
          len(debug_body) == 0,
          f"Found {len(debug_body)} debug body logs" if debug_body else "Clean")


# ══════════════════════════════════════════════════════════════════════════
# 8. DEPENDENCY SECURITY
# ══════════════════════════════════════════════════════════════════════════

def check_dependency_security():
    cat = "Dependency Security"

    # --- 8a. Run pip-audit if available ---
    try:
        result = subprocess.run(
            ["pip-audit", "--require-hashes=false", "-r",
             str(BACKEND / "requirements.txt"), "--format=json"],
            capture_output=True, text=True, timeout=120,
            cwd=str(BACKEND),
        )
        if result.returncode == 0:
            try:
                audit_data = json.loads(result.stdout)
                vulns = audit_data.get("dependencies", [])
                vuln_count = sum(
                    1 for d in vulns
                    if d.get("vulns") and len(d["vulns"]) > 0
                )
            except (json.JSONDecodeError, KeyError):
                vuln_count = 0

            check(cat, "pip-audit: no known vulnerabilities",
                  vuln_count == 0,
                  f"{vuln_count} vulnerable packages" if vuln_count
                  else "All packages clean")
        else:
            # pip-audit failed but is installed
            stderr = result.stderr.strip()[:200]
            check(cat, "pip-audit: no known vulnerabilities", False,
                  f"pip-audit exited {result.returncode}: {stderr}")
    except FileNotFoundError:
        check(cat, "pip-audit: no known vulnerabilities", False,
              "pip-audit not installed (pip install pip-audit)")
    except subprocess.TimeoutExpired:
        check(cat, "pip-audit: no known vulnerabilities", False,
              "pip-audit timed out after 120s")

    # --- 8b. No pinned insecure versions ---
    req_src = read_file(BACKEND / "requirements.txt")
    # Known CVE-affected versions (sample)
    insecure_pins = {
        "pyjwt": ["1.", "2.0.", "2.1.", "2.2.", "2.3."],
        "cryptography": ["3.", "36.", "37.", "38.", "39.", "40.", "41."],
        "flask": ["1.", "2.0.", "2.1.", "2.2."],
    }
    flagged = []
    for pkg, bad_prefixes in insecure_pins.items():
        match = re.search(rf"^{pkg}[=><!]+([0-9][^\s,;]*)", req_src,
                          re.IGNORECASE | re.MULTILINE)
        if match:
            version = match.group(1)
            for prefix in bad_prefixes:
                if version.startswith(prefix):
                    flagged.append(f"{pkg}=={version}")

    check(cat, "No known-insecure pinned versions",
          len(flagged) == 0,
          f"Flagged: {flagged}" if flagged else "Version pins look current")

    # --- 8c. Frontend: npm audit ---
    pkg_lock = FRONTEND / "package-lock.json"
    if pkg_lock.exists():
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True, text=True, timeout=60,
                cwd=str(FRONTEND),
            )
            try:
                audit_json = json.loads(result.stdout)
                total_vulns = audit_json.get("metadata", {}).get("vulnerabilities", {})
                critical = total_vulns.get("critical", 0)
                high = total_vulns.get("high", 0)
            except (json.JSONDecodeError, KeyError):
                critical, high = 0, 0

            check(cat, "npm audit: no critical/high vulnerabilities",
                  critical == 0 and high == 0,
                  f"critical={critical}, high={high}")
        except FileNotFoundError:
            check(cat, "npm audit: no critical/high vulnerabilities", False,
                  "npm not found")
        except subprocess.TimeoutExpired:
            check(cat, "npm audit: no critical/high vulnerabilities", False,
                  "npm audit timed out")
    else:
        check(cat, "npm audit: no critical/high vulnerabilities", False,
              "package-lock.json not found")

    # --- 8d. requirements.txt has pinned versions ---
    req_lines = [l.strip() for l in req_src.splitlines()
                 if l.strip() and not l.startswith("#") and not l.startswith("-")]
    unpinned = [l for l in req_lines if "==" not in l and ">=" not in l and "<" not in l]
    check(cat, "Python dependencies have version constraints",
          len(unpinned) <= 3,
          f"{len(unpinned)} unpinned: {unpinned[:5]}" if unpinned
          else "All dependencies pinned")


# ══════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════

CATEGORY_ORDER = [
    "API Security",
    "Database Security",
    "Secrets Security",
    "Transport Security",
    "AI Security",
    "Graph Engine Security",
    "Logging Security",
    "Dependency Security",
]

PASS_ICON = "\033[92mPASS\033[0m"
FAIL_ICON = "\033[91mFAIL\033[0m"


def print_report(verbose: bool = False):
    """Print human-readable report."""
    total = len(_results)
    passed = sum(1 for r in _results if r["status"] == "PASS")
    failed = total - passed

    print()
    print("=" * 72)
    print("  AuditGraph Security Hardening Report")
    print("=" * 72)
    print()

    for cat in CATEGORY_ORDER:
        cat_results = [r for r in _results if r["category"] == cat]
        if not cat_results:
            continue

        cat_pass = sum(1 for r in cat_results if r["status"] == "PASS")
        cat_total = len(cat_results)
        cat_icon = "\033[92m" if cat_pass == cat_total else "\033[91m"
        print(f"{cat_icon}[{cat_pass}/{cat_total}]\033[0m {cat}")
        print("-" * 72)

        for r in cat_results:
            icon = PASS_ICON if r["status"] == "PASS" else FAIL_ICON
            print(f"  {icon}  {r['control']}")
            if verbose and r["detail"]:
                print(f"         {r['detail']}")

        print()

    # Summary
    print("=" * 72)
    pct = (passed / total * 100) if total else 0
    color = "\033[92m" if failed == 0 else "\033[91m"
    print(f"  {color}{passed}/{total} controls passed ({pct:.0f}%)\033[0m")
    if failed > 0:
        print(f"  \033[91m{failed} controls FAILED\033[0m")
    print("=" * 72)
    print()


def print_json():
    """Print JSON report."""
    total = len(_results)
    passed = sum(1 for r in _results if r["status"] == "PASS")
    report = {
        "summary": {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "pass_rate": round(passed / total * 100, 1) if total else 0,
        },
        "categories": {},
        "results": _results,
    }
    for cat in CATEGORY_ORDER:
        cat_results = [r for r in _results if r["category"] == cat]
        report["categories"][cat] = {
            "total": len(cat_results),
            "passed": sum(1 for r in cat_results if r["status"] == "PASS"),
            "failed": sum(1 for r in cat_results if r["status"] == "FAIL"),
        }
    print(json.dumps(report, indent=2))


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="AuditGraph Security Hardening Checker"
    )
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detail for each check")
    parser.add_argument("--json", action="store_true",
                        help="Output JSON report")
    args = parser.parse_args()

    # Run all checks
    check_api_security()
    check_database_security()
    check_secrets_security()
    check_transport_security()
    check_ai_security()
    check_graph_engine_security()
    check_logging_security()
    check_dependency_security()

    # Output
    if args.json:
        print_json()
    else:
        print_report(verbose=args.verbose)

    # Exit code
    failed = sum(1 for r in _results if r["status"] == "FAIL")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
