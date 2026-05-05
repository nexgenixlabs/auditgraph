#!/usr/bin/env python3
"""AG-95 / AG-95-v2: Static lint for insecure SAML/SSO patterns.

Detects:
  SSO001 — Insecure SAML signing flags (wantAssertionsSigned: False, etc.)
  SSO002 — Direct OneLogin_Saml2_Auth construction outside approved modules
  SSO003 — Weak hash (SHA-1 / MD5) in auth/security files
  SSO004 — Plaintext code comparison (== on code/auth_code variables)
  SSO005 — Plaintext code storage in sso_auth_codes INSERT
  SSO006 — wantNameIdEncrypted: False (CWE-311, SAML V2.0 §3.4)
  SSO007 — wantAssertionsEncrypted: False (CWE-311, SAML V2.0 §6.2)
  SSO008 — Direct OneLogin_Saml2_Auth construction outside sso_security.py

Usage:
  python scripts/lint_sso_settings.py --baseline   # Generate baseline JSON
  python scripts/lint_sso_settings.py              # Check for new violations
  python scripts/lint_sso_settings.py --strict     # Ignore baseline (CI gate)
  python scripts/lint_sso_settings.py --strict --rules SSO006,SSO007,SSO008
  python scripts/lint_sso_settings.py --fix-suggestions  # Print remediation hints
"""

import ast
import json
import os
import sys
from pathlib import Path

BASELINE_FILE = os.path.join(os.path.dirname(__file__), '..', '.sso-lint-baseline.json')
SCAN_ROOT = os.path.join(os.path.dirname(__file__), '..', 'app')

# Modules allowed to construct OneLogin_Saml2_Auth directly
APPROVED_AUTH_MODULES = {'saml.py', 'sso_security.py'}

# SAML signing flags that must NOT be False
REQUIRED_TRUE_FLAGS = {
    'wantAssertionsSigned', 'wantMessagesSigned', 'rejectDeprecatedAlgorithm',
}

# SAML encryption flags that must NOT be False (AG-95-v2)
ENCRYPTION_FLAGS = {
    'wantNameIdEncrypted', 'wantAssertionsEncrypted',
}

# Files where per-org override logic reads these flags dynamically — exempt
# The only exempt path is inside build_secure_saml_settings() in sso_security.py
# which uses `not accept_unencrypted_*` (never a literal False for these keys)
ENCRYPTION_EXEMPT_FILES = set()  # No exemptions — literals should never appear

REMEDIATION = {
    'SSO001': 'Use build_secure_saml_settings() from app.security.sso_security instead of inline dicts.',
    'SSO002': 'Use get_saml_auth() from app.api.saml instead of constructing OneLogin_Saml2_Auth directly.',
    'SSO003': 'Use SHA-256 or stronger. See app.security.sso_security for hash_code() helper.',
    'SSO004': 'Use hmac.compare_digest() or verify_code_constant_time() for code comparison.',
    'SSO005': 'Use hash_code() from app.security.sso_security to HMAC-hash codes before INSERT.',
    'SSO006': "wantNameIdEncrypted must be True (CWE-311, SAML V2.0 §3.4). "
              "Use per-org override via sso_accept_unencrypted_nameid setting.",
    'SSO007': "wantAssertionsEncrypted must be True (CWE-311, SAML V2.0 §6.2). "
              "Use per-org override via sso_accept_unencrypted_assertions setting.",
    'SSO008': 'All OneLogin_Saml2_Auth construction must go through get_saml_auth() in saml.py.',
}


class SsoLintVisitor(ast.NodeVisitor):
    """AST visitor that detects insecure SSO patterns."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.violations = []

    def _add(self, rule, line, msg):
        self.violations.append({
            'file': self.filepath,
            'line': line,
            'rule': rule,
            'message': msg,
        })

    # SSO001: Dict keys with insecure False values (signing flags)
    # SSO006/SSO007: Encryption flags set to False
    def visit_Dict(self, node):
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                # SSO001: Signing flags
                if key.value in REQUIRED_TRUE_FLAGS:
                    if isinstance(value, ast.Constant) and value.value is False:
                        self._add(
                            'SSO001', node.lineno,
                            f"'{key.value}': False — must be True for SAML security",
                        )
                # SSO006: wantNameIdEncrypted
                if key.value == 'wantNameIdEncrypted':
                    if isinstance(value, ast.Constant) and value.value is False:
                        if self.filename not in ENCRYPTION_EXEMPT_FILES:
                            self._add(
                                'SSO006', node.lineno,
                                "'wantNameIdEncrypted': False — NameID must be encrypted (CWE-311)",
                            )
                # SSO007: wantAssertionsEncrypted
                if key.value == 'wantAssertionsEncrypted':
                    if isinstance(value, ast.Constant) and value.value is False:
                        if self.filename not in ENCRYPTION_EXEMPT_FILES:
                            self._add(
                                'SSO007', node.lineno,
                                "'wantAssertionsEncrypted': False — assertions must be encrypted (CWE-311)",
                            )
                # strict: False
                if key.value == 'strict':
                    if isinstance(value, ast.Constant) and value.value is False:
                        self._add('SSO001', node.lineno,
                                  "'strict': False — SAML strict mode must be True")
        self.generic_visit(node)

    # SSO002/SSO008: Direct OneLogin_Saml2_Auth() calls outside approved modules
    def visit_Call(self, node):
        func_name = ''
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name == 'OneLogin_Saml2_Auth':
            if self.filename not in APPROVED_AUTH_MODULES:
                self._add(
                    'SSO002', node.lineno,
                    'Direct OneLogin_Saml2_Auth construction — use get_saml_auth() instead',
                )
            # SSO008: Even in saml.py, only sso_security.py is ideal
            if self.filename == 'saml.py':
                # saml.py is approved for now (thin wrapper)
                pass
            elif self.filename != 'sso_security.py' and self.filename not in APPROVED_AUTH_MODULES:
                self._add(
                    'SSO008', node.lineno,
                    'OneLogin_Saml2_Auth outside sso_security.py — centralize in SSOT module',
                )

        # SSO003: Weak hash calls
        rel_path = self.filepath.replace(SCAN_ROOT, '')
        if '/api/' in rel_path or '/security/' in rel_path:
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ('sha1', 'md5'):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == 'hashlib':
                        self._add(
                            'SSO003', node.lineno,
                            f'hashlib.{node.func.attr}() — use SHA-256 or stronger',
                        )
        self.generic_visit(node)

    # SSO004: Plaintext code comparison with ==
    def visit_Compare(self, node):
        for op in node.ops:
            if isinstance(op, ast.Eq):
                names = set()
                if isinstance(node.left, ast.Name):
                    names.add(node.left.id.lower())
                for comp in node.comparators:
                    if isinstance(comp, ast.Name):
                        names.add(comp.id.lower())
                code_vars = {'code', 'auth_code', 'sso_code', 'code_hash', 'submitted_code'}
                if names & code_vars:
                    self._add(
                        'SSO004', node.lineno,
                        'Plaintext == on code variable — use hmac.compare_digest()',
                    )
        self.generic_visit(node)


def scan_file(filepath):
    """Scan a single Python file for SSO lint violations."""
    violations = []
    try:
        with open(filepath, 'r') as f:
            source = f.read()
    except (IOError, UnicodeDecodeError):
        return violations

    # AST-based checks
    try:
        tree = ast.parse(source, filename=filepath)
        visitor = SsoLintVisitor(filepath)
        visitor.visit(tree)
        violations.extend(visitor.violations)
    except SyntaxError:
        pass

    # SSO005: Regex-based check for plaintext code storage
    for i, line in enumerate(source.splitlines(), 1):
        if 'sso_auth_codes' in line and 'INSERT' in line.upper():
            start = max(0, i - 3)
            end = min(len(source.splitlines()), i + 5)
            context = '\n'.join(source.splitlines()[start:end])
            if 'hash_code' not in context and 'code_hash' not in context:
                violations.append({
                    'file': filepath,
                    'line': i,
                    'rule': 'SSO005',
                    'message': 'INSERT into sso_auth_codes without hash_code — codes must be HMAC-hashed',
                })

    return violations


def scan_all(scan_root=None):
    """Scan all Python files under app/."""
    root_dir = scan_root or SCAN_ROOT
    violations = []
    for root, _, files in os.walk(root_dir):
        for fname in sorted(files):
            if not fname.endswith('.py'):
                continue
            filepath = os.path.join(root, fname)
            violations.extend(scan_file(filepath))
    return violations


def violation_key(v):
    return f"{v['file']}:{v['line']}:{v['rule']}:{v['message']}"


def main():
    args = sys.argv[1:]
    show_suggestions = '--fix-suggestions' in args
    generate_baseline = '--baseline' in args
    strict_mode = '--strict' in args

    # Optional rule filter for --strict mode
    strict_rules = None
    for arg in args:
        if arg.startswith('--rules'):
            idx = args.index(arg)
            if '=' in arg:
                strict_rules = set(arg.split('=', 1)[1].split(','))
            elif idx + 1 < len(args):
                strict_rules = set(args[idx + 1].split(','))

    violations = scan_all()

    if generate_baseline:
        baseline = sorted(set(violation_key(v) for v in violations))
        baseline_path = os.path.abspath(BASELINE_FILE)
        with open(baseline_path, 'w') as f:
            json.dump(baseline, f, indent=2)
        print(f"Baseline generated: {len(baseline)} entries → {baseline_path}")
        return 0

    if strict_mode:
        # --strict: ignore baseline entirely. Optionally filter by rules.
        check_violations = violations
        if strict_rules:
            check_violations = [v for v in violations if v['rule'] in strict_rules]

        if check_violations:
            print(f"\n{'='*70}")
            print(f"SSO Lint [STRICT]: {len(check_violations)} violation(s) found")
            print(f"{'='*70}\n")
            for v in check_violations:
                print(f"  {v['file']}:{v['line']}: [{v['rule']}] {v['message']}")
                if show_suggestions and v['rule'] in REMEDIATION:
                    print(f"    FIX: {REMEDIATION[v['rule']]}")
            print()
            return 1

        rules_msg = f" (rules: {','.join(sorted(strict_rules))})" if strict_rules else ""
        print(f"SSO Lint [STRICT]: OK — 0 violations{rules_msg}")
        return 0

    # Normal mode: compare against baseline
    baseline_keys = set()
    baseline_path = os.path.abspath(BASELINE_FILE)
    if os.path.exists(baseline_path):
        with open(baseline_path) as f:
            baseline_keys = set(json.load(f))

    new_violations = [v for v in violations if violation_key(v) not in baseline_keys]

    if new_violations:
        print(f"\n{'='*70}")
        print(f"SSO Lint: {len(new_violations)} NEW violation(s) found")
        print(f"{'='*70}\n")
        for v in new_violations:
            print(f"  {v['file']}:{v['line']}: [{v['rule']}] {v['message']}")
            if show_suggestions and v['rule'] in REMEDIATION:
                print(f"    FIX: {REMEDIATION[v['rule']]}")
        print()
        return 1

    total = len(violations)
    baselined = total - len(new_violations)
    print(f"SSO Lint: OK — {total} total, {baselined} baselined, 0 new violations")
    return 0


if __name__ == '__main__':
    sys.exit(main())
