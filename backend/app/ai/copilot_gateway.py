"""Central Copilot Gateway — enforces tenant isolation, rate limits, prompt safety.

Architecture:
    handler → copilot_gateway.run_query() → context builders → CopilotService → Anthropic API

The LLM never touches the database. All data is pre-filtered through tenant-scoped
Database connections (RLS-enforced) and structured into safe prompts before reaching the AI.
"""

import logging
import os
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────

MAX_PROMPT_SIZE = 8000       # Max chars for user question + context combined
MAX_RESPONSE_TOKENS = 2000   # Max tokens in LLM response
DEFAULT_MODEL = os.getenv('LLM_MODEL', 'claude-sonnet-4-5-20250514')

# Queries per day per org, keyed by plan
RATE_LIMITS = {
    'free': 10,
    'trial': 100,
    'pro': 1000,
}


# ── Gateway ────────────────────────────────────────────────────────────────

class CopilotGateway:
    """Mediates between HTTP handlers and the CopilotService.

    Responsibilities:
        1. Load CopilotService from platform env key (never per-tenant)
        2. Enforce tenant isolation via RLS-scoped Database connections
        3. Apply per-org daily rate limits
        4. Truncate prompts to MAX_PROMPT_SIZE
        5. Log usage to copilot_usage table
        6. Prevent raw DB results from reaching the LLM
    """

    def __init__(self):
        self._service = None
        self._service_err = None
        self._checked = False

    def _get_service(self):
        """Lazily initialize the CopilotService from the platform env config.

        Provider routing — COPILOT_PROVIDER selects backend:
          anthropic (default) — requires ANTHROPIC_API_KEY
          openai              — requires OPENAI_API_KEY (placeholder fallback)
          ollama              — local LLM; needs `ollama serve` running
        """
        if not self._checked:
            from app.services.copilot_service import CopilotService
            provider = os.getenv('COPILOT_PROVIDER', 'anthropic').lower().strip()
            if provider == 'ollama':
                self._service = CopilotService('ollama-no-key-needed')
                self._service_err = None
            elif provider == 'openai':
                oa_key = os.getenv('OPENAI_API_KEY', '').strip()
                if oa_key:
                    self._service = CopilotService(oa_key)
                    self._service_err = None
                else:
                    self._service = None
                    self._service_err = (
                        'AI Copilot is not configured. COPILOT_PROVIDER=openai '
                        'is set but OPENAI_API_KEY is missing. Add it to '
                        '.env.local (or switch back to COPILOT_PROVIDER=anthropic).'
                    )
            else:
                api_key = os.getenv('ANTHROPIC_API_KEY', '').strip()
                if api_key:
                    self._service = CopilotService(api_key)
                    self._service_err = None
                else:
                    self._service = None
                    self._service_err = (
                        'AI Copilot is not configured. Set one of: '
                        'ANTHROPIC_API_KEY (production), '
                        'OPENAI_API_KEY + COPILOT_PROVIDER=openai (fallback), '
                        'or COPILOT_PROVIDER=ollama (local; heavy on Mac RAM).'
                    )
            self._checked = True
        return self._service, self._service_err

    # ── Public API ─────────────────────────────────────────────────────

    def check_available(self):
        """Return (service, error_msg). Error is None when available."""
        return self._get_service()

    def check_rate_limit(self, db, org_id, plan):
        """Check if the org has exceeded its daily copilot query limit.

        Returns (allowed: bool, error_msg_or_None).
        """
        limit = RATE_LIMITS.get(plan, RATE_LIMITS.get('pro', 1000))
        try:
            cursor = db.conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM copilot_usage
                WHERE org_id = %s AND created_at >= (CURRENT_DATE AT TIME ZONE 'UTC')
            """, (org_id,))
            count = cursor.fetchone()[0]
            cursor.close()
            if count >= limit:
                return False, f'Daily Copilot limit reached ({limit} queries/day on {plan} plan). Upgrade for more.'
            return True, None
        except Exception as e:
            logger.warning(f"Rate limit check failed (allowing): {e}")
            try:
                db._rollback()
            except Exception:
                pass
            return True, None  # Fail open on DB errors

    def log_usage(self, db, org_id, user_id, query_type, tokens_used=0, latency_ms=0, model=None):
        """Record a copilot request in the copilot_usage table."""
        try:
            cursor = db.conn.cursor()
            cursor.execute("""
                INSERT INTO copilot_usage (org_id, user_id, query_type, tokens_used, latency_ms, model, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (org_id, user_id, query_type, tokens_used, latency_ms,
                  model or DEFAULT_MODEL, datetime.now(timezone.utc)))
            db._commit()
            cursor.close()
        except Exception as e:
            logger.warning(f"Failed to log copilot usage: {e}")
            try:
                db._rollback()
            except Exception:
                pass

    def truncate_prompt(self, text, max_len=None):
        """Truncate text to max prompt size."""
        limit = max_len or MAX_PROMPT_SIZE
        if len(text) > limit:
            return text[:limit] + '\n\n[Context truncated for safety]'
        return text

    def build_tenant_context_prefix(self, org_id, org_name=None):
        """Build a standard tenant boundary prefix for all prompts."""
        name_part = f' ({org_name})' if org_name else ''
        return (
            f"TENANT BOUNDARY: You are analyzing security data for organization {org_id}{name_part}. "
            f"Only use the provided context. Do not reference data from other organizations. "
            f"Do not attempt to query any databases or external systems.\n\n"
        )

    def run_query(self, db, org_id, user_id, plan, query_type, execute_fn):
        """Orchestrate a copilot request through the full pipeline.

        Args:
            db: Tenant-scoped Database instance (RLS-enforced)
            org_id: Organization ID
            user_id: Requesting user ID
            plan: Org plan tier (free/trial/pro)
            query_type: String label for logging (e.g. 'chat', 'investigate_identity')
            execute_fn: Callable(service) → result dict. Called with the CopilotService.

        Returns:
            (result_dict, status_code) tuple.
        """
        # 1. Check service availability
        service, svc_err = self._get_service()
        if not service:
            return {'error': svc_err}, 503

        # 2. Check rate limit
        allowed, rate_err = self.check_rate_limit(db, org_id, plan)
        if not allowed:
            return {'error': rate_err}, 429

        # 3. Execute the query
        start = time.time()
        try:
            result = execute_fn(service)
        except Exception as e:
            logger.error(f"Copilot query error ({query_type}): {e}", exc_info=True)
            return {'error': f'AI service error: {type(e).__name__}: {e}'}, 502

        latency_ms = int((time.time() - start) * 1000)

        # 4. Log usage
        self.log_usage(db, org_id, user_id, query_type, latency_ms=latency_ms)

        # 5. Attach metadata
        if isinstance(result, dict):
            result['duration_ms'] = latency_ms
        return result, 200

    def health_check(self):
        """Return copilot health status for /api/system/ai-health."""
        service, err = self._get_service()
        return {
            'copilot_enabled': service is not None,
            'provider': 'anthropic' if service else None,
            'model': DEFAULT_MODEL if service else None,
            'api_key_present': bool(os.getenv('ANTHROPIC_API_KEY', '').strip()),
            'error': err,
        }


# ── Module-level singleton ─────────────────────────────────────────────────

_gateway = None


def get_gateway():
    """Return the module-level CopilotGateway singleton."""
    global _gateway
    if _gateway is None:
        _gateway = CopilotGateway()
    return _gateway
