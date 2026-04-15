"""
Resilience — Retry with exponential backoff + circuit breaker for external APIs.

Provides decorators and utilities for resilient external API calls:
    - Azure Graph API
    - AWS APIs
    - Anthropic (Copilot) API

Uses tenacity for retry logic with:
    - Exponential backoff (1s → 2s → 4s → 8s, max 30s)
    - Circuit breaker pattern (open after N consecutive failures)
    - Separate retry configs per service class
    - Structured logging for all retry events

Usage:
    from app.resilience import retry_graph_api, retry_aws_api, retry_llm_api

    @retry_graph_api
    def call_graph():
        response = requests.get("https://graph.microsoft.com/v1.0/users")
        response.raise_for_status()
        return response.json()
"""
import logging
import threading
import time
from functools import wraps

logger = logging.getLogger(__name__)

try:
    from tenacity import (
        retry,
        stop_after_attempt,
        wait_exponential,
        retry_if_exception_type,
        before_sleep_log,
        RetryError,
    )
    TENACITY_AVAILABLE = True
except ImportError:
    TENACITY_AVAILABLE = False
    logger.warning("tenacity not installed — retry/circuit-breaker disabled")


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------

class CircuitBreaker:
    """Simple circuit breaker with threshold-based state transitions.

    States:
        CLOSED  — normal operation, requests pass through
        OPEN    — requests blocked, returns error immediately
        HALF_OPEN — single test request allowed to check recovery

    State transitions:
        CLOSED → OPEN: after `failure_threshold` consecutive failures
        OPEN → HALF_OPEN: after `recovery_timeout` seconds
        HALF_OPEN → CLOSED: on first success
        HALF_OPEN → OPEN: on failure
    """
    CLOSED = 'closed'
    OPEN = 'open'
    HALF_OPEN = 'half_open'

    def __init__(self, name, failure_threshold=5, recovery_timeout=60):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._state = self.CLOSED
        self._failure_count = 0
        self._last_failure_time = 0
        self._lock = threading.Lock()

    @property
    def state(self):
        with self._lock:
            if self._state == self.OPEN:
                if time.time() - self._last_failure_time >= self.recovery_timeout:
                    self._state = self.HALF_OPEN
                    logger.info("Circuit breaker %s: OPEN → HALF_OPEN", self.name)
            return self._state

    def record_success(self):
        with self._lock:
            self._failure_count = 0
            if self._state != self.CLOSED:
                logger.info("Circuit breaker %s: %s → CLOSED", self.name, self._state)
                self._state = self.CLOSED

    def record_failure(self):
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            if self._failure_count >= self.failure_threshold:
                if self._state != self.OPEN:
                    logger.warning(
                        "Circuit breaker %s: OPEN after %d failures",
                        self.name, self._failure_count,
                    )
                self._state = self.OPEN

    def allow_request(self):
        return self.state != self.OPEN

    def stats(self):
        return {
            'name': self.name,
            'state': self.state,
            'failure_count': self._failure_count,
            'failure_threshold': self.failure_threshold,
            'recovery_timeout': self.recovery_timeout,
        }


# Global circuit breakers per service
_breakers = {
    'graph_api': CircuitBreaker('graph_api', failure_threshold=5, recovery_timeout=60),
    'aws_api': CircuitBreaker('aws_api', failure_threshold=5, recovery_timeout=60),
    'llm_api': CircuitBreaker('llm_api', failure_threshold=3, recovery_timeout=120),
}


def get_circuit_breaker(name):
    """Get or create a circuit breaker by name."""
    if name not in _breakers:
        _breakers[name] = CircuitBreaker(name)
    return _breakers[name]


def get_all_breaker_stats():
    """Get stats for all circuit breakers (for health endpoint)."""
    return {name: cb.stats() for name, cb in _breakers.items()}


# ---------------------------------------------------------------------------
# Retry Decorators
# ---------------------------------------------------------------------------

def _with_circuit_breaker(breaker_name):
    """Combine circuit breaker check with the wrapped function."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            cb = _breakers.get(breaker_name)
            if cb and not cb.allow_request():
                raise CircuitBreakerOpenError(
                    f"Circuit breaker '{breaker_name}' is OPEN — request blocked"
                )
            try:
                result = f(*args, **kwargs)
                if cb:
                    cb.record_success()
                return result
            except Exception as e:
                if cb:
                    cb.record_failure()
                raise
        return wrapper
    return decorator


class CircuitBreakerOpenError(Exception):
    """Raised when a circuit breaker is open and blocking requests."""
    pass


if TENACITY_AVAILABLE:
    # Azure Graph API: 3 retries, 1-8s backoff, retry on connection/timeout/5xx errors
    import requests as _requests

    retry_graph_api = retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        retry=retry_if_exception_type((
            _requests.exceptions.ConnectionError,
            _requests.exceptions.Timeout,
            _requests.exceptions.HTTPError,
        )),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )

    # AWS APIs: 3 retries, 1-8s backoff
    retry_aws_api = retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        retry=retry_if_exception_type((
            _requests.exceptions.ConnectionError,
            _requests.exceptions.Timeout,
            Exception,  # boto3 raises various client errors
        )),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )

    # Anthropic LLM API: 2 retries, 2-16s backoff (longer due to cost)
    retry_llm_api = retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=2, min=2, max=16),
        retry=retry_if_exception_type((
            _requests.exceptions.ConnectionError,
            _requests.exceptions.Timeout,
        )),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )

else:
    # Fallback: no-op decorators when tenacity is not installed
    def _noop_decorator(f):
        return f

    retry_graph_api = _noop_decorator
    retry_aws_api = _noop_decorator
    retry_llm_api = _noop_decorator


def resilient_call(breaker_name, func, *args, **kwargs):
    """Execute a function with circuit breaker protection.

    Usage:
        result = resilient_call('graph_api', requests.get, url, timeout=10)
    """
    cb = _breakers.get(breaker_name)
    if cb and not cb.allow_request():
        raise CircuitBreakerOpenError(
            f"Circuit breaker '{breaker_name}' is OPEN"
        )
    try:
        result = func(*args, **kwargs)
        if cb:
            cb.record_success()
        return result
    except Exception:
        if cb:
            cb.record_failure()
        raise
