"""AI Agent SPN Pattern Library — runtime loader with hot-reload support.

Loads config/ai_agent_patterns.json at import time and exposes a
reload() function for the admin reload endpoint.
"""

import json
import logging
import os
import re
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

_lock = threading.Lock()

# Default path: backend/config/ai_agent_patterns.json
# __file__ = backend/app/engines/discovery/agent_pattern_loader.py
# .parent x4 = backend/
_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent.parent / "config" / "ai_agent_patterns.json"

# Override via env var
if os.getenv("AI_AGENT_PATTERNS_PATH"):
    _CONFIG_PATH = Path(os.getenv("AI_AGENT_PATTERNS_PATH"))

# ── In-memory pattern store ──────────────────────────────────────────

_patterns = {
    "display_name_patterns": [],
    "known_app_ids": [],
    "api_permission_signals": [],
    "exclusion_patterns": [],
    "version": "0.0.0",
    "last_updated": None,
}

# Pre-compiled regexes for performance
_compiled_display_name = []    # list of (regex, confidence, platform)
_compiled_exclusions = []      # list of compiled regex


def _compile_patterns(raw):
    """Compile regex patterns from the raw JSON config."""
    global _compiled_display_name, _compiled_exclusions

    compiled_dn = []
    for entry in raw.get("display_name_patterns", []):
        try:
            compiled_dn.append((
                re.compile(entry["pattern"]),
                entry.get("confidence", 0.5),
                entry.get("platform", "unknown"),
            ))
        except re.error as e:
            logger.warning("Invalid display_name pattern %r: %s", entry["pattern"], e)

    compiled_ex = []
    for pat_str in raw.get("exclusion_patterns", []):
        try:
            compiled_ex.append(re.compile(pat_str))
        except re.error as e:
            logger.warning("Invalid exclusion pattern %r: %s", pat_str, e)

    _compiled_display_name = compiled_dn
    _compiled_exclusions = compiled_ex


def load(path=None):
    """Load (or reload) the AI agent patterns config from disk.

    Returns True on success, raises on failure.
    """
    global _patterns
    config_path = Path(path) if path else _CONFIG_PATH

    if not config_path.exists():
        raise FileNotFoundError(f"AI agent patterns config not found: {config_path}")

    with open(config_path, "r") as f:
        raw = json.load(f)

    # Validate required keys
    required = ["display_name_patterns", "exclusion_patterns", "version"]
    missing = [k for k in required if k not in raw]
    if missing:
        raise ValueError(f"Missing required keys in ai_agent_patterns.json: {missing}")

    with _lock:
        _patterns = raw
        _compile_patterns(raw)

    logger.info(
        "AI agent patterns loaded: version=%s, %d display_name, %d app_ids, "
        "%d permission_signals, %d exclusions",
        raw.get("version"),
        len(raw.get("display_name_patterns", [])),
        len(raw.get("known_app_ids", [])),
        len(raw.get("api_permission_signals", [])),
        len(raw.get("exclusion_patterns", [])),
    )
    return True


def get_patterns():
    """Return a copy of the current patterns config."""
    with _lock:
        return dict(_patterns)


def get_version():
    """Return the current patterns version string."""
    with _lock:
        return _patterns.get("version", "0.0.0")


def match_display_name(display_name):
    """Match a display name against loaded patterns.

    Returns (platform, confidence) or (None, 0.0) if no match.
    Excludes names matching exclusion patterns.
    """
    if not display_name:
        return None, 0.0

    # Check exclusions first
    with _lock:
        for exc_re in _compiled_exclusions:
            if exc_re.search(display_name):
                return None, 0.0

        # Check display name patterns (highest confidence wins)
        best_platform = None
        best_confidence = 0.0
        for pat_re, confidence, platform in _compiled_display_name:
            if pat_re.search(display_name) and confidence > best_confidence:
                best_platform = platform
                best_confidence = confidence

    return best_platform, best_confidence


def match_app_id(app_id):
    """Check if an app_id matches a known AI platform.

    Returns platform string or None.
    """
    if not app_id:
        return None

    with _lock:
        for entry in _patterns.get("known_app_ids", []):
            if entry.get("app_id") == app_id:
                return entry.get("platform")
    return None


def match_permissions(permissions):
    """Check if a list of permission strings contains AI-related signals.

    Returns list of (permission, confidence, platform) matches.
    """
    if not permissions:
        return []

    matches = []
    with _lock:
        signals = _patterns.get("api_permission_signals", [])
        for perm in permissions:
            perm_str = perm if isinstance(perm, str) else str(perm)
            for signal in signals:
                if signal["permission"].lower() in perm_str.lower():
                    matches.append((
                        signal["permission"],
                        signal.get("confidence", 0.5),
                        signal.get("platform", "unknown"),
                    ))
    return matches


# ── Auto-load on import ──────────────────────────────────────────────

try:
    load()
except Exception as e:
    logger.warning("Could not auto-load AI agent patterns: %s", e)
