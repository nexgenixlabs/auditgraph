"""Anthropic-shaped adapter that routes to a local Ollama daemon.

Per [[ollama-copilot-plan]] memory: enables Argus to run on a free local
LLM (Ollama) without burning Anthropic API credits. Used for dev/test/demo.

Design — adapter pattern: this class mimics the public surface of
`anthropic.Anthropic`, so CopilotService's existing call sites
(`client.messages.create(model=..., max_tokens=..., system=..., messages=...)`)
work unchanged. Swap by setting `COPILOT_PROVIDER=ollama` in env.

Setup (5 min, one-time, Mac):
    brew install ollama
    ollama serve &                       # starts daemon on :11434
    ollama pull llama3.1:8b               # ~4.7GB model

Env vars:
    COPILOT_PROVIDER=ollama               # required, default is 'anthropic'
    OLLAMA_BASE_URL=http://localhost:11434  # optional
    OLLAMA_MODEL=llama3.1:8b              # optional, model tag from `ollama list`

Quality caveat: a local 7-8B model is noticeably weaker than Claude
Sonnet at multi-step reasoning over large tenant contexts. Fine for
quick-ask chips, demo recordings, dev iteration; not recommended for
production audit-grade narration.
"""
from __future__ import annotations
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


# ── Response shape that mimics anthropic.types.Message ──────────────────────

@dataclass
class _AnthropicContent:
    """Mimics anthropic.types.ContentBlock — only the `text` shape we use."""
    text: str
    type: str = 'text'


@dataclass
class _AnthropicUsage:
    """Token-usage block. We don't have real token counts from Ollama (it
    returns prompt/eval counts that aren't strictly tokens), so we surface
    them as best-effort estimates so downstream code that logs usage
    doesn't break."""
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class _AnthropicResponse:
    """Mimics anthropic.types.Message — exposes the fields CopilotService reads."""
    content: List[_AnthropicContent]
    stop_reason: str = 'end_turn'
    model: str = ''
    role: str = 'assistant'
    usage: _AnthropicUsage = field(default_factory=_AnthropicUsage)


# ── Adapter implementation ─────────────────────────────────────────────────

class _MessagesAPI:
    """Mimics anthropic.Anthropic().messages — only `create()` is implemented."""

    def __init__(self, base_url: str, default_model: str):
        self.base_url = base_url.rstrip('/')
        self.default_model = default_model

    def create(
        self,
        *,
        model: str = '',
        max_tokens: int = 1024,
        messages: Optional[List[Dict[str, str]]] = None,
        system: str = '',
        temperature: Optional[float] = None,
        **_kwargs,  # absorb other Anthropic params we don't need to translate
    ) -> _AnthropicResponse:
        """Translate Anthropic-shaped call → Ollama /api/chat HTTP call.

        Model name handling: existing CopilotService call sites pass
        `model='claude-sonnet-4-5-...'`. Ollama doesn't know those names.
        If we see a claude-* name we substitute the configured local model.
        """
        # Override Claude model names with the configured Ollama model.
        # Anything else is passed through (lets callers explicitly request
        # e.g. 'qwen2.5:14b' if they want to A/B test).
        target_model = model if (model and not model.startswith('claude')) else self.default_model

        # Build the chat history — Anthropic puts system separately; Ollama
        # accepts a 'system' role at the head of the messages array.
        ollama_messages: List[Dict[str, str]] = []
        if system:
            ollama_messages.append({'role': 'system', 'content': system})
        for m in (messages or []):
            # Anthropic supports content as str OR list of content blocks.
            # We only translate the string case; block lists get joined.
            content = m.get('content', '')
            if isinstance(content, list):
                content = ''.join(
                    (c.get('text', '') if isinstance(c, dict) else str(c))
                    for c in content
                )
            ollama_messages.append({'role': m.get('role', 'user'), 'content': content})

        options: Dict[str, Any] = {'num_predict': max_tokens}
        if temperature is not None:
            options['temperature'] = temperature

        payload = {
            'model': target_model,
            'messages': ollama_messages,
            'stream': False,
            'options': options,
        }

        try:
            r = httpx.post(
                f'{self.base_url}/api/chat',
                json=payload,
                # Local 7B model first-token latency can be 5-10s on cold load;
                # 120s gives plenty of headroom for longer generations.
                timeout=120.0,
            )
        except httpx.ConnectError as e:
            raise RuntimeError(
                f"Ollama daemon not reachable at {self.base_url}. "
                f"Run `ollama serve` (or `brew services start ollama`) and try again. "
                f"Original error: {e}"
            ) from e

        if r.status_code == 404 and 'model' in r.text.lower():
            # Ollama returns 404 with {"error":"model 'X' not found, try pulling it first"}
            raise RuntimeError(
                f"Ollama model '{target_model}' not installed. "
                f"Run `ollama pull {target_model}` (one-time, ~4-8GB)."
            )
        r.raise_for_status()
        data = r.json()
        text = (data.get('message') or {}).get('content', '')

        # Ollama's eval_count is closest analog to output tokens (it's actually
        # decoded tokens, but close enough for usage tracking).
        return _AnthropicResponse(
            content=[_AnthropicContent(text=text)],
            stop_reason='end_turn',
            model=target_model,
            role='assistant',
            usage=_AnthropicUsage(
                input_tokens=int(data.get('prompt_eval_count') or 0),
                output_tokens=int(data.get('eval_count') or 0),
            ),
        )


class OllamaAnthropicAdapter:
    """Drop-in replacement for `anthropic.Anthropic` that routes to Ollama.

    Constructor accepts the same kwargs as anthropic.Anthropic (api_key,
    timeout, max_retries, base_url) — most are no-ops here since Ollama
    is local + unauthenticated. Provided for call-site compatibility.

    Exposes `.messages.create(...)` matching Anthropic's shape; returns
    an object with `.content[0].text` that downstream code already
    knows how to read.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,       # noqa: ARG002 — accepted for compat
        timeout: float = 120.0,              # noqa: ARG002 — handled in _MessagesAPI
        max_retries: int = 2,                # noqa: ARG002 — Ollama is local, retries less critical
        base_url: Optional[str] = None,
        default_model: Optional[str] = None,
        **_kwargs,                            # absorb anything else
    ):
        self.base_url = base_url or os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
        self.default_model = default_model or os.getenv('OLLAMA_MODEL', 'llama3.1:8b')
        self.messages = _MessagesAPI(self.base_url, self.default_model)
        logger.info(
            "OllamaAnthropicAdapter ready — base_url=%s default_model=%s",
            self.base_url, self.default_model,
        )

    @classmethod
    def is_available(cls, base_url: Optional[str] = None) -> bool:
        """Cheap reachability check — returns True if Ollama responds on /api/tags.
        Use this in `_get_client()` to fail fast with a helpful error rather
        than hanging the user's first prompt."""
        url = (base_url or os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')).rstrip('/')
        try:
            r = httpx.get(f'{url}/api/tags', timeout=2.0)
            return r.status_code == 200
        except Exception:
            return False
