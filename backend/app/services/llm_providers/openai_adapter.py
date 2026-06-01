"""Anthropic-shaped adapter that routes to OpenAI's chat completions API.

Placeholder fallback for [[ollama-copilot-plan]] / [[brand-argus]]: when
Ollama is unusable (too slow on Mac, hangs on large contexts) and
Anthropic credits are exhausted, route Argus to OpenAI instead.

Design — same adapter pattern as ollama_adapter.py: this class mimics
`anthropic.Anthropic` so CopilotService doesn't change. Swap by setting
`COPILOT_PROVIDER=openai` in env.

Setup:
    pip install openai>=1.0
    export OPENAI_API_KEY=sk-...
    export COPILOT_PROVIDER=openai
    export OPENAI_MODEL=gpt-4o-mini   # default

Quality: gpt-4o-mini is roughly comparable to Claude 3 Haiku on
multi-step reasoning — fine for Argus chat/quick-ask, weaker than
Sonnet for deep audit narration. Set OPENAI_MODEL=gpt-4o for best
quality at higher cost.
"""
from __future__ import annotations
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Response shape that mimics anthropic.types.Message ──────────────────────

@dataclass
class _AnthropicContent:
    text: str
    type: str = 'text'


@dataclass
class _AnthropicUsage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class _AnthropicResponse:
    content: List[_AnthropicContent]
    stop_reason: str = 'end_turn'
    model: str = ''
    role: str = 'assistant'
    usage: _AnthropicUsage = field(default_factory=_AnthropicUsage)


# ── Adapter implementation ─────────────────────────────────────────────────

class _MessagesAPI:
    """Mimics anthropic.Anthropic().messages — only `create()` is implemented."""

    def __init__(self, api_key: str, default_model: str, base_url: Optional[str] = None):
        self.api_key = api_key
        self.default_model = default_model
        self.base_url = base_url
        self._client = None  # lazy import

    def _get_client(self):
        if self._client is None:
            try:
                from openai import OpenAI
            except ImportError as e:
                raise RuntimeError(
                    "openai package not installed. Run `pip install openai>=1.0` "
                    "or switch COPILOT_PROVIDER back to anthropic."
                ) from e
            kwargs: Dict[str, Any] = {'api_key': self.api_key}
            if self.base_url:
                kwargs['base_url'] = self.base_url
            self._client = OpenAI(**kwargs)
        return self._client

    def create(
        self,
        *,
        model: str = '',
        max_tokens: int = 1024,
        messages: Optional[List[Dict[str, str]]] = None,
        system: str = '',
        temperature: Optional[float] = None,
        **_kwargs,
    ) -> _AnthropicResponse:
        # Substitute claude-* names with the configured OpenAI model
        target_model = model if (model and not model.startswith('claude')) else self.default_model

        oai_messages: List[Dict[str, str]] = []
        if system:
            oai_messages.append({'role': 'system', 'content': system})
        for m in (messages or []):
            content = m.get('content', '')
            if isinstance(content, list):
                content = ''.join(
                    (c.get('text', '') if isinstance(c, dict) else str(c))
                    for c in content
                )
            oai_messages.append({'role': m.get('role', 'user'), 'content': content})

        params: Dict[str, Any] = {
            'model': target_model,
            'messages': oai_messages,
            'max_tokens': max_tokens,
        }
        if temperature is not None:
            params['temperature'] = temperature

        client = self._get_client()
        resp = client.chat.completions.create(**params)

        choice = resp.choices[0] if resp.choices else None
        text = (choice.message.content if choice and choice.message else '') or ''
        usage = getattr(resp, 'usage', None)

        return _AnthropicResponse(
            content=[_AnthropicContent(text=text)],
            stop_reason='end_turn',
            model=target_model,
            role='assistant',
            usage=_AnthropicUsage(
                input_tokens=int(getattr(usage, 'prompt_tokens', 0) or 0),
                output_tokens=int(getattr(usage, 'completion_tokens', 0) or 0),
            ),
        )


class OpenAIAnthropicAdapter:
    """Drop-in replacement for `anthropic.Anthropic` that routes to OpenAI."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 120.0,  # noqa: ARG002 — OpenAI client has its own
        max_retries: int = 2,    # noqa: ARG002
        base_url: Optional[str] = None,
        default_model: Optional[str] = None,
        **_kwargs,
    ):
        self.api_key = api_key or os.getenv('OPENAI_API_KEY', '').strip()
        self.base_url = base_url or os.getenv('OPENAI_BASE_URL') or None
        self.default_model = default_model or os.getenv('OPENAI_MODEL', 'gpt-4o-mini')
        self.messages = _MessagesAPI(self.api_key, self.default_model, self.base_url)
        logger.info(
            "OpenAIAnthropicAdapter ready — base_url=%s default_model=%s",
            self.base_url or 'default', self.default_model,
        )

    @classmethod
    def is_available(cls) -> bool:
        """Returns True if an OPENAI_API_KEY env var is present. Doesn't ping
        the API (would burn a token); the first request fails fast if invalid."""
        return bool(os.getenv('OPENAI_API_KEY', '').strip())
