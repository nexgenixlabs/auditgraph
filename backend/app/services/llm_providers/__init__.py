"""LLM provider adapters for Argus (AG-Hero-3).

Each adapter exposes the same Anthropic SDK shape (`client.messages.create(...)`
returning an object with `.content[0].text`) so CopilotService doesn't need
to know which backend it's talking to.

Providers:
  - anthropic (default) — real Claude API; requires ANTHROPIC_API_KEY
  - ollama              — local LLM via Ollama daemon; free, requires `ollama serve` running

Routed via `COPILOT_PROVIDER` env var. See [[ollama-copilot-plan]] memory for
design rationale + setup steps.
"""
