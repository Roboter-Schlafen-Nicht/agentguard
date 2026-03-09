"""ASGI LLM API proxy with policy enforcement and audit logging.

Sits between LLM clients and upstream LLM APIs (OpenAI, Anthropic,
etc.), inspecting request content against Guard policies before
forwarding. All requests are audit-logged.

Requires the ``proxy`` extra: ``pip install agentguard[proxy]``
"""
