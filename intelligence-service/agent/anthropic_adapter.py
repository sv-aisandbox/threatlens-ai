"""Real model provider (Anthropic Messages API). ADR 0007.

Request shape follows the current API for claude-opus-5-5: thinking is always on (so `thinking` is omitted), effort is
set explicitly, no sampling parameters and no forced tool_choice (both are rejected by this model), and server-side
refusal fallbacks are on by default. The assistant turn is returned unchanged for replay so thinking blocks stay valid.
"""

import logging
from typing import Any

import anthropic

from agent.models import ModelError, ModelTurn, ToolCall, Usage

logger = logging.getLogger("threatlens.agent.model")

DEFAULT_MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
EFFORTS = {"low", "medium", "high", "xhigh", "max"}
_STOP = {"end_turn": "end_turn", "tool_use": "tool_use", "max_tokens": "max_tokens", "refusal": "refusal"}


class AnthropicAdapter:
    provider = "anthropic"

    def __init__(
        self,
        api_key: str | None,
        model: str = DEFAULT_MODEL,
        effort: str = "medium",
        max_tokens: int = 8000,
        fallbacks: bool = True,
        timeout: float = 120.0,
        client: Any | None = None,
    ) -> None:
        if effort not in EFFORTS:
            raise ValueError(f"effort must be one of {sorted(EFFORTS)}")
        if client is None:
            if not api_key:
                raise ModelError("model_not_configured", "MODEL_API_KEY is not set")
            client = anthropic.Anthropic(api_key=api_key, timeout=timeout, max_retries=2)
        self.client = client
        self.model = model
        self.effort = effort
        self.max_tokens = max_tokens
        self.fallbacks = fallbacks

    def _request(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        params: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": messages,
            "output_config": {"effort": self.effort},
        }
        if tools:
            params["tools"] = tools
        if self.fallbacks:
            params["betas"] = [FALLBACK_BETA]
            params["fallbacks"] = "default"
        return params

    def create(self, *, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelTurn:
        try:
            response = self.client.beta.messages.create(**self._request(system, messages, tools))
        except anthropic.AuthenticationError:
            raise ModelError("model_auth", "The model provider rejected the credentials.") from None
        except anthropic.PermissionDeniedError:
            raise ModelError("model_auth", "The model provider denied access.") from None
        except anthropic.RateLimitError:
            raise ModelError("model_rate_limited", "The model provider is rate limiting requests.") from None
        except (anthropic.APITimeoutError, anthropic.APIConnectionError):
            raise ModelError("model_unavailable", "The model provider could not be reached.") from None
        except anthropic.BadRequestError as exc:
            logger.error("model request rejected: %s", getattr(exc, "message", "bad request")[:200])
            raise ModelError("model_bad_request", "The model provider rejected the request.") from None
        except anthropic.APIStatusError as exc:
            logger.error("model provider error HTTP %s", exc.status_code)
            raise ModelError("model_error", "The model provider returned an error.") from None
        return self._to_turn(response)

    def _to_turn(self, response: Any) -> ModelTurn:
        text_parts: list[str] = []
        calls: list[ToolCall] = []
        fell_back = False
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                calls.append(ToolCall(id=block.id, name=block.name, input=dict(block.input or {})))
            elif block.type == "fallback":
                fell_back = True
        usage = response.usage
        stop = _STOP.get(response.stop_reason or "", "other")
        detail = None
        if stop == "refusal":
            details = getattr(response, "stop_details", None)
            detail = getattr(details, "category", None) if details else None
        logger.info(
            "model call ok: stop=%s in=%s out=%s request_id=%s",
            response.stop_reason, usage.input_tokens, usage.output_tokens, getattr(response, "_request_id", "-"),
        )
        return ModelTurn(
            text="\n".join(text_parts).strip(),
            tool_calls=calls,
            stop_reason=stop,
            usage=Usage(
                input_tokens=usage.input_tokens or 0,
                output_tokens=usage.output_tokens or 0,
                cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
                cache_write_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
            ),
            assistant_content=list(response.content),  # replayed unchanged
            model=getattr(response, "model", self.model) or self.model,
            fell_back=fell_back,
            detail=detail,
        )
