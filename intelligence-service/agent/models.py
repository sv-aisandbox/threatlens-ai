"""Provider-neutral types for the model adapter (ADR 0007)."""

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    def add(self, other: "Usage") -> None:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.cache_write_tokens += other.cache_write_tokens

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens + self.cache_read_tokens + self.cache_write_tokens


@dataclass
class ModelTurn:
    """One model response.

    `assistant_content` is appended to the history exactly as returned (never edited, so provider-specific
    blocks such as thinking stay valid).
    """

    text: str
    tool_calls: list[ToolCall]
    stop_reason: str  # end_turn | tool_use | max_tokens | refusal | other
    usage: Usage
    assistant_content: list[Any]
    model: str
    fell_back: bool = False
    detail: str | None = None  # e.g. refusal category; never user text


class ModelError(Exception):
    """The provider failed. `code` is stable; the message never includes provider response bodies or keys."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ModelAdapter(Protocol):
    provider: str
    model: str

    def create(self, *, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelTurn: ...


@dataclass
class ToolOutcome:
    """Result of one executed tool call, after the safety scrub."""

    body: dict[str, Any]
    is_error: bool
    latency_ms: int
    injection_suspected: bool = False
    error_code: str | None = None
    notes: list[str] = field(default_factory=list)
