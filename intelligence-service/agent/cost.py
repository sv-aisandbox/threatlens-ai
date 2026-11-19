"""Per-request cost estimate (USD per million tokens). Used for logging only, never for authorization."""

from agent.models import Usage

# model -> (input, output, cache read, cache write). Opus 5.5 and Sonnet 5.5 are the published prices; Haiku's
# cache figures are derived from the documented ratios (reads ~0.1x, writes ~1.25x of input).
PRICES: dict[str, tuple[float, float, float, float]] = {
    "claude-opus-5-5": (4.00, 20.00, 0.20, 5.00),
    "claude-sonnet-5-5": (2.00, 10.00, 0.10, 2.50),
    "claude-haiku-5-5": (0.10, 0.50, 0.01, 0.125),
}


def compute_cost(model: str, usage: Usage) -> float:
    """USD, rounded to 6 places. Unknown models (including the mock) cost 0."""
    price = PRICES.get(model)
    if price is None:
        return 0.0
    inp, out, read, write = price
    total = (
        usage.input_tokens * inp
        + usage.output_tokens * out
        + usage.cache_read_tokens * read
        + usage.cache_write_tokens * write
    ) / 1_000_000
    return round(total, 6)
