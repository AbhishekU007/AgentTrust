from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Literal
from pydantic import BaseModel, Field, ValidationError, conint

from .catalog import search_products, get_product, Product
from .llm_provider import build_provider_from_env


# Structured models for LLM-tool interaction
from .llm_models import ToolCall, LLMOutput, LLMClient

class StructuredConstraints(BaseModel):
    query: Optional[str] = None
    category: Optional[str] = None
    brand: Optional[str] = None
    merchant: Optional[str] = None
    max_price_minor: Optional[int] = None
    budget_minor: Optional[int] = None
    limit: Optional[int] = Field(default=5, ge=1)


class Recommendation(BaseModel):
    product_ids: List[str]
    total_price_minor: int
    details: List[Dict[str, Any]]

from .llm_provider import MockLLM


class AIRequester:
    """Executes LLM-guided shopping proposals using allowed tools only.

    The AIRequester runs the LLM's structured calls, validates them, and
    returns deterministic recommendations. It enforces security boundaries so
    the AI cannot call unauthorized actions.
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm = llm_client or self._build_llm_client()

    def _build_llm_client(self) -> LLMClient:
        # Build provider from environment using the new provider factory. This
        # enforces the rule: do not silently fall back from configured providers
        # to mock — build_provider_from_env raises when configuration is invalid.
        try:
            return build_provider_from_env()
        except Exception:
            # Re-raise with clearer message for callers/tests
            raise

    def propose(self, natural_language_request: str) -> Recommendation:
        # 1. Ask LLM to interpret into tool calls
        raw = self.llm.interpret(natural_language_request)

        # Validate LLM output shape using pydantic
        try:
            validated = LLMOutput.model_validate(raw) if not isinstance(raw, LLMOutput) else raw
        except ValidationError as exc:
            raise ValueError(f"Invalid LLM output: {exc}")

        # 2. Execute tool calls in order, but only allowed tools
        allowed_tools = {"search_products", "get_product"}
        intermediate_products: List[Product] = []

        for call in validated.calls:
            if call.tool not in allowed_tools:
                raise ValueError(f"Unauthorized tool requested: {call.tool}")

            if call.tool == "search_products":
                # Only pass known safe args
                args = call.args
                results = search_products(
                    query=args.get("query"),
                    category=args.get("category"),
                    brand=args.get("brand"),
                    merchant=args.get("merchant"),
                    max_price_minor=args.get("max_price_minor"),
                    available=args.get("available"),
                    limit=args.get("limit"),
                )
                intermediate_products = results

            elif call.tool == "get_product":
                pid = call.args.get("product_id")
                if not pid:
                    raise ValueError("get_product requires product_id")
                prod = get_product(pid)
                if prod is not None:
                    intermediate_products = [prod]
                else:
                    intermediate_products = []

        # 3. Selection policy: choose up to limit products within budget if provided
        selected: List[Product] = []
        budget = None
        # Try to infer budget from validated.calls args if present
        # Look for max_price_minor or budget_minor in any call args
        for call in validated.calls:
            if "max_price_minor" in call.args and call.args.get("max_price_minor") is not None:
                budget = call.args.get("max_price_minor")
        # fallback: none

        total = 0
        for p in intermediate_products:
            if budget is not None and total + p.price_minor > budget:
                continue
            selected.append(p)
            total += p.price_minor
            if len(selected) >= (validated.calls[0].args.get("limit", 5) if validated.calls else 5):
                break

        # Build recommendation details without executing anything
        details = [
            {
                "product_id": p.product_id,
                "name": p.name,
                "price_minor": p.price_minor,
                "merchant": p.merchant,
                "brand": p.brand,
                "description": p.description,  # untrusted data; treated as data only
            }
            for p in selected
        ]

        rec = Recommendation(product_ids=[p.product_id for p in selected], total_price_minor=total, details=details)
        return rec
