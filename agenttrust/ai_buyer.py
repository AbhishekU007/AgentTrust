from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Literal
from dataclasses import dataclass
from pydantic import BaseModel, Field, ValidationError, conint

from .catalog import search_products, get_product, Product


# Structured models for LLM-tool interaction
class StructuredConstraints(BaseModel):
    query: Optional[str] = None
    category: Optional[str] = None
    brand: Optional[str] = None
    merchant: Optional[str] = None
    max_price_minor: Optional[int] = None
    budget_minor: Optional[int] = None
    limit: Optional[int] = Field(default=5, ge=1)


class ToolCall(BaseModel):
    tool: Literal["search_products", "get_product"]
    args: Dict[str, Any]


class LLMOutput(BaseModel):
    # Sequence of tool calls the LLM requests (tool-first, dataflow-driven)
    calls: List[ToolCall]
    # Final recommended product ids
    recommend: List[str]


class Recommendation(BaseModel):
    product_ids: List[str]
    total_price_minor: int
    details: List[Dict[str, Any]]


@dataclass
class LLMClient:
    """Abstract LLM client. Implementations should provide interpret()."""

    def interpret(self, prompt: str) -> LLMOutput:
        raise NotImplementedError()


class MockLLM(LLMClient):
    """Deterministic mock LLM for testing and offline use.

    This simple rule-based mock translates natural-language constraints into a
    predictable sequence of tool calls. It is intentionally conservative and
    deterministic so tests do not depend on an external provider.
    """

    def interpret(self, prompt: str) -> LLMOutput:
        text = prompt.lower()
        calls: List[ToolCall] = []

        # Basic extraction rules (deterministic):
        # - budget: look for 'under X' or 'below X' where X is a number in rupees
        # - merchant/brand/category keywords
        budget = None
        max_price = None
        if "under " in text:
            try:
                seg = text.split("under ")[1].split()[0]
                # accept numbers like 5000, 5,000, or 500000 (minor units unclear)
                num = int(seg.replace(",", ""))
                # assume user means major units (rupees) -> convert to minor (paise)
                budget = num * 100
                max_price = budget
            except Exception:
                pass
        elif "below " in text:
            try:
                seg = text.split("below ")[1].split()[0]
                num = int(seg.replace(",", ""))
                budget = num * 100
                max_price = budget
            except Exception:
                pass

        # extract brand/merchant/category by keywords (naive)
        brand = None
        merchant = None
        category = None
        for b in ["acme", "nimbus", "aurora", "pixelview", "quantum"]:
            if b in text:
                brand = b.title()
                break
        for m in ["amazon", "flipkart"]:
            if m in text:
                merchant = m.title()
                break
        for c in ["footwear", "electronics", "kitchen", "fitness", "apparel"]:
            if c in text:
                category = c.title()
                break

        # primary query: derive a concise search query from the prompt
        # Prefer brand/product keywords to the full natural-language prompt
        if brand:
            query = brand
        else:
            # remove common verbs and numeric tokens to produce a useful query
            tokens = [t for t in prompt.split() if not any(c.isdigit() for c in t)]
            stop_words = {'buy','find','a','the','or','and','under','below','for','with'}
            cleaned = [t for t in tokens if t.lower().strip(',.') not in stop_words]
            query = ' '.join(cleaned).strip()
            if not query:
                query = prompt

        # Build a single search_products call
        sc_args: Dict[str, Any] = {
            "query": query,
            "category": category,
            "brand": brand,
            "merchant": merchant,
            "max_price_minor": max_price,
            "available": True,
            "limit": 1,
        }
        # remove None entries
        sc_args = {k: v for k, v in sc_args.items() if v is not None}
        calls.append(ToolCall(tool="search_products", args=sc_args))

        # For deterministic behavior: recommend top 1-3 results by default
        # We'll leave recommend empty here; the caller will execute calls and decide.
        return LLMOutput(calls=calls, recommend=[])


class AIRequester:
    """Executes LLM-guided shopping proposals using allowed tools only.

    The AIRequester runs the LLM's structured calls, validates them, and
    returns deterministic recommendations. It enforces security boundaries so
    the AI cannot call unauthorized actions.
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm = llm_client or self._build_llm_client()

    def _build_llm_client(self) -> LLMClient:
        # If environment variables indicate a real provider, a real client would be
        # created. For now, defer to mock mode if no provider configured.
        provider = os.getenv("LLM_PROVIDER")
        api_key = os.getenv("LLM_API_KEY")
        if provider and api_key:
            # Placeholder: a real client could be wired here. Tests should use mock.
            raise RuntimeError("Real LLM providers are not configured in this environment")
        return MockLLM()

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
