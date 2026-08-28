from __future__ import annotations

import os
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from .catalog import get_product, search_products
from .llm_models import LLMClient, LLMOutput, ToolCall


class MockLLM(LLMClient):
    """Deterministic mock LLM for testing and offline use."""

    def interpret(self, prompt: str) -> LLMOutput:
        text = prompt.lower()
        calls: List[ToolCall] = []

        budget = None
        max_price = None
        if "under " in text:
            try:
                seg = text.split("under ")[1].split()[0]
                num = int(seg.replace(",", ""))
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

        if brand:
            query = brand
        else:
            tokens = [t for t in prompt.split() if not any(ch.isdigit() for ch in t)]
            stop_words = {"buy", "find", "a", "the", "or", "and", "under", "below", "for", "with"}
            cleaned = [t for t in tokens if t.lower().strip(",.") not in stop_words]
            query = " ".join(cleaned).strip()
            if not query:
                query = prompt

        sc_args: Dict[str, Any] = {
            "query": query,
            "category": category,
            "brand": brand,
            "merchant": merchant,
            "max_price_minor": max_price,
            "available": True,
            "limit": 1,
        }
        sc_args = {k: v for k, v in sc_args.items() if v is not None}
        calls.append(ToolCall(tool="search_products", args=sc_args))
        return LLMOutput(calls=calls, recommend=[])


class BaseLLMProvider(LLMClient):
    """Provider interface. Implementations must implement interpret(prompt) -> LLMOutput."""

    def interpret(self, prompt: str) -> LLMOutput:
        raise NotImplementedError()


class RealLLMProvider(BaseLLMProvider):
    """Adapter for a real LLM provider.

    This prototype intentionally does not call external networks. It validates
    configuration and exposes a deterministic fake provider mode for adapter tests.
    """

    def __init__(self, provider_name: str, api_key: Optional[str] = None):
        self.provider_name = provider_name
        self.api_key = api_key

        if not self.provider_name:
            raise ValueError("provider_name is required")

        if self.provider_name != "mock" and not self.api_key:
            raise RuntimeError("Real LLM provider configured but no API key provided")

    def interpret(self, prompt: str) -> LLMOutput:
        if self.provider_name == "fake":
            return MockLLM().interpret(prompt)

        raise NotImplementedError(
            f"Real provider adapter for '{self.provider_name}' is not implemented in this environment"
        )


class GeminiProvider(BaseLLMProvider):
    """Official google.genai-backed Gemini adapter for deterministic tool calling."""

    ALLOWED_TOOLS = {"search_products", "get_product"}

    def __init__(self, api_key: Optional[str] = None, client: Optional[Any] = None):
        self.api_key = api_key
        self.client = client
        self._sdk = None

        if not self.api_key and self.client is None:
            raise RuntimeError("Gemini provider configured but no API key provided")

        if self.client is None:
            try:
                from google.genai import Client
                self._sdk = Client(api_key=self.api_key)
            except Exception as exc:  # pragma: no cover - environment guard
                raise RuntimeError("Gemini SDK not installed in this environment") from exc

    def _tool_declarations(self) -> List[Any]:
        from google.genai import types

        search_schema = {
            "type": "OBJECT",
            "properties": {
                "query": {"type": "STRING"},
                "category": {"type": "STRING"},
                "brand": {"type": "STRING"},
                "merchant": {"type": "STRING"},
                "max_price_minor": {"type": "INTEGER"},
                "available": {"type": "BOOLEAN"},
                "limit": {"type": "INTEGER"},
            },
            "required": ["query"],
        }
        get_schema = {
            "type": "OBJECT",
            "properties": {"product_id": {"type": "STRING"}},
            "required": ["product_id"],
        }
        return [
            types.FunctionDeclaration(
                name="search_products",
                description="Search the catalog for matching products and return a deterministic list of results.",
                parameters=search_schema,
            ),
            types.FunctionDeclaration(
                name="get_product",
                description="Fetch a single product by its product_id.",
                parameters=get_schema,
            ),
        ]

    def _tool_config(self) -> Any:
        from google.genai import types

        return types.ToolConfig(
            function_calling_config=types.FunctionCallingConfig(
                mode="AUTO",
                allowed_function_names=["search_products", "get_product"],
            )
        )

    def _normalize_tool_call(self, call: Any) -> ToolCall:
        if isinstance(call, ToolCall):
            return call

        if hasattr(call, "name") and hasattr(call, "args"):
            tool_name = getattr(call, "name")
            raw_args = getattr(call, "args")
            if raw_args is None:
                raw_args = {}
        elif isinstance(call, dict):
            tool_name = call.get("name") or call.get("tool")
            raw_args = call.get("args") or call.get("arguments") or {}
        else:
            raise ValueError(f"Unsupported tool-call object: {type(call)!r}")

        if not isinstance(raw_args, dict):
            raise ValueError(f"Tool arguments for '{tool_name}' must be an object")

        if tool_name not in self.ALLOWED_TOOLS:
            raise ValueError(f"Unauthorized tool requested: {tool_name}")

        if tool_name == "search_products":
            allowed = {"query", "category", "brand", "merchant", "max_price_minor", "available", "limit"}
            invalid = set(raw_args.keys()) - allowed
            if invalid:
                raise ValueError(f"Unsupported search_products arguments: {sorted(invalid)}")
            query = raw_args.get("query")
            if not isinstance(query, str) or not query.strip():
                raise ValueError("search_products requires a non-empty query string")
            if "max_price_minor" in raw_args and not isinstance(raw_args["max_price_minor"], int):
                raise ValueError("max_price_minor must be an integer")
            if "limit" in raw_args and not isinstance(raw_args["limit"], int):
                raise ValueError("limit must be an integer")
            if "available" in raw_args and not isinstance(raw_args["available"], bool):
                raise ValueError("available must be a bool")
            return ToolCall(tool=tool_name, args={k: v for k, v in raw_args.items() if v is not None})

        if tool_name == "get_product":
            product_id = raw_args.get("product_id")
            if not isinstance(product_id, str) or not product_id.strip():
                raise ValueError("get_product requires a non-empty product_id string")
            return ToolCall(tool=tool_name, args={"product_id": product_id})

        raise ValueError(f"Unsupported tool: {tool_name}")

    def _execute_tool_call(self, tool_call: ToolCall) -> Dict[str, Any]:
        if tool_call.tool == "search_products":
            args = tool_call.args
            results = search_products(
                query=args.get("query"),
                category=args.get("category"),
                brand=args.get("brand"),
                merchant=args.get("merchant"),
                max_price_minor=args.get("max_price_minor"),
                available=args.get("available"),
                limit=args.get("limit"),
            )
            return {"results": [asdict(p) for p in results]}

        if tool_call.tool == "get_product":
            product_id = tool_call.args.get("product_id")
            product = get_product(product_id)
            if product is None:
                return {"product": None}
            return {"product": asdict(product)}

        raise ValueError(f"Unsupported tool: {tool_call.tool}")

    def _extract_tool_calls(self, response: Any) -> List[ToolCall]:
        if isinstance(response, LLMOutput):
            return list(response.calls)

        if isinstance(response, dict):
            if "calls" in response:
                return [self._normalize_tool_call(call) for call in response["calls"]]
            if "function_calls" in response:
                return [self._normalize_tool_call(call) for call in response["function_calls"]]

        if hasattr(response, "function_calls"):
            return [self._normalize_tool_call(call) for call in response.function_calls]

        if hasattr(response, "candidates"):
            calls: List[ToolCall] = []
            for candidate in response.candidates:
                content = getattr(candidate, "content", None)
                if content is None:
                    continue
                parts = getattr(content, "parts", [])
                for part in parts:
                    fn = getattr(part, "function_call", None)
                    if fn is None:
                        continue
                    calls.append(self._normalize_tool_call({"name": getattr(fn, "name", None), "args": getattr(fn, "args", {})}))
            if calls:
                return calls

        raise ValueError("Gemini native function calling did not return any tool calls")

    def _finalize_llm_output(self, response: Any) -> LLMOutput:
        if isinstance(response, LLMOutput):
            return response
        if isinstance(response, dict):
            if "calls" in response or "recommend" in response:
                return LLMOutput.model_validate(response)
        if hasattr(response, "calls") or hasattr(response, "recommend"):
            return LLMOutput.model_validate(response)
        raise RuntimeError("Gemini provider returned an unsupported final response")

    def _native_tool_call_roundtrip(self, prompt: str) -> LLMOutput:
        from google.genai import types

        declarations = self._tool_declarations()
        tool = types.Tool(function_declarations=declarations)
        config = types.GenerateContentConfig(
            tools=[tool],
            tool_config=self._tool_config(),
        )

        response = self._sdk.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
            config=config,
        )

        calls = self._extract_tool_calls(response)
        if not calls:
            return self._finalize_llm_output(response)

        response_payloads = []
        for call in calls:
            validated_call = self._normalize_tool_call(call)
            result = self._execute_tool_call(validated_call)
            response_payloads.append(types.FunctionResponse(name=validated_call.tool, response=result))

        followup_response = self._sdk.models.generate_content(
            model="gemini-2.0-flash",
            contents=[prompt, *response_payloads],
            config=config,
        )
        return self._finalize_llm_output(followup_response)

    def interpret(self, prompt: str) -> LLMOutput:
        if self.client is not None:
            out = self.client.interpret(prompt)
            if isinstance(out, LLMOutput):
                return out
            return LLMOutput.model_validate(out)

        if self._sdk is None:
            raise RuntimeError("Gemini SDK client is unavailable")

        return self._native_tool_call_roundtrip(prompt)


def build_provider_from_env() -> BaseLLMProvider:
    provider = os.getenv("LLM_PROVIDER")
    api_key = os.getenv("LLM_API_KEY")

    if not provider or provider.lower() == "mock":
        return MockLLM()

    pname = provider.lower()
    if pname == "fake":
        return RealLLMProvider(provider_name=pname, api_key=api_key)
    if pname == "gemini":
        return GeminiProvider(api_key=api_key)

    return RealLLMProvider(provider_name=pname, api_key=api_key)
