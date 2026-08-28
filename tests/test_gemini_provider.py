from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from agenttrust.llm_models import LLMOutput
from agenttrust.llm_provider import GeminiProvider


class FakeGeminiClient:
    def interpret(self, prompt: str):
        return {
            "calls": [{"tool": "search_products", "args": {"query": "acme", "limit": 1}}],
            "recommend": ["acme"],
        }


class FakeFunctionCallResponse:
    def __init__(self, function_calls):
        self.function_calls = function_calls


class FakeModels:
    def __init__(self, first_response, second_response=None):
        self._first = first_response
        self._second = second_response
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        if self._second is not None and len(self.calls) > 1:
            return self._second
        return self._first


def test_gemini_requires_api_key(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    with pytest.raises(RuntimeError):
        GeminiProvider(api_key=None)


def test_gemini_sdk_present_or_missing_behavior():
    spec = importlib.util.find_spec("google.genai")
    if spec is None:
        with pytest.raises(RuntimeError):
            GeminiProvider(api_key="dummy-key")
    else:
        GeminiProvider(api_key="dummy-key")


def test_gemini_with_injected_client_parses_calls():
    client = FakeGeminiClient()
    prov = GeminiProvider(api_key="dummy", client=client)
    out = prov.interpret("Buy Acme shoes under 5000")
    assert isinstance(out, LLMOutput)
    assert len(out.calls) == 1
    assert out.calls[0].tool == "search_products"


def test_gemini_bad_response_rejected():
    class BadClient:
        def interpret(self, prompt: str):
            return {"foo": "bar"}

    prov = GeminiProvider(api_key="dummy", client=BadClient())
    with pytest.raises(Exception):
        prov.interpret("test")


def test_gemini_native_tool_schema_creation():
    prov = GeminiProvider(api_key="dummy-key")
    declarations = prov._tool_declarations()
    names = [decl.name for decl in declarations]
    assert names == ["search_products", "get_product"]
    assert all(hasattr(decl, "parameters") for decl in declarations)


def test_native_search_products_tool_call_executes_and_validates():
    prov = GeminiProvider(api_key="dummy-key")
    first = FakeFunctionCallResponse([
        {"name": "search_products", "args": {"query": "acme", "limit": 1}}
    ])
    second = {"calls": [{"tool": "search_products", "args": {"query": "acme", "limit": 1}}], "recommend": ["prod-0001"]}
    prov._sdk = type("SDK", (), {"models": FakeModels(first, second)})()

    out = prov.interpret("Buy Acme running shoes")
    assert isinstance(out, LLMOutput)
    assert out.calls[0].tool == "search_products"
    assert out.recommend == ["prod-0001"]


def test_native_get_product_tool_call_executes():
    prov = GeminiProvider(api_key="dummy-key")
    first = FakeFunctionCallResponse([
        {"name": "get_product", "args": {"product_id": "prod-0001"}}
    ])
    second = {"calls": [{"tool": "get_product", "args": {"product_id": "prod-0001"}}], "recommend": ["prod-0001"]}
    prov._sdk = type("SDK", (), {"models": FakeModels(first, second)})()

    out = prov.interpret("Fetch product prod-0001")
    assert isinstance(out, LLMOutput)
    assert out.calls[0].tool == "get_product"


def test_unauthorized_native_tool_rejected():
    prov = GeminiProvider(api_key="dummy-key")
    first = FakeFunctionCallResponse([
        {"name": "delete_account", "args": {}}
    ])
    prov._sdk = type("SDK", (), {"models": FakeModels(first)})()

    with pytest.raises(ValueError, match="Unauthorized tool"):
        prov.interpret("delete account")


def test_malformed_native_tool_args_rejected():
    prov = GeminiProvider(api_key="dummy-key")
    first = FakeFunctionCallResponse([
        {"name": "search_products", "args": {"limit": "bad"}}
    ])
    prov._sdk = type("SDK", (), {"models": FakeModels(first)})()

    with pytest.raises(ValueError, match="requires a non-empty query string|limit must be an integer"):
        prov.interpret("search")


def test_native_provider_failure_propagates():
    prov = GeminiProvider(api_key="dummy-key")

    class FailingModels:
        def generate_content(self, **kwargs):
            raise RuntimeError("provider failed")

    prov._sdk = type("SDK", (), {"models": FailingModels()})()
    with pytest.raises(RuntimeError, match="provider failed"):
        prov.interpret("anything")


def test_no_json_fallback_in_provider_source():
    source = Path("D:/AgentTrust/agenttrust/llm_provider.py").read_text(encoding="utf-8")
    assert "json.loads" not in source
    assert "google.generativeai" not in source


def test_malicious_product_description_is_data_only():
    prov = GeminiProvider(api_key="dummy-key")
    first = FakeFunctionCallResponse([
        {"name": "search_products", "args": {"query": "malicious", "limit": 1}}
    ])
    second = {"calls": [{"tool": "search_products", "args": {"query": "malicious", "limit": 1}}], "recommend": ["prod-0031"]}
    prov._sdk = type("SDK", (), {"models": FakeModels(first, second)})()

    out = prov.interpret("Find the malicious item")
    assert out.calls[0].tool == "search_products"
    assert out.recommend == ["prod-0031"]
