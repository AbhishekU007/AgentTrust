from __future__ import annotations

import os
from fastapi.testclient import TestClient
import pytest

from agenttrust.ai_buyer import AIRequester, MockLLM, LLMOutput
from agenttrust.llm_provider import build_provider_from_env, RealLLMProvider


def test_default_provider_is_mock(monkeypatch):
    # ensure no env vars
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    prov = build_provider_from_env()
    assert isinstance(prov, MockLLM)


def test_real_provider_without_api_key_raises(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    with pytest.raises(RuntimeError):
        build_provider_from_env()


def test_fake_real_provider_returns_structured_calls(monkeypatch):
    # Configure a "fake" real provider for deterministic adapter testing
    monkeypatch.setenv("LLM_PROVIDER", "fake")
    monkeypatch.setenv("LLM_API_KEY", "dummy-key")

    prov = build_provider_from_env()
    assert isinstance(prov, RealLLMProvider)

    # Use the provider to interpret a prompt and validate shape
    out = prov.interpret("Buy Acme running shoes under 5000")
    assert isinstance(out, LLMOutput)
    assert len(out.calls) >= 1
    assert out.calls[0].tool in {"search_products", "get_product"}


def test_ai_requester_uses_mock_when_unconfigured(monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    requester = AIRequester()
    # Should be able to propose using mock without raising
    rec = requester.propose("Buy Acme running shoes under 5000")
    assert rec is not None
    assert hasattr(rec, "product_ids")
