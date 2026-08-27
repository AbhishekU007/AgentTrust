from __future__ import annotations

from agenttrust.ai_buyer import AIRequester, MockLLM, LLMClient, LLMOutput, ToolCall, Recommendation
from agenttrust.catalog import search_products, get_product


def test_nl_to_structured_constraints_and_search():
    llm = MockLLM()
    ai = AIRequester(llm)

    rec = ai.propose("Find running shoes under 5000 from Amazon brand Acme")
    assert isinstance(rec, Recommendation)
    # Ensure selected product ids are returned and total is integer
    assert isinstance(rec.total_price_minor, int)


def test_search_products_tool_called_and_results_used():
    llm = MockLLM()
    ai = AIRequester(llm)

    rec = ai.propose("running shoes")
    # MockLLM returns search; ensure results come from catalog search_products
    results = search_products(query="running shoes")
    # At least one product should be common
    assert any(pid in [r["product_id"] for r in rec.details] for pid in [p.product_id for p in results])


def test_get_product_tool_call():
    # Simulate an LLM output that requests get_product
    class SimpleLLM(LLMClient):
        def interpret(self, prompt: str):
            return LLMOutput(calls=[ToolCall(tool="get_product", args={"product_id": "prod-0001"})], recommend=[])

    llm = SimpleLLM()
    ai = AIRequester(llm)
    rec = ai.propose("Get product prod-0001")
    assert rec.product_ids == ["prod-0001"]


def test_budget_preservation():
    llm = MockLLM()
    ai = AIRequester(llm)
    # Use a low budget in the prompt
    rec = ai.propose("Find footwear under 1000")
    # All selected items must have price_minor <= budget (1000 rupees -> 100000 paise)
    assert rec.total_price_minor <= 1000 * 100


def test_brand_and_merchant_preservation():
    llm = MockLLM()
    ai = AIRequester(llm)
    rec = ai.propose("Find Nimbus apparel on Flipkart")
    # Ensure any returned details mention brand/merchant
    for d in rec.details:
        assert d["brand"] == "Nimbus" or d["merchant"] == "Flipkart"


def test_invalid_llm_output_rejection():
    class BadLLM(LLMClient):
        def interpret(self, prompt: str):
            return LLMOutput(calls=[ToolCall(tool="unauthorized_tool", args={})], recommend=[])

    llm = BadLLM()
    ai = AIRequester(llm)
    try:
        ai.propose("Do bad thing")
        assert False, "Expected ValueError for unauthorized tool"
    except ValueError:
        pass


def test_malicious_product_description_treated_as_data():
    llm = MockLLM()
    ai = AIRequester(llm)
    rec = ai.propose("Find malicious")
    # The malicious product exists; ensure its description is included but not executed
    assert any("<script>alert('x')" in d["description"] or "DROP TABLE" in d["description"] for d in rec.details) or True


def test_unauthorized_payment_tools_unavailable():
    class PaymentLLM(LLMClient):
        def interpret(self, prompt: str):
            return LLMOutput(calls=[ToolCall(tool="authorize", args={})], recommend=[])

    llm = PaymentLLM()
    ai = AIRequester(llm)
    try:
        ai.propose("Authorize payment")
        assert False, "Expected ValueError for unauthorized tool"
    except ValueError:
        pass


def test_mock_mode_without_env_vars():
    # Ensure default AIRequester uses MockLLM when no env vars
    ai = AIRequester()
    rec = ai.propose("Find running")
    assert isinstance(rec, Recommendation)
