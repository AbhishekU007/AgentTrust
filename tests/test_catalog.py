from __future__ import annotations

from agenttrust.catalog import search_products, get_product, Product


def test_get_product_exists():
    p = get_product("prod-0001")
    assert p is not None
    assert isinstance(p, Product)
    assert p.product_id == "prod-0001"
    assert isinstance(p.price_minor, int)


def test_get_product_not_found():
    p = get_product("no-such-id")
    assert p is None


def test_search_query_match():
    results = search_products(query="running")
    # Should find running shoes and maybe other running items
    assert any("running" in r.name.lower() or "running" in r.description.lower() for r in results)


def test_search_category_filter():
    results = search_products(category="Electronics")
    assert all(r.category == "Electronics" for r in results)


def test_search_brand_filter():
    results = search_products(brand="Nimbus")
    assert all(r.brand == "Nimbus" for r in results)


def test_search_merchant_filter():
    results = search_products(merchant="Flipkart")
    assert all(r.merchant == "Flipkart" for r in results)


def test_search_max_price_filter():
    results = search_products(max_price_minor=100000)
    assert all(r.price_minor <= 100000 for r in results)


def test_search_availability_filter():
    results = search_products(available=True)
    assert all(r.available for r in results)
    results2 = search_products(available=False)
    assert all(not r.available for r in results2)


def test_search_limit_and_deterministic_ordering():
    a = search_products(limit=10)
    b = search_products(limit=10)
    assert [p.product_id for p in a] == [p.product_id for p in b]


def test_malicious_description_is_data():
    results = search_products(query="<script>alert('x')")
    # The malicious description product exists; ensure it's returned and not executed
    assert any("<script>alert('x')" in r.description for r in results)

