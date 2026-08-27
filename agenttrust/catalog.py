from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
import uuid


@dataclass(frozen=True)
class Product:
    product_id: str
    name: str
    description: str
    category: str
    brand: str
    merchant: str
    price_minor: int  # integer minor units (e.g., paise for INR)
    currency: str = "INR"
    available: bool = True


# Local in-memory product catalog (30-50 realistic products)
# product_id values are stable UUIDs for deterministic ordering
_PRODUCTS: List[Product] = [
    Product(product_id="prod-0001", name="Acme Running Shoes", description="Comfortable running shoes for daily jogs.", category="Footwear", brand="Acme", merchant="Amazon", price_minor=399900, available=True),
    Product(product_id="prod-0002", name="Acme Trail Shoes", description="Durable trail shoes with extra grip.", category="Footwear", brand="Acme", merchant="Amazon", price_minor=459900, available=True),
    Product(product_id="prod-0003", name="Nimbus Lightweight Jacket", description="Water-resistant jacket with breathable fabric.", category="Apparel", brand="Nimbus", merchant="Flipkart", price_minor=299900, available=True),
    Product(product_id="prod-0004", name="Aurora Yoga Mat", description="Eco-friendly non-slip yoga mat.", category="Fitness", brand="Aurora", merchant="Amazon", price_minor=49900, available=True),
    Product(product_id="prod-0005", name="Copper Chef Pan", description="Non-stick pan ideal for everyday cooking.", category="Kitchen", brand="Copper Chef", merchant="Flipkart", price_minor=349900, available=True),
    Product(product_id="prod-0006", name="Zen Electric Kettle", description="Fast-boil electric kettle with auto shut-off.", category="Appliances", brand="ZenHome", merchant="Amazon", price_minor=249900, available=True),
    Product(product_id="prod-0007", name="Stellar Blender", description="High-speed blender for smoothies and soups.", category="Appliances", brand="Stellar", merchant="Flipkart", price_minor=549900, available=True),
    Product(product_id="prod-0008", name="Orbit Headphones", description="Noise-cancelling over-ear headphones.", category="Electronics", brand="Orbit", merchant="Amazon", price_minor=1299900, available=True),
    Product(product_id="prod-0009", name="PixelView Monitor", description="27-inch 4K monitor with vibrant colors.", category="Electronics", brand="PixelView", merchant="Amazon", price_minor=2499900, available=False),
    Product(product_id="prod-0010", name="Quantum SSD 1TB", description="Fast NVMe SSD for developers and gamers.", category="Electronics", brand="Quantum", merchant="Flipkart", price_minor=799900, available=True),
    Product(product_id="prod-0011", name="Hearth Ceramic Mug", description="Microwave-safe ceramic mug (set of 2).", category="Kitchen", brand="Hearth", merchant="Amazon", price_minor=99900, available=True),
    Product(product_id="prod-0012", name="Aurora Resistance Bands", description="Set of resistance bands for home workouts.", category="Fitness", brand="Aurora", merchant="Flipkart", price_minor=19900, available=True),
    Product(product_id="prod-0013", name="Oakwood Desk", description="Solid wood work desk with cable management.", category="Furniture", brand="Oakwood", merchant="Amazon", price_minor=1599900, available=True),
    Product(product_id="prod-0014", name="Lumina Desk Lamp", description="LED desk lamp with adjustable brightness.", category="Home", brand="Lumina", merchant="Flipkart", price_minor=59900, available=True),
    Product(product_id="prod-0015", name="Glide Office Chair", description="Ergonomic office chair with lumbar support.", category="Furniture", brand="Glide", merchant="Amazon", price_minor=899900, available=True),
    Product(product_id="prod-0016", name="PureWater Filter", description="Under-sink water filter with long-life cartridges.", category="Home", brand="PureWater", merchant="Flipkart", price_minor=699900, available=True),
    Product(product_id="prod-0017", name="Comet Vacuum 2000", description="Bagless vacuum cleaner with HEPA filter.", category="Home", brand="Comet", merchant="Amazon", price_minor=399900, available=True),
    Product(product_id="prod-0018", name="Chef's Knife 8in", description="High-carbon stainless steel chef's knife.", category="Kitchen", brand="EdgePro", merchant="Flipkart", price_minor=159900, available=True),
    Product(product_id="prod-0019", name="Stride Fitness Tracker", description="Wearable fitness tracker with heart-rate monitor.", category="Electronics", brand="Stride", merchant="Amazon", price_minor=499900, available=True),
    Product(product_id="prod-0020", name="Nebula Smartphone", description="Flagship smartphone with excellent camera.", category="Electronics", brand="Nebula", merchant="Flipkart", price_minor=3999900, available=False),
    Product(product_id="prod-0021", name="Oakwood Bookshelf", description="Five-shelf bookshelf made from sustainable wood.", category="Furniture", brand="Oakwood", merchant="Amazon", price_minor=1199900, available=True),
    Product(product_id="prod-0022", name="SolarBright Lantern", description="Portable solar lantern for camping.", category="Outdoors", brand="SolarBright", merchant="Flipkart", price_minor=24900, available=True),
    Product(product_id="prod-0023", name="TrailPro Hiking Boots", description="Waterproof hiking boots for all terrains.", category="Footwear", brand="TrailPro", merchant="Amazon", price_minor=699900, available=True),
    Product(product_id="prod-0024", name="AeroBicycle Helmet", description="Lightweight bike helmet with ventilation.", category="Outdoors", brand="Aero", merchant="Flipkart", price_minor=89900, available=True),
    Product(product_id="prod-0025", name="Fusion Electric Grill", description="Indoor electric grill with non-stick plates.", category="Kitchen", brand="FusionCook", merchant="Amazon", price_minor=299900, available=True),
    Product(product_id="prod-0026", name="Echo Smart Speaker", description="Voice-enabled speaker with rich bass.", category="Electronics", brand="Echo", merchant="Flipkart", price_minor=129900, available=True),
    Product(product_id="prod-0027", name="Vertex Gaming Mouse", description="High-precision gaming mouse with RGB.", category="Electronics", brand="Vertex", merchant="Amazon", price_minor=39900, available=True),
    Product(product_id="prod-0028", name="Nimbus Rain Jacket", description="Packable rain jacket for travel.", category="Apparel", brand="Nimbus", merchant="Amazon", price_minor=199900, available=True),
    Product(product_id="prod-0029", name="Scribe Fountain Pen", description="Fine nib fountain pen with stainless body.", category="Stationery", brand="Scribe", merchant="Flipkart", price_minor=45900, available=True),
    Product(product_id="prod-0030", name="Guardian Door Lock", description="Smart door lock with mobile app integration.", category="Home", brand="Guardian", merchant="Amazon", price_minor=249900, available=True),
    Product(product_id="prod-0031", name="Malicious Item", description="<script>alert('x')</script> OR 1=1; DROP TABLE users;", category="Gadgets", brand="Unknown", merchant="Shady", price_minor=19900, available=True),
    Product(product_id="prod-0032", name="Travel Backpack 40L", description="Durable backpack with multiple compartments.", category="Outdoors", brand="Roamer", merchant="Amazon", price_minor=349900, available=True),
    Product(product_id="prod-0033", name="SolarCharger 20W", description="Compact solar charger for phones.", category="Outdoors", brand="SolarBright", merchant="Flipkart", price_minor=159900, available=True),
    Product(product_id="prod-0034", name="Glacier Insulated Bottle", description="Keeps drinks cold for 24 hours.", category="Kitchen", brand="Glacier", merchant="Amazon", price_minor=99900, available=True),
    Product(product_id="prod-0035", name="Tempo Earbuds", description="True wireless earbuds with low latency.", category="Electronics", brand="Tempo", merchant="Flipkart", price_minor=249900, available=True),
    Product(product_id="prod-0036", name="Craftsman Screwdriver Set", description="Magnetic screwdriver set for home repairs.", category="Tools", brand="Craftsman", merchant="Amazon", price_minor=19900, available=True),
    Product(product_id="prod-0037", name="Nimbus Running Shorts", description="Lightweight running shorts with pockets.", category="Apparel", brand="Nimbus", merchant="Flipkart", price_minor=49900, available=True),
    Product(product_id="prod-0038", name="EdgePro Cutting Board", description="Bamboo cutting board, antibacterial finish.", category="Kitchen", brand="EdgePro", merchant="Amazon", price_minor=29900, available=True),
    Product(product_id="prod-0039", name="Pulse Blood Pressure Monitor", description="Compact blood pressure monitor for home use.", category="Health", brand="Pulse", merchant="Flipkart", price_minor=89900, available=True),
    Product(product_id="prod-0040", name="Flex Yoga Strap", description="Yoga strap for improved stretches.", category="Fitness", brand="Aurora", merchant="Amazon", price_minor=15900, available=True),
]


def _all_products_sorted() -> List[Product]:
    # Deterministic ordering by product_id
    return sorted(_PRODUCTS, key=lambda p: p.product_id)


def search_products(
    query: Optional[str] = None,
    category: Optional[str] = None,
    brand: Optional[str] = None,
    merchant: Optional[str] = None,
    max_price_minor: Optional[int] = None,
    available: Optional[bool] = None,
    limit: Optional[int] = None,
) -> List[Product]:
    """Search products with simple filters. Returns deterministic ordering by product_id."""
    results = _all_products_sorted()

    if query:
        q = query.lower()
        results = [p for p in results if q in p.name.lower() or q in p.description.lower()]

    if category:
        cat = category.lower()
        results = [p for p in results if p.category.lower() == cat]

    if brand:
        b = brand.lower()
        results = [p for p in results if p.brand.lower() == b]

    if merchant:
        m = merchant.lower()
        results = [p for p in results if p.merchant.lower() == m]

    if max_price_minor is not None:
        results = [p for p in results if p.price_minor <= max_price_minor]

    if available is not None:
        results = [p for p in results if p.available == available]

    if limit is not None:
        results = results[:limit]

    return results


def get_product(product_id: str) -> Optional[Product]:
    """Return product or None if not found."""
    for p in _PRODUCTS:
        if p.product_id == product_id:
            return p
    return None
