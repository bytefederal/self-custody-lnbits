from base64 import urlsafe_b64encode
from http import HTTPStatus
from uuid import uuid4

from fastapi import Request
from fastapi.param_functions import Query
from fastapi.params import Depends
from starlette.exceptions import HTTPException

from lnbits.core.crud import get_user
from lnbits.core.services import create_invoice
from lnbits.decorators import (
    WalletTypeInfo,
    get_key_type,
    require_admin_key,
    require_invoice_key,
)

from . import db, diagonalley_ext
from .crud import (
    create_diagonalley_order,
    create_diagonalley_product,
    create_diagonalley_stall,
    create_diagonalley_zone,
    delete_diagonalley_order,
    delete_diagonalley_product,
    delete_diagonalley_stall,
    delete_diagonalley_zone,
    get_diagonalley_market,
    get_diagonalley_markets,
    get_diagonalley_order,
    get_diagonalley_orders,
    get_diagonalley_product,
    get_diagonalley_products,
    get_diagonalley_stall,
    get_diagonalley_stalls,
    get_diagonalley_zone,
    get_diagonalley_zones,
    update_diagonalley_product,
    update_diagonalley_stall,
    update_diagonalley_zone,
)
from .models import (
    CreateMarket,
    Orders,
    Products,
    Stalls,
    Zones,
    createOrder,
    createProduct,
    createStalls,
    createZones,
)

# from lnbits.db import open_ext_db


### Products
"""
@copilot_ext.get("/api/v1/copilot/{copilot_id}")
async def api_copilot_retrieve(
    req: Request,
    copilot_id: str = Query(None),
    wallet: WalletTypeInfo = Depends(get_key_type),
):
    copilot = await get_copilot(copilot_id)
    if not copilot:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Copilot not found"
        )
    if not copilot.lnurl_toggle:
        return copilot.dict()
    return {**copilot.dict(), **{"lnurl": copilot.lnurl(req)}}
"""


@diagonalley_ext.get("/api/v1/products")
async def api_diagonalley_products(
    wallet: WalletTypeInfo = Depends(get_key_type),
    all_stalls: bool = Query(False),
):
    wallet_ids = [wallet.wallet.id]

    if all_stalls:
        wallet_ids = (await get_user(wallet.wallet.user)).wallet_ids

    stalls = [stall.id for stall in await get_diagonalley_stalls(wallet_ids)]

    if not stalls:
        return

    return [product.dict() for product in await get_diagonalley_products(stalls)]


@diagonalley_ext.post("/api/v1/products")
@diagonalley_ext.put("/api/v1/products/{product_id}")
async def api_diagonalley_product_create(
    data: createProduct, product_id=None, wallet: WalletTypeInfo = Depends(get_key_type)
):

    if product_id:
        product = await get_diagonalley_product(product_id)
        if not product:
            return {"message": "Withdraw product does not exist."}

        stall = await get_diagonalley_stall(stall_id=product.stall)
        if stall.wallet != wallet.wallet.id:
            return {"message": "Not your withdraw product."}

        product = await update_diagonalley_product(product_id, **data.dict())
    else:
        product = await create_diagonalley_product(data=data)

    return product.dict()


@diagonalley_ext.delete("/api/v1/products/{product_id}")
async def api_diagonalley_products_delete(
    product_id, wallet: WalletTypeInfo = Depends(require_admin_key)
):
    product = await get_diagonalley_product(product_id)

    if not product:
        return {"message": "Product does not exist."}

    stall = await get_diagonalley_stall(product.stall)
    if stall.wallet != wallet.wallet.id:
        return {"message": "Not your Diagon Alley."}

    await delete_diagonalley_product(product_id)
    raise HTTPException(status_code=HTTPStatus.NO_CONTENT)


# # # Shippingzones


@diagonalley_ext.get("/api/v1/zones")
async def api_diagonalley_zones(wallet: WalletTypeInfo = Depends(get_key_type)):

    return await get_diagonalley_zones(wallet.wallet.user)


@diagonalley_ext.post("/api/v1/zones")
async def api_diagonalley_zone_create(
    data: createZones, wallet: WalletTypeInfo = Depends(get_key_type)
):
    zone = await create_diagonalley_zone(user=wallet.wallet.user, data=data)
    return zone.dict()


@diagonalley_ext.post("/api/v1/zones/{zone_id}")
async def api_diagonalley_zone_update(
    data: createZones,
    zone_id: str,
    wallet: WalletTypeInfo = Depends(require_admin_key),
):
    zone = await get_diagonalley_zone(zone_id)
    if not zone:
        return {"message": "Zone does not exist."}
    if zone.user != wallet.wallet.user:
        return {"message": "Not your record."}
    zone = await update_diagonalley_zone(zone_id, **data.dict())
    return zone


@diagonalley_ext.delete("/api/v1/zones/{zone_id}")
async def api_diagonalley_zone_delete(
    zone_id, wallet: WalletTypeInfo = Depends(require_admin_key)
):
    zone = await get_diagonalley_zone(zone_id)

    if not zone:
        return {"message": "zone does not exist."}

    if zone.user != wallet.wallet.user:
        return {"message": "Not your zone."}

    await delete_diagonalley_zone(zone_id)
    raise HTTPException(status_code=HTTPStatus.NO_CONTENT)


# # # Stalls


@diagonalley_ext.get("/api/v1/stalls")
async def api_diagonalley_stalls(
    wallet: WalletTypeInfo = Depends(get_key_type), all_wallets: bool = Query(False)
):
    wallet_ids = [wallet.wallet.id]

    if all_wallets:
        wallet_ids = (await get_user(wallet.wallet.user)).wallet_ids

    return [stall.dict() for stall in await get_diagonalley_stalls(wallet_ids)]


@diagonalley_ext.post("/api/v1/stalls")
@diagonalley_ext.put("/api/v1/stalls/{stall_id}")
async def api_diagonalley_stall_create(
    data: createStalls,
    stall_id: str = None,
    wallet: WalletTypeInfo = Depends(require_invoice_key),
):

    if stall_id:
        stall = await get_diagonalley_stall(stall_id)
        print("ID", stall_id)
        if not stall:
            return {"message": "Withdraw stall does not exist."}

        if stall.wallet != wallet.wallet.id:
            return {"message": "Not your withdraw stall."}

        stall = await update_diagonalley_stall(stall_id, **data.dict())
    else:
        stall = await create_diagonalley_stall(data=data)

    return stall.dict()


@diagonalley_ext.delete("/api/v1/stalls/{stall_id}")
async def api_diagonalley_stall_delete(
    stall_id: str, wallet: WalletTypeInfo = Depends(require_admin_key)
):
    stall = await get_diagonalley_stall(stall_id)

    if not stall:
        return {"message": "Stall does not exist."}

    if stall.wallet != wallet.wallet.id:
        return {"message": "Not your Stall."}

    await delete_diagonalley_stall(stall_id)
    raise HTTPException(status_code=HTTPStatus.NO_CONTENT)


###Orders


@diagonalley_ext.get("/api/v1/orders")
async def api_diagonalley_orders(
    wallet: WalletTypeInfo = Depends(get_key_type), all_wallets: bool = Query(False)
):
    wallet_ids = [wallet.wallet.id]

    if all_wallets:
        wallet_ids = (await get_user(wallet.wallet.user)).wallet_ids

    try:
        return [order.dict() for order in await get_diagonalley_orders(wallet_ids)]
    except:
        return {"message": "We could not retrieve the orders."}


@diagonalley_ext.post("/api/v1/orders")
async def api_diagonalley_order_create(
    data: createOrder, wallet: WalletTypeInfo = Depends(get_key_type)
):
    order = await create_diagonalley_order(wallet_id=wallet.wallet.id, data=data)
    return order.dict()


@diagonalley_ext.delete("/api/v1/orders/{order_id}")
async def api_diagonalley_order_delete(
    order_id: str, wallet: WalletTypeInfo = Depends(get_key_type)
):
    order = await get_diagonalley_order(order_id)

    if not order:
        return {"message": "Order does not exist."}

    if order.wallet != wallet.wallet.id:
        return {"message": "Not your Order."}

    await delete_diagonalley_order(order_id)

    raise HTTPException(status_code=HTTPStatus.NO_CONTENT)


@diagonalley_ext.get("/api/v1/orders/paid/{order_id}")
async def api_diagonalley_order_paid(
    order_id, wallet: WalletTypeInfo = Depends(require_admin_key)
):
    await db.execute(
        "UPDATE diagonalley.orders SET paid = ? WHERE id = ?",
        (
            True,
            order_id,
        ),
    )
    return "", HTTPStatus.OK


@diagonalley_ext.get("/api/v1/orders/shipped/{order_id}")
async def api_diagonalley_order_shipped(
    order_id, wallet: WalletTypeInfo = Depends(get_key_type)
):
    await db.execute(
        "UPDATE diagonalley.orders SET shipped = ? WHERE id = ?",
        (
            True,
            order_id,
        ),
    )
    order = await db.fetchone(
        "SELECT * FROM diagonalley.orders WHERE id = ?", (order_id,)
    )

    return [order.dict() for order in get_diagonalley_orders(order["wallet"])]


###List products based on stall id


@diagonalley_ext.get("/api/v1/stall/products/{stall_id}")
async def api_diagonalley_stall_products(
    stall_id, wallet: WalletTypeInfo = Depends(get_key_type)
):

    rows = await db.fetchone(
        "SELECT * FROM diagonalley.stalls WHERE id = ?", (stall_id,)
    )
    print(rows[1])
    if not rows:
        return {"message": "Stall does not exist."}

    products = db.fetchone(
        "SELECT * FROM diagonalley.products WHERE wallet = ?", (rows[1],)
    )
    if not products:
        return {"message": "No products"}

    return [products.dict() for products in await get_diagonalley_products(rows[1])]


###Check a product has been shipped


@diagonalley_ext.get("/api/v1/stall/checkshipped/{checking_id}")
async def api_diagonalley_stall_checkshipped(
    checking_id, wallet: WalletTypeInfo = Depends(get_key_type)
):
    rows = await db.fetchone(
        "SELECT * FROM diagonalley.orders WHERE invoiceid = ?", (checking_id,)
    )
    return {"shipped": rows["shipped"]}


###Place order


@diagonalley_ext.post("/api/v1/stall/order/{stall_id}")
async def api_diagonalley_stall_order(
    stall_id, data: createOrder, wallet: WalletTypeInfo = Depends(get_key_type)
):
    product = await get_diagonalley_product(data.productid)
    shipping = await get_diagonalley_stall(stall_id)

    if data.shippingzone == 1:
        shippingcost = shipping.zone1cost  # missing in model
    else:
        shippingcost = shipping.zone2cost  # missing in model

    checking_id, payment_request = await create_invoice(
        wallet_id=product.wallet,
        amount=shippingcost + (data.quantity * product.price),
        memo=shipping.wallet,
    )
    selling_id = urlsafe_b64encode(uuid4().bytes_le).decode("utf-8")
    await db.execute(
        """
            INSERT INTO diagonalley.orders (id, productid, wallet, product, quantity, shippingzone, address, email, invoiceid, paid, shipped)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
        (
            selling_id,
            data.productid,
            product.wallet,  # doesn't exist in model
            product.product,
            data.quantity,
            data.shippingzone,
            data.address,
            data.email,
            checking_id,
            False,
            False,
        ),
    )
    return {"checking_id": checking_id, "payment_request": payment_request}


##
# MARKETS
##


@diagonalley_ext.get("/api/v1/markets")
async def api_diagonalley_orders(wallet: WalletTypeInfo = Depends(get_key_type)):
    try:
        return [
            market.dict()
            for market in await get_diagonalley_markets(wallet.wallet.user)
        ]
    except:
        return {"message": "We could not retrieve the markets."}


@diagonalley_ext.post("/api/v1/markets")
@diagonalley_ext.put("/api/v1/markets/{market_id}")
async def api_diagonalley_stall_create(
    data: CreateMarket,
    market_id: str = None,
    wallet: WalletTypeInfo = Depends(require_invoice_key),
):

    if market_id:
        market = await get_diagonalley_market(market_id)
        if not market:
            return {"message": "Market does not exist."}

        if market.usr != wallet.wallet.user:
            return {"message": "Not your market."}

        market = await update_diagonalley_market(market_id, **data.dict())
    else:
        market = await create_diagonalley_market(data=data)

    return market.dict()
