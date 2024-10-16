from typing import Optional

from fastapi import (
    APIRouter,
    Body,
    Depends,
)

from lnbits.core.models import (
    CreateWallet,
    KeyType,
    Wallet,
    AddPublicKeyRequest
)
from lnbits.decorators import (
    WalletTypeInfo,
    get_key_type,
    require_admin_key,
)

from ..crud import (
    create_wallet,
    delete_wallet,
    update_wallet,
)

from ..services import insert_wallet_pubkey
from loguru import logger

wallet_router = APIRouter(prefix="/api/v1/wallet", tags=["Wallet"])


@wallet_router.get("")
async def api_wallet(wallet: WalletTypeInfo = Depends(get_key_type)):
    if wallet.key_type == KeyType.admin:
        return {
            "id": wallet.wallet.id,
            "name": wallet.wallet.name,
            "balance": wallet.wallet.balance_msat,
        }
    else:
        return {"name": wallet.wallet.name, "balance": wallet.wallet.balance_msat}


@wallet_router.put("/{new_name}")
async def api_update_wallet_name(
    new_name: str, wallet: WalletTypeInfo = Depends(require_admin_key)
):
    await update_wallet(wallet.wallet.id, new_name)
    return {
        "id": wallet.wallet.id,
        "name": wallet.wallet.name,
        "balance": wallet.wallet.balance_msat,
    }


@wallet_router.patch("", response_model=Wallet)
async def api_update_wallet(
    name: Optional[str] = Body(None),
    currency: Optional[str] = Body(None),
    wallet: WalletTypeInfo = Depends(require_admin_key),
):
    return await update_wallet(wallet.wallet.id, name, currency)


@wallet_router.delete("")
async def api_delete_wallet(
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> None:
    await delete_wallet(
        user_id=wallet.wallet.user,
        wallet_id=wallet.wallet.id,
    )


@wallet_router.post("", response_model=Wallet)
async def api_create_wallet(
    data: CreateWallet,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> Wallet:
    return await create_wallet(user_id=wallet.wallet.user, wallet_name=data.name)

@wallet_router.post("/pubkey", response_model=bool)
async def api_add_wallet_pubkey(data: AddPublicKeyRequest) -> bool:
    logger.info(f"Adding pubkey to wallet: {data.wallet_id}")
    result = await insert_wallet_pubkey(
            user=data.user,
            admin_key=data.admin_key,
            wallet_id=data.wallet_id,
            invoice_key=data.invoice_key,
            public_key=data.public_key,
            signed_message=data.signed_message
        )
    return result