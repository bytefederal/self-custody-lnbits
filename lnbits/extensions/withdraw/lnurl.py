import json
import traceback
from datetime import datetime
from http import HTTPStatus

import shortuuid  # type: ignore
from fastapi import HTTPException
from fastapi.param_functions import Query
from loguru import logger
from starlette.requests import Request
from starlette.responses import HTMLResponse

from lnbits.core.services import pay_invoice

from . import withdraw_ext
from .crud import get_withdraw_link_by_hash, update_withdraw_link

# FOR LNURLs WHICH ARE NOT UNIQUE


@withdraw_ext.get(
    "/api/v1/lnurl/{unique_hash}",
    response_class=HTMLResponse,
    name="withdraw.api_lnurl_response",
)
async def api_lnurl_response(request: Request, unique_hash):
    link = await get_withdraw_link_by_hash(unique_hash)

    if not link:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Withdraw link does not exist."
        )

    if link.is_spent:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Withdraw is spent."
        )
    url = request.url_for("withdraw.api_lnurl_callback", unique_hash=link.unique_hash)
    withdrawResponse = {
        "tag": "withdrawRequest",
        "callback": url,
        "k1": link.k1,
        "minWithdrawable": link.min_withdrawable * 1000,
        "maxWithdrawable": link.max_withdrawable * 1000,
        "defaultDescription": link.title,
    }
    return json.dumps(withdrawResponse)


# CALLBACK


@withdraw_ext.get(
    "/api/v1/lnurl/cb/{unique_hash}",
    name="withdraw.api_lnurl_callback",
    summary="lnurl withdraw callback",
    description="""
        This enpoints allows you to put unique_hash, k1
        and a payment_request to get your payment_request paid.
    """,
    response_description="JSON with status",
    responses={
        200: {"description": "status: OK"},
        400: {"description": "k1 is wrong or link open time or withdraw not working."},
        404: {"description": "withdraw link not found."},
        405: {"description": "withdraw link is spent."},
    },
)
async def api_lnurl_callback(
    unique_hash,
    k1: str = Query(...),
    pr: str = Query(...),
    id_unique_hash=None,
):
    link = await get_withdraw_link_by_hash(unique_hash)
    now = int(datetime.now().timestamp())
    if not link:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="withdraw not found."
        )

    if link.is_spent:
        raise HTTPException(
            status_code=HTTPStatus.METHOD_NOT_ALLOWED, detail="withdraw is spent."
        )

    if link.k1 != k1:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="k1 is wrong.")

    if now < link.open_time:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"wait link open_time {link.open_time - now} seconds.",
        )

    usescsv = ""

    for x in range(1, link.uses - link.used):
        usecv = link.usescsv.split(",")
        usescsv += "," + str(usecv[x])
    usecsvback = usescsv

    found = False
    if id_unique_hash is not None:
        useslist = link.usescsv.split(",")
        for ind, x in enumerate(useslist):
            tohash = link.id + link.unique_hash + str(x)
            if id_unique_hash == shortuuid.uuid(name=tohash):
                found = True
                useslist.pop(ind)
                usescsv = ",".join(useslist)
        if not found:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND, detail="withdraw not found."
            )
    else:
        usescsv = usescsv[1:]

    changesback = {
        "open_time": link.wait_time,
        "used": link.used,
        "usescsv": usecsvback,
    }

    try:
        changes = {
            "open_time": link.wait_time + now,
            "used": link.used + 1,
            "usescsv": usescsv,
        }
        await update_withdraw_link(link.id, **changes)

        payment_request = pr

        webhook = (
            (
                link.webhook_url,
                {
                    "lnurlw": link.id,
                },
            )
            if link.webhook_url
            else None
        )
        await pay_invoice(
            wallet_id=link.wallet,
            payment_request=payment_request,
            max_sat=link.max_withdrawable,
            extra={"tag": "withdraw"},
            webhook=webhook,
        )

        return {"status": "OK"}

    except Exception as e:
        await update_withdraw_link(link.id, **changesback)
        logger.error(traceback.format_exc())
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail=f"withdraw not working. {str(e)}"
        )


# FOR LNURLs WHICH ARE UNIQUE


@withdraw_ext.get(
    "/api/v1/lnurl/{unique_hash}/{id_unique_hash}",
    response_class=HTMLResponse,
    name="withdraw.api_lnurl_multi_response",
)
async def api_lnurl_multi_response(request: Request, unique_hash, id_unique_hash):
    link = await get_withdraw_link_by_hash(unique_hash)

    if not link:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="LNURL-withdraw not found."
        )

    if link.is_spent:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Withdraw is spent."
        )

    useslist = link.usescsv.split(",")
    found = False
    for x in useslist:
        tohash = link.id + link.unique_hash + str(x)
        if id_unique_hash == shortuuid.uuid(name=tohash):
            found = True

    if not found:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="LNURL-withdraw not found."
        )

    url = request.url_for("withdraw.api_lnurl_callback", unique_hash=link.unique_hash)
    withdrawResponse = {
        "tag": "withdrawRequest",
        "callback": url + "?id_unique_hash=" + id_unique_hash,
        "k1": link.k1,
        "minWithdrawable": link.min_withdrawable * 1000,
        "maxWithdrawable": link.max_withdrawable * 1000,
        "defaultDescription": link.title,
    }
    return json.dumps(withdrawResponse)
