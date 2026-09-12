import asyncio
import json
import logging

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from sqlalchemy import case, func, or_
from sqlalchemy.orm import Session, defer, joinedload

import config
import models
import schemas
from database import SessionLocal, get_db
from dependencies import get_current_user, limiter, user_for_token
from security import authorization
from security.crypto_validation import is_usable_encryption_key
from utils.clock import to_wire_utc
from utils.push import display_name, notify_user_push_async
from websocket_manager import manager

logger = logging.getLogger("kryptolog.messenger")

router = APIRouter(prefix="/messages", tags=["messenger"])


@router.post("", response_model=schemas.MessageResponse)
@limiter.limit("20/minute")
async def send_message(
    request: Request,
    msg: schemas.MessageCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    recipient_addr = msg.recipient_address.lower()
    recipient = authorization.find_active_user(db, recipient_addr)
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    # Validate PQC key for recipient (Messenger requires PQC for all participants)
    if not is_usable_encryption_key(recipient.encryption_public_key):
        raise HTTPException(
            status_code=400, detail="Recipient is not Messenger-capable (Missing PQC key)"
        )

    new_msg = models.Message(
        sender_address=current_user.address,
        recipient_address=recipient_addr,  # Store lowercase
        content=msg.content,
        is_read=False,
    )
    db.add(new_msg)
    db.commit()
    db.refresh(new_msg)

    msg_data = {
        "type": "NEW_MESSAGE",
        "message": {
            "id": new_msg.id,
            "sender_address": new_msg.sender_address,
            "recipient_address": new_msg.recipient_address,
            "content": new_msg.content,
            "is_read": new_msg.is_read,
            # to_wire_utc, not .isoformat(): this payload never passes through a
            # response model, so it has to mark UTC itself or the live message
            # renders at the wrong local time until a refetch corrects it.
            "created_at": to_wire_utc(new_msg.created_at),
        },
    }

    await manager.send_personal_message(msg_data, recipient_addr)

    sender_name = display_name(current_user)
    await notify_user_push_async(
        db,
        recipient_addr,
        title="New Message",
        body=f"You have a new secure message from {sender_name}",
        data={"type": "messenger", "sender": current_user.address},
    )

    # Send to Sender (for sync across their devices)
    await manager.send_personal_message(msg_data, current_user.address)

    return new_msg


@router.get("/conversations", response_model=list[schemas.ConversationResponse])
@limiter.limit("30/minute")
def get_conversations(
    request: Request,
    # Paged like the other list endpoints (audit O-3). This one is not in the
    # finding — it names the secret and group lists — but it is the same
    # defect: one row per person the user has ever exchanged a message with,
    # with no ceiling. Cheaper per row than the others (the message body is
    # deferred, so these are metadata), hence the same bounds as /history.
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Fetch a page of the current user's conversations, most recent first.
    Uses a subquery to find the latest message per conversation partner,
    then batch-loads unread counts for that page in a single query.
    """
    partner_address_col = case(
        (models.Message.sender_address == current_user.address, models.Message.recipient_address),
        else_=models.Message.sender_address,
    )

    subquery = (
        db.query(func.max(models.Message.id).label("max_id"))
        .filter(
            or_(
                models.Message.sender_address == current_user.address,
                models.Message.recipient_address == current_user.address,
            )
        )
        .group_by(partner_address_col)
        .subquery()
    )

    latest_messages = (
        db.query(models.Message)
        .options(
            joinedload(models.Message.sender),
            joinedload(models.Message.recipient),
            defer(models.Message.content),
        )
        .filter(models.Message.id.in_(subquery.select()))
        .order_by(
            models.Message.created_at.desc(),
            # Tiebreaker: two messages can share a timestamp, and without a total
            # order the same conversation can appear on two pages or on neither.
            models.Message.id.desc(),
        )
        .limit(limit)
        .offset(offset)
        .all()
    )

    conversations = []

    # Unread counts for this page's partners only — the whole point of paging
    # is that nothing here scales with the user's total conversation count.
    partner_addresses = {
        m.recipient_address if m.sender_address == current_user.address else m.sender_address
        for m in latest_messages
    }
    unread_counts_query = (
        db.query(models.Message.sender_address, func.count(models.Message.id))
        .filter(
            models.Message.recipient_address == current_user.address,
            models.Message.sender_address.in_(partner_addresses),
            models.Message.is_read == False,
        )
        .group_by(models.Message.sender_address)
        .all()
        if partner_addresses
        else []
    )

    unread_map = {addr: count for addr, count in unread_counts_query}

    for m in latest_messages:
        partner = m.recipient if m.sender_address == current_user.address else m.sender
        if not partner:
            continue

        unread = unread_map.get(partner.address, 0)
        conversations.append({"user": partner, "last_message": m, "unread_count": unread})

    return conversations


@router.post("/history", response_model=list[schemas.MessageResponse])
@limiter.limit("60/minute")
def get_message_history(
    request: Request,
    req: schemas.HistoryRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    partner_address = req.partner_address.lower()

    msgs = (
        db.query(models.Message)
        .filter(
            or_(
                (models.Message.sender_address == current_user.address)
                & (models.Message.recipient_address == partner_address),
                (models.Message.sender_address == partner_address)
                & (models.Message.recipient_address == current_user.address),
            )
        )
        .order_by(models.Message.created_at.desc())
        .limit(req.limit)
        .offset(req.offset)
        .all()
    )

    return msgs[::-1]


@router.post("/mark-read/{partner_address}")
@limiter.limit("60/minute")
def mark_read(
    request: Request,
    partner_address: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    partner_addr = partner_address.lower()

    # Mark all messages sent BY partner TO me as read
    db.query(models.Message).filter(
        models.Message.sender_address == partner_addr,
        models.Message.recipient_address == current_user.address,
        models.Message.is_read == False,
    ).update({"is_read": True})

    db.commit()
    return {"status": "ok"}


# WebSocket router without prefix so it mounts at /ws
ws_router = APIRouter()

# How long an accepted socket may stay unauthenticated before we close it (M2).
WS_AUTH_TIMEOUT_SECONDS = 10.0


def _origin_allowed(websocket: WebSocket) -> bool:
    """Whether this handshake's Origin is on the allowlist (audit M2).

    CORS does NOT cover WebSocket handshakes, so cross-site connections have to
    be rejected here. Token auth already blocks CSWSH — the bearer token is not
    auto-sent the way a cookie is — but an unchecked Origin still lets any page
    open sockets. Only enforced when an allowlist is configured, since dev may
    leave ALLOWED_ORIGINS unset.
    """
    allowed = config.get_allowed_origins()
    if not allowed:
        return True
    origin = websocket.headers.get("origin")
    return origin is not None and origin.rstrip("/") in allowed


async def _authenticate_socket(websocket: WebSocket) -> str | None:
    """Read the AUTH frame and return the caller's address, or None to reject.

    Bounded by WS_AUTH_TIMEOUT_SECONDS (audit M2) so unauthenticated sockets
    cannot linger and pile up; clients send AUTH immediately on connect. Read
    at call time rather than captured as a default so tests can adjust it.
    """
    try:
        data = await asyncio.wait_for(websocket.receive_text(), timeout=WS_AUTH_TIMEOUT_SECONDS)
    except TimeoutError:
        return None

    auth_data = json.loads(data)
    if auth_data.get("type") != "AUTH":
        return None

    token = auth_data.get("token")
    if not token:
        return None

    # Validate the token AND enforce revocation (token_version), same as HTTP.
    db = SessionLocal()
    try:
        ws_user = user_for_token(token, db)
    finally:
        db.close()

    return ws_user.address.lower() if ws_user else None


async def _client_message_loop(websocket: WebSocket) -> None:
    """Serve one authenticated socket until it disconnects.

    The only client-to-server messages are presence hints, and a malformed one
    is ignored rather than closing the socket.
    """
    while True:
        raw = await websocket.receive_text()
        try:
            msg = json.loads(raw)
            if msg.get("type") == "APP_FOCUSED":
                await manager.set_focused(websocket)
            elif msg.get("type") == "APP_BLURRED":
                await manager.set_blurred(websocket)
        except (json.JSONDecodeError, AttributeError):
            pass


@ws_router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # Closing before accept() rejects the handshake outright.
    if not _origin_allowed(websocket):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()

    try:
        user_address = await _authenticate_socket(websocket)
        if user_address is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        await manager.connect(websocket, user_address)
        try:
            await _client_message_loop(websocket)
        except WebSocketDisconnect:
            await manager.disconnect(websocket, user_address)

    except WebSocketDisconnect:
        # Disconnected before authentication completed.
        await manager.disconnect(websocket, None)
    except Exception as e:
        logger.warning("WS error: %s", e)
        try:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        except Exception:
            pass
