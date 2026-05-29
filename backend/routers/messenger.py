from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status, Request
from dependencies import limiter
from sqlalchemy import or_, func, case, and_
from sqlalchemy.orm import Session, defer, joinedload
from typing import List
import json
import models, schemas, auth
from database import get_db
from dependencies import get_current_user
from websocket_manager import manager
from utils.push import notify_user_push

router = APIRouter(
    prefix="/messages",
    tags=["messenger"]
)

@router.post("", response_model=schemas.MessageResponse)
@limiter.limit("20/minute")
async def send_message(request: Request, msg: schemas.MessageCreate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    if len(msg.content) > 10000:
        raise HTTPException(status_code=400, detail="Message too long")
    recipient_addr = msg.recipient_address.lower()
    recipient = db.query(models.User).filter(models.User.address == recipient_addr).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")
    
    # Validate PQC key for recipient (Messenger requires PQC for all participants)
    if not recipient.encryption_public_key or len(recipient.encryption_public_key) < 500:
        raise HTTPException(status_code=400, detail="Recipient is not Messenger-capable (Missing PQC key)")
    
    # Create message
    new_msg = models.Message(
        sender_address=current_user.address,
        recipient_address=recipient_addr, # Store lowercase
        content=msg.content,
        is_read=False
    )
    db.add(new_msg)
    db.commit()
    db.refresh(new_msg)
    
    # Real-time Broadcast
    msg_data = {
        "type": "NEW_MESSAGE",
        "message": {
            "id": new_msg.id,
            "sender_address": new_msg.sender_address,
            "recipient_address": new_msg.recipient_address,
            "content": new_msg.content,
            "is_read": new_msg.is_read,
            "created_at": new_msg.created_at.isoformat()
        }
    }
    
    # Send to Recipient
    await manager.send_personal_message(msg_data, recipient_addr)
    
    # Send Push Notification
    sender_name = current_user.username or f"{current_user.address[:8]}..."
    notify_user_push(
        db, 
        recipient_addr, 
        title="New Message", 
        body=f"You have a new secure message from {sender_name}",
        data={"type": "messenger", "sender": current_user.address}
    )

    # Send to Sender (for sync across their devices)
    await manager.send_personal_message(msg_data, current_user.address)

    return new_msg

@router.get("/conversations", response_model=List[schemas.ConversationResponse])
@limiter.limit("30/minute")
def get_conversations(request: Request, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Fetch list of unique conversations for the current user.
    Uses a subquery to find the latest message per conversation partner,
    then batch-loads unread counts in a single query.
    """
    partner_address_col = case(
        (models.Message.sender_address == current_user.address, models.Message.recipient_address),
        else_=models.Message.sender_address
    )

    subquery = db.query(
        func.max(models.Message.id).label("max_id")
    ).filter(
        or_(
            models.Message.sender_address == current_user.address,
            models.Message.recipient_address == current_user.address
        )
    ).group_by(partner_address_col).subquery()

    latest_messages = db.query(models.Message).options(
        joinedload(models.Message.sender),
        joinedload(models.Message.recipient),
        defer(models.Message.content)
    ).filter(
        models.Message.id.in_(subquery.select())
    ).order_by(models.Message.created_at.desc()).all()
    
    conversations = []
    
    # Batch-load unread counts grouped by sender
    unread_counts_query = db.query(
        models.Message.sender_address, func.count(models.Message.id)
    ).filter(
        models.Message.recipient_address == current_user.address,
        models.Message.is_read == False
    ).group_by(models.Message.sender_address).all()

    unread_map = {addr: count for addr, count in unread_counts_query}

    for m in latest_messages:
        partner = m.recipient if m.sender_address == current_user.address else m.sender
        if not partner:
            continue

        unread = unread_map.get(partner.address, 0)
        conversations.append({
            "user": partner,
            "last_message": m,
            "unread_count": unread
        })
    
    return conversations

@router.post("/history", response_model=List[schemas.MessageResponse])
@limiter.limit("60/minute")
def get_message_history(request: Request, req: schemas.HistoryRequest, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    if req.limit > 100:
        req.limit = 100
    
    partner_address = req.partner_address.lower()
    
    msgs = db.query(models.Message).filter(
        or_(
            (models.Message.sender_address == current_user.address) & (models.Message.recipient_address == partner_address),
            (models.Message.sender_address == partner_address) & (models.Message.recipient_address == current_user.address)
        )
    ).order_by(models.Message.created_at.desc()).limit(req.limit).offset(req.offset).all()
    
    return msgs[::-1]

@router.post("/mark-read/{partner_address}")
def mark_read(partner_address: str, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    partner_addr = partner_address.lower()
    
    # Mark all messages sent BY partner TO me as read
    db.query(models.Message).filter(
        models.Message.sender_address == partner_addr,
        models.Message.recipient_address == current_user.address,
        models.Message.is_read == False
    ).update({"is_read": True})
    
    db.commit()
    return {"status": "ok"}

# WebSocket router without prefix so it mounts at /ws
ws_router = APIRouter()

@ws_router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    
    # Wait for authentication message
    try:
        data = await websocket.receive_text()
        auth_data = json.loads(data)
        
        if auth_data.get("type") != "AUTH":
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
            
        token = auth_data.get("token")
        if not token:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        payload = auth.decode_access_token(token)
        if not payload or not payload.get("sub"):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
            
        user_address = payload.get("sub").lower()
        
        await manager.connect(websocket, user_address)
        try:
            while True:
                raw = await websocket.receive_text()
                # Handle client messages (focus state, typing indicators, etc.)
                try:
                    msg = json.loads(raw)
                    if msg.get("type") == "APP_FOCUSED":
                        manager.set_focused(websocket)
                    elif msg.get("type") == "APP_BLURRED":
                        manager.set_blurred(websocket)
                except (json.JSONDecodeError, AttributeError):
                    pass
        except WebSocketDisconnect:
            manager.disconnect(websocket, user_address)
            
    except WebSocketDisconnect:
        # Disconnected before authentication completed
        manager.disconnect(websocket, None)
    except Exception as e:
        print(f"WS Error: {e}")
        # Only try to close if not already closed
        try:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        except Exception:
            pass
