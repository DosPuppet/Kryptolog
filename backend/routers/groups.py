from fastapi import APIRouter, Depends, HTTPException, Request
from dependencies import limiter
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func
from typing import List
import uuid
import models, schemas
from database import get_db
from dependencies import get_current_user
from websocket_manager import manager
from utils.push import notify_user_push

router = APIRouter(
    prefix="/groups",
    tags=["groups"]
)


# ── Create Group ────────────────────────────────────────────────

@router.post("", response_model=schemas.GroupChannelResponse)
@limiter.limit("10/minute")
async def create_group(
    request: Request,
    data: schemas.GroupChannelCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if len(data.member_addresses) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 members per group")

    # Verify all members exist
    member_addrs = list({addr.lower() for addr in data.member_addresses})
    # Always include creator
    if current_user.address not in member_addrs:
        member_addrs.append(current_user.address)

    users = db.query(models.User).filter(models.User.address.in_(member_addrs)).all()
    found_addrs = {u.address for u in users}
    missing = set(member_addrs) - found_addrs
    if missing:
        raise HTTPException(status_code=404, detail=f"Users not found: {', '.join(missing)}")

    # Validate all members have PQC keys (Messenger requirement)
    for u in users:
        if not u.encryption_public_key or len(u.encryption_public_key) < 500:
            raise HTTPException(
                status_code=400, 
                detail=f"User {u.address} is not Messenger-capable (Missing PQC key)"
            )

    channel_id = str(uuid.uuid4())
    channel = models.GroupChannel(
        id=channel_id,
        name=data.name.strip(),
        owner_address=current_user.address,
    )
    db.add(channel)

    # Add members
    for addr in member_addrs:
        role = "owner" if addr == current_user.address else "member"
        db.add(models.GroupMember(
            channel_id=channel_id,
            user_address=addr,
            role=role,
        ))

    db.commit()
    db.refresh(channel)

    # Notify members that they have joined
    for addr in member_addrs:
        if addr != current_user.address:
            await manager.send_personal_message({
                "type": "GROUP_JOINED",
                "channel": schemas.GroupChannelResponse.model_validate(channel)
            }, addr)
            
            # Push Notification
            notify_user_push(
                db,
                addr,
                title="New Group",
                body=f"You have been added to a new group: {channel.name}",
                data={"type": "group_joined", "channel_id": channel.id}
            )

    return channel


# ── List My Groups ──────────────────────────────────────────────

@router.get("", response_model=List[schemas.GroupConversationResponse])
@limiter.limit("30/minute")
def list_groups(
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Find channels the user is a member of
    memberships = (
        db.query(models.GroupMember.channel_id)
        .filter(models.GroupMember.user_address == current_user.address)
        .scalar_subquery()
    )

    channels = (
        db.query(models.GroupChannel)
        .options(joinedload(models.GroupChannel.members).joinedload(models.GroupMember.user))
        .filter(models.GroupChannel.id.in_(memberships))
        .all()
    )

    # For each channel, find the latest message
    result = []
    for ch in channels:
        last_msg = (
            db.query(models.GroupMessage)
            .options(joinedload(models.GroupMessage.sender))
            .filter(models.GroupMessage.channel_id == ch.id)
            .order_by(models.GroupMessage.created_at.desc())
            .first()
        )

        # Unread count: messages sent after the last time the user would have seen them
        # For simplicity, we count messages not sent by user (group has no per-user read tracking yet)
        # We'll add read tracking via a last_read_at field on GroupMember
        result.append({
            "channel": ch,
            "last_message": last_msg,
            "unread_count": 0,  # Will be enhanced with read tracking
        })

    # Sort by most recent activity
    result.sort(key=lambda r: r["last_message"].created_at if r["last_message"] else r["channel"].created_at, reverse=True)
    return result


# ── Get Group Details ───────────────────────────────────────────

@router.get("/{channel_id}", response_model=schemas.GroupChannelResponse)
@limiter.limit("30/minute")
def get_group(
    request: Request,
    channel_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    channel = (
        db.query(models.GroupChannel)
        .options(joinedload(models.GroupChannel.members).joinedload(models.GroupMember.user))
        .filter(models.GroupChannel.id == channel_id)
        .first()
    )
    if not channel:
        raise HTTPException(status_code=404, detail="Group not found")

    # Verify membership
    if not any(m.user_address == current_user.address for m in channel.members):
        raise HTTPException(status_code=403, detail="Not a member of this group")

    return channel


# ── Send Group Message ──────────────────────────────────────────

@router.post("/{channel_id}/messages", response_model=schemas.GroupMessageResponse)
@limiter.limit("20/minute")
async def send_group_message(
    request: Request,
    channel_id: str,
    data: schemas.GroupMessageCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if len(data.content) > 50000:
        raise HTTPException(status_code=400, detail="Message too long")

    channel = (
        db.query(models.GroupChannel)
        .options(joinedload(models.GroupChannel.members))
        .filter(models.GroupChannel.id == channel_id)
        .first()
    )
    if not channel:
        raise HTTPException(status_code=404, detail="Group not found")

    if not any(m.user_address == current_user.address for m in channel.members):
        raise HTTPException(status_code=403, detail="Not a member of this group")

    msg = models.GroupMessage(
        channel_id=channel_id,
        sender_address=current_user.address,
        content=data.content,
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    # Real-time update
    msg_json = schemas.GroupMessageResponse.model_validate(msg).model_dump(mode="json")
    msg_data = {
        "type": "NEW_GROUP_MESSAGE",
        "message": msg_json
    }
    
    sender_name = current_user.username or f"{current_user.address[:8]}..."
    
    for member in channel.members:
        # WebSocket
        await manager.send_personal_message(msg_data, member.user_address)
        
        # Push Notification (Skip sender)
        if member.user_address != current_user.address:
            notify_user_push(
                db,
                member.user_address,
                title=f"Group: {channel.name}",
                body=f"{sender_name}: Sent a secure message",
                data={"type": "group", "channel_id": channel.id}
            )

    return msg


# ── Group Message History ───────────────────────────────────────

@router.post("/{channel_id}/history", response_model=List[schemas.GroupMessageResponse])
@limiter.limit("60/minute")
def get_group_history(
    request: Request,
    channel_id: str,
    req: schemas.GroupHistoryRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Verify membership
    membership = (
        db.query(models.GroupMember)
        .filter(
            models.GroupMember.channel_id == channel_id,
            models.GroupMember.user_address == current_user.address,
        )
        .first()
    )
    if not membership:
        raise HTTPException(status_code=403, detail="Not a member of this group")

    msgs = (
        db.query(models.GroupMessage)
        .options(joinedload(models.GroupMessage.sender))
        .filter(models.GroupMessage.channel_id == channel_id)
        .order_by(models.GroupMessage.created_at.desc())
        .limit(req.limit)
        .offset(req.offset)
        .all()
    )

    return msgs[::-1]  # Return in chronological order


# ── Add Member ──────────────────────────────────────────────────

@router.post("/{channel_id}/members", response_model=schemas.GroupMemberResponse)
@limiter.limit("10/minute")
async def add_member(
    request: Request,
    channel_id: str,
    data: schemas.GroupMemberAdd,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    channel = (
        db.query(models.GroupChannel)
        .options(joinedload(models.GroupChannel.members))
        .filter(models.GroupChannel.id == channel_id)
        .first()
    )
    if not channel:
        raise HTTPException(status_code=404, detail="Group not found")

    # Only owner/admin can add members
    caller_member = next((m for m in channel.members if m.user_address == current_user.address), None)
    if not caller_member or caller_member.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only owners/admins can add members")

    new_addr = data.user_address.lower()

    # Check not already a member
    if any(m.user_address == new_addr for m in channel.members):
        raise HTTPException(status_code=400, detail="User is already a member")

    # Verify user exists and has PQC key
    target_user = db.query(models.User).filter(models.User.address == new_addr).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if not target_user.encryption_public_key or len(target_user.encryption_public_key) < 500:
        raise HTTPException(status_code=400, detail="User is not Messenger-capable (Missing PQC key)")

    if len(channel.members) >= 50:
        raise HTTPException(status_code=400, detail="Maximum 50 members per group")

    new_member = models.GroupMember(
        channel_id=channel_id,
        user_address=new_addr,
        role="member",
    )
    db.add(new_member)
    db.commit()
    db.refresh(new_member)

    # Notify all members
    event = {
        "type": "GROUP_MEMBER_ADDED",
        "channel_id": channel_id,
        "name": channel.name,
        "added_by": current_user.address,
        "new_member": {
            "user_address": new_member.user_address,
            "role": new_member.role,
            "username": target_user.username,
            "joined_at": new_member.joined_at.isoformat(),
            "encryption_public_key": target_user.encryption_public_key
        }
    }
    
    recipients = {m.user_address for m in channel.members} | {new_addr}

    for addr in recipients:
        await manager.send_personal_message(event, addr)

    return new_member


# ── Remove Member / Leave Group ─────────────────────────────────

@router.delete("/{channel_id}/members/{member_address}")
@limiter.limit("10/minute")
async def remove_member(
    request: Request,
    channel_id: str,
    member_address: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    channel = (
        db.query(models.GroupChannel)
        .options(joinedload(models.GroupChannel.members))
        .filter(models.GroupChannel.id == channel_id)
        .first()
    )
    if not channel:
        raise HTTPException(status_code=404, detail="Group not found")

    target_addr = member_address.lower()
    caller_member = next((m for m in channel.members if m.user_address == current_user.address), None)

    if not caller_member:
        raise HTTPException(status_code=403, detail="Not a member of this group")

    target_member = next((m for m in channel.members if m.user_address == target_addr), None)
    if not target_member:
        raise HTTPException(status_code=404, detail="Member not found in group")

    # Permissions: owner can remove anyone, member can remove themselves (leave)
    is_self = target_addr == current_user.address
    if not is_self and caller_member.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only owners/admins can remove members")

    # Handle Owner removal
    if target_member.role == "owner":
        if is_self:
            # Owner leaving -> Delete group (or transfer?)
            # For now, delete group logic or just leave and group becomes ownerless/deleted.
            # Usually strict owner leaving requires transfer. 
            # But here we focus on Admin removing Owner.
            pass 
        else:
            # Admin removing Owner
            if caller_member.role != "admin":
                 raise HTTPException(status_code=403, detail="Only admins can remove the owner")
            
            # Transfer ownership to caller
            caller_member.role = "owner"
            db.add(caller_member)
            
            # Notify about ownership change
            event_owner = {
                "type": "GROUP_MEMBER_UPDATED",
                "channel_id": channel_id,
                "member": {
                    "user_address": caller_member.user_address,
                    "role": "owner",
                    "username": caller_member.user.username,
                    "joined_at": caller_member.joined_at.isoformat()
                }
            }
            # We will broadcast this below
            
            # Proceed to remove the old owner
    
    db.delete(target_member)
    db.commit()

    # Notify remaining members
    remaining = [m.user_address for m in channel.members if m.user_address != target_addr]
    
    # If ownership changed, broadcast that first or with it
    if target_member.role == "owner" and not is_self:
         for addr in remaining:
            await manager.send_personal_message(event_owner, addr)
            # Also update channel owner_address in DB if we had it there?
            # models.GroupChannel has owner_address. We should update it.
    
    # If we are transferring ownership, we MUST update channel.owner_address
    if target_member.role == "owner" and not is_self:
        channel.owner_address = caller_member.user_address
        db.add(channel)
        db.commit()

    event = {
        "type": "GROUP_MEMBER_REMOVED",
        "channel_id": channel_id,
        "removed_address": target_addr,
        "removed_by": current_user.address,
    }
    for addr in remaining:
        await manager.send_personal_message(event, addr)

    # Also notify the removed user
    if not is_self:
        await manager.send_personal_message(event, target_addr)

    return {"status": "ok"}


# ── Update Role ─────────────────────────────────────────────────

@router.put("/{channel_id}/members/{member_address}/role", response_model=schemas.GroupMemberResponse)
@limiter.limit("10/minute")
async def update_member_role(
    request: Request,
    channel_id: str,
    member_address: str,
    data: schemas.GroupMemberRoleUpdate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    channel = (
        db.query(models.GroupChannel)
        .options(joinedload(models.GroupChannel.members).joinedload(models.GroupMember.user))
        .filter(models.GroupChannel.id == channel_id)
        .first()
    )
    if not channel:
        raise HTTPException(status_code=404, detail="Group not found")

    caller_member = next((m for m in channel.members if m.user_address == current_user.address), None)
    if not caller_member or caller_member.role != "owner":
        raise HTTPException(status_code=403, detail="Only the owner can manage roles")

    target_addr = member_address.lower()
    target_member = next((m for m in channel.members if m.user_address == target_addr), None)
    if not target_member:
        raise HTTPException(status_code=404, detail="Member not found")

    if target_member.role == "owner":
        raise HTTPException(status_code=400, detail="Cannot change owner role directly")
    
    new_role = data.role.lower()
    if new_role not in ("admin", "member"):
        raise HTTPException(status_code=400, detail="Invalid role")

    target_member.role = new_role
    db.add(target_member)
    db.commit()
    db.refresh(target_member)

    # Broadcast update
    event = {
        "type": "GROUP_MEMBER_UPDATED",
        "channel_id": channel_id,
        "member": {
            "user_address": target_member.user_address,
            "role": target_member.role,
            "username": target_member.user.username,
            "joined_at": target_member.joined_at.isoformat()
        }
    }
    
    for m in channel.members:
        await manager.send_personal_message(event, m.user_address)

    return target_member


# ── Update Group (Rename) ──────────────────────────────────────

@router.put("/{channel_id}", response_model=schemas.GroupChannelResponse)
@limiter.limit("10/minute")
async def update_group(
    request: Request,
    channel_id: str,
    data: schemas.GroupUpdate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    channel = (
        db.query(models.GroupChannel)
        .options(joinedload(models.GroupChannel.members).joinedload(models.GroupMember.user))
        .filter(models.GroupChannel.id == channel_id)
        .first()
    )
    if not channel:
        raise HTTPException(status_code=404, detail="Group not found")

    caller_member = next((m for m in channel.members if m.user_address == current_user.address), None)
    if not caller_member or caller_member.role != "owner":
        raise HTTPException(status_code=403, detail="Only the owner can rename the group")

    channel.name = data.name.strip()
    db.add(channel)
    db.commit()
    db.refresh(channel)

    # Broadcast update
    event = {
        "type": "GROUP_UPDATED",
        "channel_id": channel_id,
        "name": channel.name
    }
    
    for m in channel.members:
        await manager.send_personal_message(event, m.user_address)

    return channel


# ── Mark Read ───────────────────────────────────────────────────

@router.post("/{channel_id}/mark-read")
def mark_group_read(
    channel_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Verify membership
    membership = (
        db.query(models.GroupMember)
        .filter(
            models.GroupMember.channel_id == channel_id,
            models.GroupMember.user_address == current_user.address,
        )
        .first()
    )
    if not membership:
        raise HTTPException(status_code=403, detail="Not a member of this group")

    # For now, just acknowledge. Full read tracking can be added with a
    # last_read_at timestamp on GroupMember if needed.
    return {"status": "ok"}
