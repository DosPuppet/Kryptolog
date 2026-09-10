import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

import models
import schemas
from database import get_db
from dependencies import get_current_user, limiter
from security import authorization
from security.crypto_validation import is_usable_encryption_key
from utils.push import display_name, notify_many_push_async
from websocket_manager import manager

router = APIRouter(prefix="/groups", tags=["groups"])

# Page size for GET /groups (audit O-3). A channel row drags in its whole
# member list (up to 50, each with its user) plus the last message, so an
# account in many groups produced a response nobody bounded. Bounded at both
# ends by FastAPI, matching GET /users.
GROUP_PAGE_MAX = 100
GROUP_PAGE_DEFAULT = 50


def _load_channel_or_404(
    db: Session, channel_id: str, *, with_users: bool = False
) -> models.GroupChannel:
    """Load a channel with its members, or raise 404.

    Six endpoints spelled this out. `with_users` additionally eager-loads each
    member's user row and is not cosmetic: the endpoints that broadcast a
    member's username would otherwise lazy-load one user per member.
    """
    members = joinedload(models.GroupChannel.members)
    if with_users:
        members = members.joinedload(models.GroupMember.user)

    channel = (
        db.query(models.GroupChannel)
        .options(members)
        .filter(models.GroupChannel.id == channel_id)
        .first()
    )
    if not channel:
        raise HTTPException(status_code=404, detail="Group not found")
    return channel


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

    member_addrs = list({addr.lower() for addr in data.member_addresses})
    if current_user.address not in member_addrs:
        member_addrs.append(current_user.address)

    users = db.query(models.User).filter(models.User.address.in_(member_addrs)).all()
    found_addrs = {u.address for u in users}
    missing = set(member_addrs) - found_addrs
    if missing:
        # Generic on purpose (audit L-6): naming the addresses that were not
        # found turns group creation into an account-existence oracle — probe
        # with a candidate address, read whether it came back. /auth/login is
        # already generic for the same reason.
        raise HTTPException(status_code=404, detail="One or more users could not be found")

    # Validate all members have PQC keys (Messenger requirement)
    for u in users:
        if not is_usable_encryption_key(u.encryption_public_key):
            raise HTTPException(
                status_code=400,
                detail=f"User {u.address} is not Messenger-capable (Missing PQC key)",
            )

    channel_id = str(uuid.uuid4())
    channel = models.GroupChannel(
        id=channel_id,
        name=data.name.strip(),
        owner_address=current_user.address,
    )
    db.add(channel)

    for addr in member_addrs:
        role = "owner" if addr == current_user.address else "member"
        db.add(
            models.GroupMember(
                channel_id=channel_id,
                user_address=addr,
                role=role,
            )
        )

    db.commit()
    db.refresh(channel)

    for addr in member_addrs:
        if addr != current_user.address:
            await manager.send_personal_message(
                {
                    "type": "GROUP_JOINED",
                    "channel": schemas.GroupChannelResponse.model_validate(channel),
                },
                addr,
            )

    # Push fan-out AFTER the WebSocket sends, in one off-loop hop: pushes are
    # blocking network calls, so doing them inline here would stall every other
    # request on this worker for the whole broadcast. Generic body: channel
    # names are E2EE blobs the server can't read (audit M-3) — and MUST not try
    # to display.
    await notify_many_push_async(
        db,
        [
            (
                addr,
                "New Group",
                "You have been added to a new group",
                {"type": "group_joined", "channel_id": channel.id},
            )
            for addr in member_addrs
            if addr != current_user.address
        ],
    )

    return channel


# ── List My Groups ──────────────────────────────────────────────


@router.get("", response_model=list[schemas.GroupConversationResponse])
@limiter.limit("30/minute")
def list_groups(
    request: Request,
    limit: int = Query(GROUP_PAGE_DEFAULT, ge=1, le=GROUP_PAGE_MAX),
    offset: int = Query(0, ge=0),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Most-recent-activity order and the page boundary are decided in SQL
    # (audit O-3): sorting the rows in Python after loading them would only
    # sort whichever arbitrary rows the page happened to contain.
    #
    # GroupMessage.id is autoincrement, so max(id) per channel is that
    # channel's latest message; max(created_at) alongside it is what the order
    # is actually about. A channel with no messages falls back to its own
    # created_at, which is what the previous Python sort did.
    my_channels = authorization.member_channel_ids(db, current_user.address)
    latest = (
        db.query(
            models.GroupMessage.channel_id.label("channel_id"),
            func.max(models.GroupMessage.id).label("last_id"),
            func.max(models.GroupMessage.created_at).label("last_at"),
        )
        # Scoped to this user's channels, not aggregated over every group
        # message in the system: the outer filter cannot be relied on to be
        # pushed into the aggregate, and a listing whose cost is set by other
        # people's traffic is the defect L-7 was about.
        .filter(models.GroupMessage.channel_id.in_(my_channels))
        .group_by(models.GroupMessage.channel_id)
        .subquery()
    )
    activity = func.coalesce(latest.c.last_at, models.GroupChannel.created_at)

    # Paged as bare ids first. Eager-loading the members here instead would put
    # LIMIT on the joined member rows rather than on the channels.
    page = (
        db.query(models.GroupChannel.id, latest.c.last_id)
        .outerjoin(latest, latest.c.channel_id == models.GroupChannel.id)
        .filter(models.GroupChannel.id.in_(my_channels))
        .order_by(activity.desc(), models.GroupChannel.id)
        .limit(limit)
        .offset(offset)
        .all()
    )

    channel_ids = [row[0] for row in page]
    if not channel_ids:
        return []

    channels = {
        ch.id: ch
        for ch in db.query(models.GroupChannel)
        .options(joinedload(models.GroupChannel.members).joinedload(models.GroupMember.user))
        .filter(models.GroupChannel.id.in_(channel_ids))
        .all()
    }

    # The page's last messages with their senders, in one query (was N+1).
    last_message_ids = [row[1] for row in page if row[1] is not None]
    latest_by_channel = {}
    if last_message_ids:
        latest_by_channel = {
            m.channel_id: m
            for m in db.query(models.GroupMessage)
            .options(joinedload(models.GroupMessage.sender))
            .filter(models.GroupMessage.id.in_(last_message_ids))
            .all()
        }

    return [
        {
            "channel": channels[cid],
            "last_message": latest_by_channel.get(cid),
            # Groups have no per-user read tracking yet (it would be a
            # last_read_at on GroupMember). Left at 0 until that ships.
            "unread_count": 0,
        }
        for cid in channel_ids
        if cid in channels
    ]


# ── Get Group Details ───────────────────────────────────────────


@router.get("/{channel_id}", response_model=schemas.GroupChannelResponse)
@limiter.limit("30/minute")
def get_group(
    request: Request,
    channel_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    channel = _load_channel_or_404(db, channel_id, with_users=True)

    if not authorization.is_group_member(db, channel_id, current_user.address):
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
    channel = _load_channel_or_404(db, channel_id)

    if not authorization.is_group_member(db, channel_id, current_user.address):
        raise HTTPException(status_code=403, detail="Not a member of this group")

    msg = models.GroupMessage(
        channel_id=channel_id,
        sender_address=current_user.address,
        content=data.content,
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    msg_json = schemas.GroupMessageResponse.model_validate(msg).model_dump(mode="json")
    msg_data = {"type": "NEW_GROUP_MESSAGE", "message": msg_json}

    sender_name = display_name(current_user)

    for member in channel.members:
        await manager.send_personal_message(msg_data, member.user_address)

    # Push fan-out AFTER the WebSocket sends, in one off-loop hop. Inline this
    # would be up to 50 blocking HTTPS requests on the event loop per message,
    # freezing the whole worker. Generic title: the channel name is an E2EE
    # blob (audit M-3).
    await notify_many_push_async(
        db,
        [
            (
                member.user_address,
                "Group message",
                f"{sender_name}: Sent a secure message",
                {"type": "group", "channel_id": channel.id},
            )
            for member in channel.members
            if member.user_address != current_user.address
        ],
    )

    return msg


# ── Group Message History ───────────────────────────────────────


@router.post("/{channel_id}/history", response_model=list[schemas.GroupMessageResponse])
@limiter.limit("60/minute")
def get_group_history(
    request: Request,
    channel_id: str,
    req: schemas.GroupHistoryRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not authorization.is_group_member(db, channel_id, current_user.address):
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
    channel = _load_channel_or_404(db, channel_id)

    caller_member = authorization.find_group_member(db, channel_id, current_user.address)
    if not authorization.can_administer_group(caller_member):
        raise HTTPException(status_code=403, detail="Only owners/admins can add members")

    new_addr = data.user_address.lower()

    if authorization.is_group_member(db, channel_id, new_addr):
        raise HTTPException(status_code=400, detail="User is already a member")

    target_user = db.query(models.User).filter(models.User.address == new_addr).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    if not is_usable_encryption_key(target_user.encryption_public_key):
        raise HTTPException(
            status_code=400, detail="User is not Messenger-capable (Missing PQC key)"
        )

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
            "encryption_public_key": target_user.encryption_public_key,
        },
    }

    recipients = {m.user_address for m in channel.members} | {new_addr}

    for addr in recipients:
        await manager.send_personal_message(event, addr)

    return new_member


def _succeed_owner(db, channel, caller_member, remaining, is_self):
    """Hand the group over when its owner leaves, or tear it down.

    A channel with no owner is unadministrable (the Q-1 bug), so the departure
    of an owner must always end with either a new owner or no channel.
    Successor order: the admin doing the removing, else any existing admin,
    else the earliest-joined remaining member.

    Returns (new_owner_info, group_deleted). The dict is built here, while the
    rows are still live, because reading attributes off a deleted or expired
    instance afterwards is the Q-2 bug.
    """
    if not remaining:
        # Cascades to members and messages.
        db.delete(channel)
        return None, True

    if not is_self and caller_member.role == "admin":
        successor = caller_member
    else:
        successor = next((m for m in remaining if m.role == "admin"), None) or min(
            remaining, key=lambda m: m.joined_at
        )

    successor.role = "owner"
    channel.owner_address = successor.user_address
    db.add(successor)
    db.add(channel)
    return {
        "user_address": successor.user_address,
        "role": "owner",
        "username": successor.user.username if successor.user else None,
        "joined_at": successor.joined_at.isoformat(),
    }, False


async def _broadcast_removal(
    channel_id, target_addr, removed_by, remaining_addrs, new_owner_info, is_self
):
    """Tell the group who left, and who owns it now.

    Ownership first: a client that applies the removal before the succession
    briefly renders an ownerless group.
    """
    if new_owner_info:
        owner_event = {
            "type": "GROUP_MEMBER_UPDATED",
            "channel_id": channel_id,
            "member": new_owner_info,
        }
        for addr in remaining_addrs:
            await manager.send_personal_message(owner_event, addr)

    event = {
        "type": "GROUP_MEMBER_REMOVED",
        "channel_id": channel_id,
        "removed_address": target_addr,
        "removed_by": removed_by,
    }
    for addr in remaining_addrs:
        await manager.send_personal_message(event, addr)

    # The removed user also needs to know, unless they did it themselves.
    if not is_self:
        await manager.send_personal_message(event, target_addr)


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
    """Remove a member, or leave the group yourself.

    If the departing member is the owner, the group is handed to a successor or
    deleted outright; it is never left ownerless.
    """
    channel = _load_channel_or_404(db, channel_id, with_users=True)

    target_addr = member_address.lower()
    caller_member = authorization.find_group_member(db, channel_id, current_user.address)
    if not caller_member:
        raise HTTPException(status_code=403, detail="Not a member of this group")

    target_member = authorization.find_group_member(db, channel_id, target_addr)
    if not target_member:
        raise HTTPException(status_code=404, detail="Member not found in group")

    is_self = target_addr == current_user.address
    if not authorization.can_remove_group_member(caller_member, target_addr):
        raise HTTPException(status_code=403, detail="Only owners/admins can remove members")

    # Capture everything needed BEFORE any delete or commit — reading attributes
    # off a deleted/expired instance afterwards is the Q-2 bug.
    target_was_owner = target_member.role == "owner"
    remaining = [m for m in channel.members if m.user_address != target_addr]
    remaining_addrs = [m.user_address for m in remaining]

    new_owner_info, group_deleted = None, False
    if target_was_owner:
        new_owner_info, group_deleted = _succeed_owner(
            db, channel, caller_member, remaining, is_self
        )

    if not group_deleted:
        # Delete by predicate, not by instance: `target_member` is only the FIRST
        # matching row, so removing the instance left any duplicate behind and the
        # "removed" member kept access (audit M-1). The unique constraint added in
        # migration e5f6a7b8c9d4 makes duplicates impossible going forward; this
        # stays a bulk delete so the removal is correct regardless.
        db.query(models.GroupMember).filter(
            models.GroupMember.channel_id == channel_id,
            models.GroupMember.user_address == target_addr,
        ).delete(synchronize_session="fetch")
    db.commit()

    # If the group is gone there is no one left to notify.
    if group_deleted:
        return {"status": "ok", "group_deleted": True}

    await _broadcast_removal(
        channel_id, target_addr, current_user.address, remaining_addrs, new_owner_info, is_self
    )
    return {"status": "ok"}


# ── Update Role ─────────────────────────────────────────────────


@router.put(
    "/{channel_id}/members/{member_address}/role", response_model=schemas.GroupMemberResponse
)
@limiter.limit("10/minute")
async def update_member_role(
    request: Request,
    channel_id: str,
    member_address: str,
    data: schemas.GroupMemberRoleUpdate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    channel = _load_channel_or_404(db, channel_id, with_users=True)

    caller_member = authorization.find_group_member(db, channel_id, current_user.address)
    if not authorization.can_manage_group_roles(caller_member):
        raise HTTPException(status_code=403, detail="Only the owner can manage roles")

    target_addr = member_address.lower()
    target_member = authorization.find_group_member(db, channel_id, target_addr)
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

    event = {
        "type": "GROUP_MEMBER_UPDATED",
        "channel_id": channel_id,
        "member": {
            "user_address": target_member.user_address,
            "role": target_member.role,
            "username": target_member.user.username,
            "joined_at": target_member.joined_at.isoformat(),
        },
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
    channel = _load_channel_or_404(db, channel_id, with_users=True)

    # Owner/admin, not owner-only — see can_administer_group for why (audit M-3).
    caller_member = authorization.find_group_member(db, channel_id, current_user.address)
    if not authorization.can_administer_group(caller_member):
        raise HTTPException(status_code=403, detail="Only owners/admins can rename the group")

    channel.name = data.name.strip()
    db.add(channel)
    db.commit()
    db.refresh(channel)

    event = {"type": "GROUP_UPDATED", "channel_id": channel_id, "name": channel.name}

    for m in channel.members:
        await manager.send_personal_message(event, m.user_address)

    return channel


# ── Mark Read ───────────────────────────────────────────────────


@router.post("/{channel_id}/mark-read")
@limiter.limit("60/minute")
def mark_group_read(
    request: Request,
    channel_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not authorization.is_group_member(db, channel_id, current_user.address):
        raise HTTPException(status_code=403, detail="Not a member of this group")

    # For now, just acknowledge. Full read tracking can be added with a
    # last_read_at timestamp on GroupMember if needed.
    return {"status": "ok"}
