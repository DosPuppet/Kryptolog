import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

import models
import schemas
from database import get_db
from dependencies import get_current_user, limiter
from security import authorization
from security.audit_log import audit_event, short
from security.crypto_validation import is_usable_encryption_key
from utils.clock import to_wire_utc
from utils.group_events import broadcast_removal
from utils.push import display_name, schedule_pushes
from websocket_manager import manager

router = APIRouter(prefix="/groups", tags=["groups"])

# Page size for GET /groups (audit O-3). A channel row drags in its whole
# member list (up to MAX_GROUP_MEMBERS, each with its user) plus the last
# message, so an account in many groups produced a response nobody bounded.
# Bounded at both ends by FastAPI, matching GET /users.
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
def create_group(
    request: Request,
    background_tasks: BackgroundTasks,
    data: schemas.GroupChannelCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a group with the caller as owner. At most MAX_GROUP_MEMBERS members,
    the creator included. The name is an encrypted blob only members can read.
    """
    member_addrs = list({addr.lower() for addr in data.member_addresses})
    if current_user.address not in member_addrs:
        member_addrs.append(current_user.address)

    # Counted AFTER deduplication and after adding the creator: the members the
    # group will actually have. Checked on the submitted list, 50 others plus
    # the creator made a group of 51 (audit 2026-09-23 F-6) — one that
    # add_member would then refuse to grow and MAX_GROUP_NAME_LEN, sized for 50
    # wraps, could not hold a renamed name for.
    if len(member_addrs) > schemas.MAX_GROUP_MEMBERS:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum {schemas.MAX_GROUP_MEMBERS} members per group",
        )

    users = authorization.active_users(db).filter(models.User.address.in_(member_addrs)).all()
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
    audit_event(
        "group.create",
        request=request,
        actor=current_user.address,
        channel_id=channel_id,
        members=[short(a) for a in member_addrs],
    )

    # JSON-ready, not the model (audit 2026-09-23 Q-1).
    joined = {
        "type": "GROUP_JOINED",
        "channel": schemas.GroupChannelResponse.model_validate(channel).model_dump(mode="json"),
    }
    background_tasks.add_task(
        manager.send_many,
        [(joined, addr) for addr in member_addrs if addr != current_user.address],
    )

    # Queued, not sent here (audit 2026-09-23 M-1, utils/push.py). Generic
    # body: channel names are E2EE blobs the server can't read (audit M-3) —
    # and MUST not try to display.
    schedule_pushes(
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
    """The caller's groups, most recently active first (paged), each with its last
    message and unread count.
    """
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
            # Groups have no per-user read tracking: it would need a
            # last_read_at on GroupMember, which does not exist. Always 0, and
            # the SPA does not render a group unread badge because of it.
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
    """One group and its members. Members only."""
    channel = _load_channel_or_404(db, channel_id, with_users=True)

    if not authorization.is_group_member(db, channel_id, current_user.address):
        raise HTTPException(status_code=403, detail="Not a member of this group")

    return channel


# ── Send Group Message ──────────────────────────────────────────


@router.post("/{channel_id}/messages", response_model=schemas.GroupMessageResponse)
@limiter.limit("20/minute")
def send_group_message(
    request: Request,
    background_tasks: BackgroundTasks,
    channel_id: str,
    data: schemas.GroupMessageCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Post an end-to-end encrypted message to a group. Members only. Relayed to
    every member over the WebSocket, and by push to those not in the app.
    """
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

    background_tasks.add_task(
        manager.send_many, [(msg_data, member.user_address) for member in channel.members]
    )

    # Queued, not sent here (audit 2026-09-23 M-1): inline this was up to 50
    # members' pushes inside the sender's request. Generic title: the channel
    # name is an E2EE blob (audit M-3).
    schedule_pushes(
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
    """A group's messages, oldest first, paged from the newest. Members only."""
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
def add_member(
    request: Request,
    background_tasks: BackgroundTasks,
    channel_id: str,
    data: schemas.GroupMemberAdd,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Add a user to a group. Owner or admin. The caller re-wraps the group name
    for the new member separately (`PUT /groups/{id}`).
    """
    channel = _load_channel_or_404(db, channel_id)

    caller_member = authorization.find_group_member(db, channel_id, current_user.address)
    if not authorization.can_administer_group(caller_member):
        raise HTTPException(status_code=403, detail="Only owners/admins can add members")

    new_addr = data.user_address.lower()

    if authorization.is_group_member(db, channel_id, new_addr):
        raise HTTPException(status_code=400, detail="User is already a member")

    target_user = authorization.find_active_user(db, new_addr)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    if not is_usable_encryption_key(target_user.encryption_public_key):
        raise HTTPException(
            status_code=400, detail="User is not Messenger-capable (Missing PQC key)"
        )

    if len(channel.members) >= schemas.MAX_GROUP_MEMBERS:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum {schemas.MAX_GROUP_MEMBERS} members per group",
        )

    new_member = models.GroupMember(
        channel_id=channel_id,
        user_address=new_addr,
        role="member",
    )
    db.add(new_member)
    db.commit()
    db.refresh(new_member)
    audit_event(
        "group.member_add",
        request=request,
        actor=current_user.address,
        channel_id=channel_id,
        member=short(new_addr),
    )

    event = {
        "type": "GROUP_MEMBER_ADDED",
        "channel_id": channel_id,
        "name": channel.name,
        "added_by": current_user.address,
        "new_member": {
            "user_address": new_member.user_address,
            "role": new_member.role,
            "username": target_user.username,
            "joined_at": to_wire_utc(new_member.joined_at),
            "encryption_public_key": target_user.encryption_public_key,
        },
    }

    recipients = {m.user_address for m in channel.members} | {new_addr}

    background_tasks.add_task(manager.send_many, [(event, addr) for addr in recipients])

    return new_member


# ── Remove Member / Leave Group ─────────────────────────────────


@router.delete("/{channel_id}/members/{member_address}")
@limiter.limit("10/minute")
def remove_member(
    request: Request,
    background_tasks: BackgroundTasks,
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
    if not authorization.can_remove_group_member(caller_member, target_member):
        raise HTTPException(
            status_code=403,
            detail="Only the owner removes admins or the owner; admins remove members",
        )

    # Capture everything needed BEFORE any delete or commit — reading attributes
    # off a deleted/expired instance afterwards is the Q-2 bug.
    target_was_owner = target_member.role == "owner"
    remaining = [m for m in channel.members if m.user_address != target_addr]
    remaining_addrs = [m.user_address for m in remaining]

    new_owner_info, group_deleted = None, False
    if target_was_owner:
        new_owner_info, group_deleted = authorization.succeed_group_owner(db, channel, remaining)

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
    audit_event(
        "group.member_remove",
        request=request,
        actor=current_user.address,
        channel_id=channel_id,
        member=short(target_addr),
        left=is_self,
        group_deleted=group_deleted,
    )

    # If the group is gone there is no one left to notify.
    if group_deleted:
        return {"status": "ok", "group_deleted": True}

    background_tasks.add_task(
        broadcast_removal,
        channel_id,
        target_addr,
        current_user.address,
        remaining_addrs,
        new_owner_info,
        is_self,
    )
    return {"status": "ok"}


# ── Update Role ─────────────────────────────────────────────────


@router.put(
    "/{channel_id}/members/{member_address}/role", response_model=schemas.GroupMemberResponse
)
@limiter.limit("10/minute")
def update_member_role(
    request: Request,
    background_tasks: BackgroundTasks,
    channel_id: str,
    member_address: str,
    data: schemas.GroupMemberRoleUpdate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Make a member an admin or demote them. Owner only; the owner's own role
    cannot be changed here.
    """
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
    audit_event(
        "group.role_change",
        request=request,
        actor=current_user.address,
        channel_id=channel_id,
        member=short(member_address),
        role=new_role,
    )

    event = {
        "type": "GROUP_MEMBER_UPDATED",
        "channel_id": channel_id,
        "member": {
            "user_address": target_member.user_address,
            "role": target_member.role,
            "username": target_member.user.username,
            "joined_at": to_wire_utc(target_member.joined_at),
        },
    }

    background_tasks.add_task(manager.send_many, [(event, m.user_address) for m in channel.members])

    return target_member


# ── Update Group (Rename) ──────────────────────────────────────


@router.put("/{channel_id}", response_model=schemas.GroupChannelResponse)
@limiter.limit("10/minute")
def update_group(
    request: Request,
    background_tasks: BackgroundTasks,
    channel_id: str,
    data: schemas.GroupUpdate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Replace a group's encrypted name — also how a name is re-wrapped after the
    member set changes. Owner or admin.
    """
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

    background_tasks.add_task(manager.send_many, [(event, m.user_address) for m in channel.members])

    return channel
