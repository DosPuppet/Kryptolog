"""Group membership events pushed over the WebSocket.

Transport, not policy: security/authorization.succeed_group_owner decides who
inherits a channel, and this tells everyone about it. Split out of
routers/groups.py because account deletion sends the same events for every
group a departing user was in, and a second copy of the ORDER these go out in
would be a second copy of a real rule (see the docstring below).
"""

from utils.clock import to_wire_utc
from websocket_manager import manager


async def broadcast_removal(
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
            # Rendered here rather than by the rule that picked the successor:
            # every datetime leaving this process needs its UTC offset, or a
            # browser parses it as LOCAL time. Hand-built WS payloads are the
            # half of that convention no response model covers.
            "member": {**new_owner_info, "joined_at": to_wire_utc(new_owner_info["joined_at"])},
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
