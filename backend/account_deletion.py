"""Deleting an account, in two modes.

**leave** — the identity disappears (not in the directory, cannot log in, shows
as "user removed" everywhere) and every row stays exactly where it is. Undone
by logging in again with the same vault.

**erase** — the identity's content goes too, and the key may never register
again.

Neither mode removes the `users` row; both strip it. See `models.User` for why.

What erase deliberately does NOT delete, and why each is someone else's
property rather than the departing user's:

* **Messages carrying a key envelope are redacted, not deleted.** A DM session
  key is wrapped for both sides and embedded in the FIRST message under that
  sid, and the partner's own replies reuse that sid with `keys: null`. Deleting
  the opener takes the partner's *own authored history* with it, silently, on
  their next reload. Redaction keeps `keys` and drops `ct`, under a signature
  the author produced for exactly that form.

  Group messages are redacted the same way even though groups never adopt a
  send key from inbound history (audit O-1, so a group sid only ever covers its
  own minter's messages and deleting them would be safe). One rule is worth
  more than the saving, and a thread that says "content removed" reads better
  than one that silently loses lines.

* **Signer rows on other people's workflows stay**, signed or not. Removing a
  signer without touching `threshold` leaves a quorum that can never be met;
  removing it *with* a threshold reduction is the multisig equivalent of
  forging consent. A signature already given is the workflow owner's evidence.

* **Completed workflows the user owns stay whole**, because
  `authorization.workflow_is_deletable` already refuses to delete them: the
  recipients' `encrypted_key` rows are their only copy. Account deletion must
  not become a way to retract a release after the fact — a power the API denies
  while the owner is alive.

* **Messages the user only received stay.** They are the partner's own speech.

The irreducible residue: other members' messages carry `keys[<address>]`,
ML-KEM envelopes wrapped to the departing user, inside their own signed
payloads. Stripping those would break *their* signatures for everyone. That is
the honest limit of "delete my data" in an end-to-end encrypted system, and the
confirmation UI says so.
"""

import json

from sqlalchemy.orm import Session, joinedload

import auth
import models
from security import authorization
from utils.clock import utcnow_naive

MODE_LEAVE = "leave"
MODE_ERASE = "erase"
MODES = (MODE_LEAVE, MODE_ERASE)

# The two message kinds, and the model each lives in. DMs and group messages
# have independent id sequences, so every id that leaves this module is
# namespaced — see `redaction_key`.
_KINDS = {"dm": models.Message, "group": models.GroupMessage}

# Rows fetched per round trip while walking a user's messages. Only the walk's
# memory footprint, not a page size anyone sees.
_STREAM_ROWS = 200


def redaction_key(kind: str, message_id: int) -> str:
    """The id under which one message is named in a signed deletion request.

    Namespaced because `messages.id` and `group_messages.id` are separate
    sequences: a bare 412 names two different rows, and the signed set exists
    precisely so a relay cannot drop one entry and turn a redaction into a
    deletion.
    """
    return f"{kind}:{message_id}"


def _payload(content) -> dict | None:
    """Parse a stored message payload, or None if it is not one.

    A row this cannot read is never deleted by an erase — see
    `_delete_own_messages`, and `kept_messages` for how it is reported.
    Fail safe: nothing in the current wire format hides a key envelope outside
    JSON, but the cost of being wrong is asymmetric. Leaving one of the
    departing user's own messages behind is visible and annoying; destroying
    the only copy of a session key is silent and unrecoverable for everyone
    else in that conversation.
    """
    try:
        parsed = json.loads(content)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _conv_and_gid(kind: str, row) -> tuple[str, str]:
    """The conversation this message was DELIVERED under, per audit F-1.

    Always derived from the row, never from the payload: `conv` is the message
    signature's binding to a conversation, and taking it from content a caller
    supplied would let a signature be re-homed. DMs bind to the recipient
    address, groups to the channel id — the same rule the client applies in
    `verifyMessage.js`.
    """
    if kind == "dm":
        return (row.recipient_address or "").lower(), ""
    return row.channel_id or "", row.channel_id or ""


def _is_signable(payload: dict) -> bool:
    """Can the author be asked for a signature over this message's redacted form?

    Two shapes cannot be, and both are KEPT rather than deleted — the same
    fail-safe `_payload` applies to a row that does not parse at all:

    * **No `sid`.** The signed body interpolates it, and a missing one spells
      `sid=None` in Python against `sid=null` in JS: a silent byte divergence
      inside a SIGNATURE body, which is the exact class of defect the shared
      fixture exists to catch. Such a row is not a session carrier anyway — the
      key cache is addressed by (conversation, sid), so no client can ever
      adopt from it (`useMessageSessions` requires `parsed.sid`).
    * **An envelope the Python mirror will not hash.** `check_envelope_shape`
      refuses anything the two languages would not spell identically, so asking
      for a signature over a digest this side cannot reproduce would only
      produce one it then rejects.

    Neither is reachable through the shipped clients; both are reachable by
    hand-posting a message. Before this, ONE such row — of the user's own
    making — refused the entire erase, permanently, with no way to complete it
    and nothing saying which row was to blame (audit 2026-09-12 M-2b/M-2c).
    """
    if not isinstance(payload.get("sid"), str) or not payload["sid"]:
        return False
    try:
        auth.check_envelope_shape(payload["keys"])
    except auth.NonCanonicalKeyEnvelope:
        return False
    return True


def _envelope_carriers(db: Session, address: str):
    """Every message the user sent still holding BOTH a wrapped session key and
    its ciphertext — everything an erase has left to deal with.

    `ct is not None` is what makes an erase resumable across requests: a
    redacted row KEEPS its envelope (that is the whole point of redacting
    rather than deleting), so testing `keys` alone would list it again on the
    next round and the loop would never end.

    Ordered by id so the manifest pages deterministically, and STREAMED: an
    account with tens of thousands of messages should not have all of them in
    memory to answer for a hundred (audit 2026-09-12 I-2).
    """
    for kind, model in _KINDS.items():
        rows = (
            db.query(model)
            .filter(model.sender_address == address)
            .order_by(model.id)
            .yield_per(_STREAM_ROWS)
        )
        for row in rows:
            payload = _payload(row.content)
            if payload is None or not payload.get("keys") or payload.get("ct") is None:
                continue
            yield kind, row, payload


def redactable_messages(db: Session, address: str, *, limit: int, offset: int) -> list[dict]:
    """One page of the manifest: what the client has to re-sign before an erase.

    Carries everything needed to rebuild the signed body and nothing the client
    gets to choose — `conv` and `gid` come from the row.

    Paged HERE rather than by slicing a finished list. Which rows qualify is a
    question about the parsed payload, so it cannot be asked in SQL, and the
    whole set therefore used to be rebuilt — every message parsed, every key map
    materialised — to answer for a hundred rows. A round reads ten pages, so
    that was ten full passes, and the first page of a large account cost as much
    as the last (audit 2026-09-12 I-2). Stopping at the page makes a page cost
    what precedes it instead of what exists.
    """
    manifest = []
    seen = 0
    for kind, row, payload in _envelope_carriers(db, address):
        if not _is_signable(payload):
            continue
        seen += 1
        if seen <= offset:
            continue
        conv, gid = _conv_and_gid(kind, row)
        manifest.append(
            {
                "id": row.id,
                "kind": kind,
                "key": redaction_key(kind, row.id),
                "conv": conv,
                "gid": gid,
                "sid": payload.get("sid"),
                "keys": payload["keys"],
            }
        )
        if len(manifest) >= limit:
            break
    return manifest


def redaction_keys(db: Session, address: str) -> set[str]:
    """The same set as `redactable_messages`, as ids only.

    Recomputed inside the deletion transaction, and an erase only COMPLETES
    when it is empty. That is a fixed point rather than an equality check
    against the signed set, and the difference is what makes a large account
    erasable at all: one request carries at most
    `schemas.MAX_REDACTIONS_PER_DELETE` signatures, so an account holding more
    carriers than that simply takes another round (audit 2026-09-12 M-2a).

    It still closes the same gap the equality check did — a message sent
    between reading the manifest and committing must not be DELETED rather than
    redacted, since if it opened an epoch the partner loses their own history.
    Now it cannot be: it is a carrier, `_delete_own_messages` only ever deletes
    NON-carriers, and its presence here keeps the deletion from finishing until
    the client has redacted it too.
    """
    return {
        redaction_key(kind, row.id)
        for kind, row, payload in _envelope_carriers(db, address)
        if _is_signable(payload)
    }


def kept_messages(db: Session, address: str) -> int:
    """How many of the user's own messages an erase leaves holding their content.

    Always zero for a message any shipped client wrote. Non-zero means a row
    this module refuses to guess at — one that does not parse, or one
    `_is_signable` rejects — and refusing to guess is the right call in both
    cases. Reported back to the caller because "delete my content" quietly
    meaning "most of it" is the kind of promise a deletion feature must not
    break silently (audit 2026-09-12, I-7).
    """
    kept = 0
    for _kind, model in _KINDS.items():
        for row in db.query(model).filter(model.sender_address == address).all():
            payload = _payload(row.content)
            if payload is None:
                kept += 1
            elif (
                payload.get("keys") and payload.get("ct") is not None and not _is_signable(payload)
            ):
                kept += 1
    return kept


class RedactionRefused(ValueError):
    """A redaction the server will not store. Never partially applied."""


def _redacted_content(kind: str, payload: dict, signature: str, gid: str = "") -> str:
    """Build the stored payload for a redacted message.

    Everything but the ciphertext is copied from the row the server already
    holds, so a redaction CANNOT rewrite the key envelope, the session id or
    the group binding — that would be audit M-8's targeted-exclusion attack
    executed with a valid signature. The client supplies one thing: a signature
    over the form the server built.

    `gid` is the group id as SIGNED, which is not always the one the payload
    declared: the verification below falls back to the delivered channel when a
    payload carries none. Storing the payload's own value would leave a message
    whose stored gid and signed gid disagree, so every reader would rebuild the
    wrong bytes and show an author-signed redaction as an invalid signature —
    the F-2 "suspicious" badge, on the one message that most needs to read as
    deliberate (audit 2026-09-12 I-5).
    """
    content = {
        "v": payload.get("v"),
        "sid": payload.get("sid"),
        "keys": payload["keys"],
        "ct": None,
        "sig": signature,
    }
    if kind == "group":
        content["gid"] = gid
    return json.dumps(content)


def _redactable_row(db: Session, address: str, key: str):
    """The row one signed redaction names, refusing anything it may not touch.

    Looked up from the SUBMITTED key rather than walked from the server's own
    list, because a round carries only part of that list now. Ownership is
    re-attested here rather than trusted from the manifest the client read.

    "No such message" and "not yours" answer identically, so this cannot be
    used to probe which message ids exist.
    """
    kind, separator, raw_id = key.partition(":")
    model = _KINDS.get(kind)
    if not separator or model is None or not raw_id.isdigit():
        raise RedactionRefused(f"{key} is not a message id")

    row = db.query(model).filter(model.id == int(raw_id), model.sender_address == address).first()
    if row is None:
        raise RedactionRefused(f"{key} is not one of your messages")

    payload = _payload(row.content)
    if (
        payload is None
        or not payload.get("keys")
        or payload.get("ct") is None
        or not _is_signable(payload)
    ):
        # Already redacted, never a carrier, or a shape no signature can cover.
        raise RedactionRefused(f"{key} is not a message this erase can redact")
    return kind, row, payload


def _verified_redactions(db: Session, address: str, signatures: dict[str, str]) -> list:
    """Verify every redaction in this round before applying any of them.

    All-or-nothing within the round on purpose: verifying and applying one at a
    time would leave an account half-erased when the tenth signature is bad,
    with no way for the caller to tell which half. Rounds themselves are safe
    to interrupt — each one only ever turns carriers into redacted carriers,
    and the erase does not complete until none are left.
    """
    pending = []
    for key in sorted(signatures):
        signature = signatures[key]
        kind, row, payload = _redactable_row(db, address, key)

        conv, gid = _conv_and_gid(kind, row)
        if kind == "group" and payload.get("gid") and payload["gid"] != row.channel_id:
            # The payload's self-declared group disagrees with the channel it
            # was delivered under — the same refusal verifyMessage.js makes.
            raise RedactionRefused(f"{key} declares a group it was not delivered under")

        # The gid the signature covers, and therefore the one to store: the
        # payload's own when it declares one, the delivered channel otherwise.
        signed_gid = (payload.get("gid") or gid) if kind == "group" else ""
        try:
            body = auth.message_signing_body(
                from_=address,
                conv=conv,
                gid=signed_gid,
                sid=payload.get("sid"),
                ct=None,
                keys=payload["keys"],
            )
        except auth.NonCanonicalSignedBody as exc:
            # Unreachable through `_redactable_row`, which asks `_is_signable`
            # the same questions. Kept because the two live in different
            # modules: this one must fail closed whatever that one lets past.
            raise RedactionRefused(f"{key} cannot be signed for redaction: {exc}") from exc

        if not auth.verify_message_signature(address, body, signature):
            raise RedactionRefused(f"invalid redaction signature for {key}")

        pending.append((kind, row, _redacted_content(kind, payload, signature, signed_gid)))
    return pending


def apply_redactions(db: Session, address: str, signatures: dict[str, str]) -> int:
    """Apply ONE round of author-signed redactions. Returns how many landed.

    Separate from `delete_account` because an erase is now resumable: a round
    carries at most `schemas.MAX_REDACTIONS_PER_DELETE` signatures, and an
    account with more carriers than that takes several. Each round is
    individually authorized by the popup-gated deletion signature covering
    exactly the keys it carries — which is why this is NOT an endpoint of its
    own. A bare "redact my messages" route would be reachable by any site
    holding a silent-signing grant in the extension, since a redaction body is
    `message`-context and auto-signed; the deletion signature is not.
    """
    pending = _verified_redactions(db, address, signatures)
    for _kind, row, content in pending:
        row.content = content
        db.add(row)
    # autoflush is off, so `redaction_keys` would otherwise recount the rows
    # this round just redacted and the erase could never reach its fixed point.
    db.flush()
    return len(pending)


def _delete_own_messages(db: Session, address: str) -> None:
    """Delete the user's messages that carry nobody else's session key.

    Every carrier has been redacted by `apply_redactions` before this runs —
    the caller does not get here while `redaction_keys` is non-empty.

    Deletes only what is PROVABLY safe to delete: a payload that parses and
    carries no key envelope. Anything this cannot read is left alone — see
    `_payload` — so the deletable set is computed positively rather than as
    "everything except the carriers", which would have swept up the unreadable
    rows as well. `kept_messages` counts what that leaves behind.
    """
    for kind, model in _KINDS.items():
        deletable = [
            row.id
            for row in db.query(model).filter(model.sender_address == address).all()
            if (payload := _payload(row.content)) is not None and not payload.get("keys")
        ]
        if deletable:
            db.query(model).filter(model.id.in_(deletable)).delete(synchronize_session=False)


def _leave_all_groups(db: Session, address: str) -> list[dict]:
    """Leave every group, reusing the rules the leave endpoint uses.

    The departing user goes even in `leave` mode: a stripped row has no
    `encryption_public_key`, so the group could not wrap its next session key
    to them. Staying would make them a member nobody can reach, and would cost
    the S2 rotation that stops the remaining members wrapping to a departed
    key.

    Returns what the caller must broadcast AFTER the commit — built here, while
    the rows are still live, because reading attributes off a deleted instance
    afterwards is the Q-2 bug.
    """
    departures = []
    memberships = (
        db.query(models.GroupMember).filter(models.GroupMember.user_address == address).all()
    )
    for membership in memberships:
        channel = (
            db.query(models.GroupChannel)
            .options(joinedload(models.GroupChannel.members))
            .filter(models.GroupChannel.id == membership.channel_id)
            .first()
        )
        if channel is None:
            continue

        remaining = [m for m in channel.members if m.user_address != address]
        remaining_addrs = [m.user_address for m in remaining]

        new_owner_info, group_deleted = None, False
        if membership.role == "owner":
            new_owner_info, group_deleted = authorization.succeed_group_owner(
                db, channel, membership, remaining, True
            )

        if not group_deleted:
            # By predicate, not by instance: a duplicate membership row would
            # survive an instance delete and leave the "removed" member with
            # access (audit M-1).
            db.query(models.GroupMember).filter(
                models.GroupMember.channel_id == channel.id,
                models.GroupMember.user_address == address,
            ).delete(synchronize_session="fetch")
            departures.append(
                {
                    "channel_id": channel.id,
                    "remaining_addrs": remaining_addrs,
                    "new_owner_info": new_owner_info,
                }
            )

    # `group_channels.owner_address` and `GroupMember.role == "owner"` are two
    # sources of truth. They cannot disagree today (create_group always inserts
    # the owner's member row, and succession updates both), but a channel left
    # pointing at a departed owner is the Q-1 bug, so close it rather than
    # trusting the invariant.
    # BOTH session factories are autoflush=False, so nothing above has reached
    # the database yet and the query below would read the pre-succession
    # owner_address — re-running succession on a channel already handled, using
    # a member row this loop has since deleted. Every ordering assumption in
    # this module has to be made explicit for that reason.
    db.flush()

    orphaned = (
        db.query(models.GroupChannel).filter(models.GroupChannel.owner_address == address).all()
    )
    for channel in orphaned:
        remaining = [m for m in channel.members if m.user_address != address]
        if not remaining:
            db.delete(channel)
            continue
        authorization.succeed_group_owner(db, channel, None, remaining, True)

    return departures


def _erase_multisig(db: Session, address: str) -> None:
    """Delete the workflows the user owns that the API would let them delete."""
    owned = (
        db.query(models.MultisigWorkflow)
        .filter(models.MultisigWorkflow.owner_address == address)
        .all()
    )
    for workflow in owned:
        if not authorization.workflow_is_deletable(workflow):
            # Completed: the recipients' wrapped keys and the secret's
            # ciphertext are their only copy of what was released to them.
            # _erase_secrets sees it is still workflow-managed and leaves the
            # secret alone.
            continue
        # Same order as routers/multisig.py's delete: children, then the
        # workflow, then the secret's grants, then the secret itself as an
        # INSTANCE so FileChunk cascades.
        db.query(models.MultisigWorkflowSigner).filter(
            models.MultisigWorkflowSigner.workflow_id == workflow.id
        ).delete(synchronize_session=False)
        db.query(models.MultisigWorkflowRecipient).filter(
            models.MultisigWorkflowRecipient.workflow_id == workflow.id
        ).delete(synchronize_session=False)
        secret = workflow.secret
        db.delete(workflow)
        if secret is not None:
            db.query(models.AccessGrant).filter(models.AccessGrant.secret_id == secret.id).delete(
                synchronize_session=False
            )
            db.delete(secret)

    # Recipient rows on OTHER people's workflows, on everything NOT yet
    # released. They hold a key wrapped to a user who can no longer read it, and
    # deleting the row is better than blanking the key: a recipient with a NULL
    # key makes the workflow permanently uncompletable (the L-2 dead end), where
    # removing it lets the workflow complete for everyone else.
    #
    # A COMPLETED workflow is different, and the reason the two were treated
    # alike did not survive being written down (audit 2026-09-12 I-6): there is
    # no completion left to block, and the row is the owner's record that the
    # document was released to this address. Deleting it would let a departing
    # recipient erase the evidence of a release they received — the same thing
    # `workflow_is_deletable` already refuses the OWNER a few lines above. The
    # key it holds is wrapped to a public key nobody else can use.
    released = db.query(models.MultisigWorkflow.id).filter(
        models.MultisigWorkflow.status == "completed"
    )
    db.query(models.MultisigWorkflowRecipient).filter(
        models.MultisigWorkflowRecipient.user_address == address,
        ~models.MultisigWorkflowRecipient.workflow_id.in_(released),
    ).delete(synchronize_session=False)

    # autoflush is off, so the workflows deleted above are still only marked.
    # _erase_secrets asks is_workflow_managed, which reads the table — without
    # this every secret would look managed and survive an erase.
    db.flush()


def _erase_secrets(db: Session, address: str) -> None:
    secrets = db.query(models.Secret).filter(models.Secret.owner_address == address).all()
    for secret in secrets:
        # Runs AFTER _erase_multisig, so the only workflows left referencing a
        # secret are the retained ones. Asking the existing rule rather than
        # threading a set also covers a secret managed by someone ELSE's
        # workflow, which the set would have missed.
        if authorization.is_workflow_managed(db, secret.id):
            continue
        # Grants first: access_grants.secret_id is an FK to secrets. The secret
        # goes as an instance so Secret.chunks cascades — a bulk delete would
        # orphan the file chunks.
        db.query(models.AccessGrant).filter(models.AccessGrant.secret_id == secret.id).delete(
            synchronize_session=False
        )
        db.delete(secret)

    # Grants held ON other people's secrets: useless to an identity that cannot
    # log in, and the grantor keeps their secret either way.
    db.query(models.AccessGrant).filter(models.AccessGrant.grantee_address == address).delete(
        synchronize_session=False
    )


def _erase_invite_codes(db: Session, address: str) -> None:
    """Sever the referral trail without invalidating anyone else's code.

    `created_by` is NULLed rather than deleting the codes: an unredeemed code
    the user handed out belongs to whoever is about to redeem it, and NULL is
    the shape admin-seeded codes already have. `used_by` is NULLed too, but
    `uses` is left alone — decrementing it would hand the access filter's
    budget back and let the same code create another account.
    """
    db.query(models.InviteCode).filter(models.InviteCode.created_by == address).update(
        {models.InviteCode.created_by: None}, synchronize_session=False
    )
    db.query(models.InviteCode).filter(models.InviteCode.used_by == address).update(
        {models.InviteCode.used_by: None}, synchronize_session=False
    )


def _strip_identity(user: models.User, mode: str) -> None:
    """Everything the row held about the person, gone; the address remains.

    The address is an ML-DSA public key that is already embedded in every
    message this identity ever signed, so keeping it discloses nothing new —
    and dropping it would break the signatures on the rows both modes retain.

    **The username survives a `leave`, and only a `leave`.** Freeing it the
    moment someone stepped away made the reversibility this mode promises
    conditional on nobody having taken the name in the meantime — and on an
    open-signup server anybody could, deliberately, the moment they noticed
    (audit 2026-09-12 L-1). Worse than losing a name: contacts who look the
    account up by name to share a secret would find the squatter. Erase frees
    it, because that identity is never coming back.

    The reservation costs nothing visible. `active_users` already hides deleted
    rows from the directory and its search, and `UserResponse` withholds the
    username of a deleted identity, so the reserved name is enforced in
    `username_taken` and is not readable anywhere.

    `token_version` is bumped so any JWT already in flight stops working, on
    top of `user_for_token` refusing a deleted row outright.
    """
    if mode == MODE_ERASE:
        user.username = None
    user.encryption_public_key = None
    user.encryption_key_attestation = None
    user.key_changed_at = None
    user.token_version = (user.token_version or 0) + 1
    user.deleted_at = utcnow_naive()
    # Monotonic: a block is never lifted by a later deletion. The caller takes a
    # row lock and re-checks, so a "leave" cannot reach a row an "erase" has
    # already blocked — but writing `blocked = (mode == erase)` made the
    # invariant depend entirely on that check holding, and an invariant this
    # cheap to state outright should not (audit 2026-09-12 I-1). Clearing the
    # flag stays an operator's decision, by hand, which is the right amount of
    # ceremony for undoing something the modal calls final.
    user.blocked = bool(user.blocked) or mode == MODE_ERASE


def delete_account(db: Session, user: models.User, mode: str) -> list[dict]:
    """Apply a deletion. The caller has already authorized it and commits after.

    For an erase the caller has also driven `apply_redactions` until
    `redaction_keys` came back empty, so every message of the user's that holds
    somebody else's session key already carries its author-signed redacted
    form. This step is what is left: deleting the rest.

    Returns the group departures to broadcast once the transaction lands.
    Broadcasting before the commit would tell everyone a user left a group that
    a rollback then puts them back in.
    """
    if mode not in MODES:
        raise ValueError(f"unknown deletion mode: {mode}")

    address = user.address

    # Messages before groups: tearing down a channel whose last member is
    # leaving cascades its group_messages, so doing this first keeps the two
    # from racing over the same rows.
    if mode == MODE_ERASE:
        _delete_own_messages(db, address)

    departures = _leave_all_groups(db, address)

    if mode == MODE_ERASE:
        _erase_multisig(db, address)
        _erase_secrets(db, address)
        _erase_invite_codes(db, address)

    db.query(models.PushSubscription).filter(
        models.PushSubscription.user_address == address
    ).delete(synchronize_session=False)
    db.query(models.Nonce).filter(models.Nonce.address == address).delete(synchronize_session=False)

    _strip_identity(user, mode)
    db.add(user)
    return departures
