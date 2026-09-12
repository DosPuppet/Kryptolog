from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    WithJsonSchema,
    field_validator,
)

from security.crypto_validation import is_b64, is_valid_ml_dsa_signature
from utils.clock import to_wire_utc

# Use for EVERY datetime the API returns: naive on the way in, because that is
# how the columns store it, and an explicit UTC offset on the way out, because
# a browser parses an offset-less ISO string as LOCAL time. See
# utils/clock.to_wire_utc for what that cost us. Applying this to some datetime
# fields and not others is the failure mode, so test_wire_datetimes.py walks
# every model in this file and fails on a bare `datetime`.
UtcDateTime = Annotated[
    datetime,
    PlainSerializer(to_wire_utc, return_type=str),
    # `return_type=str` alone would document these as plain strings and drop
    # `format: date-time` from /docs, which is the whole OpenAPI surface.
    WithJsonSchema({"type": "string", "format": "date-time"}, mode="serialization"),
]

# --- Input bounds (audit KRY-010) -------------------------------------------
#
# These are DoS bounds, not format validation: they cap how much a caller can
# push through a field, while the cryptographic format checks live in
# security/crypto_validation.py.
#
# An address IS an ML-DSA-44 public key — 1312 bytes, 2624 hex chars. The old
# 20 000-char cap let a caller send ~8x that in every address field. 4096 keeps
# real addresses comfortably inside while cutting the ceiling, and leaves room
# for the shorter synthetic addresses that predate strict validation (see the
# "strict on write, lenient on read" note in the audit doc).
MAX_ADDRESS_LEN = 4096

# Hard cap on group size, enforced by routers/groups.py on both create and
# add-member. It also sizes the two group blobs below, which is why it lives
# here rather than in the router: those bounds are one decision.
MAX_GROUP_MEMBERS = 50

# ── Post-quantum envelope sizing ────────────────────────────────────────────
#
# Several fields below hold PQC envelopes rather than user text, and each one
# had been budgeted as if it held the text: a group NAME is a per-member
# key-wrap map, and a message carries its own wrapped session key plus a
# signature. Sized as labels and chat lines, all three rejected ordinary use —
# no group could be created at all, no group past nine members could send, and
# the first message of a conversation was capped at ~160 characters.
#
# So the costs are spelled out and the bounds derived from them. Every figure
# is measured against crypto-core 2.0.0 and pinned on the producing side by
# packages/crypto-core/test/envelope-size.test.js, which fails if a primitive
# change outgrows what this file budgets.


def b64_chars(byte_len: int) -> int:
    """Characters base64 costs for `byte_len` bytes, padded (4 per 3 bytes)."""
    return ((byte_len + 2) // 3) * 4


# The address IS the ML-DSA-44 public key (self-certifying), in HEX — 2624
# chars, not the 42 an address usually suggests. Identifiers stayed hex through
# the L-12 cutover; only opaque payloads moved to base64.
ADDRESS_CHARS = 2_624
# A detached ML-DSA-44 signature, base64 (2420 bytes). Every message carries
# one (audit S1).
SIGNATURE_CHARS = b64_chars(2_420)  # 3 228
# One ML-KEM-768-wrapped session key, JSON-encoded: {kem, iv, encKey}.
WRAPPED_KEY_CHARS = 1_600  # measured 1 562
# One entry in a key-wrap map: the member's address, their wrapped key, and the
# JSON punctuation between them.
KEY_WRAP_CHARS_PER_MEMBER = ADDRESS_CHARS + WRAPPED_KEY_CHARS  # 4 224
# Plaintext a user may put in one message, counted the way the client counts it
# — JavaScript string length, i.e. UTF-16 code units.
MAX_MESSAGE_TEXT_CHARS = 10_000
# ...and the bytes those can encode to, which is NOT the same number. The old
# budget was `2 * MAX_MESSAGE_TEXT_CHARS` — one byte per character — so a
# message of accented or CJK text hit the cap well under the advertised 10 000
# characters and came back as a bare 422. Same failure mode the rest of this
# block exists to prevent, just narrower, and it predates the L-12 cutover.
#
# Worst case is 3 bytes per UTF-16 unit: a BMP character (CJK, Cyrillic, Greek)
# is one unit and up to 3 bytes, while an astral character (emoji) is 4 bytes
# but TWO units — cheaper per unit, not dearer.
MAX_MESSAGE_TEXT_BYTES = 3 * MAX_MESSAGE_TEXT_CHARS
# AES-GCM appends a 16-byte tag, and the result is base64 inside a JSON envelope.
CIPHERTEXT_CHARS = b64_chars(MAX_MESSAGE_TEXT_BYTES + 16)  # 40 024
# Slack for the ids, version tag and JSON structure around all of the above.
ENVELOPE_SLACK_CHARS = 1_000

# "encg1:" + JSON({ct, keys: {address: wrappedKey}}) — one wrap per member so
# each can decrypt the name (audit M-3). Rebuilt on rename and on every
# membership change, so create and update share the bound.
MAX_GROUP_NAME_LEN = MAX_GROUP_MEMBERS * KEY_WRAP_CHARS_PER_MEMBER  # 211 200

# A DM that mints a session carries two wraps (recipient and sender), keyed by
# short literal names rather than by address.
MAX_DM_CONTENT_LEN = (
    SIGNATURE_CHARS + 2 * WRAPPED_KEY_CHARS + CIPHERTEXT_CHARS + ENVELOPE_SLACK_CHARS
)

# A group message that rotates the session key carries a wrap for every member,
# addressed by address. That makes a full-group rekey genuinely large — the
# same order as an inline secret — but it is the size the protocol produces,
# and capping below it silently disables sending rather than trimming anything.
MAX_GROUP_MESSAGE_CONTENT_LEN = (
    SIGNATURE_CHARS + MAX_GROUP_NAME_LEN + CIPHERTEXT_CHARS + ENVELOPE_SLACK_CHARS
)

# Encrypted secret payload stored inline (large files go through FileChunks).
MAX_SECRET_BLOB_LEN = 500_000


class UserBase(BaseModel):
    address: str = Field(..., max_length=MAX_ADDRESS_LEN)


class UserUpdate(BaseModel):
    username: str | None = Field(None, max_length=200)


class UserResponse(UserBase):
    username: str | None
    encryption_public_key: str | None
    created_at: UtcDateTime
    # When this identity's encryption key last changed (audit S1). Null = never
    # changed since creation. Clients use it to flag/verify key swaps.
    key_changed_at: UtcDateTime | None = None
    # Self-signed ML-KEM key attestation (audit M-1) — peers verify this against
    # the address before encrypting to encryption_public_key.
    encryption_key_attestation: str | None = None
    # True once the identity has been deleted. The row is kept, stripped, so
    # that messages and workflows which still name the address can render as
    # "user removed" rather than as an unknown stranger — a deleted account is
    # not the same thing as a lookup that failed, and only the server can tell
    # the two apart. A bare username of None would be indistinguishable from an
    # account that simply never set one.
    deleted: bool = False

    model_config = ConfigDict(from_attributes=True)


class SecretBase(BaseModel):
    # Encrypted title blob (audit M-3): marker + AES-GCM envelope JSON. Legacy
    # plaintext names remain valid (they're just short strings).
    name: str = Field(..., max_length=10_000)
    type: str = Field("standard")  # 'standard' | 'file' | 'signed_document'
    # 500KB limit for SecretBase.encrypted_data. Large files use FileChunks.
    encrypted_data: str = Field(..., max_length=MAX_SECRET_BLOB_LEN)
    # Key is small, keeping strict limit
    encrypted_key: str = Field(..., max_length=50_000)


class SecretCreate(SecretBase):
    pass


class SecretSummaryResponse(BaseModel):
    """A secret WITHOUT its ciphertext — what the list endpoints return.

    Listing every secret with its `encrypted_data` inline shipped up to 500 KB
    per row for content the list never renders: the dashboard draws itself from
    `name` and `encrypted_key`, and the payload is read in exactly one place,
    on demand, for one secret at a time (audit O-3). Content now comes from
    `GET /secrets/{id}`.

    A separate model rather than `encrypted_data: Optional[str]` on
    SecretResponse: an optional field cannot tell "not sent" from "empty", so a
    caller that forgets to fetch the detail decrypts nothing and says nothing.
    Omitting the field structurally makes that a KeyError at the first attempt.
    """

    id: int
    owner_address: str
    created_at: UtcDateTime
    name: str
    type: str
    encrypted_key: str | None = (
        None  # The specific key for the requesting user (joined from AccessGrant)
    )
    owner: UserResponse

    model_config = ConfigDict(from_attributes=True)


class SecretResponse(SecretSummaryResponse):
    """One secret WITH its ciphertext. Detail endpoints only."""

    encrypted_data: str  # Relax output limit for legacy secrets


# The client chunks at 512 KB (frontend/src/utils/fileChunks.js CHUNK_SIZE);
# budget double that, as the hex-era bound did, so a chunk-size change does not
# immediately mean a schema change.
MAX_CHUNK_BYTES = 1024 * 1024
MAX_CHUNK_B64_CHARS = b64_chars(MAX_CHUNK_BYTES + 16)  # + AES-GCM tag


class FileChunkUpload(BaseModel):
    secret_id: int
    chunk_index: int
    iv: str = Field(..., max_length=100)
    encrypted_data: str = Field(..., max_length=MAX_CHUNK_B64_CHARS)

    # Both fields are base64 on the wire (hex before the L-12 cutover), but
    # nothing checked that (audit M-2), so arbitrary text reached storage and
    # only failed much later — client-side, as an opaque decrypt error. The size
    # accounting in upload_chunk also converts length to bytes, which is only
    # meaningful for a real encoding.
    @field_validator("iv", "encrypted_data")
    @classmethod
    def _must_be_b64(cls, v: str, info) -> str:
        if not is_b64(v):
            raise ValueError(f"{info.field_name} must be non-empty, canonical base64")
        return v

    @field_validator("chunk_index")
    @classmethod
    def _index_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("chunk_index must be >= 0")
        return v


class FileChunkResponse(BaseModel):
    chunk_index: int
    iv: str
    encrypted_data: str

    model_config = ConfigDict(from_attributes=True)


class AccessGrantCreate(BaseModel):
    secret_id: int
    grantee_address: str = Field(..., max_length=MAX_ADDRESS_LEN)
    encrypted_key: str = Field(..., max_length=50_000)  # Key encrypted for grantee
    expires_in: int | None = None  # Seconds


class AccessGrantResponse(BaseModel):
    """A grant on its own — who holds access, and until when.

    No nested secret at all (audit O-3). `GET /secrets/{id}/access` lists one
    secret's grantees, so embedding the secret meant N copies of the same
    ciphertext to answer a question that is entirely about the grantees; the
    share modal reads only the grantee, the expiry and the id.
    """

    id: int
    secret_id: int
    grantee_address: str
    encrypted_key: str
    created_at: UtcDateTime
    expires_at: UtcDateTime | None
    grantee: UserResponse | None

    model_config = ConfigDict(from_attributes=True)


class SharedSecretResponse(AccessGrantResponse):
    """A grant plus the secret it points at, for `GET /secrets/shared-with-me`.

    Unlike the ACL listing this one is a secrets list — it has to render a
    title and an owner — so it carries the summary. Still no ciphertext: the
    content comes from `GET /secrets/{id}` like any other secret.
    """

    secret: SecretSummaryResponse


class LoginRequest(BaseModel):
    address: str = Field(..., max_length=MAX_ADDRESS_LEN)
    signature: str = Field(..., max_length=64_000)
    nonce: str = Field(..., max_length=200)
    encryption_public_key: str | None = Field(None, max_length=MAX_ADDRESS_LEN)
    # Self-signed attestation of encryption_public_key (audit M-1). Optional for
    # compat with older clients; verified server-side when present.
    encryption_key_attestation: str | None = Field(None, max_length=64_000)
    username: str | None = Field(None, max_length=200)
    # Access filter (audit §5): only consulted when the server requires invites
    # AND this is a brand-new identity. Ignored for existing users.
    invite_code: str | None = Field(None, max_length=200)


class MultisigWorkflowBase(BaseModel):
    name: str = Field(..., max_length=200)


class MultisigWorkflowCreate(MultisigWorkflowBase):
    secret_data: SecretCreate  # Embedded secret creation
    signers: list[str]  # List of addresses
    recipients: list[str]  # List of addresses
    signer_keys: dict[str, str]  # map address -> encrypted_key
    recipient_keys: dict[str, str]  # map address -> encrypted_key
    threshold: int = Field(..., ge=1)  # N in N-of-M; must be <= len(signers)


class MultisigWorkflowSignerResponse(BaseModel):
    user_address: str
    has_signed: bool
    signature: str | None = None
    signed_at: UtcDateTime | None
    encrypted_key: str | None
    user: UserResponse | None

    model_config = ConfigDict(from_attributes=True)


class MultisigWorkflowRecipientResponse(BaseModel):
    user_address: str
    encrypted_key: str | None
    user: UserResponse | None

    model_config = ConfigDict(from_attributes=True)


class MultisigWorkflowSummaryResponse(MultisigWorkflowBase):
    """A workflow WITHOUT its secret's ciphertext — the listing shape (O-3).

    Everything a client needs to draw the list and decide whether the user owes
    a signature: status, threshold, and the signer/recipient rows. The
    ciphertext a signer approves comes from `GET /multisig/workflow/{id}`,
    which is also the copy that must be hashed — the server recomputes that
    hash from the stored row, so signing a stale list copy could only fail.
    """

    id: int
    secret_id: int
    owner_address: str
    status: str
    threshold: int | None = None  # N in N-of-M; NULL ⇒ N-of-N (= len(signers))
    rejected_by: str | None = None
    created_at: UtcDateTime
    owner: UserResponse
    secret: SecretSummaryResponse
    owner_encrypted_key: str | None = None  # Explicitly pass owner key here to avoid nesting issues
    signers: list[MultisigWorkflowSignerResponse]
    recipients: list[MultisigWorkflowRecipientResponse]

    model_config = ConfigDict(from_attributes=True)


class MultisigWorkflowResponse(MultisigWorkflowSummaryResponse):
    """One workflow WITH its secret's ciphertext — signers need it to approve."""

    secret: SecretResponse


class MultisigSignatureRequest(BaseModel):
    # 64KB limit for PQC signatures
    signature: str = Field(..., max_length=64_000)
    recipient_keys: dict[str, str] | None = None  # Only provided by the completing signer


class MessageBase(BaseModel):
    recipient_address: str = Field(..., max_length=MAX_ADDRESS_LEN)
    # A signed, session-wrapped envelope — see MAX_DM_CONTENT_LEN, not a 10KB
    # guess at how long a chat line is.
    content: str = Field(..., max_length=MAX_DM_CONTENT_LEN)


class MessageCreate(MessageBase):
    pass


class MessageResponse(MessageBase):
    id: int
    sender_address: str
    is_read: bool = False
    created_at: UtcDateTime
    content: str  # Relax output limit for legacy messages
    sender: UserResponse | None
    recipient: UserResponse | None

    model_config = ConfigDict(from_attributes=True)


class MessageSummaryResponse(BaseModel):
    """Lightweight message representation for conversation lists (no content blob)."""

    id: int
    sender_address: str
    recipient_address: str
    is_read: bool = False
    created_at: UtcDateTime
    sender: UserResponse | None = None
    recipient: UserResponse | None = None

    model_config = ConfigDict(from_attributes=True)


class ConversationResponse(BaseModel):
    user: UserResponse
    last_message: MessageSummaryResponse
    unread_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class HistoryRequest(BaseModel):
    partner_address: str
    limit: int = Field(50, ge=1, le=100)  # Default 50, Max 100
    offset: int = Field(0, ge=0)


# ── Group Channels ──────────────────────────────────────────────


class GroupChannelCreate(BaseModel):
    # An E2EE key-wrap map, not a title — see MAX_GROUP_NAME_LEN for why the
    # cap scales with group size rather than with name length.
    name: str = Field(..., min_length=1, max_length=MAX_GROUP_NAME_LEN)
    member_addresses: list[str] = Field(..., min_length=1)


class GroupMemberResponse(BaseModel):
    user_address: str
    role: str
    joined_at: UtcDateTime
    user: UserResponse | None = None

    model_config = ConfigDict(from_attributes=True)


class GroupChannelResponse(BaseModel):
    id: str
    name: str
    owner_address: str
    created_at: UtcDateTime
    members: list[GroupMemberResponse] = []

    model_config = ConfigDict(from_attributes=True)


class GroupMessageCreate(BaseModel):
    # The first message of each key epoch carries a wrap for every member, so
    # the bound scales with the member cap — see MAX_GROUP_MESSAGE_CONTENT_LEN.
    content: str = Field(..., max_length=MAX_GROUP_MESSAGE_CONTENT_LEN)


class GroupMessageResponse(BaseModel):
    id: int
    channel_id: str
    sender_address: str
    content: str
    created_at: UtcDateTime
    sender: UserResponse | None = None

    model_config = ConfigDict(from_attributes=True)


class GroupConversationResponse(BaseModel):
    channel: GroupChannelResponse
    last_message: GroupMessageResponse | None = None
    unread_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class GroupHistoryRequest(BaseModel):
    limit: int = Field(50, ge=1, le=100)
    offset: int = Field(0, ge=0)


class GroupMemberAdd(BaseModel):
    user_address: str


class GroupMemberRoleUpdate(BaseModel):
    role: str


class GroupUpdate(BaseModel):
    # Rebuilt from scratch on every rename and membership change, so it is
    # the same shape and the same size as GroupChannelCreate.name.
    name: str = Field(..., max_length=MAX_GROUP_NAME_LEN)


class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse


class KeyTransferCreate(BaseModel):
    # Client-side-encrypted vault blob (JSON of {salt, iv, data}, all hex). The
    # server never sees the passphrase that decrypts it. This bound is the only
    # cap: the router's 413 sat above a larger config value and never fired.
    ciphertext: str = Field(..., max_length=4_000_000)


class KeyTransferCreateResponse(BaseModel):
    id: str
    expires_at: UtcDateTime


class KeyTransferResponse(BaseModel):
    ciphertext: str


class PushSubscriptionCreate(BaseModel):
    # Bounded (KRY-002): these were previously unbounded strings. The endpoint
    # is additionally SSRF-validated in security.url_guard. p256dh/auth are
    # base64url-encoded P-256 point / 16-byte salt — small and fixed-ish.
    endpoint: str = Field(..., max_length=2000)
    p256dh: str = Field(..., max_length=256)
    auth: str = Field(..., max_length=256)


class PushSubscriptionResponse(PushSubscriptionCreate):
    id: int
    user_address: str
    created_at: UtcDateTime

    model_config = ConfigDict(from_attributes=True)


# ── Account deletion ────────────────────────────────────────────────────────

# One redaction is a namespaced message id plus an ML-DSA signature over the
# redacted form of that message's body. The signature dominates the size: 3228
# base64 characters against a couple of dozen for the id.
#
# The cap is a DoS bound, not a protocol limit. Erase asks the client to
# re-sign one message per session epoch it ever opened, so a long-lived account
# in many conversations can legitimately submit hundreds. At the cap the body
# is roughly 3.3 MB and the server performs 1000 ML-DSA-44 verifications,
# ~0.05 s of CPU — expensive enough to bound, cheap enough not to refuse a real
# account.
MAX_REDACTIONS_PER_DELETE = 1_000
# "dm:" / "group:" plus a 64-bit id, with room to spare.
MAX_REDACTION_KEY_LEN = 32


class RedactionSignature(BaseModel):
    key: str = Field(..., max_length=MAX_REDACTION_KEY_LEN)
    signature: str = Field(..., max_length=SIGNATURE_CHARS)

    @field_validator("signature")
    @classmethod
    def _signature_is_ml_dsa(cls, v: str) -> str:
        # Exact length and canonical spelling, not a length guess: a signature
        # commits to its message AS A STRING, so a second valid spelling of one
        # signature would be a second valid signature for it (audit L-12).
        if not is_valid_ml_dsa_signature(v):
            raise ValueError("signature must be a canonical base64 ML-DSA-44 signature")
        return v


class AccountDeleteRequest(BaseModel):
    # "leave" keeps every row and can be undone by logging in again; "erase"
    # removes the user's content and blocks the key forever. Both are signed,
    # and the MODE is part of what is signed — see auth.account_deletion_message.
    mode: Literal["leave", "erase"]
    nonce: str = Field(..., max_length=200)
    signature: str = Field(..., max_length=SIGNATURE_CHARS)
    redactions: list[RedactionSignature] = Field(
        default_factory=list, max_length=MAX_REDACTIONS_PER_DELETE
    )

    @field_validator("signature")
    @classmethod
    def _signature_is_ml_dsa(cls, v: str) -> str:
        if not is_valid_ml_dsa_signature(v):
            raise ValueError("signature must be a canonical base64 ML-DSA-44 signature")
        return v


class RedactableMessageResponse(BaseModel):
    """One message the client must re-sign before an erase.

    `conv` and `gid` are derived server-side from the delivered row (audit
    F-1); the client signs what it is given here rather than choosing its own,
    and a lying manifest could only produce a signature the server rejects.
    """

    id: int
    kind: Literal["dm", "group"]
    key: str
    conv: str
    gid: str
    sid: str | None
    keys: dict
