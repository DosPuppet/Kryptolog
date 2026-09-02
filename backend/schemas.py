from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import Optional, List
from datetime import datetime

from security.crypto_validation import is_hex

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

# Display names (groups, channels). Previously 500 000 — half a megabyte for a
# label that renders in a sidebar. Group names may be encrypted blobs in some
# clients, so this is generous rather than tight.
MAX_DISPLAY_NAME_LEN = 2_000

# Encrypted secret payload stored inline (large files go through FileChunks).
MAX_SECRET_BLOB_LEN = 500_000

class UserBase(BaseModel):
    address: str = Field(..., max_length=MAX_ADDRESS_LEN)

class UserCreate(UserBase):
    encryption_public_key: str = Field(..., max_length=MAX_ADDRESS_LEN)

class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, max_length=200)

class UserResponse(UserBase):
    username: Optional[str]
    encryption_public_key: Optional[str]
    created_at: datetime
    # When this identity's encryption key last changed (audit S1). Null = never
    # changed since creation. Clients use it to flag/verify key swaps.
    key_changed_at: Optional[datetime] = None
    # Self-signed ML-KEM key attestation (audit M-1) — peers verify this against
    # the address before encrypting to encryption_public_key.
    encryption_key_attestation: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class SecretBase(BaseModel):
    # Encrypted title blob (audit M-3): marker + AES-GCM envelope JSON. Legacy
    # plaintext names remain valid (they're just short strings).
    name: str = Field(..., max_length=10_000)
    type: str = Field("standard") # 'standard' | 'signed_document'
    # 500KB limit for SecretBase.encrypted_data. Large files use FileChunks.
    encrypted_data: str = Field(..., max_length=MAX_SECRET_BLOB_LEN)
    # Key is small, keeping strict limit
    encrypted_key: str = Field(..., max_length=50_000) 

class SecretCreate(SecretBase):
    pass

class SecretResponse(SecretBase):
    id: int
    owner_address: str
    created_at: datetime
    encrypted_data: str # Relax output limit for legacy secrets 
    encrypted_key: Optional[str] = None # The specific key for the requesting user (joined from AccessGrant)
    owner: UserResponse

    model_config = ConfigDict(from_attributes=True)

class FileChunkUpload(BaseModel):
    secret_id: int
    chunk_index: int
    iv: str = Field(..., max_length=100)
    encrypted_data: str = Field(..., max_length=2_100_000)  # ~1MB chunk hex-encoded

    # Both fields are hex on the wire, but nothing checked that (audit M-2), so
    # arbitrary text reached storage and only failed much later — client-side, as
    # an opaque decrypt error. The size accounting in upload_chunk also divides
    # length by 2 to get bytes, which is only meaningful for real hex.
    @field_validator("iv", "encrypted_data")
    @classmethod
    def _must_be_hex(cls, v: str, info) -> str:
        if not is_hex(v):
            raise ValueError(f"{info.field_name} must be non-empty, even-length hex")
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

class FileMetadata(BaseModel):
    """Stored in Secret.encrypted_data for chunked files instead of the full content."""
    file_name: str
    mime_type: str
    total_chunks: int
    total_size: int       # Original file size in bytes
    chunk_size: int       # Bytes per chunk before encryption

class AccessGrantCreate(BaseModel):
    secret_id: int
    grantee_address: str = Field(..., max_length=MAX_ADDRESS_LEN)
    encrypted_key: str = Field(..., max_length=50_000) # Key encrypted for grantee
    expires_in: Optional[int] = None # Seconds

class AccessGrantResponse(BaseModel):
    id: int
    secret_id: int
    grantee_address: str
    encrypted_key: str
    created_at: datetime
    expires_at: Optional[datetime]
    secret: SecretResponse
    grantee: Optional[UserResponse]

    model_config = ConfigDict(from_attributes=True)

class DocumentBase(BaseModel):
    name: str = Field(..., max_length=200)
    content_hash: str = Field(..., max_length=500)
    # 64KB to support potential embedded PQC signatures (Dilithium) safely
    signature: str = Field(..., max_length=64_000)

class DocumentCreate(DocumentBase):
    pass

class DocumentResponse(DocumentBase):
    id: int
    owner_address: str
    created_at: datetime
    signature: str # Relax output limit for legacy docs

    model_config = ConfigDict(from_attributes=True)

class LoginRequest(BaseModel):
    address: str = Field(..., max_length=MAX_ADDRESS_LEN)
    signature: str = Field(..., max_length=64_000)
    nonce: str = Field(..., max_length=200)
    encryption_public_key: Optional[str] = Field(None, max_length=MAX_ADDRESS_LEN)
    # Self-signed attestation of encryption_public_key (audit M-1). Optional for
    # compat with older clients; verified server-side when present.
    encryption_key_attestation: Optional[str] = Field(None, max_length=64_000)
    username: Optional[str] = Field(None, max_length=200)
    # Access filter (audit §5): only consulted when the server requires invites
    # AND this is a brand-new identity. Ignored for existing users.
    invite_code: Optional[str] = Field(None, max_length=200)

class MultisigWorkflowBase(BaseModel):
    name: str = Field(..., max_length=200)

class MultisigWorkflowCreate(MultisigWorkflowBase):
    secret_data: SecretCreate # Embedded secret creation
    signers: List[str] # List of addresses
    recipients: List[str] # List of addresses
    signer_keys: dict[str, str] # map address -> encrypted_key
    recipient_keys: dict[str, str] # map address -> encrypted_key
    threshold: int = Field(..., ge=1) # N in N-of-M; must be <= len(signers)

class MultisigWorkflowSignerResponse(BaseModel):
    user_address: str
    has_signed: bool
    signature: Optional[str] = None
    signed_at: Optional[datetime]
    encrypted_key: Optional[str]
    user: Optional[UserResponse]

    model_config = ConfigDict(from_attributes=True)

class MultisigWorkflowRecipientResponse(BaseModel):
    user_address: str
    encrypted_key: Optional[str]
    user: Optional[UserResponse]

    model_config = ConfigDict(from_attributes=True)

class MultisigWorkflowResponse(MultisigWorkflowBase):
    id: int
    secret_id: int
    owner_address: str
    status: str
    threshold: Optional[int] = None # N in N-of-M; NULL ⇒ N-of-N (= len(signers))
    rejected_by: Optional[str] = None
    created_at: datetime
    owner: UserResponse
    secret: SecretResponse # Include Secret Data so signers can access encrypted_data
    owner_encrypted_key: Optional[str] = None # Explicitly pass owner key here to avoid nesting issues
    signers: List[MultisigWorkflowSignerResponse]
    recipients: List[MultisigWorkflowRecipientResponse]

    model_config = ConfigDict(from_attributes=True)

class MultisigSignatureRequest(BaseModel):
    # 64KB limit for PQC signatures
    signature: str = Field(..., max_length=64_000)
    recipient_keys: Optional[dict[str, str]] = None # Only provided by the completing signer

class MultisigRejectRequest(BaseModel):
    reason: Optional[str] = Field(None, max_length=500)

class MessageBase(BaseModel):
    recipient_address: str = Field(..., max_length=MAX_ADDRESS_LEN)
    content: str = Field(..., max_length=10_000) # Encrypted Blob (Max 10KB)

class MessageCreate(MessageBase):
    pass

class MessageResponse(MessageBase):
    id: int
    sender_address: str
    is_read: bool = False
    created_at: datetime
    content: str # Relax output limit for legacy messages
    sender: Optional[UserResponse]
    recipient: Optional[UserResponse]

    model_config = ConfigDict(from_attributes=True)

class MessageSummaryResponse(BaseModel):
    """Lightweight message representation for conversation lists (no content blob)."""
    id: int
    sender_address: str
    recipient_address: str
    is_read: bool = False
    created_at: datetime
    sender: Optional[UserResponse] = None
    recipient: Optional[UserResponse] = None

    model_config = ConfigDict(from_attributes=True)

class ConversationResponse(BaseModel):
    user: UserResponse
    last_message: MessageSummaryResponse
    unread_count: int = 0

    model_config = ConfigDict(from_attributes=True)

class HistoryRequest(BaseModel):
    partner_address: str
    limit: int = Field(50, ge=1, le=100) # Default 50, Max 100
    offset: int = Field(0, ge=0)

# ── Group Channels ──────────────────────────────────────────────

class GroupChannelCreate(BaseModel):
    # Names are E2EE blobs (audit M-3): a per-member key-wrap map, so the cap
    # scales with group size (~2.3KB/member) rather than title length.
    name: str = Field(..., min_length=1, max_length=MAX_DISPLAY_NAME_LEN)
    member_addresses: List[str] = Field(..., min_length=1)

class GroupMemberResponse(BaseModel):
    user_address: str
    role: str
    joined_at: datetime
    user: Optional[UserResponse] = None

    model_config = ConfigDict(from_attributes=True)

class GroupChannelResponse(BaseModel):
    id: str
    name: str
    owner_address: str
    created_at: datetime
    members: List[GroupMemberResponse] = []

    model_config = ConfigDict(from_attributes=True)

class GroupMessageCreate(BaseModel):
    content: str = Field(..., max_length=50_000)

class GroupMessageResponse(BaseModel):
    id: int
    channel_id: str
    sender_address: str
    content: str
    created_at: datetime
    sender: Optional[UserResponse] = None

    model_config = ConfigDict(from_attributes=True)

class GroupConversationResponse(BaseModel):
    channel: GroupChannelResponse
    last_message: Optional[GroupMessageResponse] = None
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
    # E2EE name blob — same sizing rationale as GroupChannelCreate.name.
    name: str = Field(..., max_length=MAX_DISPLAY_NAME_LEN)

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse


class KeyTransferCreate(BaseModel):
    # Client-side-encrypted vault blob (JSON of {salt, iv, data}, all hex). The
    # server never sees the passphrase that decrypts it. Size-capped (config).
    ciphertext: str = Field(..., max_length=4_000_000)

class KeyTransferCreateResponse(BaseModel):
    id: str
    expires_at: datetime

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
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

