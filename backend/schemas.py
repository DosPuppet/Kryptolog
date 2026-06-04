from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List
from datetime import datetime

class UserBase(BaseModel):
    address: str = Field(..., max_length=20000)

class UserCreate(UserBase):
    encryption_public_key: str = Field(..., max_length=20000)

class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, max_length=200)

class UserResponse(UserBase):
    username: Optional[str]
    encryption_public_key: Optional[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class SecretBase(BaseModel):
    name: str = Field(..., max_length=200)
    type: str = Field("standard") # 'standard' | 'signed_document'
    # 500KB limit for SecretBase.encrypted_data. Large files use FileChunks.
    encrypted_data: str = Field(..., max_length=500_000)
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
    grantee_address: str = Field(..., max_length=20000)
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
    address: str = Field(..., max_length=20000)
    signature: str = Field(..., max_length=64_000)
    nonce: str = Field(..., max_length=200)
    encryption_public_key: Optional[str] = Field(None, max_length=20000)
    username: Optional[str] = Field(None, max_length=200)

class MultisigWorkflowBase(BaseModel):
    name: str = Field(..., max_length=200)

class MultisigWorkflowCreate(MultisigWorkflowBase):
    secret_data: SecretCreate # Embedded secret creation
    signers: List[str] # List of addresses
    recipients: List[str] # List of addresses
    signer_keys: dict[str, str] # map address -> encrypted_key
    recipient_keys: dict[str, str] # map address -> encrypted_key

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
    recipient_keys: Optional[dict[str, str]] = None # Only provided by the last signer

class MessageBase(BaseModel):
    recipient_address: str = Field(..., max_length=20000)
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
    name: str = Field(..., min_length=1, max_length=100)
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
    name: str = Field(..., max_length=20000)

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse


class PushSubscriptionCreate(BaseModel):
    endpoint: str
    p256dh: str
    auth: str

class PushSubscriptionResponse(PushSubscriptionCreate):
    id: int
    user_address: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

