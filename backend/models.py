from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime, Boolean
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime, timezone

Base = declarative_base()

class Nonce(Base):
    __tablename__ = "nonces"

    address = Column(String, primary_key=True, index=True) # Address associated with nonce
    nonce = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)

class User(Base):
    __tablename__ = "users"

    address = Column(String, primary_key=True, index=True) # Ethereum address (lowercase)
    username = Column(String, nullable=True, unique=True)
    encryption_public_key = Column(String, nullable=True) # For eth_decrypt
    # Bumped on logout / revoke-all; JWTs carry the version they were minted with
    # and are rejected once it no longer matches (token revocation).
    token_version = Column(Integer, nullable=False, default=0, server_default="0")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    secrets = relationship("Secret", back_populates="owner")
    access_grants = relationship("AccessGrant", back_populates="grantee")

class Secret(Base):
    __tablename__ = "secrets"

    id = Column(Integer, primary_key=True, index=True)
    owner_address = Column(String, ForeignKey("users.address"))
    name = Column(String, index=True)
    type = Column(String, default="standard") # 'standard' | 'file' | 'signed_document'
    encrypted_data = Column(Text) # AES-encrypted content or file metadata JSON
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    owner = relationship("User", back_populates="secrets")
    access_grants = relationship("AccessGrant", back_populates="secret")
    chunks = relationship("FileChunk", back_populates="secret", cascade="all, delete-orphan")

class AccessGrant(Base):
    __tablename__ = "access_grants"

    id = Column(Integer, primary_key=True, index=True)
    secret_id = Column(Integer, ForeignKey("secrets.id"))
    grantee_address = Column(String, ForeignKey("users.address"))
    encrypted_key = Column(Text) # The secret's key, encrypted for the grantee's public key
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=True)

    secret = relationship("Secret", back_populates="access_grants")
    grantee = relationship("User", back_populates="access_grants")

class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)
    owner_address = Column(String, ForeignKey("users.address"))
    name = Column(String)
    content_hash = Column(String) # Hash of the document content
    signature = Column(String) # The user's signature of the hash
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    owner = relationship("User", back_populates="documents")


class MultisigWorkflow(Base):
    __tablename__ = "multisig_workflows"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    owner_address = Column(String, ForeignKey("users.address"))
    secret_id = Column(Integer, ForeignKey("secrets.id"))
    status = Column(String, default="pending") # 'pending', 'completed', 'rejected'
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    owner = relationship("User", back_populates="workflows")
    secret = relationship("Secret")
    signers = relationship("MultisigWorkflowSigner", back_populates="workflow")
    recipients = relationship("MultisigWorkflowRecipient", back_populates="workflow")

class MultisigWorkflowSigner(Base):
    __tablename__ = "multisig_workflow_signers"

    id = Column(Integer, primary_key=True, index=True)
    workflow_id = Column(Integer, ForeignKey("multisig_workflows.id"))
    user_address = Column(String, ForeignKey("users.address"))
    has_signed = Column(Boolean, default=False)
    signature = Column(Text, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    encrypted_key = Column(Text, nullable=True)  # Signer-scoped key (separate from AccessGrant)

    workflow = relationship("MultisigWorkflow", back_populates="signers")
    user = relationship("User")

class MultisigWorkflowRecipient(Base):
    __tablename__ = "multisig_workflow_recipients"

    id = Column(Integer, primary_key=True, index=True)
    workflow_id = Column(Integer, ForeignKey("multisig_workflows.id"))
    user_address = Column(String, ForeignKey("users.address"))
    encrypted_key = Column(Text) # Key encrypted for THIS recipient, held until release

    workflow = relationship("MultisigWorkflow", back_populates="recipients")
    user = relationship("User")


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_address = Column(String, ForeignKey("users.address"), index=True)
    recipient_address = Column(String, ForeignKey("users.address"), index=True)
    content = Column(Text) # Encrypted Blob
    is_read = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    sender = relationship("User", foreign_keys=[sender_address], back_populates="sent_messages")
    recipient = relationship("User", foreign_keys=[recipient_address], back_populates="received_messages")

# Relationships added post-definition to avoid forward-reference issues
User.documents = relationship("Document", back_populates="owner")
User.workflows = relationship("MultisigWorkflow", back_populates="owner")
User.sent_messages = relationship("Message", foreign_keys=[Message.sender_address], back_populates="sender")
User.received_messages = relationship("Message", foreign_keys=[Message.recipient_address], back_populates="recipient")

class FileChunk(Base):
    __tablename__ = "file_chunks"

    id = Column(Integer, primary_key=True, index=True)
    secret_id = Column(Integer, ForeignKey("secrets.id"), index=True)
    chunk_index = Column(Integer)  # 0-based ordering
    encrypted_data = Column(Text)  # AES-GCM encrypted chunk (hex)
    iv = Column(String)            # Per-chunk IV (hex)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    secret = relationship("Secret", back_populates="chunks")


# ── Group Channels ──────────────────────────────────────────────

class GroupChannel(Base):
    __tablename__ = "group_channels"

    id = Column(String, primary_key=True)  # UUID (generated client-side)
    name = Column(String, nullable=False)
    owner_address = Column(String, ForeignKey("users.address"))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    owner = relationship("User")
    members = relationship("GroupMember", back_populates="channel", cascade="all, delete-orphan")
    messages = relationship("GroupMessage", back_populates="channel", cascade="all, delete-orphan")


class GroupMember(Base):
    __tablename__ = "group_members"

    id = Column(Integer, primary_key=True, index=True)
    channel_id = Column(String, ForeignKey("group_channels.id"), index=True)
    user_address = Column(String, ForeignKey("users.address"))
    role = Column(String, default="member")  # "owner" | "admin" | "member"
    joined_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    channel = relationship("GroupChannel", back_populates="members")
    user = relationship("User")


class GroupMessage(Base):
    __tablename__ = "group_messages"

    id = Column(Integer, primary_key=True, index=True)
    channel_id = Column(String, ForeignKey("group_channels.id"), index=True)
    sender_address = Column(String, ForeignKey("users.address"), index=True)
    content = Column(Text)  # Encrypted blob (v2 payload)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    channel = relationship("GroupChannel", back_populates="messages")
    sender = relationship("User")

class PushSubscription(Base):
    __tablename__ = "push_subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    user_address = Column(String, ForeignKey("users.address"), index=True)
    endpoint = Column(Text, nullable=False)
    p256dh = Column(String, nullable=False)
    auth = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="push_subscriptions")

User.push_subscriptions = relationship("PushSubscription", back_populates="user", cascade="all, delete-orphan")
