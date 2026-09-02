from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime, Boolean, UniqueConstraint, Index, func
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

    address = Column(String, primary_key=True, index=True) # Identity public key (ML-DSA-44, lowercase hex)
    username = Column(String, nullable=True, unique=True)
    encryption_public_key = Column(String, nullable=True) # ML-KEM-768 public key (hex)
    # Stamped whenever encryption_public_key changes for an existing identity
    # (audit S1: key-directory transparency). Lets clients surface "this contact's
    # key changed on <date>" and detect a malicious/compromised key swap.
    key_changed_at = Column(DateTime, nullable=True)
    # Self-signed binding of encryption_public_key to this identity (audit M-1):
    # an ML-DSA-44 signature (hex) by `address` over the domain-separated
    # key-attestation message. Peers verify it client-side before wrapping keys
    # to this user, so the directory can't substitute a KEM key it controls.
    # Null = account predates attestations (clients show "unverified").
    encryption_key_attestation = Column(Text, nullable=True)
    # Bumped on logout / revoke-all; JWTs carry the version they were minted with
    # and are rejected once it no longer matches (token revocation).
    token_version = Column(Integer, nullable=False, default=0, server_default="0")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Usernames are unique case-INSENSITIVELY: the column's own `unique=True` is
    # case-sensitive on PostgreSQL, which would let "alice" and "Alice" exist as
    # two identities — impersonation in a directory people pick recipients from.
    # Matches migration d4e5f6a7b8c3 and the lower() predicate in
    # security/usernames.py.
    __table_args__ = (
        Index("ix_users_username_lower_unique", func.lower(username), unique=True),
    )

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
    threshold = Column(Integer, nullable=True) # N in N-of-M; NULL ⇒ N-of-N (= len(signers))
    rejected_by = Column(String, nullable=True) # address of the signer who rejected
    rejected_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    owner = relationship("User", back_populates="workflows")
    secret = relationship("Secret")
    signers = relationship("MultisigWorkflowSigner", back_populates="workflow")
    recipients = relationship("MultisigWorkflowRecipient", back_populates="workflow")

class MultisigWorkflowSigner(Base):
    __tablename__ = "multisig_workflow_signers"
    # One row per (workflow, signer): a duplicate would let a single identity
    # contribute two signatures toward a quorum (KRY-005).
    __table_args__ = (
        UniqueConstraint("workflow_id", "user_address",
                         name="uq_multisig_signer_workflow_user"),
    )

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
    __table_args__ = (
        UniqueConstraint("workflow_id", "user_address",
                         name="uq_multisig_recipient_workflow_user"),
    )

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
    # One row per (secret, index). Without this a second upload at an index the
    # file already has is accepted, `GET .../chunks/{i}` then returns whichever
    # row PostgreSQL happens to hand back first, and the reassembled file is
    # silently wrong — corruption with no error anywhere (audit M-2).
    __table_args__ = (
        UniqueConstraint("secret_id", "chunk_index",
                         name="uq_file_chunk_secret_index"),
    )

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
    # One row per (channel, member) — the same invariant MultisigWorkflowSigner
    # gets for the symmetric reason (KRY-005). Without it, `add_member`'s
    # read-then-write check races, and a duplicate row survives removal because
    # the delete only ever matched one: the "removed" member keeps read/write
    # access to the channel (audit M-1). An admin can also do this deliberately
    # — double-add an accomplice, then publicly "remove" them.
    __table_args__ = (
        UniqueConstraint("channel_id", "user_address",
                         name="uq_group_member_channel_user"),
    )

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

class InviteCode(Base):
    """Access filter (audit §5). When invites are required (config.invites_required),
    creating a brand-new identity at first login consumes one valid code. Existing
    users are unaffected — the gate covers account *creation* only. Codes can be
    admin-seeded (created_by NULL) or minted by existing users, single- or
    multi-use, and optionally time-limited."""
    __tablename__ = "invite_codes"

    code = Column(String, primary_key=True, index=True)
    # NULL when admin-seeded (e.g. via generate_invites.py); otherwise the address
    # of the existing user who minted it (enrollment / referral).
    created_by = Column(String, ForeignKey("users.address"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    # Optional expiry (naive UTC, matching how the rest of the app stores/reads).
    expires_at = Column(DateTime, nullable=True)
    # Usage accounting. max_uses=1 ⇒ single-use (the safe default).
    max_uses = Column(Integer, nullable=False, default=1, server_default="1")
    uses = Column(Integer, nullable=False, default=0, server_default="0")
    # Last consumer (for multi-use codes this records the most recent redeemer).
    used_by = Column(String, ForeignKey("users.address"), nullable=True)
    used_at = Column(DateTime, nullable=True)


class KeyTransfer(Base):
    """One-time encrypted vault relay for device-to-device key transfer.

    Zero-knowledge: stores only the client-side-encrypted vault blob (AES-GCM
    under a transfer passphrase the server never sees) plus a random id. The id
    + passphrase are carried out of band (QR / short code) to the target device,
    which fetches once (single-use: the row is deleted on read) within a short
    TTL. Never holds plaintext or the passphrase."""
    __tablename__ = "key_transfers"

    id = Column(String, primary_key=True, index=True)  # random pickup id
    ciphertext = Column(Text, nullable=False)          # encrypted vault blob (JSON)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)


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
