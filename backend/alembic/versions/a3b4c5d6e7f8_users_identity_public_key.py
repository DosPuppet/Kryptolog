"""`users.identity_public_key`: the key an address names, stored apart from it.

Until now an address WAS the identity's ML-DSA-44 public key, and every
signature check verified against the address itself. crypto-core 4 makes the
identity key a composite (ML-DSA-65 + Ed25519, 1 984 bytes) and the address a
hash of it (audit 2026-10-12 K-10), so the server needs the key in a column of
its own and every verifier needs to read it from there.

This revision only introduces the column, with the 3.x meaning: every existing
row's key is its address, which is exactly what it was. The 4.0.0 cutover
revision is the one that changes what may be stored in it.

Kept on account deletion, unlike the encryption key: readers still verify a
deleted identity's messages and redactions, and that needs the key.

Revision ID: a3b4c5d6e7f8
Revises: f2a3b4c5d6e7
Create Date: 2026-10-13
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a3b4c5d6e7f8"
down_revision: str | Sequence[str] | None = "f2a3b4c5d6e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("identity_public_key", sa.String(), nullable=True))
    op.execute("UPDATE users SET identity_public_key = address")
    op.alter_column("users", "identity_public_key", nullable=False)


def downgrade() -> None:
    op.drop_column("users", "identity_public_key")
