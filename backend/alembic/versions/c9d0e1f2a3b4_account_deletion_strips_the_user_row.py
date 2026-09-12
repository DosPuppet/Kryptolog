"""Account deletion strips the user row instead of removing it.

Two columns on `users`. `deleted_at` marks an identity that has been deleted —
its username, encryption key and attestation are NULLed at the same time, so
what remains is the address and nothing else. `blocked` distinguishes the two
deletion modes: "leave" sets only `deleted_at` and can be undone by logging in
again, while "erase" also sets `blocked` and the key may never register again.

Why the row survives at all: `users.address` is referenced by nine other
tables, and both modes deliberately leave rows behind that still name it —
messages other people still read, and signatures the owner of someone else's
multisig workflow depends on. Removing the row would mean dropping those
foreign keys, and SQLAlchemy's `db.delete(instance)` would first NULL the very
`sender_address` / `owner_address` columns those retained signatures verify
against. The address is an ML-DSA public key that is already embedded in every
message the identity signed, so keeping it here reveals nothing new.

`blocked` carries a server_default so existing rows are backfilled as active;
`deleted_at` is nullable with NULL meaning active, which is what every existing
row already is.

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
Create Date: 2026-09-12
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c9d0e1f2a3b4"
down_revision: str | Sequence[str] | None = "b8c9d0e1f2a3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("deleted_at", sa.DateTime(), nullable=True))
    op.add_column(
        "users",
        sa.Column("blocked", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("users", "blocked")
    op.drop_column("users", "deleted_at")
