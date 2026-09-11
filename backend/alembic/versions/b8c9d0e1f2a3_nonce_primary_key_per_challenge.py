"""Key login challenges by the nonce, not the address (audit H-1).

One row per address meant `GET /auth/nonce/{address}` — unauthenticated by
necessity, and keyed by a value the whole directory can read — overwrote
whichever challenge the legitimate owner was holding. A single request from a
stranger made a chosen user's in-flight login fail, repeatably and for free.

Keying on the nonce lets several challenges be outstanding for one address at
once, so a stranger's request adds a row rather than replacing someone else's.
`expires_at` is indexed because the lazy purge now runs against a table holding
more than one row per address.

The table is recreated rather than ALTERed: a login challenge lives five
minutes, so there is nothing to preserve, and a drop/create is unambiguous on
every backend where a primary-key swap is not. The only cost is that a login in
flight during the deploy has to ask for a fresh challenge.

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e5f6
Create Date: 2026-09-11
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b8c9d0e1f2a3"
down_revision: str | Sequence[str] | None = "a7b8c9d0e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_index("ix_nonces_address", table_name="nonces")
    op.drop_table("nonces")

    op.create_table(
        "nonces",
        sa.Column("nonce", sa.String(), nullable=False),
        sa.Column("address", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("nonce"),
    )
    op.create_index(op.f("ix_nonces_address"), "nonces", ["address"], unique=False)
    op.create_index(op.f("ix_nonces_expires_at"), "nonces", ["expires_at"], unique=False)


def downgrade() -> None:
    # Going back reinstates the one-challenge-per-address constraint, so the
    # rows cannot be carried over: two live challenges for one address have no
    # representation in the old shape.
    op.drop_index(op.f("ix_nonces_expires_at"), table_name="nonces")
    op.drop_index(op.f("ix_nonces_address"), table_name="nonces")
    op.drop_table("nonces")

    op.create_table(
        "nonces",
        sa.Column("address", sa.String(), nullable=False),
        sa.Column("nonce", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("address"),
    )
    op.create_index(op.f("ix_nonces_address"), "nonces", ["address"], unique=False)
