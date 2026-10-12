"""Per-user "delete this conversation": a hide marker, not a deletion.

`conversation_clears` records, for one user and one conversation (a DM partner
or a group), the last message id that user no longer wants to see. The rows
themselves stay — the other side's copy is theirs — and erasing one's own
messages is a separate, signed operation. Audit 2026-09-11 M-6.

Revision ID: f2a3b4c5d6e7
Revises: e1f2a3b4c5d6
Create Date: 2026-10-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f2a3b4c5d6e7"
down_revision: str | Sequence[str] | None = "e1f2a3b4c5d6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "conversation_clears",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_address", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("conversation", sa.String(), nullable=False),
        sa.Column("cleared_through_id", sa.Integer(), nullable=False),
        sa.Column("cleared_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("kind IN ('dm', 'group')", name="ck_conversation_clears_kind"),
        sa.ForeignKeyConstraint(["user_address"], ["users.address"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "user_address", "kind", "conversation", name="uq_conversation_clear_user_conv"
        ),
    )


def downgrade() -> None:
    op.drop_table("conversation_clears")
