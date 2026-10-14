"""encryption_key_rotations: signed records of an identity replacing its key.

crypto-core 5.1.0 (lot 12f). Additive: one new table, nothing existing moves.
Each row is "the key with id old_kid is replaced by new_kid, as of ts",
signed by the identity, as POST /account/encryption-key/rotate accepted it.

Revision ID: d6e7f8a9b0c1
Revises: c5d6e7f8a9b0
Create Date: 2026-10-14
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d6e7f8a9b0c1"
down_revision: str | Sequence[str] | None = "c5d6e7f8a9b0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "encryption_key_rotations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_address", sa.String(), sa.ForeignKey("users.address"), nullable=False
        ),
        sa.Column("old_kid", sa.String(length=32), nullable=False),
        sa.Column("new_kid", sa.String(length=32), nullable=False),
        sa.Column("alg", sa.String(length=64), nullable=False),
        sa.Column("ts", sa.BigInteger(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("old_kid ~ '^[0-9a-f]{32}$'", name="ck_key_rotations_old_kid"),
        sa.CheckConstraint("new_kid ~ '^[0-9a-f]{32}$'", name="ck_key_rotations_new_kid"),
    )
    op.create_index(
        "ix_encryption_key_rotations_user_address", "encryption_key_rotations", ["user_address"]
    )


def downgrade() -> None:
    op.drop_index("ix_encryption_key_rotations_user_address", table_name="encryption_key_rotations")
    op.drop_table("encryption_key_rotations")
