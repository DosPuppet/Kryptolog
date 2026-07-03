"""add users.encryption_key_attestation (audit M-1: self-signed KEM key binding)

Revision ID: b2c3d4e5f6a1
Revises: a1b2c3d4e5f0
Create Date: 2026-07-03 17:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6a1'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        # ML-DSA-44 signature (hex) by the user's own identity key over the
        # domain-separated key-attestation message binding their ML-KEM key.
        # Nullable: accounts predating attestations show as "unverified".
        batch_op.add_column(sa.Column('encryption_key_attestation', sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('encryption_key_attestation')
