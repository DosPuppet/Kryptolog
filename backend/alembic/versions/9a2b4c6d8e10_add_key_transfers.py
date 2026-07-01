"""add key_transfers (device-to-device key transfer relay)

Revision ID: 9a2b4c6d8e10
Revises: 8f1a2b3c4d50
Create Date: 2026-06-12 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9a2b4c6d8e10'
down_revision: Union[str, Sequence[str], None] = '8f1a2b3c4d50'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'key_transfers',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('ciphertext', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_key_transfers_id'), 'key_transfers', ['id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_key_transfers_id'), table_name='key_transfers')
    op.drop_table('key_transfers')
