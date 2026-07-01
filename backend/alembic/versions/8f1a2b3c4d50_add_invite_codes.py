"""add invite_codes (access filter, audit §5)

Revision ID: 8f1a2b3c4d50
Revises: 7d3e9a4b1f20
Create Date: 2026-06-12 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8f1a2b3c4d50'
down_revision: Union[str, Sequence[str], None] = '7d3e9a4b1f20'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'invite_codes',
        sa.Column('code', sa.String(), nullable=False),
        sa.Column('created_by', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('max_uses', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('uses', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('used_by', sa.String(), nullable=True),
        sa.Column('used_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.address']),
        sa.ForeignKeyConstraint(['used_by'], ['users.address']),
        sa.PrimaryKeyConstraint('code'),
    )
    op.create_index(op.f('ix_invite_codes_code'), 'invite_codes', ['code'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_invite_codes_code'), table_name='invite_codes')
    op.drop_table('invite_codes')
