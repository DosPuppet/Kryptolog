"""add unique constraint to username

Revision ID: 4e7f2a1b9c3d
Revises: 3aaf73508a03
Create Date: 2026-02-17 18:56:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4e7f2a1b9c3d'
down_revision: Union[str, Sequence[str], None] = '3aaf73508a03'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.create_index('ix_users_username_unique', ['username'], unique=True)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index('ix_users_username_unique')
