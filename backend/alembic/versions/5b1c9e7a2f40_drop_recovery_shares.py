"""drop recovery_shares (MPC recovery removed)

The Google-ID / MPC recovery feature was never wired up (no router, no Google
ID-token verification) and is being removed. This drops its dormant table.

Revision ID: 5b1c9e7a2f40
Revises: 4e7f2a1b9c3d
Create Date: 2026-06-04 11:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5b1c9e7a2f40'
down_revision: Union[str, Sequence[str], None] = '4e7f2a1b9c3d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Drop the dormant recovery_shares table."""
    op.drop_table('recovery_shares')


def downgrade() -> None:
    """Recreate recovery_shares (schema only; feature is gone)."""
    op.create_table(
        'recovery_shares',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('google_id', sa.String(), nullable=True),
        sa.Column('share_data', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('recovery_shares', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_recovery_shares_google_id'), ['google_id'], unique=True)
        batch_op.create_index(batch_op.f('ix_recovery_shares_id'), ['id'], unique=False)
