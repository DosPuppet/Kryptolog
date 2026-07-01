"""add multisig threshold + reject columns (N-of-M)

Revision ID: a1b2c3d4e5f0
Revises: 9a2b4c6d8e10
Create Date: 2026-07-01 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f0'
down_revision: Union[str, Sequence[str], None] = '9a2b4c6d8e10'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('multisig_workflows', schema=None) as batch_op:
        # N in N-of-M; NULL is treated as N-of-N (= number of signers) by the app.
        batch_op.add_column(sa.Column('threshold', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('rejected_by', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('rejected_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('multisig_workflows', schema=None) as batch_op:
        batch_op.drop_column('rejected_at')
        batch_op.drop_column('rejected_by')
        batch_op.drop_column('threshold')
