"""drop the unused documents table

Revision ID: a7b8c9d0e5f6
Revises: f6a7b8c9d0e5
Create Date: 2026-09-03 09:10:00.000000

The /documents endpoints (audit L-10) had no client: nothing in the SPA or the
extension ever called them. What they did have was POST /documents accepting an
arbitrary `content_hash` and `signature` with no verification of either and no
rate limit — an authenticated write endpoint that stored unvalidated attacker
text under the user's name.

Deleting beats hardening here: there is no feature to preserve, so validating
and rate-limiting it would be work spent keeping an unused attack surface.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7b8c9d0e5f6'
down_revision: Union[str, Sequence[str], None] = 'f6a7b8c9d0e5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_table('documents')


def downgrade() -> None:
    """Downgrade schema."""
    op.create_table(
        'documents',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('owner_address', sa.String(), nullable=True),
        sa.Column('name', sa.String(), nullable=True),
        sa.Column('content_hash', sa.String(), nullable=True),
        sa.Column('signature', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['owner_address'], ['users.address'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_documents_id'), 'documents', ['id'], unique=False)
