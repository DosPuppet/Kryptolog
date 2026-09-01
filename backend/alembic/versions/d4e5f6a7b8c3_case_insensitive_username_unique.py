"""case-insensitive unique usernames

Revision ID: d4e5f6a7b8c3
Revises: c3d4e5f6a7b2
Create Date: 2026-09-01 11:20:00.000000

The existing `ix_users_username_unique` is a plain btree on the raw column, so
on PostgreSQL it is case-SENSITIVE: "alice", "Alice" and "ALICE" could all be
registered at once. In a messenger where recipients are chosen from a directory
search that is a display-name impersonation vector, so uniqueness moves to
lower(username).

The old index is left in place — a functional unique index on lower(username)
is strictly stronger, so the two never disagree, and keeping it avoids an
unnecessary drop/recreate on a live table.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4e5f6a7b8c3'
down_revision: Union[str, Sequence[str], None] = 'c3d4e5f6a7b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _colliding_usernames(conn) -> list[str]:
    """Existing usernames that differ only by case — these block the index."""
    rows = conn.execute(sa.text(
        """
        SELECT lower(username) AS name
        FROM users
        WHERE username IS NOT NULL
        GROUP BY lower(username)
        HAVING count(*) > 1
        ORDER BY name
        """
    ))
    return [row.name for row in rows]


def upgrade() -> None:
    """Upgrade schema."""
    conn = op.get_bind()

    # Fail loudly rather than picking a winner: renaming somebody's display
    # name is an operator decision, not a migration's. The message names the
    # exact rows to resolve.
    collisions = _colliding_usernames(conn)
    if collisions:
        raise RuntimeError(
            "Cannot enforce case-insensitive usernames: these names are held by "
            "more than one account, differing only by case — "
            f"{', '.join(collisions)}. Rename all but one holder of each "
            "(UPDATE users SET username = ... WHERE address = ...), then re-run "
            "this migration."
        )

    op.create_index(
        'ix_users_username_lower_unique',
        'users',
        [sa.text('lower(username)')],
        unique=True,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_users_username_lower_unique', table_name='users')
