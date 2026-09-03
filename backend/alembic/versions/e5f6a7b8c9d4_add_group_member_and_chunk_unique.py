"""add unique constraints to group members and file chunks

Revision ID: e5f6a7b8c9d4
Revises: d4e5f6a7b8c3
Create Date: 2026-09-02

Audit M-1 / M-2. Two tables were missing the uniqueness the application
assumes, both confirmed reproducible against a real database:

  group_members (channel_id, user_address)
    `add_member` checks membership then inserts, non-atomically, and
    `remove_member` deleted only the first matching row. A duplicate row
    therefore survives removal and the "removed" member keeps read and write
    access to the channel.

  file_chunks (secret_id, chunk_index)
    `upload_chunk` never checked the index. Two uploads at index 0 both
    succeeded, and reads returned whichever row PostgreSQL listed first —
    non-deterministic, so a file could reassemble differently on each
    download with nothing reporting an error.

Pre-existing duplicates are collapsed (lowest id wins) before each constraint
is added, so this is safe on a populated database. Collapsing file_chunks is
lossy by nature — a duplicated index means one of the two payloads was always
going to be discarded; keeping the earliest is the same row a read would most
likely have returned before.
"""
from alembic import op
import sqlalchemy as sa

revision = 'e5f6a7b8c9d4'
down_revision = 'd4e5f6a7b8c3'
branch_labels = None
depends_on = None


# (table, columns, constraint name) — collapsed then constrained, in order.
_TARGETS = (
    ("group_members", ("channel_id", "user_address"), "uq_group_member_channel_user"),
    ("file_chunks", ("secret_id", "chunk_index"), "uq_file_chunk_secret_index"),
)


def upgrade():
    # Correlated MIN(id) subquery rather than DELETE ... USING, so this runs on
    # both PostgreSQL and SQLite (database.py supports either) — same approach
    # as migration c3d4e5f6a7b2.
    for table, columns, name in _TARGETS:
        group_by = ", ".join(columns)
        op.execute(
            f"""
            DELETE FROM {table}
            WHERE id NOT IN (
                SELECT MIN(id) FROM {table}
                GROUP BY {group_by}
            )
            """
        )
        op.create_unique_constraint(name, table, list(columns))


def downgrade():
    for table, _columns, name in reversed(_TARGETS):
        op.drop_constraint(name, table, type_="unique")
