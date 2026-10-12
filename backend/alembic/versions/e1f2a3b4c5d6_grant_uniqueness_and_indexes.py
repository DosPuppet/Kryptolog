"""One grant per (secret, grantee); the indexes access checks need; none they don't.

Three changes to the storage invariants, one migration:

- **`uq_access_grant_secret_grantee`** (audit 2026-09-23 F-1). Sharing deleted
  and re-inserted in two commits with no constraint behind it, so concurrent
  shares of one secret to one person left two rows, and revoking one left the
  other serving the key. Existing duplicates are collapsed to the NEWEST row
  first — that is the share the owner made last, which is the one the old
  delete-then-insert meant to keep.
- **Indexes on the foreign keys every check walks** (Q-3): grants by grantee,
  workflows by secret and by owner, secrets by owner, and memberships, signers
  and recipients by user. The existing unique constraints lead with the parent
  id, so "everything this user is part of" was a sequential scan.
- **No more `ix_<table>_id`** on primary keys, which already are unique
  indexes, and no index on `secrets.name` / `multisig_workflows.name`. Those
  hold encrypted blobs nothing can query, and PostgreSQL refuses a B-tree entry
  over ~8 KB: a secret with a long name was a 500 although the schema allows it.

Revision ID: e1f2a3b4c5d6
Revises: d0e1f2a3b4c5
Create Date: 2026-10-12
"""

from collections.abc import Sequence

from alembic import op

revision: str = "e1f2a3b4c5d6"
down_revision: str | Sequence[str] | None = "d0e1f2a3b4c5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (table, column) of each redundant primary-key index.
PK_INDEXES = (
    ("access_grants", "id"),
    ("file_chunks", "id"),
    ("group_members", "id"),
    ("group_messages", "id"),
    ("invite_codes", "code"),
    ("key_transfers", "id"),
    ("messages", "id"),
    ("multisig_workflow_recipients", "id"),
    ("multisig_workflow_signers", "id"),
    ("multisig_workflows", "id"),
    ("push_subscriptions", "id"),
    ("secrets", "id"),
    ("users", "address"),
)
BLOB_INDEXES = (("secrets", "name"), ("multisig_workflows", "name"))
NEW_INDEXES = (
    ("access_grants", "grantee_address"),
    ("group_members", "user_address"),
    ("multisig_workflow_recipients", "user_address"),
    ("multisig_workflow_signers", "user_address"),
    ("multisig_workflows", "owner_address"),
    ("multisig_workflows", "secret_id"),
    ("secrets", "owner_address"),
)
UNIQUE = "uq_access_grant_secret_grantee"


def upgrade() -> None:
    op.execute(
        """
        DELETE FROM access_grants older
        USING access_grants newer
        WHERE older.secret_id = newer.secret_id
          AND older.grantee_address = newer.grantee_address
          AND older.id < newer.id
        """
    )
    op.create_unique_constraint(UNIQUE, "access_grants", ["secret_id", "grantee_address"])

    for table, column in NEW_INDEXES:
        op.create_index(f"ix_{table}_{column}", table, [column])
    for table, column in PK_INDEXES:
        op.drop_index(f"ix_{table}_{column}", table_name=table)
    # if_exists: a downgrade does not restore these (see below), so a database
    # that went down and back up has none to drop.
    for table, column in BLOB_INDEXES:
        op.drop_index(f"ix_{table}_{column}", table_name=table, if_exists=True)


def downgrade() -> None:
    # The blob-name indexes are NOT restored: recreating one fails on the first
    # long name, which is the reason they were dropped.
    for table, column in PK_INDEXES:
        op.create_index(f"ix_{table}_{column}", table, [column])
    for table, column in NEW_INDEXES:
        op.drop_index(f"ix_{table}_{column}", table_name=table)
    op.drop_constraint(UNIQUE, "access_grants", type_="unique")
