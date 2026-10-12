"""A secret's `type` is one of three values, and nothing else.

The column was free text with no bound. The request model now only accepts
"standard", "file" or "signed_document" (audit 2026-09-23 M-3: four megabytes in
`type` were accepted, stored, and returned in every list response, including
other users' shared and multisig lists). This makes the database say the same.

Existing rows outside the three values are reset to "standard" first, because
the constraint cannot be added over them. None of the shipped clients ever wrote
anything else, so on a database that saw no abuse this updates nothing. What is
lost on one that did is only the oversized label; content and keys are untouched.

The constraint is skipped on SQLite, which cannot ALTER TABLE ADD CONSTRAINT.

Revision ID: d0e1f2a3b4c5
Revises: c9d0e1f2a3b4
Create Date: 2026-10-12
"""

from collections.abc import Sequence

from alembic import op

revision: str = "d0e1f2a3b4c5"
down_revision: str | Sequence[str] | None = "c9d0e1f2a3b4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TYPES = ("standard", "file", "signed_document")
CONSTRAINT = "ck_secrets_type"


def upgrade() -> None:
    allowed = ", ".join(f"'{t}'" for t in TYPES)
    op.execute(
        f"UPDATE secrets SET type = 'standard' WHERE type IS NULL OR type NOT IN ({allowed})"
    )
    if op.get_bind().dialect.name != "sqlite":
        op.create_check_constraint(CONSTRAINT, "secrets", f"type IN ({allowed})")


def downgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        op.drop_constraint(CONSTRAINT, "secrets", type_="check")
