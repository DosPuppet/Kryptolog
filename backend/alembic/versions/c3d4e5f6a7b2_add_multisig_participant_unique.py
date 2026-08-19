"""add unique constraints to multisig participants

Revision ID: c3d4e5f6a7b2
Revises: b2c3d4e5f6a1
Create Date: 2026-08-19

KRY-005 hardening: a signer or recipient must appear at most once per
workflow. Without this, a duplicate signer row lets one identity contribute
two signatures toward a quorum, which silently weakens an N-of-M policy.
The application already avoids creating duplicates; this makes it an
invariant the database enforces, so a concurrent insert cannot slip past.

Pre-existing duplicates are collapsed (lowest id wins) before the constraint
is added, so the migration is safe on a populated database.
"""
from alembic import op
import sqlalchemy as sa

revision = 'c3d4e5f6a7b2'
down_revision = 'b2c3d4e5f6a1'
branch_labels = None
depends_on = None


def upgrade():
    # Collapse any existing duplicates first — keep the earliest row. Written
    # as a correlated subquery rather than DELETE ... USING so it runs on both
    # PostgreSQL and SQLite (database.py supports either).
    for table in ("multisig_workflow_signers", "multisig_workflow_recipients"):
        op.execute(
            f"""
            DELETE FROM {table}
            WHERE id NOT IN (
                SELECT MIN(id) FROM {table}
                GROUP BY workflow_id, user_address
            )
            """
        )

    op.create_unique_constraint(
        "uq_multisig_signer_workflow_user",
        "multisig_workflow_signers",
        ["workflow_id", "user_address"],
    )
    op.create_unique_constraint(
        "uq_multisig_recipient_workflow_user",
        "multisig_workflow_recipients",
        ["workflow_id", "user_address"],
    )


def downgrade():
    op.drop_constraint(
        "uq_multisig_recipient_workflow_user",
        "multisig_workflow_recipients",
        type_="unique",
    )
    op.drop_constraint(
        "uq_multisig_signer_workflow_user",
        "multisig_workflow_signers",
        type_="unique",
    )
