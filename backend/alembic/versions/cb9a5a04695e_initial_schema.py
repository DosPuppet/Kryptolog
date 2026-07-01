"""initial schema

Revision ID: cb9a5a04695e
Revises: 
Create Date: 2026-02-11 10:31:42.840878

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cb9a5a04695e'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""

    # ── Core tables ──────────────────────────────────────────────

    op.create_table('users',
        sa.Column('address', sa.String(), nullable=False),
        sa.Column('username', sa.String(), nullable=True),
        sa.Column('encryption_public_key', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('address')
    )
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_users_address'), ['address'], unique=False)

    op.create_table('nonces',
        sa.Column('address', sa.String(), nullable=False),
        sa.Column('nonce', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('address')
    )
    with op.batch_alter_table('nonces', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_nonces_address'), ['address'], unique=False)

    # ── Secrets & Access ─────────────────────────────────────────

    op.create_table('secrets',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('owner_address', sa.String(), nullable=True),
        sa.Column('name', sa.String(), nullable=True),
        sa.Column('type', sa.String(), nullable=True),
        sa.Column('encrypted_data', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['owner_address'], ['users.address']),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('secrets', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_secrets_id'), ['id'], unique=False)
        batch_op.create_index(batch_op.f('ix_secrets_name'), ['name'], unique=False)

    op.create_table('access_grants',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('secret_id', sa.Integer(), nullable=True),
        sa.Column('grantee_address', sa.String(), nullable=True),
        sa.Column('encrypted_key', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['grantee_address'], ['users.address']),
        sa.ForeignKeyConstraint(['secret_id'], ['secrets.id']),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('access_grants', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_access_grants_id'), ['id'], unique=False)

    op.create_table('file_chunks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('secret_id', sa.Integer(), nullable=True),
        sa.Column('chunk_index', sa.Integer(), nullable=True),
        sa.Column('encrypted_data', sa.Text(), nullable=True),
        sa.Column('iv', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['secret_id'], ['secrets.id']),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('file_chunks', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_file_chunks_id'), ['id'], unique=False)
        batch_op.create_index(batch_op.f('ix_file_chunks_secret_id'), ['secret_id'], unique=False)

    # ── Documents ────────────────────────────────────────────────

    op.create_table('documents',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('owner_address', sa.String(), nullable=True),
        sa.Column('name', sa.String(), nullable=True),
        sa.Column('content_hash', sa.String(), nullable=True),
        sa.Column('signature', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['owner_address'], ['users.address']),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_documents_id'), ['id'], unique=False)

    # ── Multisig ─────────────────────────────────────────────────

    op.create_table('multisig_workflows',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=True),
        sa.Column('owner_address', sa.String(), nullable=True),
        sa.Column('secret_id', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['owner_address'], ['users.address']),
        sa.ForeignKeyConstraint(['secret_id'], ['secrets.id']),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('multisig_workflows', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_multisig_workflows_id'), ['id'], unique=False)
        batch_op.create_index(batch_op.f('ix_multisig_workflows_name'), ['name'], unique=False)

    op.create_table('multisig_workflow_signers',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('workflow_id', sa.Integer(), nullable=True),
        sa.Column('user_address', sa.String(), nullable=True),
        sa.Column('has_signed', sa.Boolean(), nullable=True),
        sa.Column('signature', sa.Text(), nullable=True),
        sa.Column('signed_at', sa.DateTime(), nullable=True),
        sa.Column('encrypted_key', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['user_address'], ['users.address']),
        sa.ForeignKeyConstraint(['workflow_id'], ['multisig_workflows.id']),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('multisig_workflow_signers', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_multisig_workflow_signers_id'), ['id'], unique=False)

    op.create_table('multisig_workflow_recipients',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('workflow_id', sa.Integer(), nullable=True),
        sa.Column('user_address', sa.String(), nullable=True),
        sa.Column('encrypted_key', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['user_address'], ['users.address']),
        sa.ForeignKeyConstraint(['workflow_id'], ['multisig_workflows.id']),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('multisig_workflow_recipients', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_multisig_workflow_recipients_id'), ['id'], unique=False)

    # ── Messenger ────────────────────────────────────────────────

    op.create_table('messages',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('sender_address', sa.String(), nullable=True),
        sa.Column('recipient_address', sa.String(), nullable=True),
        sa.Column('content', sa.Text(), nullable=True),
        sa.Column('is_read', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['recipient_address'], ['users.address']),
        sa.ForeignKeyConstraint(['sender_address'], ['users.address']),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('messages', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_messages_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_messages_id'), ['id'], unique=False)
        batch_op.create_index(batch_op.f('ix_messages_is_read'), ['is_read'], unique=False)
        batch_op.create_index(batch_op.f('ix_messages_recipient_address'), ['recipient_address'], unique=False)
        batch_op.create_index(batch_op.f('ix_messages_sender_address'), ['sender_address'], unique=False)

    # ── Recovery ─────────────────────────────────────────────────

    op.create_table('recovery_shares',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('google_id', sa.String(), nullable=True),
        sa.Column('share_data', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('recovery_shares', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_recovery_shares_google_id'), ['google_id'], unique=True)
        batch_op.create_index(batch_op.f('ix_recovery_shares_id'), ['id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('recovery_shares')
    op.drop_table('messages')
    op.drop_table('multisig_workflow_recipients')
    op.drop_table('multisig_workflow_signers')
    op.drop_table('multisig_workflows')
    op.drop_table('documents')
    op.drop_table('file_chunks')
    op.drop_table('access_grants')
    op.drop_table('secrets')
    op.drop_table('nonces')
    op.drop_table('users')
