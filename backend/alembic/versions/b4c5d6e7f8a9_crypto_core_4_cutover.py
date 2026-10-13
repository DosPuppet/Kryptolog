"""crypto-core 4.0.0: hybrid keys, hashed addresses — a clean cutover.

Every identity becomes a composite ML-DSA-65 + Ed25519 key, every address the
SHA-384 of one, every encryption key an X-Wing key (audit 2026-10-12 K-10).
Nothing written before can be read after: a 3.x address names no composite
key, a stored ML-DSA-44 signature verifies under nothing, and every wrapped
key and envelope is in a format the clients now refuse by name.

So this revision does not migrate data — there is nothing to migrate it TO,
since the new keys exist only in the clients. It refuses to run on a database
that still holds identities, and says what to do instead: the deployment
starts empty (E2E-RECIPE.md step 0, DEPLOYMENT.md "crypto-core 4.0.0"). A
migration that ran anyway would leave rows every client renders as forgeries.

Then it makes the database hold the new shapes too: an address is 96 lowercase
hex characters, an identity key 3 968.

Revision ID: b4c5d6e7f8a9
Revises: a3b4c5d6e7f8
Create Date: 2026-10-13
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b4c5d6e7f8a9"
down_revision: str | Sequence[str] | None = "a3b4c5d6e7f8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    existing = bind.execute(sa.text("SELECT count(*) FROM users")).scalar()
    if existing:
        raise RuntimeError(
            f"This database holds {existing} identities created before crypto-core 4.0.0. "
            "Their keys, addresses, signatures and ciphertexts cannot be read by 4.0.0 "
            "clients, and there is nothing to convert them to. Start from an empty "
            "database (E2E-RECIPE.md step 0; DEPLOYMENT.md, 'crypto-core 4.0.0') — "
            "after a backup if any of it matters: scripts/backup.sh."
        )
    if bind.dialect.name != "sqlite":
        op.create_check_constraint("ck_users_address", "users", "address ~ '^[0-9a-f]{96}$'")
        op.create_check_constraint(
            "ck_users_identity_public_key", "users", "char_length(identity_public_key) = 3968"
        )


def downgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        op.drop_constraint("ck_users_identity_public_key", "users", type_="check")
        op.drop_constraint("ck_users_address", "users", type_="check")
