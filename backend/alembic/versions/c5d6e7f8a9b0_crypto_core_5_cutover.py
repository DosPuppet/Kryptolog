"""crypto-core 5.0.0: ECCG-agreed hybrids, key ids — a clean cutover.

Every identity becomes a composite ML-DSA-65 + ECDSA-P384 key, every address
the SHA-384 of one under a v5 prefix, every encryption key an ETSI TS 103 744
CatKDF key over P-384 + ML-KEM-768 (lot 12, ANSSI 2026 alignment). As with
4.0.0, nothing written before can be read after — a 4.x address names no
P-384 composite, a stored Ed25519 composite signature verifies under nothing,
and every envelope is in a format the clients refuse by name — and the new
keys exist only in the clients, so there is nothing to convert TO. This
revision refuses to run on a database that still holds identities and says
what to do instead (E2E-RECIPE.md step 0, DEPLOYMENT.md "crypto-core 5.0.0").

It is meant to be the LAST such refusal: an encryption key now carries its
suite and its id (below), so the next change of KEM can be a rotation of
encryption keys rather than a wiped server (crypto-core 5.1.0).

Shapes the database holds from here on:
  * an identity key is 4 098 hex characters (it was 3 968);
  * an encryption key, when present, 2 562 (it was not checked at all);
  * `encryption_key_alg` names the key's suite and `encryption_key_id` its id
    (crypto-core's encryptionKeyId), both NULL exactly when the key is.

Revision ID: c5d6e7f8a9b0
Revises: b4c5d6e7f8a9
Create Date: 2026-10-14
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c5d6e7f8a9b0"
down_revision: str | Sequence[str] | None = "b4c5d6e7f8a9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    existing = bind.execute(sa.text("SELECT count(*) FROM users")).scalar()
    if existing:
        raise RuntimeError(
            f"This database holds {existing} identities created before crypto-core 5.0.0. "
            "Their keys, addresses, signatures and ciphertexts cannot be read by 5.0.0 "
            "clients, and there is nothing to convert them to. Start from an empty "
            "database (E2E-RECIPE.md step 0; DEPLOYMENT.md, 'crypto-core 5.0.0') — "
            "after a backup if any of it matters: scripts/backup.sh."
        )
    op.add_column("users", sa.Column("encryption_key_alg", sa.String(length=64), nullable=True))
    op.add_column("users", sa.Column("encryption_key_id", sa.String(length=32), nullable=True))
    if bind.dialect.name != "sqlite":
        op.drop_constraint("ck_users_identity_public_key", "users", type_="check")
        op.create_check_constraint(
            "ck_users_identity_public_key", "users", "char_length(identity_public_key) = 4098"
        )
        op.create_check_constraint(
            "ck_users_encryption_key",
            "users",
            "(encryption_public_key IS NULL AND encryption_key_alg IS NULL"
            " AND encryption_key_id IS NULL)"
            " OR (char_length(encryption_public_key) = 2562"
            " AND encryption_key_alg = 'HKDFwSHA384_P384_ML-KEM-768_CatKDF'"
            " AND encryption_key_id ~ '^[0-9a-f]{32}$')",
        )


def downgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        op.drop_constraint("ck_users_encryption_key", "users", type_="check")
        op.drop_constraint("ck_users_identity_public_key", "users", type_="check")
        op.create_check_constraint(
            "ck_users_identity_public_key", "users", "char_length(identity_public_key) = 3968"
        )
    op.drop_column("users", "encryption_key_id")
    op.drop_column("users", "encryption_key_alg")
