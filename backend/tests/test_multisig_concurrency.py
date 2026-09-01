"""Multisig concurrency and atomicity (KRY-005 + the non-atomic completion bug).

The audit reported the quorum race as a miscount. The sharper consequence is
that two concurrent signers can both compute `is_completing = True` and both
clear the guard that is supposed to let only the *final* signature release
recipient keys — so a non-final signer can overwrite them.

Separately (not in the audit): the signature and the `completed` status used
to be committed one after the other, so a crash between them stranded a
fully-signed workflow in `pending` with no recovery path.
"""
import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

import models
from conftest import (
    TEST_ENCRYPTION_KEY, TestingSessionLocal, auth_header, do_login,
)
from main import app


def _create_workflow(client, token, signers, recipients=None, threshold=None):
    recipients = recipients or []
    if threshold is None:
        threshold = len(signers)
    return client.post("/multisig/workflow", json={
        "name": "ConcurrentWorkflow",
        "secret_data": {
            "name": "S", "type": "standard",
            "encrypted_data": "payload", "encrypted_key": "owner_key",
        },
        "signers": signers,
        "recipients": recipients,
        "signer_keys": {a: f"k_{a}" for a in signers},
        "recipient_keys": {a: f"k_{a}" for a in recipients},
        "threshold": threshold,
    }, headers=auth_header(token))


@pytest.fixture(autouse=True)
def _no_rate_limits():
    from dependencies import limiter
    limiter.enabled = False
    yield
    limiter.enabled = True


@pytest.fixture()
def signers(client):
    """Four distinct signer identities."""
    out = []
    for i in range(4):
        addr = f"pqc_signer_{i}_" + chr(ord('a') + i) * 100
        token, user = do_login(client, addr, TEST_ENCRYPTION_KEY, f"Signer{i}")
        out.append((token, user["address"]))
    return out


class TestConcurrentSigning:
    def test_concurrent_signatures_do_not_over_release(self, client, user1, signers):
        """Quorum 2 of 4, all four signing at once.

        Exactly two signatures may be recorded and the workflow must end
        `completed` — not a state where extra signatures landed after the
        quorum was already met.
        """
        owner_token, _ = user1
        addrs = [a for _, a in signers]
        wf = _create_workflow(client, owner_token, addrs, threshold=2).json()

        barrier = threading.Barrier(len(signers))
        results = [None] * len(signers)

        def worker(i):
            token, _ = signers[i]
            c = TestClient(app)
            try:
                barrier.wait(timeout=10)
                results[i] = c.post(
                    f"/multisig/workflow/{wf['id']}/sign",
                    json={"signature": "sig"},
                    headers=auth_header(token),
                )
            except Exception as exc:
                results[i] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(len(signers))]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        db = TestingSessionLocal()
        try:
            signed = db.query(models.MultisigWorkflowSigner).filter(
                models.MultisigWorkflowSigner.workflow_id == wf["id"],
                models.MultisigWorkflowSigner.has_signed.is_(True),
            ).count()
            row = db.query(models.MultisigWorkflow).filter(
                models.MultisigWorkflow.id == wf["id"]
            ).first()

            # Signing is closed once status leaves "pending", so no more than
            # the quorum may ever be recorded.
            assert signed == 2, f"{signed} signatures recorded for a 2-of-4 quorum"
            assert row.status == "completed"
        finally:
            db.close()

    def test_concurrent_signers_cannot_both_release_recipient_keys(self, client, user1, signers):
        """The completing-signer guard must hold under concurrency.

        Both signers race while claiming to be the final one. Pre-fix, both
        could read `already_signed == 0`, both compute `is_completing` from a
        stale count, and both write recipient keys. With the row lock the
        second signer sees the first one's committed signature, so at most one
        release can ever be authorised.
        """
        owner_token, _ = user1
        _, recipient_user = do_login(
            client, "pqc_recip_" + "z" * 100, TEST_ENCRYPTION_KEY, "Recip"
        )
        recipient = recipient_user["address"]
        addrs = [a for _, a in signers[:2]]
        wf = _create_workflow(
            client, owner_token, addrs, recipients=[recipient], threshold=2
        ).json()

        barrier = threading.Barrier(2)
        results = [None, None]

        def worker(i):
            token, _ = signers[i]
            c = TestClient(app)
            try:
                barrier.wait(timeout=10)
                results[i] = c.post(
                    f"/multisig/workflow/{wf['id']}/sign",
                    json={"signature": "sig",
                          "recipient_keys": {recipient: f"key_from_{i}"}},
                    headers=auth_header(token),
                )
            except Exception as exc:
                results[i] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        codes = [r.status_code for r in results if hasattr(r, "status_code")]
        # Neither signer is the completing one here (a rejected sign records
        # nothing, so the count never advances), so both must be refused —
        # and crucially, no recipient key may have been written.
        assert all(c == 400 for c in codes), f"unexpected outcomes: {sorted(codes)}"

        db = TestingSessionLocal()
        try:
            row = db.query(models.MultisigWorkflowRecipient).filter(
                models.MultisigWorkflowRecipient.workflow_id == wf["id"],
                models.MultisigWorkflowRecipient.user_address == recipient,
            ).first()
            assert not (row.encrypted_key or "").startswith("key_from_"), (
                "a non-completing signer released recipient keys"
            )
        finally:
            db.close()

    def test_completing_signer_releases_keys_exactly_once(self, client, user1, signers):
        """The legitimate path: first signer signs plainly, second completes
        and releases. Under the lock this must stay deterministic."""
        owner_token, _ = user1
        _, recipient_user = do_login(
            client, "pqc_recip2_" + "y" * 100, TEST_ENCRYPTION_KEY, "Recip2"
        )
        recipient = recipient_user["address"]
        addrs = [a for _, a in signers[:2]]
        wf = _create_workflow(
            client, owner_token, addrs, recipients=[recipient], threshold=2
        ).json()

        first = client.post(
            f"/multisig/workflow/{wf['id']}/sign",
            json={"signature": "sig"}, headers=auth_header(signers[0][0]),
        )
        assert first.status_code == 200, first.text

        second = client.post(
            f"/multisig/workflow/{wf['id']}/sign",
            json={"signature": "sig", "recipient_keys": {recipient: "released"}},
            headers=auth_header(signers[1][0]),
        )
        assert second.status_code == 200, second.text

        db = TestingSessionLocal()
        try:
            row = db.query(models.MultisigWorkflowRecipient).filter(
                models.MultisigWorkflowRecipient.workflow_id == wf["id"],
                models.MultisigWorkflowRecipient.user_address == recipient,
            ).first()
            assert row.encrypted_key == "released"
        finally:
            db.close()


class TestCompletionIsAtomic:
    def test_signature_and_status_land_together(self, client, user1, signers):
        """A completed quorum must never leave status behind at 'pending'."""
        owner_token, _ = user1
        addrs = [a for _, a in signers[:2]]
        wf = _create_workflow(client, owner_token, addrs, threshold=2).json()

        for token, _ in signers[:2]:
            resp = client.post(
                f"/multisig/workflow/{wf['id']}/sign",
                json={"signature": "sig"},
                headers=auth_header(token),
            )
            assert resp.status_code == 200, resp.text

        db = TestingSessionLocal()
        try:
            row = db.query(models.MultisigWorkflow).filter(
                models.MultisigWorkflow.id == wf["id"]
            ).first()
            signed = db.query(models.MultisigWorkflowSigner).filter(
                models.MultisigWorkflowSigner.workflow_id == wf["id"],
                models.MultisigWorkflowSigner.has_signed.is_(True),
            ).count()
            # Quorum reached => status must already reflect it.
            assert signed == 2
            assert row.status == "completed"
        finally:
            db.close()

    def test_signing_is_closed_once_completed(self, client, user1, signers):
        owner_token, _ = user1
        addrs = [a for _, a in signers[:3]]
        wf = _create_workflow(client, owner_token, addrs, threshold=2).json()

        for token, _ in signers[:2]:
            client.post(f"/multisig/workflow/{wf['id']}/sign",
                        json={"signature": "sig"}, headers=auth_header(token))

        # Third signer arrives after the quorum closed the workflow.
        late = client.post(f"/multisig/workflow/{wf['id']}/sign",
                           json={"signature": "sig"}, headers=auth_header(signers[2][0]))
        assert late.status_code == 400
        assert "completed" in late.text


class TestConcurrentRejectAndSign:
    """Reject and the completing signature both decide the terminal status.

    /sign takes a FOR UPDATE row lock precisely so the quorum decision
    serializes; /reject did not, so a reject that had read `pending` could
    commit "rejected" *after* the completing signature released recipient keys
    — a workflow simultaneously blocked and released — or be clobbered by it.
    With both paths taking the same lock the loser observes the winner's
    committed status and bounces off the `status != "pending"` guard.
    """

    def test_reject_racing_the_completing_signature_yields_one_outcome(
        self, client, user1, signers
    ):
        owner_token, _ = user1
        _, recipient_user = do_login(
            client, "pqc_rr_recip_" + "y" * 100, TEST_ENCRYPTION_KEY, "RRRecip"
        )
        recipient = recipient_user["address"]
        # 1-of-2: signer[0]'s signature completes it outright, so it races
        # signer[1]'s rejection with no intermediate state in between.
        addrs = [a for _, a in signers[:2]]
        wf = _create_workflow(
            client, owner_token, addrs, recipients=[recipient], threshold=1
        ).json()

        barrier = threading.Barrier(2)
        results = {}

        def signer_worker():
            c = TestClient(app)
            barrier.wait(timeout=10)
            results["sign"] = c.post(
                f"/multisig/workflow/{wf['id']}/sign",
                json={"signature": "sig", "recipient_keys": {recipient: "released"}},
                headers=auth_header(signers[0][0]),
            )

        def rejecter_worker():
            c = TestClient(app)
            barrier.wait(timeout=10)
            results["reject"] = c.post(
                f"/multisig/workflow/{wf['id']}/reject",
                json={"reason": "no"},
                headers=auth_header(signers[1][0]),
            )

        threads = [
            threading.Thread(target=signer_worker),
            threading.Thread(target=rejecter_worker),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        # Exactly one of the two may win; the loser must be refused.
        codes = sorted(r.status_code for r in results.values())
        assert codes == [200, 400], f"both calls succeeded: {codes}"

        db = TestingSessionLocal()
        try:
            row = db.query(models.MultisigWorkflow).filter(
                models.MultisigWorkflow.id == wf["id"]
            ).first()
            rec = db.query(models.MultisigWorkflowRecipient).filter(
                models.MultisigWorkflowRecipient.workflow_id == wf["id"],
                models.MultisigWorkflowRecipient.user_address == recipient,
            ).first()

            assert row.status in ("completed", "rejected")
            # The decisive invariant: keys are released if and ONLY if the
            # workflow actually completed.
            if row.status == "rejected":
                assert rec.encrypted_key != "released", (
                    "recipient keys were released on a rejected workflow"
                )
            else:
                assert rec.encrypted_key == "released"
        finally:
            db.close()


class TestParticipantUniqueness:
    def test_duplicate_signer_row_is_rejected_by_db(self, client, user1, signers):
        """UNIQUE(workflow_id, user_address): a duplicate signer row would let
        one identity contribute two signatures toward a quorum."""
        owner_token, _ = user1
        addr = signers[0][1]
        wf = _create_workflow(client, owner_token, [addr], threshold=1).json()

        db = TestingSessionLocal()
        try:
            db.add(models.MultisigWorkflowSigner(
                workflow_id=wf["id"], user_address=addr, has_signed=False,
            ))
            with pytest.raises(IntegrityError):
                db.commit()
        finally:
            db.rollback()
            db.close()
