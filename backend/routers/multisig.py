import hashlib

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session, joinedload, selectinload

import auth
import models
import schemas
from database import get_db
from dependencies import get_current_user, limiter
from routers.secrets import create_secret_with_owner_grant
from security import authorization
from utils.clock import utcnow_naive
from utils.push import display_name, notify_user_push

router = APIRouter(prefix="/multisig", tags=["multisig"])

# Page size for GET /multisig/workflows (audit O-3). Each row eager-loads its
# secret — `encrypted_data` included, 500 KB by schema — plus its signers and
# recipients, and the endpoint used to return every one of them.
WORKFLOW_PAGE_MAX = 100
WORKFLOW_PAGE_DEFAULT = 50


def _load_workflow_or_404(
    db: Session, workflow_id: int, *, for_update: bool = False, with_secret: bool = False
) -> models.MultisigWorkflow:
    """Load a workflow, or raise 404.

    `for_update` takes the row lock that /sign and /reject both need. Those two
    decide the terminal status, so they must serialize against each other
    (KRY-005); the lock stays a parameter here rather than a separate helper so
    a reader can see which endpoints take it.
    """
    query = db.query(models.MultisigWorkflow)
    if with_secret:
        query = query.options(joinedload(models.MultisigWorkflow.secret))
    query = query.filter(models.MultisigWorkflow.id == workflow_id)
    if for_update:
        query = query.with_for_update()

    workflow = query.first()
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return workflow


@router.post("/workflow", response_model=schemas.MultisigWorkflowResponse)
@limiter.limit("5/minute")
def create_multisig_workflow(
    request: Request,
    workflow: schemas.MultisigWorkflowCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not workflow.signers:
        raise HTTPException(status_code=400, detail="At least one signer is required")
    if workflow.threshold < 1 or workflow.threshold > len(workflow.signers):
        raise HTTPException(
            status_code=400,
            detail="threshold must be between 1 and the number of signers",
        )

    # 0.1 Signer/recipient rows carry an FK to users (enforced on Postgres) —
    # reject unknown addresses up front instead of failing the insert.
    participant_addrs = {a.lower() for a in workflow.signers} | {
        a.lower() for a in workflow.recipients
    }
    known = {
        addr
        for (addr,) in db.query(models.User.address).filter(
            models.User.address.in_(participant_addrs)
        )
    }
    if participant_addrs - known:
        raise HTTPException(
            status_code=400,
            detail="All signers and recipients must be registered users",
        )

    # Schema validation guarantees secret_data carries the owner's wrapped key.
    new_secret = create_secret_with_owner_grant(db, current_user, workflow.secret_data)

    new_workflow = models.MultisigWorkflow(
        name=workflow.name,
        owner_address=current_user.address,
        secret_id=new_secret.id,
        status="pending",
        threshold=workflow.threshold,
    )
    db.add(new_workflow)
    db.commit()
    db.refresh(new_workflow)

    # Addresses are lowercase everywhere, so the key maps are lowered ONCE here
    # rather than per iteration — and the recipient map below is lowered the
    # same way, which it previously was not (audit L-2).
    signer_keys = {k.lower(): v for k, v in (workflow.signer_keys or {}).items()}
    recipient_keys = {k.lower(): v for k, v in (workflow.recipient_keys or {}).items()}

    for signer_addr in workflow.signers:
        s_addr = signer_addr.lower()
        key = signer_keys.get(s_addr)

        signer_entry = models.MultisigWorkflowSigner(
            workflow_id=new_workflow.id, user_address=s_addr, has_signed=False, encrypted_key=key
        )
        db.add(signer_entry)

    # A recipient's key is withheld until the workflow completes.
    for recipient_addr in workflow.recipients:
        r_addr = recipient_addr.lower()
        key = recipient_keys.get(r_addr)

        recipient_entry = models.MultisigWorkflowRecipient(
            workflow_id=new_workflow.id, user_address=r_addr, encrypted_key=key
        )
        db.add(recipient_entry)

    db.commit()
    db.refresh(new_workflow)

    sender_name = display_name(current_user)
    for signer_addr in workflow.signers:
        s_addr = signer_addr.lower()
        if s_addr != current_user.address:
            notify_user_push(
                db,
                s_addr,
                title="Signature Required",
                body=f"{sender_name} requested your signature for: {new_workflow.name}",
                data={"type": "multisig_request", "workflow_id": new_workflow.id},
            )

    return new_workflow


@router.get("/workflows", response_model=list[schemas.MultisigWorkflowSummaryResponse])
@limiter.limit("60/minute")
def list_multisig_workflows(
    request: Request,
    limit: int = Query(WORKFLOW_PAGE_DEFAULT, ge=1, le=WORKFLOW_PAGE_MAX),
    offset: int = Query(0, ge=0),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # One query, not three merged in Python (audit O-2/O-3). "Owner, signer, or
    # recipient of something completed" is the same rule `can_read_workflow`
    # applies to a single workflow, so it is spelled once in
    # security.authorization; and paging three separate result sets could not
    # be made correct anyway, since neither half knows what the others hold.
    workflows = (
        authorization.readable_workflows(db, current_user.address)
        .options(
            # The response serialises the whole graph — owner, secret (and its
            # owner), every signer and recipient with their user rows. Left
            # lazy, one page of 50 workflows is several hundred queries.
            # selectinload for the collections: one extra query each, and
            # unlike a joined eager load it cannot interfere with LIMIT.
            joinedload(models.MultisigWorkflow.owner),
            # `encrypted_data` is deferred, not merely dropped from the response
            # schema (audit O-3): without this the ciphertext still travels
            # Postgres -> worker for every row of the page, and only Pydantic
            # throws it away. The detail endpoint loads it normally.
            joinedload(models.MultisigWorkflow.secret)
            .defer(models.Secret.encrypted_data)
            .joinedload(models.Secret.owner),
            selectinload(models.MultisigWorkflow.signers).joinedload(
                models.MultisigWorkflowSigner.user
            ),
            selectinload(models.MultisigWorkflow.recipients).joinedload(
                models.MultisigWorkflowRecipient.user
            ),
        )
        .order_by(models.MultisigWorkflow.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )

    # Batch-load owner grants for the page's owned workflows (eliminates N+1)
    owned_secret_ids = [
        w.secret.id for w in workflows if w.secret and w.owner_address == current_user.address
    ]
    owner_grants = {}
    if owned_secret_ids:
        grants = (
            db.query(models.AccessGrant)
            .filter(
                models.AccessGrant.secret_id.in_(owned_secret_ids),
                models.AccessGrant.grantee_address == current_user.address,
            )
            .all()
        )
        owner_grants = {g.secret_id: g.encrypted_key for g in grants}

    response_list = []
    for wf in workflows:
        if not wf.secret:
            continue

        val = schemas.MultisigWorkflowSummaryResponse.model_validate(wf)

        if wf.owner_address == current_user.address:
            key = owner_grants.get(wf.secret.id)
            if key:
                val.owner_encrypted_key = key
                val.secret.encrypted_key = key

        response_list.append(val)

    return response_list


@router.get("/workflow/{workflow_id}", response_model=schemas.MultisigWorkflowResponse)
@limiter.limit("60/minute")
def get_multisig_workflow(
    request: Request,
    workflow_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    wf = _load_workflow_or_404(db, workflow_id, with_secret=True)

    # Owner/signer always, recipient only once completed — the rule lives in
    # security.authorization because `can_read_secret` gates the secret behind
    # this workflow on exactly the same three conditions (audit O-2).
    if not authorization.can_read_workflow(db, wf, current_user.address):
        raise HTTPException(status_code=403, detail="Not authorized")

    wf_response = schemas.MultisigWorkflowResponse.model_validate(wf)

    if wf.secret:
        grant = (
            db.query(models.AccessGrant)
            .filter(
                models.AccessGrant.secret_id == wf.secret.id,
                models.AccessGrant.grantee_address == current_user.address,
            )
            .first()
        )

        if grant:
            wf_response.owner_encrypted_key = grant.encrypted_key
            # Both shapes: older clients read the nested one.
            wf_response.secret.encrypted_key = grant.encrypted_key

    return wf_response


def _release_recipient_keys(db: Session, wf, supplied):
    """Attach recipients' wrapped keys as part of the completing signature.

    Addresses are lowercased on BOTH sides (audit L-2). The creation path
    normalized the signer map but not the recipient map, and this lookup matched
    `user_address == r_addr` on the raw value — so a client sending a mixed-case
    address matched no row, `if recipient:` was simply false, and the loop passed
    in silence. The workflow then completed with a recipient holding no key,
    which is not recoverable: the secret is released to nobody, and a completed
    workflow cannot be deleted.

    So the completing signature is now REFUSED when a declared recipient would
    end up with no key. Failing the request leaves the workflow signable again;
    letting it through leaves it permanently stuck.
    """
    recipients = (
        db.query(models.MultisigWorkflowRecipient)
        .filter(models.MultisigWorkflowRecipient.workflow_id == wf.id)
        .all()
    )
    if not recipients:
        return

    normalized = {addr.lower(): key for addr, key in (supplied or {}).items()}
    by_address = {r.user_address.lower(): r for r in recipients}

    unknown = sorted(set(normalized) - set(by_address))
    if unknown:
        raise HTTPException(
            status_code=400,
            detail="Recipient keys supplied for addresses that are not recipients of this workflow",
        )

    for address, recipient in by_address.items():
        if address in normalized:
            recipient.encrypted_key = normalized[address]

    # A recipient may already hold a key from creation time, so this checks the
    # END state rather than what this request supplied.
    missing = sorted(addr for addr, r in by_address.items() if not r.encrypted_key)
    if missing:
        raise HTTPException(
            status_code=400,
            detail=(
                "Cannot complete: no encrypted key for recipient(s) "
                + ", ".join(missing)
                + ". Completing without them would release the secret to nobody and "
                "leave a workflow that can no longer be signed or deleted."
            ),
        )


def _verify_approval(db, wf, signer_address: str, signature: str) -> None:
    """Check that `signer_address` really approved this workflow's ciphertext.

    The server is zero-knowledge, so a signer signs the SHA-256 of the STORED
    CIPHERTEXT bound to this workflow and secret (audit M1). The server can
    recompute that hash, which is what makes `has_signed` cryptographically
    meaningful: only the holder of the signing key can advance the workflow, not
    merely someone holding a valid session token.
    """
    secret = db.query(models.Secret).filter(models.Secret.id == wf.secret_id).first()
    if not secret:
        raise HTTPException(status_code=404, detail="Workflow secret not found")

    ct_hash = hashlib.sha256((secret.encrypted_data or "").encode("utf-8")).hexdigest()
    approval_msg = auth.multisig_approval_message(wf.id, wf.secret_id, ct_hash)
    if not auth.verify_message_signature(signer_address, approval_msg, signature):
        raise HTTPException(status_code=400, detail="Invalid approval signature")


def _is_completing_signature(db, wf) -> bool:
    """Whether the signature about to be recorded reaches the quorum.

    N-of-M: the workflow completes as soon as `threshold` signatures land, not
    only when everyone has signed. The caller's `has_signed` is still False
    here, so the `+ 1` counts the signature being recorded. A NULL threshold
    (legacy rows) falls back to N-of-N.
    """
    all_signers = (
        db.query(models.MultisigWorkflowSigner)
        .filter(models.MultisigWorkflowSigner.workflow_id == wf.id)
        .all()
    )
    quorum = wf.threshold or len(all_signers)
    already_signed = sum(1 for s in all_signers if s.has_signed)
    return (already_signed + 1) >= quorum


def _notify_signature(db, wf, sender_name: str, signer_address: str, is_completing: bool) -> None:
    """Announce a signature, and a release if it completed the workflow.

    Best-effort and deliberately called AFTER the commit: a push failure must
    never roll back a recorded signature.
    """
    if wf.owner_address != signer_address:
        notify_user_push(
            db,
            wf.owner_address,
            title="Workflow Signed",
            body=f"{sender_name} signed your workflow: {wf.name}",
            data={"type": "multisig_signed", "workflow_id": wf.id},
        )

    if is_completing:
        for recipient in wf.recipients:
            notify_user_push(
                db,
                recipient.user_address,
                title="Secret Released",
                body=f"Multisig workflow '{wf.name}' is complete. You now have access to the secret.",
                data={"type": "multisig_completed", "workflow_id": wf.id},
            )


@router.post("/workflow/{workflow_id}/sign", response_model=schemas.MultisigWorkflowResponse)
@limiter.limit("20/minute")
def sign_multisig_workflow(
    request: Request,
    workflow_id: int,
    sig_req: schemas.MultisigSignatureRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Serialize concurrent signatures on this workflow (KRY-005).
    #
    # The quorum decision is read-then-write: without a lock, two signers can
    # both observe `already_signed == quorum - 1`, both conclude they are the
    # completing signer, and both pass the guard that is supposed to let only
    # the final signature release recipient keys. Taking a row lock here means
    # the second signer reads the first one's committed state.
    #
    # FOR UPDATE is a no-op on SQLite, which serializes writes at the file
    # level anyway; on PostgreSQL (the deployment target) it is what actually
    # closes the race.
    wf = _load_workflow_or_404(db, workflow_id, for_update=True)

    signer = authorization.find_workflow_signer(db, wf.id, current_user.address)
    if not signer:
        raise HTTPException(status_code=403, detail="You are not a signer for this workflow")

    # Signing is only possible while the workflow is still open. Once it has
    # reached its threshold (completed) or a signer has rejected it, it is closed.
    if wf.status != "pending":
        raise HTTPException(status_code=400, detail=f"Workflow is {wf.status}")

    if signer.has_signed:
        raise HTTPException(status_code=400, detail="Already signed")

    _verify_approval(db, wf, current_user.address, sig_req.signature)

    # Recipient keys may only be released by the COMPLETING signer (audit M1).
    # Pre-fix, any signer could overwrite them (with garbage) at any step.
    is_completing = _is_completing_signature(db, wf)
    if sig_req.recipient_keys and not is_completing:
        raise HTTPException(
            status_code=400,
            detail="Recipient keys may only be provided with the final signature",
        )

    signer.has_signed = True
    signer.signature = sig_req.signature
    signer.signed_at = utcnow_naive()

    if is_completing:
        _release_recipient_keys(db, wf, sig_req.recipient_keys)
        # The status transition rides the SAME transaction as the signature.
        # Previously the signature was committed first and the status second: a
        # crash between the two left a fully-signed workflow stuck in `pending`
        # forever, with the secret never released and no recovery path.
        wf.status = "completed"

    # One commit: signature, recipient keys and status land together or not at
    # all. This also releases the FOR UPDATE lock taken above.
    db.commit()

    _notify_signature(db, wf, display_name(current_user), current_user.address, is_completing)

    db.refresh(wf)
    return wf


@router.post("/workflow/{workflow_id}/reject", response_model=schemas.MultisigWorkflowResponse)
@limiter.limit("20/minute")
def reject_multisig_workflow(
    request: Request,
    workflow_id: int,
    reject_req: schemas.MultisigRejectRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Same row lock as /sign — reject and the completing signature both decide
    # the terminal status, so they must serialize against each other. Without
    # it, a reject that read `pending` could commit "rejected" AFTER the
    # completing signature released the recipient keys (a workflow both blocked
    # and released), or be silently overwritten by it.
    wf = _load_workflow_or_404(db, workflow_id, for_update=True)

    signer = authorization.find_workflow_signer(db, wf.id, current_user.address)
    if not signer:
        raise HTTPException(status_code=403, detail="You are not a signer for this workflow")

    if wf.status != "pending":
        raise HTTPException(status_code=400, detail=f"Workflow is {wf.status}")

    # A single rejection blocks the whole workflow. The secret is never released;
    # the owner can then delete the blocked workflow.
    wf.status = "rejected"
    wf.rejected_by = current_user.address.lower()
    wf.rejected_at = utcnow_naive()
    db.commit()

    sender_name = display_name(current_user)
    if wf.owner_address != current_user.address:
        notify_user_push(
            db,
            wf.owner_address,
            title="Workflow Rejected",
            body=f"{sender_name} rejected your workflow: {wf.name}",
            data={"type": "multisig_rejected", "workflow_id": wf.id},
        )

    db.refresh(wf)
    return wf


@router.delete("/workflow/{workflow_id}", status_code=204)
@limiter.limit("20/minute")
def delete_multisig_workflow(
    request: Request,
    workflow_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    wf = _load_workflow_or_404(db, workflow_id)

    if not authorization.can_delete_workflow(wf, current_user.address):
        raise HTTPException(status_code=403, detail="Only the workflow owner may delete it")
    if not authorization.workflow_is_deletable(wf):
        raise HTTPException(status_code=400, detail="Cannot delete a completed workflow")

    # Remove signer/recipient rows, then the workflow, then the underlying secret
    # (and its owner access grant) created alongside it.
    db.query(models.MultisigWorkflowSigner).filter(
        models.MultisigWorkflowSigner.workflow_id == wf.id
    ).delete(synchronize_session=False)
    db.query(models.MultisigWorkflowRecipient).filter(
        models.MultisigWorkflowRecipient.workflow_id == wf.id
    ).delete(synchronize_session=False)

    secret_id = wf.secret_id
    db.delete(wf)
    if secret_id is not None:
        db.query(models.AccessGrant).filter(models.AccessGrant.secret_id == secret_id).delete(
            synchronize_session=False
        )
        secret = db.query(models.Secret).filter(models.Secret.id == secret_id).first()
        if secret:
            db.delete(secret)

    db.commit()
    return None
