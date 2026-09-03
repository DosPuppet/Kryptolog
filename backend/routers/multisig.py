from fastapi import APIRouter, Depends, HTTPException, Request
from dependencies import limiter
from sqlalchemy.orm import Session, joinedload
from typing import List
from datetime import datetime, timezone
import hashlib
import models, schemas, auth
from database import get_db
from dependencies import get_current_user
from utils.push import notify_user_push

router = APIRouter(
    prefix="/multisig",
    tags=["multisig"]
)

@router.post("/workflow", response_model=schemas.MultisigWorkflowResponse)
@limiter.limit("5/minute")
def create_multisig_workflow(request: Request, workflow: schemas.MultisigWorkflowCreate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # 0. Validate the N-of-M threshold against the signer set.
    if not workflow.signers:
        raise HTTPException(status_code=400, detail="At least one signer is required")
    if workflow.threshold < 1 or workflow.threshold > len(workflow.signers):
        raise HTTPException(
            status_code=400,
            detail="threshold must be between 1 and the number of signers",
        )

    # 0.1 Signer/recipient rows carry an FK to users (enforced on Postgres) —
    # reject unknown addresses up front instead of failing the insert.
    participant_addrs = {a.lower() for a in workflow.signers} | {a.lower() for a in workflow.recipients}
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

    # 1. Create the Secret (Owned by Creator)
    new_secret = models.Secret(
        owner_address=current_user.address,
        name=workflow.secret_data.name,
        type=workflow.secret_data.type,
        encrypted_data=workflow.secret_data.encrypted_data
    )
    db.add(new_secret)
    db.flush()

    # 1.1 Create AccessGrant for Owner (Creator) - Envelope Logic
    # Schema validation ensures encrypted_key is present in secret_data
    owner_grant = models.AccessGrant(
        secret_id=new_secret.id,
        grantee_address=current_user.address,
        encrypted_key=workflow.secret_data.encrypted_key
    )
    db.add(owner_grant)
    
    db.commit() # Commit secret and grant
    db.refresh(new_secret)

    # 2. Create Workflow
    new_workflow = models.MultisigWorkflow(
        name=workflow.name,
        owner_address=current_user.address,
        secret_id=new_secret.id,
        status="pending",
        threshold=workflow.threshold
    )
    db.add(new_workflow)
    db.commit()
    db.refresh(new_workflow)

    # 3. Add Signers with their per-workflow encrypted keys.
    # Addresses are lowercase everywhere, so the key maps are lowered ONCE here
    # rather than per iteration — and the recipient map below is lowered the
    # same way, which it previously was not (audit L-2).
    signer_keys = {k.lower(): v for k, v in (workflow.signer_keys or {}).items()}
    recipient_keys = {k.lower(): v for k, v in (workflow.recipient_keys or {}).items()}

    for signer_addr in workflow.signers:
        s_addr = signer_addr.lower()
        key = signer_keys.get(s_addr)

        signer_entry = models.MultisigWorkflowSigner(
            workflow_id=new_workflow.id,
            user_address=s_addr,
            has_signed=False,
            encrypted_key=key
        )
        db.add(signer_entry)

    # 4. Add Recipients (keys released only upon workflow completion)
    for recipient_addr in workflow.recipients:
        r_addr = recipient_addr.lower()
        key = recipient_keys.get(r_addr)

        recipient_entry = models.MultisigWorkflowRecipient(
            workflow_id=new_workflow.id,
            user_address=r_addr,
            encrypted_key=key
        )
        db.add(recipient_entry)

    db.commit()
    db.refresh(new_workflow)
    
    # Notify Signers
    sender_name = current_user.username or f"{current_user.address[:8]}..."
    for signer_addr in workflow.signers:
        s_addr = signer_addr.lower()
        if s_addr != current_user.address:
            notify_user_push(
                db,
                s_addr,
                title="Signature Required",
                body=f"{sender_name} requested your signature for: {new_workflow.name}",
                data={"type": "multisig_request", "workflow_id": new_workflow.id}
            )

    return new_workflow

@router.get("/workflows", response_model=List[schemas.MultisigWorkflowResponse])
@limiter.limit("60/minute")
def list_multisig_workflows(request: Request, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Return workflows where I am owner OR signer
    # Using python filtering for simplicity unless perf is issue, OR union query.
    # Simple Union query:
    
    # Owned - Eager load secret to avoid N+1 and ensure we have it for validation
    owned = db.query(models.MultisigWorkflow).options(joinedload(models.MultisigWorkflow.secret)).filter(models.MultisigWorkflow.owner_address == current_user.address).all()
    
    # Helper to fetch workflows where I am signer
    signed_subq = db.query(models.MultisigWorkflowSigner.workflow_id).filter(models.MultisigWorkflowSigner.user_address == current_user.address)
    as_signer = db.query(models.MultisigWorkflow).options(joinedload(models.MultisigWorkflow.secret)).filter(models.MultisigWorkflow.id.in_(signed_subq)).all()

    # Helper to fetch workflows where I am recipient (ONLY COMPLETED)
    recipient_subq = db.query(models.MultisigWorkflowRecipient.workflow_id).filter(models.MultisigWorkflowRecipient.user_address == current_user.address)
    as_recipient = db.query(models.MultisigWorkflow).options(joinedload(models.MultisigWorkflow.secret)).filter(
        models.MultisigWorkflow.id.in_(recipient_subq),
        models.MultisigWorkflow.status == 'completed'
    ).all()
    
    # Deduplicate (if I am owner AND signer?)
    all_wf_orm = {w.id: w for w in owned + as_signer + as_recipient}
    
    # Batch-load owner grants for all owned workflows (eliminates N+1)
    owned_secret_ids = [w.secret.id for w in all_wf_orm.values()
                        if w.secret and w.owner_address == current_user.address]
    owner_grants = {}
    if owned_secret_ids:
        grants = db.query(models.AccessGrant).filter(
            models.AccessGrant.secret_id.in_(owned_secret_ids),
            models.AccessGrant.grantee_address == current_user.address
        ).all()
        owner_grants = {g.secret_id: g.encrypted_key for g in grants}

    response_list = []
    for wf in all_wf_orm.values():
        if not wf.secret:
            continue

        val = schemas.MultisigWorkflowResponse.model_validate(wf)

        if wf.owner_address == current_user.address and wf.secret:
            key = owner_grants.get(wf.secret.id)
            if key:
                val.owner_encrypted_key = key
                val.secret.encrypted_key = key

        response_list.append(val)

    return response_list

@router.get("/workflow/{workflow_id}", response_model=schemas.MultisigWorkflowResponse)
@limiter.limit("60/minute")
def get_multisig_workflow(request: Request, workflow_id: int, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Eager load secret to ensure it's available for schema
    wf = db.query(models.MultisigWorkflow).options(joinedload(models.MultisigWorkflow.secret)).filter(models.MultisigWorkflow.id == workflow_id).first()
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
        
    # Check permissions (Owner/Signer/Recipient?)
    is_owner = wf.owner_address == current_user.address
    is_signer = db.query(models.MultisigWorkflowSigner).filter(
        models.MultisigWorkflowSigner.workflow_id == wf.id,
        models.MultisigWorkflowSigner.user_address == current_user.address
    ).first() is not None

    is_recipient = db.query(models.MultisigWorkflowRecipient).filter(
        models.MultisigWorkflowRecipient.workflow_id == wf.id,
        models.MultisigWorkflowRecipient.user_address == current_user.address
    ).first() is not None
    
    # Access Logic: Owner/Signer always. Recipient ONLY if completed.
    has_access = is_owner or is_signer or (is_recipient and wf.status == 'completed')

    if not has_access:
         raise HTTPException(status_code=403, detail="Not authorized")

    # Convert to Pydantic Response Model
    wf_response = schemas.MultisigWorkflowResponse.model_validate(wf)

    # Populate encrypted_key for the secret response if available
    if wf.secret:
        # Checking Grant for Secret
        grant = db.query(models.AccessGrant).filter(
            models.AccessGrant.secret_id == wf.secret.id,
            models.AccessGrant.grantee_address == current_user.address
        ).first()
        
        if grant:
            # Update the Pydantic model response field
            wf_response.owner_encrypted_key = grant.encrypted_key
            # Also try nested for consistency if possible, but rely on top-level
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
    recipients = db.query(models.MultisigWorkflowRecipient).filter(
        models.MultisigWorkflowRecipient.workflow_id == wf.id
    ).all()
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


@router.post("/workflow/{workflow_id}/sign", response_model=schemas.MultisigWorkflowResponse)
@limiter.limit("20/minute")
def sign_multisig_workflow(request: Request, workflow_id: int, sig_req: schemas.MultisigSignatureRequest, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
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
    wf = (
        db.query(models.MultisigWorkflow)
        .filter(models.MultisigWorkflow.id == workflow_id)
        .with_for_update()
        .first()
    )
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")

    signer = db.query(models.MultisigWorkflowSigner).filter(
        models.MultisigWorkflowSigner.workflow_id == wf.id,
        models.MultisigWorkflowSigner.user_address == current_user.address.lower()
    ).first()

    if not signer:
        raise HTTPException(status_code=403, detail="You are not a signer for this workflow")

    # Signing is only possible while the workflow is still open. Once it has
    # reached its threshold (completed) or a signer has rejected it, it is closed.
    if wf.status != "pending":
        raise HTTPException(status_code=400, detail=f"Workflow is {wf.status}")

    if signer.has_signed:
        raise HTTPException(status_code=400, detail="Already signed")

    # --- M1: verify the approval signature server-side ---
    # The server is zero-knowledge, so the signer signs the SHA-256 of the
    # STORED CIPHERTEXT (bound to this workflow + secret), which the server can
    # recompute and verify against the signer's identity key. This makes
    # `has_signed` cryptographically meaningful — only the holder of the signing
    # key (not merely a valid session JWT) can advance the workflow.
    secret = db.query(models.Secret).filter(models.Secret.id == wf.secret_id).first()
    if not secret:
        raise HTTPException(status_code=404, detail="Workflow secret not found")
    ct_hash = hashlib.sha256((secret.encrypted_data or "").encode("utf-8")).hexdigest()
    approval_msg = auth.multisig_approval_message(wf.id, wf.secret_id, ct_hash)
    if not auth.verify_message_signature(current_user.address, approval_msg, sig_req.signature):
        raise HTTPException(status_code=400, detail="Invalid approval signature")

    # --- M1: recipient keys may only be released by the COMPLETING signer ---
    # Pre-fix, any signer could overwrite recipient keys (with garbage) at any
    # step. The release is the completing signer's job, so reject recipient_keys
    # on any sign that doesn't reach the threshold.
    #
    # N-of-M: the workflow completes as soon as `threshold` signatures land, not
    # only when everyone has signed. `signer.has_signed` is still False here, so
    # `+ 1` counts the signature we're about to record. A NULL threshold (legacy
    # rows) falls back to N-of-N (= number of signers).
    all_signers = db.query(models.MultisigWorkflowSigner).filter(
        models.MultisigWorkflowSigner.workflow_id == wf.id
    ).all()
    quorum = wf.threshold or len(all_signers)
    already_signed = sum(1 for s in all_signers if s.has_signed)
    is_completing = (already_signed + 1) >= quorum
    if sig_req.recipient_keys and not is_completing:
        raise HTTPException(
            status_code=400,
            detail="Recipient keys may only be provided with the final signature",
        )

    # Update Signer
    signer.has_signed = True
    signer.signature = sig_req.signature
    signer.signed_at = datetime.now(timezone.utc)

    # Store Recipient Keys (Release Mechanism) — only on the completing signature.
    if is_completing:
        _release_recipient_keys(db, wf, sig_req.recipient_keys)

    # Status transition happens in the SAME transaction as the signature.
    # Previously the signature was committed first and `status = "completed"`
    # second: a crash between the two left a fully-signed workflow stuck in
    # `pending` forever, with the secret never released and no recovery path.
    if is_completing:
        wf.status = "completed"

    # One commit: signature, recipient keys, and status land together or not
    # at all. This also releases the FOR UPDATE lock taken above.
    db.commit()

    sender_name = current_user.username or f"{current_user.address[:8]}..."

    # Notifications are best-effort and deliberately AFTER the commit — a push
    # failure must never roll back a recorded signature.
    if wf.owner_address != current_user.address:
        notify_user_push(
            db,
            wf.owner_address,
            title="Workflow Signed",
            body=f"{sender_name} signed your workflow: {wf.name}",
            data={"type": "multisig_signed", "workflow_id": wf.id}
        )

    if is_completing:
        for recipient in wf.recipients:
            notify_user_push(
                db,
                recipient.user_address,
                title="Secret Released",
                body=f"Multisig workflow '{wf.name}' is complete. You now have access to the secret.",
                data={"type": "multisig_completed", "workflow_id": wf.id}
            )

    db.refresh(wf)
    return wf

@router.post("/workflow/{workflow_id}/reject", response_model=schemas.MultisigWorkflowResponse)
@limiter.limit("20/minute")
def reject_multisig_workflow(request: Request, workflow_id: int, reject_req: schemas.MultisigRejectRequest, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Same row lock as /sign — reject and the completing signature both decide
    # the terminal status, so they must serialize against each other. Without
    # it, a reject that read `pending` could commit "rejected" AFTER the
    # completing signature released the recipient keys (a workflow both blocked
    # and released), or be silently overwritten by it.
    wf = (
        db.query(models.MultisigWorkflow)
        .filter(models.MultisigWorkflow.id == workflow_id)
        .with_for_update()
        .first()
    )
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")

    signer = db.query(models.MultisigWorkflowSigner).filter(
        models.MultisigWorkflowSigner.workflow_id == wf.id,
        models.MultisigWorkflowSigner.user_address == current_user.address.lower()
    ).first()
    if not signer:
        raise HTTPException(status_code=403, detail="You are not a signer for this workflow")

    if wf.status != "pending":
        raise HTTPException(status_code=400, detail=f"Workflow is {wf.status}")

    # A single rejection blocks the whole workflow. The secret is never released;
    # the owner can then delete the blocked workflow.
    wf.status = "rejected"
    wf.rejected_by = current_user.address.lower()
    wf.rejected_at = datetime.now(timezone.utc)
    db.commit()

    sender_name = current_user.username or f"{current_user.address[:8]}..."
    if wf.owner_address != current_user.address:
        notify_user_push(
            db,
            wf.owner_address,
            title="Workflow Rejected",
            body=f"{sender_name} rejected your workflow: {wf.name}",
            data={"type": "multisig_rejected", "workflow_id": wf.id}
        )

    db.refresh(wf)
    return wf

@router.delete("/workflow/{workflow_id}", status_code=204)
@limiter.limit("20/minute")
def delete_multisig_workflow(request: Request, workflow_id: int, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    wf = db.query(models.MultisigWorkflow).filter(models.MultisigWorkflow.id == workflow_id).first()
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")

    # Only the initiator (owner) may delete, and only before release. A completed
    # workflow has already handed the secret to recipients, so deletion is refused.
    if wf.owner_address != current_user.address:
        raise HTTPException(status_code=403, detail="Only the workflow owner may delete it")
    if wf.status == "completed":
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
        db.query(models.AccessGrant).filter(
            models.AccessGrant.secret_id == secret_id
        ).delete(synchronize_session=False)
        secret = db.query(models.Secret).filter(models.Secret.id == secret_id).first()
        if secret:
            db.delete(secret)

    db.commit()
    return None
