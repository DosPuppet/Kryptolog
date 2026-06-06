from fastapi import APIRouter, Depends, HTTPException, Request
from dependencies import limiter
from sqlalchemy.orm import Session, joinedload
from typing import List
from datetime import datetime, timezone
import models, schemas
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
        status="pending"
    )
    db.add(new_workflow)
    db.commit()
    db.refresh(new_workflow)

    # 3. Add Signers with their per-workflow encrypted keys
    for signer_addr in workflow.signers:
        s_addr = signer_addr.lower()
        normalized_keys = {k.lower(): v for k, v in workflow.signer_keys.items()}
        key = normalized_keys.get(s_addr)

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
        key = workflow.recipient_keys.get(r_addr)

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
def list_multisig_workflows(current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
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
def get_multisig_workflow(workflow_id: int, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
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

@router.post("/workflow/{workflow_id}/sign", response_model=schemas.MultisigWorkflowResponse)
@limiter.limit("20/minute")
def sign_multisig_workflow(request: Request, workflow_id: int, sig_req: schemas.MultisigSignatureRequest, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    wf = db.query(models.MultisigWorkflow).filter(models.MultisigWorkflow.id == workflow_id).first()
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
        
    signer = db.query(models.MultisigWorkflowSigner).filter(
        models.MultisigWorkflowSigner.workflow_id == wf.id,
        models.MultisigWorkflowSigner.user_address == current_user.address.lower()
    ).first()
    
    if not signer:
        raise HTTPException(status_code=403, detail="You are not a signer for this workflow")
        
    if signer.has_signed:
        raise HTTPException(status_code=400, detail="Already signed")
        
    # Update Signer
    signer.has_signed = True
    signer.signature = sig_req.signature
    signer.signed_at = datetime.now(timezone.utc)
    
    # Store Recipient Keys (Release Mechanism) if provided
    if sig_req.recipient_keys:
        for r_addr, enc_key in sig_req.recipient_keys.items():
            recipient = db.query(models.MultisigWorkflowRecipient).filter(
                models.MultisigWorkflowRecipient.workflow_id == wf.id,
                models.MultisigWorkflowRecipient.user_address == r_addr
            ).first()
            if recipient:
                recipient.encrypted_key = enc_key

    db.commit() # Commit this signature and keys first
    
    sender_name = current_user.username or f"{current_user.address[:8]}..."
    
    # Notify Owner
    if wf.owner_address != current_user.address:
        notify_user_push(
            db,
            wf.owner_address,
            title="Workflow Signed",
            body=f"{sender_name} signed your workflow: {wf.name}",
            data={"type": "multisig_signed", "workflow_id": wf.id}
        )

    # Check if ALL have signed
    all_signers = db.query(models.MultisigWorkflowSigner).filter(models.MultisigWorkflowSigner.workflow_id == wf.id).all()
    all_signed = all(s.has_signed for s in all_signers)
    
    if all_signed:
        wf.status = "completed"
        # Release handled above via Recipient Key updates in table
        db.commit()
        
        # Notify Recipients
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
