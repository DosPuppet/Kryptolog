from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

import models
import schemas
from database import get_db
from dependencies import get_current_user, limiter
from security import authorization
from security.crypto_validation import LEGACY_MIN_KEY_LEN
from security.usernames import InvalidUsername, normalize_username, username_taken

router = APIRouter(prefix="/users", tags=["users"])

# NOTE: a free-form `PUT /users/me/public-key` setter used to live here. It was
# unused by any client and let an authenticated session change its ML-KEM key
# without a signature — undermining the login-time key binding (M-2) and lacking
# input validation (M-5). Removed: the encryption key is set only at login, where
# the identity's signature now covers it (see auth._login_message).


@router.put("/{address}", response_model=schemas.UserResponse)
@limiter.limit("30/minute")
def update_user(
    request: Request,
    address: str,
    user_update: schemas.UserUpdate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Change the caller's own username. Case-insensitively unique, NFKC-normalized,
    and refused when it mixes scripts.
    """
    if current_user.address.lower() != address.lower():
        raise HTTPException(status_code=403, detail="Not authorized to update this user")

    user = current_user

    if user_update.username is not None:
        try:
            new_username = normalize_username(user_update.username)
        except InvalidUsername as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        # Uniqueness is case-insensitive: the directory must not hold both
        # "alice" and "Alice" as separate identities.
        if username_taken(db, new_username, exclude_address=current_user.address):
            raise HTTPException(
                status_code=409, detail=f"Username '{new_username}' is already taken."
            )
        user.username = new_username

    db.commit()
    db.refresh(user)
    return user


# The directory answers searches, it does not list (audit 2026-10-12 K-13).
# `GET /users` with no term paged out every account — name, address, keys,
# dates — 100 at a time. Now:
#   • a username matches by substring from MIN_SEARCH_LEN characters, or
#     exactly at any length, so a two-letter name is still findable by the
#     person who knows it;
#   • an address matches only by PREFIX, and only from ADDRESS_PREFIX_MIN hex
#     characters. A short substring of an address enumerates the whole table:
#     256 two-character queries cover every row. A pasted address is what this
#     path is for, and that is thousands of characters long.
# A page is capped at MAX_SEARCH_PAGE. None of this makes enumeration
# impossible for a patient member — it makes it a long, rate-limited crawl
# that has to guess names, instead of one loop over `offset`.
MIN_SEARCH_LEN = 3
ADDRESS_PREFIX_MIN = 16
MAX_SEARCH_PAGE = 20
_HEX = frozenset("0123456789abcdef")


@router.get("/{address}", response_model=schemas.UserResponse)
# Same 30/min as POST /users/resolve: both answer "does this account exist?",
# so leaving this one uncapped made the paid-for limit on the other pointless.
@limiter.limit("30/minute")
def get_user(
    request: Request,
    address: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """One directory record by exact address, including a deleted identity
    (marked `deleted`, without its name), so a message that names it can say
    "user removed".
    """
    # Deliberately answers for a DELETED identity too, marked `deleted` by the
    # response model. This is the directory half of the rule in
    # security/authorization.py: a message or a group that still names the
    # address has to render as "user removed" rather than as an unknown
    # stranger, and this is the only lookup that can say which it is.
    user = db.query(models.User).filter(models.User.address == address.lower()).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.get("", response_model=list[schemas.UserResponse])
@limiter.limit("30/minute")
def list_users(
    request: Request,
    search: str = Query(..., max_length=200),
    only_pqc: bool = False,
    # Bounded at BOTH ends by FastAPI. The ceiling used to be clamped in the
    # body while the floor was unchecked, so `?limit=-1` reached PostgreSQL as
    # `LIMIT -1` — which is a hard error, i.e. a 500 on a trivial query string.
    limit: int = Query(5, ge=1, le=MAX_SEARCH_PAGE),
    offset: int = Query(0, ge=0),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Search the directory by username, or by the start of an address.

    Answers nothing for a term too short to search with; see the note on
    MIN_SEARCH_LEN for what matches and why there is no unsearched listing.
    """
    # Deleted identities are excluded here, unlike the two by-address lookups:
    # this list exists to PICK someone — to share a secret, add a member, start
    # a conversation — and a stripped row has no encryption key to wrap to.
    query = authorization.active_users(db)

    term = search.strip().lower()
    if not term:
        return []
    # lower(): LIKE is case-insensitive on SQLite but case-sensitive on
    # Postgres — the directory search must match regardless of case.
    username = func.lower(models.User.username)
    matches = [username == term]
    if len(term) >= MIN_SEARCH_LEN:
        matches.append(username.contains(term, autoescape=True))
    if len(term) >= ADDRESS_PREFIX_MIN and set(term) <= _HEX:
        matches.append(models.User.address.startswith(term, autoescape=True))
    query = query.filter(or_(*matches))

    if only_pqc:
        # Messenger requires an ML-KEM encryption key. Filtered in SQL so paging
        # stays correct; the floor (rather than the exact 2368-char length) keeps
        # legacy accounts whose keys predate strict validation visible, matching
        # is_usable_encryption_key's non-strict behaviour used by the endpoints
        # that actually gate on capability.
        query = query.filter(func.length(models.User.encryption_public_key) >= LEGACY_MIN_KEY_LEN)

    # A total order, so paging neither repeats nor skips a row.
    return (
        query.order_by(models.User.username, models.User.address).limit(limit).offset(offset).all()
    )


class UserResolveRequest(schemas.BaseModel):
    address: schemas.Address


@router.post("/resolve", response_model=schemas.UserResponse)
@limiter.limit("30/minute")
def resolve_user(
    request: Request,
    req: UserResolveRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Like `GET /users/{address}`, with the address in the body for addresses
    too long for comfortable URLs.
    """
    # Exact-match resolve of a user by their identity public key. Auth-gated.
    # Addresses are stored lowercased, so normalize the query (matches get_user).
    # Like GET /{address}, this answers for a deleted identity so the caller can
    # label it; see the note there.
    user = db.query(models.User).filter(models.User.address == req.address.lower()).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
