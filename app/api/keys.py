from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from pydantic import BaseModel
from typing import List, Optional
import base64

from app.database import get_db
from app.kms.key_manager import KeyManager
from app.crypto.core import CryptoCore
from app.api.auth import get_current_user
from app.iam.policy import PolicyEngine

router = APIRouter(prefix="/keys", tags=["key management"])


# Pydantic models
class CreateKeyRequest(BaseModel):
    name: str
    allowed_ops: List[str]  # ["encrypt", "decrypt"]
    rotation_days: int = 90


class CreateKeyResponse(BaseModel):
    id: str
    name: str
    type: str
    algorithm: str
    created_at: str
    expires_at: str
    allowed_ops: List[str]


class EncryptRequest(BaseModel):
    key_id: str
    plaintext_b64: str
    aad_b64: Optional[str] = None


class EncryptResponse(BaseModel):
    ciphertext_b64: str
    iv_b64: str
    tag_b64: str


class DecryptRequest(BaseModel):
    key_id: str
    ciphertext_b64: str
    iv_b64: str
    tag_b64: str
    aad_b64: Optional[str] = None


class DecryptResponse(BaseModel):
    plaintext_b64: str


class ListKeysResponse(BaseModel):
    keys: List[dict]


# Initialize components
crypto = CryptoCore()
kms = KeyManager(crypto)


def _policy(db: Session) -> PolicyEngine:
    return PolicyEngine(db)


def _db_error_detail(e: Exception) -> str:
    # Helpful hint for the common SQLite schema mismatch issue
    return (
        "Database error. If you recently changed the SQLAlchemy models, "
        "SQLite tables are NOT auto-migrated by create_all(). "
        "Recreate/migrate the DB (e.g., delete data/kms-iam.db and rerun scripts/init_db.py). "
        f"Error: {str(e)}"
    )


@router.post("/create", response_model=CreateKeyResponse)
def create_key(
        request: CreateKeyRequest,
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    policy = _policy(db)
    roles = current_user.get("roles", [])
    if not policy.can_create_key(roles):
        raise HTTPException(status_code=403, detail="Not allowed to create keys")

    try:
        result = kms.create_key(
            db, request.name, current_user["id"], request.allowed_ops, request.rotation_days
        )
        return CreateKeyResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=_db_error_detail(e))


@router.post("/encrypt", response_model=EncryptResponse)
def encrypt(
        request: EncryptRequest,
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    policy = _policy(db)
    roles = current_user.get("roles", [])
    if not policy.can_encrypt(roles):
        raise HTTPException(status_code=403, detail="Not allowed to encrypt")

    try:
        plaintext = base64.b64decode(request.plaintext_b64)
        aad = base64.b64decode(request.aad_b64) if request.aad_b64 else None

        result = kms.encrypt(db, request.key_id, plaintext, current_user["id"], aad)

        return EncryptResponse(
            ciphertext_b64=result["ciphertext"],
            iv_b64=result["iv"],
            tag_b64=result["tag"],
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=_db_error_detail(e))


@router.post("/decrypt", response_model=DecryptResponse)
def decrypt(
        request: DecryptRequest,
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    policy = _policy(db)
    roles = current_user.get("roles", [])
    if not policy.can_decrypt(roles):
        raise HTTPException(status_code=403, detail="Not allowed to decrypt")

    try:
        aad = base64.b64decode(request.aad_b64) if request.aad_b64 else None

        plaintext = kms.decrypt(
            db,
            request.key_id,
            request.ciphertext_b64,
            request.iv_b64,
            request.tag_b64,
            current_user["id"],
            aad,
        )

        return DecryptResponse(plaintext_b64=base64.b64encode(plaintext).decode())
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=_db_error_detail(e))


@router.get("/", response_model=ListKeysResponse)
def list_keys(
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    policy = _policy(db)
    roles = current_user.get("roles", [])
    if not policy.can_list_keys(roles):
        raise HTTPException(status_code=403, detail="Not allowed to list keys")

    try:
        keys = kms.list_keys(db, current_user["id"])
        return ListKeysResponse(keys=keys)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=_db_error_detail(e))


@router.post("/{key_id}/rotate")
def rotate_key(
        key_id: str,
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    policy = _policy(db)
    roles = current_user.get("roles", [])
    if not policy.can_rotate_key(roles):
        raise HTTPException(status_code=403, detail="Not allowed to rotate keys")

    try:
        return kms.rotate_key(db, key_id, current_user["id"])
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=_db_error_detail(e))
