from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
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


@router.post("/create", response_model=CreateKeyResponse)
def create_key(
        request: CreateKeyRequest,
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Create a new cryptographic key"""
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


@router.post("/encrypt", response_model=EncryptResponse)
def encrypt(
        request: EncryptRequest,
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Encrypt data using a key"""
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
        # ex: key allowed_ops does not include encrypt
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/decrypt", response_model=DecryptResponse)
def decrypt(
        request: DecryptRequest,
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Decrypt data using a key"""
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


@router.get("/", response_model=ListKeysResponse)
def list_keys(
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """List all keys (metadata only)"""
    policy = _policy(db)
    roles = current_user.get("roles", [])

    if not policy.can_list_keys(roles):
        raise HTTPException(status_code=403, detail="Not allowed to list keys")

    try:
        keys = kms.list_keys(db, current_user["id"])
        return ListKeysResponse(keys=keys)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))


@router.post("/{key_id}/rotate")
def rotate_key(
        key_id: str,
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """Rotate a key (create new version)"""
    policy = _policy(db)
    roles = current_user.get("roles", [])

    if not policy.can_rotate_key(roles):
        raise HTTPException(status_code=403, detail="Not allowed to rotate keys")

    try:
        result = kms.rotate_key(db, key_id, current_user["id"])
        return result
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
