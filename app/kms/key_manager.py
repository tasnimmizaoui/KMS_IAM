import json
from datetime import datetime, timedelta
from typing import List, Dict
from sqlalchemy.orm import Session

from app.models.key import Key
from app.crypto.core import CryptoCore
from app.audit.logger import AuditLogger
from app.kms.errors import KeyNotFoundError, InvalidKeyStateError, InvalidAllowedOpsError


class KeyManager:
    # Key lifecycle & operations
    def __init__(self, crypto: CryptoCore):
        self.crypto = crypto

    @staticmethod
    def _validate_allowed_ops(allowed_ops: List[str]) -> List[str]:
        """Validate and normalize allowed operations for key usage."""
        if not isinstance(allowed_ops, list) or not allowed_ops:
            raise InvalidAllowedOpsError("allowed_ops must be a non-empty list")

        supported = {"encrypt", "decrypt"}
        normalized = []
        seen = set()

        for op in allowed_ops:
            if not isinstance(op, str):
                raise InvalidAllowedOpsError("allowed_ops entries must be strings")
            if op not in supported:
                raise InvalidAllowedOpsError(
                    "allowed_ops contains unsupported operation(s); only 'encrypt' and 'decrypt' are allowed"
                )
            if op in seen:
                raise InvalidAllowedOpsError("allowed_ops contains duplicate operation(s)")
            seen.add(op)
            normalized.append(op)

        return normalized

    def create_key(
            self,
            db: Session,
            name: str,
            user_id: str,
            allowed_ops: List[str],
            rotation_days: int = 90,
    ) -> Dict:
        """Create a new cryptographic key"""
        try:
            allowed_ops = self._validate_allowed_ops(allowed_ops)
            raw_key = self.crypto.generate_aes_key()
            encrypted_blob = self.crypto.encrypt_envelope(raw_key)
            expires_at = datetime.utcnow() + timedelta(days=rotation_days)

            new_key = Key(
                name=name,
                type="aes",
                size=256,
                algorithm="AES-256-GCM",
                encrypted_blob=json.dumps(encrypted_blob),
                created_by=user_id,
                expires_at=expires_at,
                rotation_days=rotation_days,
                state="enabled",
                allowed_ops=json.dumps(allowed_ops),
                version=1,
            )

            db.add(new_key)
            db.commit()
            db.refresh(new_key)

            AuditLogger.log(
                user_id=user_id,
                action="KEY_CREATE",
                resource="key",
                resource_id=new_key.id,
                success=True,
                details={
                    "name": name,
                    "algorithm": new_key.algorithm,
                    "type": new_key.type,
                    "version": new_key.version,
                    "rotation_days": rotation_days,
                    "allowed_ops": allowed_ops,
                },
            )

            return {
                "id": new_key.id,
                "name": new_key.name,
                "type": new_key.type,
                "algorithm": new_key.algorithm,
                "created_at": new_key.created_at.isoformat() if new_key.created_at else None,
                "expires_at": new_key.expires_at.isoformat() if new_key.expires_at else None,
                "allowed_ops": allowed_ops,
            }
        except Exception as e:
            db.rollback()
            AuditLogger.log(
                user_id=user_id,
                action="KEY_CREATE",
                resource="key",
                resource_id=name,  # best-effort identifier
                success=False,
                details={"error": str(e)},
            )
            raise

    def get_key(self, db: Session, key_id: str, user_id: str, operation: str) -> bytes:
        """Retrieve and decrypt key material (internal use)"""
        key = db.query(Key).filter(Key.id == key_id, Key.state == "enabled").first()
        if not key:
            raise ValueError(f"Key {key_id} not found or not enabled")

        allowed_ops = json.loads(key.allowed_ops or "[]")
        if operation not in allowed_ops:
            raise PermissionError(f"Key not allowed for operation: {operation}")

        encrypted_blob = json.loads(key.encrypted_blob)
        raw_key = self.crypto.decrypt_envelope(encrypted_blob)
        return raw_key

    def encrypt(self, db: Session, key_id: str, plaintext: bytes, user_id: str, aad: bytes = None) -> Dict:
        """Encrypt data using a key"""
        try:
            key_bytes = self.get_key(db, key_id, user_id, "encrypt")
            result = self.crypto.encrypt_with_key(key_bytes, plaintext, aad)

            AuditLogger.log(
                user_id=user_id,
                action="KEY_ENCRYPT",
                resource="key",
                resource_id=key_id,
                success=True,
                details={
                    "aad_present": bool(aad),
                    "plaintext_len": len(plaintext) if plaintext is not None else None,
                },
            )

            return result
        except Exception as e:
            AuditLogger.log(
                user_id=user_id,
                action="KEY_ENCRYPT",
                resource="key",
                resource_id=key_id,
                success=False,
                details={"error": str(e), "aad_present": bool(aad)},
            )
            raise

    def decrypt(
            self,
            db: Session,
            key_id: str,
            ciphertext_b64: str,
            iv_b64: str,
            tag_b64: str,
            user_id: str,
            aad: bytes = None,
    ) -> bytes:
        """Decrypt data using a key"""
        try:
            key_bytes = self.get_key(db, key_id, user_id, "decrypt")
            plaintext = self.crypto.decrypt_with_key(key_bytes, ciphertext_b64, iv_b64, tag_b64, aad)

            AuditLogger.log(
                user_id=user_id,
                action="KEY_DECRYPT",
                resource="key",
                resource_id=key_id,
                success=True,
                details={
                    "aad_present": bool(aad),
                    # no ciphertext logging, only a small metadata piece:
                    "ciphertext_b64_len": len(ciphertext_b64) if ciphertext_b64 is not None else None,
                },
            )

            return plaintext
        except Exception as e:
            AuditLogger.log(
                user_id=user_id,
                action="KEY_DECRYPT",
                resource="key",
                resource_id=key_id,
                success=False,
                details={"error": str(e), "aad_present": bool(aad)},
            )
            raise

    def list_keys(self, db: Session, user_id: str) -> List[Dict]:
        """List all keys (metadata only, no key material)"""
        keys = db.query(Key).filter(Key.state == "enabled").all()

        # (Optionnel) audit : c’est souvent bruyant, je le laisse commenté.
        # AuditLogger.log(user_id, "KEY_LIST", "key", "*", True, {"count": len(keys)})

        return [
            {
                "id": k.id,
                "name": k.name,
                "type": k.type,
                "algorithm": k.algorithm,
                "created_at": k.created_at.isoformat() if k.created_at else None,
                "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                "state": k.state,
                "allowed_ops": json.loads(k.allowed_ops or "[]"),
                "version": k.version,
            }
            for k in keys
        ]

    def rotate_key(self, db: Session, key_id: str, user_id: str) -> Dict:
        """Rotate key: create new version, keep old one for decryption"""
        old_key = db.query(Key).filter(Key.id == key_id).first()
        if not old_key:
            AuditLogger.log(
                user_id=user_id,
                action="KEY_ROTATE",
                resource="key",
                resource_id=key_id,
                success=False,
                details={"error": "key_not_found"},
            )
            raise KeyNotFoundError(f"Key {key_id} not found")

        if old_key.state != "enabled":
            AuditLogger.log(
                user_id=user_id,
                action="KEY_ROTATE",
                resource="key",
                resource_id=key_id,
                success=False,
                details={"error": "invalid_key_state", "state": old_key.state},
            )
            raise InvalidKeyStateError(
                f"Key {key_id} state '{old_key.state}' is not valid for rotation"
            )

        try:
            new_encrypted_blob = self.crypto.encrypt_envelope(self.crypto.generate_aes_key())

            new_key = Key(
                name=f"{old_key.name}_v{old_key.version + 1}",
                type=old_key.type,
                size=old_key.size,
                algorithm=old_key.algorithm,
                encrypted_blob=json.dumps(new_encrypted_blob),
                created_by=user_id,
                expires_at=datetime.utcnow() + timedelta(days=old_key.rotation_days),
                rotation_days=old_key.rotation_days,
                state="enabled",
                allowed_ops=old_key.allowed_ops,
                version=old_key.version + 1,
                previous_version_id=key_id,
            )

            db.add(new_key)

            old_ops = json.loads(old_key.allowed_ops or "[]")
            old_allowed_before = list(old_ops)

            if "encrypt" in old_ops:
                old_ops.remove("encrypt")
                old_key.allowed_ops = json.dumps(old_ops)

            db.commit()
            db.refresh(new_key)

            AuditLogger.log(
                user_id=user_id,
                action="KEY_ROTATE",
                resource="key",
                resource_id=key_id,
                success=True,
                details={
                    "old_key_id": key_id,
                    "new_key_id": new_key.id,
                    "new_version": new_key.version,
                    "old_allowed_ops_before": old_allowed_before,
                    "old_allowed_ops_after": json.loads(old_key.allowed_ops or "[]"),
                },
            )

            return {
                "old_key_id": key_id,
                "new_key_id": new_key.id,
                "new_version": new_key.version,
            }
        except Exception as e:
            db.rollback()
            AuditLogger.log(
                user_id=user_id,
                action="KEY_ROTATE",
                resource="key",
                resource_id=key_id,
                success=False,
                details={"error": str(e)},
            )
            raise
