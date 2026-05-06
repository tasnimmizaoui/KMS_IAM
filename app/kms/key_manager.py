import json
from datetime import datetime, timedelta
from typing import List, Dict
from sqlalchemy.orm import Session

from app.models.key import Key
from app.crypto.core import CryptoCore


class KeyManager:
    # Key lifecycle & operations
    def __init__(self, crypto: CryptoCore):
        self.crypto = crypto

    def create_key(
            self,
            db: Session,
            name: str,
            user_id: str,
            allowed_ops: List[str],
            rotation_days: int = 90,
    ) -> Dict:
        """Create a new cryptographic key"""
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

        return {
            "id": new_key.id,
            "name": new_key.name,
            "type": new_key.type,
            "algorithm": new_key.algorithm,
            "created_at": new_key.created_at.isoformat() if new_key.created_at else None,
            "expires_at": new_key.expires_at.isoformat() if new_key.expires_at else None,
            "allowed_ops": allowed_ops,
        }

    def get_key(self, db: Session, key_id: str, user_id: str, operation: str) -> bytes:
        """Retrieve and decrypt key material (internal use)"""
        key = db.query(Key).filter(Key.id == key_id, Key.state == "enabled").first()
        if not key:
            raise ValueError(f"Key {key_id} not found or not enabled")

        # allowed_ops must be valid JSON list
        allowed_ops = json.loads(key.allowed_ops or "[]")
        if operation not in allowed_ops:
            raise PermissionError(f"Key not allowed for operation: {operation}")

        encrypted_blob = json.loads(key.encrypted_blob)
        raw_key = self.crypto.decrypt_envelope(encrypted_blob)
        return raw_key

    def encrypt(self, db: Session, key_id: str, plaintext: bytes, user_id: str, aad: bytes = None) -> Dict:
        """Encrypt data using a key"""
        key_bytes = self.get_key(db, key_id, user_id, "encrypt")
        return self.crypto.encrypt_with_key(key_bytes, plaintext, aad)

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
        key_bytes = self.get_key(db, key_id, user_id, "decrypt")
        return self.crypto.decrypt_with_key(key_bytes, ciphertext_b64, iv_b64, tag_b64, aad)

    def list_keys(self, db: Session, user_id: str) -> List[Dict]:
        """List all keys (metadata only, no key material)"""
        keys = db.query(Key).filter(Key.state == "enabled").all()

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
            raise ValueError(f"Key {key_id} not found")

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

            # Disable old key for encryption but keep for decryption
            old_ops = json.loads(old_key.allowed_ops or "[]")
            if "encrypt" in old_ops:
                old_ops.remove("encrypt")
                old_key.allowed_ops = json.dumps(old_ops)

            db.commit()
            db.refresh(new_key)

            return {
                "old_key_id": key_id,
                "new_key_id": new_key.id,
                "new_version": new_key.version,
            }
        except Exception:
            db.rollback()
            raise
