import os
import secrets
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from app.config import settings

class CryptoCore:
    """Core cryptographic operations with envelope encryption"""
    
    def __init__(self):
        self.backend = default_backend()
        self.master_key = self._load_or_create_master_key()
    
    def _load_or_create_master_key(self) -> bytes:
        """Load existing master key or create new one"""
        os.makedirs(os.path.dirname(settings.MASTER_KEY_PATH), exist_ok=True)
        
        if os.path.exists(settings.MASTER_KEY_PATH):
            with open(settings.MASTER_KEY_PATH, 'rb') as f:
                return f.read()
        else:
            # Generate new master key (AES-256)
            master_key = secrets.token_bytes(32)
            with open(settings.MASTER_KEY_PATH, 'wb') as f:
                f.write(master_key)
            os.chmod(settings.MASTER_KEY_PATH, 0o600)
            print(f"✓ Master key created at {settings.MASTER_KEY_PATH}")
            return master_key
    
    def generate_data_key(self) -> bytes:
        """Generate a new data encryption key (DEK)"""
        return secrets.token_bytes(32)  # AES-256
    
    def encrypt_envelope(self, plaintext: bytes) -> dict:
        """
        Envelope encryption:
        1. Generate random DEK
        2. Encrypt plaintext with DEK (AES-256-GCM)
        3. Encrypt DEK with master key (AES-256-GCM)
        """
        # Generate DEK
        dek = self.generate_data_key()
        
        # Encrypt data with DEK
        iv_data = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(dek), modes.GCM(iv_data), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Encrypt DEK with master key
        iv_dek = secrets.token_bytes(12)
        master_cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(iv_dek), backend=self.backend)
        master_encryptor = master_cipher.encryptor()
        encrypted_dek = master_encryptor.update(dek) + master_encryptor.finalize()
        
        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "iv_data": base64.b64encode(iv_data).decode(),
            "tag_data": base64.b64encode(encryptor.tag).decode(),
            "encrypted_dek": base64.b64encode(encrypted_dek).decode(),
            "iv_dek": base64.b64encode(iv_dek).decode(),
            "tag_dek": base64.b64encode(master_encryptor.tag).decode()
        }
    
    def decrypt_envelope(self, envelope: dict) -> bytes:
        """
        Decrypt envelope:
        1. Decrypt DEK using master key
        2. Decrypt ciphertext using DEK
        """
        # Decrypt DEK with master key
        master_cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.GCM(
                base64.b64decode(envelope["iv_dek"]),
                base64.b64decode(envelope["tag_dek"])
            ),
            backend=self.backend
        )
        master_decryptor = master_cipher.decryptor()
        dek = master_decryptor.update(base64.b64decode(envelope["encrypted_dek"])) + master_decryptor.finalize()
        
        # Decrypt data with DEK
        cipher = Cipher(
            algorithms.AES(dek),
            modes.GCM(
                base64.b64decode(envelope["iv_data"]),
                base64.b64decode(envelope["tag_data"])
            ),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(base64.b64decode(envelope["ciphertext"])) + decryptor.finalize()
        
        return plaintext
    
    def generate_aes_key(self) -> bytes:
        """Generate raw AES key for storage as key material"""
        return secrets.token_bytes(32)
    
    def encrypt_with_key(self, key_bytes: bytes, plaintext: bytes, aad: bytes = None) -> dict:
        """Encrypt data with a provided key (for KMS operations)"""
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        if aad:
            encryptor.authenticate_additional_data(aad)
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "iv": base64.b64encode(iv).decode(),
            "tag": base64.b64encode(encryptor.tag).decode()
        }
    
    def decrypt_with_key(self, key_bytes: bytes, ciphertext_b64: str, iv_b64: str, tag_b64: str, aad: bytes = None) -> bytes:
        """Decrypt data with a provided key"""
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        tag = base64.b64decode(tag_b64)
        
        cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        
        if aad:
            decryptor.authenticate_additional_data(aad)
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
