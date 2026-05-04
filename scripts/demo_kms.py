#!/usr/bin/env python
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import base64
from app.database import SessionLocal
from app.iam.manager import IAMManager
from app.crypto.core import CryptoCore
from app.kms.key_manager import KeyManager
from app.models.user import User

def demo():
    print("=" * 50)
    print("KMS Demo - Envelope Encryption in Action")
    print("=" * 50)
    
    db = SessionLocal()
    iam = IAMManager()
    crypto = CryptoCore()
    kms = KeyManager(crypto)
    
    # 1. Create a test user
    print("\n1. Creating test user...")
    try:
        user_dict = iam.create_user(db, "demo_user", "DemoPass123!", "demo@example.com")
        user_id = user_dict['id']
        print(f"   ✓ User created: {user_dict['username']} (ID: {user_id})")
    except ValueError:
        # User exists, get from database
        from app.models.user import User
        user = db.query(User).filter(User.username == "demo_user").first()
        user_id = user.id
        print(f"   ✓ Using existing user: {user.username} (ID: {user_id})")
    
    # 2. Assign key_manager role
    print("\n2. Assigning key_manager role...")
    iam.assign_role(db, "demo_user", "key_manager")
    print("   ✓ Role assigned")
    
    # 3. Create a cryptographic key
    print("\n3. Creating a new encryption key...")
    key = kms.create_key(db, "demo-key", user_id, ["encrypt", "decrypt"], 90)
    print(f"   ✓ Key created: {key['id']}")
    print(f"     Name: {key['name']}")
    print(f"     Type: {key['type']}")
    print(f"     Algorithm: {key['algorithm']}")
    
    # 4. Encrypt a secret message
    print("\n4. Encrypting a secret message...")
    plaintext = b"Secret: The launch code is 12345"
    print(f"   Plaintext: {plaintext.decode()}")
    
    encrypted = kms.encrypt(db, key['id'], plaintext, user_id)
    print(f"   ✓ Encrypted successfully")
    print(f"     Ciphertext (first 50 chars): {encrypted['ciphertext'][:50]}...")
    print(f"     IV: {encrypted['iv'][:20]}...")
    print(f"     Tag: {encrypted['tag'][:20]}...")
    
    # 5. Decrypt the message
    print("\n5. Decrypting the message...")
    decrypted = kms.decrypt(db, key['id'], encrypted['ciphertext'], 
                           encrypted['iv'], encrypted['tag'], user_id)
    print(f"   ✓ Decrypted successfully")
    print(f"     Decrypted: {decrypted.decode()}")
    
    # 6. Verify integrity
    print("\n6. Verification...")
    if plaintext == decrypted:
        print("   ✓ PASS: Original and decrypted match!")
    else:
        print("   ✗ FAIL: Decryption produced different result")
    
    # 7. List all keys
    print("\n7. Listing all keys...")
    keys = kms.list_keys(db, user_id)
    for k in keys:
        print(f"   - {k['name']} ({k['id'][:8]}...) - {k['state']}")
    
    # 8. Show envelope encryption info
    print("\n8. Envelope encryption details:")
    print("   - Data encrypted with DEK (Data Encryption Key)")
    print("   - DEK encrypted with Master Key (stored in ./data/master.key)")
    print("   - Master key never leaves the KMS (simulated HSM)")
    
    db.close()
    print("\n" + "=" * 50)
    print("Demo completed successfully!")
    print("=" * 50)

if __name__ == "__main__":
    demo()