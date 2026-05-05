import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import SessionLocal
from app.models.role import Role

def init_roles():
    db = SessionLocal()
    
    default_roles = [
        ("admin", "Full system access - can manage users, keys, and policies"),
        ("key_manager", "Can create, rotate, and manage cryptographic keys"),
        ("key_user", "Can use existing keys for encryption and decryption only")
    ]
    
    for role_name, description in default_roles:
        exists = db.query(Role).filter(Role.name == role_name).first()
        if not exists:
            role = Role(name=role_name, description=description)
            db.add(role)
            print(f"✓ Created role: {role_name}")
    
    db.commit()
    db.close()
    print("Default roles initialized.")

if __name__ == "__main__":
    init_roles()
