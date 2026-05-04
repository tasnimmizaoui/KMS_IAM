import jwt
import bcrypt
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from typing import Optional, Dict, List
from app.config import settings
from app.database import SessionLocal
from app.models.user import User
from app.models.role import Role, user_roles
from app.audit.logger import AuditLogger

class IAMManager:
    def __init__(self):
        self.secret_key = settings.SECRET_KEY
        self.algorithm = settings.JWT_ALGORITHM
        self.expiry_minutes = settings.JWT_EXPIRY_MINUTES
    
    def hash_password(self, password: str) -> str:
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def create_user(self, db: Session, username: str, password: str, email: str = None, 
                    source_ip: str = None) -> Dict:
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            AuditLogger.log(None, "REGISTER_FAIL", "user", username, False,
                          {"reason": "username_exists", "attempted_username": username}, source_ip)
            raise ValueError(f"User '{username}' already exists")
        
        user = User(
            username=username,
            email=email,
            password_hash=self.hash_password(password),
            is_active=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        
        AuditLogger.log(user.id, "USER_CREATED", "user", user.id, True,
                       {"username": username}, source_ip)
        
        return {"id": user.id, "username": user.username, "email": user.email}
    
    def authenticate(self, db: Session, username: str, password: str, source_ip: str = None) -> Optional[str]:
        user = db.query(User).filter(User.username == username, User.is_active == True).first()
        
        if not user or not self.verify_password(password, user.password_hash):
            AuditLogger.log(None, "LOGIN_FAIL", "auth", username, False,
                          {"reason": "invalid_credentials", "attempted_username": username}, source_ip)
            return None
        
        roles = [role.name for role in user.roles]
        
        payload = {
            "sub": user.id,
            "username": user.username,
            "roles": roles,
            "exp": datetime.utcnow() + timedelta(minutes=self.expiry_minutes),
            "iat": datetime.utcnow()
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        AuditLogger.log(user.id, "LOGIN_SUCCESS", "auth", user.id, True,
                       {"username": username, "roles": roles}, source_ip)
        
        return token
    
    def verify_token(self, token: str, source_ip: str = None) -> Optional[Dict]:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            AuditLogger.log(payload.get("sub"), "TOKEN_VERIFIED", "auth", payload.get("sub"), True,
                          {"token_type": "jwt"}, source_ip)
            return payload
        except jwt.ExpiredSignatureError:
            AuditLogger.log(None, "TOKEN_EXPIRED", "auth", "unknown", False, {}, source_ip)
            return None
        except jwt.InvalidTokenError:
            AuditLogger.log(None, "TOKEN_INVALID", "auth", "unknown", False, {}, source_ip)
            return None
    
    def assign_role(self, db: Session, username: str, role_name: str, 
                    assigned_by: str = None, source_ip: str = None) -> bool:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise ValueError(f"User '{username}' not found")
        
        role = db.query(Role).filter(Role.name == role_name).first()
        if not role:
            role = Role(name=role_name, description=f"Auto-created role: {role_name}")
            db.add(role)
            db.commit()
            db.refresh(role)
        
        if role not in user.roles:
            user.roles.append(role)
            db.commit()
            AuditLogger.log(assigned_by, "ROLE_ASSIGNED", "role", role.id, True,
                          {"target_user": username, "role_name": role_name, "assigned_by": assigned_by}, source_ip)
        else:
            AuditLogger.log(assigned_by, "ROLE_ALREADY_ASSIGNED", "role", role.id, True,
                          {"target_user": username, "role_name": role_name}, source_ip)
        
        return True
    
    def get_user_roles(self, db: Session, user_id: str) -> List[str]:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return []
        return [role.name for role in user.roles]