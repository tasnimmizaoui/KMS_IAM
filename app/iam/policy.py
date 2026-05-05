# RBAC/ABAC policies
from typing import Dict, List, Any
from sqlalchemy.orm import Session
from app.models.role import Role

class PolicyEngine:
    """Simple policy evaluation engine for RBAC"""
    
    # Define what actions each role can perform
    ROLE_POLICIES = {
        "admin": {
            "allow": ["*"]  # All actions on all resources
        },
        "key_manager": {
            "allow": [
                "key:create",
                "key:read",
                "key:rotate",
                "key:list",
                "key:delete"
            ]
        },
        "key_user": {
            "allow": [
                "key:encrypt",
                "key:decrypt",
                "key:list"
            ]
        }
    }
    
    # Resource-based permissions
    RESOURCE_POLICIES = {
        "kms": {
            "key_manager": ["create", "read", "rotate", "list"],
            "key_user": ["encrypt", "decrypt", "list"]
        },
        "iam": {
            "admin": ["*"],
            "key_manager": ["view_users"],
            "key_user": []
        }
    }
    
    def __init__(self, db: Session):
        self.db = db
    
    def check_permission(self, user_roles: List[str], action: str, resource: str = "kms") -> bool:
        """
        Check if user with given roles can perform action on resource.
        Format: action can be "key:create" or simple action like "create"
        """
        # Admin can do anything
        if "admin" in user_roles:
            return True
        
        # Check role-based policies from static config
        for role in user_roles:
            if role in self.ROLE_POLICIES:
                allowed_actions = self.ROLE_POLICIES[role].get("allow", [])
                if "*" in allowed_actions or action in allowed_actions:
                    return True
                
                # Check for wildcard patterns like "key:*"
                for allowed in allowed_actions:
                    if allowed.endswith(":*") and action.startswith(allowed[:-1]):
                        return True
        
        # Check resource-based policies
        if resource in self.RESOURCE_POLICIES:
            for role in user_roles:
                if role in self.RESOURCE_POLICIES[resource]:
                    allowed_actions = self.RESOURCE_POLICIES[resource][role]
                    if "*" in allowed_actions or action in allowed_actions:
                        return True
        
        return False
    
    def can_create_key(self, user_roles: List[str]) -> bool:
        return self.check_permission(user_roles, "create", "kms")
    
    def can_encrypt(self, user_roles: List[str]) -> bool:
        return self.check_permission(user_roles, "encrypt", "kms")
    
    def can_decrypt(self, user_roles: List[str]) -> bool:
        return self.check_permission(user_roles, "decrypt", "kms")
    
    def can_rotate_key(self, user_roles: List[str]) -> bool:
        return self.check_permission(user_roles, "rotate", "kms")
