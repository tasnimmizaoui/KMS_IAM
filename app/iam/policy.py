# RBAC/ABAC policies
from typing import List
from sqlalchemy.orm import Session


class PolicyEngine:
    """Simple policy evaluation engine for RBAC"""

    # Define what actions each role can perform
    ROLE_POLICIES = {
        "admin": {
            "allow": ["*"]  # All actions on all resources
        },
        "key_manager": {
            # Align with README: key_manager can also encrypt/decrypt
            "allow": [
                "key:create",
                "key:read",
                "key:rotate",
                "key:list",
                "key:delete",
                "key:encrypt",
                "key:decrypt",
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

    # Resource-based permissions (simple actions)
    RESOURCE_POLICIES = {
        "kms": {
            # Align with README: key_manager can encrypt/decrypt
            "key_manager": ["create", "read", "rotate", "list", "encrypt", "decrypt"],
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

        action can be:
          - "key:create" (role policy style)
          - "create" (resource policy style)

        NOTE: This engine supports both formats for convenience.
        """
        # Admin can do anything
        if "admin" in user_roles:
            return True

        # 1) Check role-based policies (exact match + wildcards)
        for role in user_roles:
            role_policy = self.ROLE_POLICIES.get(role)
            if not role_policy:
                continue

            allowed_actions = role_policy.get("allow", [])
            if "*" in allowed_actions or action in allowed_actions:
                return True

            # Wildcard patterns like "key:*"
            for allowed in allowed_actions:
                if allowed.endswith(":*") and action.startswith(allowed[:-1]):
                    return True

        # 2) Check resource-based policies (simple actions)
        resource_policy = self.RESOURCE_POLICIES.get(resource, {})
        for role in user_roles:
            allowed = resource_policy.get(role, [])
            if "*" in allowed or action in allowed:
                return True

        return False

    def can_create_key(self, user_roles: List[str]) -> bool:
        return self.check_permission(user_roles, "create", "kms") or self.check_permission(user_roles, "key:create", "kms")

    def can_encrypt(self, user_roles: List[str]) -> bool:
        return self.check_permission(user_roles, "encrypt", "kms") or self.check_permission(user_roles, "key:encrypt", "kms")

    def can_decrypt(self, user_roles: List[str]) -> bool:
        return self.check_permission(user_roles, "decrypt", "kms") or self.check_permission(user_roles, "key:decrypt", "kms")

    def can_rotate_key(self, user_roles: List[str]) -> bool:
        return self.check_permission(user_roles, "rotate", "kms") or self.check_permission(user_roles, "key:rotate", "kms")

    def can_list_keys(self, user_roles: List[str]) -> bool:
        return self.check_permission(user_roles, "list", "kms") or self.check_permission(user_roles, "key:list", "kms")
