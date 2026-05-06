from fastapi import APIRouter, Depends, HTTPException
from typing import Optional
from app.audit.logger import AuditLogger
from app.api.auth import get_current_user

router = APIRouter(prefix="/audit", tags=["audit"])

@router.get("/logs")
def get_audit_logs(
    limit: Optional[int] = 100,
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Retrieve audit logs (admin only)"""
    
    # Only admin can view audit logs
    if "admin" not in current_user.get("roles", []):
        AuditLogger.log(
            user_id=current_user.get("id"),
            action="AUDIT_LOGS_READ",
            resource="audit",
            resource_id="logs",
            success=False,
            details={"reason": "insufficient_role", "roles": current_user.get("roles", [])},
        )
        raise HTTPException(status_code=403, detail="Admin access required")
    
    logs = AuditLogger.get_logs(limit=limit, user_id=user_id, action=action)
    AuditLogger.log(
        user_id=current_user.get("id"),
        action="AUDIT_LOGS_READ",
        resource="audit",
        resource_id="logs",
        success=True,
        details={"returned_count": len(logs), "filter_user_id": user_id, "filter_action": action},
    )
    return {"logs": logs, "count": len(logs)}

@router.get("/stats")
def get_audit_stats(current_user: dict = Depends(get_current_user)):
    """Get audit statistics (admin only)"""
    
    if "admin" not in current_user.get("roles", []):
        AuditLogger.log(
            user_id=current_user.get("id"),
            action="AUDIT_STATS_READ",
            resource="audit",
            resource_id="stats",
            success=False,
            details={"reason": "insufficient_role", "roles": current_user.get("roles", [])},
        )
        raise HTTPException(status_code=403, detail="Admin access required")
    
    logs = AuditLogger.get_logs(limit=1000)
    
    stats = {
        "total_events": len(logs),
        "by_action": {},
        "by_success": {"success": 0, "failure": 0}
    }
    
    for log in logs:
        action = log.get("action", "unknown")
        stats["by_action"][action] = stats["by_action"].get(action, 0) + 1
        
        if log.get("success"):
            stats["by_success"]["success"] += 1
        else:
            stats["by_success"]["failure"] += 1

    AuditLogger.log(
        user_id=current_user.get("id"),
        action="AUDIT_STATS_READ",
        resource="audit",
        resource_id="stats",
        success=True,
        details={"total_events": stats["total_events"]},
    )
    
    return stats