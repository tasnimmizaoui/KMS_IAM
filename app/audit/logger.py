import json
import os
from datetime import datetime
from typing import Optional
import threading
from app.config import settings

class AuditLogger:
    """Thread-safe audit logger for compliance"""
    
    _lock = threading.Lock()

    @staticmethod
    def _log_file_path() -> str:
        return settings.AUDIT_LOG_PATH
    
    @classmethod
    def log(cls, user_id: Optional[str], action: str, resource: str, 
            resource_id: str, success: bool, details: dict = None, 
            source_ip: str = None):
        """Record an auditable event"""
        
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user_id": user_id or "unauthenticated",
            "action": action,
            "resource": resource,
            "resource_id": resource_id,
            "success": success,
            "details": details or {},
            "source_ip": source_ip
        }

        log_file = cls._log_file_path()
        log_dir = os.path.dirname(log_file) or "."
        os.makedirs(log_dir, exist_ok=True)
        
        # Thread-safe write to audit log file
        with cls._lock:
            with open(log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        
        # Also log to console for debugging
        print(f"[AUDIT] {entry['timestamp']} | {entry['user_id']} | "
              f"{entry['action']} | {entry['resource']} | {'SUCCESS' if success else 'FAIL'}")
        
        return entry
    
    @classmethod
    def get_logs(cls, limit: int = 100, user_id: str = None, action: str = None) -> list:
        """Retrieve audit logs for reporting"""
        logs = []
        log_file = cls._log_file_path()
        
        if not os.path.exists(log_file):
            return []
        
        with open(log_file, "r") as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    
                    # Filter if needed
                    if user_id and entry.get("user_id") != user_id:
                        continue
                    if action and entry.get("action") != action:
                        continue
                    
                    logs.append(entry)
                except:
                    continue
        
        # Return most recent first
        return logs[-limit:][::-1]