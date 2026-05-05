#!/usr/bin/env python
import json
import os
from datetime import datetime

def view_audit():
    log_file = "data/audit.log"
    
    if not os.path.exists(log_file):
        print("No audit logs found yet.")
        return
    
    print("=" * 80)
    print("AUDIT LOGS")
    print("=" * 80)
    
    with open(log_file, "r") as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                timestamp = entry.get("timestamp", "")[:19]
                user = entry.get("user_id", "")[:16]
                action = entry.get("action", "").ljust(20)
                resource = entry.get("resource", "")
                success = "✅" if entry.get("success") else "❌"
                
                print(f"{timestamp} | {success} | {user} | {action} | {resource}")
            except:
                pass
    
    print("=" * 80)

if __name__ == "__main__":
    view_audit()