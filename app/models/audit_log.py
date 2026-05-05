from sqlalchemy import Column, String, DateTime, Boolean, Text, func
from app.database import Base
import uuid

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), index=True)
    action = Column(String(100))
    resource_type = Column(String(50))
    resource_id = Column(String(100))
    success = Column(Boolean)
    details = Column(Text)
    source_ip = Column(String(45))
    timestamp = Column(DateTime(timezone=True), server_default=func.now())