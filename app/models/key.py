from sqlalchemy import Column, String, Integer, DateTime, Boolean, Text, func
from app.database import Base
import uuid

class Key(Base):
    __tablename__ = "keys"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    type = Column(String(50))
    size = Column(Integer)
    algorithm = Column(String(50))
    encrypted_blob = Column(Text, nullable=False)
    created_by = Column(String(36))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True))
    rotation_days = Column(Integer, default=90)
    state = Column(String(20), default='enabled')
    allowed_ops = Column(String(255))
    version = Column(Integer, default=1)
    previous_version_id = Column(String(36), nullable=True) 