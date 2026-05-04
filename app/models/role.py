from sqlalchemy import Column, String, Table, ForeignKey, DateTime, func
from sqlalchemy.orm import relationship
from app.database import Base
import uuid

user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", String(36), ForeignKey("users.id")),
    Column("role_id", String(36), ForeignKey("roles.id"))
)

class Role(Base):
    __tablename__ = "roles"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(String(255))
    users = relationship("User", secondary=user_roles, backref="roles")