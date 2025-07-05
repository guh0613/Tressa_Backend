from sqlalchemy import Boolean, Column, Integer, String, ForeignKey, Text, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.db.base import Base


class Tress(Base):
    __tablename__ = "tresses"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    content = Column(Text)
    language = Column(String)
    is_public = Column(Boolean, default=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # 允许匿名用户，所以可以为空
    owner_username = Column(String, nullable=True)  # 匿名用户可以为空
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)  # 过期时间，可以为空表示永不过期

    owner = relationship("User", back_populates="tresses")
