from sqlalchemy import Boolean, Column, Integer, String, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.db.base import Base


class Tress(Base):
    __tablename__ = "tresses"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    content = Column(Text)
    language = Column(String)  # 代码语言/格式
    is_public = Column(Boolean, default=True)
    owner_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="tresses")
