from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List


class TressBase(BaseModel):
    title: str
    content: str
    language: str
    is_public: bool = True


class TressCreate(TressBase):
    expires_in_days: Optional[int] = Field(None, ge=1, le=365, description="过期天数，1-365天，不设置则永不过期")


class Tress(TressBase):
    id: int
    owner_id: Optional[int] = None  # 匿名用户可以为空
    owner_username: Optional[str] = None  # 匿名用户可以为空
    created_at: datetime
    expires_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class TressPreview(BaseModel):
    """Tree预览模式，只包含基本信息，不包含完整内容"""
    id: int
    title: str
    language: str
    is_public: bool
    owner_id: Optional[int] = None
    owner_username: Optional[str] = None
    created_at: datetime
    expires_at: Optional[datetime] = None
    content_preview: str = Field(description="内容预览，截取前200个字符")

    class Config:
        from_attributes = True


class PaginationInfo(BaseModel):
    """分页信息"""
    page: int = Field(description="当前页码，从1开始")
    page_size: int = Field(description="每页大小")
    total_items: int = Field(description="总条目数")
    total_pages: int = Field(description="总页数")
    has_next: bool = Field(description="是否有下一页")
    has_prev: bool = Field(description="是否有上一页")


class TressPageResponse(BaseModel):
    """分页响应"""
    items: List[TressPreview] = Field(description="当前页的树列表")
    pagination: PaginationInfo = Field(description="分页信息")
