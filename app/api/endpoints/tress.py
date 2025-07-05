from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Response, Request, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone, timedelta

from app.db.base import get_db
from app.models.tress import Tress
from app.models.user import User
from app.schemas.tress import TressCreate, Tress as TressSchema, TressPageResponse, TressPreview, PaginationInfo
from app.api.endpoints.auth import get_current_user, get_current_user_optional
from app.core.security_middleware import (
    check_rate_limit,
    sanitize_content,
    validate_content_type,
    validate_content_size,
    add_security_headers,
    generate_etag,
    check_if_none_match
)

router = APIRouter()


@router.post("/", response_model=TressSchema)
async def create_tress(
        tress: TressCreate,
        request: Request,
        db: AsyncSession = Depends(get_db),
        current_user: Optional[User] = Depends(get_current_user_optional)
):
    # 速率限制检查 - 匿名用户使用更严格的限制
    if current_user is None:
        check_rate_limit(request, "public_read")  # 匿名用户使用更严格的限制
    else:
        check_rate_limit(request, "default")

    # 内容大小验证
    validate_content_size(tress.content, is_authenticated=current_user is not None)

    # 内容安全检查
    sanitized_content = sanitize_content(tress.content)

    # 验证内容类型
    if not validate_content_type(tress.language, tress.content):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Content does not match the specified language type"
        )

    # 处理过期时间
    expires_at = None
    if tress.expires_in_days is not None:
        # 匿名用户最长只能设置365天
        if current_user is None and tress.expires_in_days > 365:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Anonymous users can only set expiration up to 365 days"
            )
        expires_at = datetime.now(timezone.utc) + timedelta(days=tress.expires_in_days)
    elif current_user is None:
        # 匿名用户如果不设置过期时间，默认设置为30天
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

    # 创建tress数据
    tress_data = tress.model_dump(exclude={"expires_in_days"})  # 排除expires_in_days字段
    tress_data["content"] = sanitized_content  # 使用清理后的内容
    tress_data["expires_at"] = expires_at

    # 设置用户信息
    if current_user:
        tress_data["owner_id"] = current_user.id
        tress_data["owner_username"] = current_user.username
    else:
        tress_data["owner_id"] = None
        tress_data["owner_username"] = "Anonymous"

    db_tress = Tress(**tress_data)
    db.add(db_tress)
    await db.commit()
    await db.refresh(db_tress)
    return db_tress


@router.put("/{tress_id}", response_model=TressSchema)
async def update_tress(
        tress_id: int,
        tress: TressCreate,
        request: Request,
        db: AsyncSession = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    # 速率限制检查
    check_rate_limit(request, "default")

    result = await db.execute(select(Tress).where(Tress.id == tress_id))
    db_tress = result.scalar_one_or_none()

    if not db_tress:
        raise HTTPException(status_code=404, detail="Tress not found")

    # 检查是否已过期
    now = datetime.now(timezone.utc)
    if db_tress.expires_at and db_tress.expires_at <= now:
        raise HTTPException(status_code=404, detail="Tress has expired")

    if db_tress.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to update this tress")

    # 内容大小验证 - 更新时用户必须已认证
    validate_content_size(tress.content, is_authenticated=True)

    # 内容安全检查
    sanitized_content = sanitize_content(tress.content)

    # 验证内容类型
    if not validate_content_type(tress.language, tress.content):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Content does not match the specified language type"
        )

    # 处理过期时间更新
    expires_at = db_tress.expires_at  # 保持原有过期时间
    if tress.expires_in_days is not None:
        expires_at = datetime.now(timezone.utc) + timedelta(days=tress.expires_in_days)

    # 更新数据
    tress_data = tress.model_dump(exclude={"expires_in_days"})  # 排除expires_in_days字段
    tress_data["content"] = sanitized_content  # 使用清理后的内容
    tress_data["expires_at"] = expires_at

    for key, value in tress_data.items():
        setattr(db_tress, key, value)

    await db.commit()
    await db.refresh(db_tress)

    return db_tress


@router.get("/", response_model=List[TressSchema])
async def read_tresses(
        skip: int = 0,
        limit: int = 100,
        db: AsyncSession = Depends(get_db)
):
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(Tress)
        .where(
            Tress.is_public == True,
            # 只显示未过期的paste（expires_at为空或大于当前时间）
            (Tress.expires_at.is_(None)) | (Tress.expires_at > now)
        )
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/my", response_model=List[TressSchema])
async def read_user_tresses(
        db: AsyncSession = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(Tress)
        .where(
            Tress.owner_id == current_user.id,
            # 只显示未过期的paste（expires_at为空或大于当前时间）
            (Tress.expires_at.is_(None)) | (Tress.expires_at > now)
        )
    )
    return result.scalars().all()


@router.get("/public/pages", response_model=TressPageResponse)
async def read_public_tresses_paginated(
        page: int = 1,
        page_size: int = 20,
        request: Request = None,
        db: AsyncSession = Depends(get_db),
        current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    获取公开树的分页预览列表
    - page: 页码，从1开始
    - page_size: 每页大小，默认20，最大100
    """
    # 对匿名用户进行速率限制
    if not current_user:
        check_rate_limit(request, "public_read")

    # 验证分页参数
    if page < 1:
        raise HTTPException(status_code=400, detail="Page must be >= 1")
    if page_size < 1 or page_size > 100:
        raise HTTPException(status_code=400, detail="Page size must be between 1 and 100")

    now = datetime.now(timezone.utc)

    # 计算总数
    from sqlalchemy import func
    count_result = await db.execute(
        select(func.count(Tress.id))
        .where(
            Tress.is_public == True,
            (Tress.expires_at.is_(None)) | (Tress.expires_at > now)
        )
    )
    total_items = count_result.scalar()

    # 计算分页信息
    total_pages = (total_items + page_size - 1) // page_size
    offset = (page - 1) * page_size

    # 获取当前页数据
    result = await db.execute(
        select(Tress)
        .where(
            Tress.is_public == True,
            (Tress.expires_at.is_(None)) | (Tress.expires_at > now)
        )
        .order_by(Tress.created_at.desc())  # 按创建时间倒序
        .offset(offset)
        .limit(page_size)
    )
    tresses = result.scalars().all()

    # 转换为预览格式
    items = []
    for tress in tresses:
        preview_content = tress.content[:200] + "..." if len(tress.content) > 200 else tress.content
        items.append(TressPreview(
            id=tress.id,
            title=tress.title,
            language=tress.language,
            is_public=tress.is_public,
            owner_id=tress.owner_id,
            owner_username=tress.owner_username,
            created_at=tress.created_at,
            expires_at=tress.expires_at,
            content_preview=preview_content
        ))

    pagination = PaginationInfo(
        page=page,
        page_size=page_size,
        total_items=total_items,
        total_pages=total_pages,
        has_next=page < total_pages,
        has_prev=page > 1
    )

    return TressPageResponse(items=items, pagination=pagination)


@router.get("/my/pages", response_model=TressPageResponse)
async def read_user_tresses_paginated(
        page: int = 1,
        page_size: int = 20,
        db: AsyncSession = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """
    获取用户自己的树的分页预览列表
    - page: 页码，从1开始
    - page_size: 每页大小，默认20，最大100
    """
    # 验证分页参数
    if page < 1:
        raise HTTPException(status_code=400, detail="Page must be >= 1")
    if page_size < 1 or page_size > 100:
        raise HTTPException(status_code=400, detail="Page size must be between 1 and 100")

    now = datetime.now(timezone.utc)

    # 计算总数
    from sqlalchemy import func
    count_result = await db.execute(
        select(func.count(Tress.id))
        .where(
            Tress.owner_id == current_user.id,
            (Tress.expires_at.is_(None)) | (Tress.expires_at > now)
        )
    )
    total_items = count_result.scalar()

    # 计算分页信息
    total_pages = (total_items + page_size - 1) // page_size
    offset = (page - 1) * page_size

    # 获取当前页数据
    result = await db.execute(
        select(Tress)
        .where(
            Tress.owner_id == current_user.id,
            (Tress.expires_at.is_(None)) | (Tress.expires_at > now)
        )
        .order_by(Tress.created_at.desc())  # 按创建时间倒序
        .offset(offset)
        .limit(page_size)
    )
    tresses = result.scalars().all()

    # 转换为预览格式
    items = []
    for tress in tresses:
        preview_content = tress.content[:200] + "..." if len(tress.content) > 200 else tress.content
        items.append(TressPreview(
            id=tress.id,
            title=tress.title,
            language=tress.language,
            is_public=tress.is_public,
            owner_id=tress.owner_id,
            owner_username=tress.owner_username,
            created_at=tress.created_at,
            expires_at=tress.expires_at,
            content_preview=preview_content
        ))

    pagination = PaginationInfo(
        page=page,
        page_size=page_size,
        total_items=total_items,
        total_pages=total_pages,
        has_next=page < total_pages,
        has_prev=page > 1
    )

    return TressPageResponse(items=items, pagination=pagination)


@router.get("/{tress_id}", response_model=TressSchema)
async def read_tress(
        tress_id: int,
        request: Request,
        db: AsyncSession = Depends(get_db),
        current_user: Optional[User] = Depends(get_current_user_optional)
):
    # 对public访问进行速率限制
    if not current_user:
        check_rate_limit(request, "public_read")

    # 查询 tress
    result = await db.execute(select(Tress).where(Tress.id == tress_id))
    tress = result.scalar_one_or_none()

    if not tress:
        raise HTTPException(status_code=404, detail="Tress not found")

    # 检查是否已过期
    now = datetime.now(timezone.utc)
    if tress.expires_at and tress.expires_at <= now:
        raise HTTPException(status_code=404, detail="Tress has expired")

    if not current_user:
        if not tress.is_public:
            raise HTTPException(status_code=403, detail="Not authorized to access this tress")
    else:
        if not tress.is_public and tress.owner_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized to access this tress")

    return tress


@router.get("/{tress_id}/raw")
async def read_tress_raw(
        tress_id: int,
        request: Request,
        db: AsyncSession = Depends(get_db),
        current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    获取tress的原始内容
    返回纯文本内容
    """
    # 对raw内容访问进行速率限制
    if not current_user:
        check_rate_limit(request, "raw_content")

    # 查询 tress
    result = await db.execute(select(Tress).where(Tress.id == tress_id))
    tress = result.scalar_one_or_none()

    if not tress:
        raise HTTPException(status_code=404, detail="Tress not found")

    # 检查是否已过期
    now = datetime.now(timezone.utc)
    if tress.expires_at and tress.expires_at <= now:
        raise HTTPException(status_code=404, detail="Tress has expired")

    # 权限检查（与普通访问相同的逻辑）
    if not current_user:
        if not tress.is_public:
            raise HTTPException(status_code=403, detail="Not authorized to access this tress")
    else:
        if not tress.is_public and tress.owner_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized to access this tress")

    # 生成ETag用于缓存控制
    etag = generate_etag(tress.content)

    # 检查客户端缓存
    if check_if_none_match(request, etag):
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)

    # 验证内容类型
    if not validate_content_type(tress.language, tress.content):
        # 记录可疑内容但不阻止访问，只是警告
        pass

    # 根据语言设置Content-Type
    content_type_map = {
        "javascript": "text/javascript",
        "python": "text/x-python",
        "java": "text/x-java-source",
        "cpp": "text/x-c++src",
        "c": "text/x-csrc",
        "html": "text/html",
        "css": "text/css",
        "json": "application/json",
        "xml": "application/xml",
        "yaml": "text/yaml",
        "markdown": "text/markdown",
        "sql": "text/x-sql",
        "shell": "text/x-shellscript",
        "bash": "text/x-shellscript",
        "typescript": "text/typescript",
        "go": "text/x-go",
        "rust": "text/x-rust",
        "php": "text/x-php",
        "ruby": "text/x-ruby",
    }

    content_type = content_type_map.get(tress.language.lower(), "text/plain")

    # 创建响应
    plain_response = PlainTextResponse(
        content=tress.content,
        headers={
            "Content-Type": f"{content_type}; charset=utf-8",
            "ETag": f'"{etag}"',
            "Cache-Control": "public, max-age=3600" if tress.is_public else "public, max-age=300",
        }
    )

    # 添加安全头
    add_security_headers(plain_response)

    return plain_response


@router.delete("/{tress_id}")
async def delete_tress(
        tress_id: int,
        db: AsyncSession = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Tress).where(Tress.id == tress_id))
    tress = result.scalar_one_or_none()

    if not tress:
        raise HTTPException(status_code=404, detail="Tress not found")

    # 检查是否已过期（已过期的paste也允许删除）
    now = datetime.now(timezone.utc)
    if tress.expires_at and tress.expires_at <= now:
        # 过期的paste仍然可以被拥有者删除
        pass

    if tress.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this tress")

    await db.delete(tress)
    await db.commit()

    return {"message": "Tress deleted successfully"}
