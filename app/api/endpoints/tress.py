from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Response, Request, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.base import get_db
from app.models.tress import Tress
from app.models.user import User
from app.schemas.tress import TressCreate, Tress as TressSchema
from app.api.endpoints.auth import get_current_user, get_current_user_optional
from app.core.security_middleware import (
    check_rate_limit,
    sanitize_content,
    validate_content_type,
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
        current_user: User = Depends(get_current_user)
):
    # 速率限制检查
    check_rate_limit(request, "default")

    # 内容安全检查
    sanitized_content = sanitize_content(tress.content)

    # 验证内容类型
    if not validate_content_type(tress.language, tress.content):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Content does not match the specified language type"
        )

    # 创建tress数据
    tress_data = tress.model_dump()
    tress_data["content"] = sanitized_content  # 使用清理后的内容

    db_tress = Tress(
        **tress_data,
        owner_id=current_user.id,
        owner_username=current_user.username
    )
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

    if db_tress.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to update this tress")

    # 内容安全检查
    sanitized_content = sanitize_content(tress.content)

    # 验证内容类型
    if not validate_content_type(tress.language, tress.content):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Content does not match the specified language type"
        )

    # 更新数据
    tress_data = tress.model_dump()
    tress_data["content"] = sanitized_content  # 使用清理后的内容

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
    result = await db.execute(
        select(Tress)
        .where(Tress.is_public == True)
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/my", response_model=List[TressSchema])
async def read_user_tresses(
        db: AsyncSession = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    result = await db.execute(
        select(Tress)
        .where(Tress.owner_id == current_user.id)
    )
    return result.scalars().all()


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

    if tress.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this tress")

    await db.delete(tress)
    await db.commit()

    return {"message": "Tress deleted successfully"}
