from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.base import get_db
from app.models.tress import Tress
from app.models.user import User
from app.schemas.tress import TressCreate, Tress as TressSchema
from app.api.endpoints.auth import get_current_user, get_current_user_optional

router = APIRouter()


@router.post("/", response_model=TressSchema)
async def create_tress(
        tress: TressCreate,
        db: AsyncSession = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    db_tress = Tress(
        **tress.dict(),
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
        db: AsyncSession = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Tress).where(Tress.id == tress_id))
    db_tress = result.scalar_one_or_none()

    if not db_tress:
        raise HTTPException(status_code=404, detail="Tress not found")

    if db_tress.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to update this tress")

    for key, value in tress.dict().items():
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
        db: AsyncSession = Depends(get_db),
        current_user: Optional[User] = Depends(get_current_user_optional)  # 修改为可选依赖
):
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
