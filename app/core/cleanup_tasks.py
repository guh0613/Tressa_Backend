"""
过期paste清理任务
定期清理已过期的paste
"""
import asyncio
import logging
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.db.base import AsyncSessionLocal
from app.models.tress import Tress

logger = logging.getLogger(__name__)


async def cleanup_expired_tresses():
    """
    清理已过期的paste
    """
    async with AsyncSessionLocal() as db:
        try:
            now = datetime.now(timezone.utc)
            
            # 查找所有已过期的paste
            result = await db.execute(
                select(Tress).where(
                    Tress.expires_at.is_not(None),
                    Tress.expires_at <= now
                )
            )
            expired_tresses = result.scalars().all()
            
            if expired_tresses:
                logger.info(f"Found {len(expired_tresses)} expired tresses to delete")
                
                # 删除过期的paste
                await db.execute(
                    delete(Tress).where(
                        Tress.expires_at.is_not(None),
                        Tress.expires_at <= now
                    )
                )
                await db.commit()
                
                logger.info(f"Successfully deleted {len(expired_tresses)} expired tresses")
            else:
                logger.debug("No expired tresses found")
                
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            await db.rollback()
            raise


async def start_cleanup_scheduler():
    """
    启动清理任务调度器
    每小时执行一次清理任务
    """
    logger.info("Starting cleanup scheduler")
    
    while True:
        try:
            await cleanup_expired_tresses()
            # 等待1小时后再次执行
            await asyncio.sleep(3600)  # 3600秒 = 1小时
        except Exception as e:
            logger.error(f"Cleanup scheduler error: {e}")
            # 出错后等待5分钟再重试
            await asyncio.sleep(300)  # 300秒 = 5分钟


def create_cleanup_task():
    """
    创建清理任务
    """
    return asyncio.create_task(start_cleanup_scheduler())
