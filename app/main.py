from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
import asyncio

from app.api.endpoints import auth, tress
from app.core.config import settings
from app.db.base import engine, Base
from app.core.cleanup_tasks import create_cleanup_task

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 全局变量存储清理任务
cleanup_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时执行
    global cleanup_task

    # 初始化数据库
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # 启动清理任务
    cleanup_task = create_cleanup_task()
    logger.info("Application startup complete")

    yield

    # 关闭时执行
    if cleanup_task:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            logger.info("Cleanup task cancelled")
    logger.info("Application shutdown complete")


app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["authentication"])
app.include_router(tress.router, prefix="/api/tress", tags=["tress"])


@app.get("/")
async def root():
    return {"message": "Welcome to Tressa API"}


@app.get("/")
async def root():
    return {"message": "Welcome to Tressa API"}
