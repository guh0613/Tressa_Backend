from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "Tressa"
    DATABASE_URL: str = "postgresql+asyncpg://postgres:abcdefg@localhost/tressa_db"
    SECRET_KEY: str = "example_secret_key"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7

    # Content size limits (in bytes)
    MAX_CONTENT_SIZE_ANONYMOUS: int = 256 * 1024  # 256KB for anonymous users
    MAX_CONTENT_SIZE_AUTHENTICATED: int = 1024 * 1024  # 1MB for authenticated users

    class Config:
        case_sensitive = True


settings = Settings()
