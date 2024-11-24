from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "Tressa"
    DATABASE_URL: str = "postgresql+asyncpg://postgres:abcdefg@localhost/tressa_db"
    SECRET_KEY: str = "example_secret_key"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7

    class Config:
        case_sensitive = True


settings = Settings()
