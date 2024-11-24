from pydantic import BaseModel


class TressBase(BaseModel):
    title: str
    content: str
    language: str
    is_public: bool = True


class TressCreate(TressBase):
    pass


class Tress(TressBase):
    id: int
    owner_id: int

    class Config:
        orm_mode = True
