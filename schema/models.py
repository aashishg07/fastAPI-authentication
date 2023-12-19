from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    refresh_token: str


class TokenData(BaseModel):
    username: str or None = None


class User(BaseModel):
    username: str 
    email: str or None = None
    full_name: str


class UserInDB(User):
    hashed_password: str

