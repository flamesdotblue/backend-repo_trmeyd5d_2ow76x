from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime

# Users collection for auth
class Account(BaseModel):
    email: EmailStr
    name: Optional[str] = None
    password_hash: str
    salt: str

class Session(BaseModel):
    user_id: str
    token: str
    expires_at: datetime

# Articles collection for news content
class Article(BaseModel):
    title: str
    source: str
    time: Optional[str] = None
    tags: List[str] = []
    summary: Optional[str] = None
    url: Optional[str] = None
