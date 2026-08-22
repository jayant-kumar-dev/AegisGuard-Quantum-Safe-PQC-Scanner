"""AegisGuard — Auth Pydantic Models"""

from pydantic import BaseModel, field_validator


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    full_name: str = ""
    org_name: str = ""

    @field_validator("username")
    @classmethod
    def clean_username(cls, v):
        v = v.strip().lower()
        if len(v) < 3:
            raise ValueError("Username must be at least 3 characters")
        if not v.isalnum() and "_" not in v:
            raise ValueError("Username must be alphanumeric (underscores allowed)")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters")
        return v


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    user_id: int


class UserProfile(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    org_name: str
    created_at: str
    scan_count: int = 0
