from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)
    company_name: str | None = None
    industry: str | None = None
    monitored_domain: str | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    company_name: str | None
    industry: str | None
    monitored_domain: str | None
    tier: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse