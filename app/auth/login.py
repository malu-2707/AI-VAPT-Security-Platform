from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import text

from app.database import engine
from app.security.password import verify_password
from app.security.jwt import create_access_token


router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(data: LoginRequest):

    with engine.connect() as connection:

        result = connection.execute(
            text("""
                SELECT username, password, role
                FROM users
                WHERE username = :username
            """),
            {"username": data.username}
        )

        user = result.fetchone()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    if not verify_password(data.password, user.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    token = create_access_token(
        user.username,
        user.role
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "role": user.role
    }
