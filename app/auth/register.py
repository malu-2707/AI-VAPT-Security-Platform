from fastapi import APIRouter, HTTPException
from sqlalchemy.exc import IntegrityError
from app.database import engine
from app.models.user import User
from app.security.password import hash_password

router = APIRouter()

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "viewer"


def create_user(username, email, password, role="viewer"):
    hashed_password = hash_password(password)

    with engine.begin() as connection:
        connection.execute(
            User.__table__.insert().values(
                username=username,
                email=email,
                password=hashed_password,
                role=role
            )
        )

    print("User created successfully!")


@router.post("/register")
def register_user(data: RegisterRequest):
    try:
        create_user(
            data.username,
            data.email,
            data.password,
            data.role
        )

        return {
            "message": "User registered successfully",
            "username": data.username,
            "role": data.role
        }

    except IntegrityError:
        raise HTTPException(
            status_code=400,
            detail="Username or email already exists"
        )

