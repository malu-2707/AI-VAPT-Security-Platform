from fastapi import Depends, HTTPException
from app.security.auth import get_current_user

def require_role(*allowed_roles):

    def role_checker(
        user=Depends(get_current_user)
    ):
        if user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to access this resource"
            )

        return user

    return role_checker
