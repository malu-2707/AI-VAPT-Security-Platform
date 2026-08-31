from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.models.finding import Finding
from app.models.target import Target

from app.database import get_db
from app.security.auth import get_current_user
from app.security.roles import require_role


# ============================================================
# TARGET ROUTER
# ============================================================

router = APIRouter()


# ============================================================
# TARGET CREATE SCHEMA
# ============================================================

class TargetCreate(BaseModel):
    name: str
    target: str
    description: str | None = None
    authorization_confirmed: bool = False


# ============================================================
# CREATE TARGET
# ============================================================

@router.post(
    "/targets",
    status_code=status.HTTP_201_CREATED
)
def create_target(
    data: TargetCreate,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db)
):

    # --------------------------------------------------------
    # Authorization confirmation
    # --------------------------------------------------------

    if not data.authorization_confirmed:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Authorization must be confirmed "
                "before adding a target."
            )
        )

    # --------------------------------------------------------
    # Prevent duplicate targets
    # --------------------------------------------------------

    existing_target = (
        db.query(Target)
        .filter(
            Target.target == data.target
        )
        .first()
    )

    if existing_target:

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This target already exists."
        )

    # --------------------------------------------------------
    # Create target
    # --------------------------------------------------------

    new_target = Target(
        name=data.name,
        target=data.target,
        description=data.description,
        authorization_confirmed=data.authorization_confirmed,
        status="active"
    )

    db.add(new_target)

    db.commit()

    db.refresh(new_target)

    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return {
        "message": "Target created successfully",

        "target": {
            "id": new_target.id,
            "name": new_target.name,
            "target": new_target.target,
            "description": new_target.description,
            "authorization_confirmed":
                new_target.authorization_confirmed,
            "status": new_target.status
        }
    }


# ============================================================
# GET ALL TARGETS
# ============================================================

@router.get("/targets")
def get_targets(
    user=Depends(get_current_user),
    db: Session = Depends(get_db)
):

    targets = (
        db.query(Target)
        .order_by(Target.id.asc())
        .all()
    )

    return targets


# ============================================================
# GET SINGLE TARGET
# ============================================================

@router.get("/targets/{target_id}")
def get_target(
    target_id: int,
    user=Depends(get_current_user),
    db: Session = Depends(get_db)
):

    target = (
        db.query(Target)
        .filter(
            Target.id == target_id
        )
        .first()
    )

    if target is None:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found"
        )

    return target


# ============================================================
# DELETE TARGET
# ============================================================

@router.delete("/targets/{target_id}")
def delete_target(
    target_id: int,

    user=Depends(
        require_role("admin")
    ),

    db: Session = Depends(get_db)
):

    # --------------------------------------------------------
    # Find target
    # --------------------------------------------------------

    target = (
        db.query(Target)
        .filter(
            Target.id == target_id
        )
        .first()
    )

    if target is None:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found"
        )

    # --------------------------------------------------------
    # Find scans belonging to target
    # --------------------------------------------------------

    scans = (
        db.query(Scan)
        .filter(
            Scan.target_id == target_id
        )
        .all()
    )

    # --------------------------------------------------------
    # Delete findings belonging to scans
    # --------------------------------------------------------

    for scan in scans:

        db.query(Finding).filter(
            Finding.scan_id == scan.id
        ).delete(
            synchronize_session=False
        )

    # --------------------------------------------------------
    # Delete scans belonging to target
    # --------------------------------------------------------

    db.query(Scan).filter(
        Scan.target_id == target_id
    ).delete(
        synchronize_session=False
    )

    # --------------------------------------------------------
    # Delete target
    # --------------------------------------------------------

    db.delete(target)

    db.commit()

    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return {
        "message": "Target deleted successfully",
        "target_id": target_id
    }

