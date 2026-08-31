from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.target import Target
from app.models.scan import Scan
from app.security.roles import require_role
from app.scanners.nikto_scanner import run_nikto


router = APIRouter()


@router.post("/scans/nikto/{target_id}")
def nikto_scan(
    target_id: int,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    target = (
        db.query(Target)
        .filter(Target.id == target_id)
        .first()
    )

    if target is None:
        raise HTTPException(
            status_code=404,
            detail="Target not found"
        )

    if not target.authorization_confirmed:
        raise HTTPException(
            status_code=403,
            detail="Target is not authorized for security testing"
        )

    started_at = datetime.utcnow()

    result = run_nikto(target.target)

    scan = Scan(
        target_id=target.id,
        scanner="nikto",
        status=(
            "completed"
            if result["return_code"] == 0
            else "failed"
        ),
        started_at=started_at,
        completed_at=datetime.utcnow(),
        return_code=result["return_code"],
        output=result["output"],
        error=result["error"]
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return {
        "message": "Nikto scan completed",
        "scan_id": scan.id,
        "target_id": target.id,
        "target": target.target,
        "scan_result": result
    }

