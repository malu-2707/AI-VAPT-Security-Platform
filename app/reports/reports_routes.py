from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.scan import Scan
from app.models.target import Target
from app.models.finding import Finding
from app.security.roles import require_role
from app.security.risk import calculate_risk


router = APIRouter()


# ============================================================
# REPORT GENERATION
# ============================================================

@router.post("/reports/{scan_id}")
def generate_report(
    scan_id: int,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db)
):

    # --------------------------------------------------------
    # Find scan
    # --------------------------------------------------------

    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    # --------------------------------------------------------
    # Find target
    # --------------------------------------------------------

    target = (
        db.query(Target)
        .filter(Target.id == scan.target_id)
        .first()
    )

    if target is None:
        raise HTTPException(
            status_code=404,
            detail="Target not found"
        )

    # --------------------------------------------------------
    # Get findings
    # --------------------------------------------------------

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id)
        .all()
    )

    # --------------------------------------------------------
    # Severity counts
    # --------------------------------------------------------

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    for finding in findings:

        severity = (
            finding.severity or "info"
        ).lower()

        if severity in severity_counts:
            severity_counts[severity] += 1

    # --------------------------------------------------------
    # Risk score
    # --------------------------------------------------------

    total_risk_score = (
        severity_counts["critical"] * 10
        + severity_counts["high"] * 7
        + severity_counts["medium"] * 4
        + severity_counts["low"] * 2
        + severity_counts["info"] * 0
    )

    # --------------------------------------------------------
    # Overall risk
    # --------------------------------------------------------

    if severity_counts["critical"] > 0:
        overall_risk = "CRITICAL"

    elif severity_counts["high"] > 0:
        overall_risk = "HIGH"

    elif severity_counts["medium"] > 0:
        overall_risk = "MEDIUM"

    elif severity_counts["low"] > 0:
        overall_risk = "LOW"

    else:
        overall_risk = "INFO"

    # --------------------------------------------------------
    # Findings report
    # --------------------------------------------------------

    finding_reports = []

    for finding in findings:

        finding_reports.append({
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity,
            "scanner": finding.scanner,
            "template_id": finding.template_id,
            "host": finding.host,
            "port": finding.port,
            "matched_at": finding.matched_at,
            "description": finding.description,
            "evidence": finding.evidence,
            "cwe": finding.cwe,

            # AI analysis
            "ai_analyzed": finding.ai_analyzed,
            "ai_priority": finding.ai_priority,
            "ai_explanation": finding.ai_explanation,
            "ai_impact": finding.ai_impact,
            "ai_exploitability": finding.ai_exploitability,
            "ai_risk_reasoning": finding.ai_risk_reasoning,
            "ai_recommendation": finding.ai_recommendation,

            "created_at": (
                finding.created_at.isoformat()
                if finding.created_at
                else None
            )
        })

    # --------------------------------------------------------
    # Final report
    # --------------------------------------------------------

    report = {

        "report": {
            "report_id": f"VAPT-{scan.id}",
            "generated_at": datetime.utcnow().isoformat(),
            "report_type": "Security Assessment Report",
            "platform": "AI-Assisted VAPT Platform"
        },

        "target": {
            "target_id": target.id,
            "name": target.name,
            "target": target.target,
            "description": target.description,
            "authorization_confirmed":
                target.authorization_confirmed
        },

        "scan": {
            "scan_id": scan.id,
            "scanner": scan.scanner,
            "status": scan.status,
            "started_at": (
                scan.started_at.isoformat()
                if scan.started_at
                else None
            ),
            "completed_at": (
                scan.completed_at.isoformat()
                if scan.completed_at
                else None
            ),
            "return_code": scan.return_code
        },

        "risk_assessment": {
            "overall_risk": overall_risk,
            "total_risk_score": total_risk_score,
            "total_findings": len(findings),
            "severity_counts": severity_counts
        },

        "findings": finding_reports,

        "summary": {
            "critical_findings":
                severity_counts["critical"],

            "high_findings":
                severity_counts["high"],

            "medium_findings":
                severity_counts["medium"],

            "low_findings":
                severity_counts["low"],

            "informational_findings":
                severity_counts["info"]
        },

        "security_recommendation": (
            "Review and remediate all high and critical "
            "security findings before deploying the "
            "assessed application to production."
        )
    }

    return report


# ============================================================
# GET EXISTING REPORT
# ============================================================

@router.get("/reports/{scan_id}")
def get_report(
    scan_id: int,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db)
):

    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    target = (
        db.query(Target)
        .filter(Target.id == scan.target_id)
        .first()
    )

    if target is None:
        raise HTTPException(
            status_code=404,
            detail="Target not found"
        )

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id)
        .all()
    )

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    for finding in findings:

        severity = (
            finding.severity or "info"
        ).lower()

        if severity in severity_counts:
            severity_counts[severity] += 1

    total_risk_score = (
        severity_counts["critical"] * 10
        + severity_counts["high"] * 7
        + severity_counts["medium"] * 4
        + severity_counts["low"] * 2
    )

    if severity_counts["critical"] > 0:
        overall_risk = "CRITICAL"
    elif severity_counts["high"] > 0:
        overall_risk = "HIGH"
    elif severity_counts["medium"] > 0:
        overall_risk = "MEDIUM"
    elif severity_counts["low"] > 0:
        overall_risk = "LOW"
    else:
        overall_risk = "INFO"

    return {
        "report_id": f"VAPT-{scan.id}",

        "generated_at":
            datetime.utcnow().isoformat(),

        "target": {
            "id": target.id,
            "name": target.name,
            "target": target.target,
            "description": target.description
        },

        "scan": {
            "id": scan.id,
            "scanner": scan.scanner,
            "status": scan.status,
            "return_code": scan.return_code,
            "started_at": (
                scan.started_at.isoformat()
                if scan.started_at
                else None
            ),
            "completed_at": (
                scan.completed_at.isoformat()
                if scan.completed_at
                else None
            )
        },

        "risk": {
            "overall": overall_risk,
            "score": total_risk_score,
            "total_findings": len(findings),
            "severity_counts": severity_counts
        },

        "findings": [
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "scanner": finding.scanner,
                "host": finding.host,
                "port": finding.port,
                "description": finding.description,
                "evidence": finding.evidence,
                "cwe": finding.cwe,

                "ai": {
                    "analyzed": finding.ai_analyzed,
                    "priority": finding.ai_priority,
                    "explanation":
                        finding.ai_explanation,
                    "impact":
                        finding.ai_impact,
                    "exploitability":
                        finding.ai_exploitability,
                    "risk_reasoning":
                        finding.ai_risk_reasoning,
                    "recommendation":
                        finding.ai_recommendation
                }
            }
            for finding in findings
        ]
    }
