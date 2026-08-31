from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.ai.analyzer import analyze_finding, save_ai_analysis
from app.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.security.roles import require_role
from app.security.risk import calculate_risk


router = APIRouter()


@router.get("/findings")
def get_findings(
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    findings = (
        db.query(Finding)
        .order_by(Finding.id.desc())
        .all()
    )

    return [
        {
            "id": finding.id,
            "scan_id": finding.scan_id,
            "target_id": finding.target_id,
            "title": finding.title,
            "severity": finding.severity,
            "risk": calculate_risk(finding.severity),

            "ai_analysis": {
                "explanation": finding.ai_explanation,
                "impact": finding.ai_impact,
                "exploitability": finding.ai_exploitability,
                "recommendation": finding.ai_recommendation,
                "risk_reasoning": finding.ai_risk_reasoning,
                "priority": finding.ai_priority,
                "analyzed": finding.ai_analyzed
            },

            "scanner": finding.scanner,
            "template_id": finding.template_id,
            "host": finding.host,
            "port": finding.port,
            "matched_at": finding.matched_at,
            "description": finding.description,
            "evidence": finding.evidence,
            "cwe": finding.cwe,
            "created_at": finding.created_at
        }
        for finding in findings
    ]


@router.get("/findings/{finding_id}")
def get_finding(
    finding_id: int,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id)
        .first()
    )

    if finding is None:
        raise HTTPException(
            status_code=404,
            detail="Finding not found"
        )

    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "target_id": finding.target_id,
        "title": finding.title,
        "severity": finding.severity,
        "risk": calculate_risk(finding.severity),

        "ai_analysis": {
            "explanation": finding.ai_explanation,
            "impact": finding.ai_impact,
            "exploitability": finding.ai_exploitability,
            "recommendation": finding.ai_recommendation,
            "risk_reasoning": finding.ai_risk_reasoning,
            "priority": finding.ai_priority,
            "analyzed": finding.ai_analyzed
        },

        "scanner": finding.scanner,
        "template_id": finding.template_id,
        "host": finding.host,
        "port": finding.port,
        "matched_at": finding.matched_at,
        "description": finding.description,
        "evidence": finding.evidence,
        "cwe": finding.cwe,
        "created_at": finding.created_at
    }


@router.post("/findings/{finding_id}/analyze")
def analyze_finding_endpoint(
    finding_id: int,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id)
        .first()
    )

    if finding is None:
        raise HTTPException(
            status_code=404,
            detail="Finding not found"
        )

    try:
        result = save_ai_analysis(finding, db)

        return {
            "message": "AI analysis completed successfully",
            "result": result
        }

    except Exception as error:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"AI analysis failed: {str(error)}"
        )


@router.get("/scans/{scan_id}/findings")
def get_scan_findings(
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

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .order_by(Finding.id.desc())
        .all()
    )

    return [
        {
            "id": finding.id,
            "scan_id": finding.scan_id,
            "target_id": finding.target_id,
            "title": finding.title,
            "severity": finding.severity,
            "risk": calculate_risk(finding.severity),

            "ai_analysis": {
                "explanation": finding.ai_explanation,
                "impact": finding.ai_impact,
                "exploitability": finding.ai_exploitability,
                "recommendation": finding.ai_recommendation,
                "risk_reasoning": finding.ai_risk_reasoning,
                "priority": finding.ai_priority,
                "analyzed": finding.ai_analyzed
            },

            "scanner": finding.scanner,
            "template_id": finding.template_id,
            "host": finding.host,
            "port": finding.port,
            "matched_at": finding.matched_at,
            "description": finding.description,
            "evidence": finding.evidence,
            "cwe": finding.cwe,
            "created_at": finding.created_at
        }
        for finding in findings
    ]


@router.get("/scans/{scan_id}/risk-summary")
def get_risk_summary(
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

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .all()
    )

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    total_score = 0

    for finding in findings:
        severity = (finding.severity or "info").lower()

        if severity in counts:
            counts[severity] += 1

        risk = calculate_risk(severity)
        total_score += risk["score"]

    if counts["critical"] > 0:
        overall_risk = "CRITICAL"

    elif counts["high"] > 0:
        overall_risk = "HIGH"

    elif counts["medium"] > 0:
        overall_risk = "MEDIUM"

    elif counts["low"] > 0:
        overall_risk = "LOW"

    elif counts["info"] > 0:
        overall_risk = "INFO"

    else:
        overall_risk = "NO FINDINGS"

    return {
        "scan_id": scan_id,
        "scanner": scan.scanner,
        "status": scan.status,
        "total_findings": len(findings),
        "severity_counts": counts,
        "total_risk_score": total_score,
        "overall_risk": overall_risk
    }

