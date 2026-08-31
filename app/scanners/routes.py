from datetime import datetime
from app.scanners.nikto_scanner import run_nikto
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.target import Target
from app.models.scan import Scan
from app.models.finding import Finding
from app.security.roles import require_role
from app.security.risk import calculate_risk
from app.scanners.nmap_scanner import run_nmap
from app.scanners.nuclei_scanner import run_nuclei
from app.ai.analyzer import save_ai_analysis


router = APIRouter()

@router.post("/scans/nmap/{target_id}")
def nmap_scan(
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

    result = run_nmap(target.target)

    scan = Scan(
        target_id=target.id,
        scanner="nmap",
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

    saved_findings = 0
    ai_analyzed_findings = 0
    ai_failed_findings = 0

    if result["return_code"] == 0 and result.get("output"):

        import re

        port_pattern = re.compile(
            r"^(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?$"
        )

        for line in result["output"].splitlines():

            match = port_pattern.match(line.strip())

            if not match:
                continue

            port = match.group(1)
            service = match.group(2)
            version = match.group(3) or ""

            finding = Finding(
                scan_id=scan.id,
                target_id=target.id,
                title="Open Port Detected",
                severity="info",
                scanner="nmap",
                template_id="nmap-open-port",
                host=result.get("hostname"),
                port=port,
                matched_at=target.target,
                description=(
                    f"Nmap detected an open TCP port {port} "
                    f"running service '{service}'."
                ),
                evidence=line.strip(),
                cwe=None,
                created_at=datetime.utcnow()
            )

            db.add(finding)
            db.flush()

            saved_findings += 1

            try:
                save_ai_analysis(
                    finding,
                    db
                )

                ai_analyzed_findings += 1

            except Exception as error:
                ai_failed_findings += 1

                finding.ai_analyzed = False
                finding.ai_priority = "INFO"
                finding.ai_risk_reasoning = (
                    "AI analysis failed. "
                    "Manual security review is required."
                )
                finding.ai_recommendation = (
                    "Review the Nmap finding manually."
                )

                db.commit()

                print(
                    f"AI analysis failed for finding "
                    f"{finding.id}: {error}"
                )

    db.commit()

    return {
        "message": "Nmap scan completed",
        "scan_id": scan.id,
        "target_id": target.id,
        "target": target.target,
        "findings_saved": saved_findings,
        "ai_analyzed": ai_analyzed_findings,
        "ai_analysis_failed": ai_failed_findings
    }

@router.post("/scans/nuclei/{target_id}")
def nuclei_scan(
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

    result = run_nuclei(target.target)

    scan = Scan(
        target_id=target.id,
        scanner="nuclei",
        status=(
            "completed"
            if result["return_code"] == 0
            else "failed"
        ),
        started_at=started_at,
        completed_at=datetime.utcnow(),
        return_code=result["return_code"],
        output="Nuclei scan completed",
        error=result.get("error", "")
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    saved_findings = 0
    ai_analyzed_findings = 0
    ai_failed_findings = 0

    for item in result.get("findings", []):

        info = item.get("info", {})
        classification = info.get("classification", {})

        severity = info.get(
            "severity",
            "info"
        )

        cwe_data = classification.get(
            "cwe-id",
            []
        )

        if isinstance(cwe_data, list):
            cwe = ", ".join(cwe_data)
        else:
            cwe = (
                str(cwe_data)
                if cwe_data
                else None
            )

        finding = Finding(
            scan_id=scan.id,
            target_id=target.id,
            title=info.get(
                "name",
                "Unknown Finding"
            ),
            severity=severity,
            scanner="nuclei",
            template_id=item.get(
                "template-id"
            ),
            host=item.get("host"),
            port=(
                str(item.get("port"))
                if item.get("port")
                else None
            ),
            matched_at=item.get(
                "matched-at"
            ),
            description=info.get(
                "description"
            ),
            evidence=item.get(
                "response"
            ),
            cwe=cwe,
            created_at=datetime.utcnow()
        )

        db.add(finding)
        db.flush()

        saved_findings += 1

        # Automatically send the finding to Gemini AI.
        try:
            save_ai_analysis(
                finding,
                db
            )

            ai_analyzed_findings += 1

        except Exception as error:
            ai_failed_findings += 1

            finding.ai_analyzed = False

            finding.ai_priority = (
                severity.upper()
            )

            finding.ai_risk_reasoning = (
                "AI analysis failed. "
                "Manual security review is required."
            )

            finding.ai_recommendation = (
                "Review the scanner finding manually "
                "and investigate the affected resource."
            )

            db.commit()

            print(
                f"AI analysis failed for finding "
                f"{finding.id}: {error}"
            )

    db.commit()

    return {
        "message": "Nuclei scan completed",
        "scan_id": scan.id,
        "target_id": target.id,
        "target": target.target,
        "findings_saved": saved_findings,
        "ai_analyzed": ai_analyzed_findings,
        "ai_analysis_failed": ai_failed_findings
    }


@router.get("/scans")
def get_scan_history(
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    scans = (
        db.query(Scan)
        .order_by(Scan.id.desc())
        .all()
    )

    results = []

    for scan in scans:

        target = (
            db.query(Target)
            .filter(Target.id == scan.target_id)
            .first()
        )

        findings_count = (
            db.query(Finding)
            .filter(
                Finding.scan_id == scan.id
            )
            .count()
        )

        ai_analyzed_count = (
            db.query(Finding)
            .filter(
                Finding.scan_id == scan.id,
                Finding.ai_analyzed == True
            )
            .count()
        )

        results.append({
            "scan_id": scan.id,
            "target_id": scan.target_id,
            "target": (
                target.target
                if target
                else None
            ),
            "scanner": scan.scanner,
            "status": scan.status,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "return_code": scan.return_code,
            "findings_count": findings_count,
            "ai_analyzed_count": ai_analyzed_count
        })

    return results


@router.get("/scans/{scan_id}/ai-summary")
def get_ai_summary(
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
        .filter(
            Finding.scan_id == scan_id
        )
        .all()
    )

    results = []

    for finding in findings:

        results.append({
            "finding_id": finding.id,
            "title": finding.title,
            "severity": finding.severity,
            "scanner": finding.scanner,
            "ai_analyzed": finding.ai_analyzed,
            "ai_priority": finding.ai_priority,
            "ai_explanation": finding.ai_explanation,
            "ai_impact": finding.ai_impact,
            "ai_exploitability": finding.ai_exploitability,
            "ai_recommendation": finding.ai_recommendation,
            "ai_risk_reasoning": finding.ai_risk_reasoning
        })

    return {
        "scan_id": scan_id,
        "scanner": scan.scanner,
        "total_findings": len(findings),
        "ai_analyzed": sum(
            1
            for finding in findings
            if finding.ai_analyzed
        ),
        "results": results
    }


@router.get("/scans/{scan_id}/findings")
def get_scan_findings(
    scan_id: int,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan_id
        )
        .all()
    )

    return [
        {
            "id": finding.id,
            "scan_id": finding.scan_id,
            "target_id": finding.target_id,
            "title": finding.title,
            "severity": finding.severity,
            "risk": calculate_risk(
                finding.severity
            ),
            "ai_analysis": {
                "analyzed": finding.ai_analyzed,
                "priority": finding.ai_priority,
                "explanation": finding.ai_explanation,
                "impact": finding.ai_impact,
                "exploitability": (
                    finding.ai_exploitability
                ),
                "recommendation": (
                    finding.ai_recommendation
                ),
                "risk_reasoning": (
                    finding.ai_risk_reasoning
                )
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
        .filter(
            Finding.scan_id == scan_id
        )
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

        severity = (
            finding.severity or "info"
        ).lower()

        if severity in counts:
            counts[severity] += 1

        risk = calculate_risk(
            severity
        )

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

    ai_analyzed = sum(
        1
        for finding in findings
        if finding.ai_analyzed
    )

    return {
        "scan_id": scan_id,
        "scanner": scan.scanner,
        "status": scan.status,
        "total_findings": len(findings),
        "severity_counts": counts,
        "total_risk_score": total_score,
        "overall_risk": overall_risk,
        "ai_analyzed": ai_analyzed,
        "ai_pending": (
            len(findings) - ai_analyzed
        )
    }

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
