from datetime import datetime
from html import escape
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.scan import Scan
from app.models.target import Target
from app.models.finding import Finding
from app.security.roles import require_role


router = APIRouter(
    prefix="/reports",
    tags=["Reports"]
)


# ============================================================
# BUILD REPORT DATA
# ============================================================

def get_scan_data(scan_id: int, db: Session):

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

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id)
        .order_by(Finding.id.asc())
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
        else:
            severity_counts["info"] += 1

    # Risk calculation
    risk_weights = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 1,
        "info": 0
    }

    risk_score = sum(
        severity_counts[level] * weight
        for level, weight in risk_weights.items()
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

        "generated_at": datetime.utcnow().isoformat(),

        "scan": {
            "scan_id": scan.id,
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

        "target": {
            "target_id": scan.target_id,

            "name": (
                target.name
                if target
                else f"Target #{scan.target_id}"
            ),

            "url": (
                target.target
                if target
                else "Unknown"
            ),

            "description": (
                target.description
                if target
                else ""
            )
        },

        "risk": {
            "score": risk_score,
            "overall_risk": overall_risk,
            "severity_counts": severity_counts
        },

        "findings": [
            {
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

                "ai_analysis": {
                    "analyzed": finding.ai_analyzed,
                    "priority": finding.ai_priority,
                    "explanation": finding.ai_explanation,
                    "impact": finding.ai_impact,
                    "exploitability": finding.ai_exploitability,
                    "risk_reasoning": finding.ai_risk_reasoning,
                    "recommendation": finding.ai_recommendation
                }
            }

            for finding in findings
        ]
    }


# ============================================================
# LIST REPORTS
# ============================================================

@router.get("")
def list_reports(
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db)
):

    scans = (
        db.query(Scan)
        .order_by(Scan.id.desc())
        .all()
    )

    reports = []

    for scan in scans:

        target = (
            db.query(Target)
            .filter(Target.id == scan.target_id)
            .first()
        )

        findings_count = (
            db.query(Finding)
            .filter(Finding.scan_id == scan.id)
            .count()
        )

        reports.append({
            "report_id": f"VAPT-{scan.id}",
            "scan_id": scan.id,
            "scanner": scan.scanner,
            "status": scan.status,

            "target": (
                target.target
                if target
                else "Unknown"
            ),

            "target_name": (
                target.name
                if target
                else f"Target #{scan.target_id}"
            ),

            "findings": findings_count,

            "created_at": (
                scan.completed_at.isoformat()
                if scan.completed_at
                else None
            )
        })

    return {
        "reports": reports,
        "total": len(reports)
    }


# ============================================================
# LATEST REPORT
# ============================================================

@router.get("/latest")
def latest_report(
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db)
):

    scan = (
        db.query(Scan)
        .order_by(Scan.id.desc())
        .first()
    )

    if scan is None:
        return {
            "message": "No security assessment has been performed yet.",
            "report": None
        }

    return get_scan_data(
        scan.id,
        db
    )


# ============================================================
# GENERATE REPORT
# ============================================================

@router.post("/{scan_id}")
def generate_report(
    scan_id: int,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db)
):

    report = get_scan_data(
        scan_id,
        db
    )

    return {
        "message": "Security assessment report generated",
        "report": report
    }


# ============================================================
# GET REPORT
# ============================================================

@router.get("/{scan_id}")
def get_report(
    scan_id: int,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db)
):

    return get_scan_data(
        scan_id,
        db
    )


# ============================================================
# HTML REPORT
# ============================================================

@router.get(
    "/{scan_id}/download",
    response_class=HTMLResponse
)
def download_report(
    scan_id: int,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db)
):

    report = get_scan_data(
        scan_id,
        db
    )

    scan = report["scan"]
    target = report["target"]
    risk = report["risk"]
    findings = report["findings"]

    counts = risk["severity_counts"]

    finding_rows = ""

    if not findings:

        finding_rows = """
        <tr>
            <td colspan="5">
                No security findings were detected.
            </td>
        </tr>
        """

    else:

        for finding in findings:

            severity = escape(
                str(
                    finding["severity"]
                    or "info"
                )
            )

            ai = finding["ai_analysis"]

            recommendation = (
                ai["recommendation"]
                or "No AI recommendation available."
            )

            finding_rows += f"""
            <tr>

                <td>
                    #{finding["id"]}
                </td>

                <td>

                    <strong>
                        {escape(
                            str(
                                finding["title"]
                                or "Unknown"
                            )
                        )}
                    </strong>

                    <div class="small">
                        {escape(
                            str(
                                finding["description"]
                                or ""
                            )
                        )}
                    </div>

                </td>

                <td>

                    <span class="severity">
                        {severity.upper()}
                    </span>

                </td>

                <td>
                    {escape(
                        str(
                            finding["scanner"]
                            or "unknown"
                        )
                    )}
                </td>

                <td>
                    {escape(
                        str(
                            recommendation
                        )
                    )}
                </td>

            </tr>
            """

    html = f"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>
AI-VAPT Security Report #{scan_id}
</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{

    margin: 0;

    font-family:
        Arial,
        Helvetica,
        sans-serif;

    background: #FFFDFD;

    color: #1C0A0A;
}}

.container {{

    max-width: 1100px;

    margin: auto;

    padding: 45px;
}}

.header {{

    border-bottom:
        3px solid #D91E36;

    padding-bottom: 25px;

    margin-bottom: 30px;
}}

.logo {{

    color: #D91E36;

    font-size: 14px;

    font-weight: bold;

    letter-spacing: 2px;
}}

h1 {{

    font-size: 32px;

    margin:
        12px 0 5px;
}}

.subtitle {{

    color: #7D6B6B;
}}

.section {{

    background: #FFFFFF;

    border:
        1px solid #F1E5E5;

    border-radius: 12px;

    padding: 25px;

    margin-bottom: 22px;
}}

.section h2 {{

    margin-top: 0;

    font-size: 19px;
}}

.grid {{

    display: grid;

    grid-template-columns:
        repeat(4, 1fr);

    gap: 14px;
}}

.metric {{

    border:
        1px solid #F1E5E5;

    border-radius: 10px;

    padding: 18px;
}}

.metric-label {{

    color: #7D6B6B;

    font-size: 12px;
}}

.metric-value {{

    font-size: 27px;

    font-weight: bold;

    margin-top: 8px;
}}

.risk {{

    color: #D91E36;
}}

table {{

    width: 100%;

    border-collapse:
        collapse;
}}

th {{

    text-align: left;

    padding: 12px;

    background: #FFF7F7;

    border-bottom:
        1px solid #F1E5E5;

    font-size: 11px;
}}

td {{

    padding: 14px 12px;

    border-bottom:
        1px solid #F1E5E5;

    vertical-align: top;

    font-size: 12px;
}}

.severity {{

    color: #D91E36;

    font-weight: bold;
}}

.small {{

    margin-top: 7px;

    color: #7D6B6B;

    line-height: 1.5;
}}

.footer {{

    margin-top: 35px;

    padding-top: 20px;

    border-top:
        1px solid #F1E5E5;

    color: #7D6B6B;

    font-size: 11px;

    text-align: center;
}}

</style>

</head>

<body>

<div class="container">

<div class="header">

<div class="logo">
AI-VAPT SECURITY PLATFORM
</div>

<h1>
Security Assessment Report
</h1>

<div class="subtitle">

Report ID:
{escape(str(report["report_id"]))}

</div>

</div>


<div class="section">

<h2>
Executive Summary
</h2>

<p>

This report presents the results of an
authorized security assessment performed
against the selected target using the
<strong>
{escape(
    str(
        scan["scanner"]
    ).upper()
)}
</strong>
scanner.

</p>

</div>


<div class="section">

<h2>
Assessment Information
</h2>

<div class="grid">

<div class="metric">

<div class="metric-label">
SCAN ID
</div>

<div class="metric-value">
#{scan["scan_id"]}
</div>

</div>


<div class="metric">

<div class="metric-label">
SCANNER
</div>

<div class="metric-value">
{escape(
    str(
        scan["scanner"]
    ).upper()
)}
</div>

</div>


<div class="metric">

<div class="metric-label">
STATUS
</div>

<div class="metric-value">
{escape(
    str(
        scan["status"]
    ).upper()
)}
</div>

</div>


<div class="metric">

<div class="metric-label">
RISK
</div>

<div class="metric-value risk">

{escape(
    str(
        risk["overall_risk"]
    )
)}

</div>

</div>

</div>

</div>


<div class="section">

<h2>
Target Information
</h2>

<p>

<strong>
Target:
</strong>

{escape(
    str(
        target["url"]
    )
)}

</p>

<p>

<strong>
Target ID:
</strong>

{target["target_id"]}

</p>

<p>

<strong>
Description:
</strong>

{escape(
    str(
        target["description"]
        or "Not provided"
    )
)}

</p>

</div>


<div class="section">

<h2>
Risk Assessment
</h2>

<div class="grid">


<div class="metric">

<div class="metric-label">
RISK SCORE
</div>

<div class="metric-value risk">
{risk["score"]}
</div>

</div>


<div class="metric">

<div class="metric-label">
CRITICAL
</div>

<div class="metric-value">
{counts["critical"]}
</div>

</div>


<div class="metric">

<div class="metric-label">
HIGH
</div>

<div class="metric-value">
{counts["high"]}
</div>

</div>


<div class="metric">

<div class="metric-label">
MEDIUM
</div>

<div class="metric-value">
{counts["medium"]}
</div>

</div>

</div>

<br>

<table>

<tr>

<th>
Severity
</th>

<th>
Count
</th>

</tr>

<tr>
<td>Critical</td>
<td>{counts["critical"]}</td>
</tr>

<tr>
<td>High</td>
<td>{counts["high"]}</td>
</tr>

<tr>
<td>Medium</td>
<td>{counts["medium"]}</td>
</tr>

<tr>
<td>Low</td>
<td>{counts["low"]}</td>
</tr>

<tr>
<td>Informational</td>
<td>{counts["info"]}</td>
</tr>

</table>

</div>


<div class="section">

<h2>
Security Findings
</h2>

<table>

<thead>

<tr>

<th>
ID
</th>

<th>
Finding
</th>

<th>
Severity
</th>

<th>
Scanner
</th>

<th>
AI Recommendation
</th>

</tr>

</thead>

<tbody>

{finding_rows}

</tbody>

</table>

</div>


<div class="footer">

AI-VAPT Security Platform
·
Authorized Security Assessment Only

<br>
<br>

Generated:

{escape(
    str(
        report["generated_at"]
    )
)}

</div>

</div>

</body>

</html>
"""

    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition":
                f'attachment; filename="vapt-report-{scan_id}.html"'
        }
    )

