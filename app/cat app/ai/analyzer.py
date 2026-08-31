import json
import os

from dotenv import load_dotenv
from google import genai

from app.models.scan import Scan
from app.models.target import Target
from app.models.finding import Finding


load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise RuntimeError("GEMINI_API_KEY is not configured")


client = genai.Client(api_key=API_KEY)

MODEL_NAME = "gemini-3.6-flash"


def analyze_finding(finding):
    """
    Analyze one vulnerability finding using Gemini AI.
    """

    if finding is None:
        raise ValueError("Finding cannot be None")

    severity = (finding.severity or "info").lower()

    finding_data = {
        "title": finding.title,
        "severity": severity,
        "scanner": getattr(finding, "scanner", "unknown"),
        "template_id": getattr(finding, "template_id", None),
        "host": getattr(finding, "host", None),
        "port": getattr(finding, "port", None),
        "matched_at": getattr(finding, "matched_at", None),
        "description": getattr(finding, "description", None),
        "evidence": getattr(finding, "evidence", None),
        "cwe": getattr(finding, "cwe", None),
    }

    prompt = f"""
You are a cybersecurity vulnerability analysis assistant.

Analyze the following finding produced by an authorized security
testing scanner.

Finding:
{json.dumps(finding_data, indent=2)}

Provide a professional defensive security analysis.

Return ONLY valid JSON with exactly these fields:

{{
  "title": "...",
  "severity": "...",
  "scanner": "...",
  "explanation": "...",
  "impact": "...",
  "exploitability": "...",
  "recommendation": "...",
  "risk_reasoning": "...",
  "priority": "..."
}}

Rules:
- Do not invent facts that are not supported by the finding.
- Do not claim that exploitation was successfully performed.
- Distinguish informational exposure from an actual confirmed vulnerability.
- Explain the security significance in beginner-friendly language.
- The recommendation should be practical and defensive.
- Consider severity, CWE, evidence, exposure, and affected resource.
- Priority must reflect the available evidence and severity.
"""

    try:
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
            config={
                "response_mime_type": "application/json"
            }
        )

        if not response.text:
            raise RuntimeError("Gemini returned an empty response")

        result = json.loads(response.text)

        required_fields = [
            "title",
            "severity",
            "scanner",
            "explanation",
            "impact",
            "exploitability",
            "recommendation",
            "risk_reasoning",
            "priority"
        ]

        for field in required_fields:
            if field not in result:
                raise ValueError(
                    f"Gemini response missing required field: {field}"
                )

        return result

    except Exception as error:
        return {
            "title": finding.title,
            "severity": severity,
            "scanner": getattr(finding, "scanner", "unknown"),
            "explanation": "AI analysis could not be completed.",
            "impact": "Unable to determine AI-generated impact analysis.",
            "exploitability": "Unknown",
            "recommendation": (
                "Review the finding manually and investigate "
                "the affected resource."
            ),
            "risk_reasoning": (
                "AI analysis failed and should not be treated "
                "as a definitive risk assessment."
            ),
            "priority": severity.upper(),
            "error": str(error)
        }


def save_ai_analysis(finding, db):
    """
    Generate AI analysis and permanently save it
    into the Finding database record.
    """

    if finding is None:
        raise ValueError("Finding cannot be None")

    result = analyze_finding(finding)

    finding.ai_explanation = result.get(
        "explanation",
        "AI analysis unavailable."
    )

    finding.ai_impact = result.get(
        "impact",
        "AI impact analysis unavailable."
    )

    finding.ai_exploitability = result.get(
        "exploitability",
        "Unknown"
    )

    finding.ai_recommendation = result.get(
        "recommendation",
        "Review the finding manually."
    )

    finding.ai_risk_reasoning = result.get(
        "risk_reasoning",
        "AI risk reasoning unavailable."
    )

    finding.ai_priority = result.get(
        "priority",
        (finding.severity or "INFO").upper()
    )

    finding.ai_analyzed = True

    try:
        db.commit()
        db.refresh(finding)

    except Exception:
        db.rollback()
        raise

    return {
        "finding_id": finding.id,
        "ai_analyzed": finding.ai_analyzed,
        "ai_priority": finding.ai_priority,
        "ai_explanation": finding.ai_explanation,
        "ai_impact": finding.ai_impact,
        "ai_exploitability": finding.ai_exploitability,
        "ai_recommendation": finding.ai_recommendation,
        "ai_risk_reasoning": finding.ai_risk_reasoning
    }
