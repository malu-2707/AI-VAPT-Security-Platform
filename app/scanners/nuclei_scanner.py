import subprocess
import json


def run_nuclei(target: str):
    command = [
        "nuclei",
        "-u", target,
        "-jsonl",
        "-tags", "swagger"
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )

        findings = []

        for line in result.stdout.splitlines():
            try:
                data = json.loads(line)

                findings.append(data)

            except json.JSONDecodeError:
                continue

        return {
            "target": target,
            "return_code": result.returncode,
            "findings": findings,
            "error": result.stderr
        }

    except subprocess.TimeoutExpired:
        return {
            "target": target,
            "return_code": -1,
            "findings": [],
            "error": "Nuclei scan timed out"
        }

    except Exception as error:
        return {
            "target": target,
            "return_code": -1,
            "findings": [],
            "error": str(error)
        }
