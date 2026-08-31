import subprocess
def run_nikto(target: str):
    try:
        command = [
            "nikto",
            "-h",
            target
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )

        return {
            "target": target,
            "return_code": result.returncode,
            "output": result.stdout,
            "error": result.stderr
        }

    except subprocess.TimeoutExpired:
        return {
            "target": target,
            "return_code": -1,
            "output": "",
            "error": "Nikto scan timed out"
        }

    except Exception as error:
        return {
            "target": target,
            "return_code": -1,
            "output": "",
            "error": str(error)
        }

