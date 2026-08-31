import subprocess
from urllib.parse import urlparse


def run_nmap(target: str):
    try:
        # Add a scheme if the target is provided without one
        parsed = urlparse(
            target if "://" in target else "http://" + target
        )

        hostname = parsed.hostname
        port = parsed.port

        if not hostname:
            return {
                "target": target,
                "return_code": -1,
                "output": "",
                "error": "Invalid target: hostname not found"
            }

        # Use the target's port if provided.
        # Otherwise use the default HTTP port.
        if not port:
            port = 80

        command = [
            "nmap",
            "-sV",
            "-p", str(port),
            hostname
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60
        )

        return {
            "target": target,
            "hostname": hostname,
            "port": port,
            "return_code": result.returncode,
            "output": result.stdout,
            "error": result.stderr
        }

    except ValueError:
        return {
            "target": target,
            "return_code": -1,
            "output": "",
            "error": "Invalid port in target"
        }

    except subprocess.TimeoutExpired:
        return {
            "target": target,
            "return_code": -1,
            "output": "",
            "error": "Nmap scan timed out"
        }

    except Exception as error:
        return {
            "target": target,
            "return_code": -1,
            "output": "",
            "error": str(error)
        }


