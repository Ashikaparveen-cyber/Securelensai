"""
HTTP Security Headers Scanner Module
"""

import requests
from urllib.parse import urlparse

SECURITY_HEADERS = {
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "severity": "high",
        "description": "Prevents XSS and data injection attacks by specifying allowed content sources.",
        "recommendation": "Add a strict CSP: Content-Security-Policy: default-src 'self'",
    },
    "strict-transport-security": {
        "name": "Strict-Transport-Security",
        "severity": "high",
        "description": "Forces HTTPS connections and prevents SSL stripping attacks.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "medium",
        "description": "Prevents clickjacking by controlling iframe embedding.",
        "recommendation": "Add: X-Frame-Options: DENY (or SAMEORIGIN)",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "medium",
        "description": "Prevents MIME-type sniffing attacks.",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "medium",
        "description": "Controls how much referrer info is sent with cross-origin requests.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "low",
        "description": "Controls access to browser APIs (camera, microphone, location).",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "low",
        "description": "Legacy XSS protection header for older browsers.",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block",
    },
}


def validate_header_value(header_key: str, value: str) -> list:
    issues = []
    lower = value.lower().strip()

    if header_key == "strict-transport-security":
        if "max-age=0" in lower:
            issues.append("max-age=0 disables HSTS — use a positive value")
        try:
            age = int(lower.split("max-age=")[1].split(";")[0].strip())
            if age < 15552000:
                issues.append(f"max-age={age} is too short — recommend at least 15552000 (6 months)")
        except Exception:
            pass

    elif header_key == "x-frame-options":
        if lower not in ("deny", "sameorigin"):
            issues.append(f"Unexpected value '{value}' — expected DENY or SAMEORIGIN")

    elif header_key == "x-content-type-options":
        if lower != "nosniff":
            issues.append(f"Value should be 'nosniff', got '{value}'")

    elif header_key == "content-security-policy":
        if "unsafe-inline" in lower:
            issues.append("'unsafe-inline' weakens CSP protection")
        if "unsafe-eval" in lower:
            issues.append("'unsafe-eval' allows dynamic script evaluation")

    return issues


def check_headers(url: str) -> dict:
    result = {
        "url": url,
        "status_code": None,
        "server": None,
        "x_powered_by": None,
        "https_redirect": False,
        "headers_found": {},
        "findings": [],
        "score": 0,
        "grade": "F",
    }

    try:
        http_url = url.replace("https://", "http://")
        try:
            http_resp = requests.get(http_url, timeout=8, allow_redirects=False)
            if http_resp.status_code in (301, 302, 307, 308):
                loc = http_resp.headers.get("location", "")
                if loc.startswith("https://"):
                    result["https_redirect"] = True
        except Exception:
            pass

        resp = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        result["status_code"] = resp.status_code
        headers = {k.lower(): v for k, v in resp.headers.items()}

        parsed = urlparse(url)
        asset_name = parsed.netloc or url

        if "server" in headers:
            result["server"] = headers["server"]
            result["findings"].append({
                "severity": "low",
                "name": "Server Header Info Leak",
                "asset": asset_name,
                "status": "open",
                "msg": f"Server version disclosed: {headers['server']}",
                "recommendation": "Configure web server to hide server signature details"
            })

        if "x-powered-by" in headers:
            result["x_powered_by"] = headers["x-powered-by"]
            result["findings"].append({
                "severity": "low",
                "name": "X-Powered-By Header Disclosed",
                "asset": asset_name,
                "status": "open",
                "msg": f"Technology stack disclosed: {headers['x-powered-by']}",
                "recommendation": "Remove X-Powered-By header from response options"
            })

        passed = 0
        total = len(SECURITY_HEADERS)

        for key, meta in SECURITY_HEADERS.items():
            present = key in headers
            value = headers.get(key, "")

            header_result = {
                "name": meta["name"],
                "present": present,
                "value": value if present else None,
                "severity": meta["severity"],
                "description": meta["description"],
                "issues": [],
            }

            if present:
                passed += 1
                issues = validate_header_value(key, value)
                header_result["issues"] = issues
                if issues:
                    passed -= 0.5
                    for issue in issues:
                        result["findings"].append({
                            "severity": "medium",
                            "name": f"Weak {meta['name']} Configuration",
                            "asset": asset_name,
                            "status": "open",
                            "msg": f"{meta['name']}: {issue}",
                            "recommendation": meta["recommendation"]
                        })
            else:
                result["findings"].append({
                    "severity": meta["severity"],
                    "name": f"Missing {meta['name']} Header",
                    "asset": asset_name,
                    "status": "open",
                    "msg": f"{meta['name']} HTTP header is missing",
                    "recommendation": meta["recommendation"]
                })

            result["headers_found"][key] = header_result

        score = int((passed / total) * 100)
        result["score"] = max(0, score)
        result["passed"] = int(passed)
        result["total"] = total

        if score >= 85:
            result["grade"] = "A"
        elif score >= 70:
            result["grade"] = "B"
        elif score >= 50:
            result["grade"] = "C"
        elif score >= 30:
            result["grade"] = "D"
        else:
            result["grade"] = "F"

    except requests.exceptions.SSLError as e:
        result["findings"].append({
            "severity": "critical",
            "name": "HTTP Connection SSL Error",
            "asset": url,
            "status": "open",
            "msg": f"SSL connection error: {str(e)}",
            "recommendation": "Fix SSL configuration on remote host"
        })
    except requests.exceptions.ConnectionError:
        result["findings"].append({
            "severity": "critical",
            "name": "Host Connection Refused",
            "asset": url,
            "status": "open",
            "msg": "Could not establish HTTP connection to host",
            "recommendation": "Check web server operation and firewall rules"
        })
    except Exception as e:
        result["findings"].append({
            "severity": "info",
            "name": "Header Scanner Info",
            "asset": url,
            "status": "open",
            "msg": f"Header check encountered: {str(e)}",
            "recommendation": "Verify URL structure"
        })

    return result
