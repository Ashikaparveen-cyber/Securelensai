"""
SSL Certificate Scanner Module
"""

import ssl
import socket
from datetime import datetime, timezone


def check_ssl(hostname: str) -> dict:
    """
    Check SSL certificate validity, expiry, issuer, and grade.
    Returns a dict with all SSL findings.
    """
    result = {
        "hostname": hostname,
        "valid": False,
        "grade": "F",
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "protocol": None,
        "cipher": None,
        "san": [],
        "findings": [],
    }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

        # Parse cert fields
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        not_after_str = cert.get("notAfter", "")
        not_before_str = cert.get("notBefore", "")

        # Parse dates
        fmt = "%b %d %H:%M:%S %Y %Z"
        not_after = datetime.strptime(not_after_str, fmt).replace(tzinfo=timezone.utc)
        not_before = datetime.strptime(not_before_str, fmt).replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (not_after - now).days

        # SANs
        san_list = []
        for san_type, san_value in cert.get("subjectAltName", []):
            if san_type == "DNS":
                san_list.append(san_value)

        result.update({
            "valid": True,
            "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
            "issuer_cn": issuer.get("commonName", ""),
            "subject": subject.get("commonName", hostname),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_until_expiry": days_left,
            "protocol": protocol,
            "cipher": cipher[0] if cipher else None,
            "cipher_bits": cipher[2] if cipher else None,
            "san": san_list,
        })

        # Grading & findings
        grade = "A"
        findings = []

        if days_left < 0:
            result["valid"] = False
            grade = "F"
            findings.append({
                "severity": "critical",
                "name": "SSL Certificate Expired",
                "asset": f"{hostname}:443",
                "status": "open",
                "msg": "SSL certificate has expired",
                "recommendation": "Renew SSL certificate immediately"
            })
        elif days_left < 14:
            grade = "C"
            findings.append({
                "severity": "high",
                "name": "SSL Certificate Expiring Soon",
                "asset": f"{hostname}:443",
                "status": "open",
                "msg": f"Certificate expires in {days_left} days",
                "recommendation": "Renew SSL certificate before expiration"
            })
        elif days_left < 30:
            grade = "B"
            findings.append({
                "severity": "medium",
                "name": "SSL Expiry Warning",
                "asset": f"{hostname}:443",
                "status": "open",
                "msg": f"Certificate expires in {days_left} days",
                "recommendation": "Schedule SSL certificate renewal"
            })

        if protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
            grade = "C"
            findings.append({
                "severity": "high",
                "name": "Outdated TLS Protocol",
                "asset": f"{hostname}:443",
                "status": "open",
                "msg": f"Outdated TLS protocol: {protocol}",
                "recommendation": "Disable TLS 1.0/1.1 and enable TLS 1.2 or TLS 1.3"
            })

        if cipher and ("RC4" in cipher[0] or "DES" in cipher[0] or "NULL" in cipher[0]):
            grade = "F"
            findings.append({
                "severity": "critical",
                "name": "Weak SSL/TLS Cipher",
                "asset": f"{hostname}:443",
                "status": "open",
                "msg": f"Weak cipher suite detected: {cipher[0]}",
                "recommendation": "Configure server to use strong cipher suites (e.g. ECDHE-RSA-AES128-GCM-SHA256)"
            })

        result["grade"] = grade
        result["findings"] = findings

    except ssl.SSLCertVerificationError as e:
        result["findings"] = [{
            "severity": "critical",
            "name": "SSL Verification Failed",
            "asset": f"{hostname}:443",
            "status": "open",
            "msg": f"SSL verification error: {str(e)}",
            "recommendation": "Install a valid, untrusted or self-signed certificate replacement from a recognized CA"
        }]
    except ssl.SSLError as e:
        result["findings"] = [{
            "severity": "critical",
            "name": "SSL Connection Error",
            "asset": f"{hostname}:443",
            "status": "open",
            "msg": f"SSL error: {str(e)}",
            "recommendation": "Verify TLS/SSL server configuration"
        }]
    except socket.timeout:
        result["findings"] = [{
            "severity": "medium",
            "name": "SSL Connection Timeout",
            "asset": f"{hostname}:443",
            "status": "open",
            "msg": "Connection timed out — port 443 may be closed",
            "recommendation": "Ensure port 443 is open and accessible"
        }]
    except ConnectionRefusedError:
        result["findings"] = [{
            "severity": "high",
            "name": "SSL Port Refused",
            "asset": f"{hostname}:443",
            "status": "open",
            "msg": "Port 443 connection refused",
            "recommendation": "Enable HTTPS listener on port 443"
        }]
    except Exception as e:
        result["findings"] = [{
            "severity": "info",
            "name": "SSL Scanner Info",
            "asset": f"{hostname}:443",
            "status": "open",
            "msg": f"Could not complete SSL check: {str(e)}",
            "recommendation": "Verify hostname availability"
        }]

    return result
