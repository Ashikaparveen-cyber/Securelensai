"""
WHOIS Registration & Domain Intelligence Scanner Module
"""

import whois
from datetime import datetime, timezone


def check_whois(hostname: str) -> dict:
    result = {
        "hostname": hostname,
        "registrar": None,
        "registrant_country": None,
        "created": None,
        "updated": None,
        "expires": None,
        "domain_age_days": None,
        "days_until_expiry": None,
        "nameservers": [],
        "privacy_protected": False,
        "findings": [],
    }

    try:
        w = whois.whois(hostname)
        now = datetime.now(timezone.utc)

        result["registrar"] = str(w.registrar) if w.registrar else "Unknown"

        if hasattr(w, "country") and w.country:
            result["registrant_country"] = str(w.country)

        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if hasattr(created, "tzinfo") and created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            if hasattr(created, "isoformat"):
                result["created"] = created.isoformat()
                result["domain_age_days"] = (now - created).days

        expires = w.expiration_date
        if isinstance(expires, list):
            expires = expires[0]
        if expires:
            if hasattr(expires, "tzinfo") and expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if hasattr(expires, "isoformat"):
                result["expires"] = expires.isoformat()
                result["days_until_expiry"] = (expires - now).days

        updated = w.updated_date
        if isinstance(updated, list):
            updated = updated[0]
        if updated and hasattr(updated, "isoformat"):
            result["updated"] = updated.isoformat()

        ns = w.name_servers
        if ns:
            result["nameservers"] = [str(n).lower() for n in (ns if isinstance(ns, list) else [ns])]

        privacy_keywords = ["privacy", "protect", "proxy", "redacted", "whoisguard", "domainprivacy"]
        if any(kw in str(w).lower() for kw in privacy_keywords):
            result["privacy_protected"] = True

        if result["domain_age_days"] is not None and result["domain_age_days"] < 90:
            result["findings"].append({
                "severity": "high",
                "name": "Newly Registered Domain",
                "asset": hostname,
                "status": "open",
                "msg": f"Domain is only {result['domain_age_days']} days old — higher risk of phishing/suspicious activity",
                "recommendation": "Monitor domain for brand impersonation or suspicious behavior"
            })
        elif result["domain_age_days"] is not None and result["domain_age_days"] < 365:
            result["findings"].append({
                "severity": "medium",
                "name": "Recent Domain Registration",
                "asset": hostname,
                "status": "open",
                "msg": f"Domain age is less than 1 year ({result['domain_age_days']} days)",
                "recommendation": "Establish baseline security monitoring"
            })

        if result["days_until_expiry"] is not None:
            if result["days_until_expiry"] < 0:
                result["findings"].append({
                    "severity": "critical",
                    "name": "Expired Domain Registration",
                    "asset": hostname,
                    "status": "open",
                    "msg": "Domain registration has expired!",
                    "recommendation": "Renew domain registration immediately to avoid hijacking"
                })
            elif result["days_until_expiry"] < 30:
                result["findings"].append({
                    "severity": "high",
                    "name": "Domain Expiry Approaching",
                    "asset": hostname,
                    "status": "open",
                    "msg": f"Domain registration expires in {result['days_until_expiry']} days",
                    "recommendation": "Renew domain registration promptly"
                })

    except Exception as e:
        result["findings"].append({
            "severity": "info",
            "name": "WHOIS Lookup Info",
            "asset": hostname,
            "status": "open",
            "msg": f"WHOIS query detail: {str(e)}",
            "recommendation": "Verify domain registrar WHOIS privacy settings"
        })

    return result
