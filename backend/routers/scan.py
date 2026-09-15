"""
FastAPI Router — Scan Operations
"""

import uuid
import asyncio
from datetime import datetime, timezone
from urllib.parse import urlparse
from fastapi import APIRouter, HTTPException, Depends

from scanners.ssl_checker import check_ssl
from scanners.header_checker import check_headers
from scanners.whois_checker import check_whois
from scanners.dns_checker import check_dns
from scanners.risk_engine import calculate_risk_score

from database.db import save_scan, get_scan, list_scans
from database.models import ScanRequest
from ai.groq_service import generate_scan_ai_summary
from auth.auth import get_current_user

router = APIRouter(prefix="", tags=["Scan"])


def _merge_domain_results(hostname: str, whois_res: dict, dns_res: dict) -> dict:
    domain_res = {
        "hostname": hostname,
        "registrar": whois_res.get("registrar"),
        "registrant_country": whois_res.get("registrant_country"),
        "created": whois_res.get("created"),
        "updated": whois_res.get("updated"),
        "expires": whois_res.get("expires"),
        "domain_age_days": whois_res.get("domain_age_days"),
        "days_until_expiry": whois_res.get("days_until_expiry"),
        "nameservers": whois_res.get("nameservers", []),
        "privacy_protected": whois_res.get("privacy_protected", False),
        "mx_records": dns_res.get("mx_records", []),
        "a_records": dns_res.get("a_records", []),
        "txt_records": dns_res.get("txt_records", []),
        "spf_present": dns_res.get("spf_present", False),
        "dmarc_present": dns_res.get("dmarc_present", False),
        "dkim_hint": dns_res.get("dkim_hint", False),
        "findings": whois_res.get("findings", []) + dns_res.get("findings", []),
    }

    score = 60
    age = domain_res.get("domain_age_days") or 0
    if age > 1825:
        score += 20
    elif age > 365:
        score += 10
    elif age < 90:
        score -= 20

    if domain_res["spf_present"]:
        score += 8
    if domain_res["dmarc_present"]:
        score += 8
    if domain_res["nameservers"]:
        score += 4

    expiry = domain_res.get("days_until_expiry") or 365
    if expiry < 30:
        score -= 15
    elif expiry < 90:
        score -= 5

    domain_res["trust_score"] = max(0, min(100, score))
    return domain_res


@router.post("/scan")
@router.post("/api/scan")
async def run_scan(req: ScanRequest, user_id: str = Depends(get_current_user)):
    """Run a full security scan on a target URL."""
    scan_id = str(uuid.uuid4())
    url = req.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or url

    results = {
        "scan_id": scan_id,
        "url": url,
        "hostname": hostname,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": user_id,
    }

    # Execute scanners concurrently
    ssl_task = asyncio.create_task(asyncio.to_thread(check_ssl, hostname))
    headers_task = asyncio.create_task(asyncio.to_thread(check_headers, url))
    whois_task = asyncio.create_task(asyncio.to_thread(check_whois, hostname))
    dns_task = asyncio.create_task(asyncio.to_thread(check_dns, hostname))

    completed = await asyncio.gather(ssl_task, headers_task, whois_task, dns_task, return_exceptions=True)

    results["ssl"] = completed[0] if not isinstance(completed[0], Exception) else {"error": str(completed[0])}
    results["headers"] = completed[1] if not isinstance(completed[1], Exception) else {"error": str(completed[1])}

    whois_res = completed[2] if not isinstance(completed[2], Exception) else {"error": str(completed[2])}
    dns_res = completed[3] if not isinstance(completed[3], Exception) else {"error": str(completed[3])}

    results["domain"] = _merge_domain_results(hostname, whois_res, dns_res)

    # Compute overall risk score & aggregated findings
    results["risk"] = calculate_risk_score(results)

    # Generate Groq AI executive summary if enabled
    if req.include_ai:
        try:
            results["ai_analysis"] = await generate_scan_ai_summary(results)
        except Exception as e:
            results["ai_analysis"] = f"AI Analysis Summary Unavailable: {str(e)}"

    # Save result to MongoDB / DB
    await save_scan(scan_id, results, user_id=user_id)

    return results


@router.get("/scan/history")
@router.get("/api/scan/history")
async def get_history(user_id: str = Depends(get_current_user)):
    """Retrieve scan history list for logged-in user."""
    return await list_scans(user_id=user_id, limit=50)


@router.get("/scan/{scan_id}")
@router.get("/api/scan/{scan_id}")
async def get_scan_details(scan_id: str, user_id: str = Depends(get_current_user)):
    """Retrieve full scan details by scan ID."""
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
