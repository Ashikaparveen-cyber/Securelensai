"""
Composite Risk Scoring & Vulnerability Engine
"""

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high":     12,
    "medium":    5,
    "low":       2,
    "info":      0,
}


def calculate_risk_score(scan_results: dict) -> dict:
    """
    Compute 0-100 risk score, risk level, finding counts, and sorted vulnerability list.
    0 = worst security risk, 100 = optimal security score.
    """
    score = 100
    all_findings = []
    category_scores = {}

    # SSL Evaluation
    ssl_data = scan_results.get("ssl", {})
    ssl_deduction = 0
    if isinstance(ssl_data, dict) and not ssl_data.get("error"):
        if not ssl_data.get("valid"):
            ssl_deduction += 40
        for f in ssl_data.get("findings", []):
            ssl_deduction += SEVERITY_WEIGHTS.get(f.get("severity", "info"), 0)
            all_findings.append({**f, "category": "SSL/TLS Certificate"})
        ssl_deduction = min(ssl_deduction, 40)
    category_scores["ssl"] = max(0, 100 - int(ssl_deduction * 2.5))
    score -= ssl_deduction

    # HTTP Headers Evaluation
    headers = scan_results.get("headers", {})
    headers_deduction = 0
    if isinstance(headers, dict) and not headers.get("error"):
        raw_score = headers.get("score", 50)
        headers_deduction = max(0, (100 - raw_score) * 0.25)
        for f in headers.get("findings", []):
            all_findings.append({**f, "category": "HTTP Security Headers"})
    category_scores["headers"] = headers.get("score", 50) if isinstance(headers, dict) else 50
    score -= headers_deduction

    # Domain / WHOIS & DNS Evaluation
    domain = scan_results.get("domain", {})
    domain_deduction = 0
    if isinstance(domain, dict) and not domain.get("error"):
        trust = domain.get("trust_score", 60)
        domain_deduction = max(0, (100 - trust) * 0.10)
        for f in domain.get("findings", []):
            all_findings.append({**f, "category": "Domain & DNS Posture"})
    category_scores["domain"] = domain.get("trust_score", 60) if isinstance(domain, dict) else 60
    score -= domain_deduction

    final_score = max(0, min(100, round(score)))

    # Determine Risk Level & Display Color
    if final_score >= 80:
        risk_level = "Low Risk"
        risk_color = "green"
    elif final_score >= 60:
        risk_level = "Medium Risk"
        risk_color = "amber"
    elif final_score >= 40:
        risk_level = "High Risk"
        risk_color = "orange"
    else:
        risk_level = "Critical Risk"
        risk_color = "red"

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 99))

    return {
        "overall_score": final_score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "category_scores": category_scores,
        "all_findings": all_findings,
        "finding_counts": {
            "critical": sum(1 for f in all_findings if f.get("severity") == "critical"),
            "high":     sum(1 for f in all_findings if f.get("severity") == "high"),
            "medium":   sum(1 for f in all_findings if f.get("severity") == "medium"),
            "low":      sum(1 for f in all_findings if f.get("severity") == "low"),
        }
    }
