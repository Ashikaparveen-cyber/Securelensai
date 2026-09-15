"""
DNS Posture & Email Security Scanner Module
"""

import dns.resolver


def check_dns(hostname: str) -> dict:
    result = {
        "hostname": hostname,
        "mx_records": [],
        "a_records": [],
        "txt_records": [],
        "spf_present": False,
        "dmarc_present": False,
        "dkim_hint": False,
        "findings": [],
    }

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        # A records
        try:
            a_records = resolver.resolve(hostname, "A")
            result["a_records"] = [str(r) for r in a_records]
        except Exception:
            pass

        # MX records
        try:
            mx_records = resolver.resolve(hostname, "MX")
            result["mx_records"] = [str(r.exchange).rstrip(".") for r in mx_records]
        except Exception:
            pass

        # TXT records (SPF, DMARC, DKIM)
        try:
            txt_records = resolver.resolve(hostname, "TXT")
            for r in txt_records:
                txt = str(r).strip('"')
                result["txt_records"].append(txt)
                if txt.startswith("v=spf1"):
                    result["spf_present"] = True
                if "dkim" in txt.lower():
                    result["dkim_hint"] = True
        except Exception:
            pass

        # DMARC
        try:
            dmarc_records = resolver.resolve(f"_dmarc.{hostname}", "TXT")
            for r in dmarc_records:
                if "v=DMARC1" in str(r):
                    result["dmarc_present"] = True
        except Exception:
            pass

        # Email security posture checks
        if not result["spf_present"]:
            result["findings"].append({
                "severity": "medium",
                "name": "Missing SPF Record",
                "asset": hostname,
                "status": "open",
                "msg": "No SPF TXT record found — domain susceptible to email spoofing",
                "recommendation": "Add SPF record: v=spf1 include:_spf.example.com ~all"
            })
        if not result["dmarc_present"]:
            result["findings"].append({
                "severity": "medium",
                "name": "Missing DMARC Policy",
                "asset": hostname,
                "status": "open",
                "msg": "No DMARC record found — email From headers can be forged",
                "recommendation": "Add DMARC TXT record: _dmarc.example.com TXT v=DMARC1; p=quarantine"
            })

    except Exception as e:
        result["findings"].append({
            "severity": "info",
            "name": "DNS Query Info",
            "asset": hostname,
            "status": "open",
            "msg": f"DNS query output: {str(e)}",
            "recommendation": "Check domain DNS resolution"
        })

    return result
