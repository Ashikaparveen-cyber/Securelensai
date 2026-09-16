"""
Groq AI Security Analyst Service
Powered by Llama 3.1 models via Groq API
"""

import os
import json
import httpx
from typing import List, Dict, Any

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
DEFAULT_MODEL = "openai/gpt-oss-20b"  # Groq's recommended replacement for llama-3.1-8b-instant
GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"


async def call_groq_api(messages: List[Dict[str, str]], temperature: float = 0.3) -> str:
    """Call Groq API using HTTP client."""
    if not GROQ_API_KEY:
        return (
            "[Groq API Key Not Configured] To activate live AI Analyst responses, set the GROQ_API_KEY environment variable in backend/.env. "
            "Based on static analysis: The scan identified security gaps that should be remediated by implementing missing HTTP headers and ensuring valid SSL configuration."
        )

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": DEFAULT_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": 1024,
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(GROQ_ENDPOINT, headers=headers, json=payload)
            if response.status_code == 200:
                data = response.json()
                return data["choices"][0]["message"]["content"]
            else:
                return f"[Groq API Error {response.status_code}]: {response.text}"
    except Exception as e:
        return f"[Groq Connection Error]: Could not reach Groq API ({str(e)})"


async def generate_scan_ai_summary(scan_data: dict) -> str:
    """Generate executive AI summary of scan findings."""
    url = scan_data.get("url", "")
    risk = scan_data.get("risk", {})
    score = risk.get("overall_score", 0)
    risk_level = risk.get("risk_level", "Unknown")
    findings = risk.get("all_findings", [])

    prompt = (
        f"You are SecureLens AI, an expert Lead Cybersecurity Analyst.\n"
        f"Target URL: {url}\n"
        f"Overall Risk Score: {score}/100 ({risk_level})\n"
        f"Vulnerabilities & Findings Count: {len(findings)}\n"
        f"Top Findings:\n" + "\n".join([f"- [{f.get('severity', 'info').upper()}] {f.get('name', f.get('msg', ''))}" for f in findings[:6]]) + "\n\n"
        f"Provide a concise executive security summary (3-4 sentences) outlining the immediate risk posture and top 2 recommended remediation actions."
    )

    messages = [
        {"role": "system", "content": "You are a professional senior cybersecurity analyst providing clear, actionable risk assessment summaries."},
        {"role": "user", "content": prompt}
    ]
    return await call_groq_api(messages, temperature=0.2)


async def chat_with_ai_analyst(scan_data: dict, history: List[dict], user_message: str) -> str:
    """Chat with AI analyst about a specific scan."""
    url = scan_data.get("url", "Target Website") if scan_data else "Target Website"
    risk = scan_data.get("risk", {}) if scan_data else {}
    score = risk.get("overall_score", "N/A")
    risk_level = risk.get("risk_level", "N/A")
    findings = risk.get("all_findings", []) if scan_data else []

    system_prompt = (
        f"You are SecureLens AI Analyst, a top-tier virtual Chief Information Security Officer (CISO) and cybersecurity expert.\n"
        f"You are assisting an operator with security audit findings for target: {url}\n"
        f"Current Scan Context:\n"
        f"- Target URL: {url}\n"
        f"- Overall Security Score: {score}/100 ({risk_level})\n"
        f"- Active Findings: {json.dumps(findings, indent=2)}\n\n"
        f"Instructions:\n"
        f"1. Answer questions clearly, precisely, and with cybersecurity best practices.\n"
        f"2. Reference exact headers, SSL details, or WHOIS/DNS findings from the context when relevant.\n"
        f"3. Provide actionable code/config snippets (e.g. Nginx, Apache, HTML) when asked for fixes.\n"
        f"4. Maintain a professional, authoritative, yet helpful cyber-analyst tone."
    )

    messages = [{"role": "system", "content": system_prompt}]

    # Include recent conversation history
    for item in history[-6:]:
        role = "assistant" if item.get("sender") == "ai" else "user"
        messages.append({"role": role, "content": item.get("text", "")})

    # Add latest prompt
    messages.append({"role": "user", "content": user_message})

    return await call_groq_api(messages, temperature=0.4)
