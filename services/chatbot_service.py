import os
import time
from groq import Groq


class ChatbotService:
    """SOC Investigation Chatbot — Groq Llama 3.3 70B"""

    MODEL = "llama-3.3-70b-versatile"  # 14400 req/day FREE masze karo

    def __init__(self, api_key: str):
        self.client       = Groq(api_key=api_key)
        self.last_request = 0
        self.min_interval = 2  # seconds between requests

    def ask(self, question: str, alert: dict, logs: str) -> str:

        # Rate-limit guard
        wait = self.min_interval - (time.time() - self.last_request)
        if wait > 0:
            return f"⏳ Please wait {round(wait, 1)}s before sending another request."

        self.last_request = time.time()

        try:
            response = self.client.chat.completions.create(
                model=self.MODEL,
                messages=[
                    {"role": "system", "content": self._system()},
                    {"role": "user",   "content": self._prompt(question, alert, logs)},
                ],
                max_tokens=1024,
                temperature=0.3,
            )
            return response.choices[0].message.content

        except Exception as e:
            msg = str(e)
            if "429" in msg or "rate_limit" in msg.lower():
                return (
                    "⚠️ Groq rate limit hit. Please wait 30 seconds and try again.\n\n"
                    "Groq free tier: **14,400 requests/day** — very generous, rare to hit."
                )
            if "401" in msg or "invalid_api_key" in msg.lower():
                return "❌ Invalid Groq API key. Check GROQ_API_KEY in your .env file."
            return f"❌ Groq Error: {msg}"

    # ── Helpers ────────────────────────────────────────────────────────────────
    def _system(self) -> str:
        return (
            "You are an expert SOC Level-2 Incident Response Analyst. "
            "Analyze only the provided alert data. "
            "Never invent IPs, usernames, or details not present in the alert. "
            "Be concise, structured, and actionable."
        )

    def _prompt(self, question: str, alert: dict, logs: str) -> str:
        return f"""
SECURITY ALERT
══════════════
Threat              : {alert.get("threat")}
Severity            : {alert.get("severity")} | Risk Score: {alert.get("risk_score")}/10
Detection           : {alert.get("final_detection")}
MITRE Technique     : {alert.get("mapped_technique")}
MITRE Tactic        : {alert.get("mitre_tactic")}
Context             : {alert.get("context")}
Business Impact     : {alert.get("business_impact")}
Investigation Prio  : {alert.get("investigation_priority")}

ASSOCIATED LOGS
═══════════════
{logs}

ANALYST QUESTION
════════════════
{question}

Respond with these sections (keep each section 2-4 lines):

**1. Executive Summary**
**2. Threat Explanation**
**3. Root Cause Analysis**
**4. MITRE ATT&CK Explanation**
**5. Business Impact**
**6. Investigation Steps**
**7. Containment Recommendations**
**8. Remediation Steps**
**9. Confidence Level** (High / Medium / Low + reason)
"""