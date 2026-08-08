import os
from groq import Groq


class LLMService:
    """One-shot investigation report — Groq Llama 3.3 70B"""

    MODEL = "llama-3.3-70b-versatile"

    def __init__(self, api_key: str):
        self.client = Groq(api_key=api_key)

    def investigate(self, alert: dict) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.MODEL,
                messages=[
                    {"role": "system", "content": self._system()},
                    {"role": "user",   "content": self._prompt(alert)},
                ],
                max_tokens=1500,
                temperature=0.3,
            )
            return response.choices[0].message.content

        except Exception as e:
            msg = str(e)
            if "429" in msg or "rate_limit" in msg.lower():
                return (
                    "⚠️ Groq rate limit hit. Please wait 30 seconds.\n\n"
                    "Groq free tier allows **14,400 requests/day**."
                )
            if "401" in msg or "invalid_api_key" in msg.lower():
                return "❌ Invalid Groq API key. Check GROQ_API_KEY in your .env file."
            return f"❌ Groq Error: {msg}"

    def _system(self) -> str:
        return (
            "You are an expert SOC Level-2 Security Analyst. "
            "Generate a complete, structured investigation report. "
            "Use only the data provided. Never invent details."
        )

    def _prompt(self, alert: dict) -> str:
        return f"""
Generate a full SOC investigation report for this security alert.

ALERT DETAILS
═════════════
Threat              : {alert.get("threat")}
Severity            : {alert.get("severity")} | Risk Score: {alert.get("risk_score")}/10
Detection           : {alert.get("final_detection")}
MITRE Technique     : {alert.get("mapped_technique")}
MITRE Tactic        : {alert.get("mitre_tactic")}
Context             : {alert.get("context")}
Business Impact     : {alert.get("business_impact")}
Investigation Prio  : {alert.get("investigation_priority")}
Signature           : {alert.get("signature")}
Detection Tool      : {alert.get("tool")}

Write a professional report with these sections:

## 1. Executive Summary
## 2. Root Cause Analysis
## 3. For the Developer 👨‍💻
## 4. For the Business 💼
## 5. For the SOC Analyst 🔍
## 6. Mitigation Steps
## 7. Detection Improvement
"""