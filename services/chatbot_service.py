import os
import time
from groq import Groq


class ChatbotService:
    """
    SOC L2 Investigation Chatbot — Groq Llama 3.3 70B
    FIX: Alert injected fresh into system prompt every call → alert-specific answers.
    FIX: Conversation history passed as messages → multi-turn context works.
    """

    MODEL = "llama3-8b-8192"

    def __init__(self, api_key: str):
        self.client       = Groq(api_key=api_key)
        self.last_request = 0
        self.min_interval = 2

    def ask(self, question: str, alert: dict, logs: str, history: list = None) -> str:
        wait = self.min_interval - (time.time() - self.last_request)
        if wait > 0:
            return f"⏳ Please wait {round(wait, 1)}s before sending another request."
        self.last_request = time.time()

        # System prompt built fresh with live alert data every single call
        messages = [{"role": "system", "content": self._system(alert, logs)}]

        # Include prior conversation (max 6 turns) for multi-turn context
        if history:
            for msg in history[-6:]:
                if msg.get("role") in ("user", "assistant"):
                    messages.append({"role": msg["role"], "content": msg["content"]})

        messages.append({"role": "user", "content": question})

        try:
            resp = self.client.chat.completions.create(
                model=self.MODEL,
                messages=messages,
                max_tokens=1024,
                temperature=0.4,
            )
            return resp.choices[0].message.content
        except Exception as e:
            msg = str(e)
            if "429" in msg or "rate_limit" in msg.lower():
                return "⚠️ Groq rate limit hit. Please wait 30 seconds and try again."
            if "401" in msg or "invalid_api_key" in msg.lower():
                return "❌ Invalid Groq API key. Check GROQ_API_KEY in your .env file."
            return f"❌ Groq Error: {msg}"

    def _system(self, alert: dict, logs: str) -> str:
        """
        System prompt is rebuilt fresh each call with actual alert fields.
        This is THE fix for same-answer-every-time bug.
        """
        threat = alert.get("threat", "Unknown")
        return f"""You are a SOC Level-2 Incident Response Analyst.

You are investigating THIS specific security alert:

══════════════════════════════════════
ACTIVE ALERT
══════════════════════════════════════
Threat         : {threat}
Severity       : {alert.get("severity")} | Risk: {alert.get("risk_score")}/10
Detection      : {alert.get("final_detection")}
MITRE          : {alert.get("mapped_technique")} ({alert.get("mitre_tactic")}) — {alert.get("mitre_sub_name","?")}
Context        : {alert.get("context")}
Business Impact: {alert.get("business_impact")}
Priority       : {alert.get("investigation_priority")}
Tool           : {alert.get("tool")} | Rule: {alert.get("rule_type")}
Signature      : {alert.get("signature","Not available")}

LOGS
════
{logs}
══════════════════════════════════════

Rules:
- ALWAYS reference the specific threat: "{threat}"
- NEVER give generic advice — tailor to this exact alert
- NEVER invent IPs, usernames, or timestamps not present above
- If data is missing, say "Not available in supplied telemetry"
- Be concise, structured, and directly actionable
- Recommendations must be specific to {alert.get("mitre_tactic")} / {alert.get("mapped_technique")}
"""