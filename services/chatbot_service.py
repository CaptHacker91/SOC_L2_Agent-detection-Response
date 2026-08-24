import os
import time
from groq import Groq


class ChatbotService:
    """
    SOC L2 Investigation Chatbot — Groq
    BUG FIX: Updated to current active model (llama-3.3-70b-versatile).
    BUG FIX: Alert injected fresh into system prompt every call (no same-answer bug).
    BUG FIX: Conversation history passed as messages for multi-turn context.
    """

    # llama3-8b-8192 was decommissioned — use current active models
    MODEL_CHAIN = [
        "llama-3.3-70b-versatile",   # Primary — 14400 req/day free, best quality
        "llama-3.1-8b-instant",       # Fallback — fast, lightweight
        "gemma2-9b-it",               # Last resort
    ]

    def __init__(self, api_key: str):
        self.client       = Groq(api_key=api_key)
        self.model        = os.getenv("GROQ_MODEL", self.MODEL_CHAIN[0])
        self.last_request = 0
        self.min_interval = 2

    def ask(self, question: str, alert: dict, logs: str, history: list = None) -> str:
        wait = self.min_interval - (time.time() - self.last_request)
        if wait > 0:
            return f"Please wait {round(wait, 1)}s before sending another request."

        self.last_request = time.time()

        # System prompt rebuilt fresh every call with live alert data
        messages = [{"role": "system", "content": self._system(alert, logs)}]

        # Include prior conversation (max 6 turns)
        if history:
            for msg in history[-6:]:
                if msg.get("role") in ("user", "assistant"):
                    messages.append({
                        "role": msg["role"],
                        "content": msg["content"]
                    })

        messages.append({"role": "user", "content": question})

        # Try model chain
        for model in self.MODEL_CHAIN:
            try:
                resp = self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    max_tokens=1024,
                    temperature=0.4,
                )
                return resp.choices[0].message.content

            except Exception as e:
                msg = str(e)
                if "decommissioned" in msg or "model_decommissioned" in msg or "404" in msg:
                    continue  # try next model
                if "429" in msg or "rate_limit" in msg.lower():
                    return (
                        "Groq rate limit hit. Please wait 30 seconds and try again.\n"
                        "Groq free tier: 14,400 requests/day."
                    )
                if "401" in msg or "invalid_api_key" in msg.lower():
                    return "Invalid Groq API key. Check GROQ_API_KEY in your .env file."
                return f"Groq Error: {msg}"

        return "All Groq models unavailable. Please check your API key and try again."

    def _system(self, alert: dict, logs: str) -> str:
        """
        System prompt rebuilt fresh per call with actual alert data.
        This ensures every question gets an alert-specific answer.
        """
        threat = alert.get("threat", "Unknown")
        return (
            "You are a SOC Level-2 Incident Response Analyst.\n\n"
            "You are investigating THIS specific security alert:\n\n"
            "ACTIVE ALERT\n"
            "============\n"
            f"Threat         : {threat}\n"
            f"Severity       : {alert.get('severity')} | Risk: {alert.get('risk_score')}/10\n"
            f"Detection      : {alert.get('final_detection')}\n"
            f"MITRE          : {alert.get('mapped_technique')} ({alert.get('mitre_tactic')}) -- {alert.get('mitre_sub_name', '?')}\n"
            f"Context        : {alert.get('context')}\n"
            f"Business Impact: {alert.get('business_impact')}\n"
            f"Priority       : {alert.get('investigation_priority')}\n"
            f"Tool           : {alert.get('tool')} | Rule: {alert.get('rule_type')}\n"
            f"Signature      : {alert.get('signature', 'Not available')}\n\n"
            "LOGS\n"
            "====\n"
            f"{logs}\n\n"
            "Rules:\n"
            f"- ALWAYS reference the specific threat: '{threat}'\n"
            "- NEVER give generic advice -- tailor to this exact alert\n"
            "- NEVER invent IPs, usernames, or timestamps not present above\n"
            "- If data is missing, say 'Not available in supplied telemetry'\n"
            "- Be concise, structured, and directly actionable\n"
            f"- Recommendations must be specific to {alert.get('mitre_tactic')} / {alert.get('mapped_technique')}\n"
        )