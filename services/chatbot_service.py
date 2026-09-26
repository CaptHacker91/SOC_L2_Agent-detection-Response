import os
from groq import Groq


class ChatbotService:
    """
    Incident-aware SOC chat assistant.

    MODEL CHAIN — verified against Groq's current production catalog
    (llama-3.3-70b-versatile and llama-3.1-8b-instant were shut down
    for free/developer tiers; the current text models are the
    GPT-OSS family plus Qwen3 as a preview fallback). GROQ_MODEL in
    .env always takes priority if set. If Groq's lineup changes again,
    check https://console.groq.com/docs/models and update this list —
    the chain below will keep working as long as AT LEAST ONE id is
    still valid, since each failure falls through to the next.
    """

    MODEL_CHAIN = [
        os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
        "openai/gpt-oss-20b",
        "qwen/qwen3.6-27b",
    ]

    def __init__(self, api_key: str):
        self.client = Groq(api_key=api_key)

    def ask(self, question: str, alert: dict, chat_history: list) -> str:
        messages = [{"role": "system", "content": self._system(alert)}]
        # last 6 turns of prior context, excluding the message just appended by the caller
        for m in chat_history[-7:-1]:
            messages.append({"role": m["role"], "content": m["content"]})
        messages.append({"role": "user", "content": question})

        for model in self.MODEL_CHAIN:
            try:
                response = self.client.chat.completions.create(
                    model=model, messages=messages, max_tokens=800, temperature=0.3,
                )
                return response.choices[0].message.content
            except Exception as e:
                msg = str(e)
                if "decommissioned" in msg or "model_decommissioned" in msg or "404" in msg:
                    continue
                if "429" in msg or "rate_limit" in msg.lower():
                    return "⚠️ Groq rate limit hit. Please wait 30 seconds."
                if "401" in msg or "invalid_api_key" in msg.lower():
                    return "❌ Invalid Groq API key. Check GROQ_API_KEY in your .env file."
                return f"❌ Groq Error: {msg}"

        return "❌ All Groq models unavailable. Please check your API key and try again."

    def _system(self, alert: dict) -> str:
        return f"""You are a SOC Level-2 Incident Response Analyst investigating ONE specific alert.

INCIDENT TELEMETRY (this is the only ground truth you have — do not invent anything beyond it):
Threat: {alert.get('threat')}
Severity: {alert.get('severity')} | Risk Score: {alert.get('risk_score')}/10
Detection: {alert.get('final_detection')} — {alert.get('detection_reason')}
MITRE Technique: {alert.get('mapped_technique')} ({alert.get('mitre_technique_name')})
MITRE Tactic: {alert.get('mitre_tactic')}

Source IP: {alert.get('source_ip') or 'not available in supplied telemetry'}
Hostname: {alert.get('hostname') or 'not available in supplied telemetry'}
Username: {alert.get('username') or 'not available in supplied telemetry'}
HTTP Method/Status: {alert.get('http_method')} / {alert.get('http_status')}
URI Path: {alert.get('uri_path') or 'not available'}
URI Query: {alert.get('uri_query') or 'not available'}
Full URL: {alert.get('url') or 'not available'}
Referer: {alert.get('referer') or 'not available'}
Raw Event: {str(alert.get('raw_event'))[:300] if alert.get('raw_event') else 'not available'}

RULES:
- Answer only about THIS incident. Never give generic cybersecurity advice.
- Never invent an IP, hostname, username, or any other field not shown above.
- If telemetry needed to answer isn't present, say so explicitly rather than guessing.
- Do not claim a MITRE technique unless one is already listed above.
- Do not describe an HTTP 4xx/5xx response as a "confirmed" attack — describe what the evidence actually shows.
- Be concise, structured, and directly useful to an analyst."""
