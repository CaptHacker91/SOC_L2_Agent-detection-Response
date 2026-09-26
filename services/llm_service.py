import os
from groq import Groq


class LLMService:
    """
    One-shot AI Investigation Report — Groq.

    Same verified model chain as ChatbotService (see that file's
    docstring for why). Kept as a separate class because this
    produces a structured investigation report, not a conversational
    answer, and is called on-demand (not on every page load) to
    avoid burning API quota.
    """

    MODEL_CHAIN = [
        os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
        "openai/gpt-oss-20b",
        "qwen/qwen3.6-27b",
    ]

    def __init__(self, api_key: str):
        self.client = Groq(api_key=api_key)

    def investigate(self, alert: dict) -> str:
        for model in self.MODEL_CHAIN:
            try:
                response = self.client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": self._system()},
                        {"role": "user", "content": self._prompt(alert)},
                    ],
                    max_tokens=1500,
                    temperature=0.3,
                )
                return response.choices[0].message.content
            except Exception as e:
                msg = str(e)
                if "decommissioned" in msg or "model_decommissioned" in msg or "404" in msg:
                    continue
                if "429" in msg or "rate_limit" in msg.lower():
                    return "⚠️ Groq rate limit hit. Please wait 30 seconds.\n\nGroq free tier allows **14,400 requests/day**."
                if "401" in msg or "invalid_api_key" in msg.lower():
                    return "❌ Invalid Groq API key. Check GROQ_API_KEY in your .env file."
                return f"❌ Groq Error: {msg}"

        return "❌ All Groq models unavailable. Please check your API key and try again."

    def _system(self) -> str:
        return (
            "You are a senior SOC L2 analyst writing a structured incident investigation "
            "report. Use ONLY the telemetry given to you. Never invent an IP, hostname, "
            "username, or MITRE technique that is not already present in the input. "
            "If a MITRE technique is 'Not mapped from supplied telemetry', say explicitly "
            "that this telemetry does not support a confident ATT&CK mapping — do not "
            "invent one. Never describe an HTTP 4xx/5xx response as a confirmed attack; "
            "describe exactly what the evidence shows and what remains unconfirmed."
        )

    def _prompt(self, alert: dict) -> str:
        return f"""Investigate this incident and produce:
1. Executive Summary
2. Why This Alert Is Suspicious (or isn't, if evidence is weak)
3. Evidence Supporting The Conclusion
4. Likely MITRE Technique (state clearly if none is supported)
5. Attack Chain (only if evidence supports one; otherwise say attack chain is not established)
6. IOC Interpretation
7. Investigation Steps
8. Containment Recommendations
9. Remediation Recommendations
10. Confidence Level
11. Limitations of this telemetry

INCIDENT DATA:
Threat: {alert.get('threat')}
Severity: {alert.get('severity')} | Risk Score: {alert.get('risk_score')}/10
Detection Result: {alert.get('final_detection')}
Detection Reason: {alert.get('detection_reason')}
MITRE Technique: {alert.get('mapped_technique')} ({alert.get('mitre_technique_name')})
MITRE Tactic: {alert.get('mitre_tactic')}

Source IP: {alert.get('source_ip') or 'not available in supplied telemetry'}
Hostname: {alert.get('hostname') or 'not available in supplied telemetry'}
Username: {alert.get('username') or 'not available in supplied telemetry'}
HTTP Method: {alert.get('http_method')}
HTTP Status: {alert.get('http_status')}
URI Path: {alert.get('uri_path') or 'not available'}
URI Query: {alert.get('uri_query') or 'not available'}
Full URL: {alert.get('url') or 'not available'}
Referer: {alert.get('referer') or 'not available'}
Business Impact: {alert.get('business_impact')}
Investigation Priority: {alert.get('investigation_priority')}
Raw Event: {str(alert.get('raw_event'))[:400] if alert.get('raw_event') else 'not available'}"""
