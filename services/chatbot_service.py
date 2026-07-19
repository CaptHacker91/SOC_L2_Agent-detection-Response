import os
import time
from google import genai


class ChatbotService:
    """SOC Investigation Chatbot"""

    def __init__(self, api_key):
        self.client = genai.Client(api_key=api_key)
        self.model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite")
        self.last_request = 0
        self.min_interval = 3  # seconds

    def ask(self, question, alert, logs):

        now = time.time()

        if now - self.last_request < self.min_interval:
            wait = round(self.min_interval - (now - self.last_request), 1)
            return f"⏳ Please wait {wait} seconds before sending another request."

        self.last_request = now

        prompt = f"""
You are an experienced SOC Level-2 Incident Response Analyst.

Analyze ONLY the information provided below.

========================
SECURITY ALERT
========================

Threat:
{alert.get("threat")}

Severity:
{alert.get("severity")}

Risk Score:
{alert.get("risk_score")}

Detection:
{alert.get("final_detection")}

MITRE Technique:
{alert.get("mapped_technique")}

MITRE Tactic:
{alert.get("mitre_tactic")}

Business Impact:
{alert.get("business_impact")}

Investigation Priority:
{alert.get("investigation_priority")}

========================
ASSOCIATED LOGS
========================

{logs}

========================
ANALYST QUESTION
========================

{question}

Respond in this format:

1. Executive Summary
2. Threat Explanation
3. Root Cause Analysis
4. MITRE ATT&CK Explanation
5. Business Impact
6. Investigation Steps
7. Containment Recommendations
8. Remediation Steps
9. Confidence Level

Rules:
- Do NOT invent information.
- Base every conclusion only on the supplied alert and logs.
- Keep the response concise and professional.
"""

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
            )

            return response.text

        except Exception as error:
            msg = str(error)

            if "404" in msg or "NOT_FOUND" in msg:
                return (
                    f"❌ Model '{self.model}' not found.\n"
                    "Update GEMINI_MODEL in your .env file."
                )

            if "429" in msg or "RESOURCE_EXHAUSTED" in msg:
                return (
                    "⚠️ Gemini API rate limit exceeded.\n"
                    "Please wait a minute and try again."
                )

            return f"Gemini API Error: {msg}"