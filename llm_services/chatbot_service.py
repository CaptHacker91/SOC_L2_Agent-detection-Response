import google.generativeai as genai


class ChatbotService:
    """
    SOC Investigation Chatbot
    """

    def __init__(self, api_key):

        genai.configure(
            api_key=api_key
        )

        self.model = genai.GenerativeModel(
            "gemini-2.5-flash"
        )

    def ask(
        self,
        question,
        alert,
        logs,
    ):

        prompt = f"""
You are an experienced SOC Level 2 Security Analyst.

Current Security Alert

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

Associated Logs

{logs}

Analyst Question

{question}

Provide a professional SOC analyst response including:

- Threat explanation
- Root cause
- Investigation guidance
- Containment recommendations
- Remediation steps
"""

        try:

            response = self.model.generate_content(
                prompt
            )

            return response.text

        except Exception as error:

            return f"Gemini API Error: {error}"