import google.generativeai as genai


class ChatbotService:
    """
    SOC Investigation Chatbot
    """

    def __init__(self, api_key):
        genai.configure(api_key=api_key)

        self.model = genai.GenerativeModel(
            "gemini-2.5-flash"
        )

    def ask(
        self,
        question,
        alert,
        report,
    ):

        prompt = f"""
You are an experienced SOC Level 2 Analyst.

Current Alert

Threat:
{alert.get("threat")}

Severity:
{alert.get("severity")}

MITRE:
{alert.get("mapped_technique")}

Investigation Report:

{report}

Analyst Question:

{question}

Answer professionally.
"""

        response = self.model.generate_content(
            prompt
        )

        return response.text