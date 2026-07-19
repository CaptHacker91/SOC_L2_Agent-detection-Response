from google import genai


class LLMService:
    """
    AI Investigation Service

    Generates:
    - Executive Summary
    - Root Cause Analysis
    - Threat Impact
    - Containment
    - Remediation
    """

   def __init__(self, api_key):
    self.client = genai.Client(api_key=api_key)
    self.model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite")
    self.last_request = 0
    self.min_interval = 3

    def investigate(self, alert):

        prompt = self._build_prompt(alert)

        response = self.model.generate_content(
            prompt
        )

        return response.text

    def _build_prompt(self, alert):

        return f"""
You are an experienced SOC Level 2 Analyst.

Analyze the following security alert.

Threat:
{alert.get("threat")}

Detection Status:
{alert.get("final_detection")}

MITRE Technique:
{alert.get("mapped_technique")}

MITRE Tactic:
{alert.get("mitre_tactic")}

SOC Risk Score:
{alert.get("risk_score")}

Severity:
{alert.get("severity")}

Context:
{alert.get("context")}

Business Impact:
{alert.get("business_impact")}

Investigation Priority:
{alert.get("investigation_priority")}

Provide:

1. Executive Summary

2. Root Cause Analysis

3. Threat Impact

4. Investigation Steps

5. Containment

6. Remediation

7. SOC Analyst Notes
"""