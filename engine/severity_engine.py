class SeverityEngine:
    """
    Deterministic, explainable risk scoring. Every score is tied to a
    specific threat label with a documented reason — there is no
    generic "unknown -> 6.5 -> Medium" fallback, which was the root
    cause of every event landing on Medium regardless of evidence.

    Bands:
        0.0-3.9  = Low
        4.0-6.9  = Medium
        7.0-8.9  = High
        9.0-10.0 = Critical
    """

    RISK_SCORES = {
        # Synthetic SOC dataset — carried over, unchanged values
        "PowerShell Abuse":        (9.4, "Rule-matched living-off-the-land execution technique; high fidelity."),
        "Credential Dumping":      (9.8, "Rule-matched direct credential theft; near-certain compromise."),
        "Ransomware Execution":    (10.0, "Rule-matched destructive/impact-class threat."),
        "Malicious File Download": (7.5, "Rule-matched inbound file transfer to a flagged destination."),
        "Phishing Email":          (7.0, "Rule-matched initial-access vector; human verification still required."),

        # Web-access derived — tied directly to the HTTP evidence
        "Suspicious Request Pattern (Success)": (9.0, "Suspicious URI pattern AND the request succeeded (HTTP 200) — strongest available evidence of impact."),
        "Suspicious Request Pattern":           (7.2, "Suspicious URI pattern, but the request did not succeed — attempt only, outcome unconfirmed."),
        "Access Denied Attempt":                (5.5, "Explicit 403 — possible reconnaissance or unauthorized access attempt, request was blocked."),
        "Server Error on Request":               (5.0, "5xx in response to the request — may reflect an exploitation attempt or a plain application fault; this telemetry alone can't distinguish the two."),
        "Malformed Web Request":                (4.0, "400 Bad Request — usually a client-side error; low inherent risk without further correlation."),
        "Not Acceptable Request":               (3.5, "406 — content-negotiation failure, typically benign."),
        "Request Timeout":                      (3.0, "408 — client-side timeout, typically benign."),
        "Protocol Version Error":               (3.0, "505 — malformed/unsupported HTTP version, typically a scanner or misconfigured client."),
    }

    DEFAULT_RISK = (3.0, "No specific rule or pattern matched this event; defaulting to Low rather than an unearned Medium score.")
    NORMAL_RISK  = (0.0, "Classified as Normal telemetry.")

    def calculate(self, df):
        if df.empty:
            return df

        risks, reasons, severities = [], [], []
        for _, row in df.iterrows():
            if row.get("final_detection") == "Normal":
                score, why = self.NORMAL_RISK
            else:
                score, why = self.RISK_SCORES.get(row.get("threat"), self.DEFAULT_RISK)

            risks.append(score)
            reasons.append(why)
            severities.append(self._band(score, row.get("final_detection")))

        df["risk_score"] = risks
        df["risk_justification"] = reasons
        df["severity"] = severities
        return df

    @staticmethod
    def _band(score, final_detection):
        if final_detection == "Normal":
            return "Normal"
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        return "Low"
