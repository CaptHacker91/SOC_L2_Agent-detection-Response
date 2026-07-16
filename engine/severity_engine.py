class SeverityEngine:
    """
    SOC Risk Scoring Engine

    Calculates:
    - Risk Score
    - Severity
    """

    def __init__(self):
        self.scores = self._load_scores()

    def _load_scores(self):
        """
        Threat Risk Scores
        """

        return {

            "Credential Dumping": 9.8,

            "PowerShell Abuse": 9.4,

            "Ransomware Execution": 10.0,

            "Lateral Movement": 9.2,

            "Persistence": 8.8,

            "Privilege Escalation": 9.5,

            "Defense Evasion": 8.7,

            "Suspicious Login": 7.2,

            "Reconnaissance": 5.6,

        }

    def calculate(self, dataframe):
        """
        Calculate SOC Risk Score
        """

        dataframe["risk_score"] = (
            dataframe["threat"]
            .apply(self._risk_score)
        )

        dataframe["severity"] = (
            dataframe["risk_score"]
            .apply(self._severity)
        )

        return dataframe

    def _risk_score(self, threat):
        """
        Return Risk Score
        """

        return self.scores.get(
            threat,
            6.5
        )

    def _severity(self, score):
        """
        Convert Risk Score
        into Severity
        """

        if score >= 9.0:
            return "Critical"

        if score >= 7.0:
            return "High"

        if score >= 4.0:
            return "Medium"

        return "Low"