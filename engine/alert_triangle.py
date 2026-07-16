class AlertTriangle:
    """
    Alert Triangle Engine

    Components:
    - Severity
    - Context
    - Business Impact
    """

    def generate(self, dataframe):
        dataframe["context"] = dataframe["mapped_technique"].apply(
            self._context
        )

        dataframe["business_impact"] = dataframe["severity"].apply(
            self._impact
        )

        dataframe["investigation_priority"] = dataframe.apply(
            self._priority,
            axis=1
        )

        return dataframe

    def _context(self, technique):
        context = {
            "T1059.001": "PowerShell Execution",
            "T1003.001": "Credential Dumping",
            "T1486": "Ransomware",
            "T1021": "Lateral Movement",
            "T1547": "Persistence",
            "T1110": "Brute Force",
            "T1078": "Valid Accounts",
            "T1047": "WMI Execution",
            "T1082": "System Discovery",
            "T1083": "File Discovery",
            "T1055": "Process Injection",
            "T1562": "Defense Evasion",
            "T1105": "Command & Control",
            "T1053": "Scheduled Task",
        }

        return context.get(technique, "Unknown Context")

    def _impact(self, severity):
        impact = {
            "Critical": "Very High",
            "High": "High",
            "Medium": "Moderate",
            "Low": "Low",
        }

        return impact.get(severity, "Unknown")

    def _priority(self, row):
        severity = row["severity"]

        if severity == "Critical":
            return "Immediate Investigation"

        if severity == "High":
            return "High Priority"

        if severity == "Medium":
            return "Medium Priority"

        return "Low Priority"