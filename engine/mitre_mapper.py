class MitreMapper:
    """
    MITRE ATT&CK Mapping Engine

    Maps MITRE Techniques to their
    corresponding ATT&CK Tactics.
    """

    def __init__(self):
        self.mapping = self._load_mapping()

    def _load_mapping(self):
        """
        MITRE Technique Mapping
        """

        return {
            "T1059.001": "Execution",
            "T1003.001": "Credential Access",
            "T1486": "Impact",
            "T1021": "Lateral Movement",
            "T1547": "Persistence",
            "T1110": "Credential Access",
            "T1078": "Initial Access",
            "T1047": "Execution",
            "T1082": "Discovery",
            "T1083": "Discovery",
            "T1055": "Defense Evasion",
            "T1562": "Defense Evasion",
            "T1105": "Command and Control",
            "T1053": "Persistence",
        }

    def map(self, dataframe):
        """
        Add MITRE Tactic Column
        """

        dataframe["mitre_tactic"] = (
            dataframe["mapped_technique"]
            .apply(self._get_tactic)
        )

        return dataframe

    def _get_tactic(self, technique):
        """
        Return MITRE Tactic
        """

        return self.mapping.get(
            technique,
            "Unknown"
        )