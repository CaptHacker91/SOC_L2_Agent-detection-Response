import pandas as pd


class MitreMapper:
    """
        MITRE ATT&CK Mapping Engine
            """

                def map(self, dataframe):

                        df = dataframe.copy()

                                df["mitre_tactic"] = df["mapped_technique"].apply(
                                            self._get_tactic
                                                    )

                                                            return df

                                                                def _get_tactic(self, technique):

                                                                        mapping = {

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
                                                                                                                                                                                                                                                "T1053": "Persistence"

                                                                                                                                                                                                                                                        }

                                                                                                                                                                                                                                                                return mapping.get(
                                                                                                                                                                                                                                                                            technique,
                                                                                                                                                                                                                                                                                        "Unknown"
                                                                                                                                                                                                                                                                                                )