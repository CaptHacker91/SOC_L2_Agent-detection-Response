class MitreMapper:
    """
    Maps a detected threat label to a MITRE ATT&CK technique — but
    ONLY when the evidence genuinely supports it. Everything else is
    explicitly left unmapped rather than guessed.

    T1105 (Ingress Tool Transfer) is intentionally NOT assigned to a
    plain 404/403/5xx "suspicious" hit — those only prove an attempt,
    not a transfer. It's only used, alongside T1190, when the
    detection engine itself already confirmed a successful (HTTP 200)
    suspicious request.
    """

    MAPPING = {
        # Synthetic SOC dataset (BLUE_TEAM_DEFENSE_DATASET.jsonl)
        "PowerShell Abuse":        ("T1059.001", "PowerShell", "Execution"),
        "Credential Dumping":      ("T1003.001", "LSASS Memory", "Credential Access"),
        "Ransomware Execution":    ("T1486", "Data Encrypted for Impact", "Impact"),
        "Malicious File Download": ("T1105", "Ingress Tool Transfer", "Command and Control"),
        "Phishing Email":          ("T1566.001", "Spearphishing Attachment", "Initial Access"),

        # Web-access derived — only the case with confirmed success
        "Suspicious Request Pattern (Success)": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    }

    UNMAPPED_TECHNIQUE = "Not mapped from supplied telemetry"
    UNMAPPED_NAME = "Unknown Technique"
    UNMAPPED_TACTIC = "Not mapped"

    def map(self, df):
        if df.empty:
            return df

        techniques, names, tactics = [], [], []
        for threat in df.get("threat", []):
            if threat in self.MAPPING:
                tid, tname, tactic = self.MAPPING[threat]
            else:
                tid, tname, tactic = self.UNMAPPED_TECHNIQUE, self.UNMAPPED_NAME, self.UNMAPPED_TACTIC
            techniques.append(tid)
            names.append(tname)
            tactics.append(tactic)

        df["mapped_technique"] = techniques
        df["mitre_technique_name"] = names
        df["mitre_tactic"] = tactics
        return df
