class MitreMapper:
    """
    Resolves the MITRE ATT&CK technique for each event - but ONLY when the
    evidence genuinely supports it. Everything else is explicitly left
    unmapped rather than guessed.

    Priority:
      1. MITRE information supplied by the SIEM itself (columns
         mitre_technique / mitre_technique_name / mitre_tactic, e.g. from a
         Wazuh rule's mitre block) - used exactly as supplied.
      2. The static MAPPING below, keyed by threat label (fallback /
         enrichment for events the SIEM did not tag).
      3. Otherwise: "Not mapped from supplied telemetry".

    T1105 (Ingress Tool Transfer) is intentionally NOT assigned to a
    plain 404/403/5xx "suspicious" hit - those only prove an attempt,
    not a transfer. It's only used, alongside T1190, when the
    detection engine itself already confirmed a successful (HTTP 200)
    suspicious request.
    """

    MAPPING = {
        # Threat labels carrying a signature (fallback mapping)
        "PowerShell Abuse":        ("T1059.001", "PowerShell", "Execution"),
        "Credential Dumping":      ("T1003.001", "LSASS Memory", "Credential Access"),
        "Ransomware Execution":    ("T1486", "Data Encrypted for Impact", "Impact"),
        "Malicious File Download": ("T1105", "Ingress Tool Transfer", "Command and Control"),
        "Phishing Email":          ("T1566.001", "Spearphishing Attachment", "Initial Access"),

        # Web-access derived - only the case with confirmed success
        "Suspicious Request Pattern (Success)": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    }

    UNMAPPED_TECHNIQUE = "Not mapped from supplied telemetry"
    UNMAPPED_NAME = "Unknown Technique"
    UNMAPPED_TACTIC = "Not mapped"
    NOT_SUPPLIED = "Not supplied by source"

    def map(self, df):
        if df.empty:
            return df

        techniques, names, tactics = [], [], []
        for _, row in df.iterrows():
            tid, tname, tactic = self._lookup(row)
            techniques.append(tid)
            names.append(tname)
            tactics.append(tactic)

        df["mapped_technique"] = techniques
        df["mitre_technique_name"] = names
        df["mitre_tactic"] = tactics
        return df

    def _lookup(self, row):
        supplied = self._clean(row.get("mitre_technique"))
        if supplied:
            return (
                supplied,
                self._clean(row.get("mitre_technique_name")) or self.NOT_SUPPLIED,
                self._clean(row.get("mitre_tactic")) or self.NOT_SUPPLIED,
            )

        threat = row.get("threat")
        if threat in self.MAPPING:
            return self.MAPPING[threat]

        return (self.UNMAPPED_TECHNIQUE, self.UNMAPPED_NAME, self.UNMAPPED_TACTIC)

    @staticmethod
    def _clean(value):
        if value is None:
            return None
        text = str(value).strip()
        return None if text.lower() in ("", "none", "nan", "null") else text
