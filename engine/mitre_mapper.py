"""Evidence-preserving MITRE ATT&CK mapping stage."""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Available evidence se MITRE ATT&CK technique/tactic mapping karta hai aur unsupported mapping invent nahi karta.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

import json
from pathlib import Path
import re


# CLASS: MitreMapper
# Role: Ye class ka main kaam Mitre Mapper se related processing ko centrally handle karna hai.
# Is class ke methods milkar ek focused responsibility ko handle karte hain.
class MitreMapper:
    """Prefer source-supplied IDs, then explicit configured-rule mappings, else unmapped."""

    # -----------------------------------------------------------------------
    # EXPLICIT SUPPORTED MAPPINGS - VERIFIED MITRE REFERENCES
    # -----------------------------------------------------------------------
    UNMAPPED = "Not mapped from supplied telemetry."
    NOT_SUPPLIED = "Not supplied by source."
    MAPPING = {
        "PowerShell Abuse": ("T1059.001", "PowerShell", "Execution"),
        "Credential Dumping": ("T1003.001", "LSASS Memory", "Credential Access"),
        "Ransomware Execution": ("T1486", "Data Encrypted for Impact", "Impact"),
        "Malicious File Download": ("T1105", "Ingress Tool Transfer", "Command and Control"),
        "Phishing Email": ("T1566.001", "Spearphishing Attachment", "Initial Access"),
        "Suspicious Request Pattern (Success)": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    }
    TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

    # FUNCTION: __init__
    # Purpose: Ye function ka main kaam init se related processing ko centrally handle karna hai.
    # Input: rules_path.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def __init__(self, rules_path=None):
        """Load explicit MITRE mappings from detection-rule configuration."""
        self.rules = {}
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if rules_path:
            # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
            try:
                data = json.loads(Path(rules_path).read_text(encoding="utf-8"))
                # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
                if isinstance(data, list):
                    self.rules = {str(i.get("threat")): i for i in data if isinstance(i, dict) and i.get("threat")}
            except (OSError, json.JSONDecodeError):
                self.rules = {}

    # FUNCTION: map
    # Purpose: Ye function map operation handle karta hai.
    # Input: df.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def map(self, df):
        """Populate mapping ID, name, tactic and mapping source without inventing telemetry."""
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if df.empty:
            return df
        values = [self._lookup(row) for _, row in df.iterrows()]
        df["mapped_technique"] = [v[0] for v in values]
        df["mitre_technique_name"] = [v[1] for v in values]
        df["mitre_tactic"] = [v[2] for v in values]
        df["mitre_mapping_source"] = [v[3] for v in values]
        return df

    # FUNCTION: _lookup
    # Purpose: Ye internal helper ka main kaam lookup se related processing ko centrally handle karna hai.
    # Input: row.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _lookup(self, row):
        """Resolve one row from source telemetry, explicit rule data or the safe unmapped state."""
        supplied = self._clean(row.get("mitre_technique"))
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if supplied and self._valid_ids(supplied):
            return (
                supplied,
                self._clean(row.get("mitre_technique_name")) or self.NOT_SUPPLIED,
                self._clean(row.get("mitre_tactic")) or self.NOT_SUPPLIED,
                "Wazuh telemetry" if row.get("event_category") == "wazuh" else "Supplied telemetry",
            )

        threat = str(row.get("threat") or "")
        configured = self.rules.get(threat)
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if configured and configured.get("mitre") and self._valid_ids(str(configured["mitre"])):
            return (
                str(configured["mitre"]),
                str(configured.get("mitre_name") or self.NOT_SUPPLIED),
                str(configured.get("mitre_tactic") or self.NOT_SUPPLIED),
                "Detection rule configuration",
            )
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if threat in self.MAPPING:
            mapping = self.MAPPING[threat]
            return mapping + ("Built-in explicit mapping",)
        return self.UNMAPPED, self.UNMAPPED, self.UNMAPPED, self.UNMAPPED

    @classmethod
    # FUNCTION: _valid_ids
    # Purpose: Ye internal helper ka main kaam valid ids se related processing ko centrally handle karna hai.
    # Input: cls, value.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _valid_ids(cls, value: str) -> bool:
        """Return True only when every supplied technique ID matches the expected ATT&CK form."""
        ids = [part.strip() for part in value.split(",") if part.strip()]
        return bool(ids) and all(cls.TECHNIQUE_RE.match(item) for item in ids)

    @staticmethod
    # FUNCTION: _clean
    # Purpose: Ye internal helper clean operation handle karta hai.
    # Input: value.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _clean(value):
        """Normalize optional mapping text while preserving meaningful values."""
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if value is None:
            return None
        text = str(value).strip()
        return None if text.lower() in {"", "none", "nan", "null"} else text
