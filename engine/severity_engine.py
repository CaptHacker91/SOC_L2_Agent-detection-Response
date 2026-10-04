"""Explainable severity, risk and confidence calculation."""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Severity, risk score, confidence aur confirmation ko explainable policy se calculate karta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

import json
from pathlib import Path


# CLASS: SeverityEngine
# Role: Ye class ka main kaam Severity Engine se related processing ko centrally handle karna hai.
# Is class ke methods milkar ek focused responsibility ko handle karte hain.
class SeverityEngine:
    """Keep severity, numeric risk, confidence and confirmation independent."""

    # -----------------------------------------------------------------------
    # RISK POLICY - EXPLAINABLE SCORING RULES
    # -----------------------------------------------------------------------
    DEFAULT_RISK = (2.0, "No configured risk evidence matched; a low baseline is used.")
    NORMAL_RISK = (0.0, "Event was classified as Normal telemetry.")
    WEB_RISK = {
        "Suspicious Request Pattern (Success)": (9.0, "Suspicious URI pattern plus an observed HTTP 200 response; exploit impact remains unconfirmed."),
        "Suspicious Request Pattern": (7.2, "Suspicious URI pattern was observed, but successful exploitation was not established."),
        "Access Denied Attempt": (5.5, "HTTP 403 was observed; the request was denied."),
        "Server Error on Request": (5.0, "HTTP 5xx was observed; application fault versus exploitation cannot be distinguished from this event alone."),
        "Malformed Web Request": (4.0, "HTTP 400 was observed; low inherent risk without corroborating evidence."),
        "Not Acceptable Request": (3.5, "HTTP 406 was observed; content negotiation failed."),
        "Request Timeout": (3.0, "HTTP 408 was observed; request timed out."),
        "Protocol Version Error": (3.0, "HTTP 505 was observed; unsupported HTTP version."),
    }

    # FUNCTION: __init__
    # Purpose: Ye function ka main kaam init se related processing ko centrally handle karna hai.
    # Input: rules_path.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def __init__(self, rules_path=None):
        """Load risk metadata for configured synthetic SOC rules."""
        self.rules = {}
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if rules_path:
            # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
            try:
                data = json.loads(Path(rules_path).read_text(encoding="utf-8"))
                # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
                if isinstance(data, list):
                    self.rules = {str(item.get("threat")): item for item in data if isinstance(item, dict) and item.get("threat")}
            except (OSError, json.JSONDecodeError):
                self.rules = {}

    # FUNCTION: calculate
    # Purpose: Ye function calculate operation handle karta hai.
    # Input: df.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def calculate(self, df):
        """Calculate risk, severity and confidence for each analysed event."""
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if df.empty:
            return df
        risks, reasons, severities = [], [], []
        confidence, confidence_level, confidence_reason = [], [], []

        # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
        for _, row in df.iterrows():
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if row.get("final_detection") == "Normal":
                score, reason = self.NORMAL_RISK
                conf, clevel, creason = 0.0, "None", "No security detection was established."
            # Yaha previous checks ke fail hone par alternate condition evaluate ki ja rahi hai.
            elif row.get("event_category") == "wazuh":
                score, reason = self._wazuh_score(row)
                conf, clevel, creason = self._wazuh_confidence(row)
            # Yaha previous checks ke fail hone par alternate condition evaluate ki ja rahi hai.
            elif row.get("threat") in self.WEB_RISK:
                score, reason = self.WEB_RISK[row.get("threat")]
                conf, clevel, creason = 0.90, "High", "A deterministic HTTP pattern/status rule matched observed telemetry."
            else:
                config = self.rules.get(str(row.get("threat")))
                # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
                if config and row.get("event_category") == "synthetic_soc":
                    # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
                    try:
                        score = float(config.get("risk_score"))
                    except (TypeError, ValueError):
                        score = self.DEFAULT_RISK[0]
                    reason = str(config.get("risk_reason") or f"Configured rule risk score for '{row.get('threat')}'.")
                    conf, clevel, creason = 0.90, "High", "A configured rule matched supplied signature evidence."
                else:
                    score, reason = self.DEFAULT_RISK
                    conf, clevel, creason = 0.25, "Low", "Evidence is insufficient for a strong confidence assessment."

            score = max(0.0, min(float(score), 10.0))
            risks.append(round(score, 1))
            reasons.append(reason)
            severities.append(self._band(score, row.get("final_detection")))
            confidence.append(conf)
            confidence_level.append(clevel)
            confidence_reason.append(creason)

        df["risk_score"] = risks
        df["risk_justification"] = reasons
        df["severity"] = severities
        df["confidence_score"] = confidence
        df["confidence_level"] = confidence_level
        df["confidence_reason"] = confidence_reason
        return df

    # FUNCTION: _wazuh_score
    # Purpose: Ye internal helper ka main kaam wazuh score se related processing ko centrally handle karna hai.
    # Input: row.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _wazuh_score(self, row):
        """Scale a Wazuh rule level into a bounded 0-10 triage risk score."""
        # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
        try:
            level = max(0, min(int(row.get("rule_level")), 15))
        except (TypeError, ValueError):
            return self.DEFAULT_RISK
        return round(level / 15 * 10, 1), f"Wazuh rule level {level}/15, scaled to a 0-10 risk score."

    @staticmethod
    # FUNCTION: _wazuh_confidence
    # Purpose: Ye internal helper ka main kaam wazuh confidence se related processing ko centrally handle karna hai.
    # Input: row.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _wazuh_confidence(row):
        """Explain confidence in the source-reported Wazuh rule match."""
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if row.get("rule_id") and row.get("description"):
            return 0.90, "High", "Confidence is high that the source reported the stated Wazuh rule match; this does not confirm compromise."
        return 0.70, "Medium", "Wazuh-like evidence was detected but rule metadata is incomplete."

    @staticmethod
    # FUNCTION: _band
    # Purpose: Ye internal helper ka main kaam band se related processing ko centrally handle karna hai.
    # Input: score, final_detection.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _band(score, final_detection):
        """Convert numeric risk and detection state into the displayed severity band."""
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if final_detection == "Normal":
            return "Normal"
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if score >= 9.0:
            return "Critical"
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if score >= 7.0:
            return "High"
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if score >= 4.0:
            return "Medium"
        return "Low"
