"""Evidence-based security detection stage.

Detection classification is deliberately separate from severity/risk and from
incident confirmation. A high score or a rule match is not proof of compromise.
"""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Rules aur explicit evidence ke basis par security detection classification karta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


# CLASS: DetectionEngine
# Role: Ye class ka main kaam Detection Engine se related processing ko centrally handle karna hai.
# Is class ke methods milkar ek focused responsibility ko handle karte hain.
class DetectionEngine:
    """Apply configured security rules plus explicit web and Wazuh evidence checks."""

    # -----------------------------------------------------------------------
    # DETECTION CONSTANTS - RULES AUR THRESHOLDS
    # -----------------------------------------------------------------------
    WAZUH_INFORMATIONAL_MAX_LEVEL = 3
    SUSPICIOUS_URI_PATTERNS = (
        "..", "/etc/passwd", "select ", "union select", "<script", "cmd.exe",
        "/bin/sh", "wp-admin", ".php?", "eval(", "../",
    )
    ANOMALOUS_STATUS_REASONS = {
        400: ("Malformed Web Request", "HTTP 400 Bad Request - the server rejected a malformed or invalid request."),
        403: ("Access Denied Attempt", "HTTP 403 Forbidden - the server denied the request; unauthorized access is not established."),
        404: ("Suspicious Resource Access Attempt", "HTTP 404 Not Found - the requested resource was absent; exploitation is not established."),
        406: ("Not Acceptable Request", "HTTP 406 Not Acceptable - content negotiation failed."),
        408: ("Request Timeout", "HTTP 408 Request Timeout - the request timed out."),
        500: ("Server Error on Request", "HTTP 500 Internal Server Error - an application fault or exploitation attempt is possible, but not distinguishable from this telemetry alone."),
        503: ("Service Unavailable", "HTTP 503 Service Unavailable - the service was unavailable when requested."),
        505: ("Protocol Version Error", "HTTP 505 HTTP Version Not Supported - the client used an unsupported HTTP version."),
    }

    # FUNCTION: __init__
    # Purpose: Ye function ka main kaam init se related processing ko centrally handle karna hai.
    # Input: rules_path.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def __init__(self, rules_path: str | Path | None = None):
        """Load enabled detection rules from the configured JSON file."""
        self.rules_path = Path(rules_path) if rules_path else None
        self.rules: list[dict[str, Any]] = []
        self.load_error: str | None = None
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if self.rules_path:
            # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
            try:
                loaded = json.loads(self.rules_path.read_text(encoding="utf-8"))
                # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
                if isinstance(loaded, list):
                    self.rules = [r for r in loaded if isinstance(r, dict) and r.get("enabled", True)]
                else:
                    self.load_error = "Detection rule file must contain a JSON list."
            except (OSError, json.JSONDecodeError) as exc:
                self.load_error = f"Could not load detection rules: {type(exc).__name__}."
        self._rule_map = {str(r["threat"]): r for r in self.rules if r.get("threat")}

    # FUNCTION: analyze
    # Purpose: Ye function analyze operation handle karta hai.
    # Input: df.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def analyze(self, df):
        """Classify every normalized event while preserving the rest of the DataFrame."""
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if df.empty:
            return df
        results = [self._classify_row(row) for _, row in df.iterrows()]
        columns = list(zip(*results))
        threat, reason, rule_type, tool, status, evidence = columns
        df["threat"] = list(threat)
        df["detection_reason"] = list(reason)
        df["rule_type"] = list(rule_type)
        df["tool"] = list(tool)
        df["final_detection"] = list(status)
        df["evidence_summary"] = list(evidence)
        return df

    # FUNCTION: _classify_row
    # Purpose: Ye internal helper classify row operation handle karta hai.
    # Input: row.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _classify_row(self, row):
        """Route one normalized event to the source-specific detection logic."""
        category = row.get("event_category", "other")
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if category == "wazuh":
            return self._classify_wazuh(row)
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if category == "vendor_sales":
            return (
                "Vendor Sales Record",
                "Business telemetry; this pipeline does not classify sales records as security threats.",
                "Business Record",
                "Splunk/Vendor Feed",
                "Normal",
                "Business record only.",
            )
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if category == "web_access":
            return self._classify_web(row)
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if category == "synthetic_soc":
            return self._classify_synthetic(row)
        return (
            "Unclassified Event",
            "Event does not match a configured security detection category.",
            "None",
            "Detection Engine",
            "Normal",
            "No security detection evidence established.",
        )

    # FUNCTION: _classify_wazuh
    # Purpose: Ye internal helper classify wazuh operation handle karta hai.
    # Input: row.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _classify_wazuh(self, row):
        """Classify structurally recognized Wazuh alerts using rule metadata and source evidence."""
        level = self._to_int(row.get("rule_level"))
        rule_id = row.get("rule_id") or "not supplied"
        description = str(row.get("description") or "Wazuh alert (no rule description supplied)").strip()
        groups = row.get("rule_groups") or "not supplied"
        has_mitre = bool(row.get("mitre_technique"))
        informational = level is not None and level <= self.WAZUH_INFORMATIONAL_MAX_LEVEL and not has_mitre
        status = "Normal" if informational else "Anomaly"
        reason = f"Wazuh rule {rule_id} fired"
        reason += f" at level {level}/15" if level is not None else " (level not supplied)"
        reason += f": {description}. Groups: {groups}."
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if has_mitre:
            reason += " MITRE information was supplied by the event source."
        return (
            description,
            reason,
            "Wazuh Rule",
            "Wazuh" if row.get("source") != "MOCK" else "Wazuh-shaped Mock Data",
            status,
            "Source reported a Wazuh rule match; this is not proof of compromise or successful impact.",
        )

    # FUNCTION: _classify_synthetic
    # Purpose: Ye internal helper classify synthetic operation handle karta hai.
    # Input: row.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _classify_synthetic(self, row):
        """Use a configured signature match as the strongest synthetic SOC detection evidence."""
        threat = str(row.get("threat") or "Unclassified Event")
        rule = self._rule_map.get(threat)
        signature = row.get("signature")
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if rule and signature:
            return (
                threat,
                f"Matched configured detection rule '{threat}' using supplied signature evidence.",
                str(row.get("rule_type") or "Configured Rule"),
                str(row.get("tool") or "Detection Engine"),
                "Anomaly",
                "Configured rule matched the supplied dataset record; compromise is not independently confirmed.",
            )
        return (
            threat,
            "The record contains a threat label but no configured rule/signature match was established.",
            str(row.get("rule_type") or "Unmatched"),
            str(row.get("tool") or "Detection Engine"),
            "Anomaly",
            "Threat label is present in supplied telemetry; independent confirmation is unavailable.",
        )

    # FUNCTION: _classify_web
    # Purpose: Ye internal helper classify web operation handle karta hai.
    # Input: row.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _classify_web(self, row):
        """Classify suspicious URI and HTTP-status evidence without claiming successful exploitation."""
        status = self._to_int(row.get("http_status"))
        uri = str(row.get("url") or row.get("uri_path") or "").lower()
        suspicious = any(pattern in uri for pattern in self.SUSPICIOUS_URI_PATTERNS)
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if suspicious:
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if status == 200:
                return (
                    "Suspicious Request Pattern (Success)",
                    "Request URI matched a configured suspicious pattern and returned HTTP 200; request success is observed, but exploit impact is not proven.",
                    "HTTP Pattern Rule",
                    "Web Access Log",
                    "Anomaly",
                    "Suspicious URI evidence plus HTTP 200 response.",
                )
            return (
                "Suspicious Request Pattern",
                f"Request URI matched a configured suspicious pattern; server returned HTTP {status if status is not None else 'unknown'}. Outcome is unconfirmed.",
                "HTTP Pattern Rule",
                "Web Access Log",
                "Anomaly",
                "Suspicious URI evidence; successful exploitation is not established.",
            )
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if status in self.ANOMALOUS_STATUS_REASONS:
            threat, reason = self.ANOMALOUS_STATUS_REASONS[status]
            return threat, reason, "HTTP Status Rule", "Web Access Log", "Anomaly", f"Observed HTTP {status}."
        return (
            "Normal Web Access",
            f"HTTP {status if status is not None else 'status unavailable'} - no configured suspicious URI/status evidence.",
            "Baseline",
            "Web Access Log",
            "Normal",
            "No configured web detection evidence matched.",
        )

    @staticmethod
    # FUNCTION: _to_int
    # Purpose: Ye internal helper ka main kaam to int se related processing ko centrally handle karna hai.
    # Input: value.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _to_int(value):
        """Safely convert a telemetry value to an integer or return None."""
        # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
