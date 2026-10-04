"""Evidence-grounded context shared by Investigation, PDF and optional AI."""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Selected alert aur related telemetry ko evidence-grounded investigation context me convert karta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

import math
from typing import Any

import pandas as pd

from core.security import safe_json

NA = "Not available in supplied telemetry"


# FUNCTION: is_present
# Purpose: Ye function is present operation handle karta hai.
# Input: value.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def is_present(value: Any) -> bool:
    """Return True only for meaningful values; fixes the original missing-helper crash."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if value is None:
        return False
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if isinstance(value, float):
        # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
        try:
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if math.isnan(value):
                return False
        except (TypeError, ValueError):
            pass
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if isinstance(value, str):
        return value.strip().lower() not in {"", "none", "nan", "null", "n/a", "na", "-"}
    return True


# FUNCTION: _value
# Purpose: Ye internal helper ka main kaam value se related processing ko centrally handle karna hai.
# Input: obj, *keys.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _value(obj: dict[str, Any] | Any, *keys: str) -> Any:
    # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
    for key in keys:
        value = obj.get(key) if isinstance(obj, dict) else None
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if is_present(value):
            return value
    return NA


# FUNCTION: find_related_events
# Purpose: Ye function find related events operation handle karta hai.
# Input: df, alert, limit.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def find_related_events(df: pd.DataFrame | None, alert: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
    """Find related loaded events using conservative evidence-based correlation."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if df is None or df.empty or not isinstance(alert, dict):
        return []

    current_id = str(alert.get("id", ""))
    source_ip = alert.get("source_ip")
    hostname = alert.get("hostname")
    rule_id = alert.get("rule_id")
    related: list[dict[str, Any]] = []

    # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
    for _, row in df.iterrows():
        item = row.to_dict()
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if str(item.get("id", "")) == current_id:
            continue
        same_ip = is_present(source_ip) and is_present(item.get("source_ip")) and str(source_ip) == str(item.get("source_ip"))
        same_host_rule = (
            is_present(hostname) and is_present(item.get("hostname"))
            and str(hostname) == str(item.get("hostname"))
            and is_present(rule_id) and is_present(item.get("rule_id"))
            and str(rule_id) == str(item.get("rule_id"))
        )
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if same_ip or same_host_rule:
            related.append({
                "id": str(item.get("id", NA)),
                "timestamp": item.get("timestamp", NA),
                "severity": item.get("severity", NA),
                "threat": item.get("threat", NA),
                "reason": item.get("detection_reason", NA),
                "line": _related_line(item),
            })
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if len(related) >= max(1, limit):
            break
    return related


# FUNCTION: _related_line
# Purpose: Ye internal helper ka main kaam related line se related processing ko centrally handle karna hai.
# Input: row.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _related_line(row: dict[str, Any]) -> str:
    raw = row.get("original_log") if is_present(row.get("original_log")) else row.get("raw_event")
    raw_text = safe_json(raw, max_chars=1200) if isinstance(raw, (dict, list)) else str(raw or NA)
    return f"{row.get('timestamp', row.get('event_time', NA))} | {row.get('severity', NA)} | {row.get('threat', NA)} | {raw_text}"


# FUNCTION: build_incident_context
# Purpose: Ye function build incident context operation handle karta hai.
# Input: alert, related.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def build_incident_context(alert: dict[str, Any], related: list[dict[str, Any]] | None = None) -> str:
    """Build bounded, redacted evidence context; no credentials or invented facts are added."""
    related = related or []
    fields = [
        ("Alert ID", "id"), ("Alert / Threat", "threat"), ("Timestamp", "timestamp"),
        ("Severity", "severity"), ("Risk Score", "risk_score"), ("Confidence", "confidence_level"),
        ("Hostname", "hostname"), ("Agent ID", "agent_id"), ("Agent IP", "agent_ip"),
        ("Source IP", "source_ip"), ("Destination IP", "destination_ip"), ("Username", "username"),
        ("Event Type", "event_type"), ("Detection", "final_detection"),
        ("Confirmation Status", "confirmation_status"), ("Detection Reason", "detection_reason"),
        ("Rule ID", "rule_id"), ("Rule Level", "rule_level"), ("Rule Groups", "rule_groups"),
        ("MITRE Technique", "mapped_technique"), ("MITRE Technique Name", "mitre_technique_name"),
        ("MITRE Tactic", "mitre_tactic"), ("MITRE Mapping Source", "mitre_mapping_source"),
        ("Process", "process"), ("Command", "command"), ("Domain", "domain"), ("URL", "url"),
        ("File Name", "filename"), ("File Hash", "file_hash"), ("HTTP Method", "http_method"),
        ("HTTP Status", "http_status"), ("URI Path", "uri_path"), ("URI Query", "uri_query"),
        ("Risk Reason", "risk_justification"), ("Confidence Reason", "confidence_reason"),
    ]
    lines = ["=== SELECTED INCIDENT ==="]
    # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
    for label, key in fields:
        value = _value(alert, key)
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if isinstance(value, (dict, list)):
            value = safe_json(value, max_chars=3000)
        lines.append(f"{label}: {value}")

    raw = alert.get("raw_event")
    lines.append("Original / Raw Event (redacted): " + safe_json(raw, max_chars=6000))
    lines.append("")
    lines.append("=== RELATED EVENTS ===")
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if related:
        # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
        for event in related:
            lines.append(f"[{event.get('id', NA)}] {event.get('line', NA)}")
    else:
        lines.append("No related events among the currently loaded telemetry.")
    return "\n".join(lines)
