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

from core.security import redact_text, safe_json

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
def find_related_events(
    df: pd.DataFrame | None,
    alert: dict[str, Any],
    limit: int = 10,
    window_hours: int = 24 * 7,
    mode: str = "auto",
) -> list[dict[str, Any]]:
    """Find nearby related events using explicit source-IP or host+rule correlation.

    Correlation is intentionally conservative: the candidate must share the selected
    event's source IP, or share both hostname and rule ID, and must fall within the
    configured correlation window (7 days by default). Results are ordered by temporal
    proximity and then correlation strength so the analyst sees the most useful
    context first.
    """
    if df is None or df.empty or not isinstance(alert, dict):
        return []

    current_id = str(alert.get("id", ""))
    source_ip = alert.get("source_ip")
    hostname = alert.get("hostname")
    rule_id = alert.get("rule_id")
    try:
        window_hours = max(1, int(window_hours))
    except (TypeError, ValueError):
        window_hours = 24 * 7

    current_ts = pd.to_datetime(alert.get("timestamp"), utc=True, errors="coerce")
    if pd.isna(current_ts):
        # Without a trustworthy timestamp, silently correlating arbitrary records is unsafe.
        return []

    candidates: list[dict[str, Any]] = []
    for _, row in df.iterrows():
        item = row.to_dict()
        if str(item.get("id", "")) == current_id:
            continue

        item_ts = pd.to_datetime(item.get("timestamp"), utc=True, errors="coerce")
        if pd.isna(item_ts):
            continue
        delta_hours = abs((current_ts - item_ts).total_seconds()) / 3600.0
        if delta_hours > window_hours:
            continue

        same_ip = (
            is_present(source_ip)
            and is_present(item.get("source_ip"))
            and str(source_ip) == str(item.get("source_ip"))
        )
        same_host_rule = (
            is_present(hostname)
            and is_present(item.get("hostname"))
            and str(hostname) == str(item.get("hostname"))
            and is_present(rule_id)
            and is_present(item.get("rule_id"))
            and str(rule_id) == str(item.get("rule_id"))
        )
        same_host = is_present(hostname) and is_present(item.get("hostname")) and str(hostname) == str(item.get("hostname"))
        same_user = is_present(alert.get("username")) and is_present(item.get("username")) and str(alert.get("username")) == str(item.get("username"))
        same_rule = is_present(rule_id) and is_present(item.get("rule_id")) and str(rule_id) == str(item.get("rule_id"))
        if mode == "source_ip":
            accepted = same_ip
        elif mode == "host":
            accepted = same_host
        elif mode == "username":
            accepted = same_user
        elif mode == "rule":
            accepted = same_rule
        elif mode == "host_rule":
            accepted = same_host_rule
        else:
            accepted = same_ip or same_host_rule
        if not accepted:
            continue

        reasons = []
        if same_ip:
            reasons.append(f"Same source IP ({source_ip})")
        if same_host_rule:
            reasons.append(f"Same host + rule ({hostname}, {rule_id})")
        if mode == "host" and same_host:
            reasons.append(f"Same host ({hostname})")
        if mode == "username" and same_user:
            reasons.append(f"Same username ({alert.get('username')})")
        if mode == "rule" and same_rule:
            reasons.append(f"Same rule ({rule_id})")

        strength = (2 if same_host_rule else 0) + (1 if same_ip else 0) + (1 if same_user else 0) + (1 if same_rule else 0)
        confidence = "Strong" if strength >= 2 else "Moderate" if strength == 1 else "Weak"
        candidates.append({
            "id": str(item.get("id", NA)),
            "timestamp": item.get("timestamp", NA),
            "severity": item.get("severity", NA),
            "threat": item.get("threat", NA),
            "correlation": "; ".join(reasons),
            "detection_reason": item.get("detection_reason", NA),
            "line": _related_line(item),
            "correlation_confidence": confidence,
            "correlation_window_hours": round(delta_hours, 2),
            "_delta_hours": delta_hours,
            "_strength": strength,
        })

    candidates.sort(key=lambda item: (item["_delta_hours"], -item["_strength"]))
    limit = max(1, int(limit))
    visible = candidates[:limit]
    for item in visible:
        item.pop("_delta_hours", None)
        item.pop("_strength", None)
    return visible


# FUNCTION: _related_line
# Purpose: Ye internal helper ka main kaam related line se related processing ko centrally handle karna hai.
# Input: row.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _related_line(row: dict[str, Any]) -> str:
    raw = row.get("original_log") if is_present(row.get("original_log")) else row.get("raw_event")
    raw_text = safe_json(raw, max_chars=1200)
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
        else:
            value = redact_text(value)
        lines.append(f"{label}: {value}")

    raw = alert.get("raw_event")
    lines.append("Original / Raw Event (redacted): " + safe_json(raw, max_chars=6000))
    lines.append("")
    lines.append("=== RELATED EVENTS ===")
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if related:
        # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
        for event in related:
            correlation = event.get("correlation", NA)
            detection_reason = event.get("detection_reason", NA)
            lines.append(
                f"[{event.get('id', NA)}] Correlation: {correlation} | "
                f"Detection: {detection_reason} | Event: {event.get('line', NA)}"
            )
    else:
        lines.append("No related events among the currently loaded telemetry using the configured correlation criteria.")
    return "\n".join(lines)
