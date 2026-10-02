import json
import pandas as pd


NA = "Not available in supplied telemetry"


def _value(obj, *keys):
    for key in keys:
        value = obj.get(key) if isinstance(obj, dict) else None
        if value is not None and str(value).strip().lower() not in ("", "none", "nan", "null"):
            return value
    return NA


def find_related_events(df, alert, limit=10):
    """
    Find related alerts using the same source IP, or same host + rule.
    """
    if df is None or df.empty:
        return []

    current_id = str(alert.get("id", ""))

    related = []

    for _, row in df.iterrows():
        row = row.to_dict()

        if str(row.get("id", "")) == current_id:
            continue

        same_ip = (
            _value(row, "source_ip") != NA
            and _value(alert, "source_ip") != NA
            and str(row.get("source_ip")) == str(alert.get("source_ip"))
        )

        same_host_rule = (
            _value(row, "hostname") != NA
            and _value(alert, "hostname") != NA
            and str(row.get("hostname")) == str(alert.get("hostname"))
            and str(row.get("rule_id", "")) == str(alert.get("rule_id", ""))
        )

        if same_ip or same_host_rule:
            related.append({
                "id": str(row.get("id", "")),
                "line": _related_line(row),
            })

        if len(related) >= limit:
            break

    return related


def _related_line(row):
    raw = row.get("original_log") or row.get("raw_event")

    if isinstance(raw, (dict, list)):
        raw = json.dumps(raw, ensure_ascii=False, default=str)

    return (
        f"{row.get('event_time', NA)} | "
        f"{row.get('severity', NA)} | "
        f"{row.get('threat', NA)} | "
        f"{raw if raw else NA}"
    )


def build_incident_context(alert, related=None):
    """
    Build a compact, evidence-grounded context for the Groq SOC assistant.
    """
    if related is None:
        related = []

    fields = [
        ("Alert ID", "id"),
        ("Alert / Threat", "threat"),
        ("Timestamp", "event_time"),
        ("Severity", "severity"),
        ("Risk Score", "risk_score"),
        ("Hostname", "hostname"),
        ("Source IP", "source_ip"),
        ("Destination IP", "dst_ip"),
        ("Username", "username"),
        ("Detection", "final_detection"),
        ("Detection Reason", "detection_reason"),
        ("Rule ID", "rule_id"),
        ("Rule Level", "rule_level"),
        ("Rule Groups", "rule_groups"),
        ("MITRE Technique", "mapped_technique"),
        ("MITRE Technique Name", "mitre_technique_name"),
        ("MITRE Tactic", "mitre_tactic"),
        ("HTTP Method", "http_method"),
        ("HTTP Status", "http_status"),
        ("URI Path", "uri_path"),
        ("URI Query", "uri_query"),
        ("Referer", "referer"),
        ("Process", "process"),
        ("Command Line", "command_line"),
        ("Domain", "domain"),
        ("URL", "url"),
        ("Filename", "filename"),
        ("File Hash", "file_hash"),
        ("Business Impact", "business_impact"),
        ("Investigation Priority", "investigation_priority"),
        ("Risk Justification", "risk_justification"),
    ]

    lines = ["=== SELECTED INCIDENT ==="]

    for label, key in fields:
        value = _value(alert, key)

        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, default=str)

        lines.append(f"{label}: {value}")

    raw = alert.get("original_log")
    if raw is None:
        raw = alert.get("raw_event")

    if isinstance(raw, (dict, list)):
        raw = json.dumps(raw, ensure_ascii=False, default=str)

    lines.append(f"Original / Raw Event: {raw if raw else NA}")

    lines.append("")
    lines.append("=== RELATED EVENTS ===")

    if related:
        for event in related:
            lines.append(
                f"[{event.get('id', NA)}] {event.get('line', NA)}"
            )
    else:
        lines.append("No related events among the currently loaded alerts.")

    return "\n".join(lines)
